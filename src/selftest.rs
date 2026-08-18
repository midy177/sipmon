//! In-process robustness (fuzz-style) tests: malformed frames, random bytes,
//! mutated SIP/RTP/RTCP must never panic anywhere in the decode→correlate
//! pipeline. Declared from main.rs; only compiled under `cfg(test)`.

#[cfg(test)]
mod tests {
    use crate::config::Config;
    use crate::correlate::Correlator;
    use bytes::Bytes;

    /// Deterministic LCG so failures are reproducible.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            self.0
        }
        fn below(&mut self, n: u64) -> u64 {
            self.next() % n.max(1)
        }
        fn byte(&mut self) -> u8 {
            (self.next() >> 33) as u8
        }
    }

    fn fixture_path() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/pcap_fixtures/sipbot_call.pcap")
    }

    #[test]
    fn fuzz_mutated_frames_no_panic() {
        let Ok(data) = std::fs::read(fixture_path()) else {
            return; // fixture optional for unit runs
        };
        let mut rng = Rng(0xdead_beef_cafe_1234);
        let mut corr = Correlator::new(&Config::default(), "fuzz".into());

        // Walk pcap records, mutate a few bytes, feed through the full pipeline.
        let mut off = 24usize;
        let mut fed = 0usize;
        while off + 16 <= data.len() && fed < 5000 {
            let caplen = u32::from_le_bytes(data[off + 8..off + 12].try_into().unwrap()) as usize;
            let end = (off + 16 + caplen).min(data.len());
            let mut pkt = data[off + 16..end].to_vec();
            if !pkt.is_empty() {
                let mutations = rng.below(8);
                for _ in 0..mutations {
                    let pos = (rng.below(pkt.len() as u64)) as usize;
                    pkt[pos] = rng.byte();
                }
                let ts = rng.below(4_000_000_000_000);
                corr.ingest_frame(ts, 1, &pkt);
                fed += 1;
            }
            off = end;
            if caplen == 0 {
                // guard: malformed caplen — stop walking
                break;
            }
        }

        // Pure random buffers across all supported link types (+ bogus ones).
        for _ in 0..5000 {
            let len = rng.below(1600) as usize;
            let buf: Vec<u8> = (0..len).map(|_| rng.byte()).collect();
            let lt = [1u32, 12, 113, 276, 999][(rng.below(5)) as usize];
            corr.ingest_frame(rng.below(4_000_000_000_000), lt, &buf);
        }

        // Sanity: the pipeline survived and produced some state.
        assert!(corr.reg.pkts_total > 0);
        let _ = corr.reg.snapshot(10);
    }

    #[test]
    fn fuzz_rtcp_like_no_panic() {
        use crate::decode::rtcp;
        let mut rng = Rng(0x1234_5678_9abc_def0);
        for _ in 0..20_000 {
            let len = 4 + rng.below(1200) as usize;
            let mut buf: Vec<u8> = (0..len).map(|_| rng.byte()).collect();
            // Force RTCP-like first bytes: v=2 + packet type 200..207.
            buf[0] = 0x80 | (rng.below(2) as u8 * 0x20);
            buf[1] = 200 + (rng.below(8) as u8);
            let _ = rtcp::parse_all(&buf);
        }
    }

    #[test]
    fn fuzz_sip_like_no_panic() {
        use crate::decode::sip::parse_sip;
        use crate::model::packet::{Flow5Tuple, Proto};
        let mut rng = Rng(0x00fe_dcba_9876_5432);
        let flow = Flow5Tuple {
            proto: Proto::Udp,
            src: "1.2.3.4:5060".parse().unwrap(),
            dst: "5.6.7.8:5060".parse().unwrap(),
        };
        let seeds: Vec<Vec<u8>> = vec![
            b"INVITE sip:bob@example.com SIP/2.0\r\nVia: SIP/2.0/UDP x;branch=z9\r\n".to_vec(),
            b"SIP/2.0 200 OK\r\n".to_vec(),
            b"INVITE sip:x SIP/2.0\r\nCSeq: 999999999999 INVITE\r\nContent-Length: 999999999999\r\n\r\n".to_vec(),
            b"REGISTER sip:x SIP/2.0\r\nFrom: <sip:\xff\xfe>;tag=\x00\x01\r\n".to_vec(),
        ];
        for i in 0..20_000 {
            let mut buf = seeds[(rng.below(seeds.len() as u64)) as usize].clone();
            let extra = rng.below(400) as usize;
            for _ in 0..extra {
                buf.push(rng.byte());
            }
            if rng.below(2) == 1 && !buf.is_empty() {
                let pos = (rng.below(buf.len() as u64)) as usize;
                buf[pos] = rng.byte();
            }
            let _ = parse_sip(1_000_000 + (i as u64), flow, &buf, None);
        }
    }

    #[test]
    fn fuzz_tcp_reasm_bounded() {
        use crate::decode::tcp_reasm::TcpReassembler;
        use crate::model::packet::{Flow5Tuple, Proto};
        let flow = Flow5Tuple {
            proto: Proto::Tcp,
            src: "1.2.3.4:5060".parse().unwrap(),
            dst: "5.6.7.8:5060".parse().unwrap(),
        };
        let mut reasm = TcpReassembler::new();

        // Endless garbage after a header claiming a huge Content-Length must
        // not grow the buffer beyond the cap.
        let hdr = b"INVITE sip:x SIP/2.0\r\nContent-Length: 2000000000\r\n\r\n";
        reasm.feed(flow, hdr, 0);
        let chunk = vec![0x41u8; 8192];
        for _ in 0..1024 {
            reasm.feed(flow, &chunk, 0);
        }
        assert!(
            reasm.buffered_bytes() <= crate::decode::tcp_reasm::MAX_STREAM_BUF,
            "reasm buffer must stay bounded"
        );
    }

    #[test]
    fn fuzz_evlog_reader_corruption_no_panic() {
        use crate::store::evlog::{EvlogReader, EvlogWriter};
        let mut buf: Vec<u8> = Vec::new();
        {
            let mut w = EvlogWriter::new(&mut buf).unwrap();
            for i in 0..100u64 {
                w.write(&crate::store::evlog::Event::Error(
                    crate::store::evlog::ErrorEvt {
                        ts_us: i * 1000,
                        kind: "t".into(),
                        msg: "m".repeat(50),
                    },
                ))
                .unwrap();
            }
        }
        // Corrupt: flip bytes across the file and read; reader must return an
        // error or events, never panic or allocate unboundedly.
        let mut rng = Rng(0xfeed_face);
        for round in 0..200 {
            let mut data = buf.clone();
            let flips = 1 + rng.below(6);
            for _ in 0..flips {
                if data.is_empty() {
                    break;
                }
                let pos = (rng.below(data.len() as u64)) as usize;
                data[pos] = rng.byte();
            }
            // Truncation rounds.
            if round % 3 == 0 {
                let cut = (rng.below(data.len() as u64 + 1)) as usize;
                data.truncate(cut);
            }
            let mut r = EvlogReader::new(std::io::Cursor::new(data)).unwrap();
            while let Ok(Some(_)) = r.next_event() {}
        }
    }

    #[test]
    fn evlog_reader_rejects_huge_record_length() {
        use crate::store::evlog::EvlogReader;
        // Header + delta varint(1) + type(1) + length varint(2^40-ish).
        let mut data = Vec::new();
        data.extend_from_slice(b"SMON");
        data.extend_from_slice(&1u16.to_be_bytes());
        data.extend_from_slice(&0u16.to_be_bytes());
        data.extend_from_slice(&0i32.to_be_bytes());
        data.push(1); // ts delta
        data.push(1); // type
        // 10-byte varint encoding a huge value (0x01 << 63).
        for _i in 0..9 {
            data.push(0xFF);
        }
        data.push(0x7F);
        let mut r = EvlogReader::new(std::io::Cursor::new(data)).unwrap();
        let res = r.next_event();
        assert!(res.is_err(), "huge record length must fail cleanly");
    }

    // ------------------------- memory-bound regression -------------------------

    use crate::model::packet::{Flow5Tuple, Proto};
    use crate::model::sip::{Method, SipMsg};

    fn sip(ts: u64, call_id: &str, method: Method, to_tag: bool) -> SipMsg {
        SipMsg {
            ts_us: ts,
            flow: Flow5Tuple {
                proto: Proto::Udp,
                src: "1.1.1.1:5060".parse().unwrap(),
                dst: "2.2.2.2:5060".parse().unwrap(),
            },
            is_request: true,
            method: Some(method),
            status: None,
            call_id: call_id.into(),
            cseq: Some(1),
            cseq_method: Some(method.name().into()),
            branch: Some("b".into()),
            from_tag: Some("f".into()),
            to_tag: to_tag.then(|| "t".to_string()),
            from_uri: Some("<sip:a@1.1.1.1>".into()),
            to_uri: Some("<sip:b@2.2.2.2>".into()),
            raw: Bytes::new(),
            contact_addr: None,
            route_count: 0,
            record_route_count: 0,
            has_sdp: false,
        }
    }

    fn sip_resp(ts: u64, call_id: &str, status: u16, cseq_method: &str) -> SipMsg {
        SipMsg {
            ts_us: ts,
            flow: Flow5Tuple {
                proto: Proto::Udp,
                src: "2.2.2.2:5060".parse().unwrap(),
                dst: "1.1.1.1:5060".parse().unwrap(),
            },
            is_request: false,
            method: None,
            status: Some(status),
            call_id: call_id.into(),
            cseq: Some(2),
            cseq_method: Some(cseq_method.into()),
            branch: Some("b".into()),
            from_tag: Some("f".into()),
            to_tag: Some("t".into()),
            from_uri: None,
            to_uri: None,
            raw: Bytes::new(),
            contact_addr: None,
            route_count: 0,
            record_route_count: 0,
            has_sdp: false,
        }
    }

    fn complete_call(corr: &mut Correlator, ts: u64, i: u32) {
        let id = format!("leak-{i}");
        corr.ingest_sip(sip(ts, &id, Method::Invite, false));
        corr.ingest_sip(sip(ts + 100, &id, Method::Bye, true));
        // 200 OK to BYE terminates the call -> eviction + bookkeeping prune.
        corr.ingest_sip(sip_resp(ts + 200, &id, 200, "BYE"));
    }

    /// Over a long session with eviction, per-call bookkeeping in the
    /// Correlator must stay bounded by the live+recently-evicted call count,
    /// not grow with the total number of calls ever seen.
    #[test]
    fn long_session_bookkeeping_stays_bounded() {
        let cfg = Config {
            max_calls: 200,
            ..Config::default()
        };
        let mut corr = Correlator::new(&cfg, "memtest".into());
        let mut ts = 1_000_000u64;
        for i in 0..50_000u32 {
            complete_call(&mut corr, ts, i);
            ts += 1_000;
            if i % 200 == 0 {
                corr.maybe_periodic_flush(ts);
            }
        }
        // Registry bounded.
        assert!(
            corr.reg.calls.len() <= 200,
            "calls={}",
            corr.reg.calls.len()
        );
        // Bookkeeping pruned: invite_rr / terminal_done must not track all 50k.
        let (invite_rr, terminal_done) = corr.test_bookkeeping_lens();
        assert!(
            invite_rr <= 200 + 16,
            "invite_rr grew to {invite_rr} (50k calls)"
        );
        assert!(
            terminal_done <= 200 + 16,
            "terminal_done grew to {terminal_done} (50k calls)"
        );
    }

    /// Headless record drops a call from RAM as soon as it tears down (the
    /// evlog already has SipMsg + Call teardown).
    #[test]
    fn headless_drops_call_on_terminal() {
        let cfg = Config {
            keep_terminated: false,
            ..Config::default()
        };
        let mut corr = Correlator::new(&cfg, "headless".into());
        complete_call(&mut corr, 1_000_000, 1);
        assert!(
            corr.reg.calls.is_empty(),
            "terminated call retained: {}",
            corr.reg.calls.len()
        );
        let (invite_rr, terminal_done) = corr.test_bookkeeping_lens();
        assert_eq!(invite_rr, 0);
        assert_eq!(terminal_done, 0);
        assert_eq!(corr.reg.completed + corr.reg.failed, 1);
    }

    /// Terminated and idle calls older than the TTL are evicted on flush.
    #[test]
    fn terminated_calls_evicted_by_ttl() {
        let cfg = Config {
            call_ttl_secs: 60,
            max_calls: 100_000,
            ..Config::default()
        };
        let mut corr = Correlator::new(&cfg, "ttl".into());
        complete_call(&mut corr, 1_000_000, 1);
        assert_eq!(corr.reg.calls.len(), 1);
        // Prime the flush clock, then jump past the 60s TTL.
        corr.maybe_periodic_flush(1_000_000);
        corr.maybe_periodic_flush(70_000_000);
        assert!(
            corr.reg.calls.is_empty(),
            "TTL did not drop terminated call: {}",
            corr.reg.calls.len()
        );
        let (invite_rr, terminal_done) = corr.test_bookkeeping_lens();
        assert_eq!(invite_rr, 0);
        assert_eq!(terminal_done, 0);
    }

    /// last_lost must not outlive the streams it tracks.
    #[test]
    fn last_lost_pruned_after_stream_evict() {
        use crate::correlate::turn::Encap;
        use crate::decode::rtp::RtpHeader;
        let cfg = Config {
            keep_terminated: false,
            ..Config::default()
        };
        let mut corr = Correlator::new(&cfg, "lostmap".into());
        let id = "lost-prune";
        corr.ingest_sip(sdp_msg(
            1_000_000,
            id,
            true,
            Method::Invite,
            None,
            "10.10.0.1:5060",
            "10.20.0.1:5060",
            "10.10.0.1",
            20000,
            false,
        ));
        let hdr = RtpHeader {
            version: 2,
            payload_type: 0,
            sequence_number: 1,
            timestamp: 0,
            ssrc: 0x1111,
        };
        let flow = Flow5Tuple {
            proto: Proto::Udp,
            src: "10.10.0.1:20000".parse().unwrap(),
            dst: "10.20.0.1:20000".parse().unwrap(),
        };
        corr.ingest_rtp(2_000_000, flow, hdr, 172, Encap::Direct);
        corr.maybe_periodic_flush(2_000_000);
        corr.maybe_periodic_flush(8_000_000);
        assert!(corr.test_last_lost_len() > 0);
        corr.ingest_sip(sip(9_000_000, id, Method::Bye, true));
        corr.ingest_sip(sip_resp(9_100_000, id, 200, "BYE"));
        corr.maybe_periodic_flush(15_000_000);
        assert_eq!(corr.test_last_lost_len(), 0);
        assert!(corr.reg.streams.is_empty());
    }

    /// A single pathological call (thousands of messages) must not grow the
    /// message buffer without limit.
    #[test]
    fn call_message_buffer_is_capped() {
        let mut corr = Correlator::new(&Config::default(), "memtest".into());
        for i in 0..20_000u32 {
            let mut m = sip(1_000_000 + i as u64 * 1000, "hot-call", Method::Info, true);
            m.raw = Bytes::from(vec![0x41u8; 500]);
            corr.ingest_sip(m);
        }
        let n = corr.reg.calls.get("hot-call").unwrap().messages.len();
        assert!(n <= 2000, "messages grew to {n}");
    }

    /// Heatmap cells are pruned once buckets age out of the retention window.
    #[test]
    fn heatmap_prunes_old_buckets() {
        use crate::store::heatmap::Heatmap;
        let mut h = Heatmap::new(900);
        let base = 1_800_000_000_000_000u64; // unix-us epoch
        for i in 0..20u64 {
            // One record per 900s bucket.
            h.record_call(
                base + i * 900_000_000,
                format!("k{i}"),
                true,
                false,
                None,
                None,
                None,
                None,
                None,
            );
        }
        assert_eq!(h.cell_count(), 20);
        // Retain only the last 5 buckets.
        let cutoff = base + 15 * 900_000_000;
        h.prune_older_than(cutoff);
        assert_eq!(h.cell_count(), 5);
    }

    /// TURN tracker maps must be capped (hostile many-clients scenario).
    #[test]
    fn turn_tracker_capped() {
        use crate::correlate::turn::TurnTracker;
        let mut t = TurnTracker::new(&[]);
        let txn = [1u8; 12];
        // Simulate many distinct clients allocating (no success responses needed
        // for alloc map growth) by feeding allocate requests.
        let mut f = Flow5Tuple {
            proto: Proto::Udp,
            src: "10.0.0.1:3000".parse().unwrap(),
            dst: "203.0.113.1:3478".parse().unwrap(),
        };
        for i in 0..40_000u32 {
            f.src = format!("10.0.{}.{}:3000", (i / 250) % 250, i % 250 + 1)
                .parse()
                .unwrap();
            let _ = t.ingest(i as u64, &f, &alloc_request(&txn));
        }
        t.prune();
        assert!(t.allocs.len() <= 8192, "allocs={}", t.allocs.len());
        // servers learned from requests: still bounded by distinct dst ip (one here).
        assert!(t.turn_servers.len() <= 512);
    }

    use crate::decode::stun;
    fn alloc_request(txn: &[u8; 12]) -> Vec<u8> {
        let body = Vec::new();
        let typ: u16 = stun::METHOD_ALLOCATE;
        let mut out = Vec::new();
        out.extend_from_slice(&typ.to_be_bytes());
        out.extend_from_slice(&(body.len() as u16).to_be_bytes());
        out.extend_from_slice(&stun::MAGIC_COOKIE.to_be_bytes());
        out.extend_from_slice(txn);
        out.extend_from_slice(&body);
        out
    }

    /// A SIP message with a real SDP body (so the correlator learns the media
    /// endpoints and can attribute subsequent RTP to the call).
    #[allow(clippy::too_many_arguments)]
    fn sdp_msg(
        ts: u64,
        call_id: &str,
        is_req: bool,
        method: Method,
        status: Option<u16>,
        src: &str,
        dst: &str,
        sdp_ip: &str,
        port: u16,
        to_tag: bool,
    ) -> SipMsg {
        let body = format!(
            "v=0\r\no=- 1 1 IN IP4 {sdp_ip}\r\ns=-\r\nc=IN IP4 {sdp_ip}\r\nt=0 0\r\nm=audio {port} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n"
        );
        let start_line = if is_req {
            format!("{} sip:x SIP/2.0", method.name())
        } else {
            format!("SIP/2.0 {} Something", status.unwrap_or(0))
        };
        let raw = format!(
            "{start_line}\r\nContent-Type: application/sdp\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        SipMsg {
            ts_us: ts,
            flow: Flow5Tuple {
                proto: Proto::Udp,
                src: src.parse().unwrap(),
                dst: dst.parse().unwrap(),
            },
            is_request: is_req,
            method: Some(method),
            status,
            call_id: call_id.into(),
            cseq: Some(1),
            cseq_method: Some("INVITE".into()),
            branch: Some("b".into()),
            from_tag: Some("f".into()),
            to_tag: to_tag.then(|| "t".to_string()),
            from_uri: Some("<sip:a@1.1.1.1>".into()),
            to_uri: Some("<sip:b@2.2.2.2>".into()),
            raw: Bytes::from(raw),
            contact_addr: None,
            route_count: 0,
            record_route_count: 0,
            has_sdp: true,
        }
    }

    /// Per-IP stats must count RTP packets against both endpoint IPs, and the
    /// owning call must remember those IPs for the drill-down.
    #[test]
    fn per_ip_rtp_stats_attributed() {
        use crate::correlate::turn::Encap;
        use crate::decode::rtp::RtpHeader;
        let mut corr = Correlator::new(&Config::default(), "ipstats".into());
        let id = "ip-attr";
        // INVITE (offer) + 200 OK (answer) with SDP, then ACK.
        corr.ingest_sip(sdp_msg(
            1_000_000,
            id,
            true,
            Method::Invite,
            None,
            "10.10.0.1:5060",
            "10.20.0.1:5060",
            "10.10.0.1",
            20000,
            false,
        ));
        corr.ingest_sip(sdp_msg(
            1_010_000,
            id,
            false,
            Method::Invite,
            Some(200),
            "10.20.0.1:5060",
            "10.10.0.1:5060",
            "10.20.0.1",
            30000,
            true,
        ));
        // RTP toward the negotiated endpoints.
        let flow = Flow5Tuple {
            proto: Proto::Udp,
            src: "10.10.0.1:20000".parse().unwrap(),
            dst: "10.20.0.1:30000".parse().unwrap(),
        };
        for i in 0..10u16 {
            corr.ingest_rtp(
                1_100_000 + i as u64 * 20_000,
                flow,
                RtpHeader {
                    version: 2,
                    payload_type: 0,
                    sequence_number: 1000 + i,
                    timestamp: 16_000 + i as u32 * 160,
                    ssrc: 0x1000,
                },
                160,
                Encap::Direct,
            );
        }
        // Both endpoint IPs tracked with the right packet/byte counts.
        let stats = corr.reg.ipstats.snapshot();
        assert_eq!(stats.len(), 2, "both endpoints tracked");
        let a = stats
            .iter()
            .find(|s| s.ip == "10.10.0.1".parse::<std::net::IpAddr>().unwrap())
            .unwrap();
        assert_eq!(a.pkts_tx + a.pkts_rx, 10);
        assert_eq!(a.bytes_tx + a.bytes_rx, 1600);
        let b = stats
            .iter()
            .find(|s| s.ip == "10.20.0.1".parse::<std::net::IpAddr>().unwrap())
            .unwrap();
        assert_eq!(b.pkts_tx + b.pkts_rx, 10);
        // Call remembers the media IPs for the drill-down.
        let call = corr.reg.calls.get(id).unwrap();
        assert!(
            call.ips
                .contains(&"10.10.0.1".parse::<std::net::IpAddr>().unwrap())
        );
        assert!(
            call.ips
                .contains(&"10.20.0.1".parse::<std::net::IpAddr>().unwrap())
        );
        // Active-call counters for both signaling endpoints.
        let a = stats
            .iter()
            .find(|s| s.ip == "10.10.0.1".parse::<std::net::IpAddr>().unwrap())
            .unwrap();
        assert_eq!(a.active_calls, 1);
    }

    /// clear() must wipe calls, streams, per-IP stats and counters.
    #[test]
    fn clear_resets_state() {
        let mut corr = Correlator::new(&Config::default(), "clear".into());
        corr.ingest_sip(sip(1_000_000, "x", Method::Invite, false));
        corr.ingest_sip(sip(1_100_000, "x", Method::Bye, true));
        corr.reg.ipstats.observe_packet(
            "10.0.0.1".parse().unwrap(),
            1_000_000,
            100,
            crate::store::ipstats::Dir::Tx,
        );
        assert!(!corr.reg.calls.is_empty());
        assert!(!corr.reg.ipstats.snapshot().is_empty());
        corr.clear();
        assert!(corr.reg.calls.is_empty());
        assert!(corr.reg.order.is_empty());
        assert_eq!(corr.reg.ipstats.snapshot().len(), 0);
        assert_eq!(corr.reg.completed, 0);
        assert_eq!(corr.reg.failed, 0);
    }

    /// Live-exit stats are built from correlator events (same report as
    /// `sipmon stats`), not from the possibly TTL-trimmed call table.
    #[test]
    fn live_session_stats_from_memory() {
        use crate::correlate::turn::Encap;
        use crate::decode::rtp::RtpHeader;
        let mut corr = Correlator::new(&Config::default(), "live-stats".into());
        corr.enable_session_stats();
        let id = "live-stats-call";
        corr.ingest_sip(sdp_msg(
            1_000_000,
            id,
            true,
            Method::Invite,
            None,
            "10.10.0.1:5060",
            "10.20.0.1:5060",
            "10.10.0.1",
            20000,
            false,
        ));
        corr.ingest_sip(sdp_msg(
            1_010_000,
            id,
            false,
            Method::Invite,
            Some(200),
            "10.20.0.1:5060",
            "10.10.0.1:5060",
            "10.20.0.1",
            30000,
            true,
        ));
        let flow = Flow5Tuple {
            proto: Proto::Udp,
            src: "10.10.0.1:20000".parse().unwrap(),
            dst: "10.20.0.1:30000".parse().unwrap(),
        };
        for i in 0..20u16 {
            corr.ingest_rtp(
                1_100_000 + i as u64 * 20_000,
                flow,
                RtpHeader {
                    version: 2,
                    payload_type: 0,
                    sequence_number: 1000 + i,
                    timestamp: 16_000 + i as u32 * 160,
                    ssrc: 0x1000,
                },
                160,
                Encap::Direct,
            );
        }
        corr.maybe_periodic_flush(1_100_000);
        corr.maybe_periodic_flush(7_000_000);
        corr.ingest_sip(sip(8_000_000, id, Method::Bye, true));
        corr.ingest_sip(sip_resp(8_100_000, id, 200, "BYE"));
        let acc = corr.take_session_stats().expect("stats enabled");
        let s = acc.finish("live:test".into(), 0, None, 10);
        assert_eq!(s.reliability.seizures, 1);
        assert!(s.calls.invite >= 1);
        assert_eq!(s.calls.bye, 1);
        assert!(s.traffic.sip_msgs >= 3);
        assert!(s.traffic.rtp_pkts > 0, "stream snaps should count RTP");
        let text = s.render_text();
        assert!(text.contains("in-memory"), "{text}");
        assert!(text.contains("Reliability"), "{text}");
        assert!(text.contains("live:test"), "{text}");
    }
}
