//! Offline summary of an event log: reliability (ASR/PDD/…), traffic, and
//! 5-minute call-availability + network windows. Scans the file once without re-parsing SIP.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::IpAddr;
use std::path::Path;

use anyhow::{Context, Result};
use chrono::Offset;
use serde_json::{Value, json};

use crate::model::packet::Flow5Tuple;
#[cfg(test)]
use crate::store::evlog::walk_records;
use crate::store::evlog::{
    CallEvtKind, Event, EvlogReader, StreamSnapLite, decode_payload, parse_rtcp_rtt_ms,
    parse_stream_snap_lite,
};

/// Default number of IPs ranked by loss% in `sipmon stats`.
pub const DEFAULT_TOP_IPS: usize = 50;

/// 5-minute window used by `sipmon stats`.
pub const WINDOW_US: u64 = 300 * 1_000_000;

#[derive(Clone, Copy, Default, Debug)]
struct Counters {
    pkts: u64,
    lost: u64,
    bytes: u64,
}

impl Counters {
    fn add(&mut self, pkts: u64, lost: u64, bytes: u64) {
        self.pkts += pkts;
        self.lost += lost;
        self.bytes += bytes;
    }
    fn loss_pct(self) -> Option<f64> {
        if self.pkts == 0 {
            return if self.lost > 0 { Some(100.0) } else { None };
        }
        Some(self.lost as f64 / self.pkts as f64 * 100.0)
    }
}

#[derive(Default)]
struct WindowAcc {
    loss: Counters,
    sip_msgs: u64,
    sip_bytes: u64,
    invites: HashSet<u32>,
    teardowns: u64,
    answered: u64,
    completed: u64,
    canceled: u64,
    fail: FailSplit,
    calls: HashSet<u32>,
    streams: HashSet<(u32, u32)>,
    rtt_sum: f64,
    rtt_n: u64,
}

/// Split of Failed teardowns by SIP / Q.850 cause.
#[derive(Clone, Copy, Default, Debug)]
struct FailSplit {
    notfound: u64,
    reject: u64,
    busy: u64,
    timeout: u64,
    fail: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FailKind {
    NotFound,
    Reject,
    Busy,
    Timeout,
    Fail,
}

/// Map INVITE final cause → notfound / reject / busy / timeout / fail.
/// Accepts SIP 4xx–6xx and Q.850 causes stored in `hangup_code`.
fn classify_fail(code: Option<u32>) -> FailKind {
    match code {
        Some(404 | 410 | 484 | 485 | 604 | 1) => FailKind::NotFound,
        Some(486 | 600 | 17) => FailKind::Busy,
        Some(408 | 480 | 504 | 18 | 19) => FailKind::Timeout,
        Some(401 | 403 | 407 | 433 | 488 | 603 | 606 | 607 | 21) => FailKind::Reject,
        _ => FailKind::Fail,
    }
}

impl FailSplit {
    fn bump(&mut self, kind: FailKind) {
        match kind {
            FailKind::NotFound => self.notfound += 1,
            FailKind::Reject => self.reject += 1,
            FailKind::Busy => self.busy += 1,
            FailKind::Timeout => self.timeout += 1,
            FailKind::Fail => self.fail += 1,
        }
    }
}

/// One 5-minute performance window.
#[derive(Debug, Clone)]
pub struct LossWindow {
    pub start_ts_us: u64,
    pub calls: usize,
    pub streams: usize,
    pub invites: usize,
    pub teardowns: u64,
    pub answered: u64,
    pub asr_pct: Option<f64>,
    /// (answered + notfound + reject + busy) / teardowns in this window.
    pub ner_pct: Option<f64>,
    pub ccr_pct: Option<f64>,
    pub cancel_pct: Option<f64>,
    pub notfound_pct: Option<f64>,
    pub reject_pct: Option<f64>,
    pub busy_pct: Option<f64>,
    pub timeout_pct: Option<f64>,
    /// Residual Failed teardowns (5xx, 482, …) / teardowns.
    pub fail_pct: Option<f64>,
    pub pkts: u64,
    pub lost: u64,
    pub rtp_bytes: u64,
    pub sip_msgs: u64,
    pub loss_pct: Option<f64>,
    pub avg_rtt_ms: Option<f64>,
}

/// Per-IP all-time loss (TX+RX) derived from StreamSnap deltas.
#[derive(Debug, Clone)]
pub struct IpLoss {
    pub ip: IpAddr,
    pub pkts: u64,
    pub lost: u64,
    pub bytes: u64,
    pub loss_pct: Option<f64>,
}

/// Event-type histogram.
#[derive(Debug, Clone, Default)]
pub struct EventCounts {
    pub sip: u64,
    pub txn: u64,
    pub call: u64,
    pub stream_snap: u64,
    pub rtcp_rtt: u64,
    pub health: u64,
    pub error: u64,
    pub diag: u64,
    /// Framed records whose payload could not be decoded (ignored).
    pub skipped: u64,
}

impl EventCounts {
    pub fn total(&self) -> u64 {
        self.sip
            + self.txn
            + self.call
            + self.stream_snap
            + self.rtcp_rtt
            + self.health
            + self.error
            + self.diag
    }
}

#[derive(Debug, Clone, Default)]
pub struct CallCounts {
    pub unique: usize,
    pub invite: u64,
    pub bye: u64,
    pub cancel: u64,
    pub completed: u64,
    pub failed: u64,
    pub canceled: u64,
}

/// Call-completion / answer metrics from INVITE + Call teardown.
#[derive(Debug, Clone, Default)]
pub struct Reliability {
    /// Unique Call-IDs that carried an INVITE request (seizures).
    pub seizures: u64,
    /// Teardowns with `answer_ts` set.
    pub answered: u64,
    /// Answer-Seizure Ratio: answered / seizures × 100.
    pub asr_pct: Option<f64>,
    /// Completed / seizures × 100.
    pub ccr_pct: Option<f64>,
    pub cancel_pct: Option<f64>,
    /// (answered + notfound + reject + busy) / seizures × 100.
    pub ner_pct: Option<f64>,
    pub notfound: u64,
    pub reject: u64,
    pub busy: u64,
    pub timeout: u64,
    /// Residual Failed teardowns (network / protocol / 5xx).
    pub fail: u64,
    pub notfound_pct: Option<f64>,
    pub reject_pct: Option<f64>,
    pub busy_pct: Option<f64>,
    pub timeout_pct: Option<f64>,
    pub fail_pct: Option<f64>,
    pub avg_pdd_ms: Option<f64>,
    pub p50_pdd_ms: Option<f64>,
    pub p95_pdd_ms: Option<f64>,
    pub avg_setup_ms: Option<f64>,
    /// Average talk time (answer → end) for answered calls.
    pub avg_talk_ms: Option<f64>,
    /// Average call duration (invite → end).
    pub avg_call_ms: Option<f64>,
    /// Top SIP hangup / Reason codes from Call teardown.
    pub hangup_codes: Vec<(u32, u64)>,
}

/// Volume + media-quality aggregates.
#[derive(Debug, Clone, Default)]
pub struct Traffic {
    pub rtp_pkts: u64,
    pub rtp_lost: u64,
    pub rtp_bytes: u64,
    pub sip_msgs: u64,
    pub sip_bytes: u64,
    pub loss_pct: Option<f64>,
    /// Average RTP bit-rate over the capture span (bits/s).
    pub avg_bps: Option<f64>,
    pub avg_rtp_pps: Option<f64>,
    /// Seizures per second over the capture span.
    pub avg_cps: Option<f64>,
    pub avg_mos: Option<f64>,
    pub avg_jitter_ms: Option<f64>,
    pub avg_rtt_ms: Option<f64>,
    pub rtt_samples: u64,
    /// SIP response class histogram: index 0 unused, 1..=6 → 1xx..=6xx.
    pub sip_class: [u64; 7],
}

/// Full `sipmon stats` report.
#[derive(Debug, Clone)]
pub struct EvlogStats {
    pub file: String,
    pub bytes: u64,
    pub tz_offset_secs: Option<i32>,
    pub start_ts_us: Option<u64>,
    pub end_ts_us: Option<u64>,
    pub events: EventCounts,
    pub calls: CallCounts,
    pub reliability: Reliability,
    pub traffic: Traffic,
    pub windows: Vec<LossWindow>,
    pub top_ips: Vec<IpLoss>,
    loss: Counters,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct StreamId {
    ssrc: u32,
    flow: Flow5Tuple,
}

#[derive(Clone, Copy)]
struct StreamSnapState {
    packets: u64,
    lost: u64,
    bytes: u64,
}

#[derive(Clone, Copy, Default)]
struct StreamQuality {
    packets: u64,
    mos: Option<f64>,
    jitter_ms: Option<f64>,
    rtt_ms: Option<f64>,
}

/// Incremental `sipmon stats` accumulator. Fed either by scanning an evlog
/// or by the live correlator (so a TUI session can print the same report on
/// exit without re-reading a file).
#[derive(Default)]
pub struct StatsAcc {
    events: EventCounts,
    intern: HashMap<String, u32>,
    call_ids: HashSet<u32>,
    seizure_ids: HashSet<u32>,
    calls: CallCounts,
    last_snap: HashMap<(u32, StreamId), StreamSnapState>,
    last_quality: HashMap<(u32, StreamId), StreamQuality>,
    windows: BTreeMap<u64, WindowAcc>,
    ip_loss: HashMap<IpAddr, Counters>,
    all: Counters,
    sip_bytes: u64,
    sip_class: [u64; 7],
    hangup: HashMap<u32, u64>,
    fail: FailSplit,
    pdd_samples: Vec<u32>,
    setup_sum: f64,
    setup_n: u64,
    talk_sum: f64,
    talk_n: u64,
    call_dur_sum: f64,
    call_dur_n: u64,
    answered: u64,
    rtt_sum: f64,
    rtt_n: u64,
    start_ts_us: Option<u64>,
    end_ts_us: Option<u64>,
}

impl StatsAcc {
    pub fn new() -> Self {
        Self::default()
    }

    fn note_ts(&mut self, ts: u64) {
        if self.start_ts_us.is_none() {
            self.start_ts_us = Some(ts);
        }
        self.end_ts_us = Some(ts);
    }

    fn intern(&mut self, s: &str) -> u32 {
        if let Some(&id) = self.intern.get(s) {
            return id;
        }
        let id = self.intern.len() as u32;
        self.intern.insert(s.to_owned(), id);
        id
    }

    pub fn ingest(&mut self, ev: &Event) {
        let ts = ev.ts_us();
        match ev {
            Event::SipMsg(e) => {
                self.note_ts(ts);
                self.events.sip += 1;
                let cid = self.intern(&e.call_id);
                self.call_ids.insert(cid);
                self.sip_bytes += e.raw.len() as u64;
                let win = ts / WINDOW_US * WINDOW_US;
                let w = self.windows.entry(win).or_default();
                w.calls.insert(cid);
                w.sip_msgs += 1;
                w.sip_bytes += e.raw.len() as u64;
                if e.is_request {
                    if let Some(m) = e.method.as_deref() {
                        if m.eq_ignore_ascii_case("INVITE") {
                            self.calls.invite += 1;
                            self.seizure_ids.insert(cid);
                            w.invites.insert(cid);
                        } else if m.eq_ignore_ascii_case("BYE") {
                            self.calls.bye += 1;
                        } else if m.eq_ignore_ascii_case("CANCEL") {
                            self.calls.cancel += 1;
                        }
                    }
                } else if let Some(status) = e.status {
                    let class = (status / 100) as usize;
                    if (1..=6).contains(&class) {
                        self.sip_class[class] += 1;
                    }
                }
            }
            Event::Txn(_) => {
                self.note_ts(ts);
                self.events.txn += 1;
            }
            Event::Call(e) => {
                self.note_ts(ts);
                self.events.call += 1;
                let cid = self.intern(&e.call_id);
                self.call_ids.insert(cid);
                if !matches!(e.kind, CallEvtKind::Teardown) {
                    return;
                }
                let win = ts / WINDOW_US * WINDOW_US;
                let w = self.windows.entry(win).or_default();
                w.teardowns += 1;
                w.calls.insert(cid);
                match e.state {
                    3 => {
                        self.calls.completed += 1;
                        w.completed += 1;
                    }
                    4 => {
                        self.calls.failed += 1;
                        let kind = classify_fail(e.hangup_code);
                        self.fail.bump(kind);
                        w.fail.bump(kind);
                    }
                    5 => {
                        self.calls.canceled += 1;
                        w.canceled += 1;
                    }
                    _ => {}
                }
                if e.answer_ts.is_some() {
                    self.answered += 1;
                    w.answered += 1;
                }
                if let Some(p) = e.pdd_ms {
                    self.pdd_samples.push(p);
                }
                if let Some(s) = e.setup_ms {
                    self.setup_sum += s as f64;
                    self.setup_n += 1;
                }
                if let (Some(a), Some(end)) = (e.answer_ts, e.end_ts.or(e.bye_ts))
                    && end >= a
                {
                    self.talk_sum += (end - a) as f64 / 1000.0;
                    self.talk_n += 1;
                }
                if let (Some(inv), Some(end)) = (e.invite_ts, e.end_ts.or(e.bye_ts))
                    && end >= inv
                {
                    self.call_dur_sum += (end - inv) as f64 / 1000.0;
                    self.call_dur_n += 1;
                }
                if let Some(code) = e.hangup_code {
                    *self.hangup.entry(code).or_default() += 1;
                }
            }
            Event::StreamSnap(e) => self.ingest_stream_snap(
                ts,
                &StreamSnapLite {
                    call_id: &e.call_id,
                    ssrc: e.ssrc,
                    flow: e.flow,
                    packets: e.packets,
                    lost: e.lost,
                    bytes: e.bytes,
                    jitter_ms: e.jitter_ms,
                    mos: e.mos,
                    rtt_avg_ms: e.rtt_avg_ms,
                },
            ),
            Event::RtcpRtt(e) => self.ingest_rtcp_rtt(ts, e.rtt_ms),
            Event::HealthBucket(_) => {
                self.note_ts(ts);
                self.events.health += 1;
            }
            Event::Error(_) => {
                self.note_ts(ts);
                self.events.error += 1;
            }
            Event::Diag(_) => {
                self.note_ts(ts);
                self.events.diag += 1;
            }
        }
    }

    fn ingest_record(&mut self, ty: u8, ts: u64, payload: &[u8]) {
        let parsed = match ty {
            4 => parse_stream_snap_lite(payload).map(|lite| {
                self.ingest_stream_snap(ts, &lite);
            }),
            5 => parse_rtcp_rtt_ms(payload).map(|rtt| {
                self.ingest_rtcp_rtt(ts, rtt);
            }),
            1 | 3 => decode_payload(ty, ts, payload).map(|ev| {
                self.ingest(&ev);
            }),
            2 => {
                self.note_ts(ts);
                self.events.txn += 1;
                Ok(())
            }
            6 => {
                self.note_ts(ts);
                self.events.health += 1;
                Ok(())
            }
            7 => {
                self.note_ts(ts);
                self.events.error += 1;
                Ok(())
            }
            8 => {
                self.note_ts(ts);
                self.events.diag += 1;
                Ok(())
            }
            _ => {
                self.note_ts(ts);
                self.events.error += 1;
                Ok(())
            }
        };
        if parsed.is_err() {
            self.events.skipped += 1;
        }
    }

    fn ingest_stream_snap(&mut self, ts: u64, e: &StreamSnapLite<'_>) {
        self.note_ts(ts);
        self.events.stream_snap += 1;
        let cid = self.intern(e.call_id);
        self.call_ids.insert(cid);
        let sid = StreamId {
            ssrc: e.ssrc,
            flow: e.flow,
        };
        let key = (cid, sid);
        let prev = self
            .last_snap
            .get(&key)
            .copied()
            .unwrap_or(StreamSnapState {
                packets: 0,
                lost: 0,
                bytes: 0,
            });
        let pkts = e.packets.saturating_sub(prev.packets);
        let lost = e.lost.saturating_sub(prev.lost);
        let bytes_d = e.bytes.saturating_sub(prev.bytes);
        self.last_snap.insert(
            key,
            StreamSnapState {
                packets: e.packets,
                lost: e.lost,
                bytes: e.bytes,
            },
        );
        self.last_quality.insert(
            key,
            StreamQuality {
                packets: e.packets,
                mos: e.mos,
                jitter_ms: e.jitter_ms,
                rtt_ms: e.rtt_avg_ms,
            },
        );
        let win = ts / WINDOW_US * WINDOW_US;
        let w = self.windows.entry(win).or_default();
        w.loss.add(pkts, lost, bytes_d);
        w.calls.insert(cid);
        w.streams.insert((cid, e.ssrc));
        self.all.add(pkts, lost, bytes_d);
        if pkts > 0 || lost > 0 || bytes_d > 0 {
            self.ip_loss
                .entry(e.flow.src.ip())
                .or_default()
                .add(pkts, lost, bytes_d);
            self.ip_loss
                .entry(e.flow.dst.ip())
                .or_default()
                .add(pkts, lost, bytes_d);
        }
    }

    fn ingest_rtcp_rtt(&mut self, ts: u64, rtt_ms: f64) {
        self.note_ts(ts);
        self.events.rtcp_rtt += 1;
        self.rtt_sum += rtt_ms;
        self.rtt_n += 1;
        let win = ts / WINDOW_US * WINDOW_US;
        let w = self.windows.entry(win).or_default();
        w.rtt_sum += rtt_ms;
        w.rtt_n += 1;
    }

    /// Seal the accumulator into the printable/JSON report.
    pub fn finish(
        mut self,
        file: String,
        bytes: u64,
        tz_offset_secs: Option<i32>,
        top_ips: usize,
    ) -> EvlogStats {
        self.calls.unique = self.call_ids.len();
        let seizures = self.seizure_ids.len() as u64;
        let rate = |n: u64| {
            if seizures == 0 {
                None
            } else {
                Some(n as f64 / seizures as f64 * 100.0)
            }
        };

        self.pdd_samples.sort_unstable();
        let reliability = Reliability {
            seizures,
            answered: self.answered,
            asr_pct: rate(self.answered),
            ccr_pct: rate(self.calls.completed),
            cancel_pct: rate(self.calls.canceled),
            ner_pct: rate(self.answered + self.fail.notfound + self.fail.reject + self.fail.busy),
            notfound: self.fail.notfound,
            reject: self.fail.reject,
            busy: self.fail.busy,
            timeout: self.fail.timeout,
            fail: self.fail.fail,
            notfound_pct: rate(self.fail.notfound),
            reject_pct: rate(self.fail.reject),
            busy_pct: rate(self.fail.busy),
            timeout_pct: rate(self.fail.timeout),
            fail_pct: rate(self.fail.fail),
            avg_pdd_ms: mean_u32(&self.pdd_samples),
            p50_pdd_ms: percentile(&self.pdd_samples, 0.50),
            p95_pdd_ms: percentile(&self.pdd_samples, 0.95),
            avg_setup_ms: mean_f64(self.setup_sum, self.setup_n),
            avg_talk_ms: mean_f64(self.talk_sum, self.talk_n),
            avg_call_ms: mean_f64(self.call_dur_sum, self.call_dur_n),
            hangup_codes: top_codes(self.hangup, 10),
        };

        let span_us = match (self.start_ts_us, self.end_ts_us) {
            (Some(a), Some(b)) if b > a => b - a,
            _ => 0,
        };
        let span_s = (span_us as f64 / 1_000_000.0).max(1e-9);

        let (mos_sum, mos_w, jit_sum, jit_w, snap_rtt_sum, snap_rtt_w) =
            quality_weighted(&self.last_quality);
        let avg_rtt_ms =
            mean_f64(self.rtt_sum, self.rtt_n).or_else(|| mean_f64(snap_rtt_sum, snap_rtt_w));
        let traffic = Traffic {
            rtp_pkts: self.all.pkts,
            rtp_lost: self.all.lost,
            rtp_bytes: self.all.bytes,
            sip_msgs: self.events.sip,
            sip_bytes: self.sip_bytes,
            loss_pct: self.all.loss_pct(),
            avg_bps: (self.all.bytes > 0).then_some(self.all.bytes as f64 * 8.0 / span_s),
            avg_rtp_pps: (self.all.pkts > 0).then_some(self.all.pkts as f64 / span_s),
            avg_cps: (seizures > 0).then_some(seizures as f64 / span_s),
            avg_mos: mean_f64(mos_sum, mos_w),
            avg_jitter_ms: mean_f64(jit_sum, jit_w),
            avg_rtt_ms,
            rtt_samples: self.rtt_n,
            sip_class: self.sip_class,
        };

        let windows: Vec<LossWindow> = self
            .windows
            .into_iter()
            .map(|(start_ts_us, w)| {
                let den = w.teardowns;
                let rate = |n: u64| {
                    if den == 0 {
                        None
                    } else {
                        Some(n as f64 / den as f64 * 100.0)
                    }
                };
                LossWindow {
                    start_ts_us,
                    calls: w.calls.len(),
                    streams: w.streams.len(),
                    invites: w.invites.len(),
                    teardowns: w.teardowns,
                    answered: w.answered,
                    asr_pct: rate(w.answered),
                    ner_pct: rate(w.answered + w.fail.notfound + w.fail.reject + w.fail.busy),
                    ccr_pct: rate(w.completed),
                    cancel_pct: rate(w.canceled),
                    notfound_pct: rate(w.fail.notfound),
                    reject_pct: rate(w.fail.reject),
                    busy_pct: rate(w.fail.busy),
                    timeout_pct: rate(w.fail.timeout),
                    fail_pct: rate(w.fail.fail),
                    pkts: w.loss.pkts,
                    lost: w.loss.lost,
                    rtp_bytes: w.loss.bytes,
                    sip_msgs: w.sip_msgs,
                    loss_pct: w.loss.loss_pct(),
                    avg_rtt_ms: mean_f64(w.rtt_sum, w.rtt_n),
                }
            })
            .collect();

        let mut top_list: Vec<IpLoss> = self
            .ip_loss
            .into_iter()
            .map(|(ip, c)| IpLoss {
                ip,
                pkts: c.pkts,
                lost: c.lost,
                bytes: c.bytes,
                loss_pct: c.loss_pct(),
            })
            .collect();
        top_list.sort_by(|a, b| {
            b.loss_pct
                .unwrap_or(0.0)
                .partial_cmp(&a.loss_pct.unwrap_or(0.0))
                .unwrap_or(std::cmp::Ordering::Equal)
                .then(b.lost.cmp(&a.lost))
        });
        top_list.truncate(top_ips);

        EvlogStats {
            file,
            bytes,
            tz_offset_secs,
            start_ts_us: self.start_ts_us,
            end_ts_us: self.end_ts_us,
            events: self.events,
            calls: self.calls,
            reliability,
            traffic,
            loss: self.all,
            windows,
            top_ips: top_list,
        }
    }
}

/// Scan `path` once and build the report. `top_ips` caps the IP ranking.
/// Reads sequentially (1 MiB buffer + one record) so a GB-scale evlog cannot OOM.
pub fn scan_path(path: impl AsRef<Path>, top_ips: usize) -> Result<EvlogStats> {
    let path = path.as_ref();
    let bytes = std::fs::metadata(path)
        .with_context(|| format!("stat evlog {}", path.display()))?
        .len();
    let reader = EvlogReader::open(path)?;
    scan(reader, bytes, path.display().to_string(), top_ips)
}

/// Zero-copy scan of an in-memory evlog image (header + records).
#[cfg(test)]
pub fn scan_buf(data: &[u8], file: String, top_ips: usize) -> Result<EvlogStats> {
    let mut acc = StatsAcc::new();
    let tz = walk_records(data, |ty, ts, payload| {
        acc.ingest_record(ty, ts, payload);
        Ok(())
    })?;
    Ok(acc.finish(file, data.len() as u64, tz, top_ips))
}

/// Streaming scan of an already-opened reader. One record in flight.
pub fn scan(
    mut reader: EvlogReader,
    bytes: u64,
    file: String,
    top_ips: usize,
) -> Result<EvlogStats> {
    let tz = reader.tz_offset_secs();
    let mut acc = StatsAcc::new();
    loop {
        match reader.next_raw() {
            Ok(Some((ty, ts, payload))) => acc.ingest_record(ty, ts, payload),
            Ok(None) => break,
            // Framing error (hostile length, I/O). Cannot resync; keep what
            // was already accumulated instead of failing the whole report.
            Err(_) => {
                acc.events.skipped += 1;
                break;
            }
        }
    }
    Ok(acc.finish(file, bytes, tz, top_ips))
}

fn quality_weighted(q: &HashMap<(u32, StreamId), StreamQuality>) -> (f64, u64, f64, u64, f64, u64) {
    let mut mos_sum = 0.0;
    let mut mos_w = 0u64;
    let mut jit_sum = 0.0;
    let mut jit_w = 0u64;
    let mut rtt_sum = 0.0;
    let mut rtt_w = 0u64;
    for s in q.values() {
        let w = s.packets.max(1);
        if let Some(m) = s.mos {
            mos_sum += m * w as f64;
            mos_w += w;
        }
        if let Some(j) = s.jitter_ms {
            jit_sum += j * w as f64;
            jit_w += w;
        }
        if let Some(r) = s.rtt_ms {
            rtt_sum += r * w as f64;
            rtt_w += w;
        }
    }
    (mos_sum, mos_w, jit_sum, jit_w, rtt_sum, rtt_w)
}

fn mean_u32(v: &[u32]) -> Option<f64> {
    if v.is_empty() {
        None
    } else {
        Some(v.iter().map(|&x| x as f64).sum::<f64>() / v.len() as f64)
    }
}

fn mean_f64(sum: f64, n: u64) -> Option<f64> {
    if n == 0 { None } else { Some(sum / n as f64) }
}

fn percentile(sorted: &[u32], p: f64) -> Option<f64> {
    if sorted.is_empty() {
        return None;
    }
    let idx = ((sorted.len() as f64 - 1.0) * p).round() as usize;
    Some(sorted[idx.min(sorted.len() - 1)] as f64)
}

fn top_codes(map: HashMap<u32, u64>, n: usize) -> Vec<(u32, u64)> {
    let mut v: Vec<_> = map.into_iter().collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    v.truncate(n);
    v
}

impl EvlogStats {
    pub fn to_json(&self) -> Value {
        let r = &self.reliability;
        let t = &self.traffic;
        json!({
            "file": self.file,
            "bytes": self.bytes,
            "tz_offset_secs": self.tz_offset_secs,
            "start_ts_us": self.start_ts_us,
            "end_ts_us": self.end_ts_us,
            "events": {
                "total": self.events.total(),
                "sip": self.events.sip,
                "txn": self.events.txn,
                "call": self.events.call,
                "stream_snap": self.events.stream_snap,
                "rtcp_rtt": self.events.rtcp_rtt,
                "health": self.events.health,
                "error": self.events.error,
                "diag": self.events.diag,
                "skipped": self.events.skipped,
            },
            "calls": {
                "unique": self.calls.unique,
                "invite": self.calls.invite,
                "bye": self.calls.bye,
                "cancel": self.calls.cancel,
                "completed": self.calls.completed,
                "failed": self.calls.failed,
                "canceled": self.calls.canceled,
            },
            "reliability": {
                "seizures": r.seizures,
                "answered": r.answered,
                "asr_pct": round2(r.asr_pct),
                "ccr_pct": round2(r.ccr_pct),
                "ner_pct": round2(r.ner_pct),
                "cancel_pct": round2(r.cancel_pct),
                "notfound": r.notfound,
                "reject": r.reject,
                "busy": r.busy,
                "timeout": r.timeout,
                "fail": r.fail,
                "notfound_pct": round2(r.notfound_pct),
                "reject_pct": round2(r.reject_pct),
                "busy_pct": round2(r.busy_pct),
                "timeout_pct": round2(r.timeout_pct),
                "fail_pct": round2(r.fail_pct),
                "avg_pdd_ms": round2(r.avg_pdd_ms),
                "p50_pdd_ms": round2(r.p50_pdd_ms),
                "p95_pdd_ms": round2(r.p95_pdd_ms),
                "avg_setup_ms": round2(r.avg_setup_ms),
                "avg_talk_ms": round2(r.avg_talk_ms),
                "avg_call_ms": round2(r.avg_call_ms),
                "hangup_codes": r.hangup_codes.iter().map(|(c, n)| json!({
                    "code": c, "count": n
                })).collect::<Vec<_>>(),
            },
            "traffic": {
                "rtp_pkts": t.rtp_pkts,
                "rtp_lost": t.rtp_lost,
                "rtp_bytes": t.rtp_bytes,
                "sip_msgs": t.sip_msgs,
                "sip_bytes": t.sip_bytes,
                "loss_pct": round2(t.loss_pct),
                "avg_bps": round2(t.avg_bps),
                "avg_rtp_pps": round2(t.avg_rtp_pps),
                "avg_cps": round2(t.avg_cps),
                "avg_mos": round2(t.avg_mos),
                "avg_jitter_ms": round2(t.avg_jitter_ms),
                "avg_rtt_ms": round2(t.avg_rtt_ms),
                "rtt_samples": t.rtt_samples,
                "sip_class": {
                    "1xx": t.sip_class[1],
                    "2xx": t.sip_class[2],
                    "3xx": t.sip_class[3],
                    "4xx": t.sip_class[4],
                    "5xx": t.sip_class[5],
                    "6xx": t.sip_class[6],
                },
            },
            "loss": {
                "pkts": self.loss.pkts,
                "lost": self.loss.lost,
                "bytes": self.loss.bytes,
                "pct": round2(self.loss.loss_pct()),
            },
            "windows": self.windows.iter().map(|w| json!({
                "start_ts_us": w.start_ts_us,
                "time": fmt_time(w.start_ts_us, self.tz_offset_secs),
                "calls": w.calls,
                "streams": w.streams,
                "invites": w.invites,
                "teardowns": w.teardowns,
                "answered": w.answered,
                "asr_pct": round2(w.asr_pct),
                "ner_pct": round2(w.ner_pct),
                "ccr_pct": round2(w.ccr_pct),
                "cancel_pct": round2(w.cancel_pct),
                "notfound_pct": round2(w.notfound_pct),
                "reject_pct": round2(w.reject_pct),
                "busy_pct": round2(w.busy_pct),
                "timeout_pct": round2(w.timeout_pct),
                "fail_pct": round2(w.fail_pct),
                "pkts": w.pkts,
                "lost": w.lost,
                "rtp_bytes": w.rtp_bytes,
                "sip_msgs": w.sip_msgs,
                "loss_pct": round2(w.loss_pct),
                "avg_rtt_ms": round2(w.avg_rtt_ms),
            })).collect::<Vec<_>>(),
            "top_ips": self.top_ips.iter().map(|i| json!({
                "ip": i.ip.to_string(),
                "pkts": i.pkts,
                "lost": i.lost,
                "bytes": i.bytes,
                "loss_pct": round2(i.loss_pct),
            })).collect::<Vec<_>>(),
        })
    }

    pub fn render_text(&self) -> String {
        let mut out = String::new();
        let span = match (self.start_ts_us, self.end_ts_us) {
            (Some(a), Some(b)) => format!(
                "{} – {} (+{})",
                fmt_time(a, self.tz_offset_secs),
                fmt_time(b, self.tz_offset_secs),
                fmt_elapsed(b.saturating_sub(a))
            ),
            _ => "empty".into(),
        };
        out.push_str(&format!("== {} ==\n", self.file));
        out.push_str(&format!(
            "  size      {}\n",
            if self.bytes == 0 {
                "in-memory".to_string()
            } else {
                fmt_bytes(self.bytes)
            }
        ));
        out.push_str(&format!("  span      {span}\n"));
        out.push_str(&format!(
            "  events    {}  (sip {}  stream-snap {}  call {}  diag {}  rtt {})\n",
            self.events.total(),
            self.events.sip,
            self.events.stream_snap,
            self.events.call,
            self.events.diag,
            self.events.rtcp_rtt
        ));
        if self.events.skipped > 0 {
            out.push_str(&format!(
                "  skipped   {} unreadable record{}\n",
                self.events.skipped,
                if self.events.skipped == 1 { "" } else { "s" }
            ));
        }

        let r = &self.reliability;
        out.push_str("\n== Reliability ==\n");
        out.push_str(&format!(
            "  seizures  {} unique INVITE Call-IDs\n",
            r.seizures
        ));
        out.push_str(&format!(
            "  answered  {}  (ASR {})\n",
            r.answered,
            fmt_pct(r.asr_pct)
        ));
        out.push_str(&format!(
            "  teardown  completed={}  failed={}  canceled={}\n",
            self.calls.completed, self.calls.failed, self.calls.canceled
        ));
        out.push_str(&format!(
            "  rates     ASR={}  CCR={}  NER={}  cancel={}\n",
            fmt_pct(r.asr_pct),
            fmt_pct(r.ccr_pct),
            fmt_pct(r.ner_pct),
            fmt_pct(r.cancel_pct)
        ));
        out.push_str(&format!(
            "  fail      notfound={} ({})  reject={} ({})  busy={} ({})  timeout={} ({})  fail={} ({})\n",
            r.notfound,
            fmt_pct(r.notfound_pct),
            r.reject,
            fmt_pct(r.reject_pct),
            r.busy,
            fmt_pct(r.busy_pct),
            r.timeout,
            fmt_pct(r.timeout_pct),
            r.fail,
            fmt_pct(r.fail_pct)
        ));
        out.push_str(&format!(
            "  timing    PDD avg={} p50={} p95={} | setup={} | ACD={} | call={}\n",
            fmt_ms(r.avg_pdd_ms),
            fmt_ms(r.p50_pdd_ms),
            fmt_ms(r.p95_pdd_ms),
            fmt_ms(r.avg_setup_ms),
            fmt_ms(r.avg_talk_ms),
            fmt_ms(r.avg_call_ms)
        ));
        if !r.hangup_codes.is_empty() {
            let codes: Vec<String> = r
                .hangup_codes
                .iter()
                .map(|(c, n)| format!("{c}×{n}"))
                .collect();
            out.push_str(&format!("  hangup    {}\n", codes.join("  ")));
        }
        out.push_str("\n== Definitions ==\n");
        out.push_str("  ASR      answered / seizures × 100\n");
        out.push_str("           seizures = unique Call-IDs that sent an INVITE request\n");
        out.push_str("           answered = teardowns with answer_ts (INVITE 2xx)\n");
        out.push_str("  CCR      completed / seizures × 100  (teardown state Completed)\n");
        out.push_str("  NER      (answered + notfound + reject + busy) / seizures × 100\n");
        out.push_str("           user-side failures still count as network-effective\n");
        out.push_str("  cancel   canceled / seizures × 100  (CANCEL / 487)\n");
        out.push_str("  NF       404/410/604 / Q.850-1     unallocated / not found\n");
        out.push_str("  REJ      403/603/488/607 / Q.850-21  forbidden / decline\n");
        out.push_str("  BUSY     486/600 / Q.850-17\n");
        out.push_str("  TMO      408/480/504 / Q.850-18/19   timeout / no answer\n");
        out.push_str("  FAIL     other Failed teardowns (5xx, 482, …)\n");
        out.push_str("  PDD      INVITE → first 1xx (100/180/183), milliseconds\n");
        out.push_str("  setup    INVITE → 2xx answer\n");
        out.push_str("  ACD      talk time: answer → BYE/end (answered calls only)\n");
        out.push_str("  call     INVITE → BYE/end\n");
        out.push_str("  windows  call-availability rates use teardowns in that 5-minute bucket\n");

        let t = &self.traffic;
        out.push_str("\n== Traffic ==\n");
        out.push_str(&format!(
            "  RTP       {}  pkts={}  lost={} ({})  ~{} pps  ~{}\n",
            fmt_bytes(t.rtp_bytes),
            t.rtp_pkts,
            t.rtp_lost,
            fmt_pct(t.loss_pct),
            fmt_rate(t.avg_rtp_pps),
            fmt_bps(t.avg_bps)
        ));
        out.push_str(&format!(
            "  SIP       {} msgs  {}  responses 1xx={} 2xx={} 4xx={} 5xx={} 6xx={}\n",
            t.sip_msgs,
            fmt_bytes(t.sip_bytes),
            t.sip_class[1],
            t.sip_class[2],
            t.sip_class[4],
            t.sip_class[5],
            t.sip_class[6]
        ));
        out.push_str(&format!(
            "  load      ~{} CPS over span\n",
            fmt_rate(t.avg_cps)
        ));
        out.push_str(&format!(
            "  quality   MOS {}  jitter {}  RTT {} ({} samples)\n",
            fmt_float(t.avg_mos, 2),
            fmt_ms(t.avg_jitter_ms),
            fmt_ms(t.avg_rtt_ms),
            t.rtt_samples
        ));

        out.push_str("\n== Calls ==\n");
        out.push_str(&format!(
            "  dialogs   {} unique Call-IDs\n",
            self.calls.unique
        ));
        out.push_str(&format!(
            "  SIP       INVITE={}  BYE={}  CANCEL={}\n",
            self.calls.invite, self.calls.bye, self.calls.cancel
        ));

        out.push_str("\n== Loss ==\n");
        out.push_str(&format!(
            "  all-time  {}  (pkts {}  lost {}  bytes {})\n",
            fmt_pct(self.loss.loss_pct()),
            self.loss.pkts,
            self.loss.lost,
            fmt_bytes(self.loss.bytes)
        ));
        if !self.top_ips.is_empty() {
            out.push_str(&format!(
                "  {:<15} {:>7} {:>12} {:>10} {:>10}\n",
                "IP", "LOSS%", "PKTS", "LOST", "BYTES"
            ));
            for ip in &self.top_ips {
                out.push_str(&format!(
                    "  {:<15} {:>7} {:>12} {:>10} {:>10}\n",
                    ip.ip,
                    fmt_pct(ip.loss_pct),
                    ip.pkts,
                    ip.lost,
                    fmt_bytes(ip.bytes)
                ));
            }
        }

        out.push_str("\n== 5-minute call availability ==\n");
        out.push_str(&format!(
            "  {:<8} {:>6} {:>5} {:>5} {:>5} {:>5} {:>7} {:>5} {:>5} {:>5} {:>5} {:>5}\n",
            "TIME",
            "INVITE",
            "TEARD",
            "ASR%",
            "NER%",
            "CCR%",
            "CANCEL%",
            "NF%",
            "REJ%",
            "BUSY%",
            "TMO%",
            "FAIL%"
        ));
        for w in &self.windows {
            out.push_str(&format!(
                "  {:<8} {:>6} {:>5} {:>5} {:>5} {:>5} {:>7} {:>5} {:>5} {:>5} {:>5} {:>5}\n",
                fmt_time(w.start_ts_us, self.tz_offset_secs),
                w.invites,
                w.teardowns,
                fmt_pct_short(w.asr_pct),
                fmt_pct_short(w.ner_pct),
                fmt_pct_short(w.ccr_pct),
                fmt_pct_short(w.cancel_pct),
                fmt_pct_short(w.notfound_pct),
                fmt_pct_short(w.reject_pct),
                fmt_pct_short(w.busy_pct),
                fmt_pct_short(w.timeout_pct),
                fmt_pct_short(w.fail_pct)
            ));
        }
        if self.windows.is_empty() {
            out.push_str("  (no events)\n");
        }

        out.push_str("\n== 5-minute network ==\n");
        out.push_str(&format!(
            "  {:<8} {:>10} {:>10} {:>6} {:>7} {:>7}\n",
            "TIME", "RTP_BYTES", "PKTS", "LOSS%", "SIP", "RTT"
        ));
        for w in &self.windows {
            out.push_str(&format!(
                "  {:<8} {:>10} {:>10} {:>6} {:>7} {:>7}\n",
                fmt_time(w.start_ts_us, self.tz_offset_secs),
                fmt_bytes_short(w.rtp_bytes),
                w.pkts,
                fmt_pct_short(w.loss_pct),
                w.sip_msgs,
                fmt_ms_short(w.avg_rtt_ms)
            ));
        }
        if self.windows.is_empty() {
            out.push_str("  (no events)\n");
        }
        out
    }
}

fn round2(v: Option<f64>) -> Value {
    match v {
        None => Value::Null,
        Some(p) => json!((p * 100.0).round() / 100.0),
    }
}

fn fmt_pct(v: Option<f64>) -> String {
    match v {
        None => "-".into(),
        Some(p) => format!("{p:.2}%"),
    }
}

fn fmt_pct_short(v: Option<f64>) -> String {
    match v {
        None => "-".into(),
        Some(p) => format!("{p:.1}"),
    }
}

fn fmt_ms(v: Option<f64>) -> String {
    match v {
        None => "-".into(),
        Some(ms) if ms >= 1000.0 => format!("{:.1}s", ms / 1000.0),
        Some(ms) => format!("{ms:.0}ms"),
    }
}

fn fmt_ms_short(v: Option<f64>) -> String {
    match v {
        None => "-".into(),
        Some(ms) => format!("{ms:.0}"),
    }
}

fn fmt_float(v: Option<f64>, digits: usize) -> String {
    match v {
        None => "-".into(),
        Some(x) => format!("{x:.digits$}"),
    }
}

fn fmt_rate(v: Option<f64>) -> String {
    match v {
        None => "-".into(),
        Some(x) if x >= 100.0 => format!("{x:.0}"),
        Some(x) if x >= 10.0 => format!("{x:.1}"),
        Some(x) => format!("{x:.2}"),
    }
}

fn fmt_bps(v: Option<f64>) -> String {
    match v {
        None => "-".into(),
        Some(bps) if bps >= 1_000_000.0 => format!("{:.2} Mbps", bps / 1_000_000.0),
        Some(bps) if bps >= 1_000.0 => format!("{:.1} kbps", bps / 1_000.0),
        Some(bps) => format!("{bps:.0} bps"),
    }
}

fn fmt_bytes(n: u64) -> String {
    if n >= 1_073_741_824 {
        format!("{:.2} GB", n as f64 / 1_073_741_824.0)
    } else if n >= 1_048_576 {
        format!("{:.1} MB", n as f64 / 1_048_576.0)
    } else if n >= 1024 {
        format!("{:.1} KB", n as f64 / 1024.0)
    } else {
        format!("{n} B")
    }
}

fn fmt_bytes_short(n: u64) -> String {
    if n >= 1_048_576 {
        format!("{:.1}M", n as f64 / 1_048_576.0)
    } else if n >= 1024 {
        format!("{:.0}K", n as f64 / 1024.0)
    } else {
        format!("{n}")
    }
}

fn fmt_elapsed(us: u64) -> String {
    let s = us / 1_000_000;
    if s < 60 {
        format!("{s}s")
    } else if s < 3600 {
        format!("{}m{:02}s", s / 60, s % 60)
    } else {
        format!("{}h{:02}m", s / 3600, (s % 3600) / 60)
    }
}

fn fmt_time(ts_us: u64, tz_secs: Option<i32>) -> String {
    let Some(utc) = chrono::DateTime::from_timestamp((ts_us / 1_000_000) as i64, 0) else {
        return "??:??:??".into();
    };
    let offset = tz_secs.unwrap_or_else(|| chrono::Local::now().offset().fix().local_minus_utc());
    let local = utc + chrono::Duration::seconds(offset as i64);
    local.format("%H:%M:%S").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::packet::{Flow5Tuple, Proto};
    use crate::store::evlog::{
        CallEvt, CallEvtKind, EvlogReader, EvlogWriter, SipMsgEvt, StreamSnapEvt,
    };

    fn flow() -> Flow5Tuple {
        Flow5Tuple {
            proto: Proto::Udp,
            src: "10.10.0.8:4000".parse().unwrap(),
            dst: "10.20.0.8:4000".parse().unwrap(),
        }
    }

    fn sip(ts: u64, method: &str, call: &str) -> Event {
        Event::SipMsg(SipMsgEvt {
            ts_us: ts,
            flow: Flow5Tuple {
                proto: Proto::Udp,
                src: "10.10.0.8:5060".parse().unwrap(),
                dst: "10.20.0.8:5060".parse().unwrap(),
            },
            is_request: true,
            method: Some(method.into()),
            status: None,
            call_id: call.into(),
            cseq: Some(1),
            branch: Some("z9hG4bK".into()),
            from_tag: Some("ft".into()),
            to_tag: None,
            raw: b"INVITE sip:x SIP/2.0\r\n\r\n".to_vec(),
        })
    }

    fn snap(ts: u64, call: &str, packets: u64, lost: u64, bytes: u64) -> Event {
        Event::StreamSnap(StreamSnapEvt {
            ts_us: ts,
            call_id: call.into(),
            ssrc: 0xabc,
            flow: flow(),
            codec: Some("PCMU".into()),
            payload_type: Some(0),
            packets,
            lost,
            expected: packets + lost,
            loss_pct: if packets == 0 {
                0.0
            } else {
                lost as f64 / packets as f64 * 100.0
            },
            jitter_ms: Some(2.0),
            mos: Some(4.1),
            direction: None,
            bytes,
            first_ts_us: Some(ts),
            last_ts_us: Some(ts),
            rtt_min_ms: None,
            rtt_avg_ms: Some(40.0),
            rtt_max_ms: None,
            oneway_ms: None,
            leg: None,
            via_turn: false,
        })
    }

    fn teardown(ts: u64, call: &str, answered: bool, pdd: u32) -> Event {
        Event::Call(CallEvt {
            ts_us: ts,
            call_id: call.into(),
            kind: CallEvtKind::Teardown,
            from_user: Some("a".into()),
            to_user: Some("b".into()),
            from_uri: None,
            to_uri: None,
            state: if answered { 3 } else { 5 },
            outcome: 0,
            invite_ts: Some(ts.saturating_sub(5_000_000)),
            trying_ts: Some(ts.saturating_sub(4_900_000)),
            ringing_ts: Some(ts.saturating_sub(4_800_000)),
            answer_ts: answered.then_some(ts.saturating_sub(4_000_000)),
            bye_ts: Some(ts.saturating_sub(100_000)),
            end_ts: Some(ts),
            pdd_ms: Some(pdd),
            setup_ms: answered.then_some(1000),
            hangup_code: if answered { None } else { Some(487) },
            hangup_reason: None,
            pkts_sip: 10,
            pkts_rtp: 100,
            pkts_rtcp: 2,
            bytes: 20_000,
        })
    }

    fn teardown_fail(ts: u64, call: &str, code: u32) -> Event {
        Event::Call(CallEvt {
            ts_us: ts,
            call_id: call.into(),
            kind: CallEvtKind::Teardown,
            from_user: Some("a".into()),
            to_user: Some("b".into()),
            from_uri: None,
            to_uri: None,
            state: 4,
            outcome: 0,
            invite_ts: Some(ts.saturating_sub(5_000_000)),
            trying_ts: Some(ts.saturating_sub(4_900_000)),
            ringing_ts: None,
            answer_ts: None,
            bye_ts: None,
            end_ts: Some(ts),
            pdd_ms: Some(50),
            setup_ms: None,
            hangup_code: Some(code),
            hangup_reason: None,
            pkts_sip: 4,
            pkts_rtp: 0,
            pkts_rtcp: 0,
            bytes: 800,
        })
    }

    #[test]
    fn five_minute_windows_and_call_counts() {
        let mut buf = Vec::new();
        let mut w = EvlogWriter::new(&mut buf).unwrap();
        // Window A: 00:00
        w.write(&sip(1_000_000, "INVITE", "c1")).unwrap();
        w.write(&snap(2_000_000, "c1", 100, 2, 16_000)).unwrap();
        w.write(&teardown(3_000_000, "c1", true, 80)).unwrap();
        // Window B: +6 minutes
        let t2 = 6 * 60 * 1_000_000 + 1_000_000;
        w.write(&sip(t2, "INVITE", "c2")).unwrap();
        w.write(&sip(t2 + 1000, "BYE", "c1")).unwrap();
        w.write(&snap(t2, "c1", 250, 5, 40_000)).unwrap(); // delta 150 pkts / 3 lost
        w.write(&teardown(t2 + 2_000_000, "c2", false, 200))
            .unwrap();
        w.flush().unwrap();
        drop(w);

        let reader = EvlogReader::new(std::io::Cursor::new(buf.clone())).unwrap();
        let s = scan(reader, 0, "t.evlog".into(), 10).unwrap();
        let s_buf = scan_buf(&buf, "t.evlog".into(), 10).unwrap();
        assert_eq!(s.calls.unique, 2);
        assert_eq!(s.calls.invite, 2);
        assert_eq!(s.calls.bye, 1);
        assert_eq!(s.reliability.seizures, 2);
        assert_eq!(s.reliability.answered, 1);
        assert!((s.reliability.asr_pct.unwrap() - 50.0).abs() < 1e-9);
        assert_eq!(s.traffic.rtp_bytes, 40_000);
        assert!(s.traffic.avg_mos.is_some());
        assert_eq!(s.windows.len(), 2);
        assert_eq!(s.windows[0].pkts, 100);
        assert_eq!(s.windows[0].lost, 2);
        assert_eq!(s.windows[0].rtp_bytes, 16_000);
        assert_eq!(s.windows[0].invites, 1);
        assert_eq!(s.windows[0].asr_pct, Some(100.0));
        assert_eq!(s.windows[0].ner_pct, Some(100.0));
        assert_eq!(s.windows[0].ccr_pct, Some(100.0));
        assert_eq!(s.windows[0].fail_pct, Some(0.0));
        assert_eq!(s.windows[0].cancel_pct, Some(0.0));
        assert_eq!(s.windows[1].pkts, 150);
        assert_eq!(s.windows[1].lost, 3);
        assert_eq!(s.windows[1].asr_pct, Some(0.0));
        assert_eq!(s.windows[1].fail_pct, Some(0.0));
        assert_eq!(s.windows[1].cancel_pct, Some(100.0));
        assert_eq!(s.loss.pkts, 250);
        assert_eq!(s.loss.lost, 5);
        assert_eq!(s.top_ips.len(), 2);
        assert_eq!(s_buf.loss.pkts, s.loss.pkts);
        assert_eq!(s_buf.loss.lost, s.loss.lost);
        assert_eq!(s_buf.windows.len(), s.windows.len());
        assert_eq!(s_buf.windows[1].cancel_pct, s.windows[1].cancel_pct);
        assert_eq!(s_buf.reliability.seizures, s.reliability.seizures);
        assert_eq!(s_buf.events.stream_snap, s.events.stream_snap);
        let text = s.render_text();
        assert!(text.contains("Reliability"), "{text}");
        assert!(text.contains("ASR"), "{text}");
        assert!(text.contains("answered / seizures"), "{text}");
        assert!(text.contains("Definitions"), "{text}");
        assert!(text.contains("Traffic"), "{text}");
        assert!(text.contains("5-minute call availability"), "{text}");
        assert!(text.contains("5-minute network"), "{text}");
        assert!(text.contains("CANCEL%"), "{text}");
        assert!(text.contains("NF%"), "{text}");
        assert!(text.contains("LOSS%"), "{text}");
        let j = s.to_json();
        assert_eq!(j["calls"]["unique"], 2);
        assert_eq!(j["reliability"]["seizures"], 2);
        assert_eq!(j["reliability"]["answered"], 1);
        assert_eq!(j["traffic"]["rtp_bytes"], 40_000);
        assert_eq!(j["windows"].as_array().unwrap().len(), 2);
        assert_eq!(j["windows"][1]["cancel_pct"], 100.0);
        assert_eq!(s.events.skipped, 0);
    }

    #[test]
    fn classify_fail_maps_sip_and_q850() {
        assert_eq!(classify_fail(Some(404)), FailKind::NotFound);
        assert_eq!(classify_fail(Some(1)), FailKind::NotFound);
        assert_eq!(classify_fail(Some(486)), FailKind::Busy);
        assert_eq!(classify_fail(Some(17)), FailKind::Busy);
        assert_eq!(classify_fail(Some(480)), FailKind::Timeout);
        assert_eq!(classify_fail(Some(408)), FailKind::Timeout);
        assert_eq!(classify_fail(Some(403)), FailKind::Reject);
        assert_eq!(classify_fail(Some(607)), FailKind::Reject);
        assert_eq!(classify_fail(Some(500)), FailKind::Fail);
        assert_eq!(classify_fail(Some(482)), FailKind::Fail);
        assert_eq!(classify_fail(None), FailKind::Fail);
    }

    #[test]
    fn fail_split_and_ner_from_teardowns() {
        let mut buf = Vec::new();
        let mut w = EvlogWriter::new(&mut buf).unwrap();
        w.write(&sip(1_000_000, "INVITE", "ok")).unwrap();
        w.write(&teardown(2_000_000, "ok", true, 20)).unwrap();
        w.write(&sip(3_000_000, "INVITE", "nf")).unwrap();
        w.write(&teardown_fail(4_000_000, "nf", 404)).unwrap();
        w.write(&sip(5_000_000, "INVITE", "bz")).unwrap();
        w.write(&teardown_fail(6_000_000, "bz", 486)).unwrap();
        w.write(&sip(7_000_000, "INVITE", "tm")).unwrap();
        w.write(&teardown_fail(8_000_000, "tm", 480)).unwrap();
        w.write(&sip(9_000_000, "INVITE", "rj")).unwrap();
        w.write(&teardown_fail(10_000_000, "rj", 403)).unwrap();
        w.write(&sip(11_000_000, "INVITE", "fl")).unwrap();
        w.write(&teardown_fail(12_000_000, "fl", 500)).unwrap();
        w.flush().unwrap();
        drop(w);

        let s = scan_buf(&buf, "t.evlog".into(), 10).unwrap();
        assert_eq!(s.reliability.seizures, 6);
        assert_eq!(s.reliability.answered, 1);
        assert_eq!(s.reliability.notfound, 1);
        assert_eq!(s.reliability.reject, 1);
        assert_eq!(s.reliability.busy, 1);
        assert_eq!(s.reliability.timeout, 1);
        assert_eq!(s.reliability.fail, 1);
        // NER = (answered + nf + rej + busy) / 6 = 4/6
        assert!((s.reliability.ner_pct.unwrap() - 400.0 / 6.0).abs() < 1e-9);
        let w0 = &s.windows[0];
        assert!(w0.notfound_pct.is_some());
        let text = s.render_text();
        assert!(text.contains("NF%"), "{text}");
        assert!(text.contains("BUSY%"), "{text}");
        assert!(text.contains("TMO%"), "{text}");
        assert!(text.contains("NER"), "{text}");
    }

    #[test]
    fn truncated_tail_is_ignored() {
        let mut buf = Vec::new();
        let mut w = EvlogWriter::new(&mut buf).unwrap();
        w.write(&sip(1_000_000, "INVITE", "c1")).unwrap();
        w.write(&snap(2_000_000, "c1", 100, 2, 16_000)).unwrap();
        w.write(&teardown(3_000_000, "c1", true, 80)).unwrap();
        w.flush().unwrap();
        drop(w);

        let full = scan_buf(&buf, "t.evlog".into(), 10).unwrap();
        assert_eq!(full.calls.invite, 1);
        assert_eq!(full.events.skipped, 0);

        // Simulate kill(): drop the last 17 bytes of the last record.
        let cut = buf.len().saturating_sub(17);
        assert!(cut > 12 && cut < buf.len());
        let truncated = &buf[..cut];
        let s_buf = scan_buf(truncated, "t.evlog".into(), 10).unwrap();
        let reader = EvlogReader::new(std::io::Cursor::new(truncated.to_vec())).unwrap();
        let s = scan(reader, truncated.len() as u64, "t.evlog".into(), 10).unwrap();
        assert_eq!(s.calls.invite, 1, "complete prefix must still count");
        assert_eq!(s_buf.calls.invite, 1);
        assert_eq!(s.reliability.seizures, 1);
        // Trailing garbage that looks like a framed but undecodable body.
        let mut dirty = buf.clone();
        dirty.extend_from_slice(&[1, 4, 8, 0, 1, 2, 3, 4, 5, 6, 7]);
        let reader = EvlogReader::new(std::io::Cursor::new(dirty)).unwrap();
        let dirty_s = scan(reader, 0, "t.evlog".into(), 10).unwrap();
        assert_eq!(dirty_s.calls.invite, 1);
        assert!(
            dirty_s.events.skipped >= 1,
            "undecodable tail must be skipped"
        );
        let text = dirty_s.render_text();
        assert!(text.contains("skipped"), "{text}");
    }
}
