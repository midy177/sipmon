# sipmon Detailed Development Plan

A SIP/RTP signaling and media quality monitoring tool. A standalone Rust
executable deployed on a mirrored port / packet capture box, **with no dependency
on a running PBX**.

Input = live capture (libpcap) / pcap file / stdin `tcpdump -w -` stream / own event-log replay / **event log recorded by `record`**; output = live TUI monitoring + exportable analysis results (event log → SQLite/JSONL).

```
[mirrored interface] ──┐
[*.pcap]            ──┤──▶ Capture ─▶ Decode ─▶ Parse ─▶ Correlate ─▶ Analyze ─▶ In-Memory ─▶ TUI
[tcpdump -w-]        ─┘                       (L2/L3/L4)   (SIP)   (Call+RTP)   (metrics)   (AppState)   │
[sipmon record] ─▶ evlog ─▶ replay ─┘                                                                   ▼
                                                                                        event log ─▶ SQLite/JSONL export
```

## Technical decisions

- **Language**: Rust (reuses `rsipstack` SIP parsing, vendors `rustpbx-sipflow`'s RTP statistics)
- **Live capture**: libpcap bindings (`pcap` crate + BPF filter), same privilege requirements as tcpdump; offline pcap files and stdin streams also supported
- **Recording format**: a new standalone event log (binary append-only, no raw RTP payload)
- **Integration**: standalone executable, no dependency on a running PBX
- **Storage**: in-memory + export (hot data in memory, archived on schedule / exit / signal)
- **TUI scope**: live monitoring + offline analysis
- **Reliability metrics**: full set (setup delay/PDD, RTP jitter/loss/latency, hangup cause, aggregated by IP×time-slot into failure rate + MOS estimate heatmap)
- **Heatmap dimensions**: time×remote-IP and time×local-endpoint both supported; page switchable
- **Latency measurement**: RTT from RTCP RR LSR/DLSR (when both directions visible); when one-way, an indirect estimate from RTP arrival intervals (labeled "estimate")

## 1. Project structure

```
sipmon/
├── Cargo.toml
└── src/
├── main.rs              clap CLI / subcommands / tokio runtime
├── config.rs            thresholds / bucket granularity / filtering / storage paths
├── error.rs
├── model/               pure data structures (no logic)
│   ├── packet.rs        CapturedPacket, Flow5Tuple
│   ├── sip.rs           SipMsg, SipTransaction, Call, Leg, CallState, HangupCause
│   ├── media.rs         RtpStream, RtcpReport, StreamSummary
│   └── stats.rs         HealthBucket, MetricSet
├── capture/             input sources (unified CaptureSource trait)
│   ├── live.rs          LivePcap  (pcap crate + BPF)
│   ├── file.rs          PcapFile  (pcap-file crate, pcap/pcapng)
│   ├── stdin.rs         StdinPcap (tcpdump -w -)
│   └── replay.rs        EventReplay (re-analyzes the own event log)
├── decode/              L2→L7
│   ├── frame.rs         etherparse: Eth/VLAN/SLL/IP/TCP/UDP
│   ├── sip.rs           SIP classification + rsipstack parsing
│   ├── rtp.rs           RTP header parsing
│   ├── rtcp.rs          RTCP SR/RR (LSR/DLSR/loss fract/RR)
│   └── tcp_reasm.rs     SIP-over-TCP stream reassembly (Content-Length framing)
├── correlate/
│   ├── transaction.rs   branch+method transaction correlation
│   ├── call.rs          Call-ID state machine
│   └── stream.rs        5-tuple+ssrc → call+leg attribution
├── analyze/
│   ├── media_stats.rs   vendored from rustpbx-sipflow: RFC3550 jitter/loss
│   ├── rtcp_rtt.rs      LSR/DLSR RTT + SR NTP↔RTP one-way delay
│   ├── mos.rs           E-model G.107 MOS estimate
│   └── metrics.rs       PDD/setup delay/hangup/reliability
├── store/
│   ├── registry.rs      active call registry + Call-ID/number/IP/SSRC indexes
│   ├── heatmap.rs       aggregation buckets (time×IP / time×endpoint)
│   └── evlog.rs         event-log binary read/write
├── export/
│   ├── sqlite.rs        rusqlite export
│   └── jsonl.rs
└── ui/                  ratatui TUI
    ├── overview.rs      summary cards + call table
    ├── search.rs        sngrep-style Call-ID/number/IP/SSRC search
    ├── call_detail.rs   flow / raw message / network stats three sub-views
    ├── heatmap.rs
    ├── streams.rs
    └── eventlog.rs
```

## 2. Core data structures

```rust
// model/packet.rs
struct Flow5Tuple { proto: Proto, src: SocketAddr, dst: SocketAddr }   // enum key
struct CapturedPacket { ts_us: u64, flow: Flow5Tuple, payload: Bytes }

// model/sip.rs
enum CallState { Dialing, Ringing, Active, Completed, Failed, Canceled }
struct HangupCause { code: Option<u32>, reason: Option<String> }       // Q.850/Reason header
struct Leg { tag_from, tag_to, branch, remote: SocketAddr, local: SocketAddr, direction }
struct SipMsg { ts_us, flow, is_request, method: Option<Method>,
                status: Option<u16>, call_id, cseq, branch, from_tag, to_tag,
                raw: Bytes /* truncated per --raw-truncate */ }
struct Call {
    call_id, legs: Vec<Leg>, state: CallState,
    invite_ts: Option<u64>, trying_ts, ringing_ts, answer_ts, bye_ts: Option<u64>,
    pdd_ms: Option<u32>, setup_ms: Option<u32>,
    hangup: HangupCause, outcome: Outcome,
    media: Vec<StreamSummary>,
    pkts_sip: u64, pkts_rtp: u64, pkts_rtcp: u64, bytes: u64,
}

// model/media.rs
struct RtpStream { flow, ssrc: u32, pt: u8, codec: String, clock_rate: u32,
                   acc: MediaStatsAccumulator /* vendor */ }
struct RtcpRtt { ts_us, ssrc, rtt_ms: f64 }
struct StreamSummary { ssrc, codec, packets, lost, loss_pct, jitter_ms,
                       rtt_min/rtt_avg/rtt_max_ms: Option<f64>, oneway_ms: Option<f64>, mos: Option<f64> }
```

## 3. Event log format (own binary)

Append-only, file header + record stream. **No raw RTP payload is stored**, only the summaries needed to rebuild the analysis.

```
FileHeader:  magic "SMON"(4) | version u16 | flags u16 | tz_offset i32
Record:      ts_delta varint | ev_type u8 | len varint | payload[len]
Event types ev_type:
  1 SipMsgEvt       { flow, call_id, cseq, branch, method|status, from/to_tag, raw[<=truncate] }
  2 TxnEvt          { call_id, branch, method, response_code, delay_ms }
  3 CallEvt         { call_id, type: Setup|Update|Teardown, state, timestamps..., cause }
  4 StreamSnapEvt   { call_id, ssrc, flow, codec, packets, lost, jitter_ms, ts_window_us }  // every 5s
  5 RtcpRttEvt      { call_id, ssrc, ts_us, rtt_ms, oneway_ms }
  6 HealthBucketEvt { bucket_us, dim_key, metric_set }
  7 ErrorEvt        { ts, kind, msg }
```

Write: a background single-threaded consumer drains a bounded channel and flushes in batches. Read: `replay.rs` parses sequentially and feeds back into the pipeline.

The event log keeps the raw `SipMsgEvt` message bytes (enabled by default, truncatable via `--raw-truncate`), so **historical calls can be re-queried by Call-ID later for the full flow**.

## 4. Key algorithms

**RTP/RTCP classification**: UDP payload first byte `version=2`; `PT = payload[1]&0x7f`; PT∈{200..207} is RTCP (SR/RR/SDES/BYE/APP/RTPFB/PSFB/XR), otherwise RTP. SIP over TCP is framed by Content-Length.

**RTT (RTCP RR)**: `RTT = arrival_NTP − LSR − DLSR` (LSR/DLSR are 32-bit middle-NTP fields).

**One-way delay (RTCP SR)**: the SR carries an NTP(64)+RTP_ts(32) mapping; when both directions are visible, project the peer's RTP_ts onto the local arrival NTP and subtract the sender NTP for the one-way delay. When only one direction is visible, fall back to an indirect estimate from RTP arrival-interval jitter (labeled "indirect").

**jitter/loss**: directly vendors `MediaStatsAccumulator` (RFC3550, with a 64-packet reorder window, `j += (D−j)/16`).

**MOS (simplified E-model, G.107)**:
`R = 93.2 − Id(delay+jitter) − Ie(codec, loss)`
`MOS = 1 + 0.035R + 7e-6·R·(R−60)·(100−R)` (R<100; R≥100 → 4.5). Labeled "estimate".

**Heatmap aggregation**: a 2-D map `(bucket_us, key)`, key = remote IP (optionally /24 aggregated) or local endpoint; each bucket accumulates calls/answered/failed/pdd/jitter/loss/rtt/mos, exporting ASR, setup_fail_rate, and the various averages. Bucket granularity 15min/1h/1d, switchable.

## 5. TUI design (ratatui + crossterm)

Top bar: source, duration, pps, packet count, lost count, pause state.

| Page | Content | sngrep equivalent |
|---|---|---|
| **Overview** | Summary cards (active/completed/failed, avg PDD/jitter/loss, ASR) + call table (PDD/setup/ring·180-183, hangup initiator) | call list |
| **Search** | `/` searches Call-ID / From / To / remote IP / SSRC, fuzzy match, `Enter` on a result opens the call | call filter |
| **Call Detail** | Fixed side-by-side: left **Flow** A→B chronological message table (select messages up/down); right sub-view cycled with `Tab`: ① **Raw** full headers+SDP of the selected message ② **Network** 5-tuple + SIP/RTP/RTCP packet counts + per-stream stats + RTT curve ③ **Diagnostics** call-level diagnostics | flow / message / — |
| **Heatmap** | Grid time×remote-IP (`e` switches to time×local-endpoint); select a cell → call list in the bucket | — |
| **Streams** | Per-RTP-stream live stats table | — |
| **EventLog** | Tail of the own event log | — |
| **IP Stats** | Per-IP table (concurrent calls, loss over 1s/5s/10s/20s/1m/10m/1h/all, bytes, pkts), bottom loss heatmap (`w` switches window), sort newest/max/min (`s`), `Enter` drills into the IP's calls | — |

Keys: `Tab` cycles pages (inside Call Detail: cycles the right sub-view) / `1-7` direct jump / `/` search / `f` BPF filter / `Space` pause / `e` export / `b` bucket granularity / `x` clear / `q` quit.

## 6. CLI interface

```
sipmon live   -i any [-f bpf] [--no-media] [-w log]        # live capture + TUI (-i any captures all interfaces; optionally writes an evlog too)
sipmon record -i any [-f bpf] [--no-media] -w log [-d] [--pidfile p] [--logfile l]
                                                           # headless recording: live capture → binary event log (-w)
                                                           # -d daemonizes; SIGTERM/SIGINT flush and exit gracefully
sipmon -                                          # read a pcap stream from stdin (tcpdump -w -)
sipmon file   -r cap.pcap [--pcapng] [--rate 1x]       # offline pcap analysis + TUI (speed adjustable)
sipmon replay -l sipmon.evlog                         # replay an event log + TUI
sipmon query  -l sipmon.evlog -c <callid>             # no TUI; query flow+stats by Call-ID (script friendly)
sipmon export -l sipmon.evlog --sqlite out.db|--jsonl out.jsonl [--from --to]
sipmon cap.pcap | cap.evlog | out.jsonl          # default mode: no subcommand, dispatch by extension to file/replay/jsonl view
common: --raw-truncate 1024 --bucket 15m --ring-hours 24 --export-jsonl/--export-sqlite --dry-run
```

Mode matrix:

| Mode | Input | Output | Description |
|---|---|---|---|
| `(default FILE)` | pcap/pcapng or evlog | same as file/replay | no subcommand → dispatch by extension: `*.pcap/pcapng` → `file -r`, `*.evlog` → `replay -l`, `*.jsonl` → load snapshot export |
| `live` | interface/stdin/pcap | TUI + (optional) evlog | interactive monitoring |
| `record` | interface | evlog (required) | headless recording, `-d` daemonizable, suited for 7×24 continuous capture |
| `replay` | evlog | TUI / headless JSON | replay and re-analyze a past recording |

## 7. Dependency list

| Purpose | Crate | Version |
|---|---|---|
| TUI | ratatui + crossterm | 0.30 / 0.28 |
| Live capture | pcap | 2.4 |
| Offline pcap/pcapng | pcap-file | 3.0 |
| L2-L4 decoding | etherparse | 0.16 |
| SIP parsing | rsipstack (path dependency) | 0.5.24 |
| RTP/RTCP/jitter/loss | **vendor** media_stats.rs | — |
| SQLite export | rusqlite (bundled feature) | 0.32 |
| Runtime | tokio (full) | 1.52 |
| Other | chrono, serde, serde_json, bytes, clap, anyhow, tracing, tracing-subscriber, dashmap | — |

## 8. Milestones (each with a verifiable artifact)

**M0 — data path (no TUI)**
- 4 input sources + frame decoding + SIP parsing (UDP) + RTP/RTCP classification + event-log persistence
- Verify: `sipmon file -r sample.pcap --print-events` prints structured SIP messages; `sipmon - < <(tcpdump -r x.pcap -w -)` works

**M1 — correlation and metrics**
- transaction/call/stream correlation + PDD/setup/hangup + jitter/loss + RTCP RTT + MOS + in-memory AppState + heatmap buckets
- Verify: unit tests cover the state machine, RTT, the loss reorder window, and MOS; per-call metric JSON for a real call pcap

**M2 — TUI (live + analysis)**
- Overview / Search(sngrep) / Call Detail(Flow+Raw+Network) / Heatmap / Streams / EventLog
- Verify: all TUI pages usable under both live and file sources; Call-ID search hits historical calls and shows the flow

**M3 — export and replay**
- sqlite/jsonl export + `query` subcommand + `replay` re-analysis from the event log + offline pcap speed control
- Verify: SQL queries after export reproduce the heatmap; replay rebuilds consistently with live

**M4 — polish**
- interactive BPF filtering, /24 subnet aggregation, report export (HTML/CSV), complete SIP-over-TCP stream reassembly, documentation

## 9. Testing strategy

- `tests/pcap_fixtures/`: constructed pcaps containing INVITE→200→RTP→BYE (reusing existing sipflow bench data), covering loss/reorder/RTCP
- Unit tests: state machine, RTP header/RTCP parsing, jitter/loss algorithms, RTT, MOS, event-log round-trip
- Integration: `file`/`stdin`/`replay` produce identical metrics from the same pcap
- Benchmarks: ring buffers must not drop under high pps (following sipflow's recv-buffer / multi-receive-task pattern)

## 10. Risks and mitigations

| Risk | Mitigation |
|---|---|
| TLS/SRTP not parseable | Not in v1; docs note capture at the decryption point |
| Peak memory | bounded ring + bucket downsampling + scheduled archival (reusing sipflow's batched flush approach) |
| One-way passive absolute delay inaccurate | RTCP RTT as the primary metric; one-way only as an "estimate" label |
| SIP-over-TCP reassembly is complex | UDP first in M0; TCP (Content-Length framing) added in M4 |
| rsipstack pulls in heavy dependencies | Measured: parse layer only, no network stack; vendor the parsing subset if too heavy |
