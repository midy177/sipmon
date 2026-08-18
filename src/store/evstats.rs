//! Offline summary of an event log: reliability (ASR/PDD/…), traffic, and
//! 5-minute quality windows. Scans the file once without re-parsing SIP.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::IpAddr;
use std::path::Path;

use anyhow::Result;
use chrono::Offset;
use serde_json::{Value, json};

use crate::model::packet::Flow5Tuple;
use crate::store::evlog::{CallEvtKind, Event, EvlogReader};

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
    invites: HashSet<String>,
    teardowns: u64,
    answered: u64,
    calls: HashSet<String>,
    streams: HashSet<(String, u32)>,
    rtt_sum: f64,
    rtt_n: u64,
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
    pub fail_pct: Option<f64>,
    pub cancel_pct: Option<f64>,
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
    call_ids: HashSet<String>,
    seizure_ids: HashSet<String>,
    calls: CallCounts,
    last_snap: HashMap<(String, StreamId), StreamSnapState>,
    last_quality: HashMap<(String, StreamId), StreamQuality>,
    windows: BTreeMap<u64, WindowAcc>,
    ip_loss: HashMap<IpAddr, Counters>,
    all: Counters,
    sip_bytes: u64,
    sip_class: [u64; 7],
    hangup: HashMap<u32, u64>,
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

    pub fn ingest(&mut self, ev: &Event) {
        let ts = ev.ts_us();
        if self.start_ts_us.is_none() {
            self.start_ts_us = Some(ts);
        }
        self.end_ts_us = Some(ts);
        let win = ts / WINDOW_US * WINDOW_US;
        match ev {
            Event::SipMsg(e) => {
                self.events.sip += 1;
                self.call_ids.insert(e.call_id.clone());
                self.sip_bytes += e.raw.len() as u64;
                let w = self.windows.entry(win).or_default();
                w.calls.insert(e.call_id.clone());
                w.sip_msgs += 1;
                w.sip_bytes += e.raw.len() as u64;
                if e.is_request {
                    match e
                        .method
                        .as_deref()
                        .map(|m| m.to_ascii_uppercase())
                        .as_deref()
                    {
                        Some("INVITE") => {
                            self.calls.invite += 1;
                            self.seizure_ids.insert(e.call_id.clone());
                            w.invites.insert(e.call_id.clone());
                        }
                        Some("BYE") => self.calls.bye += 1,
                        Some("CANCEL") => self.calls.cancel += 1,
                        _ => {}
                    }
                } else if let Some(status) = e.status {
                    let class = (status / 100) as usize;
                    if (1..=6).contains(&class) {
                        self.sip_class[class] += 1;
                    }
                }
            }
            Event::Txn(_) => self.events.txn += 1,
            Event::Call(e) => {
                self.events.call += 1;
                self.call_ids.insert(e.call_id.clone());
                if !matches!(e.kind, CallEvtKind::Teardown) {
                    return;
                }
                let w = self.windows.entry(win).or_default();
                w.teardowns += 1;
                w.calls.insert(e.call_id.clone());
                match e.state {
                    3 => self.calls.completed += 1,
                    4 => self.calls.failed += 1,
                    5 => self.calls.canceled += 1,
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
            Event::StreamSnap(e) => {
                self.events.stream_snap += 1;
                self.call_ids.insert(e.call_id.clone());
                let sid = StreamId {
                    ssrc: e.ssrc,
                    flow: e.flow,
                };
                let key = (e.call_id.clone(), sid);
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
                    key.clone(),
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
                let w = self.windows.entry(win).or_default();
                w.loss.add(pkts, lost, bytes_d);
                w.calls.insert(e.call_id.clone());
                w.streams.insert((e.call_id.clone(), e.ssrc));
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
            Event::RtcpRtt(e) => {
                self.events.rtcp_rtt += 1;
                self.rtt_sum += e.rtt_ms;
                self.rtt_n += 1;
                let w = self.windows.entry(win).or_default();
                w.rtt_sum += e.rtt_ms;
                w.rtt_n += 1;
            }
            Event::HealthBucket(_) => self.events.health += 1,
            Event::Error(_) => self.events.error += 1,
            Event::Diag(_) => self.events.diag += 1,
        }
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
            fail_pct: rate(self.calls.failed),
            cancel_pct: rate(self.calls.canceled),
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
                let asr_pct = if w.teardowns == 0 {
                    None
                } else {
                    Some(w.answered as f64 / w.teardowns as f64 * 100.0)
                };
                LossWindow {
                    start_ts_us,
                    calls: w.calls.len(),
                    streams: w.streams.len(),
                    invites: w.invites.len(),
                    teardowns: w.teardowns,
                    answered: w.answered,
                    asr_pct,
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
pub fn scan_path(path: impl AsRef<Path>, top_ips: usize) -> Result<EvlogStats> {
    let path = path.as_ref();
    let bytes = std::fs::metadata(path)?.len();
    let reader = EvlogReader::open(path)?;
    scan(reader, bytes, path.display().to_string(), top_ips)
}

pub fn scan(
    mut reader: EvlogReader,
    bytes: u64,
    file: String,
    top_ips: usize,
) -> Result<EvlogStats> {
    let tz = reader.tz_offset_secs();
    let mut acc = StatsAcc::new();
    while let Some(ev) = reader.next_event()? {
        acc.ingest(&ev);
    }
    Ok(acc.finish(file, bytes, tz, top_ips))
}

fn quality_weighted(
    q: &HashMap<(String, StreamId), StreamQuality>,
) -> (f64, u64, f64, u64, f64, u64) {
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
                "fail_pct": round2(r.fail_pct),
                "cancel_pct": round2(r.cancel_pct),
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
            "  rates     CCR={}  fail={}  cancel={}\n",
            fmt_pct(r.ccr_pct),
            fmt_pct(r.fail_pct),
            fmt_pct(r.cancel_pct)
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
            out.push_str("  top IPs   (by loss%)\n");
            for ip in &self.top_ips {
                out.push_str(&format!(
                    "    {:<16}  loss={}  pkts={}  lost={}  {}\n",
                    ip.ip,
                    fmt_pct(ip.loss_pct),
                    ip.pkts,
                    ip.lost,
                    fmt_bytes(ip.bytes)
                ));
            }
        }

        out.push_str("\n== 5-minute windows ==\n");
        out.push_str(&format!(
            "  {:<8} {:>7} {:>5} {:>6} {:>8} {:>10} {:>8} {:>7} {:>7}\n",
            "time", "invite", "ASR%", "teard", "rtp_bytes", "pkts", "loss%", "sip", "rtt"
        ));
        for w in &self.windows {
            out.push_str(&format!(
                "  {:<8} {:>7} {:>5} {:>6} {:>8} {:>10} {:>8} {:>7} {:>7}\n",
                fmt_time(w.start_ts_us, self.tz_offset_secs),
                w.invites,
                fmt_pct_short(w.asr_pct),
                w.teardowns,
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
    use crate::store::evlog::{CallEvt, CallEvtKind, EvlogWriter, SipMsgEvt, StreamSnapEvt};

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

        let reader = EvlogReader::new(std::io::Cursor::new(buf)).unwrap();
        let s = scan(reader, 0, "t.evlog".into(), 10).unwrap();
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
        assert_eq!(s.windows[1].pkts, 150);
        assert_eq!(s.windows[1].lost, 3);
        assert_eq!(s.loss.pkts, 250);
        assert_eq!(s.loss.lost, 5);
        assert_eq!(s.top_ips.len(), 2);
        let text = s.render_text();
        assert!(text.contains("Reliability"), "{text}");
        assert!(text.contains("ASR"), "{text}");
        assert!(text.contains("Traffic"), "{text}");
        assert!(text.contains("5-minute windows"), "{text}");
        let j = s.to_json();
        assert_eq!(j["calls"]["unique"], 2);
        assert_eq!(j["reliability"]["seizures"], 2);
        assert_eq!(j["reliability"]["answered"], 1);
        assert_eq!(j["traffic"]["rtp_bytes"], 40_000);
        assert_eq!(j["windows"].as_array().unwrap().len(), 2);
    }
}
