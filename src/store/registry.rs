use std::collections::{HashMap, HashSet, VecDeque};

use crate::diagnostics::Diagnostic;
use crate::model::media::StreamSummary;
use crate::model::sip::{B2buaInfo, Call, CallState, HangupBy, Method, Outcome, SipMsg};
use crate::store::ipstats::{Dir, IpStats, IpStatsStore};

/// Focused-call detail payload for the Call Detail page.
#[derive(Debug, Clone, Default)]
pub struct Focus {
    pub call_id: String,
    pub state: Option<CallState>,
    pub from_user: Option<String>,
    pub to_user: Option<String>,
    /// Caller-side UA string (User-Agent of the initial INVITE).
    pub caller_ua: Option<String>,
    /// Callee-side UA string (Server/User-Agent of the first response).
    pub callee_ua: Option<String>,
    /// Caller signaling address (src of the initial INVITE).
    pub caller_addr: Option<std::net::SocketAddr>,
    /// Caller signaling IP (from the initial INVITE; survives message trimming
    /// via the call's `invite_key`). Used to split media into TX/RX.
    pub caller_ip: Option<std::net::IpAddr>,
    /// Callee signaling address (src of the first response).
    pub callee_addr: Option<std::net::SocketAddr>,
    pub messages: Vec<SipMsg>,
    /// Dialog (leg) index per message, parallel to `messages`. Messages of the
    /// same dialog share a leg index; a call with ≥2 legs is a same-Call-ID
    /// B2BUA split. Legs are derived from `from_tag` (fallback `branch`).
    pub legs: Vec<u8>,
    /// B2BUA evidence: dual-dialog split within this Call-ID, or a pairing
    /// with a sibling call-id whose INVITE the B2BUA rewrote.
    pub b2bua: Option<B2buaInfo>,
    pub streams: Vec<StreamSummary>,
    pub diagnostics: Vec<Diagnostic>,
    pub negotiated_endpoints: Vec<std::net::SocketAddr>,
    /// Call timing / outcome details for the header block.
    pub pdd_ms: Option<u32>,
    pub setup_ms: Option<u32>,
    pub ring_ms: Option<u32>,
    /// True if early media (183 with SDP) was negotiated.
    pub early_media: bool,
    /// Milestone timestamps for the setup timeline (chrome-devtools-style).
    pub invite_ts: Option<u64>,
    pub trying_ts: Option<u64>,
    pub ringing_ts: Option<u64>,
    pub answer_ts: Option<u64>,
    pub bye_ts: Option<u64>,
    pub end_ts: Option<u64>,
    pub hangup_by: Option<HangupBy>,
    pub hangup_code: Option<u32>,
    pub hangup_reason: Option<String>,
}

/// One RTP/RTCP stream keyed by (5-tuple, ssrc).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StreamKey {
    pub flow: crate::model::packet::Flow5Tuple,
    pub ssrc: u32,
}

/// Identity of an imported (replay) stream. `flow` is None for older/partial
/// summaries that didn't carry a 5-tuple.
#[derive(Clone, PartialEq, Eq, Hash)]
struct ImportKey {
    call_id: String,
    ssrc: u32,
    flow: Option<crate::model::packet::Flow5Tuple>,
}

fn import_key(s: &StreamSummary) -> ImportKey {
    ImportKey {
        call_id: s.call_id.clone().unwrap_or_default(),
        ssrc: s.ssrc,
        flow: s.flow,
    }
}

/// Recent-activity ordering helper.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CallSummary {
    pub call_id: String,
    pub from_user: Option<String>,
    pub to_user: Option<String>,
    /// Source IP of the initial INVITE (the caller side).
    pub caller_ip: Option<std::net::IpAddr>,
    pub state: CallState,
    pub outcome: Outcome,
    pub invite_ts: Option<u64>,
    pub duration_ms: Option<u64>,
    pub pdd_ms: Option<u32>,
    pub setup_ms: Option<u32>,
    /// Ringing duration (ring → answer).
    pub ring_ms: Option<u32>,
    /// Provisional code that started ringing: 180 or 183.
    pub ring_code: Option<u16>,
    /// True if early media (183 with SDP) was negotiated.
    pub early_media: bool,
    /// Who initiated the hangup.
    pub hangup_by: Option<HangupBy>,
    pub hangup_code: Option<u32>,
    pub pkts_sip: u64,
    pub pkts_rtp: u64,
    pub best_mos: Option<f64>,
    pub warn_count: u32,
    pub critical_count: u32,
    pub stream_count: usize,
    /// True if the call's media traversed a learned TURN relay.
    pub via_turn: bool,
    /// Distinct IPs involved in the call (drill-down from the IP page).
    pub ips: Vec<std::net::IpAddr>,
}

/// Lightweight immutable snapshot for the TUI/export.
#[derive(Debug, Clone, Default)]
pub struct Snapshot {
    pub source: String,
    pub elapsed_us: Option<u64>,
    /// Absolute (epoch us) timestamp of the first observed frame: the
    /// recording/session start used to compute each event's already-recorded
    /// duration in the Call Detail flow / call lists.
    pub start_us: Option<u64>,
    /// UTC offset (seconds) of the machine that recorded the event log, when
    /// known (replay). Used to render the original local wall-clock.
    pub tz_offset_secs: Option<i32>,
    pub pps: f64,
    pub pkts_total: u64,
    #[allow(dead_code)]
    pub pkts_dropped: u64,
    pub calls_total: u64,
    pub active: usize,
    pub completed: usize,
    pub failed: usize,
    pub avg_pdd_ms: f64,
    pub avg_setup_ms: f64,
    pub avg_jitter_ms: f64,
    pub avg_loss_pct: f64,
    pub avg_rtt_ms: f64,
    pub avg_mos: f64,
    pub asr: f64,
    pub calls: Vec<CallSummary>,
    pub streams: Vec<StreamSummary>,
    pub events: VecDeque<String>,
    /// Diagnostics for the focused call (filtered by the UI).
    pub diagnostics: Vec<Diagnostic>,
    /// Per-IP network stats (IP page).
    pub ip_stats: Vec<IpStats>,
    /// Heatmap cells: (bucket_us, key, metrics).
    pub buckets: Vec<(u64, String, crate::model::stats::MetricSet)>,
    /// Focused call detail (set by the UI via Correlator focus hint).
    pub focus: Option<Focus>,
    #[allow(dead_code)]
    pub paused: bool,
}

/// In-memory application state. Updated by the pipeline thread, snapshotted by
/// the UI/export thread.
pub struct Registry {
    pub calls: HashMap<String, Call>,
    /// Insertion order for stable recent-first listing.
    pub order: Vec<String>,
    pub streams: HashMap<StreamKey, crate::correlate::stream::RtpStream>,
    /// call_id per stream (reverse lookup).
    pub stream_call: HashMap<StreamKey, String>,
    /// SDP-advertised media endpoint -> call_id (for RTP association).
    pub endpoint_call: HashMap<std::net::SocketAddr, String>,
    pub events: VecDeque<String>,
    pub source: String,
    pub start_us: Option<u64>,
    pub last_us: Option<u64>,
    pub pkts_total: u64,
    /// UTC offset (seconds) of the machine that recorded the event log
    /// (populated on replay); used to render the original local wall-clock.
    pub tz_offset_secs: Option<i32>,
    #[allow(dead_code)]
    pub pkts_dropped: u64,
    pub pkts_last_window: u64,
    pub window_start_us: Option<u64>,
    pub pps: f64,
    pub completed: u64,
    pub failed: u64,
    /// Diagnostic ring buffer.
    pub diagnostics: VecDeque<Diagnostic>,
    /// Heatmap aggregation buckets.
    pub heatmap: crate::store::heatmap::Heatmap,
    /// UI focus hint: call id whose detail should be included in snapshots.
    pub focus_hint: Option<String>,
    /// Call-ids removed by eviction since the last drain (lets the correlator
    /// prune its own per-call maps like `invite_rr` / `terminal_done`, keeping
    /// long-running sessions bounded).
    pub removed: VecDeque<String>,
    /// Heatmap bucket window in microseconds (older buckets are pruned).
    pub heatmap_retain_us: u64,
    /// Per-call stream index (call_id -> stream keys): keeps per-packet and
    /// per-call paths O(streams-in-call) instead of O(total streams).
    pub stream_index: HashMap<String, Vec<StreamKey>>,
    /// SSRC -> stream keys: O(1) RTCP sample attachment (no full scan).
    pub ssrc_index: HashMap<u32, Vec<StreamKey>>,
    /// Per-IP packet/loss statistics (updated on the RTP hot path + 5s flush).
    pub ipstats: IpStatsStore,
    /// Stream summaries reconstructed from a replay/import, keyed for O(1)
    /// upsert (StreamSnap is emitted every 5s; a Vec + linear scan was O(n²)
    /// on multi-hour recordings).
    imported_streams: HashMap<ImportKey, StreamSummary>,
    /// call_id → import keys, so summarize/focus don't scan every imported stream.
    imported_by_call: HashMap<String, Vec<ImportKey>>,
    pub max_calls: usize,
    pub max_streams: usize,
    pub max_diagnostics: usize,
}

impl Default for Registry {
    fn default() -> Self {
        Self {
            calls: HashMap::new(),
            order: Vec::new(),
            streams: HashMap::new(),
            stream_call: HashMap::new(),
            endpoint_call: HashMap::new(),
            events: VecDeque::with_capacity(512),
            source: String::new(),
            start_us: None,
            last_us: None,
            pkts_total: 0,
            tz_offset_secs: None,
            pkts_dropped: 0,
            pkts_last_window: 0,
            window_start_us: None,
            pps: 0.0,
            completed: 0,
            failed: 0,
            diagnostics: VecDeque::new(),
            heatmap: crate::store::heatmap::Heatmap::new(900),
            focus_hint: None,
            stream_index: HashMap::new(),
            ssrc_index: HashMap::new(),
            ipstats: IpStatsStore::new(),
            imported_streams: HashMap::new(),
            imported_by_call: HashMap::new(),
            removed: VecDeque::new(),
            heatmap_retain_us: 24 * 3600 * 1_000_000,
            max_calls: 100_000,
            max_streams: 50_000,
            max_diagnostics: 50_000,
        }
    }
}

impl Registry {
    pub fn with_source(source: String) -> Self {
        Self {
            source,
            ..Self::default()
        }
    }

    pub fn set_caps(&mut self, max_calls: usize, max_streams: usize, max_diagnostics: usize) {
        self.max_calls = max_calls;
        self.max_streams = max_streams;
        self.max_diagnostics = max_diagnostics;
    }

    pub fn set_bucket(&mut self, bucket_secs: u64) {
        let heat = std::mem::replace(
            &mut self.heatmap,
            crate::store::heatmap::Heatmap::new(bucket_secs),
        );
        if heat.bucket_secs() != bucket_secs {
            // Buckets are incompatible; rebuild empty (v1: heatmap is
            // forward-accumulating only).
        }
    }

    /// Reset all runtime state (the `x` / clear shortcut): calls, streams,
    /// diagnostics, events, heatmap, per-IP stats and counters. The evlog
    /// writer keeps its own file and is unaffected.
    pub fn clear(&mut self) {
        self.calls.clear();
        self.order.clear();
        self.streams.clear();
        self.stream_call.clear();
        self.endpoint_call.clear();
        self.stream_index.clear();
        self.ssrc_index.clear();
        self.events.clear();
        self.diagnostics.clear();
        self.heatmap = crate::store::heatmap::Heatmap::new(self.heatmap.bucket_secs());
        self.ipstats.clear();
        self.imported_streams.clear();
        self.imported_by_call.clear();
        self.pkts_total = 0;
        self.pkts_last_window = 0;
        self.window_start_us = None;
        self.start_us = None;
        self.last_us = None;
        self.pps = 0.0;
        self.completed = 0;
        self.failed = 0;
        self.focus_hint = None;
    }

    /// Record that `key` belongs to `call_id` (called on stream creation).
    pub fn note_stream(&mut self, call_id: &str, key: StreamKey) {
        self.stream_index
            .entry(call_id.to_string())
            .or_default()
            .push(key);
        self.ssrc_index.entry(key.ssrc).or_default().push(key);
    }

    /// Remove a stream key from the per-call index (and reverse maps).
    fn forget_stream(&mut self, key: &StreamKey) {
        if let Some(cid) = self.stream_call.remove(key)
            && let Some(v) = self.stream_index.get_mut(&cid)
        {
            v.retain(|k| k != key);
            if v.is_empty() {
                self.stream_index.remove(&cid);
            }
        }
        if let Some(v) = self.ssrc_index.get_mut(&key.ssrc) {
            v.retain(|k| k != key);
            if v.is_empty() {
                self.ssrc_index.remove(&key.ssrc);
            }
        }
    }

    /// Streams belonging to a call (empty slice if none).
    pub fn call_stream_keys(&self, call_id: &str) -> &[StreamKey] {
        self.stream_index
            .get(call_id)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Drain the list of call-ids removed since last call.
    pub fn drain_removed(&mut self) -> Vec<String> {
        self.removed.drain(..).collect()
    }

    /// Prune heatmap buckets older than the retention window.
    pub fn prune_heatmap(&mut self) {
        if let Some(last) = self.last_us {
            let cutoff = last.saturating_sub(self.heatmap_retain_us);
            self.heatmap.prune_older_than(cutoff);
        }
    }

    /// Evict oldest *terminated* calls when above `max_calls`. Falls back to
    /// evicting the oldest active call only if all are still active.
    pub fn evict_if_needed(&mut self) {
        while self.calls.len() > self.max_calls {
            // Find oldest terminated call by invite_ts.
            let target = self
                .order
                .iter()
                .filter_map(|id| self.calls.get(id))
                .filter(|c| {
                    matches!(
                        c.state,
                        CallState::Completed | CallState::Failed | CallState::Canceled
                    )
                })
                .min_by_key(|c| c.invite_ts.unwrap_or(u64::MAX))
                .map(|c| c.call_id.clone());

            let cid = target
                .or_else(|| {
                    // All active; evict oldest by invite_ts.
                    self.order
                        .iter()
                        .filter_map(|id| self.calls.get(id))
                        .min_by_key(|c| c.invite_ts.unwrap_or(u64::MAX))
                        .map(|c| c.call_id.clone())
                })
                .unwrap_or_else(|| self.order.first().cloned().unwrap_or_default());

            if cid.is_empty() {
                break;
            }
            self.remove_call(&cid);
        }

        // Stream eviction.
        if self.streams.len() > self.max_streams {
            let mut keyed: Vec<(StreamKey, u64)> = self
                .streams
                .iter()
                .map(|(k, s)| (*k, s.first_ts_us.unwrap_or(u64::MAX)))
                .collect();
            keyed.sort_by_key(|(_, t)| *t);
            let to_remove: Vec<StreamKey> = keyed
                .into_iter()
                .take(self.streams.len().saturating_sub(self.max_streams))
                .map(|(k, _)| k)
                .collect();
            for k in to_remove {
                self.streams.remove(&k);
                self.forget_stream(&k);
            }
        }
    }

    /// Drop idle and terminated calls older than `ttl_secs` of capture time.
    /// `ttl_secs == 0` disables time-based eviction (file/replay).
    pub fn evict_stale(&mut self, ttl_secs: u64, now_us: u64) {
        if ttl_secs == 0 || now_us == 0 {
            return;
        }
        let cutoff = now_us.saturating_sub(ttl_secs.saturating_mul(1_000_000));
        let focus = self.focus_hint.clone();
        let stale: Vec<String> = self
            .calls
            .iter()
            .filter(|(id, c)| {
                if focus.as_deref() == Some(id.as_str()) {
                    return false;
                }
                let terminal = matches!(
                    c.state,
                    CallState::Completed | CallState::Failed | CallState::Canceled
                );
                let t = if terminal {
                    c.end_ts.or(c.bye_ts).unwrap_or(c.last_ts_us)
                } else {
                    c.last_ts_us
                };
                t != 0 && t < cutoff
            })
            .map(|(id, _)| id.clone())
            .collect();
        self.remove_calls(&stale);
    }

    /// Remove a call and its streams from in-memory indexes.
    pub(crate) fn remove_call(&mut self, call_id: &str) {
        self.remove_calls(&[call_id.to_string()]);
    }

    fn remove_calls(&mut self, ids: &[String]) {
        if ids.is_empty() {
            return;
        }
        let drop: HashSet<String> = ids.iter().cloned().collect();
        for id in ids {
            self.calls.remove(id);
            self.removed.push_back(id.clone());
            let stream_keys: Vec<StreamKey> = self.stream_index.remove(id).unwrap_or_default();
            for k in stream_keys {
                self.streams.remove(&k);
                self.stream_call.remove(&k);
                if let Some(v) = self.ssrc_index.get_mut(&k.ssrc) {
                    v.retain(|k2| k2 != &k);
                    if v.is_empty() {
                        self.ssrc_index.remove(&k.ssrc);
                    }
                }
            }
        }
        self.order.retain(|id| !drop.contains(id));
        self.endpoint_call.retain(|_, v| !drop.contains(v));
    }

    pub fn touch_time(&mut self, ts_us: u64) {
        if self.start_us.is_none() {
            self.start_us = Some(ts_us);
        }
        self.last_us = Some(ts_us);
        // pps over a 1s sliding window.
        match self.window_start_us {
            None => self.window_start_us = Some(ts_us),
            Some(w) => {
                if ts_us.saturating_sub(w) >= 1_000_000 {
                    let elapsed_s = (ts_us.saturating_sub(w)) as f64 / 1_000_000.0;
                    self.pps = self.pkts_last_window as f64 / elapsed_s.max(1e-6);
                    self.pkts_last_window = 0;
                    self.window_start_us = Some(ts_us);
                }
            }
        }
        self.pkts_last_window += 1;
    }

    /// Record the session/replay start if not already set (used by replay so
    /// the first evlog event, not just the first SIP message, anchors the
    /// already-recorded-duration delta).
    pub fn ensure_start(&mut self, ts_us: u64) {
        if self.start_us.is_none() {
            self.start_us = Some(ts_us);
        }
    }

    pub fn get_or_create_call(&mut self, call_id: &str) -> &mut Call {
        if !self.calls.contains_key(call_id) {
            self.calls
                .insert(call_id.to_string(), Call::new(call_id.to_string()));
            self.order.push(call_id.to_string());
        }
        self.calls.get_mut(call_id).unwrap()
    }

    pub fn push_event(&mut self, line: String) {
        self.events.push_back(line);
        while self.events.len() > 1000 {
            self.events.pop_front();
        }
    }

    /// Register a stream summary reconstructed from an evlog record (replay
    /// path). Consecutive snaps of the same (call, ssrc, flow) replace the
    /// previous row so the Streams page doesn't accumulate one row per 5s flush.
    pub fn add_imported_stream(&mut self, s: StreamSummary) {
        let key = import_key(&s);
        if let Some(slot) = self.imported_streams.get_mut(&key) {
            *slot = s;
            return;
        }
        if self.imported_streams.len() >= self.max_streams {
            return;
        }
        if !key.call_id.is_empty() {
            self.imported_by_call
                .entry(key.call_id.clone())
                .or_default()
                .push(key.clone());
        }
        self.imported_streams.insert(key, s);
    }

    /// Import a StreamSnap from an evlog (replay). Upserts the stream summary
    /// and attributes the packet/loss *delta* since the previous snap of the
    /// same stream onto per-IP stats.
    pub fn import_stream_snap(&mut self, ts_us: u64, s: StreamSummary) {
        if ts_us > self.last_us.unwrap_or(0) {
            self.last_us = Some(ts_us);
        }
        let key = import_key(&s);
        let (prev_pkts, prev_lost, prev_bytes) = self
            .imported_streams
            .get(&key)
            .map(|p| (p.packets, p.lost, p.bytes))
            .unwrap_or((0, 0, 0));
        let pkts_delta = s.packets.saturating_sub(prev_pkts);
        let lost_delta = s.lost.saturating_sub(prev_lost);
        let bytes_delta = s.bytes.saturating_sub(prev_bytes);
        let flow = s.flow;
        self.add_imported_stream(s);
        let Some(flow) = flow else {
            return;
        };
        if pkts_delta > 0 || bytes_delta > 0 {
            self.ipstats
                .observe_packets(flow.src.ip(), ts_us, pkts_delta, bytes_delta, Dir::Tx);
            self.ipstats
                .observe_packets(flow.dst.ip(), ts_us, pkts_delta, bytes_delta, Dir::Rx);
        }
        if lost_delta > 0 {
            self.ipstats
                .observe_lost(flow.src.ip(), ts_us, lost_delta, Dir::Tx);
            self.ipstats
                .observe_lost(flow.dst.ip(), ts_us, lost_delta, Dir::Rx);
        }
    }

    fn imported_for_call(&self, call_id: &str) -> impl Iterator<Item = &StreamSummary> {
        self.imported_by_call
            .get(call_id)
            .into_iter()
            .flatten()
            .filter_map(|k| self.imported_streams.get(k))
    }

    /// Build a UI snapshot: recent calls capped to `limit`, streams capped to
    /// 1000 (display only; exports use `snapshot_full`).
    pub fn snapshot(&self, limit: usize) -> Snapshot {
        self.snapshot_with(limit, 1000)
    }

    /// Full-fidelity snapshot for exports / end-of-run output.
    pub fn snapshot_full(&self) -> Snapshot {
        self.snapshot_with(usize::MAX, usize::MAX)
    }

    pub fn snapshot_with(&self, limit: usize, stream_limit: usize) -> Snapshot {
        let mut summaries: Vec<CallSummary> = self
            .order
            .iter()
            .rev()
            .take(limit)
            .filter_map(|id| self.calls.get(id))
            .map(|c| self.summarize(c))
            .collect();

        let (active_n, comp_n, fail_n) =
            summaries
                .iter()
                .fold((0usize, 0usize, 0usize), |(a, c, f), s| match s.state {
                    CallState::Dialing | CallState::Ringing | CallState::Active => (a + 1, c, f),
                    CallState::Completed => (a, c + 1, f),
                    CallState::Failed | CallState::Canceled => (a, c, f + 1),
                });

        // aggregate averages over terminated calls with data.
        let mut pdd = 0.0;
        let mut pdd_n = 0u64;
        let mut setup = 0.0;
        let mut setup_n = 0u64;
        for c in self.calls.values() {
            if let Some(p) = c.pdd_ms {
                pdd += p as f64;
                pdd_n += 1;
            }
            if let Some(s) = c.setup_ms {
                setup += s as f64;
                setup_n += 1;
            }
        }
        let mut jit = 0.0;
        let mut jit_n = 0u64;
        let mut loss = 0.0;
        let mut loss_n = 0u64;
        let mut mos = 0.0;
        let mut mos_n = 0u64;
        let mut rtt = 0.0;
        let mut rtt_n = 0u64;
        for s in self.streams.values() {
            let st = s.summary();
            if let Some(j) = st.jitter_ms {
                jit += j;
                jit_n += 1;
            }
            loss += st.loss_pct;
            loss_n += 1;
            if let Some(m) = st.mos {
                mos += m;
                mos_n += 1;
            }
            if let Some(r) = st.rtt_avg_ms {
                rtt += r;
                rtt_n += 1;
            }
        }
        for s in self.imported_streams.values() {
            if let Some(j) = s.jitter_ms {
                jit += j;
                jit_n += 1;
            }
            loss += s.loss_pct;
            loss_n += 1;
            if let Some(m) = s.mos {
                mos += m;
                mos_n += 1;
            }
            if let Some(r) = s.rtt_avg_ms {
                rtt += r;
                rtt_n += 1;
            }
        }
        let avg = |sum: f64, n: u64| if n == 0 { 0.0 } else { sum / n as f64 };
        let calls_total = self.completed + self.failed + active_n as u64;
        let answered = self.completed;
        let asr = if calls_total == 0 {
            0.0
        } else {
            answered as f64 / calls_total as f64 * 100.0
        };

        summaries.sort_by_key(|s| std::cmp::Reverse(s.invite_ts.unwrap_or(0)));

        Snapshot {
            source: self.source.clone(),
            elapsed_us: match (self.start_us, self.last_us) {
                (Some(a), Some(b)) => Some(b.saturating_sub(a)),
                _ => None,
            },
            start_us: self.start_us,
            tz_offset_secs: self.tz_offset_secs,
            pps: self.pps,
            pkts_total: self.pkts_total,
            pkts_dropped: self.pkts_dropped,
            calls_total: calls_total.max(self.calls.len() as u64),
            active: active_n,
            completed: comp_n,
            failed: fail_n,
            avg_pdd_ms: avg(pdd, pdd_n),
            avg_setup_ms: avg(setup, setup_n),
            avg_jitter_ms: avg(jit, jit_n),
            avg_loss_pct: avg(loss, loss_n),
            avg_rtt_ms: avg(rtt, rtt_n),
            avg_mos: avg(mos, mos_n),
            asr,
            calls: summaries,
            streams: {
                let mut s: Vec<_> = self
                    .streams
                    .values()
                    .take(stream_limit)
                    .map(|s| s.summary())
                    .collect();
                let remaining = stream_limit.saturating_sub(s.len());
                s.extend(self.imported_streams.values().take(remaining).cloned());
                s
            },
            events: self.events.clone(),
            diagnostics: self.diagnostics.iter().cloned().collect(),
            ip_stats: self.ipstats.snapshot(),
            buckets: self.heatmap.flat(),
            focus: self
                .focus_hint
                .as_ref()
                .and_then(|id| self.focus_detail(id)),
            paused: false,
        }
    }

    /// Build the focus payload for the Call Detail page.
    fn focus_detail(&self, call_id: &str) -> Option<Focus> {
        let call = self.calls.get(call_id)?;
        let msgs = if call.messages.len() > 1000 {
            call.messages[call.messages.len() - 1000..].to_vec()
        } else {
            call.messages.clone()
        };
        // Party identities from the SIP messages: the initial INVITE identifies
        // the caller, the first response identifies the callee.
        let invite = msgs.iter().find(|m| {
            m.is_request && matches!(m.method, Some(Method::Invite)) && m.to_tag.is_none()
        });
        let response = msgs.iter().find(|m| !m.is_request);
        let caller_ua = invite.and_then(|m| sip_header(&m.raw, "User-Agent"));
        let callee_ua = response
            .and_then(|m| sip_header(&m.raw, "Server"))
            .or_else(|| response.and_then(|m| sip_header(&m.raw, "User-Agent")));
        let caller_addr = invite.map(|m| m.flow.src);
        let callee_addr = response.map(|m| m.flow.src);
        // Caller IP survives message trimming via the call's invite_key.
        let caller_ip = invite
            .map(|m| m.flow.src.ip())
            .or_else(|| call.invite_key.as_deref().and_then(|k| k.parse().ok()));
        let mut streams: Vec<_> = self
            .call_stream_keys(call_id)
            .iter()
            .filter_map(|k| self.streams.get(k))
            .map(|s| s.summary())
            .collect();
        streams.extend(self.imported_for_call(call_id).cloned());
        let diagnostics = self
            .diagnostics
            .iter()
            .filter(|d| d.call_id == call_id)
            .cloned()
            .collect();
        // Dialog (leg) derivation: every message of a dialog shares the same
        // From tag (fallback: branch). ≥2 distinct legs inside one Call-ID is a
        // same-Call-ID B2BUA split.
        let (legs, leg_count) = dialog_legs(&msgs);
        let b2bua = (leg_count >= 2).then(|| B2buaInfo {
            addr: common_flow_ip(&msgs, &legs),
            legs: leg_count,
        });
        Some(Focus {
            call_id: call_id.to_string(),
            state: Some(call.state),
            from_user: call.from_user.clone(),
            to_user: call.to_user.clone(),
            caller_ua,
            callee_ua,
            caller_addr,
            caller_ip,
            callee_addr,
            messages: msgs,
            legs,
            b2bua,
            streams,
            diagnostics,
            negotiated_endpoints: call.negotiated.endpoints.clone(),
            pdd_ms: call.pdd_ms,
            setup_ms: call.setup_ms,
            ring_ms: call.ring_ms,
            early_media: call.early_media,
            invite_ts: call.invite_ts,
            trying_ts: call.trying_ts,
            ringing_ts: call.ringing_ts,
            answer_ts: call.answer_ts,
            bye_ts: call.bye_ts,
            end_ts: call.end_ts,
            hangup_by: call.hangup_by,
            hangup_code: call.hangup.code,
            hangup_reason: call.hangup.reason.clone(),
        })
    }

    fn summarize(&self, c: &Call) -> CallSummary {
        let keys = self.call_stream_keys(&c.call_id);
        let imported: Vec<&StreamSummary> = self.imported_for_call(&c.call_id).collect();
        let best_mos = keys
            .iter()
            .filter_map(|k| self.streams.get(k))
            .filter_map(|s| s.summary().mos)
            .chain(imported.iter().filter_map(|s| s.mos))
            .fold(None, |acc: Option<f64>, m| {
                Some(acc.map_or(m, |a| a.min(m)))
            });
        let stream_count = keys.len() + imported.len();
        let imported_pkts_rtp: u64 = imported.iter().map(|s| s.packets).sum();
        CallSummary {
            call_id: c.call_id.clone(),
            from_user: c.from_user.clone(),
            to_user: c.to_user.clone(),
            caller_ip: c.invite_key.as_deref().and_then(|k| k.parse().ok()),
            state: c.state,
            outcome: c.outcome,
            invite_ts: c.invite_ts,
            duration_ms: c.duration_ms(),
            pdd_ms: c.pdd_ms,
            setup_ms: c.setup_ms,
            ring_ms: c.ring_ms,
            ring_code: c.ring_code,
            early_media: c.early_media,
            hangup_by: c.hangup_by,
            hangup_code: c.hangup.code,
            pkts_sip: c.pkts_sip,
            pkts_rtp: c.pkts_rtp + imported_pkts_rtp,
            best_mos,
            warn_count: c.warn_count,
            critical_count: c.critical_count,
            stream_count,
            via_turn: c.via_turn,
            ips: c.ips.clone(),
        }
    }

    /// Call summaries for a specific call (for call-detail view).
    #[allow(dead_code)]
    pub fn call_messages(&self, call_id: &str) -> Option<&[crate::model::sip::SipMsg]> {
        self.calls.get(call_id).map(|c| c.messages.as_slice())
    }
}

/// Extract the value of a single-line SIP header from raw message bytes.
fn sip_header(raw: &[u8], name: &str) -> Option<String> {
    let text = std::str::from_utf8(raw).ok()?;
    text.lines().find_map(|line| {
        let (n, v) = line.split_once(':')?;
        n.trim()
            .eq_ignore_ascii_case(name)
            .then(|| v.trim().to_string())
    })
}

/// Per-message dialog (leg) index, keyed by From tag (fallback: branch).
/// Returns (per-message legs, number of distinct legs). Messages without any
/// tag key collapse into leg 0.
fn dialog_legs(msgs: &[SipMsg]) -> (Vec<u8>, u8) {
    let mut leg_of: std::collections::HashMap<String, u8> = std::collections::HashMap::new();
    let legs: Vec<u8> = msgs
        .iter()
        .map(|m| {
            let key = m
                .from_tag
                .clone()
                .or_else(|| m.branch.clone())
                .unwrap_or_default();
            if key.is_empty() {
                0
            } else {
                let n = leg_of.len().min(u8::MAX as usize) as u8;
                *leg_of.entry(key).or_insert(n)
            }
        })
        .collect();
    let count = leg_of.len().max(1).min(u8::MAX as usize) as u8;
    (legs, count)
}

/// The one IP shared by the flows of both the first two legs — i.e. the
/// B2BUA/SBC in a same-Call-ID dual-dialog split. None when ambiguous.
fn common_flow_ip(msgs: &[SipMsg], legs: &[u8]) -> Option<std::net::IpAddr> {
    let mut by_leg: std::collections::HashMap<u8, Vec<std::net::IpAddr>> =
        std::collections::HashMap::new();
    for (m, l) in msgs.iter().zip(legs) {
        by_leg
            .entry(*l)
            .or_default()
            .extend([m.flow.src.ip(), m.flow.dst.ip()]);
    }
    let l0 = by_leg.get(&0)?;
    let l1 = by_leg.get(&1)?;
    let shared: Vec<std::net::IpAddr> = l0.iter().copied().filter(|ip| l1.contains(ip)).collect();
    (shared.len() == 1).then(|| shared[0])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::media::StreamSummary;
    use crate::model::packet::{Flow5Tuple, Proto};
    use crate::model::sip::Method;

    fn mk_sip(from_tag: Option<&str>, from: &str, to: &str) -> SipMsg {
        SipMsg {
            ts_us: 0,
            flow: Flow5Tuple {
                proto: Proto::Udp,
                src: from.parse().unwrap(),
                dst: to.parse().unwrap(),
            },
            is_request: true,
            method: Some(Method::Invite),
            status: None,
            call_id: "c1".into(),
            cseq: Some(1),
            cseq_method: Some("INVITE".into()),
            branch: Some("b".into()),
            from_tag: from_tag.map(str::to_owned),
            to_tag: None,
            from_uri: None,
            to_uri: None,
            raw: bytes::Bytes::new(),
            contact_addr: None,
            route_count: 0,
            record_route_count: 0,
            has_sdp: false,
        }
    }

    #[test]
    fn dialog_legs_groups_by_from_tag() {
        let msgs = vec![
            mk_sip(Some("t1"), "1.1.1.1:5060", "2.2.2.2:5060"),
            mk_sip(Some("t2"), "2.2.2.2:5060", "3.3.3.3:5060"),
            mk_sip(Some("t1"), "2.2.2.2:5060", "1.1.1.1:5060"),
        ];
        let (legs, n) = dialog_legs(&msgs);
        assert_eq!(legs, vec![0, 1, 0]);
        assert_eq!(n, 2);
        // A re-INVITE (same From tag) stays in the same dialog → not a B2BUA.
        let msgs2 = vec![
            mk_sip(Some("t1"), "1.1.1.1:5060", "2.2.2.2:5060"),
            mk_sip(Some("t1"), "1.1.1.1:5060", "2.2.2.2:5060"),
        ];
        let (_, n2) = dialog_legs(&msgs2);
        assert_eq!(n2, 1);
    }

    #[test]
    fn common_flow_ip_finds_same_call_id_b2bua() {
        let msgs = vec![
            mk_sip(Some("t1"), "1.1.1.1:5060", "2.2.2.2:5060"),
            mk_sip(Some("t2"), "2.2.2.2:5060", "3.3.3.3:5060"),
        ];
        let (legs, _) = dialog_legs(&msgs);
        assert_eq!(
            common_flow_ip(&msgs, &legs),
            Some("2.2.2.2".parse().unwrap()),
            "shared flow IP (the B2BUA) must be found"
        );
        // No shared IP → None (ambiguous).
        let msgs2 = vec![
            mk_sip(Some("t1"), "1.1.1.1:5060", "2.2.2.2:5060"),
            mk_sip(Some("t2"), "3.3.3.3:5060", "4.4.4.4:5060"),
        ];
        let (legs2, _) = dialog_legs(&msgs2);
        assert_eq!(common_flow_ip(&msgs2, &legs2), None);
    }

    #[test]
    fn focus_detail_exposes_legs_and_b2bua() {
        let mut reg = Registry::with_source("t".into());
        let call = reg.get_or_create_call("c1");
        call.from_user = Some("alice".into());
        call.to_user = Some("bob".into());
        call.invite_ts = Some(1_000_000);
        let msgs = vec![
            mk_sip(Some("t1"), "1.1.1.1:5060", "2.2.2.2:5060"),
            mk_sip(Some("t2"), "2.2.2.2:5060", "3.3.3.3:5060"),
        ];
        call.messages = msgs;
        reg.focus_hint = Some("c1".into());
        let focus = reg.snapshot_full().focus.expect("focus detail present");
        assert_eq!(focus.legs, vec![0, 1]);
        let b2bua = focus.b2bua.expect("same Call-ID split must be detected");
        assert_eq!(b2bua.legs, 2);
        assert_eq!(b2bua.addr, Some("2.2.2.2".parse().unwrap()));
    }

    #[test]
    fn focus_detail_no_b2bua_for_single_dialog() {
        let mut reg = Registry::with_source("t".into());
        let call = reg.get_or_create_call("c1");
        call.from_user = Some("alice".into());
        call.to_user = Some("bob".into());
        call.invite_ts = Some(1_000_000);
        call.messages = vec![
            mk_sip(Some("t1"), "1.1.1.1:5060", "2.2.2.2:5060"),
            mk_sip(Some("t1"), "2.2.2.2:5060", "1.1.1.1:5060"),
        ];
        reg.focus_hint = Some("c1".into());
        let focus = reg.snapshot_full().focus.expect("focus detail present");
        assert_eq!(focus.legs, vec![0, 0]);
        assert!(focus.b2bua.is_none(), "single dialog must not be a B2BUA");
    }

    #[test]
    fn imported_streams_surface_in_snapshot_focus_and_summary() {
        let mut reg = Registry::with_source("replay".into());
        reg.get_or_create_call("c1");
        let mut st = StreamSummary {
            ssrc: 0x1000,
            packets: 500,
            lost: 4,
            loss_pct: 0.8,
            bytes: 4000,
            mos: Some(4.3),
            ..StreamSummary::default()
        };
        st.call_id = Some("c1".into());
        reg.add_imported_stream(st);

        // Snapshot streams include the imported stream.
        let snap = reg.snapshot_full();
        assert_eq!(snap.streams.len(), 1);
        assert_eq!(snap.streams[0].ssrc, 0x1000);

        // Focus detail (Call Detail media table) includes it with flow/pkts.
        reg.focus_hint = Some("c1".into());
        let snap = reg.snapshot_full();
        let focus = snap.focus.expect("focus detail present");
        assert_eq!(focus.streams.len(), 1, "media table must show the stream");
        assert_eq!(focus.streams[0].packets, 500);
        assert_eq!(focus.streams[0].bytes, 4000);

        // Call summary aggregates RTP packets + MOS from imported streams.
        let call = &snap.calls[0];
        assert_eq!(call.pkts_rtp, 500);
        assert_eq!(call.best_mos, Some(4.3));
        assert_eq!(call.stream_count, 1);
    }

    #[test]
    fn import_stream_snap_feeds_ip_stats_and_upserts() {
        let mut reg = Registry::with_source("replay".into());
        let flow = Flow5Tuple {
            proto: Proto::Udp,
            src: "10.10.0.8:4000".parse().unwrap(),
            dst: "10.20.0.8:4000".parse().unwrap(),
        };
        let mut snap = StreamSummary {
            ssrc: 0xabc,
            packets: 100,
            lost: 2,
            bytes: 16000,
            loss_pct: 2.0,
            ..StreamSummary::default()
        };
        snap.call_id = Some("c1".into());
        snap.flow = Some(flow);

        // First 5s snap: 100 pkts / 2 lost.
        reg.import_stream_snap(1_000_000, snap.clone());
        // Second snap of the same stream: cumulative 250 pkts / 5 lost.
        snap.packets = 250;
        snap.lost = 5;
        snap.bytes = 40000;
        reg.import_stream_snap(6_000_000, snap);

        let ip_stats = reg.snapshot_full().ip_stats;
        assert_eq!(ip_stats.len(), 2, "both endpoints must appear");
        let src = ip_stats
            .iter()
            .find(|s| s.ip.to_string() == "10.10.0.8")
            .unwrap();
        let dst = ip_stats
            .iter()
            .find(|s| s.ip.to_string() == "10.20.0.8")
            .unwrap();
        assert_eq!(src.pkts_tx, 250);
        assert_eq!(src.lost_tx, 5);
        assert_eq!(dst.pkts_rx, 250);
        assert_eq!(dst.lost_rx, 5);
        let src_loss = src.loss_pct(0, Dir::Tx).unwrap();
        assert!((src_loss - 2.0).abs() < 1e-9, "all-time TX loss {src_loss}");

        // Consecutive snaps of the same stream replace, not accumulate, the row.
        assert_eq!(reg.snapshot_full().streams.len(), 1);
        assert_eq!(reg.snapshot_full().streams[0].packets, 250);
    }

    #[test]
    fn import_many_stream_snaps_stays_fast() {
        let mut reg = Registry::with_source("replay".into());
        let flow = Flow5Tuple {
            proto: Proto::Udp,
            src: "10.10.0.8:4000".parse().unwrap(),
            dst: "10.20.0.8:4000".parse().unwrap(),
        };
        let t0 = std::time::Instant::now();
        for i in 0..20_000u64 {
            let mut s = StreamSummary {
                ssrc: (i % 200) as u32,
                packets: 100 + i,
                lost: i / 40,
                bytes: (100 + i) * 160,
                loss_pct: 1.0,
                ..StreamSummary::default()
            };
            s.call_id = Some("c1".into());
            s.flow = Some(flow);
            reg.import_stream_snap(1_000_000 + i * 5_000_000, s);
        }
        let snap = reg.snapshot_full();
        assert!(
            t0.elapsed().as_millis() < 1_000,
            "20k stream snaps must stay O(n), took {:?}",
            t0.elapsed()
        );
        assert_eq!(snap.streams.len(), 200, "upsert keeps one row per ssrc");
        assert_eq!(snap.ip_stats.len(), 2);
        assert!(snap.calls.is_empty()); // snaps don't create calls
    }
}
