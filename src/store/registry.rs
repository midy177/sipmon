use std::collections::{HashMap, VecDeque};

use crate::diagnostics::Diagnostic;
use crate::model::media::StreamSummary;
use crate::model::sip::{Call, CallState, Outcome, SipMsg};

/// Focused-call detail payload for the Call Detail page.
#[derive(Debug, Clone, Default)]
pub struct Focus {
    pub call_id: String,
    pub state: Option<CallState>,
    pub from_user: Option<String>,
    pub to_user: Option<String>,
    pub messages: Vec<SipMsg>,
    pub streams: Vec<StreamSummary>,
    pub diagnostics: Vec<Diagnostic>,
    pub negotiated_endpoints: Vec<std::net::SocketAddr>,
}

/// One RTP/RTCP stream keyed by (5-tuple, ssrc).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StreamKey {
    pub flow: crate::model::packet::Flow5Tuple,
    pub ssrc: u32,
}

/// Recent-activity ordering helper.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CallSummary {
    pub call_id: String,
    pub from_user: Option<String>,
    pub to_user: Option<String>,
    pub state: CallState,
    pub outcome: Outcome,
    pub invite_ts: Option<u64>,
    pub duration_ms: Option<u64>,
    pub pdd_ms: Option<u32>,
    pub setup_ms: Option<u32>,
    pub hangup_code: Option<u32>,
    pub pkts_sip: u64,
    pub pkts_rtp: u64,
    pub best_mos: Option<f64>,
    pub warn_count: u32,
    pub critical_count: u32,
    pub stream_count: usize,
    /// True if the call's media traversed a learned TURN relay.
    pub via_turn: bool,
}

/// Lightweight immutable snapshot for the TUI/export.
#[derive(Debug, Clone, Default)]
pub struct Snapshot {
    pub source: String,
    pub elapsed_us: Option<u64>,
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

    fn remove_call(&mut self, call_id: &str) {
        self.calls.remove(call_id);
        self.order.retain(|id| id != call_id);
        self.removed.push_back(call_id.to_string());
        // Clean endpoint + stream indices (stream keys come from the index,
        // no full scan).
        self.endpoint_call.retain(|_, v| v != call_id);
        let stream_keys: Vec<StreamKey> = self.stream_index.remove(call_id).unwrap_or_default();
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
            streams: self
                .streams
                .values()
                .take(stream_limit)
                .map(|s| s.summary())
                .collect(),
            events: self.events.clone(),
            diagnostics: self.diagnostics.iter().cloned().collect(),
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
        let streams = self
            .call_stream_keys(call_id)
            .iter()
            .filter_map(|k| self.streams.get(k))
            .map(|s| s.summary())
            .collect();
        let diagnostics = self
            .diagnostics
            .iter()
            .filter(|d| d.call_id == call_id)
            .cloned()
            .collect();
        Some(Focus {
            call_id: call_id.to_string(),
            state: Some(call.state),
            from_user: call.from_user.clone(),
            to_user: call.to_user.clone(),
            messages: msgs,
            streams,
            diagnostics,
            negotiated_endpoints: call.negotiated.endpoints.clone(),
        })
    }

    fn summarize(&self, c: &Call) -> CallSummary {
        let keys = self.call_stream_keys(&c.call_id);
        let best_mos = keys
            .iter()
            .filter_map(|k| self.streams.get(k))
            .filter_map(|s| s.summary().mos)
            .fold(None, |acc: Option<f64>, m| {
                Some(acc.map_or(m, |a| a.min(m)))
            });
        let stream_count = keys.len();
        CallSummary {
            call_id: c.call_id.clone(),
            from_user: c.from_user.clone(),
            to_user: c.to_user.clone(),
            state: c.state,
            outcome: c.outcome,
            invite_ts: c.invite_ts,
            duration_ms: c.duration_ms(),
            pdd_ms: c.pdd_ms,
            setup_ms: c.setup_ms,
            hangup_code: c.hangup.code,
            pkts_sip: c.pkts_sip,
            pkts_rtp: c.pkts_rtp,
            best_mos,
            warn_count: c.warn_count,
            critical_count: c.critical_count,
            stream_count,
            via_turn: c.via_turn,
        }
    }

    /// Call summaries for a specific call (for call-detail view).
    #[allow(dead_code)]
    pub fn call_messages(&self, call_id: &str) -> Option<&[crate::model::sip::SipMsg]> {
        self.calls.get(call_id).map(|c| c.messages.as_slice())
    }
}
