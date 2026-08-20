//! Per-IP SIP signaling statistics for the SIP Stats page: a request/response
//! distribution table (INV/BYE/CANCEL/OPTIONS/INFO/other × response codes) and
//! an INVITE answer-rate time series (1/5/15-minute buckets) that feeds the
//! success heatmap. Answers are credited back to the initial INVITE's source
//! IP so B2BUA-originated 200s still rate the originating sender.

use std::collections::HashMap;
use std::net::IpAddr;

use crate::model::sip::Method;

/// Request columns: INVITE / ACK / BYE / CANCEL / OPTIONS / INFO / REGISTER /
/// MESSAGE / other.
pub const REQ_LABELS: [&str; 9] = [
    "INVITE", "ACK", "BYE", "CANCEL", "OPTION", "INFO", "REGISTER", "MESSAGE", "oth",
];
/// Response columns: the codes operators grep for first, then class buckets,
/// then everything else (181, 202, …). 487 is the normal CANCEL response.
pub const RESP_LABELS: [&str; 15] = [
    "100", "180", "183", "200", "486", "404", "403", "408", "480", "487", "3xx", "4xx", "5xx",
    "6xx", "oth",
];

pub const REQ_N: usize = REQ_LABELS.len();
pub const RESP_N: usize = RESP_LABELS.len();

/// Column index of a request method.
pub fn req_idx(method: Method) -> usize {
    match method {
        Method::Invite => 0,
        Method::Ack => 1,
        Method::Bye => 2,
        Method::Cancel => 3,
        Method::Options => 4,
        Method::Info => 5,
        Method::Register => 6,
        Method::Message => 7,
        _ => 8,
    }
}

/// Column index of a response status code.
pub fn resp_idx(status: u16) -> usize {
    match status {
        100 => 0,
        180 => 1,
        183 => 2,
        200 => 3,
        486 => 4,
        404 => 5,
        403 => 6,
        408 => 7,
        480 => 8,
        487 => 9,
        300..=399 => 10,
        400..=499 => 11,
        500..=599 => 12,
        600..=699 => 13,
        _ => 14,
    }
}

/// Heatmap bucket widths (seconds), cycled by the `w` key.
pub const SERIES_BUCKETS: [u64; 3] = [60, 300, 900];
/// Buckets retained per ring (60 → 1h / 5h / 15h spans).
const SERIES_RETAIN: usize = 60;
const M1_US: u64 = 60 * 1_000_000;
const M5_US: u64 = 300 * 1_000_000;
const M15_US: u64 = 900 * 1_000_000;

/// One endpoint's (or the global) SIP counters.
#[derive(Debug, Clone, Default)]
pub struct SipIpStats {
    /// All-time request counts by [`REQ_LABELS`] column.
    pub req: [u64; REQ_N],
    /// All-time response counts by [`RESP_LABELS`] column.
    pub resp: [u64; RESP_N],
    /// 1-minute buckets: (bucket_start_us, invites, answered), oldest first.
    pub m1: Vec<(u64, u64, u64)>,
    /// 5-minute buckets.
    pub m5: Vec<(u64, u64, u64)>,
    /// 15-minute buckets.
    pub m15: Vec<(u64, u64, u64)>,
    pub last_ts_us: Option<u64>,
}

impl SipIpStats {
    /// Ring for a bucket width in seconds (60/300/900; anything else → 1m).
    pub fn series(&self, bucket_secs: u64) -> &[(u64, u64, u64)] {
        match bucket_secs {
            300 => &self.m5,
            900 => &self.m15,
            _ => &self.m1,
        }
    }

    /// (invites, answered) over the whole ring of `bucket_secs`.
    pub fn series_totals(&self, bucket_secs: u64) -> (u64, u64) {
        self.series(bucket_secs)
            .iter()
            .fold((0u64, 0u64), |(i, a), (_, inv, ans)| (i + inv, a + ans))
    }

    /// Answer-rate percentage over the ring, None when no INVITEs.
    pub fn asr_pct(&self, bucket_secs: u64) -> Option<f64> {
        let (inv, ans) = self.series_totals(bucket_secs);
        (inv > 0).then(|| ans.min(inv) as f64 / inv as f64 * 100.0)
    }

    pub fn total_msgs(&self) -> u64 {
        self.req.iter().sum::<u64>() + self.resp.iter().sum::<u64>()
    }

    /// Response columns that represent errors: the specific failure codes
    /// (486/404/403/408/480) plus the 4xx/5xx/6xx class buckets. 487 (the
    /// normal CANCEL response) is not an error.
    pub fn resp_errors(&self) -> u64 {
        [4usize, 5, 6, 7, 8, 11, 12, 13]
            .iter()
            .map(|&i| self.resp[i])
            .sum()
    }
}

/// Snapshot row: per-IP counters, or the global aggregate (`ip == None`).
#[derive(Debug, Clone)]
pub struct SipIpRow {
    pub ip: Option<IpAddr>,
    pub stats: SipIpStats,
}

/// One SIP message observation offered to the store.
pub struct SipObs {
    /// Sender IP of the message (distribution attribution).
    pub ip: IpAddr,
    pub ts_us: u64,
    pub is_request: bool,
    pub method: Option<Method>,
    pub status: Option<u16>,
    /// Set when this message is the first 2xx answering a dialog's INVITE:
    /// the source IP of that initial INVITE, credited in its series.
    pub answer_for_ip: Option<IpAddr>,
    /// True for the dialog-initial INVITE request (no To tag) — the only
    /// INVITE counted by the answer-rate series.
    pub initial_invite: bool,
}

#[derive(Default)]
pub struct SipStatsStore {
    ips: HashMap<IpAddr, SipIpStats>,
    all: SipIpStats,
}

impl SipStatsStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn entry(&mut self, ip: IpAddr) -> &mut SipIpStats {
        self.ips.entry(ip).or_default()
    }

    /// Record one message into the per-IP and global aggregates.
    pub fn observe(&mut self, o: &SipObs) {
        apply_dist(self.entry(o.ip), o);
        apply_dist(&mut self.all, o);
        if let Some(ans_ip) = o.answer_for_ip {
            apply_answer(self.entry(ans_ip), o.ts_us);
            apply_answer(&mut self.all, o.ts_us);
        }
    }

    pub fn clear(&mut self) {
        self.ips.clear();
        self.all = SipIpStats::default();
    }

    /// Drop IPs idle since `cutoff_us` (bounds memory on long sessions).
    pub fn prune_idle(&mut self, cutoff_us: u64) {
        self.ips
            .retain(|_, s| s.last_ts_us.unwrap_or(0) >= cutoff_us);
    }

    /// Global aggregate row followed by per-IP rows (busiest first).
    pub fn snapshot(&self) -> Vec<SipIpRow> {
        let mut rows: Vec<SipIpRow> = self
            .ips
            .iter()
            .map(|(ip, s)| SipIpRow {
                ip: Some(*ip),
                stats: s.clone(),
            })
            .collect();
        rows.sort_by(|a, b| {
            b.stats
                .total_msgs()
                .cmp(&a.stats.total_msgs())
                .then(a.ip.cmp(&b.ip))
        });
        rows.insert(
            0,
            SipIpRow {
                ip: None,
                stats: self.all.clone(),
            },
        );
        rows
    }
}

fn apply_dist(s: &mut SipIpStats, o: &SipObs) {
    if o.is_request {
        let idx = o.method.map(req_idx).unwrap_or(REQ_N - 1);
        s.req[idx] += 1;
        if o.initial_invite {
            ring_bump(&mut s.m1, M1_US, o.ts_us, 1, 0);
            ring_bump(&mut s.m5, M5_US, o.ts_us, 1, 0);
            ring_bump(&mut s.m15, M15_US, o.ts_us, 1, 0);
        }
    } else if let Some(code) = o.status {
        s.resp[resp_idx(code)] += 1;
    }
    s.last_ts_us = Some(o.ts_us.max(s.last_ts_us.unwrap_or(0)));
}

fn apply_answer(s: &mut SipIpStats, ts_us: u64) {
    ring_bump(&mut s.m1, M1_US, ts_us, 0, 1);
    ring_bump(&mut s.m5, M5_US, ts_us, 0, 1);
    ring_bump(&mut s.m15, M15_US, ts_us, 0, 1);
    s.last_ts_us = Some(ts_us.max(s.last_ts_us.unwrap_or(0)));
}

/// Bump a bucket ring at `ts_us`. Buckets are aligned to their width; gaps are
/// zero-filled up to the retention cap, older-than-ring timestamps are folded
/// into an exact match when still retained (reordered input) or dropped.
fn ring_bump(ring: &mut Vec<(u64, u64, u64)>, bucket_us: u64, ts_us: u64, inv: u64, ans: u64) {
    if inv == 0 && ans == 0 {
        return;
    }
    let key = ts_us / bucket_us * bucket_us;
    let Some(&(last_key, _, _)) = ring.last() else {
        ring.push((key, inv, ans));
        return;
    };
    if key == last_key {
        let e = ring.last_mut().unwrap();
        e.1 += inv;
        e.2 += ans;
        return;
    }
    if key > last_key {
        if key.saturating_sub(last_key) > bucket_us * SERIES_RETAIN as u64 {
            // Gap larger than the whole ring: restart at this bucket.
            ring.clear();
            ring.push((key, inv, ans));
            return;
        }
        let mut next = last_key + bucket_us;
        while next < key && ring.len() < SERIES_RETAIN {
            ring.push((next, 0, 0));
            next += bucket_us;
        }
        while ring.len() >= SERIES_RETAIN {
            ring.remove(0);
        }
        ring.push((key, inv, ans));
        return;
    }
    // Reordered timestamp behind the tail.
    if let Some(e) = ring.iter_mut().find(|(k, _, _)| *k == key) {
        e.1 += inv;
        e.2 += ans;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip() -> IpAddr {
        "10.10.0.8".parse().unwrap()
    }

    #[test]
    fn response_codes_map_to_columns() {
        assert_eq!(resp_idx(100), 0);
        assert_eq!(resp_idx(180), 1);
        assert_eq!(resp_idx(183), 2);
        assert_eq!(resp_idx(200), 3);
        assert_eq!(resp_idx(486), 4);
        assert_eq!(resp_idx(404), 5);
        assert_eq!(resp_idx(403), 6);
        assert_eq!(resp_idx(408), 7);
        assert_eq!(resp_idx(480), 8);
        assert_eq!(resp_idx(487), 9);
        assert_eq!(resp_idx(302), 10);
        assert_eq!(resp_idx(415), 11); // not listed → 4xx bucket
        assert_eq!(resp_idx(500), 12);
        assert_eq!(resp_idx(603), 13);
        assert_eq!(resp_idx(181), 14); // not listed → oth
        assert_eq!(resp_idx(202), 14);
    }

    #[test]
    fn request_methods_map_to_columns() {
        assert_eq!(req_idx(Method::Invite), 0);
        assert_eq!(req_idx(Method::Ack), 1);
        assert_eq!(req_idx(Method::Bye), 2);
        assert_eq!(req_idx(Method::Cancel), 3);
        assert_eq!(req_idx(Method::Options), 4);
        assert_eq!(req_idx(Method::Info), 5);
        assert_eq!(req_idx(Method::Register), 6);
        assert_eq!(req_idx(Method::Message), 7);
        assert_eq!(req_idx(Method::Subscribe), 8);
        assert_eq!(req_idx(Method::Other), 8);
    }

    #[test]
    fn invite_answer_series_and_asr() {
        let mut st = SipStatsStore::new();
        let t0 = 1_800_000_000_000_000u64; // aligned minute
        // 4 initial INVITEs, 2 answered.
        for i in 0..4u64 {
            st.observe(&SipObs {
                ip: ip(),
                ts_us: t0 + i * 1_000_000,
                is_request: true,
                method: Some(Method::Invite),
                status: None,
                answer_for_ip: None,
                initial_invite: true,
            });
        }
        for i in 0..2u64 {
            st.observe(&SipObs {
                ip: "2.2.2.2".parse().unwrap(), // SBC sends the 200
                ts_us: t0 + i * 5_000_000 + 2_000_000,
                is_request: false,
                method: None,
                status: Some(200),
                answer_for_ip: Some(ip()),
                initial_invite: false,
            });
        }
        let rows = st.snapshot();
        assert_eq!(rows.len(), 3); // ALL + caller + SBC
        let all = &rows[0];
        assert_eq!(all.stats.req[0], 4);
        assert_eq!(all.stats.resp[3], 2);
        assert_eq!(all.stats.asr_pct(60), Some(50.0));
        let caller = rows.iter().find(|r| r.ip == Some(ip())).unwrap();
        // Answer credited to the INVITE source, not the 200 sender.
        assert_eq!(caller.stats.series_totals(60), (4, 2));
        assert_eq!(caller.stats.asr_pct(60), Some(50.0));
        let sbc = rows
            .iter()
            .find(|r| r.ip.is_some() && r.ip != Some(ip()))
            .unwrap();
        assert_eq!(sbc.stats.series_totals(60), (0, 0), "SBC has no invites");
        assert_eq!(sbc.stats.resp[3], 2, "200 still in the SBC's distribution");
    }

    #[test]
    fn ring_gaps_zero_fill_and_cap() {
        let mut ring = Vec::new();
        let b = 60_000_000u64;
        let t0 = 1_800_000_000_000_000u64;
        ring_bump(&mut ring, b, t0, 1, 0);
        // Jump 3 buckets ahead: two zero buckets in between.
        ring_bump(&mut ring, b, t0 + 3 * b, 1, 1);
        assert_eq!(ring.len(), 4);
        assert_eq!(ring[1], (t0 + b, 0, 0));
        assert_eq!(ring[3], (t0 + 3 * b, 1, 1));
        // Same-bucket second bump merges.
        ring_bump(&mut ring, b, t0 + 3 * b + 1_000, 0, 1);
        assert_eq!(ring.len(), 4);
        assert_eq!(ring[3].2, 2);
        // Retention: 100 buckets later the ring restarts at 1 entry.
        ring_bump(&mut ring, b, t0 + 100 * b, 1, 0);
        assert_eq!(ring.len(), 1);
        // Reordered older timestamp lands in its bucket when retained.
        ring_bump(&mut ring, b, t0 + 100 * b + b, 1, 0);
        ring_bump(&mut ring, b, t0 + 100 * b, 0, 1);
        assert_eq!(ring[0].2, 1);
    }

    #[test]
    fn reinvite_ack_and_others_not_counted_as_attempts() {
        let mut st = SipStatsStore::new();
        let t0 = 1_800_000_000_000_000u64;
        // re-INVITE (initial=false): distribution only.
        st.observe(&SipObs {
            ip: ip(),
            ts_us: t0,
            is_request: true,
            method: Some(Method::Invite),
            status: None,
            answer_for_ip: None,
            initial_invite: false,
        });
        // ACK + REGISTER + MESSAGE + OPTIONS + INFO + one unlisted method.
        for m in [
            Method::Ack,
            Method::Register,
            Method::Message,
            Method::Options,
            Method::Info,
            Method::Subscribe,
        ] {
            st.observe(&SipObs {
                ip: ip(),
                ts_us: t0,
                is_request: true,
                method: Some(m),
                status: None,
                answer_for_ip: None,
                initial_invite: false,
            });
        }
        // Timeouts and a CANCEL's 487.
        for code in [408u16, 480, 487] {
            st.observe(&SipObs {
                ip: ip(),
                ts_us: t0,
                is_request: false,
                method: None,
                status: Some(code),
                answer_for_ip: None,
                initial_invite: false,
            });
        }
        let all = &st.snapshot()[0];
        assert_eq!(all.stats.req[0], 1, "INVITE column counts every INVITE");
        assert_eq!(all.stats.req[1], 1, "ACK has its own column");
        assert_eq!(all.stats.series_totals(60), (0, 0), "no initial INVITE");
        assert_eq!(all.stats.req[4], 1); // OPTION
        assert_eq!(all.stats.req[5], 1); // INFO
        assert_eq!(all.stats.req[6], 1); // REGISTER
        assert_eq!(all.stats.req[7], 1); // MESSAGE
        assert_eq!(all.stats.req[8], 1); // SUBSCRIBE → oth
        assert_eq!(all.stats.resp[7], 1, "408 own column");
        assert_eq!(all.stats.resp[8], 1, "480 own column");
        assert_eq!(all.stats.resp[9], 1, "487 own column");
        assert_eq!(all.stats.resp_errors(), 2, "408+480 are errors, 487 is not");
    }

    #[test]
    fn prune_and_clear() {
        let mut st = SipStatsStore::new();
        st.observe(&SipObs {
            ip: ip(),
            ts_us: 1_000_000,
            is_request: true,
            method: Some(Method::Invite),
            status: None,
            answer_for_ip: None,
            initial_invite: true,
        });
        st.observe(&SipObs {
            ip: "2.2.2.2".parse().unwrap(),
            ts_us: 10_000_000_000,
            is_request: true,
            method: Some(Method::Invite),
            status: None,
            answer_for_ip: None,
            initial_invite: true,
        });
        st.prune_idle(5_000_000_000);
        assert_eq!(st.snapshot().len(), 2, "idle IP dropped, ALL stays");
        st.clear();
        assert_eq!(st.snapshot().len(), 1);
        assert_eq!(st.snapshot()[0].stats.total_msgs(), 0);
    }
}
