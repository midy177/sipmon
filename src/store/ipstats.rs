//! Per-IP network statistics: time-windowed packet loss / volume.
//!
//! For every observed endpoint IP we keep two rolling ring buffers — per-second
//! buckets (60s of 1s buckets) and per-minute buckets (60m of 1m buckets) — plus
//! all-time totals. Loss rates for the 1s/5s/10s/20s/1m/10m/1h/all windows are
//! derived by summing the relevant buckets, so the UI can show short-term and
//! long-term quality side by side. The 1s series also feeds the per-IP heatmap.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;

/// Loss-rate windows supported by the UI: (window_secs, label). 0 = all-time.
pub const WINDOWS: [(u64, &str); 8] = [
    (1, "1s"),
    (5, "5s"),
    (10, "10s"),
    (20, "20s"),
    (60, "1m"),
    (600, "10m"),
    (3600, "1h"),
    (0, "all"),
];

const SEC1_RETAIN: u64 = 600; // 600 one-second buckets (10 minutes)
const SEC60_RETAIN: u64 = 60; // 60 one-minute buckets (1 hour)

/// One fixed-width time bucket.
#[derive(Debug, Clone, Copy, Default)]
pub struct Bucket {
    pub packets: u64,
    pub lost: u64,
    pub bytes: u64,
}

#[derive(Debug, Clone)]
pub struct IpStats {
    pub ip: IpAddr,
    /// Concurrent calls involving this IP (decremented at call teardown).
    pub active_calls: u32,
    /// All-time totals.
    pub pkts_total: u64,
    pub lost_total: u64,
    pub bytes_total: u64,
    pub first_seen_us: Option<u64>,
    pub last_seen_us: Option<u64>,
    /// 1s buckets, oldest first (bounded to SEC1_RETAIN).
    sec1: VecDeque<(u64, Bucket)>,
    /// 1m buckets, oldest first (bounded to SEC60_RETAIN).
    sec60: VecDeque<(u64, Bucket)>,
}

impl IpStats {
    fn new(ip: IpAddr) -> Self {
        Self {
            ip,
            active_calls: 0,
            pkts_total: 0,
            lost_total: 0,
            bytes_total: 0,
            first_seen_us: None,
            last_seen_us: None,
            sec1: VecDeque::new(),
            sec60: VecDeque::new(),
        }
    }

    /// Ensure a bucket exists for `ts_us` in the given ring, pushing empty
    /// buckets to fill gaps and pruning entries older than `retain`. The common
    /// in-order case is O(1); only reordered timestamps fall back to a scan.
    fn bucket_mut(ring: &mut VecDeque<(u64, Bucket)>, ts_us: u64, width_us: u64, retain: u64) -> &mut Bucket {
        let key = ts_us / width_us;
        if ring.is_empty() {
            ring.push_back((key, Bucket::default()));
            let tail = ring.back_mut().unwrap();
            return &mut tail.1;
        }
        // Align the tail forward to `key`, filling gaps and pruning the front.
        while ring.back().map(|(k, _)| *k).unwrap_or(0) < key
            && (ring.len() as u64) < retain
        {
            let next = ring.back().unwrap().0 + 1;
            ring.push_back((next, Bucket::default()));
        }
        if ring.back().unwrap().0 < key {
            // Ring is full and `key` is still ahead: shift forward bucket by bucket.
            while ring.back().unwrap().0 < key {
                ring.pop_front();
                let next = ring.back().unwrap().0 + 1;
                ring.push_back((next, Bucket::default()));
            }
        }
        if ring.back().unwrap().0 == key {
            let tail = ring.back_mut().unwrap();
            return &mut tail.1;
        }
        // Reordered timestamp behind the tail: find the bucket, else fold into
        // the oldest (retention dropped the real one — negligible inaccuracy).
        match ring.iter().position(|(k, _)| *k == key) {
            Some(i) => &mut ring[i].1,
            None => {
                let front = ring.front_mut().unwrap();
                &mut front.1
            }
        }
    }

    fn add_packet(&mut self, ts_us: u64, len: usize) {
        if self.first_seen_us.is_none() {
            self.first_seen_us = Some(ts_us);
        }
        self.last_seen_us = Some(ts_us);
        self.pkts_total += 1;
        self.bytes_total += len as u64;
        let b = Self::bucket_mut(&mut self.sec1, ts_us, 1_000_000, SEC1_RETAIN);
        b.packets += 1;
        b.bytes += len as u64;
        let b = Self::bucket_mut(&mut self.sec60, ts_us, 60_000_000, SEC60_RETAIN);
        b.packets += 1;
        b.bytes += len as u64;
    }

    fn add_lost(&mut self, ts_us: u64, lost: u64) {
        if lost == 0 {
            return;
        }
        if self.last_seen_us.is_none() {
            self.last_seen_us = Some(ts_us);
        }
        self.lost_total += lost;
        let b = Self::bucket_mut(&mut self.sec1, ts_us, 1_000_000, SEC1_RETAIN);
        b.lost += lost;
        let b = Self::bucket_mut(&mut self.sec60, ts_us, 60_000_000, SEC60_RETAIN);
        b.lost += lost;
    }

    fn active_add(&mut self, delta: i32) {
        self.active_calls = self.active_calls.saturating_add_signed(delta);
    }

    /// Aggregate (packets, lost) over the last `window_secs` (0 = all-time).
    fn window(&self, window_secs: u64) -> (u64, u64) {
        if window_secs == 0 {
            return (self.pkts_total, self.lost_total);
        }
        if window_secs <= SEC1_RETAIN {
            return Self::sum_ring(&self.sec1, window_secs);
        }
        Self::sum_ring(&self.sec60, window_secs.div_ceil(60))
    }

    fn sum_ring(ring: &VecDeque<(u64, Bucket)>, n: u64) -> (u64, u64) {
        let (mut pkts, mut lost) = (0u64, 0u64);
        for (_, b) in ring.iter().rev().take(n as usize) {
            pkts += b.packets;
            lost += b.lost;
        }
        (pkts, lost)
    }

    /// Loss percentage (0..100) for a window, or None when no packets observed.
    pub fn loss_pct(&self, window_secs: u64) -> Option<f64> {
        let (pkts, lost) = self.window(window_secs);
        if pkts == 0 {
            None
        } else {
            Some(lost as f64 / pkts as f64 * 100.0)
        }
    }

    #[allow(dead_code)]
    pub fn pkts_in(&self, window_secs: u64) -> u64 {
        self.window(window_secs).0
    }

    #[allow(dead_code)]
    pub fn bytes_in(&self, window_secs: u64) -> u64 {
        if window_secs == 0 {
            return self.bytes_total;
        }
        if window_secs <= SEC1_RETAIN {
            self.sec1.iter().rev().take(window_secs as usize).map(|(_, b)| b.bytes).sum()
        } else {
            self.sec60.iter().rev().take(window_secs.div_ceil(60) as usize).map(|(_, b)| b.bytes).sum()
        }
    }

    /// Column series for the bottom heatmap: up to `cols` buckets covering the
    /// last `window_secs`, each a (bucket_start_us, loss_pct). Uses the 1s ring
    /// (aggregated) for ≤10m windows and the 1m ring for longer ones.
    pub fn heatmap_columns(&self, window_secs: u64, cols: u64) -> Vec<(u64, f64)> {
        let (ring, bucket_us, secs_per_key) = if window_secs <= SEC1_RETAIN * 10 {
            (&self.sec1, 1_000_000u64, 1u64)
        } else {
            (&self.sec60, 60_000_000u64, 60u64)
        };
        // Aggregate ring keys into ~cols groups.
        let group = (window_secs / secs_per_key / cols).max(1);
        let mut map: std::collections::BTreeMap<u64, (u64, u64)> =
            std::collections::BTreeMap::new();
        for (key, b) in ring {
            let g = key / group;
            let e = map.entry(g).or_default();
            e.0 += b.packets;
            e.1 += b.lost;
        }
        map.into_iter()
            .map(|(g, (p, l))| {
                let pct = if p == 0 { 0.0 } else { l as f64 / p as f64 * 100.0 };
                (g * group * bucket_us, pct)
            })
            .collect()
    }
}

/// All the per-IP stats, keyed by IP.
#[derive(Debug, Clone, Default)]
pub struct IpStatsStore {
    map: HashMap<IpAddr, IpStats>,
}

impl IpStatsStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn clear(&mut self) {
        self.map.clear();
    }

    fn entry(&mut self, ip: IpAddr) -> &mut IpStats {
        self.map.entry(ip).or_insert_with(|| IpStats::new(ip))
    }

    pub fn observe_packet(&mut self, ip: IpAddr, ts_us: u64, len: usize) {
        self.entry(ip).add_packet(ts_us, len);
    }

    pub fn observe_lost(&mut self, ip: IpAddr, ts_us: u64, lost: u64) {
        self.entry(ip).add_lost(ts_us, lost);
    }

    pub fn add_active(&mut self, ip: IpAddr, delta: i32) {
        self.entry(ip).active_add(delta);
    }

    /// Snapshot of all tracked IPs (sorted by IP for stable display).
    pub fn snapshot(&self) -> Vec<IpStats> {
        let mut v: Vec<IpStats> = self.map.values().cloned().collect();
        v.sort_by_key(|s| s.ip);
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_and_totals() {
        let mut st = IpStatsStore::new();
        let ip: IpAddr = "10.1.2.3".parse().unwrap();
        // 10 pkts/s for 30s at ts=1_000_000 + i*1s
        for i in 0..30 {
            let ts = 1_000_000 + i * 1_000_000;
            for _ in 0..10 {
                st.observe_packet(ip, ts, 160);
            }
            if i % 10 == 0 {
                st.observe_lost(ip, ts, 1); // 1 lost / 100 pkts = 1%
            }
        }
        let s = st.snapshot().pop().unwrap();
        assert_eq!(s.pkts_total, 300);
        assert_eq!(s.bytes_total, 300 * 160);
        assert_eq!(s.lost_total, 3);
        assert!((s.loss_pct(0).unwrap() - 1.0).abs() < 1e-9); // all-time
        assert!((s.loss_pct(10).unwrap() - 1.0).abs() < 1e-9); // 10s window includes one lost
        assert_eq!(s.loss_pct(1).unwrap(), 0.0); // last 1s: no loss
        assert_eq!(s.pkts_in(10), 100);
        assert_eq!(s.bytes_in(5), 5 * 10 * 160);
    }

    #[test]
    fn active_call_counting() {
        let mut st = IpStatsStore::new();
        let ip: IpAddr = "10.1.2.3".parse().unwrap();
        st.add_active(ip, 1);
        st.add_active(ip, 1);
        st.add_active(ip, -1);
        let s = st.snapshot().pop().unwrap();
        assert_eq!(s.active_calls, 1);
    }

    #[test]
    fn heatmap_columns_produce_loss_pct() {
        let mut st = IpStatsStore::new();
        let ip: IpAddr = "10.1.2.3".parse().unwrap();
        let ts = 1_000_000;
        for _ in 0..8 {
            st.observe_packet(ip, ts, 160);
        }
        st.observe_lost(ip, ts, 2);
        let s = st.snapshot().pop().unwrap();
        let cols = s.heatmap_columns(60, 60);
        assert_eq!(cols.len(), 1);
        assert!((cols[0].1 - 25.0).abs() < 1e-9);
    }
}
