//! Vendored RTP media statistics accumulator (RFC 3550 jitter/loss with a
//! 64-packet reorder window). Adapted from rustpbx-sipflow's `rtp_stats.rs`,
//! kept self-contained (no external struct dependency).

pub const RTP_REORDER_WINDOW: u16 = 64;

#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub struct RtpStatsHeader {
    pub payload_type: u8,
    pub sequence_number: u16,
    pub rtp_timestamp: u32,
    pub ssrc: u32,
}

#[derive(Debug, Default)]
pub struct MediaStatsAccumulator {
    pub packet_count: u64,
    pub lost_packets: u64,
    pub payload_type: Option<u8>,
    pub clock_rate: Option<u32>,
    pub first_sequence: Option<u16>,
    pub last_sequence: Option<u16>,
    pub pending_missing: std::collections::BTreeSet<u16>,
    pub prev_arrival_micros: Option<u64>,
    pub prev_rtp_timestamp: Option<u32>,
    pub jitter_rtp_units: f64,
    pub jitter_samples: u64,
}

#[derive(Debug, Clone, Default)]
#[allow(dead_code)]
pub struct MediaStats {
    pub packet_count: u64,
    pub lost_packets: u64,
    pub expected_packets: u64,
    pub loss_percent: f64,
    pub jitter_ms: Option<f64>,
    pub payload_type: Option<u8>,
    pub clock_rate: Option<u32>,
}

impl MediaStatsAccumulator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn observe(&mut self, arrival_micros: u64, header: Option<RtpStatsHeader>) {
        self.packet_count += 1;
        let Some(header) = header else { return };

        self.payload_type.get_or_insert(header.payload_type);
        let clock_rate = *self.clock_rate.get_or_insert_with(|| {
            crate::decode::rtp::rtp_clock_rate_for_payload_type(header.payload_type)
        });

        self.observe_sequence(header.sequence_number);
        self.observe_jitter(arrival_micros, header.rtp_timestamp, clock_rate);
    }

    fn observe_sequence(&mut self, seq: u16) {
        if self.first_sequence.is_none() {
            self.first_sequence = Some(seq);
            self.last_sequence = Some(seq);
            return;
        }
        let last = match self.last_sequence {
            Some(l) => l,
            None => {
                self.last_sequence = Some(seq);
                return;
            }
        };
        let diff = seq.wrapping_sub(last);
        if diff == 0 {
            return;
        }
        if diff < 0x8000 {
            if diff > 1 {
                self.defer_missing(last, seq);
            }
            self.last_sequence = Some(seq);
            self.expire_missing();
        } else {
            self.pending_missing.remove(&seq);
        }
    }

    fn defer_missing(&mut self, prev: u16, cur: u16) {
        let missing = cur.wrapping_sub(prev) - 1;
        let buffered = missing.min(RTP_REORDER_WINDOW);
        self.lost_packets += (missing - buffered) as u64;
        let first_off = missing - buffered + 1;
        for off in first_off..=missing {
            self.pending_missing.insert(prev.wrapping_add(off));
        }
    }

    fn expire_missing(&mut self) {
        let Some(last) = self.last_sequence else {
            return;
        };
        let expired: Vec<u16> = self
            .pending_missing
            .iter()
            .copied()
            .filter(|s| {
                let age = last.wrapping_sub(*s);
                age > RTP_REORDER_WINDOW && age < 0x8000
            })
            .collect();
        self.lost_packets += expired.len() as u64;
        for s in expired {
            self.pending_missing.remove(&s);
        }
    }

    fn observe_jitter(&mut self, arrival_us: u64, rtp_ts: u32, clock_rate: u32) {
        if let (Some(prev_arr), Some(prev_rtp)) =
            (self.prev_arrival_micros, self.prev_rtp_timestamp)
        {
            let arr_delta = arrival_us as i128 - prev_arr as i128;
            let arr_delta_units = arr_delta as f64 * clock_rate as f64 / 1_000_000.0;
            let rtp_delta_units = rtp_ts_delta(rtp_ts, prev_rtp) as f64;
            let delta = (arr_delta_units - rtp_delta_units).abs();
            if delta.is_finite() {
                self.jitter_rtp_units += (delta - self.jitter_rtp_units) / 16.0;
                self.jitter_samples += 1;
            }
        }
        self.prev_arrival_micros = Some(arrival_us);
        self.prev_rtp_timestamp = Some(rtp_ts);
    }

    pub fn snapshot(&self) -> MediaStats {
        let lost = self.lost_packets + self.pending_missing.len() as u64;
        let expected = self.packet_count + lost;
        let loss_pct = if expected > 0 {
            lost as f64 / expected as f64 * 100.0
        } else {
            0.0
        };
        let jitter_ms = match (self.clock_rate, self.jitter_samples > 0) {
            (Some(cr), true) if cr > 0 => Some(self.jitter_rtp_units * 1000.0 / cr as f64),
            _ => None,
        };
        MediaStats {
            packet_count: self.packet_count,
            lost_packets: lost,
            expected_packets: expected,
            loss_percent: loss_pct,
            jitter_ms,
            payload_type: self.payload_type,
            clock_rate: self.clock_rate,
        }
    }
}

pub fn rtp_ts_delta(cur: u32, prev: u32) -> i64 {
    let forward = cur.wrapping_sub(prev);
    if forward <= i32::MAX as u32 {
        forward as i64
    } else {
        -(prev.wrapping_sub(cur) as i64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hdr(seq: u16, ts: u32) -> RtpStatsHeader {
        RtpStatsHeader {
            payload_type: 0,
            sequence_number: seq,
            rtp_timestamp: ts,
            ssrc: 1,
        }
    }

    #[test]
    fn reordered_packet_clears_pending_loss() {
        let mut s = MediaStatsAccumulator::new();
        s.observe(10_000, Some(hdr(10, 1_600)));
        s.observe(30_000, Some(hdr(12, 1_920)));
        s.observe(40_000, Some(hdr(11, 1_760)));
        let st = s.snapshot();
        assert_eq!(st.packet_count, 3);
        assert_eq!(st.lost_packets, 0);
    }

    #[test]
    fn unfilled_gap_counts_as_loss() {
        let mut s = MediaStatsAccumulator::new();
        s.observe(10_000, Some(hdr(10, 1_600)));
        s.observe(30_000, Some(hdr(12, 1_920)));
        let st = s.snapshot();
        assert_eq!(st.lost_packets, 1);
        assert_eq!(st.expected_packets, 3);
    }
}
