//! RTCP-derived network timing.
//!
//! * RTT from RR: `RTT = arrival_NTP - LSR - DLSR` (middle-32 NTP seconds).
//! * One-way delay from SR NTP<->RTP mapping when both directions are visible.

use crate::decode::rtcp::{SrReport, ntp_to_seconds};

/// Compute RTT (ms) from an RR report block, given the arrival time as NTP
/// seconds (middle-32 -> reconstruct full seconds is not needed; we use the
/// low-32 fractional representation consistently).
///
/// `arrival_ntp_secs` is the NTP timestamp (full seconds+fraction) of when the
/// RR was received. LSR/DLSR are the 32-bit middle-NTP fields.
pub fn rtt_from_rr(arrival_ntp_secs: f64, block: &crate::decode::rtcp::ReportBlock) -> Option<f64> {
    if block.lsr == 0 {
        return None;
    }
    // Work in 1/65536-second units, middle-32 NTP space (mod 2^32).
    let arrival_mid32 = ((arrival_ntp_secs * 65536.0) as u64 & 0xFFFF_FFFF) as f64;
    let lsr = block.lsr as f64;
    let dlsr = block.dlsr as f64;
    let mut diff = arrival_mid32 - lsr - dlsr;
    if diff < 0.0 {
        diff += 4_294_967_296.0; // 2^32
    }
    if !(0.0..=60.0 * 65536.0).contains(&diff) {
        return None;
    }
    // Convert 1/65536-second units to milliseconds.
    Some(diff / 65536.0 * 1000.0)
}

/// One-way delay estimate from an SR, given we know the arrival time as NTP
/// seconds. The SR carries the sender's NTP timestamp of when it was sent; the
/// difference is the network one-way delay (clock-skew aware only if corrected).
pub fn oneway_from_sr(arrival_ntp_secs: f64, sr: &SrReport) -> Option<f64> {
    let sent = ntp_to_seconds(sr.sender.ntp_secs, sr.sender.ntp_frac);
    let mut d = arrival_ntp_secs - sent;
    if d < 0.0 {
        d += 4_294_967_296.0; // full NTP 32-bit wrap
    }
    if !(0.0..=60.0).contains(&d) {
        return None;
    }
    Some(d * 1000.0)
}

/// Helper: convert a Unix microsecond timestamp to NTP seconds.
pub fn unix_us_to_ntp_secs(ts_us: u64) -> f64 {
    // NTP epoch is 1900-01-01, 70 years before Unix.
    const NTP_UNIX_OFFSET: u64 = 2_208_988_800; // seconds
    let secs = (ts_us / 1_000_000) as f64 + NTP_UNIX_OFFSET as f64;
    let frac = (ts_us % 1_000_000) as f64 / 1_000_000.0;
    secs + frac
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rtt_round_trip_sane() {
        // SR sent at NTP t0; peer receives ~immediately and after 0.5s sends RR
        // with DLSR=0.5s; we receive RR at t0+0.6s -> RTT ~ 0.1s.
        let t0 = unix_us_to_ntp_secs(1_000_000_000_000_000); // arbitrary
        let lsr = ((t0 * 65536.0).round() as u64 & 0xFFFF_FFFF) as u32;
        let block = crate::decode::rtcp::ReportBlock {
            ssrc: 1,
            fraction_lost: 0,
            cumulative_lost: 0,
            highest_seq: 0,
            jitter: 0,
            lsr,
            dlsr: (0.5_f64 * 65536.0) as u32,
        };
        let arrival = t0 + 0.6;
        let rtt = rtt_from_rr(arrival, &block).unwrap();
        assert!(rtt > 50.0 && rtt < 200.0, "rtt={rtt}");
    }
}
