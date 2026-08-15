/// RTCP packet types (RFC 3550 / 4585 / 5104).
pub const PT_SR: u8 = 200;
pub const PT_RR: u8 = 201;
#[allow(dead_code)]
pub const PT_SDES: u8 = 202;
#[allow(dead_code)]
pub const PT_BYE: u8 = 203;
#[allow(dead_code)]
pub const PT_APP: u8 = 204;
#[allow(dead_code)]
pub const PT_RTPFB: u8 = 205;
#[allow(dead_code)]
pub const PT_PSFB: u8 = 206;
#[allow(dead_code)]
pub const PT_XR: u8 = 207;

#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub struct RtcpHeader {
    pub payload_type: u8,
    /// Length of this compound member in bytes (including the common header).
    pub length_bytes: usize,
    pub ssrc: u32,
}

/// Parsed report block from an SR/RR.
#[derive(Debug, Clone, Copy, Default)]
#[allow(dead_code)]
pub struct ReportBlock {
    pub ssrc: u32,
    pub fraction_lost: u8,
    /// Cumulative number of packets lost (signed 24-bit).
    pub cumulative_lost: i32,
    pub highest_seq: u32,
    pub jitter: u32,
    /// Middle 32 bits of the NTP timestamp of the last SR (LSR).
    pub lsr: u32,
    /// Delay since last SR, expressed in 1/65536 seconds (DLSR).
    pub dlsr: u32,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct SenderInfo {
    pub ntp_secs: u32,
    pub ntp_frac: u32,
    pub rtp_timestamp: u32,
    pub sender_packet_count: u32,
    pub sender_octet_count: u32,
}

#[derive(Debug, Clone)]
pub struct SrReport {
    pub ssrc: u32,
    pub sender: SenderInfo,
    pub reports: Vec<ReportBlock>,
}

#[derive(Debug, Clone)]
pub struct RrReport {
    pub ssrc: u32,
    pub reports: Vec<ReportBlock>,
}

#[derive(Debug, Clone)]
pub enum RtcpMessage {
    Sr(SrReport),
    Rr(RrReport),
    Other(u8),
}

/// Parse the first RTCP member of a compound packet (the one we mainly need).
#[allow(dead_code)]
pub fn parse_first(payload: &[u8]) -> Option<RtcpMessage> {
    let members = parse_all(payload);
    members.into_iter().next()
}

/// Parse all RTCP members in a compound packet.
pub fn parse_all(payload: &[u8]) -> Vec<RtcpMessage> {
    let mut out = Vec::new();
    let mut off = 0usize;
    while off + 4 <= payload.len() {
        let rc_or_fmt = payload[off] & 0x1f;
        let pt = payload[off + 1];
        let len_words = u16::from_be_bytes([payload[off + 2], payload[off + 3]]) as usize;
        let member_bytes = (len_words + 1) * 4;
        if off + member_bytes > payload.len() {
            break;
        }
        let member = &payload[off..off + member_bytes];
        if member.len() >= 8 {
            let ssrc = u32::from_be_bytes([member[4], member[5], member[6], member[7]]);
            match pt {
                PT_SR => {
                    if member.len() >= 28 {
                        let sender = SenderInfo {
                            ntp_secs: u32::from_be_bytes([
                                member[8], member[9], member[10], member[11],
                            ]),
                            ntp_frac: u32::from_be_bytes([
                                member[12], member[13], member[14], member[15],
                            ]),
                            rtp_timestamp: u32::from_be_bytes([
                                member[16], member[17], member[18], member[19],
                            ]),
                            sender_packet_count: u32::from_be_bytes([
                                member[20], member[21], member[22], member[23],
                            ]),
                            sender_octet_count: u32::from_be_bytes([
                                member[24], member[25], member[26], member[27],
                            ]),
                        };
                        let reports = parse_report_blocks(member, 28, rc_or_fmt as usize);
                        out.push(RtcpMessage::Sr(SrReport {
                            ssrc,
                            sender,
                            reports,
                        }));
                    }
                }
                PT_RR => {
                    let reports = parse_report_blocks(member, 8, rc_or_fmt as usize);
                    out.push(RtcpMessage::Rr(RrReport { ssrc, reports }));
                }
                _ => out.push(RtcpMessage::Other(pt)),
            }
        }
        off += member_bytes;
        if member_bytes == 0 {
            break;
        }
    }
    out
}

fn parse_report_blocks(member: &[u8], start: usize, count: usize) -> Vec<ReportBlock> {
    let mut blocks = Vec::with_capacity(count);
    let mut off = start;
    for _ in 0..count {
        if off + 24 > member.len() {
            break;
        }
        let b = &member[off..off + 24];
        let ssrc = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
        let fraction_lost = b[4];
        // 24-bit signed cumulative lost: place in high bytes, arithmetic
        // shift right by 8 to sign-extend.
        let cumulative_lost = i32::from_be_bytes([b[5], b[6], b[7], 0]) >> 8;
        let highest_seq = u32::from_be_bytes([b[8], b[9], b[10], b[11]]);
        let jitter = u32::from_be_bytes([b[12], b[13], b[14], b[15]]);
        let lsr = u32::from_be_bytes([b[16], b[17], b[18], b[19]]);
        let dlsr = u32::from_be_bytes([b[20], b[21], b[22], b[23]]);
        blocks.push(ReportBlock {
            ssrc,
            fraction_lost,
            cumulative_lost,
            highest_seq,
            jitter,
            lsr,
            dlsr,
        });
        off += 24;
    }
    blocks
}

/// Convert (secs, frac) NTP to seconds.
pub fn ntp_to_seconds(secs: u32, frac: u32) -> f64 {
    secs as f64 + frac as f64 / u32::MAX as f64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_rr() -> Vec<u8> {
        // RR with one report block: RC=1, PT=201, len=7 words.
        let mut p = vec![0x81, PT_RR, 0, 7];
        p.extend_from_slice(&0x1234_5678u32.to_be_bytes()); // sender ssrc
        // report block
        let mut b = Vec::new();
        b.extend_from_slice(&0xdead_beefu32.to_be_bytes()); // reported ssrc
        b.push(12); // fraction lost 12/256
        b.extend_from_slice(&[0, 0, 5]); // cumulative lost 5
        b.extend_from_slice(&1_000u32.to_be_bytes()); // highest seq
        b.extend_from_slice(&40u32.to_be_bytes()); // jitter
        b.extend_from_slice(&0x1122_3344u32.to_be_bytes()); // LSR
        b.extend_from_slice(&32768u32.to_be_bytes()); // DLSR = 0.5s
        p.extend_from_slice(&b);
        p
    }

    #[test]
    fn parse_rr_report_block() {
        let msgs = parse_all(&build_rr());
        assert_eq!(msgs.len(), 1);
        match &msgs[0] {
            RtcpMessage::Rr(rr) => {
                assert_eq!(rr.ssrc, 0x1234_5678);
                assert_eq!(rr.reports.len(), 1);
                let b = &rr.reports[0];
                assert_eq!(b.ssrc, 0xdead_beef);
                assert_eq!(b.fraction_lost, 12);
                assert_eq!(b.cumulative_lost, 5);
                assert_eq!(b.highest_seq, 1000);
                assert_eq!(b.jitter, 40);
                assert_eq!(b.lsr, 0x1122_3344);
                assert_eq!(b.dlsr, 32768);
            }
            _ => panic!("expected RR"),
        }
    }

    #[test]
    fn parse_sr() {
        // SR: RC=0, PT=200, len=6 words
        let mut p = vec![0x80, PT_SR, 0, 6];
        p.extend_from_slice(&1u32.to_be_bytes());
        p.extend_from_slice(&3_700_000u32.to_be_bytes()); // ntp secs
        p.extend_from_slice(&0u32.to_be_bytes()); // ntp frac
        p.extend_from_slice(&160_000u32.to_be_bytes()); // rtp ts
        p.extend_from_slice(&100u32.to_be_bytes());
        p.extend_from_slice(&1600u32.to_be_bytes());
        let msgs = parse_all(&p);
        match &msgs[0] {
            RtcpMessage::Sr(sr) => {
                assert_eq!(sr.sender.rtp_timestamp, 160_000);
                assert_eq!(sr.sender.sender_packet_count, 100);
                assert!(sr.reports.is_empty());
            }
            _ => panic!("expected SR"),
        }
    }
}
