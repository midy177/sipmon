use etherparse::SlicedPacket;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::model::packet::{Flow5Tuple, Proto};

/// Well-known pcap datalink types we support.
pub const DLT_EN10MB: u32 = 1;
pub const DLT_RAW: u32 = 12;
pub const DLT_LINUX_SLL: u32 = 113;
pub const DLT_LINUX_SLL2: u32 = 276;

pub enum L4<'a> {
    Udp(&'a [u8]),
    Tcp(&'a [u8]),
}

pub struct Decoded<'a> {
    pub flow: Flow5Tuple,
    pub l4: L4<'a>,
}

fn ip_from_v4(b: [u8; 4]) -> IpAddr {
    IpAddr::V4(Ipv4Addr::from(b))
}
fn ip_from_v6(b: [u8; 16]) -> IpAddr {
    IpAddr::V6(Ipv6Addr::from(b))
}

enum Fast<'a> {
    Hit(Decoded<'a>),
    /// Not IP / not UDP-TCP: do not spend time in etherparse.
    Miss,
    /// Unusual encapsulation; try the full parser.
    Fallback,
}

/// Decode one captured frame into a 5-tuple + L4 payload.
///
/// `linktype` is the pcap DLT of the source. Supports Ethernet (incl. VLAN),
/// Linux cooked v1/v2, and raw IP. Returns None for non-IP or non-UDP/TCP.
///
/// The L4 payload is a borrow of `data` — callers must not retain it past the
/// originating capture buffer.
pub fn decode(linktype: u32, data: &[u8]) -> Option<Decoded<'_>> {
    match decode_fast(linktype, data) {
        Fast::Hit(d) => Some(d),
        Fast::Miss => None,
        Fast::Fallback => decode_etherparse(linktype, data),
    }
}

fn decode_fast(linktype: u32, data: &[u8]) -> Fast<'_> {
    let ip = match l2_payload(linktype, data) {
        FastL2::Ip(p) => p,
        FastL2::Miss => return Fast::Miss,
        FastL2::Fallback => return Fast::Fallback,
    };
    if ip.is_empty() {
        return Fast::Miss;
    }
    match ip[0] >> 4 {
        4 => parse_ipv4(ip),
        6 => parse_ipv6(ip),
        _ => Fast::Miss,
    }
}

enum FastL2<'a> {
    Ip(&'a [u8]),
    Miss,
    Fallback,
}

fn l2_payload(linktype: u32, data: &[u8]) -> FastL2<'_> {
    match linktype {
        DLT_EN10MB => ethernet_payload(data),
        DLT_RAW => FastL2::Ip(data),
        DLT_LINUX_SLL => {
            if data.len() < 16 {
                return FastL2::Miss;
            }
            ethertype_payload(u16::from_be_bytes([data[14], data[15]]), &data[16..])
        }
        DLT_LINUX_SLL2 => {
            if data.len() < 20 {
                return FastL2::Miss;
            }
            ethertype_payload(u16::from_be_bytes([data[0], data[1]]), &data[20..])
        }
        _ => FastL2::Fallback,
    }
}

fn ethernet_payload(data: &[u8]) -> FastL2<'_> {
    if data.len() < 14 {
        return FastL2::Miss;
    }
    let mut ethertype = u16::from_be_bytes([data[12], data[13]]);
    let mut off = 14usize;
    // 802.1Q / QinQ / 802.1Q-in-Q vendor tag.
    for _ in 0..2 {
        if ethertype != 0x8100 && ethertype != 0x88a8 && ethertype != 0x9100 {
            break;
        }
        if data.len() < off + 4 {
            return FastL2::Miss;
        }
        ethertype = u16::from_be_bytes([data[off + 2], data[off + 3]]);
        off += 4;
    }
    ethertype_payload(ethertype, data.get(off..).unwrap_or(&[]))
}

fn ethertype_payload(ethertype: u16, rest: &[u8]) -> FastL2<'_> {
    match ethertype {
        0x0800 | 0x86dd => FastL2::Ip(rest),
        _ => FastL2::Miss,
    }
}

fn parse_ipv4(data: &[u8]) -> Fast<'_> {
    if data.len() < 20 {
        return Fast::Miss;
    }
    let ihl = (data[0] & 0x0f) as usize * 4;
    if ihl < 20 || data.len() < ihl {
        return Fast::Miss;
    }
    // Non-first fragments have no L4 header.
    let frag = u16::from_be_bytes([data[6], data[7]]);
    if frag & 0x1fff != 0 {
        return Fast::Miss;
    }
    let proto = data[9];
    let src = ip_from_v4([data[12], data[13], data[14], data[15]]);
    let dst = ip_from_v4([data[16], data[17], data[18], data[19]]);
    let total = u16::from_be_bytes([data[2], data[3]]) as usize;
    let ip_end = if total >= ihl && total <= data.len() {
        total
    } else {
        data.len()
    };
    parse_l4(proto, src, dst, &data[ihl..ip_end])
}

fn parse_ipv6(data: &[u8]) -> Fast<'_> {
    if data.len() < 40 {
        return Fast::Miss;
    }
    let next = data[6];
    // Extension headers: let etherparse walk them.
    if next != 6 && next != 17 {
        return if next == 58 {
            Fast::Miss
        } else {
            Fast::Fallback
        };
    }
    let mut src = [0u8; 16];
    let mut dst = [0u8; 16];
    src.copy_from_slice(&data[8..24]);
    dst.copy_from_slice(&data[24..40]);
    let payload_len = u16::from_be_bytes([data[4], data[5]]) as usize;
    let end = if payload_len > 0 {
        (40 + payload_len).min(data.len())
    } else {
        data.len()
    };
    if end < 40 {
        return Fast::Miss;
    }
    parse_l4(next, ip_from_v6(src), ip_from_v6(dst), &data[40..end])
}

fn parse_l4(proto: u8, src_ip: IpAddr, dst_ip: IpAddr, l4: &[u8]) -> Fast<'_> {
    match proto {
        17 => {
            if l4.len() < 8 {
                return Fast::Miss;
            }
            let src_port = u16::from_be_bytes([l4[0], l4[1]]);
            let dst_port = u16::from_be_bytes([l4[2], l4[3]]);
            let ulen = u16::from_be_bytes([l4[4], l4[5]]) as usize;
            let payload = if ulen >= 8 && ulen <= l4.len() {
                &l4[8..ulen]
            } else {
                &l4[8..]
            };
            Fast::Hit(Decoded {
                flow: Flow5Tuple {
                    proto: Proto::Udp,
                    src: SocketAddr::new(src_ip, src_port),
                    dst: SocketAddr::new(dst_ip, dst_port),
                },
                l4: L4::Udp(payload),
            })
        }
        6 => {
            if l4.len() < 20 {
                return Fast::Miss;
            }
            let src_port = u16::from_be_bytes([l4[0], l4[1]]);
            let dst_port = u16::from_be_bytes([l4[2], l4[3]]);
            let doff = ((l4[12] >> 4) as usize) * 4;
            if doff < 20 || l4.len() < doff {
                return Fast::Miss;
            }
            Fast::Hit(Decoded {
                flow: Flow5Tuple {
                    proto: Proto::Tcp,
                    src: SocketAddr::new(src_ip, src_port),
                    dst: SocketAddr::new(dst_ip, dst_port),
                },
                l4: L4::Tcp(&l4[doff..]),
            })
        }
        _ => Fast::Miss,
    }
}

fn decode_etherparse(linktype: u32, data: &[u8]) -> Option<Decoded<'_>> {
    let sliced: SlicedPacket<'_> = match linktype {
        DLT_EN10MB => SlicedPacket::from_ethernet(data).ok()?,
        DLT_RAW => SlicedPacket::from_ip(data).ok()?,
        DLT_LINUX_SLL => {
            let ip = data.get(16..)?;
            SlicedPacket::from_ip(ip).ok()?
        }
        DLT_LINUX_SLL2 => {
            let ip = data.get(20..)?;
            SlicedPacket::from_ip(ip).ok()?
        }
        _ => SlicedPacket::from_ethernet(data).ok()?,
    };

    let net = sliced.net?;
    let (src_ip, dst_ip) = match net {
        etherparse::NetSlice::Ipv4(v) => (
            ip_from_v4(v.header().source()),
            ip_from_v4(v.header().destination()),
        ),
        etherparse::NetSlice::Ipv6(v) => (
            ip_from_v6(v.header().source()),
            ip_from_v6(v.header().destination()),
        ),
    };

    let (proto, src_port, dst_port, payload) = match sliced.transport? {
        etherparse::TransportSlice::Udp(u) => (
            Proto::Udp,
            u.source_port(),
            u.destination_port(),
            u.payload(),
        ),
        etherparse::TransportSlice::Tcp(t) => (
            Proto::Tcp,
            t.source_port(),
            t.destination_port(),
            t.payload(),
        ),
        _ => return None,
    };

    let flow = Flow5Tuple {
        proto,
        src: SocketAddr::new(src_ip, src_port),
        dst: SocketAddr::new(dst_ip, dst_port),
    };

    let l4 = match proto {
        Proto::Udp => L4::Udp(payload),
        Proto::Tcp => L4::Tcp(payload),
    };

    Some(Decoded { flow, l4 })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn eth_ipv4_udp(payload: &[u8]) -> Vec<u8> {
        let mut pkt = vec![0u8; 14 + 20 + 8 + payload.len()];
        pkt[12] = 0x08;
        pkt[13] = 0x00;
        pkt[14] = 0x45;
        let total = (20 + 8 + payload.len()) as u16;
        pkt[16..18].copy_from_slice(&total.to_be_bytes());
        pkt[23] = 17; // UDP
        pkt[26..30].copy_from_slice(&[10, 0, 0, 1]);
        pkt[30..34].copy_from_slice(&[10, 0, 0, 2]);
        pkt[34..36].copy_from_slice(&5060u16.to_be_bytes());
        pkt[36..38].copy_from_slice(&5060u16.to_be_bytes());
        let ulen = (8 + payload.len()) as u16;
        pkt[38..40].copy_from_slice(&ulen.to_be_bytes());
        pkt[42..].copy_from_slice(payload);
        pkt
    }

    #[test]
    fn fast_path_ethernet_ipv4_udp() {
        let pkt = eth_ipv4_udp(b"INVITE sip:x SIP/2.0");
        let d = decode(DLT_EN10MB, &pkt).expect("decode");
        assert_eq!(d.flow.src.port(), 5060);
        assert_eq!(d.flow.dst.port(), 5060);
        match d.l4 {
            L4::Udp(p) => assert_eq!(p, b"INVITE sip:x SIP/2.0"),
            L4::Tcp(_) => panic!("expected UDP"),
        }
        assert!(matches!(decode_fast(DLT_EN10MB, &pkt), Fast::Hit(_)));
    }

    #[test]
    fn vlan_ethernet_ipv4_udp() {
        let inner = eth_ipv4_udp(b"rtp");
        let mut pkt = Vec::with_capacity(inner.len() + 4);
        pkt.extend_from_slice(&inner[..12]);
        pkt.extend_from_slice(&[0x81, 0x00, 0x00, 0x01]);
        pkt.extend_from_slice(&inner[12..]);
        let d = decode(DLT_EN10MB, &pkt).expect("vlan decode");
        match d.l4 {
            L4::Udp(p) => assert_eq!(p, b"rtp"),
            L4::Tcp(_) => panic!("expected UDP"),
        }
    }

    #[test]
    fn arp_is_skipped_without_fallback() {
        let mut pkt = vec![0u8; 42];
        pkt[12] = 0x08;
        pkt[13] = 0x06;
        assert!(matches!(decode_fast(DLT_EN10MB, &pkt), Fast::Miss));
        assert!(decode(DLT_EN10MB, &pkt).is_none());
    }

    #[test]
    fn raw_ipv4_udp() {
        let eth = eth_ipv4_udp(b"x");
        let ip = &eth[14..];
        let d = decode(DLT_RAW, ip).expect("raw");
        match d.l4 {
            L4::Udp(p) => assert_eq!(p, b"x"),
            L4::Tcp(_) => panic!("expected UDP"),
        }
    }
}
