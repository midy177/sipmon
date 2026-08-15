use bytes::Bytes;
use etherparse::SlicedPacket;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::model::packet::{Flow5Tuple, Proto};

/// Well-known pcap datalink types we support.
pub const DLT_EN10MB: u32 = 1;
pub const DLT_RAW: u32 = 12;
pub const DLT_LINUX_SLL: u32 = 113;
pub const DLT_LINUX_SLL2: u32 = 276;

pub enum L4 {
    Udp(Bytes),
    Tcp(Bytes),
    #[allow(dead_code)]
    Other,
}

pub struct Decoded {
    pub flow: Flow5Tuple,
    pub l4: L4,
}

fn ip_from_v4(b: [u8; 4]) -> IpAddr {
    IpAddr::V4(Ipv4Addr::from(b))
}
fn ip_from_v6(b: [u8; 16]) -> IpAddr {
    IpAddr::V6(Ipv6Addr::from(b))
}

/// Decode one captured frame into a 5-tuple + L4 payload.
///
/// `linktype` is the pcap DLT of the source. Supports Ethernet (incl. VLAN),
/// Linux cooked v1/v2, and raw IP. Returns None for non-IP or non-UDP/TCP.
pub fn decode(linktype: u32, data: &[u8]) -> Option<Decoded> {
    let sliced: SlicedPacket<'_> = match linktype {
        DLT_EN10MB => SlicedPacket::from_ethernet(data).ok()?,
        DLT_RAW => SlicedPacket::from_ip(data).ok()?,
        DLT_LINUX_SLL => {
            // SLL: 16-byte header, then IP. protocol field @ offset 14 (big-endian).
            let ip = data.get(16..)?;
            SlicedPacket::from_ip(ip).ok()?
        }
        DLT_LINUX_SLL2 => {
            // SLL2: 20-byte header, then IP.
            let ip = data.get(20..)?;
            SlicedPacket::from_ip(ip).ok()?
        }
        _ => SlicedPacket::from_ethernet(data).ok()?,
    };

    let net = sliced.net?;
    let (src_ip, dst_ip, l4payload) = match net {
        etherparse::NetSlice::Ipv4(v) => (
            ip_from_v4(v.header().source()),
            ip_from_v4(v.header().destination()),
            v.payload().payload,
        ),
        etherparse::NetSlice::Ipv6(v) => (
            ip_from_v6(v.header().source()),
            ip_from_v6(v.header().destination()),
            v.payload().payload,
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
    let _ = l4payload;

    let flow = Flow5Tuple {
        proto,
        src: SocketAddr::new(src_ip, src_port),
        dst: SocketAddr::new(dst_ip, dst_port),
    };

    let l4 = match proto {
        Proto::Udp => L4::Udp(Bytes::copy_from_slice(payload)),
        Proto::Tcp => L4::Tcp(Bytes::copy_from_slice(payload)),
    };

    Some(Decoded { flow, l4 })
}
