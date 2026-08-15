//! Minimal STUN / TURN (RFC 5389 / 5766 / 8656) parser for passive diagnosis.
//!
//! Decodes the 20-byte STUN header, message class/method, common attributes
//! (XOR addresses, ERROR-CODE, CHANNEL-NUMBER, DATA, LIFETIME) and detects
//! TURN ChannelData frames (RFC 8656 demultiplexing).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

pub const MAGIC_COOKIE: u32 = 0x2112_A442;

// TURN methods (RFC 5766).
#[allow(dead_code)]
pub const METHOD_BINDING: u16 = 0x001;
pub const METHOD_ALLOCATE: u16 = 0x003;
pub const METHOD_REFRESH: u16 = 0x004;
pub const METHOD_SEND: u16 = 0x006;
pub const METHOD_DATA: u16 = 0x007;
#[allow(dead_code)]
pub const METHOD_CREATE_PERMISSION: u16 = 0x008;
pub const METHOD_CHANNEL_BIND: u16 = 0x009;

// Attribute types.
#[allow(dead_code)]
pub const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
#[allow(dead_code)]
pub const ATTR_USERNAME: u16 = 0x0006;
pub const ATTR_ERROR_CODE: u16 = 0x0009;
pub const ATTR_CHANNEL_NUMBER: u16 = 0x000C;
pub const ATTR_LIFETIME: u16 = 0x000D;
pub const ATTR_XOR_PEER_ADDRESS: u16 = 0x0012;
pub const ATTR_DATA: u16 = 0x0013;
pub const ATTR_XOR_RELAYED_ADDRESS: u16 = 0x0016;
pub const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StunClass {
    Request,
    Indication,
    Success,
    Error,
}

#[derive(Debug, Clone)]
pub struct StunAttribute {
    pub typ: u16,
    pub value: Vec<u8>,
}

impl StunAttribute {
    pub fn error_code(&self) -> Option<(u16, String)> {
        if self.typ != ATTR_ERROR_CODE || self.value.len() < 4 {
            return None;
        }
        let class = self.value[2] as u16;
        let number = self.value[3] as u16;
        let reason = String::from_utf8_lossy(&self.value[4..]).into_owned();
        Some((class * 100 + number, reason))
    }

    pub fn channel_number(&self) -> Option<u16> {
        if self.typ != ATTR_CHANNEL_NUMBER || self.value.len() < 4 {
            return None;
        }
        Some(u16::from_be_bytes([self.value[0], self.value[1]]))
    }

    pub fn lifetime(&self) -> Option<u32> {
        if self.typ != ATTR_LIFETIME || self.value.len() < 4 {
            return None;
        }
        Some(u32::from_be_bytes([
            self.value[0],
            self.value[1],
            self.value[2],
            self.value[3],
        ]))
    }

    pub fn data(&self) -> Option<&[u8]> {
        (self.typ == ATTR_DATA).then_some(&self.value[..])
    }

    /// Decode an XOR-* address attribute using the transaction ID.
    pub fn xor_address(&self, txn_id: &[u8; 12]) -> Option<SocketAddr> {
        if !matches!(
            self.typ,
            ATTR_XOR_MAPPED_ADDRESS | ATTR_XOR_RELAYED_ADDRESS | ATTR_XOR_PEER_ADDRESS
        ) || self.value.len() < 4
        {
            return None;
        }
        let family = self.value[1];
        let xport =
            u16::from_be_bytes([self.value[2], self.value[3]]) ^ (MAGIC_COOKIE >> 16) as u16;
        let key: Vec<u8> = MAGIC_COOKIE
            .to_be_bytes()
            .iter()
            .chain(txn_id.iter())
            .copied()
            .collect();
        match family {
            0x01 => {
                if self.value.len() < 8 {
                    return None;
                }
                let mut ip = [0u8; 4];
                for i in 0..4 {
                    ip[i] = self.value[4 + i] ^ key[i];
                }
                Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), xport))
            }
            0x02 => {
                if self.value.len() < 20 {
                    return None;
                }
                let mut ip = [0u8; 16];
                for i in 0..16 {
                    ip[i] = self.value[4 + i] ^ key[i];
                }
                Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip)), xport))
            }
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct StunMessage {
    pub method: u16,
    pub class: StunClass,
    pub txn_id: [u8; 12],
    pub attrs: Vec<StunAttribute>,
}

impl StunMessage {
    #[allow(dead_code)]
    pub fn is_allocate_error(&self) -> bool {
        self.method == METHOD_ALLOCATE && self.class == StunClass::Error
    }
    pub fn error_code(&self) -> Option<(u16, String)> {
        self.attrs.iter().find_map(|a| a.error_code())
    }
    pub fn relayed_address(&self) -> Option<SocketAddr> {
        self.attrs
            .iter()
            .find(|a| a.typ == ATTR_XOR_RELAYED_ADDRESS)
            .and_then(|a| a.xor_address(&self.txn_id))
    }
    pub fn peer_address(&self) -> Option<SocketAddr> {
        self.attrs
            .iter()
            .find(|a| a.typ == ATTR_XOR_PEER_ADDRESS)
            .and_then(|a| a.xor_address(&self.txn_id))
    }
    pub fn data_payload(&self) -> Option<&[u8]> {
        self.attrs.iter().find_map(|a| a.data())
    }
}

fn stun_method(typ: u16) -> u16 {
    (typ & 0x000F) | ((typ >> 1) & 0x0070)
}

fn stun_class(typ: u16) -> StunClass {
    let c = (((typ >> 8) & 1) << 1) | ((typ >> 4) & 1);
    match c {
        0 => StunClass::Request,
        1 => StunClass::Indication,
        2 => StunClass::Success,
        _ => StunClass::Error,
    }
}

/// True if `data` starts with a STUN message (20-byte header + magic cookie).
pub fn is_stun(data: &[u8]) -> bool {
    data.len() >= 20 && u32::from_be_bytes([data[4], data[5], data[6], data[7]]) == MAGIC_COOKIE
}

/// RFC 8656 demultiplexing: 0x00-0x3F = STUN, 0x40-0x7F = ChannelData.
pub fn is_channel_data(data: &[u8]) -> bool {
    data.len() >= 4 && (data[0] & 0xC0) == 0x40
}

/// Channel number of a ChannelData frame.
#[allow(dead_code)]
pub fn channel_number(data: &[u8]) -> Option<u16> {
    if !is_channel_data(data) {
        return None;
    }
    Some((((data[0] & 0x3F) as u16) << 8) | data[1] as u16)
}

/// Payload of a ChannelData frame (after the 4-byte header).
pub fn channel_data_payload(data: &[u8]) -> Option<&[u8]> {
    if !is_channel_data(data) {
        return None;
    }
    let len = u16::from_be_bytes([data[2], data[3]]) as usize;
    if 4 + len > data.len() {
        return None;
    }
    Some(&data[4..4 + len])
}

pub fn parse(data: &[u8]) -> Option<StunMessage> {
    if !is_stun(data) {
        return None;
    }
    let typ = u16::from_be_bytes([data[0], data[1]]);
    let len = u16::from_be_bytes([data[2], data[3]]) as usize;
    if 20 + len > data.len() {
        return None;
    }
    let mut txn_id = [0u8; 12];
    txn_id.copy_from_slice(&data[8..20]);
    let method = stun_method(typ);
    let class = stun_class(typ);

    let mut attrs = Vec::new();
    let mut off = 20usize;
    let end = 20 + len;
    while off + 4 <= end {
        let atyp = u16::from_be_bytes([data[off], data[off + 1]]);
        let alen = u16::from_be_bytes([data[off + 2], data[off + 3]]) as usize;
        if off + 4 + alen > end {
            break;
        }
        let value = data[off + 4..off + 4 + alen].to_vec();
        attrs.push(StunAttribute { typ: atyp, value });
        off += 4 + alen.div_ceil(4) * 4;
    }

    Some(StunMessage {
        method,
        class,
        txn_id,
        attrs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn xor_addr_bytes(addr: SocketAddr, txn: &[u8; 12]) -> Vec<u8> {
        let key: Vec<u8> = MAGIC_COOKIE
            .to_be_bytes()
            .iter()
            .chain(txn.iter())
            .copied()
            .collect();
        let mut out = vec![0u8, 0x01]; // reserved, family IPv4
        let xport = addr.port() ^ (MAGIC_COOKIE >> 16) as u16;
        out.extend_from_slice(&xport.to_be_bytes());
        if let IpAddr::V4(v4) = addr.ip() {
            for (i, b) in v4.octets().iter().enumerate() {
                out.push(b ^ key[i]);
            }
        }
        out
    }

    fn stun(typ: u16, txn: &[u8; 12], attrs: &[(u16, Vec<u8>)]) -> Vec<u8> {
        let mut body = Vec::new();
        for (at, av) in attrs {
            body.extend_from_slice(&at.to_be_bytes());
            body.extend_from_slice(&(av.len() as u16).to_be_bytes());
            body.extend_from_slice(av);
            while body.len() % 4 != 0 {
                body.push(0);
            }
        }
        let mut out = Vec::new();
        out.extend_from_slice(&typ.to_be_bytes());
        out.extend_from_slice(&(body.len() as u16).to_be_bytes());
        out.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        out.extend_from_slice(txn);
        out.extend_from_slice(&body);
        out
    }

    #[test]
    fn parse_allocate_request() {
        let txn = [7u8; 12];
        let data = stun(METHOD_ALLOCATE, &txn, &[(ATTR_USERNAME, b"alice".to_vec())]);
        assert!(is_stun(&data));
        let m = parse(&data).unwrap();
        assert_eq!(m.method, METHOD_ALLOCATE);
        assert_eq!(m.class, StunClass::Request);
        assert_eq!(m.attrs.len(), 1);
    }

    #[test]
    fn parse_allocate_success_with_relayed() {
        let txn = [9u8; 12];
        let relayed: SocketAddr = "203.0.113.7:50000".parse().unwrap();
        let av = xor_addr_bytes(relayed, &txn);
        let data = stun(
            METHOD_ALLOCATE | 0x0100, // success response class
            &txn,
            &[
                (ATTR_XOR_RELAYED_ADDRESS, av),
                (ATTR_LIFETIME, 600u32.to_be_bytes().to_vec()),
            ],
        );
        let m = parse(&data).unwrap();
        assert_eq!(m.class, StunClass::Success);
        assert_eq!(m.relayed_address(), Some(relayed));
        assert!(m.attrs.iter().any(|a| a.lifetime() == Some(600)));
    }

    #[test]
    fn parse_allocate_error() {
        let txn = [1u8; 12];
        // ERROR-CODE: reserved(2) + class(1) + number(1) + reason
        let mut ev = vec![0, 0, 4, 86];
        ev.extend_from_slice(b"Allocation Quota Reached");
        let data = stun(
            METHOD_ALLOCATE | 0x0110, // error response class
            &txn,
            &[(ATTR_ERROR_CODE, ev)],
        );
        let m = parse(&data).unwrap();
        assert!(m.is_allocate_error());
        let (code, reason) = m.error_code().unwrap();
        assert_eq!(code, 486);
        assert!(reason.contains("Quota"));
    }

    #[test]
    fn parse_channel_data() {
        let rtp = [0x80u8, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0xAA];
        let mut frame = vec![0x40, 0x01]; // channel 1
        frame.extend_from_slice(&(rtp.len() as u16).to_be_bytes());
        frame.extend_from_slice(&rtp);
        assert!(is_channel_data(&frame));
        assert!(!is_stun(&frame));
        assert_eq!(channel_number(&frame), Some(1));
        assert_eq!(channel_data_payload(&frame), Some(&rtp[..]));
    }

    #[test]
    fn parse_send_indication_data_attr() {
        let txn = [3u8; 12];
        let inner = [0x80u8, 0, 5, 6, 0, 0, 0, 0, 0, 0, 0, 2];
        let data = stun(METHOD_SEND | 0x0010, &txn, &[(ATTR_DATA, inner.to_vec())]);
        let m = parse(&data).unwrap();
        assert_eq!(m.method, METHOD_SEND);
        assert_eq!(m.class, StunClass::Indication);
        assert_eq!(m.data_payload(), Some(&inner[..]));
    }
}
