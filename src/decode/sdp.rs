use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone)]
pub struct SdpCodec {
    pub pt: u8,
    pub name: String,
    #[allow(dead_code)]
    pub clock_rate: u32,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct SdpMedia {
    pub media: String,
    pub port: u16,
    pub proto: String,
    pub formats: Vec<String>,
    pub connection_ip: Option<IpAddr>,
    pub codecs: Vec<SdpCodec>,
}

#[derive(Debug, Clone, Default)]
pub struct SdpSession {
    pub connection_ip: Option<IpAddr>,
    pub media: Vec<SdpMedia>,
}

impl SdpSession {
    /// All media endpoints (ip:port) advertised, resolved against connection IP.
    pub fn endpoints(&self) -> Vec<std::net::SocketAddr> {
        let mut out = Vec::new();
        for m in &self.media {
            if m.port == 0 {
                continue;
            }
            if let Some(ip) = m.connection_ip.or(self.connection_ip) {
                out.push(std::net::SocketAddr::new(ip, m.port));
            }
        }
        out
    }

    /// Union of all negotiated payload types.
    pub fn payload_types(&self) -> Vec<u8> {
        let mut pts: Vec<u8> = self
            .media
            .iter()
            .flat_map(|m| m.formats.iter().filter_map(|f| f.parse::<u8>().ok()))
            .collect();
        pts.sort_unstable();
        pts.dedup();
        pts
    }

    pub fn codec_name_for_pt(&self, pt: u8) -> Option<String> {
        for m in &self.media {
            if let Some(c) = m.codecs.iter().find(|c| c.pt == pt) {
                return Some(c.name.clone());
            }
        }
        // Static payload type fallback.
        Some(static_codec_name(pt)?).map(|s| s.to_string())
    }
}

pub fn static_codec_name(pt: u8) -> Option<&'static str> {
    Some(match pt {
        0 => "PCMU",
        8 => "PCMA",
        9 => "G.722",
        18 => "G.729",
        4 | 15 | 16 => "G.723",
        13 => "CN",
        97 | 98 | 111 | 112 | 115 => "OPUS",
        101 => "telephone-event",
        _ => return None,
    })
}

fn parse_ip(s: &str) -> Option<IpAddr> {
    let s = s.trim();
    // Forms: "IN IP4 1.2.3.4" | "IN IP6 ::1" | "IP4 1.2.3.4" | "1.2.3.4"
    let tokens: Vec<&str> = s.split_whitespace().collect();
    let addr_tok = match tokens.as_slice() {
        [.., last] if !tokens.is_empty() => *last,
        _ => return None,
    };
    addr_tok
        .parse::<Ipv4Addr>()
        .ok()
        .map(IpAddr::V4)
        .or_else(|| addr_tok.parse::<Ipv6Addr>().ok().map(IpAddr::V6))
}

pub fn parse(body: &[u8]) -> Option<SdpSession> {
    let text = std::str::from_utf8(body).ok()?;
    let mut session = SdpSession::default();
    let mut current: Option<SdpMedia> = None;

    let mut rtpmap: Vec<SdpCodec> = Vec::new();

    for line in text.lines() {
        let line = line.trim();
        let (key, val) = match line.split_once('=') {
            Some((k, v)) => (k, v.trim()),
            None => continue,
        };
        match key {
            "c" => {
                let ip = parse_ip(val);
                if let Some(m) = current.as_mut() {
                    m.connection_ip = ip;
                } else {
                    session.connection_ip = ip;
                }
            }
            "m" => {
                if let Some(m) = current.take() {
                    session.media.push(m);
                }
                let mut parts = val.split_whitespace();
                let media = parts.next().unwrap_or("audio").to_string();
                let port: u16 = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
                let proto = parts.next().unwrap_or("RTP/AVP").to_string();
                let formats: Vec<String> = parts.map(String::from).collect();
                current = Some(SdpMedia {
                    media,
                    port,
                    proto,
                    formats,
                    connection_ip: None,
                    codecs: Vec::new(),
                });
            }
            "a" => {
                if let Some(rest) = val.strip_prefix("rtpmap:") {
                    // rtpmap:<pt> <codec>/<clock>[/<enc>]
                    if let Some((pt_s, desc)) = rest.split_once(' ')
                        && let Ok(pt) = pt_s.trim().parse::<u8>()
                    {
                        let mut dit = desc.trim().split('/');
                        let name = dit.next().unwrap_or("").to_string();
                        let clock: u32 = dit.next().and_then(|c| c.parse().ok()).unwrap_or(8000);
                        rtpmap.push(SdpCodec {
                            pt,
                            name,
                            clock_rate: clock,
                        });
                    }
                }
            }
            _ => {}
        }
    }
    if let Some(m) = current.take() {
        session.media.push(m);
    }
    // attach rtpmap to the right media lines (by pt presence)
    for m in session.media.iter_mut() {
        for c in &rtpmap {
            if m.formats.iter().any(|f| f == &c.pt.to_string()) {
                m.codecs.push(c.clone());
            }
        }
    }
    Some(session)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_basic_sdp() {
        let body = b"v=0\r\no=- 1 1 IN IP4 10.0.0.1\r\ns=-\r\nc=IN IP4 10.0.0.1\r\nt=0 0\r\nm=audio 5004 RTP/AVP 0 8 101\r\na=rtpmap:0 PCMU/8000\r\na=rtpmap:101 telephone-event/8000\r\n";
        let s = parse(body).unwrap();
        assert_eq!(s.connection_ip, Some("10.0.0.1".parse().unwrap()));
        let eps = s.endpoints();
        assert_eq!(eps.len(), 1);
        assert_eq!(eps[0].to_string(), "10.0.0.1:5004");
        let pts = s.payload_types();
        assert!(pts.contains(&0) && pts.contains(&8) && pts.contains(&101));
        assert_eq!(s.codec_name_for_pt(0), Some("PCMU".into()));
        assert_eq!(s.codec_name_for_pt(101), Some("telephone-event".into()));
    }
}
