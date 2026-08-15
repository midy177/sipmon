use bytes::Bytes;
use std::net::SocketAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
pub enum Proto {
    Udp,
    Tcp,
}

impl Proto {
    pub fn as_str(self) -> &'static str {
        match self {
            Proto::Udp => "UDP",
            Proto::Tcp => "TCP",
        }
    }
}

/// L3/L4 5-tuple identifying a packet flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
pub struct Flow5Tuple {
    pub proto: Proto,
    pub src: SocketAddr,
    pub dst: SocketAddr,
}

impl Flow5Tuple {
    pub fn reverse(self) -> Self {
        Self {
            proto: self.proto,
            src: self.dst,
            dst: self.src,
        }
    }
}

impl std::fmt::Display for Flow5Tuple {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}->{}", self.proto.as_str(), self.src, self.dst)
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct CapturedPacket {
    /// Microseconds since Unix epoch.
    pub ts_us: u64,
    pub flow: Flow5Tuple,
    pub payload: Bytes,
}
