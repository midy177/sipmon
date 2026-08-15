use crate::model::packet::Flow5Tuple;
use std::net::SocketAddr;

/// One RTT sample derived from an RTCP RR (LSR/DLSR) or SR exchange.
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub struct RtcpRtt {
    pub ts_us: u64,
    pub ssrc: u32,
    pub rtt_ms: f64,
    pub oneway_ms: Option<f64>,
}

/// Negotiated media for a call, derived from SDP offer/answer.
#[derive(Debug, Clone, Default)]
pub struct NegotiatedMedia {
    /// SDP-advertised RTP endpoints (ip:port) for this call.
    pub endpoints: Vec<SocketAddr>,
    /// Negotiated payload types.
    pub pts: Vec<u8>,
    /// Codec names (parallel-ish to pts).
    pub codecs: Vec<String>,
}

/// Final summary for a single RTP stream, computed at snapshot/teardown.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct StreamSummary {
    pub ssrc: u32,
    pub flow: Option<Flow5Tuple>,
    pub codec: Option<String>,
    pub payload_type: Option<u8>,
    pub packets: u64,
    pub lost: u64,
    pub expected: u64,
    pub loss_pct: f64,
    pub jitter_ms: Option<f64>,
    pub rtt_min_ms: Option<f64>,
    pub rtt_avg_ms: Option<f64>,
    pub rtt_max_ms: Option<f64>,
    pub oneway_ms: Option<f64>,
    pub mos: Option<f64>,
    pub direction: Option<String>,
    /// Relay leg label for TURN-relayed media: "client" | "peer" | None.
    pub leg: Option<String>,
    /// True if this stream traversed a learned TURN relay.
    pub via_turn: bool,
}
