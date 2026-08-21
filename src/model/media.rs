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
    /// RTP clock rates from `a=rtpmap`, parallel to `pts`.
    pub clock_rates: Vec<u32>,
}

impl NegotiatedMedia {
    /// SDP clock for `pt`, else the static/dynamic PT default.
    pub fn clock_rate_for_pt(&self, pt: u8) -> u32 {
        self.pts
            .iter()
            .position(|p| *p == pt)
            .and_then(|i| self.clock_rates.get(i).copied())
            .filter(|&r| r > 0)
            .unwrap_or_else(|| crate::decode::rtp::rtp_clock_rate_for_payload_type(pt))
    }
}

/// One periodic (5s) throughput/quality sample for a stream.
#[derive(Debug, Clone, Copy, serde::Serialize)]
pub struct RatePoint {
    /// End of the sample window (unix microseconds).
    pub ts_us: u64,
    /// Bytes of RTP observed within the window.
    pub bytes: u64,
    /// Packets observed within the window.
    pub packets: u64,
    /// Cumulative loss % at this point.
    pub loss_pct: f64,
    /// Cumulative jitter at this point.
    pub jitter_ms: Option<f64>,
    /// Cumulative MOS estimate at this point.
    pub mos: Option<f64>,
}

/// Final summary for a single RTP stream, computed at snapshot/teardown.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct StreamSummary {
    /// Owning call (if known at snapshot time).
    pub call_id: Option<String>,
    pub ssrc: u32,
    pub flow: Option<Flow5Tuple>,
    pub codec: Option<String>,
    pub payload_type: Option<u8>,
    pub packets: u64,
    pub lost: u64,
    pub expected: u64,
    pub loss_pct: f64,
    pub jitter_ms: Option<f64>,
    pub first_ts_us: Option<u64>,
    pub last_ts_us: Option<u64>,
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
    /// Cumulative RTP bytes observed.
    pub bytes: u64,
    /// Periodic 5s throughput/quality samples (oldest first, capped).
    pub history: Vec<RatePoint>,
}
