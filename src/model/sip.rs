use bytes::Bytes;
use std::net::SocketAddr;

use crate::model::media::NegotiatedMedia;
use crate::model::packet::Flow5Tuple;

/// Lightweight SIP method mirror (serializable, decoupled from rsipstack).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Method {
    Invite,
    Ack,
    Bye,
    Cancel,
    Register,
    Options,
    Prack,
    Update,
    Subscribe,
    Notify,
    Publish,
    Info,
    Refer,
    Message,
    #[allow(dead_code)]
    Other,
}

impl Method {
    pub fn name(self) -> &'static str {
        match self {
            Method::Invite => "INVITE",
            Method::Ack => "ACK",
            Method::Bye => "BYE",
            Method::Cancel => "CANCEL",
            Method::Register => "REGISTER",
            Method::Options => "OPTIONS",
            Method::Prack => "PRACK",
            Method::Update => "UPDATE",
            Method::Subscribe => "SUBSCRIBE",
            Method::Notify => "NOTIFY",
            Method::Publish => "PUBLISH",
            Method::Info => "INFO",
            Method::Refer => "REFER",
            Method::Message => "MESSAGE",
            Method::Other => "OTHER",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
pub enum CallState {
    Dialing,
    Ringing,
    Active,
    Completed,
    Failed,
    Canceled,
}

impl CallState {
    pub fn label(self) -> &'static str {
        match self {
            CallState::Dialing => "Dialing",
            CallState::Ringing => "Ringing",
            CallState::Active => "Active",
            CallState::Completed => "Completed",
            CallState::Failed => "Failed",
            CallState::Canceled => "Canceled",
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct HangupCause {
    pub code: Option<u32>,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum Outcome {
    /// Not yet terminated.
    #[allow(dead_code)]
    InProgress,
    Answered,
    Rejected,
    #[allow(dead_code)]
    NoAnswer,
    Canceled,
    Failed,
}

/// A SIP leg within a call (a dialog direction).
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct Leg {
    pub from_tag: Option<String>,
    pub to_tag: Option<String>,
    pub branch: Option<String>,
    pub remote: Option<SocketAddr>,
    pub local: Option<SocketAddr>,
}

/// A classified/decoded SIP message relevant to analysis.
#[derive(Debug, Clone)]
pub struct SipMsg {
    pub ts_us: u64,
    pub flow: Flow5Tuple,
    pub is_request: bool,
    pub method: Option<Method>,
    pub status: Option<u16>,
    pub call_id: String,
    pub cseq: Option<u32>,
    pub cseq_method: Option<String>,
    pub branch: Option<String>,
    pub from_tag: Option<String>,
    pub to_tag: Option<String>,
    pub from_uri: Option<String>,
    pub to_uri: Option<String>,
    /// Raw message bytes (optionally truncated by Config::raw_truncate).
    pub raw: Bytes,

    // --- diagnostic-relevant fields (cheap to extract) ---
    pub contact_addr: Option<SocketAddr>,
    pub route_count: usize,
    pub record_route_count: usize,
    pub has_sdp: bool,
}

/// Aggregate per-call state tracked by the correlator.
#[derive(Debug, Clone)]
pub struct Call {
    pub call_id: String,
    pub from_uri: Option<String>,
    pub to_uri: Option<String>,
    pub from_user: Option<String>,
    pub to_user: Option<String>,
    pub state: CallState,
    pub outcome: Outcome,
    pub hangup: HangupCause,
    #[allow(dead_code)]
    pub legs: Vec<Leg>,
    /// Ordered list of SIP messages observed for this call.
    pub messages: Vec<SipMsg>,
    pub invite_ts: Option<u64>,
    pub trying_ts: Option<u64>,
    pub ringing_ts: Option<u64>,
    pub answer_ts: Option<u64>,
    pub bye_ts: Option<u64>,
    pub end_ts: Option<u64>,
    pub pdd_ms: Option<u32>,
    pub setup_ms: Option<u32>,
    pub pkts_sip: u64,
    pub pkts_rtp: u64,
    pub pkts_rtcp: u64,
    pub bytes: u64,
    /// Negotiated media from SDP offer/answer.
    #[allow(dead_code)]
    pub negotiated: NegotiatedMedia,
    /// Diagnostic counts (for the call-list column).
    pub warn_count: u32,
    pub critical_count: u32,
    /// True if any media stream traversed a learned TURN relay.
    pub via_turn: bool,
    /// Remote IP key for heatmap (source IP of the first INVITE), kept on the
    /// call so it survives message-buffer trimming.
    pub invite_key: Option<String>,
}

impl Call {
    pub fn new(call_id: String) -> Self {
        Self {
            call_id,
            from_uri: None,
            to_uri: None,
            from_user: None,
            to_user: None,
            state: CallState::Dialing,
            outcome: Outcome::InProgress,
            hangup: HangupCause::default(),
            legs: Vec::new(),
            messages: Vec::new(),
            invite_ts: None,
            trying_ts: None,
            ringing_ts: None,
            answer_ts: None,
            bye_ts: None,
            end_ts: None,
            pdd_ms: None,
            setup_ms: None,
            pkts_sip: 0,
            pkts_rtp: 0,
            pkts_rtcp: 0,
            bytes: 0,
            negotiated: NegotiatedMedia::default(),
            warn_count: 0,
            critical_count: 0,
            via_turn: false,
            invite_key: None,
        }
    }

    pub fn duration_ms(&self) -> Option<u64> {
        match (self.invite_ts, self.end_ts.or(self.bye_ts)) {
            (Some(a), Some(b)) if b >= a => Some((b - a) / 1000),
            _ => None,
        }
    }

    #[allow(dead_code)]
    pub fn talk_ms(&self) -> Option<u64> {
        match (self.answer_ts, self.end_ts.or(self.bye_ts)) {
            (Some(a), Some(b)) if b >= a => Some((b - a) / 1000),
            _ => None,
        }
    }
}
