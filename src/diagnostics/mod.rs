use serde::{Deserialize, Serialize};

pub mod rules;

/// Diagnostic severity. Ordering matters for the `--diag-level` filter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Warn,
    Critical,
}

impl Severity {
    pub fn label(self) -> &'static str {
        match self {
            Severity::Info => "INFO",
            Severity::Warn => "WARN",
            Severity::Critical => "CRIT",
        }
    }

    pub fn from_level(s: &str) -> Severity {
        match s.to_ascii_lowercase().as_str() {
            "critical" | "crit" => Severity::Critical,
            "info" => Severity::Info,
            _ => Severity::Warn,
        }
    }
}

// Diagnostic codes (stable identifiers for export/filtering).
pub const CONTACT_UNREACHABLE: &str = "CONTACT_UNREACHABLE";
pub const CONTACT_PRIVATE_NAT: &str = "CONTACT_PRIVATE_NAT";
pub const CONTACT_MCAST: &str = "CONTACT_MCAST";
pub const RR_NOT_HONORED: &str = "RR_NOT_HONORED";
#[allow(dead_code)]
pub const RR_DEPTH_MISMATCH: &str = "RR_DEPTH_MISMATCH";
pub const SDP_HOLD: &str = "SDP_HOLD";
pub const RTP_PT_MISMATCH: &str = "RTP_PT_MISMATCH";
pub const RTP_FLOW_UNEXPECTED: &str = "RTP_FLOW_UNEXPECTED";
pub const RTP_PT_CHANGED: &str = "RTP_PT_CHANGED";
pub const ONE_WAY_MEDIA: &str = "ONE_WAY_MEDIA";

// TURN (RFC 5766/8656).
pub const TURN_ALLOC_OK: &str = "TURN_ALLOC_OK";
pub const TURN_ALLOC_FAILED: &str = "TURN_ALLOC_FAILED";
pub const TURN_REFRESH_FAILED: &str = "TURN_REFRESH_FAILED";
pub const TURN_RELAY_MEDIA: &str = "TURN_RELAY_MEDIA";
pub const TURN_CHANNEL_MEDIA: &str = "TURN_CHANNEL_MEDIA";
pub const TURN_SEND_IND_MEDIA: &str = "TURN_SEND_IND_MEDIA";
pub const TURN_LEG_IMBALANCE: &str = "TURN_LEG_IMBALANCE";

/// Map a diagnostic code string back to its `&'static str` constant without
/// leaking per-record strings. Unknown codes fall back to a shared placeholder.
pub fn code_from_str(s: &str) -> &'static str {
    match s {
        CONTACT_UNREACHABLE => CONTACT_UNREACHABLE,
        CONTACT_PRIVATE_NAT => CONTACT_PRIVATE_NAT,
        CONTACT_MCAST => CONTACT_MCAST,
        RR_NOT_HONORED => RR_NOT_HONORED,
        RR_DEPTH_MISMATCH => RR_DEPTH_MISMATCH,
        SDP_HOLD => SDP_HOLD,
        RTP_PT_MISMATCH => RTP_PT_MISMATCH,
        RTP_FLOW_UNEXPECTED => RTP_FLOW_UNEXPECTED,
        RTP_PT_CHANGED => RTP_PT_CHANGED,
        ONE_WAY_MEDIA => ONE_WAY_MEDIA,
        TURN_ALLOC_OK => TURN_ALLOC_OK,
        TURN_ALLOC_FAILED => TURN_ALLOC_FAILED,
        TURN_REFRESH_FAILED => TURN_REFRESH_FAILED,
        TURN_RELAY_MEDIA => TURN_RELAY_MEDIA,
        TURN_CHANNEL_MEDIA => TURN_CHANNEL_MEDIA,
        TURN_SEND_IND_MEDIA => TURN_SEND_IND_MEDIA,
        TURN_LEG_IMBALANCE => TURN_LEG_IMBALANCE,
        _ => "UNKNOWN_DIAG",
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Diagnostic {
    pub ts_us: u64,
    pub call_id: String,
    pub severity: Severity,
    pub code: &'static str,
    pub message: String,
}
