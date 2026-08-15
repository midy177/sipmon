use std::net::{IpAddr, Ipv4Addr};

use crate::decode::sdp::SdpSession;
use crate::diagnostics::{Diagnostic, Severity};
use crate::model::media::NegotiatedMedia;
use crate::model::packet::Flow5Tuple;
use crate::model::sip::SipMsg;

fn diag(
    ts_us: u64,
    call_id: &str,
    sev: Severity,
    code: &'static str,
    msg: impl Into<String>,
) -> Diagnostic {
    Diagnostic {
        ts_us,
        call_id: call_id.to_string(),
        severity: sev,
        code,
        message: msg.into(),
    }
}

fn is_zero(ip: IpAddr) -> bool {
    matches!(ip, IpAddr::V4(v4) if v4 == Ipv4Addr::UNSPECIFIED)
}
fn is_multicast(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_multicast() || v4.is_link_local() || v4.is_broadcast(),
        IpAddr::V6(_) => false,
    }
}
fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_loopback() || v4.is_link_local(),
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_unicast_link_local(),
    }
}

/// Contact reachability + NAT diagnostics for a SIP message carrying a Contact.
pub fn check_contact(
    ts_us: u64,
    call_id: &str,
    msg: &SipMsg,
    peer_public: bool,
) -> Vec<Diagnostic> {
    let mut out = Vec::new();
    let Some(addr) = msg.contact_addr else {
        return out;
    };
    let ip = addr.ip();
    if is_zero(ip) || addr.port() == 0 {
        out.push(diag(
            ts_us,
            call_id,
            Severity::Critical,
            crate::diagnostics::CONTACT_UNREACHABLE,
            format!("Contact {}:{} is unreachable", ip, addr.port()),
        ));
        return out;
    }
    if is_multicast(ip) {
        out.push(diag(
            ts_us,
            call_id,
            Severity::Warn,
            crate::diagnostics::CONTACT_MCAST,
            format!("Contact {} is in a reserved/multicast range", ip),
        ));
    }
    if is_private(ip) && peer_public {
        out.push(diag(
            ts_us,
            call_id,
            Severity::Warn,
            crate::diagnostics::CONTACT_PRIVATE_NAT,
            format!("Contact {} is private but peer appears public (NAT?)", ip),
        ));
    }
    out
}

/// Record-Route honoring: in-dialog requests should carry Route when INVITE had RR.
pub fn check_record_route(
    ts_us: u64,
    call_id: &str,
    msg: &SipMsg,
    invite_had_rr: bool,
) -> Vec<Diagnostic> {
    let mut out = Vec::new();
    if !msg.is_request {
        return out;
    }
    let in_dialog = matches!(
        msg.method,
        Some(crate::model::sip::Method::Bye)
            | Some(crate::model::sip::Method::Ack)
            | Some(crate::model::sip::Method::Invite) /* re-INVITE */
            | Some(crate::model::sip::Method::Info)
            | Some(crate::model::sip::Method::Notify)
            | Some(crate::model::sip::Method::Refer)
            | Some(crate::model::sip::Method::Update)
    ) && msg.to_tag.is_some();
    if !in_dialog {
        return out;
    }
    if invite_had_rr && msg.route_count == 0 {
        out.push(diag(
            ts_us,
            call_id,
            Severity::Warn,
            crate::diagnostics::RR_NOT_HONORED,
            format!(
                "in-dialog {} has no Route header but INVITE carried Record-Route",
                msg.method.map(|m| m.name()).unwrap_or("?")
            ),
        ));
    }
    out
}

/// SDP-level diagnostics (hold / 0.0.0.0 connection).
pub fn check_sdp(ts_us: u64, call_id: &str, sdp: &SdpSession) -> Vec<Diagnostic> {
    let mut out = Vec::new();
    let session_zero = matches!(sdp.connection_ip, Some(ip) if is_zero(ip));
    let any_media_zero = sdp
        .media
        .iter()
        .any(|m| matches!(m.connection_ip, Some(ip) if is_zero(ip)));
    if session_zero || any_media_zero {
        out.push(diag(
            ts_us,
            call_id,
            Severity::Info,
            crate::diagnostics::SDP_HOLD,
            "SDP advertises connection IP 0.0.0.0 (hold/misconfig)".to_string(),
        ));
    }
    out
}

/// RTP payload type must be within the negotiated set.
pub fn check_rtp_pt(
    ts_us: u64,
    call_id: &str,
    ssrc: u32,
    pt: u8,
    negotiated: &NegotiatedMedia,
) -> Option<Diagnostic> {
    if negotiated.pts.is_empty() {
        return None;
    }
    if !negotiated.pts.contains(&pt) {
        Some(diag(
            ts_us,
            call_id,
            Severity::Warn,
            crate::diagnostics::RTP_PT_MISMATCH,
            format!(
                "RTP ssrc={:#x} PT={pt} not in negotiated codecs {{{}}}",
                ssrc,
                negotiated.codecs.to_vec().join(",")
            ),
        ))
    } else {
        None
    }
}

/// RTP flow endpoint must match an SDP-advertised media address.
pub fn check_rtp_flow(
    ts_us: u64,
    call_id: &str,
    flow: &Flow5Tuple,
    negotiated: &NegotiatedMedia,
) -> Option<Diagnostic> {
    if negotiated.endpoints.is_empty() {
        return None;
    }
    let matches = negotiated
        .endpoints
        .iter()
        .any(|e| *e == flow.src || *e == flow.dst);
    if !matches {
        Some(diag(
            ts_us,
            call_id,
            Severity::Warn,
            crate::diagnostics::RTP_FLOW_UNEXPECTED,
            format!(
                "RTP flow {}->{} does not match any SDP media endpoint",
                flow.src, flow.dst
            ),
        ))
    } else {
        None
    }
}

/// Payload type changed mid-stream.
pub fn check_pt_change(
    ts_us: u64,
    call_id: &str,
    ssrc: u32,
    pt: u8,
    prev_pt: Option<u8>,
) -> Option<Diagnostic> {
    match prev_pt {
        Some(p) if p != pt => Some(diag(
            ts_us,
            call_id,
            Severity::Info,
            crate::diagnostics::RTP_PT_CHANGED,
            format!("RTP ssrc={:#x} payload type changed {p} -> {pt}", ssrc),
        )),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_contact_is_critical() {
        let mut msg = crate::model::sip::SipMsg {
            ts_us: 0,
            flow: Flow5Tuple {
                proto: crate::model::packet::Proto::Udp,
                src: "1.1.1.1:5060".parse().unwrap(),
                dst: "2.2.2.2:5060".parse().unwrap(),
            },
            is_request: true,
            method: Some(crate::model::sip::Method::Invite),
            status: None,
            call_id: "c".into(),
            cseq: Some(1),
            cseq_method: None,
            branch: None,
            from_tag: None,
            to_tag: None,
            from_uri: None,
            to_uri: None,
            raw: bytes::Bytes::new(),
            contact_addr: Some("0.0.0.0:5060".parse().unwrap()),
            route_count: 0,
            record_route_count: 0,
            has_sdp: false,
        };
        let d = check_contact(0, "c", &msg, false);
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].severity, Severity::Critical);

        msg.contact_addr = Some("10.0.0.5:5060".parse().unwrap());
        let d = check_contact(0, "c", &msg, true);
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].code, crate::diagnostics::CONTACT_PRIVATE_NAT);
    }

    #[test]
    fn rtp_pt_mismatch() {
        let neg = NegotiatedMedia {
            endpoints: vec![],
            pts: vec![0, 8],
            codecs: vec!["PCMU".into(), "PCMA".into()],
        };
        let d = check_rtp_pt(0, "c", 1, 18, &neg);
        assert!(d.is_some());
        let d = check_rtp_pt(0, "c", 1, 0, &neg);
        assert!(d.is_none());
    }
}
