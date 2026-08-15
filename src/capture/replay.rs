use crate::model::sip::SipMsg;
use crate::store::evlog::SipMsgEvt;

/// Convert an evlog-recorded SIP message event back into a model message for
/// re-analysis (replay feeds these through the correlator again).
///
/// Prefers re-parsing the stored raw bytes (full fidelity: contact, routes,
/// SDP); falls back to the recorded summary fields if parsing fails.
pub fn evt_to_sipmsg(evt: &SipMsgEvt) -> SipMsg {
    if let Some(m) = crate::decode::sip::parse_sip(evt.ts_us, evt.flow, &evt.raw, None) {
        return m;
    }
    SipMsg {
        ts_us: evt.ts_us,
        flow: evt.flow,
        is_request: evt.is_request,
        method: evt.method.as_deref().map(parse_method),
        status: evt.status,
        call_id: evt.call_id.clone(),
        cseq: evt.cseq,
        cseq_method: None,
        branch: evt.branch.clone(),
        from_tag: evt.from_tag.clone(),
        to_tag: evt.to_tag.clone(),
        from_uri: None,
        to_uri: None,
        raw: bytes::Bytes::from(evt.raw.clone()),
        contact_addr: None,
        route_count: 0,
        record_route_count: 0,
        has_sdp: false,
    }
}

fn parse_method(s: &str) -> crate::model::sip::Method {
    match s.to_ascii_uppercase().as_str() {
        "INVITE" => crate::model::sip::Method::Invite,
        "ACK" => crate::model::sip::Method::Ack,
        "BYE" => crate::model::sip::Method::Bye,
        "CANCEL" => crate::model::sip::Method::Cancel,
        "REGISTER" => crate::model::sip::Method::Register,
        "OPTIONS" => crate::model::sip::Method::Options,
        "PRACK" => crate::model::sip::Method::Prack,
        "UPDATE" => crate::model::sip::Method::Update,
        "SUBSCRIBE" => crate::model::sip::Method::Subscribe,
        "NOTIFY" => crate::model::sip::Method::Notify,
        "PUBLISH" => crate::model::sip::Method::Publish,
        "INFO" => crate::model::sip::Method::Info,
        "REFER" => crate::model::sip::Method::Refer,
        "MESSAGE" => crate::model::sip::Method::Message,
        _ => crate::model::sip::Method::Other,
    }
}
