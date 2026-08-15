use bytes::Bytes;

use rsipstack::sip::{self, HeadersExt, SipMessage};

use crate::model::packet::Flow5Tuple;
use crate::model::sip::{Method, SipMsg};

/// Map rsipstack method to our lightweight mirror.
fn map_method(m: &sip::Method) -> Method {
    match m {
        sip::Method::Invite => Method::Invite,
        sip::Method::Ack => Method::Ack,
        sip::Method::Bye => Method::Bye,
        sip::Method::Cancel => Method::Cancel,
        sip::Method::Register => Method::Register,
        sip::Method::Options => Method::Options,
        sip::Method::PRack => Method::Prack,
        sip::Method::Update => Method::Update,
        sip::Method::Subscribe => Method::Subscribe,
        sip::Method::Notify => Method::Notify,
        sip::Method::Publish => Method::Publish,
        sip::Method::Info => Method::Info,
        sip::Method::Refer => Method::Refer,
        sip::Method::Message => Method::Message,
    }
}

/// Extract the value of a `;name=value` parameter from a header string.
fn param<'a>(value: &'a str, name: &str) -> Option<&'a str> {
    let lower = value.to_ascii_lowercase();
    let needle = format!("{name}=");
    let idx = lower.find(&needle)?;
    let start = idx + needle.len();
    let rest = &value[start..];
    let end = rest
        .find([';', ' ', '\t', '\r', '\n'])
        .unwrap_or(rest.len());
    Some(rest[..end].trim_matches('"'))
}

fn cseq_number(msg: &SipMessage) -> Option<u32> {
    msg.cseq_header()
        .ok()?
        .value()
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

fn cseq_method(msg: &SipMessage) -> Option<String> {
    msg.cseq_header()
        .ok()?
        .value()
        .split_whitespace()
        .nth(1)
        .map(str::to_owned)
}

/// Quick check: does this payload begin like a SIP message?
pub fn looks_like_sip(payload: &[u8]) -> bool {
    if payload.len() < 8 {
        return false;
    }
    payload.starts_with(b"SIP/") || starts_with_method(payload)
}

fn starts_with_method(payload: &[u8]) -> bool {
    const METHODS: &[&[u8]] = &[
        b"INVITE ",
        b"ACK ",
        b"BYE ",
        b"CANCEL ",
        b"REGISTER ",
        b"OPTIONS ",
        b"PRACK ",
        b"UPDATE ",
        b"SUBSCRIBE ",
        b"NOTIFY ",
        b"PUBLISH ",
        b"INFO ",
        b"REFER ",
        b"MESSAGE ",
    ];
    METHODS.iter().any(|m| payload.starts_with(m))
}

/// Try to decode `raw` (a UDP/TCP payload) as a SIP message.
pub fn parse_sip(
    ts_us: u64,
    flow: Flow5Tuple,
    raw: &[u8],
    raw_truncate: Option<usize>,
) -> Option<SipMsg> {
    if !looks_like_sip(raw) {
        return None;
    }
    let msg: SipMessage = sip::parser::parse_message(raw).ok()?;

    let (is_request, method, status) = match &msg {
        SipMessage::Request(r) => (true, Some(map_method(r.method())), None),
        SipMessage::Response(r) => (false, None, Some(r.status_code().code())),
    };

    let call_id = msg.call_id_header().ok()?.value().trim().to_string();

    let cseq = cseq_number(&msg);
    let cseq_m = cseq_method(&msg);

    // Branch from top Via.
    let branch = msg
        .top_via_header()
        .ok()
        .and_then(|v| param(v.value(), "branch").map(str::to_owned));

    let (from_tag, to_tag) = {
        let f = msg.from_header().ok().map(|h| h.value().to_string());
        let t = msg.to_header().ok().map(|h| h.value().to_string());
        (
            f.as_ref().and_then(|v| param(v, "tag").map(str::to_owned)),
            t.as_ref().and_then(|v| param(v, "tag").map(str::to_owned)),
        )
    };
    let from_uri = msg.from_header().ok().map(|h| h.value().trim().to_string());
    let to_uri = msg.to_header().ok().map(|h| h.value().trim().to_string());

    let stored = match raw_truncate {
        Some(n) if raw.len() > n => Bytes::copy_from_slice(&raw[..n]),
        _ => Bytes::copy_from_slice(raw),
    };

    // Diagnostic-relevant fields.
    let route_count = msg.route_headers().len();
    let record_route_count = msg.record_route_headers().len();
    let contact_addr = msg
        .contact_header()
        .ok()
        .and_then(|c| extract_sockaddr(c.value()));
    let has_sdp = msg
        .header_value("content-type")
        .map(|v| v.eq_ignore_ascii_case("application/sdp"))
        .unwrap_or(false)
        || msg.header_value("c").is_some()
        || {
            let body_start = raw
                .windows(4)
                .position(|w| w == b"\r\n\r\n")
                .map(|i| i + 4)
                .unwrap_or(raw.len());
            raw.get(body_start..body_start + 3) == Some(b"v=0")
        };

    Some(SipMsg {
        ts_us,
        flow,
        is_request,
        method,
        status,
        call_id,
        cseq,
        cseq_method: cseq_m,
        branch,
        from_tag,
        to_tag,
        from_uri,
        to_uri,
        raw: stored,
        contact_addr,
        route_count,
        record_route_count,
        has_sdp,
    })
}

/// Extract a host:port socket address from a SIP URI-bearing header value.
fn extract_sockaddr(value: &str) -> Option<std::net::SocketAddr> {
    // Strip display name: take the part inside <...> if present.
    let candidate = match value.find('<') {
        Some(s) => value[s + 1..].split('>').next().unwrap_or(""),
        None => value,
    };
    let after_scheme = candidate
        .strip_prefix("sips:")
        .or_else(|| candidate.strip_prefix("sip:"))
        .unwrap_or(candidate);
    // Drop params.
    let addr_part = after_scheme.split(';').next().unwrap_or(after_scheme);
    // Drop user@ if present.
    let hostport = match addr_part.rfind('@') {
        Some(i) => &addr_part[i + 1..],
        None => addr_part,
    }
    .trim();
    hostport.parse().ok()
}
