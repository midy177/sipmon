//! Pure call state-machine transitions, applied to a `Call` for each SIP msg.

use crate::model::sip::{Call, CallState, Method, Outcome, SipMsg};

/// Extract a user portion from a SIP From/To header value.
pub fn user_of(value: &str) -> Option<String> {
    let candidate = match value.find('<') {
        Some(s) => value[s + 1..].split('>').next().unwrap_or(""),
        None => value,
    };
    let after = candidate
        .strip_prefix("sips:")
        .or_else(|| candidate.strip_prefix("sip:"))
        .unwrap_or(candidate);
    let no_params = after.split(';').next().unwrap_or(after);
    let userhost = match no_params.rfind('@') {
        Some(i) => &no_params[..i],
        None => no_params,
    }
    .trim();
    if userhost.is_empty() {
        None
    } else {
        Some(userhost.to_string())
    }
}

pub fn apply_sip(call: &mut Call, msg: &SipMsg) {
    call.pkts_sip += 1;
    call.bytes += msg.raw.len() as u64;
    call.messages.push(msg.clone());

    // Populate identities from the first INVITE if not set.
    if matches!(msg.method, Some(Method::Invite)) {
        if call.from_uri.is_none() {
            call.from_uri = msg.from_uri.clone();
            call.from_user = msg.from_uri.as_deref().and_then(user_of);
        }
        if call.to_uri.is_none() {
            call.to_uri = msg.to_uri.clone();
            call.to_user = msg.to_uri.as_deref().and_then(user_of);
        }
    }

    let is_initial_invite =
        matches!(msg.method, Some(Method::Invite)) && msg.is_request && msg.to_tag.is_none();

    if is_initial_invite {
        if call.invite_ts.is_none() {
            call.invite_ts = Some(msg.ts_us);
        }
        if call.invite_key.is_none() {
            call.invite_key = Some(msg.flow.src.ip().to_string());
        }
        call.state = CallState::Dialing;
        return;
    }

    if msg.is_request {
        match msg.method {
            Some(Method::Bye) => {
                if call.bye_ts.is_none() {
                    call.bye_ts = Some(msg.ts_us);
                }
                // Hangup cause from the Reason header, if present.
                if let Some((code, text)) = reason_from_raw(&msg.raw) {
                    call.hangup.code = Some(code);
                    if !text.is_empty() {
                        call.hangup.reason = Some(text);
                    }
                }
            }
            Some(Method::Cancel)
                if !matches!(call.state, CallState::Completed | CallState::Failed) =>
            {
                call.state = CallState::Canceled;
                call.end_ts = Some(msg.ts_us);
            }
            _ => {}
        }
        return;
    }

    // Responses.
    let Some(code) = msg.status else {
        return;
    };
    let cm = msg.cseq_method.as_deref();

    // Provisional responses to INVITE.
    if (100..200).contains(&code)
        && cm.is_none_or(|m| m.eq_ignore_ascii_case("INVITE"))
        && matches!(call.state, CallState::Dialing | CallState::Ringing)
    {
        if (180..190).contains(&code) || code == 183 {
            if call.ringing_ts.is_none() {
                call.ringing_ts = Some(msg.ts_us);
                call.pdd_ms =
                    Some(((msg.ts_us - call.invite_ts.unwrap_or(msg.ts_us)) / 1000) as u32);
            }
            call.state = CallState::Ringing;
        } else if code >= 100 && call.trying_ts.is_none() {
            call.trying_ts = Some(msg.ts_us);
        }
        return;
    }

    // 2xx responses.
    if (200..300).contains(&code) {
        if cm.is_some_and(|m| m.eq_ignore_ascii_case("BYE")) {
            // Final response to BYE: teardown.
            if call.end_ts.is_none() {
                call.end_ts = Some(msg.ts_us);
            }
            call.state = if call.answer_ts.is_some() {
                CallState::Completed
            } else {
                CallState::Failed
            };
            return;
        }
        // 2xx to INVITE (or assume INVITE when CSeq method unknown).
        if call.answer_ts.is_none() {
            call.answer_ts = Some(msg.ts_us);
            if let Some(inv) = call.invite_ts {
                call.setup_ms = Some(((msg.ts_us - inv) / 1000) as u32);
            }
            call.state = CallState::Active;
            call.outcome = Outcome::Answered;
        }
        return;
    }

    // Non-2xx final responses.
    if code >= 300 {
        call.hangup.code = Some(code as u32);
        if cm.is_some_and(|m| m.eq_ignore_ascii_case("BYE")) {
            call.state = if call.answer_ts.is_some() {
                CallState::Completed
            } else {
                CallState::Failed
            };
            if call.end_ts.is_none() {
                call.end_ts = Some(msg.ts_us);
            }
            return;
        }
        if code == 487 {
            call.state = CallState::Canceled;
            call.outcome = Outcome::Canceled;
        } else if matches!(call.state, CallState::Dialing | CallState::Ringing) {
            call.state = CallState::Failed;
            call.outcome = if (400..500).contains(&code) {
                Outcome::Rejected
            } else {
                Outcome::Failed
            };
            if call.end_ts.is_none() {
                call.end_ts = Some(msg.ts_us);
            }
        } else {
            call.state = if call.answer_ts.is_some() {
                CallState::Completed
            } else {
                CallState::Failed
            };
            if call.end_ts.is_none() {
                call.end_ts = Some(msg.ts_us);
            }
        }
    }
}

/// Extract hangup cause (code/reason) from a Reason header in the raw message,
/// if present. Returns (code, reason_text).
pub fn reason_from_raw(raw: &[u8]) -> Option<(u32, String)> {
    let text = std::str::from_utf8(raw).ok()?;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("Reason:") {
            let rest = rest.trim();
            let cause = extract_attr(rest, "cause").and_then(|c| c.parse::<u32>().ok());
            let text_val = extract_attr(rest, "text").map(|t| t.trim_matches('"').to_string());
            if let Some(c) = cause {
                return Some((c, text_val.unwrap_or_default()));
            }
        }
    }
    None
}

fn extract_attr<'a>(s: &'a str, name: &str) -> Option<&'a str> {
    let needle = format!("{name}=");
    let idx = s.find(&needle)?;
    let rest = &s[idx + needle.len()..];
    let end = rest
        .find([';', ' ', '\t', '\r', '\n'])
        .unwrap_or(rest.len());
    Some(rest[..end].trim_matches('"'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::packet::{Flow5Tuple, Proto};
    use bytes::Bytes;

    fn mk(
        ts: u64,
        is_req: bool,
        method: Option<Method>,
        status: Option<u16>,
        to_tag: Option<&str>,
    ) -> SipMsg {
        SipMsg {
            ts_us: ts,
            flow: Flow5Tuple {
                proto: Proto::Udp,
                src: "1.1.1.1:5060".parse().unwrap(),
                dst: "2.2.2.2:5060".parse().unwrap(),
            },
            is_request: is_req,
            method,
            status,
            call_id: "c1".into(),
            cseq: Some(1),
            cseq_method: Some("INVITE".into()),
            branch: Some("b".into()),
            from_tag: Some("f".into()),
            to_tag: to_tag.map(str::to_owned),
            from_uri: Some("<sip:alice@1.1.1.1>".into()),
            to_uri: Some("<sip:bob@2.2.2.2>".into()),
            raw: Bytes::new(),
            contact_addr: None,
            route_count: 0,
            record_route_count: 0,
            has_sdp: false,
        }
    }

    #[test]
    fn happy_path_state_machine() {
        let mut call = Call::new("c1".into());
        apply_sip(
            &mut call,
            &mk(1_000_000, true, Some(Method::Invite), None, None),
        );
        apply_sip(&mut call, &mk(1_100_000, false, None, Some(180), None));
        assert_eq!(call.state, CallState::Ringing);
        assert_eq!(call.pdd_ms, Some(100));
        apply_sip(&mut call, &mk(1_500_000, false, None, Some(200), None));
        assert_eq!(call.state, CallState::Active);
        assert_eq!(call.setup_ms, Some(500));
        let mut bye = mk(3_000_000, true, Some(Method::Bye), None, Some("x"));
        bye.cseq_method = Some("BYE".into());
        apply_sip(&mut call, &bye);
        let mut bye_ok = mk(3_010_000, false, None, Some(200), Some("x"));
        bye_ok.cseq_method = Some("BYE".into());
        apply_sip(&mut call, &bye_ok);
        assert_eq!(call.state, CallState::Completed);
        assert_eq!(call.outcome, Outcome::Answered);
    }

    #[test]
    fn rejected_path() {
        let mut call = Call::new("c1".into());
        apply_sip(
            &mut call,
            &mk(1_000_000, true, Some(Method::Invite), None, None),
        );
        apply_sip(&mut call, &mk(1_200_000, false, None, Some(486), None));
        assert_eq!(call.state, CallState::Failed);
        assert_eq!(call.outcome, Outcome::Rejected);
    }
}
