//! Call filter rules shared by the TUI Overview filter bar and the pipeline's
//! search-pin protection, so what the user filters and what stays pinned use
//! identical semantics.
//!
//! A query is whitespace-separated tokens, each an optional `prefix:value`
//! (`ip:`, `caller:`, `callee:`, `callid:`) or a bare word matching any field.
//! All tokens must match (AND). Values are case-insensitive substrings;
//! `ip:` accepts `addr` or `addr:port` (the port is ignored — calls are
//! indexed by IP), and a value that parses as a complete address matches
//! exactly instead of as a substring (`ip:10.0.0.1` will not hit `10.0.0.10`).

use std::net::{IpAddr, SocketAddr};

use crate::model::sip::Call;
use crate::store::registry::CallSummary;

/// One parsed filter token; needles are stored lowercased.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rule {
    /// `ip:…` — any IP involved in the call. `addr` is set when the value
    /// parses as a complete address, switching to exact matching.
    Ip {
        needle: String,
        addr: Option<IpAddr>,
    },
    /// `caller:…` — From user substring.
    Caller(String),
    /// `callee:…` — To user substring.
    Callee(String),
    /// `callid:…` — Call-ID substring.
    CallId(String),
    /// Bare word — matches call-id / caller / callee / any IP.
    Any {
        needle: String,
        addr: Option<IpAddr>,
    },
}

/// Fields the filter needs from a call, implemented by the UI's
/// [`CallSummary`] and the pipeline's [`Call`] so both sides share one
/// matching engine.
pub trait CallLike {
    fn call_id(&self) -> &str;
    fn caller(&self) -> Option<&str>;
    fn callee(&self) -> Option<&str>;
    fn caller_ip(&self) -> Option<IpAddr>;
    fn ips(&self) -> &[IpAddr];
}

impl CallLike for CallSummary {
    fn call_id(&self) -> &str {
        &self.call_id
    }
    fn caller(&self) -> Option<&str> {
        self.from_user.as_deref()
    }
    fn callee(&self) -> Option<&str> {
        self.to_user.as_deref()
    }
    fn caller_ip(&self) -> Option<IpAddr> {
        self.caller_ip
    }
    fn ips(&self) -> &[IpAddr] {
        &self.ips
    }
}

impl CallLike for Call {
    fn call_id(&self) -> &str {
        &self.call_id
    }
    fn caller(&self) -> Option<&str> {
        self.from_user.as_deref()
    }
    fn callee(&self) -> Option<&str> {
        self.to_user.as_deref()
    }
    fn caller_ip(&self) -> Option<IpAddr> {
        self.invite_key.as_deref().and_then(|k| k.parse().ok())
    }
    fn ips(&self) -> &[IpAddr] {
        &self.ips
    }
}

/// Parse a query into rules. Tokens whose value is empty (a lone `ip:`) are
/// dropped so they become no-ops instead of matching everything.
pub fn parse(query: &str) -> Vec<Rule> {
    query.split_whitespace().filter_map(token_rule).collect()
}

fn token_rule(tok: &str) -> Option<Rule> {
    let lower = tok.to_ascii_lowercase();
    if let Some(v) = lower.strip_prefix("callid:") {
        (!v.is_empty()).then(|| Rule::CallId(v.to_string()))
    } else if let Some(v) = lower.strip_prefix("caller:") {
        (!v.is_empty()).then(|| Rule::Caller(v.to_string()))
    } else if let Some(v) = lower.strip_prefix("callee:") {
        (!v.is_empty()).then(|| Rule::Callee(v.to_string()))
    } else if let Some(v) = lower.strip_prefix("ip:") {
        (!v.is_empty()).then(|| Rule::Ip {
            needle: v.to_string(),
            addr: parse_addr(v),
        })
    } else {
        let addr = parse_addr(&lower);
        Some(Rule::Any {
            needle: lower,
            addr,
        })
    }
}

/// Parse `addr` or `addr:port` (the port is ignored).
fn parse_addr(v: &str) -> Option<IpAddr> {
    v.parse()
        .ok()
        .or_else(|| v.parse::<SocketAddr>().ok().map(|a| a.ip()))
}

/// True when the call satisfies every rule (AND). An empty rule list matches
/// everything.
pub fn matches(c: &impl CallLike, rules: &[Rule]) -> bool {
    rules.iter().all(|r| matches_rule(c, r))
}

fn matches_rule(c: &impl CallLike, r: &Rule) -> bool {
    match r {
        Rule::Ip { needle, addr } => ip_hit(c, needle, *addr),
        Rule::Caller(n) => text_hit(c.caller(), n),
        Rule::Callee(n) => text_hit(c.callee(), n),
        Rule::CallId(n) => c.call_id().to_ascii_lowercase().contains(n),
        Rule::Any { needle, addr } => {
            c.call_id().to_ascii_lowercase().contains(needle)
                || text_hit(c.caller(), needle)
                || text_hit(c.callee(), needle)
                || ip_hit(c, needle, *addr)
        }
    }
}

fn text_hit(v: Option<&str>, needle: &str) -> bool {
    v.is_some_and(|s| s.to_ascii_lowercase().contains(needle))
}

fn ip_hit(c: &impl CallLike, needle: &str, addr: Option<IpAddr>) -> bool {
    match addr {
        Some(a) => c.caller_ip() == Some(a) || c.ips().contains(&a),
        None => {
            c.caller_ip().is_some_and(|ip| ip.to_string().contains(needle))
                || c.ips().iter().any(|ip| ip.to_string().contains(needle))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::sip::Call;

    fn summary(
        call_id: &str,
        from: Option<&str>,
        to: Option<&str>,
        caller_ip: Option<IpAddr>,
        ips: &[&str],
    ) -> CallSummary {
        CallSummary {
            call_id: call_id.into(),
            from_user: from.map(Into::into),
            to_user: to.map(Into::into),
            caller_ip,
            caller_src: None,
            state: crate::model::sip::CallState::Completed,
            outcome: crate::model::sip::Outcome::Answered,
            invite_ts: Some(1),
            duration_ms: None,
            pdd_ms: None,
            setup_ms: None,
            ring_ms: None,
            ring_code: None,
            early_media: false,
            hangup_by: None,
            hangup_code: None,
            pkts_sip: 0,
            pkts_rtp: 0,
            best_mos: None,
            warn_count: 0,
            critical_count: 0,
            stream_count: 0,
            via_turn: false,
            ips: ips.iter().map(|s| s.parse().unwrap()).collect(),
        }
    }

    fn rules(q: &str) -> Vec<Rule> {
        parse(q)
    }

    #[test]
    fn parse_recognizes_prefixes_and_bare_words() {
        assert_eq!(
            rules("callid:abc"),
            vec![Rule::CallId("abc".into())]
        );
        assert_eq!(
            rules("caller:1001"),
            vec![Rule::Caller("1001".into())]
        );
        assert_eq!(
            rules("CALLEE:2002"),
            vec![Rule::Callee("2002".into())],
            "prefix matching is case-insensitive"
        );
        let ip = rules("ip:10.0.0.1:5060");
        match ip.as_slice() {
            [Rule::Ip { addr, .. }] => {
                assert_eq!(*addr, Some("10.0.0.1".parse().unwrap()), "port ignored")
            }
            _ => panic!("expected Ip rule, got {ip:?}"),
        }
        assert_eq!(rules("1001"), vec![Rule::Any {
            needle: "1001".into(),
            addr: None
        }]);
        assert!(rules("ip:").is_empty(), "empty values are dropped");
    }

    #[test]
    fn empty_rules_match_everything() {
        let c = summary("c1", None, None, None, &[]);
        assert!(matches(&c, &[]));
        assert!(matches(&c, &rules("   ")));
    }

    #[test]
    fn bare_word_matches_any_field() {
        let c = summary("inv-123", Some("alice"), Some("2002"), None, &["10.1.2.3"]);
        assert!(matches(&c, &rules("123")));
        assert!(matches(&c, &rules("ALICE")));
        assert!(matches(&c, &rules("2002")));
        assert!(matches(&c, &rules("10.1.2.3")));
        assert!(!matches(&c, &rules("bob")));
    }

    #[test]
    fn rules_combine_with_and() {
        let c = summary("c1", Some("1001"), Some("2002"), None, &[]);
        assert!(matches(&c, &rules("caller:1001 callee:2002")));
        assert!(!matches(&c, &rules("caller:1001 callee:2003")));
    }

    #[test]
    fn exact_ip_does_not_substring_match() {
        let c = summary("c1", None, None, None, &["10.0.0.10"]);
        assert!(!matches(&c, &rules("ip:10.0.0.1")), "exact, not prefix");
        assert!(matches(&c, &rules("ip:10.0.0.10")));
        assert!(matches(&c, &rules("ip:10.0.0.10:5060")), "port is ignored");
        assert!(matches(&c, &rules("10.0.0.10:5060")), "bare addr:port");
        // Unparseable values fall back to substring matching.
        assert!(matches(&c, &rules("ip:10.0.0.")));
    }

    #[test]
    fn ip_rule_matches_caller_ip_and_any_call_ip() {
        let caller: IpAddr = "192.168.1.1".parse().unwrap();
        let c = summary("c1", None, None, Some(caller), &["192.168.1.2"]);
        assert!(matches(&c, &rules("ip:192.168.1.1")));
        assert!(matches(&c, &rules("ip:192.168.1.2")));
        assert!(!matches(&c, &rules("ip:192.168.1.3")));
    }

    #[test]
    fn pipeline_call_matches_via_invite_key() {
        let mut call = Call::new("abc".into());
        call.from_user = Some("3003".into());
        call.invite_key = Some("172.16.0.9".into());
        call.ips.push("172.16.0.9".parse().unwrap());
        assert!(matches(&call, &rules("callid:abc ip:172.16.0.9:5060")));
        assert!(matches(&call, &rules("caller:3003")));
        assert!(!matches(&call, &rules("callee:3003")));
    }
}
