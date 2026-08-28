use std::path::PathBuf;

/// Bucket granularity for heatmap aggregation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Bucket {
    FifteenMin,
    OneHour,
    OneDay,
}

impl Bucket {
    pub fn seconds(self) -> u64 {
        match self {
            Bucket::FifteenMin => 900,
            Bucket::OneHour => 3600,
            Bucket::OneDay => 86_400,
        }
    }
    pub fn from_str_lossy(s: &str) -> Self {
        match s {
            "15m" => Bucket::FifteenMin,
            "1d" => Bucket::OneDay,
            _ => Bucket::OneHour,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    pub raw_truncate: Option<usize>,
    pub bucket: Bucket,
    #[allow(dead_code)]
    pub ring_hours: u64,
    pub export_jsonl: Option<PathBuf>,
    pub no_media: bool,
    pub bpf: Option<String>,
    /// Binary event-log output path (None = no event logging).
    pub evlog: Option<PathBuf>,
    /// Pure in-memory analysis: no event-log writer thread, no files written.
    /// Explicit `export` subcommand is still allowed when invoked.
    pub dry_run: bool,
    /// Maximum retained calls (evicted oldest-terminated first).
    pub max_calls: usize,
    /// Maximum retained RTP streams (ring).
    pub max_streams: usize,
    /// Maximum retained diagnostics (ring).
    pub max_diagnostics: usize,
    /// Minimum diagnostic severity to record/display: info|warn|critical.
    pub diag_level: String,
    /// Optional TURN server IPs to label server-side flows (auto-learned too).
    pub turn_servers: Vec<std::net::IpAddr>,
    /// Live libpcap capture buffer size, in MiB.
    pub pcap_buffer_mib: i32,
    /// Live capture snapshot length, in bytes.
    pub snaplen: i32,
    /// IPs of the local (monitored) machine. Used to anchor the Call Detail
    /// flow / media display so the local endpoint is always the right side and
    /// the arrows show ingress/egress. Empty = no directional anchor (raw
    /// `src → dst` is shown instead).
    pub local_ips: Vec<std::net::IpAddr>,
    /// Drop idle and terminated calls after this many seconds (0 = keep until
    /// `max_calls`). Live/record default 15 minutes so a multi-hour capture
    /// cannot retain every SIP raw forever.
    pub call_ttl_secs: u64,
    /// When false (headless `record`), drop a call from memory as soon as it
    /// reaches a terminal state — the evlog already has SipMsg/StreamSnap/Call
    /// teardown. TUI/file/replay keep terminated calls for inspection.
    pub keep_terminated: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            raw_truncate: None,
            bucket: Bucket::FifteenMin,
            ring_hours: 24,
            export_jsonl: None,
            no_media: false,
            bpf: None,
            evlog: None,
            dry_run: false,
            max_calls: 100_000,
            max_streams: 50_000,
            max_diagnostics: 50_000,
            diag_level: "warn".to_string(),
            turn_servers: Vec::new(),
            pcap_buffer_mib: 64,
            snaplen: 65_535,
            local_ips: Vec::new(),
            call_ttl_secs: 15 * 60,
            keep_terminated: true,
        }
    }
}

/// Resolve the local-machine IP set: an explicit `--local-ips` list wins,
/// otherwise auto-detect the host's interface addresses (excluding loopback)
/// as a convenient default for running on the monitored host itself.
pub fn resolve_local_ips(explicit: &[std::net::IpAddr]) -> Vec<std::net::IpAddr> {
    if !explicit.is_empty() {
        return explicit.to_vec();
    }
    detect_local_ips()
}

/// Enumerate the host's non-loopback interface addresses via getifaddrs.
#[cfg(unix)]
pub fn detect_local_ips() -> Vec<std::net::IpAddr> {
    let mut out: Vec<std::net::IpAddr> = Vec::new();
    unsafe {
        let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut head) != 0 {
            return out;
        }
        let mut cur = head;
        while !cur.is_null() {
            let ifa = &*cur;
            if let Some(a) = (!ifa.ifa_addr.is_null())
                .then(|| sockaddr_to_ip(ifa.ifa_addr))
                .flatten()
                && !a.is_loopback()
                && !a.is_unspecified()
                && !a.is_multicast()
                && !is_link_local(a)
                && !out.contains(&a)
            {
                out.push(a);
            }
            cur = ifa.ifa_next;
        }
        libc::freeifaddrs(head);
    }
    out
}

/// Convert a getifaddrs sockaddr to an IP address (None for non-IP families).
#[cfg(unix)]
unsafe fn sockaddr_to_ip(sa: *const libc::sockaddr) -> Option<std::net::IpAddr> {
    unsafe {
        if sa.is_null() {
            return None;
        }
        match (*sa).sa_family as libc::c_int {
            libc::AF_INET => {
                let s = &*(sa as *const libc::sockaddr_in);
                Some(std::net::IpAddr::V4(std::net::Ipv4Addr::from(
                    u32::from_be(s.sin_addr.s_addr),
                )))
            }
            libc::AF_INET6 => {
                let s = &*(sa as *const libc::sockaddr_in6);
                Some(std::net::IpAddr::V6(std::net::Ipv6Addr::from(
                    s.sin6_addr.s6_addr,
                )))
            }
            _ => None,
        }
    }
}

#[cfg(not(unix))]
pub fn detect_local_ips() -> Vec<std::net::IpAddr> {
    Vec::new()
}

fn is_link_local(a: std::net::IpAddr) -> bool {
    match a {
        std::net::IpAddr::V4(v4) => v4.is_link_local(),
        std::net::IpAddr::V6(v6) => v6.is_unicast_link_local(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_local_ips_win_over_detection() {
        let explicit: Vec<std::net::IpAddr> =
            ["10.20.0.8".parse().unwrap(), "10.20.0.9".parse().unwrap()].to_vec();
        assert_eq!(resolve_local_ips(&explicit), explicit);
    }

    #[test]
    fn detection_never_returns_loopback() {
        let ips = detect_local_ips();
        assert!(ips.iter().all(|a| !a.is_loopback()), "loopback leaked");
    }
}
