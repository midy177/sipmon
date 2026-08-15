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
        }
    }
}
