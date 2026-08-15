use serde::{Deserialize, Serialize};

/// Aggregated metrics for one (bucket, dimension-key) cell of the heatmap.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MetricSet {
    pub calls: u64,
    pub answered: u64,
    pub failed: u64,
    pub pdd_sum_ms: f64,
    pub pdd_n: u64,
    pub jitter_sum_ms: f64,
    pub jitter_n: u64,
    pub loss_sum_pct: f64,
    pub loss_n: u64,
    pub rtt_sum_ms: f64,
    pub rtt_n: u64,
    pub mos_sum: f64,
    pub mos_n: u64,
}

impl MetricSet {
    pub fn asr(&self) -> f64 {
        if self.calls == 0 {
            0.0
        } else {
            self.answered as f64 / self.calls as f64 * 100.0
        }
    }
    #[allow(dead_code)]
    pub fn fail_rate(&self) -> f64 {
        if self.calls == 0 {
            0.0
        } else {
            self.failed as f64 / self.calls as f64 * 100.0
        }
    }
    pub fn avg(sum: f64, n: u64) -> f64 {
        if n == 0 { 0.0 } else { sum / n as f64 }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthBucket {
    pub bucket_us: u64,
    pub dim_key: String,
    pub metrics: MetricSet,
}
