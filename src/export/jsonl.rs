use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result};
use serde_json::json;

use crate::store::registry::Snapshot;

/// Write a snapshot as JSON lines: one object per line, tagged by "kind".
pub fn export_snapshot(path: &Path, snap: &Snapshot) -> Result<()> {
    let mut f =
        std::fs::File::create(path).with_context(|| format!("create {}", path.display()))?;
    let mut w = std::io::BufWriter::new(&mut f);

    for c in &snap.calls {
        let line = json!({
            "kind": "call",
            "call_id": c.call_id,
            "from": c.from_user,
            "to": c.to_user,
            "state": c.state.label(),
            "outcome": format!("{:?}", c.outcome),
            "invite_ts_us": c.invite_ts,
            "duration_ms": c.duration_ms,
            "pdd_ms": c.pdd_ms,
            "setup_ms": c.setup_ms,
            "hangup_code": c.hangup_code,
            "pkts_sip": c.pkts_sip,
            "pkts_rtp": c.pkts_rtp,
            "best_mos": c.best_mos,
            "warn_count": c.warn_count,
            "critical_count": c.critical_count,
            "stream_count": c.stream_count,
            "via_turn": c.via_turn,
        });
        writeln!(w, "{line}")?;
    }
    for s in &snap.streams {
        let line = json!({
            "kind": "stream",
            "ssrc": format!("{:#x}", s.ssrc),
            "flow_src": s.flow.map(|f| f.src.to_string()),
            "flow_dst": s.flow.map(|f| f.dst.to_string()),
            "codec": s.codec,
            "pt": s.payload_type,
            "packets": s.packets,
            "lost": s.lost,
            "loss_pct": round2(s.loss_pct),
            "jitter_ms": s.jitter_ms.map(round2),
            "rtt_avg_ms": s.rtt_avg_ms.map(round2),
            "oneway_ms": s.oneway_ms.map(round2),
            "mos": s.mos.map(round2),
            "direction": s.direction,
            "leg": s.leg,
            "via_turn": s.via_turn,
        });
        writeln!(w, "{line}")?;
    }
    for d in &snap.diagnostics {
        let line = json!({
            "kind": "diag",
            "ts_us": d.ts_us,
            "call_id": d.call_id,
            "severity": d.severity.label(),
            "code": d.code,
            "message": d.message,
        });
        writeln!(w, "{line}")?;
    }
    for (bucket_us, key, m) in &snap.buckets {
        let line = json!({
            "kind": "bucket",
            "bucket_us": bucket_us,
            "dim_key": key,
            "calls": m.calls,
            "answered": m.answered,
            "failed": m.failed,
            "asr_pct": round2(m.asr()),
            "avg_pdd_ms": round2(crate::model::stats::MetricSet::avg(m.pdd_sum_ms, m.pdd_n)),
            "avg_jitter_ms": round2(crate::model::stats::MetricSet::avg(m.jitter_sum_ms, m.jitter_n)),
            "avg_loss_pct": round2(crate::model::stats::MetricSet::avg(m.loss_sum_pct, m.loss_n)),
            "avg_rtt_ms": round2(crate::model::stats::MetricSet::avg(m.rtt_sum_ms, m.rtt_n)),
            "avg_mos": round2(crate::model::stats::MetricSet::avg(m.mos_sum, m.mos_n)),
        });
        writeln!(w, "{line}")?;
    }
    w.flush()?;
    Ok(())
}

fn round2(v: f64) -> f64 {
    (v * 100.0).round() / 100.0
}
