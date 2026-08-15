use std::path::Path;

use anyhow::{Context, Result};
use rusqlite::Connection;

use crate::store::registry::Snapshot;

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS calls (
    call_id TEXT PRIMARY KEY,
    from_user TEXT, to_user TEXT,
    state TEXT, outcome TEXT,
    invite_ts_us INTEGER, duration_ms INTEGER,
    pdd_ms INTEGER, setup_ms INTEGER, hangup_code INTEGER,
    pkts_sip INTEGER, pkts_rtp INTEGER,
    best_mos REAL, warn_count INTEGER, critical_count INTEGER, stream_count INTEGER,
    via_turn INTEGER
);
CREATE TABLE IF NOT EXISTS streams (
    ssrc TEXT, flow_src TEXT, flow_dst TEXT, codec TEXT, pt INTEGER,
    packets INTEGER, lost INTEGER, loss_pct REAL,
    jitter_ms REAL, rtt_avg_ms REAL, oneway_ms REAL, mos REAL, direction TEXT,
    leg TEXT, via_turn INTEGER
);
CREATE TABLE IF NOT EXISTS diagnostics (
    ts_us INTEGER, call_id TEXT, severity TEXT, code TEXT, message TEXT
);
CREATE TABLE IF NOT EXISTS buckets (
    bucket_us INTEGER, dim_key TEXT,
    calls INTEGER, answered INTEGER, failed INTEGER, asr_pct REAL,
    avg_pdd_ms REAL, avg_jitter_ms REAL, avg_loss_pct REAL, avg_rtt_ms REAL, avg_mos REAL
);
";

pub fn export_snapshot(path: &Path, snap: &Snapshot) -> Result<()> {
    if path.exists() {
        std::fs::remove_file(path).with_context(|| format!("remove old {}", path.display()))?;
    }
    let conn = Connection::open(path).with_context(|| format!("open sqlite {}", path.display()))?;
    conn.execute_batch(SCHEMA)?;

    let mut call_stmt =
        conn.prepare("INSERT OR REPLACE INTO calls VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)")?;
    for c in &snap.calls {
        call_stmt.execute(rusqlite::params![
            c.call_id,
            c.from_user,
            c.to_user,
            c.state.label(),
            format!("{:?}", c.outcome),
            c.invite_ts.map(|t| t as i64),
            c.duration_ms.map(|d| d as i64),
            c.pdd_ms,
            c.setup_ms,
            c.hangup_code,
            c.pkts_sip,
            c.pkts_rtp,
            c.best_mos,
            c.warn_count,
            c.critical_count,
            c.stream_count as i64,
            c.via_turn as i64,
        ])?;
    }
    drop(call_stmt);

    let mut stream_stmt =
        conn.prepare("INSERT INTO streams VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)")?;
    for s in &snap.streams {
        stream_stmt.execute(rusqlite::params![
            format!("{:#x}", s.ssrc),
            s.flow.map(|f| f.src.to_string()),
            s.flow.map(|f| f.dst.to_string()),
            s.codec,
            s.payload_type,
            s.packets,
            s.lost,
            s.loss_pct,
            s.jitter_ms,
            s.rtt_avg_ms,
            s.oneway_ms,
            s.mos,
            s.direction,
            s.leg,
            s.via_turn as i64,
        ])?;
    }
    drop(stream_stmt);

    let mut diag_stmt = conn.prepare("INSERT INTO diagnostics VALUES (?,?,?,?,?)")?;
    for d in &snap.diagnostics {
        diag_stmt.execute(rusqlite::params![
            d.ts_us as i64,
            d.call_id,
            d.severity.label(),
            d.code,
            d.message,
        ])?;
    }
    drop(diag_stmt);

    let mut b_stmt = conn.prepare("INSERT INTO buckets VALUES (?,?,?,?,?,?,?,?,?,?,?)")?;
    for (bucket_us, key, m) in &snap.buckets {
        b_stmt.execute(rusqlite::params![
            *bucket_us as i64,
            key,
            m.calls,
            m.answered,
            m.failed,
            m.asr(),
            crate::model::stats::MetricSet::avg(m.pdd_sum_ms, m.pdd_n),
            crate::model::stats::MetricSet::avg(m.jitter_sum_ms, m.jitter_n),
            crate::model::stats::MetricSet::avg(m.loss_sum_pct, m.loss_n),
            crate::model::stats::MetricSet::avg(m.rtt_sum_ms, m.rtt_n),
            crate::model::stats::MetricSet::avg(m.mos_sum, m.mos_n),
        ])?;
    }
    Ok(())
}
