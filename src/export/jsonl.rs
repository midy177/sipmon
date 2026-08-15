use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result};
use serde_json::{Value, json};

use crate::diagnostics::{Diagnostic, Severity, code_from_str};
use crate::model::media::StreamSummary;
use crate::model::packet::{Flow5Tuple, Proto};
use crate::model::sip::{CallState, Outcome};
use crate::model::stats::MetricSet;
use crate::store::registry::{CallSummary, Snapshot};

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
            "call_id": s.call_id,
            "ssrc": format!("{:#x}", s.ssrc),
            "flow_src": s.flow.map(|f| f.src.to_string()),
            "flow_dst": s.flow.map(|f| f.dst.to_string()),
            "codec": s.codec,
            "pt": s.payload_type,
            "packets": s.packets,
            "lost": s.lost,
            "bytes": s.bytes,
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

/// Load a snapshot from a JSONL export (reverse of `export_snapshot`). Unknown
/// or malformed lines are skipped; the reader is tolerant of other line kinds.
pub fn import_snapshot(path: &Path) -> Result<Snapshot> {
    let text = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let mut snap = Snapshot {
        source: format!("jsonl:{}", path.display()),
        ..Snapshot::default()
    };

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let v: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => continue, // not our export format; skip
        };
        match v.get("kind").and_then(|k| k.as_str()) {
            Some("call") => snap.calls.push(import_call(&v)),
            Some("stream") => snap.streams.push(import_stream(&v)),
            Some("diag") => snap.diagnostics.push(import_diag(&v)),
            Some("bucket") => snap.buckets.push(import_bucket(&v)),
            _ => {}
        }
    }

    snap.calls_total = snap.calls.len() as u64;
    let (active, completed, failed) =
        snap.calls
            .iter()
            .fold((0usize, 0usize, 0usize), |(a, c, f), s| match s.state {
                CallState::Dialing | CallState::Ringing | CallState::Active => (a + 1, c, f),
                CallState::Completed => (a, c + 1, f),
                CallState::Failed | CallState::Canceled => (a, c, f + 1),
            });
    snap.active = active;
    snap.completed = completed;
    snap.failed = failed;
    snap.avg_pdd_ms = mean_opt(snap.calls.iter().filter_map(|c| c.pdd_ms.map(f64::from)));
    snap.avg_setup_ms = mean_opt(snap.calls.iter().filter_map(|c| c.setup_ms.map(f64::from)));
    snap.avg_jitter_ms = mean_opt(snap.streams.iter().filter_map(|s| s.jitter_ms));
    snap.avg_loss_pct = mean_opt(snap.streams.iter().map(|s| s.loss_pct));
    snap.avg_mos = mean_opt(snap.streams.iter().filter_map(|s| s.mos));
    snap.avg_rtt_ms = mean_opt(snap.streams.iter().filter_map(|s| s.rtt_avg_ms));
    snap.asr = if snap.calls_total == 0 {
        0.0
    } else {
        completed as f64 / snap.calls_total as f64 * 100.0
    };

    snap.calls
        .sort_by_key(|c| std::cmp::Reverse(c.invite_ts.unwrap_or(0)));
    Ok(snap)
}

fn mean_opt<I>(mut it: I) -> f64
where
    I: Iterator<Item = f64>,
{
    let (mut sum, mut n) = (0.0, 0u64);
    for v in it.by_ref() {
        sum += v;
        n += 1;
    }
    if n == 0 { 0.0 } else { sum / n as f64 }
}

fn opt_str(v: &Value, key: &str) -> Option<String> {
    v.get(key).and_then(|x| x.as_str()).map(str::to_owned)
}

fn opt_u32(v: &Value, key: &str) -> Option<u32> {
    v.get(key).and_then(|x| x.as_u64()).map(|x| x as u32)
}

fn opt_f64(v: &Value, key: &str) -> Option<f64> {
    v.get(key).and_then(|x| x.as_f64())
}

fn parse_state(s: Option<&str>) -> CallState {
    match s {
        Some("Dialing") => CallState::Dialing,
        Some("Ringing") => CallState::Ringing,
        Some("Active") => CallState::Active,
        Some("Completed") => CallState::Completed,
        Some("Canceled") => CallState::Canceled,
        Some("Failed") => CallState::Failed,
        _ => CallState::Failed,
    }
}

fn parse_outcome(s: Option<&str>) -> Outcome {
    match s {
        Some("Answered") => Outcome::Answered,
        Some("Rejected") => Outcome::Rejected,
        Some("NoAnswer") => Outcome::NoAnswer,
        Some("Canceled") => Outcome::Canceled,
        Some("Failed") => Outcome::Failed,
        _ => Outcome::InProgress,
    }
}

fn parse_severity(s: Option<&str>) -> Severity {
    match s {
        Some("CRIT") => Severity::Critical,
        Some("INFO") => Severity::Info,
        _ => Severity::Warn,
    }
}

fn parse_ssrc(v: &Value) -> u32 {
    match v.get("ssrc").and_then(|x| x.as_str()) {
        Some(s) => {
            let hex = s.strip_prefix("0x").unwrap_or(s);
            u32::from_str_radix(hex, 16).unwrap_or(0)
        }
        None => v.get("ssrc").and_then(|x| x.as_u64()).unwrap_or(0) as u32,
    }
}

fn import_call(v: &Value) -> CallSummary {
    CallSummary {
        call_id: v["call_id"].as_str().unwrap_or_default().to_string(),
        from_user: opt_str(v, "from"),
        to_user: opt_str(v, "to"),
        state: parse_state(v.get("state").and_then(|x| x.as_str())),
        outcome: parse_outcome(v.get("outcome").and_then(|x| x.as_str())),
        invite_ts: v.get("invite_ts_us").and_then(|x| x.as_u64()),
        duration_ms: v.get("duration_ms").and_then(|x| x.as_u64()),
        pdd_ms: opt_u32(v, "pdd_ms"),
        setup_ms: opt_u32(v, "setup_ms"),
        hangup_code: opt_u32(v, "hangup_code"),
        pkts_sip: v.get("pkts_sip").and_then(|x| x.as_u64()).unwrap_or(0),
        pkts_rtp: v.get("pkts_rtp").and_then(|x| x.as_u64()).unwrap_or(0),
        best_mos: opt_f64(v, "best_mos"),
        warn_count: opt_u32(v, "warn_count").unwrap_or(0),
        critical_count: opt_u32(v, "critical_count").unwrap_or(0),
        stream_count: v
            .get("stream_count")
            .and_then(|x| x.as_u64())
            .map(|x| x as usize)
            .unwrap_or(0),
        via_turn: v.get("via_turn").and_then(|x| x.as_bool()).unwrap_or(false),
    }
}

fn import_stream(v: &Value) -> StreamSummary {
    let src = opt_str(v, "flow_src").and_then(|s| s.parse().ok());
    let dst = opt_str(v, "flow_dst").and_then(|s| s.parse().ok());
    let flow = match (src, dst) {
        (Some(s), Some(d)) => Some(Flow5Tuple {
            proto: Proto::Udp,
            src: s,
            dst: d,
        }),
        _ => None,
    };
    let packets = v.get("packets").and_then(|x| x.as_u64()).unwrap_or(0);
    let lost = v.get("lost").and_then(|x| x.as_u64()).unwrap_or(0);
    StreamSummary {
        call_id: opt_str(v, "call_id"),
        ssrc: parse_ssrc(v),
        flow,
        codec: opt_str(v, "codec"),
        payload_type: v.get("pt").and_then(|x| x.as_u64()).map(|x| x as u8),
        packets,
        lost,
        expected: packets + lost,
        loss_pct: v.get("loss_pct").and_then(|x| x.as_f64()).unwrap_or(0.0),
        jitter_ms: opt_f64(v, "jitter_ms"),
        first_ts_us: None,
        last_ts_us: None,
        rtt_min_ms: None,
        rtt_avg_ms: opt_f64(v, "rtt_avg_ms"),
        rtt_max_ms: None,
        oneway_ms: opt_f64(v, "oneway_ms"),
        mos: opt_f64(v, "mos"),
        direction: opt_str(v, "direction"),
        leg: opt_str(v, "leg"),
        via_turn: v.get("via_turn").and_then(|x| x.as_bool()).unwrap_or(false),
        bytes: v.get("bytes").and_then(|x| x.as_u64()).unwrap_or(0),
        history: Vec::new(),
    }
}

fn import_diag(v: &Value) -> Diagnostic {
    Diagnostic {
        ts_us: v.get("ts_us").and_then(|x| x.as_u64()).unwrap_or(0),
        call_id: v["call_id"].as_str().unwrap_or_default().to_string(),
        severity: parse_severity(v.get("severity").and_then(|x| x.as_str())),
        code: code_from_str(v.get("code").and_then(|x| x.as_str()).unwrap_or("")),
        message: v
            .get("message")
            .and_then(|x| x.as_str())
            .unwrap_or_default()
            .to_string(),
    }
}

fn import_bucket(v: &Value) -> (u64, String, MetricSet) {
    let calls = v.get("calls").and_then(|x| x.as_u64()).unwrap_or(0);
    let m = MetricSet {
        calls,
        answered: v.get("answered").and_then(|x| x.as_u64()).unwrap_or(0),
        failed: v.get("failed").and_then(|x| x.as_u64()).unwrap_or(0),
        pdd_sum_ms: opt_f64(v, "avg_pdd_ms").unwrap_or(0.0) * calls as f64,
        pdd_n: calls,
        jitter_sum_ms: opt_f64(v, "avg_jitter_ms").unwrap_or(0.0) * calls as f64,
        jitter_n: calls,
        loss_sum_pct: opt_f64(v, "avg_loss_pct").unwrap_or(0.0) * calls as f64,
        loss_n: calls,
        rtt_sum_ms: opt_f64(v, "avg_rtt_ms").unwrap_or(0.0) * calls as f64,
        rtt_n: calls,
        mos_sum: opt_f64(v, "avg_mos").unwrap_or(0.0) * calls as f64,
        mos_n: calls,
    };
    (
        v.get("bucket_us").and_then(|x| x.as_u64()).unwrap_or(0),
        v.get("dim_key")
            .and_then(|x| x.as_str())
            .unwrap_or_default()
            .to_string(),
        m,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn export_import_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("snap.jsonl");

        let mut snap = Snapshot {
            source: "test".into(),
            ..Snapshot::default()
        };
        snap.calls.push(CallSummary {
            call_id: "abc@x".into(),
            from_user: Some("1001".into()),
            to_user: Some("1002".into()),
            state: CallState::Completed,
            outcome: Outcome::Answered,
            invite_ts: Some(1_000_000),
            duration_ms: Some(5_000),
            pdd_ms: Some(150),
            setup_ms: Some(200),
            hangup_code: Some(200),
            pkts_sip: 8,
            pkts_rtp: 100,
            best_mos: Some(4.2),
            warn_count: 1,
            critical_count: 0,
            stream_count: 1,
            via_turn: false,
        });
        snap.streams.push(StreamSummary {
            call_id: Some("abc@x".into()),
            ssrc: 0xdeadbeef,
            flow: Some(Flow5Tuple {
                proto: Proto::Udp,
                src: "10.0.0.1:5004".parse().unwrap(),
                dst: "10.0.0.2:5004".parse().unwrap(),
            }),
            codec: Some("PCMU".into()),
            payload_type: Some(0),
            packets: 100,
            lost: 2,
            expected: 102,
            loss_pct: 2.0,
            jitter_ms: Some(1.5),
            first_ts_us: None,
            last_ts_us: None,
            rtt_min_ms: None,
            rtt_avg_ms: Some(12.3),
            rtt_max_ms: None,
            oneway_ms: Some(6.1),
            mos: Some(4.2),
            direction: Some("sendrecv".into()),
            leg: None,
            via_turn: false,
            bytes: 0,
            history: Vec::new(),
        });
        snap.diagnostics.push(Diagnostic {
            ts_us: 1_001_000,
            call_id: "abc@x".into(),
            severity: Severity::Warn,
            code: crate::diagnostics::RTP_PT_MISMATCH,
            message: "PT=8 not in negotiated codecs".into(),
        });
        snap.buckets.push((
            900_000,
            "10.0.0.1".into(),
            MetricSet {
                calls: 2,
                answered: 1,
                failed: 1,
                ..MetricSet::default()
            },
        ));

        export_snapshot(&path, &snap).unwrap();
        let loaded = import_snapshot(&path).unwrap();

        assert_eq!(loaded.calls.len(), 1);
        assert_eq!(loaded.calls[0].call_id, "abc@x");
        assert_eq!(loaded.calls[0].state, CallState::Completed);
        assert_eq!(loaded.calls[0].pdd_ms, Some(150));
        assert_eq!(loaded.streams.len(), 1);
        assert_eq!(loaded.streams[0].call_id.as_deref(), Some("abc@x"));
        assert_eq!(loaded.streams[0].ssrc, 0xdeadbeef);
        assert_eq!(loaded.streams[0].codec.as_deref(), Some("PCMU"));
        assert_eq!(loaded.diagnostics.len(), 1);
        assert_eq!(
            loaded.diagnostics[0].code,
            crate::diagnostics::RTP_PT_MISMATCH
        );
        assert_eq!(loaded.buckets.len(), 1);
        assert_eq!(loaded.buckets[0].2.asr(), 50.0);
        // Summary aggregates recomputed from the imported rows.
        assert_eq!(loaded.completed, 1);
        assert_eq!(loaded.calls_total, 1);
        assert!((loaded.avg_setup_ms - 200.0).abs() < f64::EPSILON);
    }

    #[test]
    fn import_ignores_unrelated_lines() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mixed.jsonl");
        std::fs::write(
            &path,
            "not json\n{\"kind\":\"call\",\"call_id\":\"x\",\"state\":\"Active\"}\ngarbage line\n",
        )
        .unwrap();
        let snap = import_snapshot(&path).unwrap();
        assert_eq!(snap.calls.len(), 1);
        assert_eq!(snap.calls[0].call_id, "x");
    }
}
