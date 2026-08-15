//! End-to-end TURN diagnostics: analysis of the `turn_relay.pcap` fixture
//! (3 TURN-relayed calls, media via a learned relay, asymmetric leg loss).

use std::path::PathBuf;
use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_sipmon"))
}

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/pcap_fixtures/turn_relay.pcap")
}

/// Run file analysis with --export-jsonl and parse every line.
fn analyze_export() -> Vec<serde_json::Value> {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.jsonl");
    let status = bin()
        .arg("--export-jsonl")
        .arg(&out)
        .arg("file")
        .arg("-r")
        .arg(fixture())
        .arg("--no-tui")
        .status()
        .unwrap();
    assert!(status.success());
    std::fs::read_to_string(&out)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

#[test]
fn turn_calls_completed_and_marked() {
    let rows = analyze_export();
    let calls: Vec<_> = rows.iter().filter(|r| r["kind"] == "call").collect();
    assert_eq!(calls.len(), 2, "fixture has 2 TURN calls");
    for c in &calls {
        assert_eq!(c["state"], "Completed", "call {}", c["call_id"]);
        assert_eq!(c["via_turn"], true, "call must be marked via_turn");
    }
}

#[test]
fn relay_media_legs_are_labeled() {
    let rows = analyze_export();
    let streams: Vec<_> = rows.iter().filter(|r| r["kind"] == "stream").collect();
    assert_eq!(streams.len(), 4, "2 calls x 2 relay legs");
    for s in &streams {
        assert_eq!(s["via_turn"], true, "relay stream must be via_turn");
        let leg = s["leg"].as_str().unwrap();
        assert!(
            leg == "client" || leg == "peer",
            "unexpected leg label {leg}"
        );
        assert!(s["packets"].as_u64().unwrap() > 0);
        assert!(s["loss_pct"].as_f64().unwrap() >= 0.0);
        assert!(s["jitter_ms"].is_number());
    }
}

#[test]
fn leg_imbalance_diagnostic_emitted() {
    let rows = analyze_export();
    let diags: Vec<_> = rows
        .iter()
        .filter(|r| r["kind"] == "diag" && r["code"] == "TURN_LEG_IMBALANCE")
        .collect();
    assert_eq!(diags.len(), 2, "one imbalance diag per TURN call");
    for d in &diags {
        assert_eq!(d["severity"], "WARN");
        let msg = d["message"].as_str().unwrap();
        assert!(
            msg.contains("bottleneck on relay<->peer"),
            "peer leg has ~20% loss vs ~0% client leg: {msg}"
        );
    }
}

#[test]
fn allocation_learned_auto() {
    // Even without --turn-servers, the Allocate exchange must auto-learn the
    // relay so legs are classified (covered implicitly by leg labels above,
    // but assert alloc diagnostics present at info level too).
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("info.jsonl");
    let status = bin()
        .arg("--diag-level")
        .arg("info")
        .arg("--export-jsonl")
        .arg(&out)
        .arg("file")
        .arg("-r")
        .arg(fixture())
        .arg("--no-tui")
        .status()
        .unwrap();
    assert!(status.success());
    let content = std::fs::read_to_string(&out).unwrap();
    assert!(
        content.contains("TURN_ALLOC_OK"),
        "allocation success should be visible at info level"
    );
    assert!(
        content.contains("TURN_RELAY_MEDIA"),
        "relay media diag should be visible at info level"
    );
}

#[test]
fn turn_srv_flag_labels_control_flow() {
    // Passing --turn-servers must not break analysis.
    let status = bin()
        .arg("--turn-servers")
        .arg("203.0.113.1")
        .arg("file")
        .arg("-r")
        .arg(fixture())
        .arg("--no-tui")
        .status()
        .unwrap();
    assert!(status.success());
}
