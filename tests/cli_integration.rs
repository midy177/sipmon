//! End-to-end tests running the sipmon binary against a real pcap fixture
//! (INVITE -> 100 -> 200 -> ACK -> RTP/RTCP (both directions) -> BYE -> 200),
//! captured from two sipbot instances on loopback.

use std::path::PathBuf;
use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_sipmon"))
}

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/pcap_fixtures/sipbot_call.pcap")
}

struct CallLine {
    state: String,
    setup_ms: Option<i64>,
    crit: i64,
}

fn run_headless(pcap: &PathBuf, extra: &[&str]) -> Vec<CallLine> {
    let mut cmd = bin();
    for a in extra {
        cmd.arg(a);
    }
    cmd.arg("file").arg("-r").arg(pcap).arg("--no-tui");
    let out = cmd.output().expect("run sipmon");
    assert!(
        out.status.success(),
        "sipmon failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| {
            let v: serde_json::Value = serde_json::from_str(l).ok()?;
            Some(CallLine {
                state: v["state"].as_str()?.to_string(),
                setup_ms: v["setup_ms"].as_i64(),
                crit: v["crit"].as_i64().unwrap_or(0),
            })
        })
        .collect()
}

#[test]
fn file_analysis_finds_completed_call() {
    let calls = run_headless(&fixture(), &[]);
    assert_eq!(calls.len(), 1, "expected exactly one call in the fixture");
    let c = &calls[0];
    assert_eq!(c.state, "Completed");
    assert!(c.setup_ms.unwrap_or(0) > 0, "setup_ms should be positive");
    assert_eq!(
        c.crit, 0,
        "no critical diagnostics expected on a clean call"
    );
}

#[test]
fn default_positional_pcap_mode() {
    // `sipmon <file.pcap>` without a subcommand is equivalent to `file -r`.
    let mut cmd = bin();
    cmd.arg("--no-tui").arg(fixture());
    let out = cmd.output().expect("run sipmon");
    assert!(
        out.status.success(),
        "sipmon failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("\"state\":\"Completed\""),
        "default pcap mode must analyze the file, got: {stdout}"
    );
}

#[test]
fn default_positional_evlog_replays() {
    // `sipmon <file.evlog>` without a subcommand is equivalent to `replay FILE`.
    let dir = tempfile::tempdir().unwrap();
    let evlog = dir.path().join("t.evlog");
    let mut cmd = bin();
    cmd.arg("--evlog")
        .arg(&evlog)
        .arg("file")
        .arg("-r")
        .arg(fixture())
        .arg("--no-tui");
    let out = cmd.output().expect("run sipmon");
    assert!(out.status.success());
    assert!(evlog.exists(), "event log must be written");

    let r = bin().arg("--no-tui").arg(&evlog).output().unwrap();
    assert!(
        r.status.success(),
        "default evlog mode failed: {}",
        String::from_utf8_lossy(&r.stderr)
    );
    let rout = String::from_utf8_lossy(&r.stdout);
    assert!(
        rout.contains("Completed"),
        "default evlog mode must replay the log, got: {rout}"
    );
}

#[test]
fn evlog_roundtrip_and_query() {
    let dir = tempfile::tempdir().unwrap();
    let evlog = dir.path().join("t.evlog");

    let mut cmd = bin();
    cmd.arg("--evlog")
        .arg(&evlog)
        .arg("file")
        .arg("-r")
        .arg(fixture())
        .arg("--no-tui");
    let out = cmd.output().expect("run sipmon");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let call_id: String = {
        let v: serde_json::Value = serde_json::from_str(stdout.lines().next().unwrap()).unwrap();
        v["call_id"].as_str().unwrap().to_string()
    };
    assert!(evlog.exists(), "event log must be written");

    // query: full flow for the call
    let q = bin()
        .args(["query", "-l"])
        .arg(&evlog)
        .arg("-c")
        .arg(&call_id)
        .output()
        .unwrap();
    assert!(q.status.success());
    let qout = String::from_utf8_lossy(&q.stdout);
    let sip_msgs = qout.lines().filter(|l| l.contains("\"msg\"")).count();
    let streams = qout.lines().filter(|l| l.contains("\"stream\"")).count();
    assert!(
        sip_msgs >= 6,
        "expected INVITE/100/200/ACK/BYE/200, got {sip_msgs}"
    );
    assert!(
        streams >= 2,
        "expected periodic stream snapshots, got {streams}"
    );

    // stats: positional FILE (and -l still works)
    let s = bin().args(["stats"]).arg(&evlog).output().unwrap();
    assert!(
        s.status.success(),
        "stats failed: {}",
        String::from_utf8_lossy(&s.stderr)
    );
    let sout = String::from_utf8_lossy(&s.stdout);
    assert!(sout.contains("Calls"), "stats must list dialogs: {sout}");
    assert!(
        sout.contains("Reliability") && sout.contains("ASR"),
        "stats must report ASR: {sout}"
    );
    assert!(
        sout.contains("Traffic"),
        "stats must report traffic: {sout}"
    );
    assert!(
        sout.contains("5-minute call availability") && sout.contains("5-minute network"),
        "stats must list 5-minute call-availability and network tables: {sout}"
    );
    assert!(
        sout.contains("CANCEL%") && sout.contains("NF%"),
        "stats windows must include cancel and fail-class rates: {sout}"
    );
    assert!(
        sout.contains("answered / seizures"),
        "stats must explain ASR: {sout}"
    );
    assert!(
        sout.contains("Definitions"),
        "stats must include metric definitions: {sout}"
    );
    let s_flag = bin().args(["stats", "-l"]).arg(&evlog).output().unwrap();
    assert!(
        s_flag.status.success(),
        "-l/--evlog alias must still work: {}",
        String::from_utf8_lossy(&s_flag.stderr)
    );
    let sj = bin()
        .args(["stats"])
        .arg(&evlog)
        .arg("--json")
        .output()
        .unwrap();
    assert!(sj.status.success());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&sj.stdout)).unwrap();
    assert!(v["calls"]["unique"].as_u64().unwrap_or(0) >= 1);
    assert!(v["reliability"]["seizures"].as_u64().unwrap_or(0) >= 1);
    assert!(
        v["windows"]
            .as_array()
            .map(|a| !a.is_empty())
            .unwrap_or(false)
    );

    // replay reproduces the same terminal state
    let r = bin()
        .args(["replay"])
        .arg(&evlog)
        .arg("--no-tui")
        .output()
        .unwrap();
    assert!(r.status.success());
    let rout = String::from_utf8_lossy(&r.stdout);
    assert!(
        rout.contains(&call_id) && rout.contains("Completed"),
        "replay must reproduce the completed call"
    );

    // export jsonl
    let jsonl = dir.path().join("t.jsonl");
    let e = bin()
        .args(["export", "-l"])
        .arg(&evlog)
        .arg("--jsonl")
        .arg(&jsonl)
        .output()
        .unwrap();
    assert!(e.status.success());
    let content = std::fs::read_to_string(&jsonl).unwrap();
    assert!(content.contains("\"kind\":\"call\""));
    assert!(content.contains("\"kind\":\"stream\""));
    assert!(content.contains("PCMU"));
}

#[test]
fn dry_run_writes_no_files() {
    let dir = tempfile::tempdir().unwrap();
    let before: Vec<_> = std::fs::read_dir(dir.path()).unwrap().collect();
    assert!(before.is_empty());

    let mut cmd = bin();
    cmd.arg("--dry-run")
        .arg("--evlog")
        .arg(dir.path().join("should-not-exist.evlog"))
        .arg("file")
        .arg("-r")
        .arg(fixture())
        .arg("--no-tui");
    let out = cmd.output().unwrap();
    assert!(out.status.success());
    let after: Vec<_> = std::fs::read_dir(dir.path()).unwrap().collect();
    assert!(after.is_empty(), "dry-run must not write any files");
}

#[test]
fn caps_limit_retained_calls() {
    // The fixture has one call; cap of 1 keeps it (no crash, sane output).
    let calls = run_headless(&fixture(), &["--max-calls", "1", "--max-streams", "2"]);
    assert!(!calls.is_empty());
}

#[test]
fn stdin_stream_mode() {
    // tcpdump-style: re-emit the fixture as a pcap stream on stdin.
    let raw = std::fs::read(fixture()).unwrap();
    let mut child = bin()
        .arg("-")
        .env_remove("TERM")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    use std::io::Write;
    child.stdin.take().unwrap().write_all(&raw).unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("Completed"),
        "stdin mode must analyze the piped pcap stream"
    );
}

#[test]
fn record_requires_evlog() {
    let out = bin().arg("record").arg("-i").arg("lo").output().unwrap();
    assert!(!out.status.success(), "record without --evlog must fail");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("--evlog"),
        "error should mention --evlog: {err}"
    );
}

#[test]
fn record_bad_interface_clean_error() {
    let dir = tempfile::tempdir().unwrap();
    let evlog = dir.path().join("t.evlog");
    let out = bin()
        .arg("record")
        .arg("-i")
        .arg("definitely-not-an-interface-xyz")
        .arg("-w")
        .arg(&evlog)
        .output()
        .unwrap();
    assert!(!out.status.success(), "bad interface must fail cleanly");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("Error"), "expected a clean error, got: {err}");
    assert!(
        !evlog.exists(),
        "no evlog should be created when the interface fails"
    );
}
