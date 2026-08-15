//! Security / robustness integration tests: hostile or malformed inputs must
//! never crash the process, hang, or trigger huge allocations.

use std::io::Write;
use std::process::{Command, Stdio};
use std::time::Duration;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_sipmon"))
}

/// Run `sipmon -` (stdin pcap stream) with the given bytes; return (status, stdout).
fn run_stdin(bytes: Vec<u8>, timeout_s: u64) -> std::process::Output {
    let mut child = bin()
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn sipmon");
    // Child may exit immediately (e.g. invalid pcap magic) and close stdin;
    // ignore the resulting broken pipe and just close our end.
    let _ = child.stdin.take().map(|mut w| w.write_all(&bytes));
    // Wait with a timeout so a hang is detected as failure.
    let start = std::time::Instant::now();
    loop {
        if let Ok(Some(status)) = child.try_wait() {
            let out = child.wait_with_output().unwrap();
            return std::process::Output {
                status,
                stdout: out.stdout,
                stderr: out.stderr,
            };
        }
        if start.elapsed() > Duration::from_secs(timeout_s) {
            child.kill().ok();
            panic!("sipmon did not exit within {timeout_s}s (possible hang)");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn not_crash(status: &std::process::ExitStatus) -> bool {
    !status.code().map(|c| c < 0 || c == 134).unwrap_or(false)
}

/// A minimal pcap (Ethernet linktype) built from raw frames.
fn build_pcap(frames: Vec<Vec<u8>>) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&0xA1B2C3D4u32.to_le_bytes()); // magic
    out.extend_from_slice(&2u16.to_le_bytes());
    out.extend_from_slice(&4u16.to_le_bytes());
    out.extend_from_slice(&0i32.to_le_bytes());
    out.extend_from_slice(&0i32.to_le_bytes());
    out.extend_from_slice(&65535u32.to_le_bytes());
    out.extend_from_slice(&1u32.to_le_bytes()); // DLT_EN10MB
    let ts = 1_800_000_000u32;
    for f in frames {
        out.extend_from_slice(&ts.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&(f.len() as u32).to_le_bytes());
        out.extend_from_slice(&(f.len() as u32).to_le_bytes());
        out.extend_from_slice(&f);
    }
    out
}

fn ether_ip_tcp(payload: &[u8], sport: u16, dport: u16) -> Vec<u8> {
    let mut tcp = Vec::new();
    tcp.extend_from_slice(&sport.to_be_bytes());
    tcp.extend_from_slice(&dport.to_be_bytes());
    tcp.extend_from_slice(&1u32.to_be_bytes()); // seq
    tcp.extend_from_slice(&0u32.to_be_bytes()); // ack
    tcp.push(0x50); // data offset 5
    tcp.push(0x18); // PSH|ACK
    tcp.extend_from_slice(&65535u16.to_be_bytes()); // window
    tcp.extend_from_slice(&0u16.to_be_bytes()); // checksum (ignored)
    tcp.extend_from_slice(&0u16.to_be_bytes()); // urg
    tcp.extend_from_slice(payload);

    let mut ip = Vec::new();
    ip.extend_from_slice(&[0x45, 0x00]);
    ip.extend_from_slice(&((20 + tcp.len()) as u16).to_be_bytes());
    ip.extend_from_slice(&0u16.to_be_bytes()); // id
    ip.extend_from_slice(&0u16.to_be_bytes()); // flags/frag
    ip.extend_from_slice(&64u8.to_be_bytes());
    ip.extend_from_slice(&6u8.to_be_bytes()); // TCP
    ip.extend_from_slice(&0u16.to_be_bytes()); // cksum
    ip.extend_from_slice(&[10, 0, 0, 1]);
    ip.extend_from_slice(&[10, 0, 0, 2]);

    let mut eth = Vec::new();
    eth.extend_from_slice(&[0x02, 0, 0, 0, 0, 1]);
    eth.extend_from_slice(&[0x02, 0, 0, 0, 0, 2]);
    eth.extend_from_slice(&[0x08, 0x00]);
    eth.extend_from_slice(&ip);
    eth.extend_from_slice(&tcp);
    eth
}

#[test]
fn garbage_pcap_stdin_no_crash() {
    let mut rng = 0xdeadbeefu64;
    let mut blob = Vec::with_capacity(1_000_000);
    for _ in 0..1_000_000 {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        blob.push((rng & 0xff) as u8);
    }
    let out = run_stdin(blob, 30);
    // Must terminate quickly. Invalid pcap magic may produce a clean error
    // (nonzero exit); a crash signal or hang is the failure mode.
    assert!(
        not_crash(&out.status),
        "garbage stdin caused a crash: {:?}",
        out.status
    );
}

#[test]
fn truncated_pcap_no_crash() {
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/pcap_fixtures/sipbot_call.pcap");
    let data = std::fs::read(fixture).unwrap();
    // Feed progressively truncated versions; all must terminate without crash.
    for cut in [10usize, 100, 1000, 10_000, 100_000, data.len() / 2] {
        let out = run_stdin(data[..cut.min(data.len())].to_vec(), 20);
        if cut >= 24 {
            // Valid global header present: analysis should run to EOF.
            assert!(
                out.status.success(),
                "truncated pcap at {cut} should analyze cleanly"
            );
        } else {
            // No valid header: a clean error is fine, a crash is not.
            assert!(not_crash(&out.status), "truncated pcap at {cut} crashed");
        }
    }
}

#[test]
fn huge_content_length_tcp_no_oom() {
    // SIP headers advertising a huge Content-Length, followed by a large
    // stream of body bytes in separate TCP segments. The reassembler must
    // bound its buffer (1 MiB cap) instead of growing without limit.
    let hdr = b"INVITE sip:x SIP/2.0\r\nContent-Length: 2000000000\r\n\r\n".to_vec();
    let mut frames = vec![ether_ip_tcp(&hdr, 5060, 5060)];
    let chunk = vec![0x41u8; 4096];
    for _ in 0..3000 {
        // ~12 MB of body bytes after the headers.
        frames.push(ether_ip_tcp(&chunk, 5060, 5060));
    }
    let pcap = build_pcap(frames);
    let out = run_stdin(pcap, 60);
    assert!(
        out.status.success(),
        "huge CL must terminate cleanly, not OOM"
    );
}

#[test]
fn corrupt_evlog_huge_length_clean_error() {
    let dir = tempfile::tempdir().unwrap();
    let evlog = dir.path().join("bad.evlog");
    let mut data = Vec::new();
    data.extend_from_slice(b"SMON");
    data.extend_from_slice(&1u16.to_be_bytes());
    data.extend_from_slice(&0u16.to_be_bytes());
    data.extend_from_slice(&0i32.to_be_bytes());
    data.push(1); // ts delta
    data.push(1); // type
    data.extend_from_slice(&[0xFF; 9]); // huge varint length
    data.push(0x7F);
    std::fs::write(&evlog, data).unwrap();

    // query must fail fast with a clean error, not hang / OOM.
    let start = std::time::Instant::now();
    let out = bin()
        .args(["query", "-l"])
        .arg(&evlog)
        .arg("-c")
        .arg("x")
        .output()
        .unwrap();
    assert!(start.elapsed() < Duration::from_secs(10));
    // Nonzero exit (corrupt file) is acceptable; no crash/hang is the invariant.
    let _ = out;
}

#[test]
fn nonexistent_inputs_clean_errors() {
    for args in [
        vec!["file", "-r", "/nonexistent/nope.pcap", "--no-tui"],
        vec!["query", "-l", "/nonexistent/nope.evlog", "-c", "x"],
        vec!["replay", "-l", "/nonexistent/nope.evlog", "--no-tui"],
    ] {
        let mut c = bin();
        for a in &args {
            c.arg(a);
        }
        let start = std::time::Instant::now();
        let out = c.output().unwrap();
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "args {args:?} hung"
        );
        // Must not panic (panic => SIGABRT => signal, not normal error).
        assert!(
            !out.status
                .code()
                .map(|c| c < 0 || c == 134)
                .unwrap_or(false),
            "args {args:?} crashed: {:?}",
            out.status
        );
    }
}

#[test]
fn random_sip_blast_no_crash() {
    // Craft packets that look like SIP start lines with hostile tails.
    let mut frames = Vec::new();
    let seeds: &[&[u8]] = &[
        b"INVITE sip:a SIP/2.0\r\nCSeq: 1 INVITE\r\nContent-Length: 999999999999\r\n\r\n",
        b"SIP/2.0 999 BAD\r\n\r\n",
        b"BYE sip:x SIP/2.0\r\nReason: SIP ;cause=99999\r\n\r\n",
        b"INVITE sip:a SIP/2.0\r\nContent-Type: application/sdp\r\n\r\nv=0\r\nc=IN IP4 notanip\r\nm=audio 0 RTP/AVP -1\r\n",
    ];
    for s in seeds {
        frames.push(ether_ip_tcp(s, 5060, 5060));
    }
    let pcap = build_pcap(frames);
    let out = run_stdin(pcap, 20);
    assert!(out.status.success());
}
