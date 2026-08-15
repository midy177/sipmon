mod analyze;
mod capture;
mod config;
mod correlate;
mod decode;
mod diagnostics;
mod error;
mod export;
mod model;
#[cfg(test)]
mod selftest;
mod store;
mod ui;

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use capture::CaptureSource;
use config::{Bucket, Config};
use correlate::Correlator;
use diagnostics::Severity;
use store::evlog::{Event, EvlogReader, EvlogWriter};
use store::registry::Snapshot;

#[derive(Parser)]
#[command(
    name = "sipmon",
    version,
    about = "SIP/RTP signaling & media quality monitor (passive, pcap-based)"
)]
struct Cli {
    /// Default capture source: a .pcap/.pcapng file to analyze, or a .evlog to
    /// replay. Equivalent to `sipmon file -r FILE` / `sipmon replay -l FILE`.
    #[arg(value_name = "FILE")]
    file: Option<PathBuf>,

    #[command(subcommand)]
    cmd: Option<Cmd>,

    // ---- common options ----
    /// Headless: no TUI, print final per-call JSON (for default FILE mode)
    #[arg(long)]
    no_tui: bool,
    /// In-memory only: no event-log writer thread, no continuous files
    #[arg(long)]
    dry_run: bool,
    /// Max retained calls (evict oldest terminated first)
    #[arg(long, default_value = "100000")]
    max_calls: usize,
    /// Max retained RTP streams
    #[arg(long, default_value = "50000")]
    max_streams: usize,
    /// Max retained diagnostics (ring)
    #[arg(long, default_value = "50000")]
    max_diagnostics: usize,
    /// Minimum diagnostic level: info|warn|critical
    #[arg(long, default_value = "warn")]
    diag_level: String,
    /// Comma-separated TURN server IPs (optional; also auto-learned)
    #[arg(long, value_delimiter = ',')]
    turn_servers: Vec<std::net::IpAddr>,
    /// Truncate stored raw SIP messages to N bytes
    #[arg(long)]
    raw_truncate: Option<usize>,
    /// Heatmap bucket granularity: 15m|1h|1d
    #[arg(long, default_value = "15m")]
    bucket: String,
    /// Write the binary event log to this path
    #[arg(short = 'w', long)]
    evlog: Option<PathBuf>,
    /// Export final snapshot as JSONL on exit
    #[arg(long)]
    export_jsonl: Option<PathBuf>,
    /// Export final snapshot as SQLite on exit
    #[arg(long)]
    export_sqlite: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Live capture from a network interface
    Live {
        /// Interface to capture on (default: any)
        #[arg(short = 'i', long, default_value = "any")]
        interface: String,
        /// BPF filter
        #[arg(short = 'f', long)]
        filter: Option<String>,
        /// Disable RTP/RTCP analysis
        #[arg(long)]
        no_media: bool,
    },
    /// Analyze a pcap/pcapng file
    File {
        #[arg(short = 'r', long)]
        read: String,
        /// Replay speed multiplier (e.g. 1 = real-time)
        #[arg(long)]
        rate: Option<f64>,
        /// Print structured events to stdout (M0 verification)
        #[arg(long)]
        print_events: bool,
        /// Headless: no TUI, print final per-call JSON
        #[arg(long)]
        no_tui: bool,
    },
    /// Record a live capture into a binary event log (headless, daemonizable)
    Record {
        /// Interface to capture on (default: any)
        #[arg(short = 'i', long, default_value = "any")]
        interface: String,
        /// BPF filter
        #[arg(short = 'f', long)]
        filter: Option<String>,
        /// Disable RTP/RTCP analysis
        #[arg(long)]
        no_media: bool,
        /// Event-log output path (required)
        #[arg(short = 'w', long)]
        evlog: PathBuf,
        /// Run as a background daemon
        #[arg(short = 'd', long)]
        daemon: bool,
        /// Write the daemon PID to this file
        #[arg(long)]
        pidfile: Option<PathBuf>,
        /// Daemon stderr/tracing log file (default: /dev/null)
        #[arg(long)]
        logfile: Option<PathBuf>,
    },
    /// Replay a sipmon event log
    Replay {
        #[arg(short = 'l', long)]
        evlog: String,
        #[arg(long)]
        no_tui: bool,
    },
    /// Query one Call-ID from an event log (script friendly)
    Query {
        #[arg(short = 'l', long)]
        evlog: String,
        #[arg(short = 'c', long)]
        call_id: String,
    },
    /// Export an event log to sqlite/jsonl
    Export {
        #[arg(short = 'l', long)]
        evlog: String,
        #[arg(long)]
        sqlite: Option<PathBuf>,
        #[arg(long)]
        jsonl: Option<PathBuf>,
        /// Filter from (unix seconds)
        #[arg(long)]
        from: Option<u64>,
        /// Filter to (unix seconds)
        #[arg(long)]
        to: Option<u64>,
    },
}

struct Shared {
    snap: Arc<Mutex<Snapshot>>,
    pause: Arc<AtomicBool>,
    focus: Arc<Mutex<Option<String>>>,
    quit: Arc<AtomicBool>,
}

impl Shared {
    fn new() -> Self {
        Self {
            snap: Arc::new(Mutex::new(Snapshot::default())),
            pause: Arc::new(AtomicBool::new(false)),
            focus: Arc::new(Mutex::new(None)),
            quit: Arc::new(AtomicBool::new(false)),
        }
    }
}

fn main() -> Result<()> {
    // Never die on a closed pipe (e.g. `sipmon ... | head`): ignore SIGPIPE.
    #[cfg(unix)]
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
    }

    // `sipmon -` == stdin pcap stream mode.
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("-") {
        let rest: Vec<String> = args.iter().skip(2).cloned().collect();
        let no_tui = rest.iter().any(|a| a == "--no-tui");
        let cli = Cli::parse_from(std::iter::once("sipmon".to_string()).chain(rest));
        return run_stdin(cli, want_tui(no_tui));
    }

    let cli = Cli::parse();
    let cfg = build_config(&cli);
    let global_no_tui = cli.no_tui;

    match cli.cmd {
        Some(Cmd::Live {
            interface,
            filter,
            no_media,
        }) => {
            let mut c = cfg.clone();
            c.bpf = filter;
            c.no_media = no_media;
            let source = capture::live::LiveSource::open(&interface, c.bpf.as_deref())?;
            run_capture_loop(
                Box::new(source),
                c,
                format!("live:{interface}"),
                want_tui(false),
                false,
                false,
            )
        }
        Some(Cmd::File {
            read,
            rate,
            print_events,
            no_tui,
        }) => {
            let source = capture::file::FileSource::open(&read, rate)?;
            run_capture_loop(
                Box::new(source),
                cfg,
                format!("file:{read}"),
                want_tui(no_tui || global_no_tui),
                print_events,
                false,
            )
        }
        Some(Cmd::Record {
            interface,
            filter,
            no_media,
            evlog,
            daemon,
            pidfile,
            logfile,
        }) => {
            let mut c = cfg.clone();
            c.bpf = filter;
            c.no_media = no_media;
            run_record(
                c,
                &interface,
                &evlog,
                daemon,
                pidfile.as_deref(),
                logfile.as_deref(),
            )
        }
        Some(Cmd::Replay { evlog, no_tui }) => {
            run_replay(&cfg, &evlog, want_tui(no_tui || global_no_tui))
        }
        Some(Cmd::Query { evlog, call_id }) => run_query(&evlog, &call_id),
        Some(Cmd::Export {
            evlog,
            sqlite,
            jsonl,
            from,
            to,
        }) => run_export(&cfg, &evlog, sqlite, jsonl, from, to),
        None => {
            // No subcommand: a bare FILE defaults to the matching mode,
            // otherwise start a live capture on the default interface.
            if let Some(path) = cli.file {
                return run_default_file(&cfg, &path, global_no_tui);
            }
            let source = capture::live::LiveSource::open("any", cfg.bpf.as_deref())?;
            run_capture_loop(
                Box::new(source),
                cfg,
                "live:any".to_string(),
                want_tui(false),
                false,
                false,
            )
        }
    }
}

/// Default FILE mode: a .pcap/.pcapng is analyzed like `file -r`, a .evlog is
/// replayed like `replay -l`, a .jsonl snapshot export is loaded for viewing.
fn run_default_file(cfg: &Config, path: &std::path::Path, no_tui: bool) -> Result<()> {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    match ext.as_str() {
        "pcap" | "pcapng" => {
            let source = capture::file::FileSource::open(&path.to_string_lossy(), None)?;
            run_capture_loop(
                Box::new(source),
                cfg.clone(),
                format!("file:{}", path.display()),
                want_tui(no_tui),
                false,
                false,
            )
        }
        "evlog" => run_replay(cfg, &path.to_string_lossy(), want_tui(no_tui)),
        "jsonl" => run_jsonl_view(cfg, path, want_tui(no_tui)),
        _ => anyhow::bail!(
            "unrecognized file type '{ext}': pass `file -r FILE` for pcap/pcapng, `replay -l FILE` for an evlog, or a .jsonl snapshot export"
        ),
    }
}

/// Decide whether to launch the TUI: explicit --no-tui wins, otherwise require
/// a tty so piped/CI invocations fall back to headless output.
fn want_tui(explicit_no_tui: bool) -> bool {
    use std::io::IsTerminal;
    !explicit_no_tui && std::io::stdout().is_terminal()
}

fn build_config(cli: &Cli) -> Config {
    let mut c = Config {
        raw_truncate: cli.raw_truncate,
        dry_run: cli.dry_run,
        max_calls: cli.max_calls,
        max_streams: cli.max_streams,
        max_diagnostics: cli.max_diagnostics,
        diag_level: cli.diag_level.clone(),
        turn_servers: cli.turn_servers.clone(),
        bucket: Bucket::from_str_lossy(&cli.bucket),
        export_jsonl: cli.export_jsonl.clone(),
        export_sqlite: cli.export_sqlite.clone(),
        evlog: cli.evlog.clone(),
        ..Config::default()
    };
    if c.dry_run {
        // Dry-run: pure in-memory analysis; no continuous files. Explicit
        // `export` subcommand remains allowed, and exit-time export flags are
        // also honored only if the user passed them explicitly — keep them.
        c.evlog = None;
    }
    c
}

fn run_stdin(cli: Cli, with_tui: bool) -> Result<()> {
    let cfg = build_config(&cli);
    let source = unsafe { capture::stdin::StdinSource::open()? };
    run_capture_loop(
        Box::new(source),
        cfg,
        "stdin".to_string(),
        with_tui,
        false,
        false,
    )
}

/// Record mode: live capture → binary event log, headless and optionally
/// daemonized (`-d`). Same pipeline as `live`/`file`, but it always writes the
/// evlog and never prints per-call JSON.
fn run_record(
    mut cfg: Config,
    interface: &str,
    evlog: &std::path::Path,
    daemon: bool,
    pidfile: Option<&std::path::Path>,
    logfile: Option<&std::path::Path>,
) -> Result<()> {
    if daemon {
        daemonize(logfile)?;
    }
    install_signal_handlers();
    if let Some(p) = pidfile {
        write_pidfile(p)?;
    }

    cfg.evlog = Some(evlog.to_path_buf());
    cfg.dry_run = false; // record always persists

    let source = capture::live::LiveSource::open(interface, cfg.bpf.as_deref())?;
    run_capture_loop(
        Box::new(source),
        cfg,
        format!("record:{interface}"),
        false,
        false,
        true,
    )
}

/// A signal (SIGTERM/SIGINT) sets this; the capture loop polls it so the evlog
/// writer can flush and shut down cleanly.
#[cfg(unix)]
static QUIT_SIG: AtomicBool = AtomicBool::new(false);

#[cfg(unix)]
extern "C" fn on_terminate(_: libc::c_int) {
    QUIT_SIG.store(true, Ordering::SeqCst);
}

#[cfg(unix)]
fn install_signal_handlers() {
    unsafe {
        libc::signal(
            libc::SIGTERM,
            on_terminate as *const () as libc::sighandler_t,
        );
        libc::signal(
            libc::SIGINT,
            on_terminate as *const () as libc::sighandler_t,
        );
    }
}

#[cfg(unix)]
fn quit_sig_raised() -> bool {
    QUIT_SIG.load(Ordering::SeqCst)
}

#[cfg(not(unix))]
fn quit_sig_raised() -> bool {
    false
}

/// Classic double-fork daemonization. stdio is redirected to `logfile`
/// (default /dev/null). The working directory is left unchanged so relative
/// evlog paths keep working. The logfile is opened before forking so open
/// errors are reported to the invoking shell.
#[cfg(unix)]
fn daemonize(logfile: Option<&std::path::Path>) -> Result<()> {
    use std::os::fd::AsRawFd;
    let devnull = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/null")?;
    let out = match logfile {
        Some(p) => std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(p)?,
        None => devnull.try_clone()?,
    };
    unsafe {
        match libc::fork() {
            -1 => anyhow::bail!("daemonize: first fork failed"),
            0 => {}
            _ => std::process::exit(0),
        }
        if libc::setsid() < 0 {
            anyhow::bail!("daemonize: setsid failed");
        }
        match libc::fork() {
            -1 => anyhow::bail!("daemonize: second fork failed"),
            0 => {}
            _ => std::process::exit(0),
        }
        libc::dup2(devnull.as_raw_fd(), 0); // stdin
        libc::dup2(out.as_raw_fd(), 1); // stdout
        libc::dup2(out.as_raw_fd(), 2); // stderr
    }
    Ok(())
}

#[cfg(not(unix))]
fn daemonize(_logfile: Option<&std::path::Path>) -> Result<()> {
    anyhow::bail!("daemon mode (-d) is only supported on Unix")
}

fn write_pidfile(path: &std::path::Path) -> Result<()> {
    std::fs::write(path, format!("{}\n", std::process::id()))?;
    Ok(())
}

/// Core pipeline: pull frames → correlate → publish snapshots (+ evlog).
fn run_capture_loop(
    source: Box<dyn CaptureSource>,
    cfg: Config,
    name: String,
    with_tui: bool,
    print_events: bool,
    quiet: bool,
) -> Result<()> {
    let shared = Arc::new(Shared::new());
    let evlog_path: Option<PathBuf> = if cfg.dry_run { None } else { cfg.evlog.clone() };

    let corr = Correlator::new(&cfg, name.clone());
    let writer = match &evlog_path {
        Some(p) => Some(EvlogWriter::create(p)?),
        None => None,
    };

    let mut source = source;
    let mut last_publish = std::time::Instant::now();

    // TUI runs on the main thread; pipeline runs on a worker.
    let shared2 = shared.clone();
    let handle = std::thread::spawn(move || {
        let mut corr = corr;
        let mut writer = writer;
        // Shutdown signal: unblocks capture and lets the loop exit.
        source.set_stop(shared2.quit.clone());
        // Idle-skip bookkeeping: republish only when traffic or focus changed.
        let mut last_pub_pkts = u64::MAX;
        let mut last_pub_focus: Option<String> = Some("\u{0}init".to_string());
        let mut exhausted = false;
        loop {
            if quit_sig_raised() {
                shared2.quit.store(true, Ordering::Relaxed);
            }
            if shared2.quit.load(Ordering::Relaxed) {
                break;
            }
            if shared2.pause.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_millis(50));
                continue;
            }
            let Some(frame) = source.next_frame() else {
                if !exhausted {
                    // Source EOF: final flush + full-fidelity publish so the
                    // UI/export sees the complete capture.
                    exhausted = true;
                    corr.maybe_periodic_flush(corr.reg.last_us.unwrap_or(0));
                    for ev in corr.take_events() {
                        if let Some(w) = writer.as_mut() {
                            let _ = w.write(&ev);
                        }
                    }
                    if let Some(w) = writer.as_mut() {
                        let _ = w.flush();
                    }
                    publish(&shared2, &mut corr, true);
                }
                if with_tui {
                    // Capture finished but the TUI is still open: keep the
                    // worker alive so focus changes (Enter on a call) are
                    // republished into the snapshot.
                    let cur_focus = shared2.focus.lock().ok().and_then(|f| f.clone());
                    if cur_focus != last_pub_focus {
                        publish(&shared2, &mut corr, true);
                        last_pub_focus = cur_focus;
                    }
                    std::thread::sleep(Duration::from_millis(50));
                    continue;
                }
                break;
            };
            let ts = frame.ts_us;
            corr.ingest_frame(frame);
            corr.maybe_periodic_flush(ts);

            // Drain evlog events.
            for ev in corr.take_events() {
                if print_events {
                    print_event(&ev);
                }
                if let Some(w) = writer.as_mut() {
                    let _ = w.write(&ev);
                }
            }

            if last_publish.elapsed() >= Duration::from_millis(100) {
                let cur_pkts = corr.reg.pkts_total;
                let cur_focus = shared2.focus.lock().ok().and_then(|f| f.clone());
                if cur_pkts != last_pub_pkts || cur_focus != last_pub_focus {
                    publish(&shared2, &mut corr, false);
                    last_pub_pkts = cur_pkts;
                    last_pub_focus = cur_focus;
                }
                if let Some(w) = writer.as_mut() {
                    let _ = w.flush();
                }
                last_publish = std::time::Instant::now();
            }
        }
        corr.maybe_periodic_flush(corr.reg.last_us.unwrap_or(0));
        for ev in corr.take_events() {
            if let Some(w) = writer.as_mut() {
                let _ = w.write(&ev);
            }
        }
        if let Some(w) = writer.as_mut() {
            let _ = w.flush();
        }
        // Final publish: full fidelity (all calls + all streams) for
        // headless output and exports.
        publish(&shared2, &mut corr, true);
    });

    if with_tui {
        run_tui(shared.clone())?;
        shared.quit.store(true, Ordering::Relaxed);
        handle
            .join()
            .map_err(|_| anyhow::anyhow!("pipeline thread panicked"))?;
    } else {
        handle
            .join()
            .map_err(|_| anyhow::anyhow!("pipeline thread panicked"))?;
        // Headless: print final per-call JSON lines (unless quiet, e.g. record).
        if !quiet {
            let snap = shared.snap.lock().unwrap().clone();
            for c in &snap.calls {
                println!(
                    "{}",
                    serde_json::json!({"kind": "call", "call_id": c.call_id, "state": c.state.label(), "pdd_ms": c.pdd_ms, "setup_ms": c.setup_ms, "warn": c.warn_count, "crit": c.critical_count})
                );
            }
        }
    }

    final_exports(&cfg, &shared)?;
    Ok(())
}

fn publish(shared: &Shared, corr: &mut Correlator, full: bool) {
    let focus = shared.focus.lock().ok().and_then(|f| f.clone());
    corr.set_focus(focus);
    let snap = if full {
        corr.reg.snapshot_full()
    } else {
        corr.reg.snapshot(500)
    };
    if let Ok(mut s) = shared.snap.lock() {
        *s = snap;
    }
}

fn print_event(ev: &Event) {
    let j = match ev {
        Event::SipMsg(e) => serde_json::json!({
            "type": "sip", "ts_us": e.ts_us, "call_id": e.call_id,
            "method": e.method, "status": e.status,
            "src": e.flow.src.to_string(), "dst": e.flow.dst.to_string(),
            "cseq": e.cseq, "branch": e.branch,
        }),
        Event::Txn(e) => {
            serde_json::json!({"type":"txn","ts_us":e.ts_us,"call_id":e.call_id,"method":e.method,"code":e.response_code,"delay_ms":e.delay_ms})
        }
        Event::Call(e) => {
            serde_json::json!({"type":"call","ts_us":e.ts_us,"call_id":e.call_id,"kind":format!("{:?}", e.kind),"state":e.state,"pdd_ms":e.pdd_ms,"setup_ms":e.setup_ms,"hangup":e.hangup_code})
        }
        Event::StreamSnap(e) => {
            serde_json::json!({"type":"stream","ts_us":e.ts_us,"call_id":e.call_id,"ssrc":format!("{:#x}",e.ssrc),"packets":e.packets,"lost":e.lost,"loss_pct":(e.loss_pct*100.0).round()/100.0,"jitter_ms":e.jitter_ms,"mos":e.mos})
        }
        Event::RtcpRtt(e) => {
            serde_json::json!({"type":"rtcp_rtt","ts_us":e.ts_us,"call_id":e.call_id,"ssrc":format!("{:#x}",e.ssrc),"rtt_ms":e.rtt_ms,"oneway_ms":e.oneway_ms})
        }
        Event::HealthBucket(e) => {
            serde_json::json!({"type":"bucket","bucket_us":e.bucket_us,"key":e.dim_key,"metrics":e.metrics})
        }
        Event::Error(e) => {
            serde_json::json!({"type":"error","ts_us":e.ts_us,"kind":e.kind,"msg":e.msg})
        }
        Event::Diag(e) => {
            serde_json::json!({"type":"diag","ts_us":e.ts_us,"call_id":e.call_id,"severity":e.severity,"code":e.code,"message":e.message})
        }
    };
    println!("{j}");
}

fn final_exports(cfg: &Config, shared: &Shared) -> Result<()> {
    let snap = shared.snap.lock().unwrap().clone();
    if let Some(p) = &cfg.export_jsonl {
        export::jsonl::export_snapshot(p, &snap)
            .with_context(|| format!("export jsonl {}", p.display()))?;
        eprintln!("exported {}", p.display());
    }
    if let Some(p) = &cfg.export_sqlite {
        export::sqlite::export_snapshot(p, &snap)
            .with_context(|| format!("export sqlite {}", p.display()))?;
        eprintln!("exported {}", p.display());
    }
    Ok(())
}

// ----------------------------- replay -----------------------------

fn run_replay(cfg: &Config, evlog: &str, with_tui: bool) -> Result<()> {
    let mut reader = EvlogReader::open(evlog)?;
    let shared = Arc::new(Shared::new());
    let corr = Correlator::new(cfg, format!("replay:{evlog}"));

    let shared2 = shared.clone();
    let handle = std::thread::spawn(move || {
        let mut corr = corr;
        let mut last_pub_focus: Option<String> = Some("\u{0}init".to_string());
        let mut done = false;
        loop {
            if shared2.quit.load(Ordering::Relaxed) {
                break;
            }
            if shared2.pause.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_millis(50));
                continue;
            }
            match reader.next_event() {
                Ok(Some(ev)) => {
                    if let Event::SipMsg(e) = &ev {
                        let msg = capture::replay::evt_to_sipmsg(e);
                        corr.ingest_sip(msg);
                    } else if let Event::StreamSnap(e) = &ev {
                        corr.reg.push_event(format!(
                            "stream {} ssrc={:#x} pkts={} loss={:.1}%",
                            e.call_id, e.ssrc, e.packets, e.loss_pct
                        ));
                    } else if let Event::Diag(e) = &ev {
                        corr.reg
                            .push_event(format!("[{}] {} {}", e.severity, e.code, e.message));
                    }
                    corr.take_events(); // replay does not re-write evlog
                }
                Ok(None) => {
                    if !done {
                        done = true;
                        publish(&shared2, &mut corr, true);
                    }
                    if with_tui {
                        // Replay finished but the TUI is still open: keep the
                        // worker alive so focus changes (Enter on a call) are
                        // republished into the snapshot.
                        let cur_focus = shared2.focus.lock().ok().and_then(|f| f.clone());
                        if cur_focus != last_pub_focus {
                            publish(&shared2, &mut corr, true);
                            last_pub_focus = cur_focus;
                        }
                        std::thread::sleep(Duration::from_millis(50));
                        continue;
                    }
                    break;
                }
                Err(_) => break,
            }
        }
        publish(&shared2, &mut corr, true);
    });

    if with_tui {
        run_tui(shared.clone())?;
        shared.quit.store(true, Ordering::Relaxed);
        handle
            .join()
            .map_err(|_| anyhow::anyhow!("replay thread panicked"))?;
    } else {
        handle
            .join()
            .map_err(|_| anyhow::anyhow!("replay thread panicked"))?;
        let snap = shared.snap.lock().unwrap().clone();
        for c in &snap.calls {
            println!(
                "{}",
                serde_json::json!({"kind":"call","call_id":c.call_id,"state":c.state.label(),"pdd_ms":c.pdd_ms,"setup_ms":c.setup_ms,"warn":c.warn_count,"crit":c.critical_count})
            );
        }
    }
    final_exports(cfg, &shared)?;
    Ok(())
}

// ----------------------------- jsonl snapshot view -----------------------------

/// View a JSONL snapshot export: load it once and show it in the TUI (or print
/// the per-call lines headless). Unlike replay, there is no event stream — the
/// full snapshot is published immediately and a worker only re-publishes when
/// the UI focuses a call so the Call Detail page gets its per-call diagnostics.
fn run_jsonl_view(cfg: &Config, path: &std::path::Path, with_tui: bool) -> Result<()> {
    let base = export::jsonl::import_snapshot(path)?;
    let shared = Arc::new(Shared::new());
    *shared.snap.lock().unwrap() = base.clone();

    let shared2 = shared.clone();
    let handle = std::thread::spawn(move || {
        let mut last_pub_focus: Option<String> = Some("\u{0}init".to_string());
        loop {
            if shared2.quit.load(Ordering::Relaxed) {
                break;
            }
            if shared2.pause.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_millis(50));
                continue;
            }
            let cur_focus = shared2.focus.lock().ok().and_then(|f| f.clone());
            if cur_focus != last_pub_focus {
                publish_jsonl(&shared2, &base, cur_focus.as_deref());
                last_pub_focus = cur_focus;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    });

    if with_tui {
        run_tui(shared.clone())?;
        shared.quit.store(true, Ordering::Relaxed);
        handle
            .join()
            .map_err(|_| anyhow::anyhow!("jsonl view thread panicked"))?;
    } else {
        shared.quit.store(true, Ordering::Relaxed);
        handle
            .join()
            .map_err(|_| anyhow::anyhow!("jsonl view thread panicked"))?;
        let snap = shared.snap.lock().unwrap().clone();
        for c in &snap.calls {
            println!(
                "{}",
                serde_json::json!({"kind":"call","call_id":c.call_id,"state":c.state.label(),"pdd_ms":c.pdd_ms,"setup_ms":c.setup_ms,"warn":c.warn_count,"crit":c.critical_count})
            );
        }
    }
    final_exports(cfg, &shared)?;
    Ok(())
}

/// Rebuild the published snapshot for a jsonl view, filling in the focused
/// call's detail (streams/messages are not present in the export, so the detail
/// is limited to its diagnostics).
fn publish_jsonl(shared: &Shared, base: &store::registry::Snapshot, focus: Option<&str>) {
    let mut snap = base.clone();
    snap.focus = focus.and_then(|id| build_jsonl_focus(base, id));
    if let Ok(mut s) = shared.snap.lock() {
        *s = snap;
    }
}

fn build_jsonl_focus(
    base: &store::registry::Snapshot,
    call_id: &str,
) -> Option<store::registry::Focus> {
    let call = base.calls.iter().find(|c| c.call_id == call_id)?;
    Some(store::registry::Focus {
        call_id: call.call_id.clone(),
        state: Some(call.state),
        from_user: call.from_user.clone(),
        to_user: call.to_user.clone(),
        caller_ua: None,
        callee_ua: None,
        caller_addr: None,
        caller_ip: None,
        callee_addr: None,
        messages: Vec::new(),
        streams: Vec::new(),
        diagnostics: base
            .diagnostics
            .iter()
            .filter(|d| d.call_id == call_id)
            .cloned()
            .collect(),
        negotiated_endpoints: Vec::new(),
    })
}

// ----------------------------- query -----------------------------

fn run_query(evlog: &str, call_id: &str) -> Result<()> {
    let mut reader = EvlogReader::open(evlog)?;
    let mut found = 0usize;
    let mut streams = 0usize;
    let mut rtts = 0usize;
    while let Ok(Some(ev)) = reader.next_event() {
        match &ev {
            Event::SipMsg(e) if e.call_id == call_id => {
                found += 1;
                let label = if e.is_request {
                    e.method.clone().unwrap_or_default()
                } else {
                    e.status.map(|s| s.to_string()).unwrap_or_default()
                };
                println!(
                    "{}",
                    serde_json::json!({
                        "ts_us": e.ts_us, "msg": label,
                        "src": e.flow.src.to_string(), "dst": e.flow.dst.to_string(),
                        "cseq": e.cseq, "branch": e.branch,
                        "from_tag": e.from_tag, "to_tag": e.to_tag,
                        "raw_len": e.raw.len(),
                    })
                );
            }
            Event::StreamSnap(e) if e.call_id == call_id => {
                streams += 1;
                println!(
                    "{}",
                    serde_json::json!({
                        "ts_us": e.ts_us, "stream": format!("{:#x}", e.ssrc),
                        "codec": e.codec, "packets": e.packets, "lost": e.lost,
                        "loss_pct": e.loss_pct, "jitter_ms": e.jitter_ms, "mos": e.mos,
                    })
                );
            }
            Event::RtcpRtt(e) if e.call_id == call_id => {
                rtts += 1;
                println!(
                    "{}",
                    serde_json::json!({"ts_us": e.ts_us, "ssrc": format!("{:#x}", e.ssrc), "rtt_ms": e.rtt_ms, "oneway_ms": e.oneway_ms})
                );
            }
            Event::Diag(e) if e.call_id == call_id => {
                println!(
                    "{}",
                    serde_json::json!({"ts_us": e.ts_us, "diag": e.code, "severity": e.severity, "message": e.message})
                );
            }
            _ => {}
        }
    }
    eprintln!("query: {found} sip msgs, {streams} stream snaps, {rtts} rtt samples for {call_id}");
    Ok(())
}

// ----------------------------- export -----------------------------

fn run_export(
    cfg: &Config,
    evlog: &str,
    sqlite: Option<PathBuf>,
    jsonl: Option<PathBuf>,
    from: Option<u64>,
    to: Option<u64>,
) -> Result<()> {
    let mut reader = EvlogReader::open(evlog)?;
    let mut corr = Correlator::new(cfg, "export".into());

    let mut streams_extra = Vec::new();
    let mut diags_extra = Vec::new();
    let mut buckets_extra = Vec::new();

    while let Ok(Some(ev)) = reader.next_event() {
        let in_range = |ts: u64| {
            from.map(|f| ts >= f * 1_000_000).unwrap_or(true)
                && to.map(|t| ts <= t * 1_000_000).unwrap_or(true)
        };
        match &ev {
            Event::SipMsg(e) => {
                if in_range(e.ts_us) {
                    corr.ingest_sip(capture::replay::evt_to_sipmsg(e));
                    // Replay never writes an evlog; drop the re-emitted events
                    // immediately or `pending_events` grows with every message.
                    corr.take_events();
                }
            }
            Event::StreamSnap(e) => {
                if in_range(e.ts_us) {
                    streams_extra.push(model::media::StreamSummary {
                        call_id: Some(e.call_id.clone()),
                        ssrc: e.ssrc,
                        flow: Some(e.flow),
                        codec: e.codec.clone(),
                        payload_type: e.payload_type,
                        packets: e.packets,
                        lost: e.lost,
                        expected: e.expected,
                        loss_pct: e.loss_pct,
                        jitter_ms: e.jitter_ms,
                        first_ts_us: None,
                        last_ts_us: None,
                        rtt_min_ms: None,
                        rtt_avg_ms: None,
                        rtt_max_ms: None,
                        oneway_ms: None,
                        mos: e.mos,
                        direction: e.direction.clone(),
                        leg: None,
                        via_turn: false,
                        bytes: 0,
                        history: Vec::new(),
                    });
                }
            }
            Event::Diag(e) => {
                if in_range(e.ts_us) {
                    diags_extra.push(diagnostics::Diagnostic {
                        ts_us: e.ts_us,
                        call_id: e.call_id.clone(),
                        severity: match e.severity {
                            0 => Severity::Info,
                            1 => Severity::Warn,
                            _ => Severity::Critical,
                        },
                        code: diagnostics::code_from_str(&e.code),
                        message: e.message.clone(),
                    });
                }
            }
            Event::HealthBucket(e) => {
                buckets_extra.push((e.bucket_us, e.dim_key.clone(), e.metrics.clone()))
            }
            _ => {}
        }
    }

    let mut snap = corr.reg.snapshot_full();
    snap.streams.extend(streams_extra);
    snap.diagnostics.extend(diags_extra);
    snap.buckets.extend(buckets_extra);

    if let Some(p) = jsonl.as_ref() {
        export::jsonl::export_snapshot(p, &snap)?;
        eprintln!("exported {}", p.display());
    }
    if let Some(p) = sqlite.as_ref() {
        export::sqlite::export_snapshot(p, &snap)?;
        eprintln!("exported {}", p.display());
    }
    if jsonl.is_none() && sqlite.is_none() {
        eprintln!("nothing to do: pass --jsonl and/or --sqlite");
    }
    Ok(())
}

// ----------------------------- TUI -----------------------------

fn run_tui(shared: Arc<Shared>) -> Result<()> {
    let mut terminal =
        ratatui::Terminal::new(ratatui::backend::CrosstermBackend::new(std::io::stdout()))?;
    crossterm::terminal::enable_raw_mode()?;
    crossterm::execute!(std::io::stdout(), crossterm::terminal::EnterAlternateScreen)?;

    let mut app = ui::app::App::new(
        shared.snap.clone(),
        shared.pause.clone(),
        shared.focus.clone(),
    );
    let r = (|| -> Result<()> {
        loop {
            terminal.draw(|f| ui::render(f, &mut app))?;
            if !app.poll(Duration::from_millis(100)) {
                break;
            }
        }
        Ok(())
    })();

    crossterm::execute!(std::io::stdout(), crossterm::terminal::LeaveAlternateScreen)?;
    crossterm::terminal::disable_raw_mode()?;
    r
}
