pub mod app;
pub mod call_detail;
pub mod eventlog;
pub mod heatmap;
pub mod ipstats;
pub mod overview;
pub mod search;
pub mod streams;
pub mod theme;

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

use crate::store::registry::Snapshot;
use app::{App, Page, RecordState};
use chrono::Offset;

/// Mask a user/number for privacy: keep the first 3 and last 4 characters,
/// mask the middle (very short values keep only their first character).
pub fn mask_user(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    let n = chars.len();
    if n <= 4 {
        return chars
            .iter()
            .enumerate()
            .map(|(i, c)| if i == 0 { *c } else { '*' })
            .collect();
    }
    let back_start = n.saturating_sub(4).max(3);
    let mid = if back_start > 3 { "…" } else { "*" };
    let front: String = chars[..3].iter().collect();
    let back: String = chars[back_start..].iter().collect();
    format!("{front}{mid}{back}")
}

/// Mask an IP address: keep the first and last octets (IPv4) or hextets (IPv6).
pub fn mask_ip(ip: std::net::IpAddr) -> String {
    match ip {
        std::net::IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}.{}", o[0], '*', '*', o[3])
        }
        std::net::IpAddr::V6(v6) => {
            let s = v6.segments();
            format!("{:x}:…:{:x}", s[0], s[7])
        }
    }
}

/// Mask a socket string `ip:port` (or bare IP), preserving the port.
pub fn mask_socket(s: &str) -> String {
    if let Ok(ip) = s.parse::<std::net::IpAddr>() {
        return mask_ip(ip);
    }
    if let Ok(a) = s.parse::<std::net::SocketAddr>() {
        return format!("{}:{}", mask_ip(a.ip()), a.port());
    }
    s.to_string()
}

/// Shared top bar (3 lines): source/stats/status, global keys, page keys.
pub fn render_topbar(f: &mut Frame, area: Rect, snap: &Snapshot, app: &App) {
    let paused = app.pause.load(std::sync::atomic::Ordering::Relaxed);
    let mut spans = vec![
        Span::styled(
            format!(" sipmon [{}] ", snap.source),
            Style::default()
                .fg(theme::INFO)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(format!("{} ", duration_summary(snap))),
        Span::styled(
            format!("{:>8.0} pps ", snap.pps),
            Style::default().fg(theme::SUCCESS),
        ),
        Span::raw(format!("pkts {} ", snap.pkts_total)),
        Span::styled(
            format!("calls {} ", snap.calls_total),
            Style::default().fg(theme::WARNING),
        ),
        Span::styled(
            format!("diag {} ", snap.diagnostics.len()),
            Style::default().fg(theme::ACCENT),
        ),
    ];
    if snap.pkts_dropped > 0 {
        // Monitor-side drops (kernel/libpcap ring overflow): the loss figures
        // include packets this machine never captured.
        spans.push(Span::styled(
            format!("⚠ ifdrop {} ", snap.pkts_dropped),
            Style::default()
                .fg(theme::ERROR)
                .add_modifier(Modifier::BOLD),
        ));
    }
    if paused {
        spans.push(Span::styled(
            "⏸ PAUSED ",
            Style::default()
                .fg(theme::ERROR)
                .add_modifier(Modifier::BOLD),
        ));
    }
    if let Some(rec) = record_indicator(&app.record) {
        spans.push(rec);
    }
    if app.privacy {
        spans.push(Span::styled(
            "🔒 PRIVACY ",
            Style::default()
                .fg(theme::ACCENT)
                .add_modifier(Modifier::BOLD),
        ));
    }
    spans.push(Span::styled(
        format!(" {} ", app.status),
        Style::default().fg(theme::PRIMARY),
    ));
    let line1 = Line::from(spans);
    let line2 = Line::from(Span::styled(
        " Global: [Tab] pages [1-7] jump [/] search [Space] pause [e] export [p] privacy [x] clear [Ctrl-C/q] quit",
        Style::default().fg(theme::MUTED),
    ));
    let line3 = if app.search_editing {
        Line::from(Span::styled(
            " Search: type query — [Enter] apply [Esc] cancel",
            Style::default().fg(theme::WARNING),
        ))
    } else {
        Line::from(Span::styled(
            format!(" {}: {}", app.page.title(), page_keys(app.page)),
            Style::default().fg(theme::MUTED),
        ))
    };
    let p = Paragraph::new(vec![line1, line2, line3]).style(Style::default().fg(theme::INK));
    f.render_widget(p, area);

    // Brand watermark on the top-right corner of the top bar.
    let brand = Paragraph::new(Line::from(Span::styled(
        "by miuda.ai",
        Style::default().fg(theme::WARNING),
    )))
    .alignment(ratatui::layout::Alignment::Right);
    let brand_area = Rect {
        x: area.right().saturating_sub(13),
        y: area.y,
        width: 13.min(area.width),
        height: 1,
    };
    f.render_widget(brand, brand_area);
}

/// Live-recording indicator: a blinking ● REC <file> (<size>) shown in the top
/// bar while the pipeline writes an event log. Blinks by alternating the dot
/// glyph every 500 ms — terminal blink modifiers are too unreliable across
/// emulators. Hidden entirely when not recording.
fn record_indicator(record: &RecordState) -> Option<Span<'static>> {
    use std::sync::atomic::Ordering;
    if !record.active.load(Ordering::Relaxed) {
        return None;
    }
    let name = record
        .path
        .lock()
        .ok()
        .and_then(|p| p.clone())
        .map(|p| {
            p.file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("evlog")
                .to_string()
        })
        .unwrap_or_else(|| "evlog".to_string());
    let bytes = record.bytes.load(Ordering::Relaxed);
    let blink_on = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| (d.as_millis() / 500) % 2 == 0)
        .unwrap_or(true);
    let dot = if blink_on { "●" } else { "○" };
    Some(Span::styled(
        format!(" {dot} REC {name} ({}) ", fmt_bytes(bytes)),
        Style::default()
            .fg(theme::ERROR)
            .add_modifier(Modifier::BOLD),
    ))
}

/// Page-specific key hints shown on the top bar's third line.
fn page_keys(page: Page) -> &'static str {
    match page {
        Page::Overview => "[↑↓/PgUp/PgDn] select [Enter] open call detail",
        Page::Search => "[↑↓/PgUp/PgDn] select [Enter] open call detail [/] new query",
        Page::CallDetail => "[↑↓] msg  [l] link b-leg  [L] unlink  [PgUp/PgDn] raw  [←/Esc] back",
        Page::Heatmap => "[↑↓/PgUp/PgDn] scroll [s] sort [w] loss window",
        Page::Streams => "[↑↓/PgUp/PgDn] select stream",
        Page::EventLog => "[↑↓/PgUp/PgDn] scroll",
        Page::IpStats => "[↑↓/PgUp/PgDn] select [Enter] calls [s] sort [w] window [c] loss-only",
    }
}

pub fn render(f: &mut Frame, app: &mut App) {
    let snap = app.snapshot();
    let area = f.area();
    // Reserve the last row for the 1-7 page tab bar.
    let body = Rect {
        height: area.height.saturating_sub(1),
        ..area
    };
    use app::Page::*;
    match app.page {
        Overview => overview::render(f, body, &snap, app),
        Search => search::render(f, body, &snap, app),
        CallDetail => call_detail::render(f, body, &snap, app),
        Heatmap => heatmap::render(f, body, &snap, app),
        Streams => streams::render(f, body, &snap, app),
        EventLog => eventlog::render(f, body, &snap, app),
        IpStats => ipstats::render(f, body, &snap, app),
    }
    render_page_tabs(
        f,
        Rect {
            y: body.height,
            height: 1,
            ..area
        },
        app,
    );
}

/// Bottom page tab bar: `1 Overview … 7 IP Stats`, with the active page
/// highlighted. `Tab`/`Shift-Tab` walk across them continuously.
fn render_page_tabs(f: &mut Frame, area: Rect, app: &App) {
    const TABS: [(u8, &str); 7] = [
        (1, "Overview"),
        (2, "Search"),
        (3, "Detail"),
        (4, "Heatmap"),
        (5, "Streams"),
        (6, "EventLog"),
        (7, "IP Stats"),
    ];
    let active = app.page.index();
    let spans: Vec<Span> = TABS
        .iter()
        .enumerate()
        .flat_map(|(i, (n, name))| {
            let sep = if i == 0 {
                Vec::new()
            } else {
                vec![Span::raw("  ")]
            };
            let selected = i == active;
            let style = if selected {
                Style::default()
                    .fg(theme::INK)
                    .bg(theme::ACCENT)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(theme::MUTED)
            };
            sep.into_iter()
                .chain(std::iter::once(Span::styled(format!("{n} {name}"), style)))
                .collect::<Vec<_>>()
        })
        .collect();
    let p = Paragraph::new(Line::from(spans));
    f.render_widget(p, area);
}

/// Format a capture timestamp (us) as HH:MM:SS in the current machine's local
/// timezone. Callers that know the recording machine's UTC offset should use
/// `fmt_time_tz` instead so a replay shows the wall-clock as it was recorded.
pub fn fmt_time(ts_us: u64) -> String {
    fmt_time_tz(ts_us, None)
}

/// Format a capture timestamp (us) as HH:MM:SS. `tz_secs` is the recording
/// machine's UTC offset in seconds (positive east of UTC); `None` falls back to
/// the current machine's local timezone.
pub fn fmt_time_tz(ts_us: u64, tz_secs: Option<i32>) -> String {
    let Some(utc) = chrono::DateTime::from_timestamp((ts_us / 1_000_000) as i64, 0) else {
        return "??:??:??".into();
    };
    let offset = match tz_secs {
        Some(s) => s,
        None => chrono::Local::now().offset().fix().local_minus_utc(),
    };
    let local = utc + chrono::Duration::seconds(offset as i64);
    local.format("%H:%M:%S").to_string()
}

/// Merged flow-time cell: local wall-clock plus the already-recorded duration,
/// e.g. `12:34:56(+1m05s)`. `base_us` is the recording/session start, so the
/// delta is how far into the recording this message/call happened.
pub fn fmt_time_delta(ts_us: u64, base_us: u64, tz_secs: Option<i32>) -> String {
    format!(
        "{}(+{})",
        fmt_time_tz(ts_us, tz_secs),
        fmt_elapsed(ts_us.saturating_sub(base_us))
    )
}

/// Compact elapsed duration, e.g. `0.12s` / `45.6s` / `1m05s` / `1h05m`.
pub fn fmt_elapsed(us: u64) -> String {
    let ms = us / 1000;
    if ms < 1000 {
        format!("{:.2}s", ms as f64 / 1000.0)
    } else if ms < 60_000 {
        format!("{:.1}s", ms as f64 / 1000.0)
    } else if ms < 3_600_000 {
        format!("{}m{:02}s", ms / 60_000, (ms % 60_000) / 1000)
    } else {
        format!("{}h{:02}m", ms / 3_600_000, (ms % 3_600_000) / 60_000)
    }
}

/// Format ms with one decimal, or "-".
pub fn fmt_ms(v: Option<f64>) -> String {
    match v {
        Some(x) => format!("{x:.1}"),
        None => "-".into(),
    }
}

/// Format ms as seconds with two decimals, e.g. 230 → "0.23s".
pub fn fmt_secs(ms: Option<u64>) -> String {
    match ms {
        None => "-".into(),
        Some(ms) => format!("{}.{:02}s", ms / 1000, (ms % 1000) / 10),
    }
}

pub fn fmt_dur(ms: Option<u64>) -> String {
    match ms {
        None => "-".into(),
        Some(ms) if ms < 60_000 => format!("{}.{:01}s", ms / 1000, (ms % 1000) / 100),
        Some(ms) => format!("{}m{}s", ms / 60_000, (ms % 60_000) / 1000),
    }
}

/// Format a byte count with an explicit KB/MB unit.
pub fn fmt_bytes(n: u64) -> String {
    if n >= 1_048_576 {
        format!("{:.1} MB", n as f64 / 1_048_576.0)
    } else if n >= 1024 {
        format!("{:.1} KB", n as f64 / 1024.0)
    } else {
        format!("{n} B")
    }
}

/// Format a byte rate with an explicit KB/s / MB/s unit.
pub fn fmt_rate(bytes_per_sec: f64) -> String {
    if bytes_per_sec >= 1_048_576.0 {
        format!("{:.2} MB/s", bytes_per_sec / 1_048_576.0)
    } else if bytes_per_sec >= 1024.0 {
        format!("{:.1} KB/s", bytes_per_sec / 1024.0)
    } else {
        format!("{bytes_per_sec:.0} B/s")
    }
}

pub fn duration_summary(snap: &Snapshot) -> String {
    match snap.elapsed_us {
        Some(us) => fmt_dur(Some(us / 1000)),
        None => "-".into(),
    }
}
