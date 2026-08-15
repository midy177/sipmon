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
use app::{App, Page};

/// Shared top bar (3 lines): source/stats/status, global keys, page keys.
pub fn render_topbar(f: &mut Frame, area: Rect, snap: &Snapshot, app: &App) {
    let paused = app.pause.load(std::sync::atomic::Ordering::Relaxed);
    let line1 = Line::from(vec![
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
        if paused {
            Span::styled(
                "⏸ PAUSED ",
                Style::default()
                    .fg(theme::ERROR)
                    .add_modifier(Modifier::BOLD),
            )
        } else {
            Span::raw("")
        },
        Span::styled(
            format!(" {} ", app.status),
            Style::default().fg(theme::PRIMARY),
        ),
    ]);
    let line2 = Line::from(Span::styled(
        " Global: [Tab/Shift-Tab] pages [1-7] jump [/] search [Space] pause [e] export [b] bucket [x] clear [Ctrl-C/q] quit",
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
}

/// Page-specific key hints shown on the top bar's third line.
fn page_keys(page: Page) -> &'static str {
    match page {
        Page::Overview => "[↑↓] select [Enter] open call detail",
        Page::Search => "[↑↓] select [Enter] open call detail [/] new query",
        Page::CallDetail => {
            "[↑↓] select msg [Tab] right pane [PgUp/PgDn] scroll raw [←/Esc] back to list"
        }
        Page::Heatmap => "[b] bucket granularity",
        Page::Streams => "[↑↓] select stream",
        Page::EventLog => "[↑↓] scroll",
        Page::IpStats => "[↑↓] select [Enter] calls [s] sort [w] heatmap window",
    }
}

pub fn render(f: &mut Frame, app: &mut App) {
    let snap = app.snapshot();
    use app::Page::*;
    match app.page {
        Overview => overview::render(f, f.area(), &snap, app),
        Search => search::render(f, f.area(), &snap, app),
        CallDetail => call_detail::render(f, f.area(), &snap, app),
        Heatmap => heatmap::render(f, f.area(), &snap, app),
        Streams => streams::render(f, f.area(), &snap, app),
        EventLog => eventlog::render(f, f.area(), &snap, app),
        IpStats => ipstats::render(f, f.area(), &snap, app),
    }
}

/// Format a capture timestamp (us) as HH:MM:SS.
pub fn fmt_time(ts_us: u64) -> String {
    chrono::DateTime::from_timestamp((ts_us / 1_000_000) as i64, 0)
        .map(|d| d.format("%H:%M:%S").to_string())
        .unwrap_or_else(|| "??:??:??".into())
}

/// Format ms with one decimal, or "-".
pub fn fmt_ms(v: Option<f64>) -> String {
    match v {
        Some(x) => format!("{x:.1}"),
        None => "-".into(),
    }
}

pub fn fmt_u32(v: Option<u32>) -> String {
    v.map(|x| x.to_string()).unwrap_or_else(|| "-".into())
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
