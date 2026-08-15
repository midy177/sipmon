pub mod app;
pub mod call_detail;
pub mod eventlog;
pub mod heatmap;
pub mod overview;
pub mod search;
pub mod streams;

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
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
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(format!("{} ", duration_summary(snap))),
        Span::styled(
            format!("{:>8.0} pps ", snap.pps),
            Style::default().fg(Color::Green),
        ),
        Span::raw(format!("pkts {} ", snap.pkts_total)),
        Span::styled(
            format!("calls {} ", snap.calls_total),
            Style::default().fg(Color::Yellow),
        ),
        Span::styled(
            format!("diag {} ", snap.diagnostics.len()),
            Style::default().fg(Color::Magenta),
        ),
        if paused {
            Span::styled(
                "⏸ PAUSED ",
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            )
        } else {
            Span::raw("")
        },
        Span::styled(
            format!(" {} ", app.status),
            Style::default().fg(Color::Blue),
        ),
    ]);
    let line2 = Line::from(Span::styled(
        " Global: [Tab/Shift-Tab] pages [1-6] jump [/] search [Space] pause [e] export [b] bucket [Ctrl-C/q] quit",
        Style::default().fg(Color::DarkGray),
    ));
    let line3 = if app.search_editing {
        Line::from(Span::styled(
            " Search: type query — [Enter] apply [Esc] cancel",
            Style::default().fg(Color::Yellow),
        ))
    } else {
        Line::from(Span::styled(
            format!(" {}: {}", app.page.title(), page_keys(app.page)),
            Style::default().fg(Color::DarkGray),
        ))
    };
    let p = Paragraph::new(vec![line1, line2, line3]).style(Style::default());
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

pub fn duration_summary(snap: &Snapshot) -> String {
    match snap.elapsed_us {
        Some(us) => fmt_dur(Some(us / 1000)),
        None => "-".into(),
    }
}
