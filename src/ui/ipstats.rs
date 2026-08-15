//! Per-IP network-stats page: time-windowed loss table + heatmap + drill-down.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::Span;
use ratatui::widgets::{Block, Borders, Cell, Row, Table};

use std::net::IpAddr;

use crate::store::ipstats::{IpStats, WINDOWS};
use crate::store::registry::{CallSummary, Snapshot};
use crate::ui::app::{App, IpSort};
use crate::ui::{fmt_bytes, fmt_time, theme};

/// The IP rows of the page, sorted per the current sort mode.
pub fn sorted_rows(snap: &Snapshot, sort: IpSort) -> Vec<&IpStats> {
    let mut v: Vec<&IpStats> = snap.ip_stats.iter().collect();
    match sort {
        IpSort::Newest => v.sort_by(|a, b| {
            b.last_seen_us
                .unwrap_or(0)
                .cmp(&a.last_seen_us.unwrap_or(0))
        }),
        IpSort::MaxLoss => v.sort_by(|a, b| {
            b.loss_pct(0)
                .unwrap_or(0.0)
                .partial_cmp(&a.loss_pct(0).unwrap_or(0.0))
                .unwrap_or(std::cmp::Ordering::Equal)
        }),
        IpSort::MinLoss => v.sort_by(|a, b| {
            a.loss_pct(0)
                .unwrap_or(0.0)
                .partial_cmp(&b.loss_pct(0).unwrap_or(0.0))
                .unwrap_or(std::cmp::Ordering::Equal)
        }),
    }
    v
}

/// Calls involving an IP (drill-down list).
pub fn calls_for_ip(snap: &Snapshot, ip: Option<IpAddr>) -> Vec<&CallSummary> {
    let Some(ip) = ip else { return Vec::new() };
    snap.calls.iter().filter(|c| c.ips.contains(&ip)).collect()
}

pub fn render(f: &mut Frame, area: Rect, snap: &Snapshot, app: &mut App) {
    let chunks = Layout::vertical([
        Constraint::Length(3),
        Constraint::Percentage(58),
        Constraint::Min(0),
    ])
    .split(area);
    super::render_topbar(f, chunks[0], snap, app);
    if app.ip_drill.is_some() {
        render_drill(f, chunks[1], snap, app);
    } else {
        render_table(f, chunks[1], snap, app);
    }
    render_heatmap(f, chunks[2], snap, app);
}

fn loss_cell(pct: Option<f64>) -> Cell<'static> {
    match pct {
        None => Cell::from("-").style(Style::default().fg(theme::MUTED)),
        Some(p) => {
            let style = if p >= 2.0 {
                Style::default().fg(theme::ERROR).add_modifier(Modifier::BOLD)
            } else if p >= 0.5 {
                Style::default().fg(theme::WARNING)
            } else {
                Style::default().fg(theme::SUCCESS)
            };
            Cell::from(format!("{p:.1}")).style(style)
        }
    }
}

fn render_table(f: &mut Frame, area: Rect, snap: &Snapshot, app: &mut App) {
    let rows = sorted_rows(snap, app.ip_sort);
    let data_rows = rows.iter().map(|s| {
        let mut cells = vec![
            Cell::from(s.ip.to_string()),
            Cell::from(s.active_calls.to_string()).style(Style::default().fg(theme::ACCENT)),
        ];
        for (w, _) in &WINDOWS {
            cells.push(loss_cell(s.loss_pct(*w)));
        }
        cells.push(Cell::from(fmt_bytes(s.bytes_total)));
        cells.push(Cell::from(s.pkts_total.to_string()));
        Row::new(cells)
    });

    let widths = vec![
        Constraint::Length(16),
        Constraint::Length(4),
        Constraint::Length(5),
        Constraint::Length(5),
        Constraint::Length(5),
        Constraint::Length(5),
        Constraint::Length(5),
        Constraint::Length(5),
        Constraint::Length(5),
        Constraint::Length(5),
        Constraint::Length(11),
        Constraint::Length(9),
    ];
    let mut header_cells: Vec<Cell> = vec!["IP".into(), "Act".into()];
    header_cells.extend(WINDOWS.iter().map(|(_, l)| Cell::from(*l)));
    header_cells.push(Cell::from("Bytes"));
    header_cells.push(Cell::from("Pkts"));

    let table = Table::new(data_rows, widths)
        .header(
            Row::new(header_cells).style(Style::default().fg(theme::WARNING).add_modifier(Modifier::BOLD)),
        )
        .block(Block::default().borders(Borders::ALL).title(format!(
            "IP network stats ({} IPs) — Enter=call list, s=sort:{}",
            rows.len(),
            app.ip_sort.label()
        )))
        .row_highlight_style(Style::default().bg(theme::MUTED));
    f.render_stateful_widget(table, area, &mut app.ip_table_state);
}

fn render_drill(f: &mut Frame, area: Rect, snap: &Snapshot, app: &mut App) {
    let calls = calls_for_ip(snap, app.ip_drill);
    let ip = app.ip_drill.map(|i| i.to_string()).unwrap_or_default();
    let rows = calls.iter().map(|c| {
        let hangup = match (c.hangup_by, c.hangup_code) {
            (Some(b), Some(code)) => format!("{}·{code}", b.label()),
            (Some(b), None) => b.label().to_string(),
            (None, Some(code)) => code.to_string(),
            (None, None) => "-".into(),
        };
        Row::new(vec![
            Cell::from(c.invite_ts.map(fmt_time).unwrap_or_else(|| "-".into())),
            Cell::from(c.from_user.clone().unwrap_or_default()),
            Cell::from(c.to_user.clone().unwrap_or_default()),
            Cell::from(c.state.label()),
            Cell::from(c.pkts_rtp.to_string()),
            Cell::from(crate::ui::fmt_ms(c.best_mos)),
            Cell::from(hangup),
            Cell::from(c.call_id.clone()).style(Style::default().fg(theme::MUTED)),
        ])
    });
    let table = Table::new(
        rows,
        [
            Constraint::Length(8),
            Constraint::Length(14),
            Constraint::Length(12),
            Constraint::Length(10),
            Constraint::Length(8),
            Constraint::Length(5),
            Constraint::Length(8),
            Constraint::Min(10),
        ],
    )
    .header(Row::new(
        ["Time", "From", "To", "State", "RTP pkts", "MOS", "End", "Call-ID"]
            .iter()
            .map(|h| Cell::from(*h)),
    ))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!("Calls for {ip} ({} — Enter=detail, Esc=back)", calls.len())),
    )
    .row_highlight_style(Style::default().bg(theme::MUTED));
    f.render_stateful_widget(table, area, &mut app.ip_drill_state);
}

/// Bottom heatmap: rows = IPs, columns = time buckets, color = loss%.
fn render_heatmap(f: &mut Frame, area: Rect, snap: &Snapshot, app: &mut App) {
    let window = app.ip_window_secs;
    let col_secs = if window <= 600 {
        window.div_ceil(60).max(1)
    } else {
        60
    };
    let col_us = col_secs * 1_000_000;
    let cols = 60usize;
    let now = snap
        .ip_stats
        .iter()
        .filter_map(|s| s.last_seen_us)
        .max()
        .unwrap_or(0);
    let axis_start = now.saturating_sub(col_us * cols as u64);

    let rows = sorted_rows(snap, app.ip_sort);
    let height = (area.height as usize).saturating_sub(2);
    let visible: Vec<&IpStats> = rows.into_iter().take(height).collect();

    // Header: time labels at 0/25/50/75/100%.
    let mut head_cells = vec![Cell::from("IP"), Cell::from("Loss% ▁▂▃▄▅▆▇█")];
    head_cells.push(Cell::from(format!(
        "{}..{}",
        fmt_time(axis_start),
        fmt_time(axis_start + col_us * cols as u64)
    )));
    let head = Row::new(head_cells);

    let body = visible.iter().map(|s| {
        let mut cells = vec![
            Cell::from(s.ip.to_string()),
            Cell::from(format!("{:.1}", s.loss_pct(0).unwrap_or(0.0))),
        ];
        let cols_series = s.heatmap_columns(window, 60);
        let mut grid = vec![None; cols];
        for (ts, pct) in cols_series {
            if ts <= axis_start {
                continue;
            }
            let idx = ((ts.saturating_sub(axis_start)) / col_us) as usize;
            if idx < cols {
                grid[idx] = Some(pct);
            }
        }
        for pct in grid {
            cells.push(heat_cell(pct));
        }
        Row::new(cells)
    });

    let widths = std::iter::once(Constraint::Length(16))
        .chain(std::iter::once(Constraint::Length(16)))
        .chain((0..cols).map(|_| Constraint::Length(1)))
        .collect::<Vec<_>>();

    let table = Table::new(body, widths).header(head).block(
        Block::default().borders(Borders::ALL).title(format!(
            "Loss% heatmap (last {}s, w=switch) — s=sort:{}",
            app.ip_window_secs,
            app.ip_sort.label()
        )),
    );
    f.render_widget(table, area);
}

fn heat_cell(pct: Option<f64>) -> Cell<'static> {
    match pct {
        None => Cell::from("·").style(Style::default().fg(theme::MUTED)),
        Some(p) if p <= 0.0 => Cell::from(Span::styled(" ", Style::default())),
        Some(p) => {
            let (ch, color) = if p < 1.0 {
                ("▁", theme::SUCCESS)
            } else if p < 2.0 {
                ("▃", theme::WARNING)
            } else if p < 5.0 {
                ("▅", theme::WARNING)
            } else if p < 10.0 {
                ("▇", theme::ERROR)
            } else {
                ("█", theme::ERROR)
            };
            Cell::from(Span::styled(ch, Style::default().fg(color)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    use std::sync::atomic::AtomicBool;
    use std::sync::{Arc, Mutex};

    use crate::ui::app::{App, Page};

    fn sample_snapshot() -> Snapshot {
        let mut st = crate::store::ipstats::IpStatsStore::new();
        let ts = 1_800_000_000_000_000u64;
        for i in 0..30u64 {
            st.observe_packet(
                "10.10.0.8".parse().unwrap(),
                ts + i * 1_000_000,
                160,
            );
            st.observe_packet(
                "10.20.0.8".parse().unwrap(),
                ts + i * 1_000_000,
                160,
            );
            if i % 10 == 0 {
                st.observe_lost("10.20.0.8".parse().unwrap(), ts + i * 1_000_000, 1);
            }
        }
        st.add_active("10.10.0.8".parse().unwrap(), 2);
        st.add_active("10.20.0.8".parse().unwrap(), 1);
        let mut snap = Snapshot {
            ip_stats: st.snapshot(),
            ..Snapshot::default()
        };
        snap.calls.push(crate::store::registry::CallSummary {
            call_id: "c1".into(),
            from_user: Some("alice".into()),
            to_user: Some("bob".into()),
            state: crate::model::sip::CallState::Active,
            outcome: crate::model::sip::Outcome::Answered,
            invite_ts: Some(ts),
            duration_ms: Some(10_000),
            pdd_ms: Some(100),
            setup_ms: Some(200),
            ring_ms: Some(100),
            ring_code: Some(180),
            hangup_by: None,
            hangup_code: None,
            pkts_sip: 4,
            pkts_rtp: 500,
            best_mos: Some(4.3),
            warn_count: 0,
            critical_count: 0,
            stream_count: 1,
            via_turn: false,
            ips: vec!["10.10.0.8".parse().unwrap(), "10.20.0.8".parse().unwrap()],
        });
        snap
    }

    #[test]
    fn ip_page_renders_without_panic() {
        let snap = Arc::new(Mutex::new(sample_snapshot()));
        let mut app = App::new(
            snap,
            Arc::new(AtomicBool::new(false)),
            Arc::new(Mutex::new(None)),
            Arc::new(AtomicBool::new(false)),
        );
        app.page = Page::IpStats;
        let mut terminal = Terminal::new(TestBackend::new(150, 44)).unwrap();
        terminal.draw(|f| crate::ui::render(f, &mut app)).unwrap();
        let buf = terminal.backend().buffer().clone();
        // Both IPs present in the table; all 8 window headers present.
        let text: String = (0..buf.area.height)
            .map(|y| {
                (0..buf.area.width)
                    .map(|x| buf[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n");
        assert!(text.contains("10.10.0.8"));
        assert!(text.contains("10.20.0.8"));
        for (_, label) in crate::store::ipstats::WINDOWS {
            assert!(text.contains(label), "window header {label} missing");
        }
    }

    #[test]
    fn ip_drill_renders_calls() {
        let snap = Arc::new(Mutex::new(sample_snapshot()));
        let mut app = App::new(
            snap,
            Arc::new(AtomicBool::new(false)),
            Arc::new(Mutex::new(None)),
            Arc::new(AtomicBool::new(false)),
        );
        app.page = Page::IpStats;
        app.ip_drill = Some("10.20.0.8".parse().unwrap());
        let mut terminal = Terminal::new(TestBackend::new(150, 44)).unwrap();
        terminal.draw(|f| crate::ui::render(f, &mut app)).unwrap();
        let buf = terminal.backend().buffer().clone();
        let text: String = (0..buf.area.height)
            .map(|y| {
                (0..buf.area.width)
                    .map(|x| buf[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n");
        assert!(text.contains("c1"), "drill-down must list the call");
    }
}
