use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table};

use crate::store::registry::Snapshot;
use crate::ui::app::App;
use crate::ui::{fmt_dur, fmt_ms, fmt_time, fmt_u32};

pub fn render(f: &mut Frame, area: Rect, snap: &Snapshot, app: &mut App) {
    let chunks = Layout::vertical([
        Constraint::Length(3),
        Constraint::Length(4),
        Constraint::Min(0),
    ])
    .split(area);

    super::render_topbar(f, chunks[0], snap, app);

    // Summary cards.
    let cards = Paragraph::new(Line::from(vec![
        Span::styled(
            format!(
                " calls {} | active {} | done {} | fail {} ",
                snap.calls_total, snap.active, snap.completed, snap.failed
            ),
            Style::default().fg(Color::Cyan),
        ),
        Span::raw("│"),
        Span::styled(
            format!(" ASR {:.1}% ", snap.asr),
            Style::default().fg(if snap.asr < 80.0 {
                Color::Red
            } else {
                Color::Green
            }),
        ),
        Span::raw("│"),
        Span::styled(
            format!(
                " PDD {}ms | setup {}ms | jitter {}ms | loss {:.1}% | RTT {}ms | MOS {} ",
                fmt_ms(Some(snap.avg_pdd_ms)),
                fmt_ms(Some(snap.avg_setup_ms)),
                fmt_ms(Some(snap.avg_jitter_ms)),
                snap.avg_loss_pct,
                fmt_ms(Some(snap.avg_rtt_ms)),
                fmt_ms(Some(snap.avg_mos)),
            ),
            Style::default().fg(Color::Gray),
        ),
    ]))
    .block(Block::default().borders(Borders::ALL).title("Summary"));
    f.render_widget(cards, chunks[1]);

    // Call table.
    let header = [
        "Time", "From", "To", "State", "PDD", "Setup", "Dur", "MOS", "RTP", "Diag", "Call-ID",
    ];
    let rows = snap.calls.iter().map(|c| {
        let diag_cell = if c.critical_count > 0 {
            Cell::from(format!("{}C/{}W", c.critical_count, c.warn_count))
                .style(Style::default().fg(Color::Red).add_modifier(Modifier::BOLD))
        } else if c.warn_count > 0 {
            Cell::from(format!("{}", c.warn_count)).style(Style::default().fg(Color::Yellow))
        } else {
            Cell::from("·").style(Style::default().fg(Color::DarkGray))
        };
        let turn_mark = if c.via_turn { " [T]" } else { "" };
        Row::new(vec![
            Cell::from(c.invite_ts.map(fmt_time).unwrap_or_else(|| "-".into())),
            Cell::from(format!(
                "{}{}",
                c.from_user.clone().unwrap_or_default(),
                turn_mark
            )),
            Cell::from(c.to_user.clone().unwrap_or_default()),
            Cell::from(c.state.label()).style(state_color(c.state)),
            Cell::from(fmt_u32(c.pdd_ms)),
            Cell::from(fmt_u32(c.setup_ms)),
            Cell::from(fmt_dur(c.duration_ms)),
            Cell::from(fmt_ms(c.best_mos)),
            Cell::from(c.pkts_rtp.to_string()),
            diag_cell,
            Cell::from(c.call_id.clone()).style(Style::default().fg(Color::DarkGray)),
        ])
    });

    let table = Table::new(
        rows,
        [
            Constraint::Length(8),
            Constraint::Length(14),
            Constraint::Length(12),
            Constraint::Length(10),
            Constraint::Length(6),
            Constraint::Length(7),
            Constraint::Length(8),
            Constraint::Length(5),
            Constraint::Length(7),
            Constraint::Length(7),
            Constraint::Min(10),
        ],
    )
    .header(
        Row::new(header.iter().map(|h| Cell::from(*h))).style(Style::default().fg(Color::Yellow)),
    )
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!("Calls ({}) — Enter=detail", snap.calls.len())),
    )
    .row_highlight_style(Style::default().bg(Color::DarkGray));
    f.render_stateful_widget(table, chunks[2], &mut app.table_state);
}

pub fn state_color(state: crate::model::sip::CallState) -> Style {
    use crate::model::sip::CallState::*;
    match state {
        Dialing | Ringing => Style::default().fg(Color::Cyan),
        Active => Style::default().fg(Color::Green),
        Completed => Style::default().fg(Color::Blue),
        Failed => Style::default().fg(Color::Red),
        Canceled => Style::default().fg(Color::Magenta),
    }
}
