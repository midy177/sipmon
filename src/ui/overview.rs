use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table};

use crate::model::sip::HangupBy;
use crate::store::registry::Snapshot;
use crate::ui::app::App;
use crate::ui::{fmt_dur, fmt_ms, fmt_secs, fmt_time_delta, mask_user, theme};

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
            Style::default().fg(theme::INFO),
        ),
        Span::raw("│"),
        Span::styled(
            format!(" ASR {:.1}% ", snap.asr),
            Style::default().fg(if snap.asr < 80.0 {
                theme::ERROR
            } else {
                theme::SUCCESS
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
            Style::default().fg(theme::MUTED),
        ),
    ]))
    .block(Block::default().borders(Borders::ALL).title("Summary"));
    f.render_widget(cards, chunks[1]);

    // Call table. The SrcIP column was dropped to give the (wider) local-time +
    // recorded-duration Time column room.
    let header = [
        "Time",
        "From",
        "To",
        "State",
        "PDD",
        "Setup",
        "Ring",
        "Dur",
        "EarlyMedia",
        "MOS",
        "RTP",
        "Diag",
        "End",
        "Call-ID",
    ];
    // Keep the highlight anchored to the same call as new calls arrive, then
    // apply the state filter (`f` cycles all/pending/success/failed/canceled).
    app.anchor_overview_selection(snap);
    let privacy = app.privacy;
    let visible: Vec<&crate::store::registry::CallSummary> = snap
        .calls
        .iter()
        .filter(|c| app.filter.matches(c.state))
        .collect();
    let rows = visible.iter().map(|c| {
        let diag_cell = if c.critical_count > 0 {
            Cell::from(format!("{}C/{}W", c.critical_count, c.warn_count)).style(
                Style::default()
                    .fg(theme::ERROR)
                    .add_modifier(Modifier::BOLD),
            )
        } else if c.warn_count > 0 {
            Cell::from(format!("{}", c.warn_count)).style(Style::default().fg(theme::WARNING))
        } else {
            Cell::from("·").style(Style::default().fg(theme::MUTED))
        };
        let turn_mark = if c.via_turn { " [T]" } else { "" };
        let from = match c.from_user.as_deref() {
            Some(v) if privacy => mask_user(v),
            Some(v) => v.to_string(),
            None => String::new(),
        };
        let to = match c.to_user.as_deref() {
            Some(v) if privacy => mask_user(v),
            Some(v) => v.to_string(),
            None => String::new(),
        };
        let em_cell = if c.early_media {
            Cell::from("✓").style(
                Style::default()
                    .fg(theme::ACCENT)
                    .add_modifier(Modifier::BOLD),
            )
        } else {
            Cell::from("·").style(Style::default().fg(theme::MUTED))
        };
        Row::new(vec![
            Cell::from(
                c.invite_ts
                    .map(|t| fmt_time_delta(t, snap.start_us.unwrap_or(t), snap.tz_offset_secs))
                    .unwrap_or_else(|| "-".into()),
            ),
            Cell::from(format!("{from}{turn_mark}")),
            Cell::from(to),
            Cell::from(c.state.label()).style(state_color(c.state)),
            Cell::from(fmt_secs(c.pdd_ms.map(|m| m as u64))),
            Cell::from(fmt_secs(c.setup_ms.map(|m| m as u64))),
            Cell::from(fmt_secs(c.ring_ms.map(|m| m as u64))).style(ring_style(c.ring_code)),
            Cell::from(fmt_dur(c.duration_ms)),
            em_cell,
            Cell::from(fmt_ms(c.best_mos)),
            Cell::from(c.pkts_rtp.to_string()),
            diag_cell,
            Cell::from(fmt_end(c.hangup_by, c.hangup_code)).style(end_style(c.hangup_by)),
            Cell::from(c.call_id.clone()).style(Style::default().fg(theme::MUTED)),
        ])
    });

    let table = Table::new(
        rows,
        [
            Constraint::Length(17),
            Constraint::Length(16),
            Constraint::Length(14),
            Constraint::Length(10),
            Constraint::Length(7),
            Constraint::Length(7),
            Constraint::Length(10),
            Constraint::Length(9),
            Constraint::Length(10),
            Constraint::Length(5),
            Constraint::Length(7),
            Constraint::Length(8),
            Constraint::Length(8),
            Constraint::Min(10),
        ],
    )
    .header(
        Row::new(header.iter().map(|h| Cell::from(*h))).style(Style::default().fg(theme::WARNING)),
    )
    .block(Block::default().borders(Borders::ALL).title(format!(
        "Calls ({}/{}) — Enter=detail, f=filter:{}  [PDD=INV→try/ring, Setup=INV→200, Ring=dur, EarlyMedia=183+media]",
        visible.len(),
        snap.calls.len(),
        app.filter.label()
    )))
    .row_highlight_style(theme::selected());
    f.render_stateful_widget(table, chunks[2], &mut app.table_state);
}

pub fn state_color(state: crate::model::sip::CallState) -> Style {
    use crate::model::sip::CallState::*;
    match state {
        Dialing | Ringing => Style::default().fg(theme::INFO),
        Active => Style::default().fg(theme::SUCCESS),
        Completed => Style::default().fg(theme::PRIMARY),
        Failed => Style::default().fg(theme::ERROR),
        Canceled => Style::default().fg(theme::ACCENT),
    }
}

/// Ring column: ringing duration (provisional code is folded into the EM
/// column / color, not shown as text).
fn ring_style(code: Option<u16>) -> Style {
    // 183 = early media, worth highlighting.
    match code {
        Some(183) => Style::default()
            .fg(theme::ACCENT)
            .add_modifier(Modifier::BOLD),
        _ => Style::default(),
    }
}

/// End column: who initiated the hangup (caller/callee BYE, cancel, reject).
fn fmt_end(by: Option<HangupBy>, code: Option<u32>) -> String {
    match (by, code) {
        (Some(b), Some(code)) if b == HangupBy::Reject => format!("{}·{code}", b.label()),
        (Some(b), _) => b.label().to_string(),
        (None, Some(code)) => format!("{code}"),
        (None, None) => "-".into(),
    }
}

fn end_style(by: Option<HangupBy>) -> Style {
    match by {
        Some(HangupBy::Reject) | Some(HangupBy::Cancel) => Style::default().fg(theme::ERROR),
        Some(HangupBy::Caller) | Some(HangupBy::Callee) => Style::default().fg(theme::MUTED),
        None => Style::default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use std::sync::atomic::AtomicBool;
    use std::sync::{Arc, Mutex};

    use crate::store::registry::CallSummary;
    use crate::ui::app::{App, Page, RecordState};

    fn render_overview(privacy: bool) -> String {
        let snap = Arc::new(Mutex::new(Snapshot {
            calls: vec![CallSummary {
                call_id: "c1".into(),
                from_user: Some("13812345678".into()),
                to_user: Some("bob".into()),
                caller_ip: Some("10.10.0.8".parse().unwrap()),
                state: crate::model::sip::CallState::Active,
                outcome: crate::model::sip::Outcome::Answered,
                invite_ts: Some(1_000_000),
                duration_ms: Some(5_000),
                pdd_ms: Some(100),
                setup_ms: Some(200),
                ring_ms: Some(50),
                ring_code: Some(180),
                early_media: true,
                hangup_by: None,
                hangup_code: None,
                pkts_sip: 4,
                pkts_rtp: 100,
                best_mos: Some(4.2),
                warn_count: 0,
                critical_count: 0,
                stream_count: 1,
                via_turn: false,
                ips: vec!["10.10.0.8".parse().unwrap()],
            }],
            ..Snapshot::default()
        }));
        let mut app = App::new(
            snap,
            Arc::new(AtomicBool::new(false)),
            Arc::new(Mutex::new(Some("c1".to_string()))),
            Arc::new(AtomicBool::new(false)),
            RecordState::default(),
        );
        app.privacy = privacy;
        app.page = Page::Overview;
        let mut terminal = Terminal::new(TestBackend::new(150, 44)).unwrap();
        terminal.draw(|f| crate::ui::render(f, &mut app)).unwrap();
        let buf = terminal.backend().buffer().clone();
        (0..buf.area.height)
            .map(|y| {
                (0..buf.area.width)
                    .map(|x| buf[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn overview_merges_local_time_and_recorded_duration() {
        let text = render_overview(false);
        assert!(
            !text.contains("SrcIP"),
            "SrcIP column must be removed to make room for the time display"
        );
        // The Time cell carries the local wall-clock plus the recorded delta.
        assert!(
            text.contains("(+"),
            "time column must include the recorded duration: {text}"
        );
    }

    #[test]
    fn overview_masks_users_in_privacy_mode() {
        let text = render_overview(true);
        assert!(
            !text.contains("13812345678"),
            "caller number leaked in privacy"
        );
        assert!(text.contains("138…5678"), "masked caller number missing");
    }
}
