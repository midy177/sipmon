use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::Style;
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table};

use crate::store::registry::Snapshot;
use crate::ui::app::{App, search_results};
use crate::ui::{fmt_dur, fmt_ms, fmt_time_delta, mask_user, theme};

pub fn render(f: &mut Frame, area: Rect, snap: &Snapshot, app: &mut App) {
    let chunks = Layout::vertical([Constraint::Length(3), Constraint::Min(0)]).split(area);
    super::render_topbar(f, chunks[0], snap, app);

    let prompt = if app.search_editing { ">" } else { " " };
    let input = Paragraph::new(format!("{prompt} {}", app.search_query))
        .style(Style::default().fg(theme::WARNING))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Search Call-ID / From / To  (press / to edit)"),
        );
    f.render_widget(input, chunks[1]);

    let area2 = chunks[1];
    let inner = Rect {
        y: area2.y + 3,
        height: area2.height.saturating_sub(3),
        ..area2
    };

    let results = search_results(snap, &app.search_query);
    let privacy = app.privacy;
    let user = |v: &Option<String>| match v.as_deref() {
        Some(v) if privacy => mask_user(v),
        Some(v) => v.to_string(),
        None => String::new(),
    };
    let rows = results.iter().map(|c| {
        Row::new(vec![
            Cell::from(
                c.invite_ts
                    .map(|t| fmt_time_delta(t, snap.start_us.unwrap_or(t), snap.tz_offset_secs))
                    .unwrap_or_else(|| "-".into()),
            ),
            Cell::from(user(&c.from_user)),
            Cell::from(user(&c.to_user)),
            Cell::from(c.state.label()),
            Cell::from(fmt_dur(c.duration_ms)),
            Cell::from(fmt_ms(c.best_mos)),
            Cell::from(format!("{}W/{}C", c.warn_count, c.critical_count)),
            Cell::from(c.call_id.clone()),
        ])
    });
    let table = Table::new(
        rows,
        [
            Constraint::Length(17),
            Constraint::Length(12),
            Constraint::Length(12),
            Constraint::Length(10),
            Constraint::Length(8),
            Constraint::Length(6),
            Constraint::Length(9),
            Constraint::Min(16),
        ],
    )
    .header(Row::new(
        [
            "Time", "From", "To", "State", "Dur", "MOS", "Diag", "Call-ID",
        ]
        .iter()
        .map(|h| Cell::from(*h)),
    ))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!("Results ({}) — Enter=detail", results.len())),
    )
    .row_highlight_style(Style::default().bg(theme::MUTED));
    f.render_stateful_widget(table, inner, &mut app.search_state);
}
