use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::Style;
use ratatui::text::Line;
use ratatui::widgets::{Block, Borders, Paragraph};

use crate::store::registry::Snapshot;
use crate::ui::app::App;
use crate::ui::theme;

pub fn render(f: &mut Frame, area: Rect, snap: &Snapshot, app: &mut App) {
    let chunks = Layout::vertical([Constraint::Length(3), Constraint::Min(0)]).split(area);
    super::render_topbar(f, chunks[0], snap, app);

    let total = snap.events.len();
    let lines: Vec<Line> = snap
        .events
        .iter()
        .rev()
        .skip(app.eventlog_scroll as usize)
        .map(|e| Line::from(e.clone()))
        .collect();
    let p = Paragraph::new(if lines.is_empty() {
        vec![Line::from(
            "(no events yet — diagnostics and call state changes appear here)",
        )]
    } else {
        lines
    })
    .style(Style::default().fg(theme::MUTED))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!("Event Log ({} lines, newest first)", total)),
    );
    f.render_widget(p, chunks[1]);
}
