use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::widgets::{Block, Borders, Cell, Row, Table};

use crate::store::registry::Snapshot;
use crate::ui::app::App;
use crate::ui::{fmt_time, theme};

pub fn render(f: &mut Frame, area: Rect, snap: &Snapshot, app: &mut App) {
    let mut area = area;
    super::render_topbar(f, Rect { height: 3, ..area }, snap, app);
    area.y += 3;
    area.height = area.height.saturating_sub(3);

    // Group buckets by key; columns = last ~8 buckets.
    let mut keys: Vec<String> = Vec::new();
    let mut buckets: Vec<u64> = Vec::new();
    for (b, k, _) in &snap.buckets {
        if !buckets.contains(b) {
            buckets.push(*b);
        }
        if !keys.contains(k) {
            keys.push(k.clone());
        }
    }
    buckets.sort_unstable();
    keys.sort_unstable();
    let tail: Vec<u64> = buckets
        .iter()
        .rev()
        .take(8)
        .cloned()
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();

    let header: Vec<Cell> = std::iter::once(Cell::from("Remote IP"))
        .chain(tail.iter().map(|b| Cell::from(fmt_time(*b))))
        .collect();

    let rows = keys.iter().map(|k| {
        let mut cells = vec![Cell::from(k.clone())];
        for b in &tail {
            if let Some((_, _, m)) = snap.buckets.iter().find(|(bb, kk, _)| kk == k && bb == b) {
                let asr = m.asr();
                let style = if asr >= 95.0 {
                    Style::default().fg(theme::SUCCESS)
                } else if asr >= 80.0 {
                    Style::default().fg(theme::WARNING)
                } else {
                    Style::default().fg(theme::ERROR)
                };
                let cell = format!("{:.0}%", asr);
                cells.push(Cell::from(cell).style(style));
            } else {
                cells.push(Cell::from("·").style(Style::default().fg(theme::MUTED)));
            }
        }
        Row::new(cells)
    });

    let widths = std::iter::once(ratatui::layout::Constraint::Length(16))
        .chain((0..tail.len()).map(|_| ratatui::layout::Constraint::Length(9)))
        .collect::<Vec<_>>();

    let table = Table::new(rows, widths).header(Row::new(header)).block(
        Block::default().borders(Borders::ALL).title(format!(
            "Heatmap ASR%% by time×remote-IP (bucket {}s, 'b' to switch)",
            app.bucket_secs
        )),
    );
    f.render_widget(table, area);
}
