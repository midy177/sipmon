//! Page 4: per-IP network packet-loss heatmap (full screen). Reuses the same
//! loss heatmap rendering as the IP Stats page bottom section.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};

use crate::store::registry::Snapshot;
use crate::ui::app::App;

pub fn render(f: &mut Frame, area: Rect, snap: &Snapshot, app: &mut App) {
    let chunks = Layout::vertical([Constraint::Length(3), Constraint::Min(0)]).split(area);
    super::render_topbar(f, chunks[0], snap, app);
    super::ipstats::render_loss_heatmap(f, chunks[1], snap, app);
}
