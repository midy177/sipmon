use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::widgets::{Block, Borders, Cell, Row, Table};

use crate::store::registry::Snapshot;
use crate::ui::app::App;
use crate::ui::{fmt_ms, mask_socket, theme};

pub fn render(f: &mut Frame, area: Rect, snap: &Snapshot, app: &mut App) {
    let chunks = Layout::vertical([Constraint::Length(3), Constraint::Min(0)]).split(area);
    super::render_topbar(f, chunks[0], snap, app);

    let mut streams = snap.streams.clone();
    streams.sort_by_key(|s| s.ssrc);
    let privacy = app.privacy;
    let local = &app.local_ips;
    let flow_w = streams
        .iter()
        .filter_map(|s| s.flow)
        .map(|f| {
            let src = if privacy {
                mask_socket(&f.src.to_string())
            } else {
                f.src.to_string()
            };
            let dst = if privacy {
                mask_socket(&f.dst.to_string())
            } else {
                f.dst.to_string()
            };
            src.len().max(dst.len())
        })
        .max()
        .unwrap_or(0);
    let rows = streams.iter().map(|s| {
        let flow = match s.flow {
            Some(f) => {
                let src = if privacy {
                    mask_socket(&f.src.to_string())
                } else {
                    f.src.to_string()
                };
                let dst = if privacy {
                    mask_socket(&f.dst.to_string())
                } else {
                    f.dst.to_string()
                };
                super::call_detail::dir_flow(f.src.ip(), f.dst.ip(), &src, &dst, local, flow_w)
            }
            None => "-".into(),
        };
        Row::new(vec![
            Cell::from(format!("{:#x}", s.ssrc)),
            Cell::from(s.codec.clone().unwrap_or_else(|| "-".into())),
            Cell::from(
                s.payload_type
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "-".into()),
            ),
            Cell::from(flow),
            Cell::from(s.packets.to_string()),
            Cell::from(s.lost.to_string()),
            Cell::from(format!("{:.1}", s.loss_pct)),
            Cell::from(fmt_ms(s.jitter_ms)),
            Cell::from(fmt_ms(s.rtt_avg_ms)),
            Cell::from(fmt_ms(s.mos)),
        ])
    });
    let table = Table::new(
        rows,
        [
            Constraint::Length(12),
            Constraint::Length(10),
            Constraint::Length(4),
            Constraint::Length((flow_w * 2 + 4) as u16),
            Constraint::Length(8),
            Constraint::Length(7),
            Constraint::Length(7),
            Constraint::Length(9),
            Constraint::Length(9),
            Constraint::Length(6),
        ],
    )
    .header(Row::new(
        [
            "SSRC", "Codec", "PT", "Flow", "Pkts", "Lost", "Loss%", "Jitter", "RTT", "MOS",
        ]
        .iter()
        .map(|h| Cell::from(*h)),
    ))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!("RTP streams ({})", streams.len())),
    )
    .row_highlight_style(theme::selected());
    f.render_stateful_widget(table, chunks[1], &mut app.streams_state);
}
