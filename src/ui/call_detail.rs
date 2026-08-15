use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table, Tabs};

use crate::model::sip::{Method, SipMsg};
use crate::store::registry::Snapshot;
use crate::ui::app::App;
use crate::ui::{fmt_ms, fmt_time};

/// Right-pane sub-views (selected message vs call-level content).
const TABS: [&str; 3] = ["Raw", "Network", "Diagnostics"];

pub fn render(f: &mut Frame, area: Rect, snap: &Snapshot, app: &mut App) {
    let chunks = Layout::vertical([
        Constraint::Length(3),
        Constraint::Length(3),
        Constraint::Min(0),
    ])
    .split(area);
    super::render_topbar(f, chunks[0], snap, app);

    let Some(focus) = &snap.focus else {
        let msg = match &app.focus_pending {
            Some(id) => format!("Opening call {id} …"),
            None => "No call selected — press Enter on a call in Overview/Search.".to_string(),
        };
        let p = Paragraph::new(msg).block(Block::default().borders(Borders::ALL));
        f.render_widget(p, chunks[2]);
        return;
    };
    // Focus arrived: clear the pending hint.
    app.focus_pending = None;

    let title = format!(
        "Call {} ({} → {}) [{}]{}",
        focus.call_id,
        focus.from_user.as_deref().unwrap_or("?"),
        focus.to_user.as_deref().unwrap_or("?"),
        focus.state.map(|s| s.label()).unwrap_or("?"),
        if focus.streams.iter().any(|s| s.via_turn) {
            "  ⚙ via-TURN"
        } else {
            ""
        },
    );
    let p = Paragraph::new(Line::from(Span::styled(
        title,
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    )));
    f.render_widget(p, chunks[1]);

    // Fixed left-right split: left = flow list, right = selected-message / call detail.
    let cols = Layout::horizontal([Constraint::Percentage(45), Constraint::Percentage(55)])
        .split(chunks[2]);
    render_flow(f, cols[0], &focus.messages, app);

    let right = Layout::vertical([Constraint::Length(3), Constraint::Min(0)]).split(cols[1]);
    let tabs = Tabs::new(TABS.to_vec())
        .select(app.detail_tab)
        .highlight_style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )
        .block(Block::default().borders(Borders::ALL));
    f.render_widget(tabs, right[0]);

    match app.detail_tab {
        0 => render_raw(f, right[1], &focus.messages, app),
        1 => render_network(f, right[1], focus),
        _ => render_diag(f, right[1], focus),
    }
}

fn label_of(m: &SipMsg) -> String {
    if m.is_request {
        m.method
            .map(|x| x.name().to_string())
            .unwrap_or_else(|| "?".into())
    } else {
        format!(
            "{} {}",
            m.status.unwrap_or(0),
            short_reason(m.status.unwrap_or(0))
        )
    }
}

fn short_reason(code: u16) -> &'static str {
    match code {
        100 => "Trying",
        180 => "Ringing",
        183 => "Session Progress",
        200 => "OK",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        407 => "Proxy Auth Required",
        408 => "Request Timeout",
        486 => "Busy Here",
        487 => "Request Terminated",
        488 => "Not Acceptable",
        503 => "Service Unavailable",
        _ => "",
    }
}

fn render_flow(f: &mut Frame, area: Rect, messages: &[SipMsg], app: &mut App) {
    let base = messages.first().map(|m| m.ts_us).unwrap_or(0);
    let rows = messages.iter().map(|m| {
        let label = label_of(m);
        let style = if m.is_request {
            match m.method {
                Some(Method::Invite) => Style::default().fg(Color::Green),
                Some(Method::Bye) | Some(Method::Cancel) => Style::default().fg(Color::Red),
                _ => Style::default().fg(Color::Cyan),
            }
        } else {
            match m.status {
                Some(s) if (200..300).contains(&s) => Style::default().fg(Color::Green),
                Some(s) if s >= 300 => Style::default().fg(Color::Red),
                _ => Style::default().fg(Color::Yellow),
            }
        };
        Row::new(vec![
            Cell::from(fmt_time(m.ts_us)),
            Cell::from(format!("{:>8.3}", (m.ts_us - base) as f64 / 1000.0)),
            Cell::from(format!(
                "{}->{}",
                short(&m.flow.src.to_string()),
                short(&m.flow.dst.to_string())
            )),
            Cell::from(label).style(style),
            Cell::from(m.call_id.clone()).style(Style::default().fg(Color::DarkGray)),
        ])
    });
    let table = Table::new(
        rows,
        [
            Constraint::Length(10),
            Constraint::Length(10),
            Constraint::Length(24),
            Constraint::Length(20),
            Constraint::Min(12),
        ],
    )
    .header(Row::new(
        ["Time", "Rel ms", "Src→Dst", "Msg", "Call-ID"]
            .iter()
            .map(|h| Cell::from(*h)),
    ))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!("Flow ({} msgs)", messages.len())),
    )
    .row_highlight_style(Style::default().bg(Color::DarkGray));
    f.render_stateful_widget(table, area, &mut app.flow_state);
}

fn short(s: &str) -> String {
    // "1.2.3.4:5060" -> "1.2.3.4"
    s.split(':').next().unwrap_or(s).to_string()
}

fn render_raw(f: &mut Frame, area: Rect, messages: &[SipMsg], app: &mut App) {
    let idx = app
        .flow_state
        .selected()
        .unwrap_or(0)
        .min(messages.len().saturating_sub(1));
    let text = messages
        .get(idx)
        .map(|m| String::from_utf8_lossy(&m.raw).to_string())
        .unwrap_or_default();
    let lines: Vec<Line> = text
        .lines()
        .skip(app.raw_scroll)
        .map(|l| Line::from(l.to_string()))
        .collect();
    let p = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!("Raw [{idx}]")),
    );
    f.render_widget(p, area);
}

fn render_network(f: &mut Frame, area: Rect, focus: &crate::store::registry::Focus) {
    let chunks = Layout::vertical([Constraint::Min(0), Constraint::Length(6)]).split(area);

    let rows = focus.streams.iter().map(|s| {
        let leg = match (s.via_turn, s.leg.as_deref()) {
            (true, Some(l)) => format!("turn-{l}"),
            (true, None) => "turn".to_string(),
            (false, _) => "-".into(),
        };
        Row::new(vec![
            Cell::from(format!("{:#x}", s.ssrc)),
            Cell::from(s.codec.clone().unwrap_or_else(|| "-".into())),
            Cell::from(format!(
                "{}->{}",
                short(&s.flow.map(|f| f.src.to_string()).unwrap_or_default()),
                short(&s.flow.map(|f| f.dst.to_string()).unwrap_or_default())
            )),
            Cell::from(leg).style(Style::default().fg(Color::Magenta)),
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
            Constraint::Length(26),
            Constraint::Length(10),
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
            "SSRC", "Codec", "Flow", "Leg", "Pkts", "Lost", "Loss%", "Jitter", "RTT", "MOS",
        ]
        .iter()
        .map(|h| Cell::from(*h)),
    ))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title("Media streams (Leg: turn-client/turn-peer = TURN-relayed)"),
    );
    f.render_widget(table, chunks[0]);

    let neg = focus
        .negotiated_endpoints
        .iter()
        .map(|e| e.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    let info = Paragraph::new(vec![
        Line::from(Span::styled(
            format!("SDP endpoints: {}", if neg.is_empty() { "-" } else { &neg }),
            Style::default().fg(Color::Gray),
        )),
        Line::from(format!("SIP msgs: {}", focus.messages.len())),
    ])
    .block(Block::default().borders(Borders::ALL).title("Negotiated"));
    f.render_widget(info, chunks[1]);
}

fn render_diag(f: &mut Frame, area: Rect, focus: &crate::store::registry::Focus) {
    let lines: Vec<Line> = focus
        .diagnostics
        .iter()
        .map(|d| {
            let color = match d.severity {
                crate::diagnostics::Severity::Critical => Color::Red,
                crate::diagnostics::Severity::Warn => Color::Yellow,
                crate::diagnostics::Severity::Info => Color::Gray,
            };
            Line::from(Span::styled(
                format!(
                    "{} [{}] {} {}",
                    fmt_time(d.ts_us),
                    d.severity.label(),
                    d.code,
                    d.message
                ),
                Style::default().fg(color),
            ))
        })
        .collect();
    let p = Paragraph::new(if lines.is_empty() {
        vec![Line::from("no diagnostics for this call")]
    } else {
        lines
    })
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!("Diagnostics ({})", focus.diagnostics.len())),
    );
    f.render_widget(p, area);
}
