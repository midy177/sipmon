use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::symbols::Marker;
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Axis, Block, Borders, Cell, Chart, Dataset, GraphType, LegendPosition, Paragraph, Row, Table,
    Tabs,
};

use crate::model::media::StreamSummary;
use crate::model::sip::{Method, SipMsg};
use crate::store::registry::Snapshot;
use crate::ui::app::App;
use crate::ui::{fmt_bytes, fmt_ms, fmt_rate, fmt_time, theme};

/// Right-pane sub-views (selected message vs call-level content).
const TABS: [&str; 3] = ["Raw", "Network", "Diagnostics"];

pub fn render(f: &mut Frame, area: Rect, snap: &Snapshot, app: &mut App) {
    let chunks = Layout::vertical([
        Constraint::Length(3),
        Constraint::Length(4),
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
    let caller = format!(
        "{} @ {}",
        focus.caller_ua.as_deref().unwrap_or("?"),
        focus
            .caller_addr
            .map(|a| a.to_string())
            .unwrap_or_else(|| "?".into())
    );
    let callee = format!(
        "{} @ {}",
        focus.callee_ua.as_deref().unwrap_or("?"),
        focus
            .callee_addr
            .map(|a| a.to_string())
            .unwrap_or_else(|| "?".into())
    );
    let timing = format!(
        "PDD {}ms | Setup {}ms | Ring {}·{}",
        fmt_ms(focus.pdd_ms.map(|m| m as f64)),
        fmt_ms(focus.setup_ms.map(|m| m as f64)),
        fmt_ms(focus.ring_ms.map(|m| m as f64)),
        focus
            .ring_code
            .map(|c| c.to_string())
            .unwrap_or_else(|| "-".into()),
    );
    let hangup = match (focus.hangup_by, focus.hangup_code, focus.hangup_reason.as_deref()) {
        (Some(b), code, _) => format!(
            "End: {} {}",
            b.label(),
            code.map(|c| c.to_string()).unwrap_or_default()
        ),
        (None, Some(code), reason) => {
            format!("End: {code} {}", reason.unwrap_or(""))
        }
        (None, None, _) => "End: -".into(),
    };
    let lines = vec![
        Line::from(Span::styled(
            title,
            Style::default()
                .fg(theme::INFO)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::styled(
            format!("Caller ← {}", caller),
            Style::default().fg(theme::SUCCESS),
        )),
        Line::from(Span::styled(
            format!("Callee → {}", callee),
            Style::default().fg(theme::WARNING),
        )),
        Line::from(Span::styled(
            format!("{timing}   {hangup}"),
            Style::default().fg(theme::MUTED),
        )),
    ];
    f.render_widget(Paragraph::new(lines), chunks[1]);

    // Fixed left-right split: left = flow list, right = selected-message / call detail.
    let cols = Layout::horizontal([Constraint::Percentage(45), Constraint::Percentage(55)])
        .split(chunks[2]);
    render_flow(f, cols[0], &focus.messages, app);

    let right = Layout::vertical([Constraint::Length(3), Constraint::Min(0)]).split(cols[1]);
    let tabs = Tabs::new(TABS.to_vec())
        .select(app.detail_tab)
        .highlight_style(
            Style::default()
                .fg(theme::WARNING)
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
                Some(Method::Invite) => Style::default().fg(theme::SUCCESS),
                Some(Method::Bye) | Some(Method::Cancel) => Style::default().fg(theme::ERROR),
                _ => Style::default().fg(theme::INFO),
            }
        } else {
            match m.status {
                Some(s) if (200..300).contains(&s) => Style::default().fg(theme::SUCCESS),
                Some(s) if s >= 300 => Style::default().fg(theme::ERROR),
                _ => Style::default().fg(theme::WARNING),
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
        ])
    });
    let table = Table::new(
        rows,
        [
            Constraint::Length(10),
            Constraint::Length(10),
            Constraint::Length(24),
            Constraint::Min(20),
        ],
    )
    .header(Row::new(
        ["Time", "Rel ms", "Src→Dst", "Msg"]
            .iter()
            .map(|h| Cell::from(*h)),
    ))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!("Flow ({} msgs)", messages.len())),
    )
    .row_highlight_style(Style::default().bg(theme::MUTED));
    f.render_stateful_widget(table, area, &mut app.flow_state);
}

fn short(s: &str) -> String {
    // "1.2.3.4:5060" -> "1.2.3.4"
    s.split(':').next().unwrap_or(s).to_string()
}

/// Media flow label: IP→IP (ports omitted so it fits the compact table).
fn flow_short(f: Option<crate::model::packet::Flow5Tuple>) -> String {
    match f {
        Some(fl) => format!(
            "{}→{}",
            short(&fl.src.to_string()),
            short(&fl.dst.to_string())
        ),
        None => "-".into(),
    }
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
    let chunks = Layout::vertical([
        Constraint::Length(4),
        Constraint::Min(0),
        Constraint::Length(10),
    ])
    .split(area);

    // Split the call's media into TX (from the caller) / RX (toward the caller).
    // Match streams to the caller by IP; when both parties share an IP
    // (loopback), pair the reverse flows so each direction lands in its own
    // bucket instead of everything collapsing into one side.
    let caller_ip = focus.caller_ip;
    let streams = &focus.streams;
    let flows: Vec<Option<crate::model::packet::Flow5Tuple>> =
        streams.iter().map(|s| s.flow).collect();
    let mut is_tx = vec![false; streams.len()];
    let mut paired = vec![false; streams.len()];
    for i in 0..streams.len() {
        if paired[i] {
            continue;
        }
        let rev = flows[i].map(|f| f.reverse());
        let j = flows.iter().position(|f| *f == rev);
        if let Some(j) = j.filter(|&j| j != i) {
            let i_tx = caller_ip
                .map(|cip| flows[i].map(|f| f.src.ip()) == Some(cip))
                .unwrap_or(true);
            is_tx[i] = i_tx;
            paired[i] = true;
            is_tx[j] = !i_tx;
            paired[j] = true;
        }
    }
    let mut tx_bytes = 0u64;
    let mut rx_bytes = 0u64;
    let mut tx_rate = 0.0f64;
    let mut rx_rate = 0.0f64;
    for (i, s) in streams.iter().enumerate() {
        let rate = stream_bytes_per_sec(s);
        let tx = if paired[i] {
            is_tx[i]
        } else {
            flows[i].map(|f| f.src.ip()) == caller_ip
        };
        if tx {
            tx_bytes += s.bytes;
            tx_rate += rate;
        } else {
            rx_bytes += s.bytes;
            rx_rate += rate;
        }
    }
    let neg = focus
        .negotiated_endpoints
        .iter()
        .map(|e| e.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    let totals = Paragraph::new(vec![
        Line::from(Span::styled(
            format!(
                "↑ TX {} @ {}    ↓ RX {} @ {}",
                fmt_bytes(tx_bytes),
                fmt_rate(tx_rate),
                fmt_bytes(rx_bytes),
                fmt_rate(rx_rate)
            ),
            Style::default().fg(theme::SUCCESS),
        )),
        Line::from(Span::styled(
            format!(
                "SDP endpoints: {}   SIP msgs: {}",
                if neg.is_empty() { "-" } else { &neg },
                focus.messages.len()
            ),
            Style::default().fg(theme::MUTED),
        )),
    ])
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title("Traffic (TX=caller side)"),
    );
    f.render_widget(totals, chunks[0]);

    let rows = focus.streams.iter().map(|s| {
        let leg = match (s.via_turn, s.leg.as_deref()) {
            (true, Some(l)) if l.starts_with("client") => "t-c".to_string(),
            (true, Some(_)) => "t-p".to_string(),
            (true, None) => "trn".to_string(),
            (false, _) => "-".into(),
        };
        Row::new(vec![
            Cell::from(format!("{:#x}", s.ssrc)),
            Cell::from(s.codec.clone().unwrap_or_else(|| "-".into())),
            Cell::from(flow_short(s.flow)),
            Cell::from(leg).style(Style::default().fg(theme::ACCENT)),
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
            Constraint::Length(8),
            Constraint::Length(7),
            Constraint::Length(17),
            Constraint::Length(3),
            Constraint::Length(6),
            Constraint::Length(5),
            Constraint::Length(6),
            Constraint::Length(7),
            Constraint::Length(7),
            Constraint::Length(5),
        ],
    )
    .column_spacing(1)
    .header(Row::new(
        ["SSRC", "Codec", "Flow", "Leg", "Pkts", "Lost", "Loss%", "Jitter", "RTT", "MOS"]
            .iter()
            .map(|h| Cell::from(*h)),
    ))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title("Media streams (Leg: t-c/t-p = TURN client/peer leg)"),
    );
    f.render_widget(table, chunks[1]);

    render_waveform(f, chunks[2], focus);
}

/// Per-stream average rate (bytes/sec) over its observed lifetime.
fn stream_bytes_per_sec(s: &StreamSummary) -> f64 {
    match (s.bytes, s.first_ts_us, s.last_ts_us) {
        (b, Some(a), Some(z)) if z > a => b as f64 / ((z - a) as f64 / 1_000_000.0),
        _ => 0.0,
    }
}

/// Bidirectional throughput waveform: one series per stream, plotted from the
/// per-stream 5s sample history (KB/s). Shows a rolling 60s window so the
/// shape stays readable while the call runs.
type Series = (String, Vec<(f64, f64)>, Color);

const WAVE_WINDOW_US: u64 = 60_000_000; // 60s of visible history

fn render_waveform(f: &mut Frame, area: Rect, focus: &crate::store::registry::Focus) {
    const COLORS: [Color; 6] = [
        theme::SUCCESS,
        theme::ERROR,
        theme::WARNING,
        theme::INFO,
        theme::ACCENT,
        theme::PRIMARY,
    ];
    const WINDOW_US: f64 = 5_000_000.0;

    // Rolling window: the newest 5s sample across all streams is "now".
    let now = focus
        .streams
        .iter()
        .filter_map(|s| s.history.last().map(|h| h.ts_us))
        .max()
        .unwrap_or(0);
    let window_start = now.saturating_sub(WAVE_WINDOW_US);

    let mut series: Vec<Series> = Vec::new();
    let mut x_max = 1.0f64;
    let mut y_max = 1.0f64;
    for (i, s) in focus.streams.iter().enumerate() {
        if s.history.is_empty() {
            continue;
        }
        let mut pts = Vec::new();
        let mut prev_ts: Option<u64> = None;
        for h in &s.history {
            if h.ts_us < window_start {
                // Keep as the rate reference for the first visible point.
                prev_ts = Some(h.ts_us);
                continue;
            }
            let x = (h.ts_us.saturating_sub(window_start)) as f64 / 1_000_000.0;
            let dt_us = match prev_ts {
                Some(p) => h.ts_us.saturating_sub(p).max(1) as f64,
                None => WINDOW_US,
            };
            prev_ts = Some(h.ts_us);
            let kbps = h.bytes as f64 / (dt_us / 1_000_000.0) / 1024.0;
            x_max = x_max.max(x);
            y_max = y_max.max(kbps);
            pts.push((x, kbps));
        }
        if pts.is_empty() {
            continue;
        }
        let cur = pts.last().map(|p| p.1).unwrap_or(0.0);
        let label = match s.flow {
            Some(fl) => format!(
                "{}→{} {:.0}KB/s",
                short(&fl.src.to_string()),
                short(&fl.dst.to_string()),
                cur
            ),
            None => format!("{:#x}", s.ssrc),
        };
        series.push((label, pts, COLORS[i % COLORS.len()]));
    }

    let datasets: Vec<Dataset> = series
        .iter()
        .map(|(name, pts, color)| {
            Dataset::default()
                .name(name.as_str())
                .marker(Marker::Braille)
                .graph_type(GraphType::Line)
                .style(Style::default().fg(*color))
                .data(pts.as_slice())
        })
        .collect();

    let chart = Chart::new(datasets)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Throughput KB/s (last 60s, 5s buckets)"),
        )
        .x_axis(
            Axis::default()
                .title(Span::styled(
                    "elapsed s (rolling 60s)",
                    Style::default().fg(theme::MUTED),
                ))
                .style(Style::default().fg(theme::MUTED))
                .bounds([0.0, x_max]),
        )
        .y_axis(
            Axis::default()
                .title(Span::styled("KB/s", Style::default().fg(theme::MUTED)))
                .style(Style::default().fg(theme::MUTED))
                .bounds([0.0, y_max]),
        )
        .legend_position(Some(LegendPosition::TopLeft));
    f.render_widget(chart, area);
}

fn render_diag(f: &mut Frame, area: Rect, focus: &crate::store::registry::Focus) {
    let lines: Vec<Line> = focus
        .diagnostics
        .iter()
        .map(|d| {
            let color = match d.severity {
                crate::diagnostics::Severity::Critical => theme::ERROR,
                crate::diagnostics::Severity::Warn => theme::WARNING,
                crate::diagnostics::Severity::Info => theme::MUTED,
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

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    use std::sync::atomic::AtomicBool;
    use std::sync::{Arc, Mutex};

    use crate::model::packet::{Flow5Tuple, Proto};
    use crate::store::registry::{Focus, Snapshot};
    use crate::ui::app::Page;

    /// The Network tab's media table must fit inside the right pane at typical
    /// widths without the header wrapping onto a second line. Regression test
    /// for the demo screenshot where the right side wrapped.
    #[test]
    fn network_table_header_fits_no_wrap() {
        let focus = Focus {
            call_id: "c1".into(),
            state: Some(crate::model::sip::CallState::Active),
            from_user: Some("alice".into()),
            to_user: Some("bob".into()),
            streams: vec![
                StreamSummary {
                    ssrc: 0x1000,
                    codec: Some("PCMU".into()),
                    flow: Some(Flow5Tuple {
                        proto: Proto::Udp,
                        src: "10.10.0.8:20014".parse().unwrap(),
                        dst: "10.20.0.8:30014".parse().unwrap(),
                    }),
                    packets: 684,
                    lost: 5,
                    loss_pct: 0.7,
                    jitter_ms: Some(1.3),
                    rtt_avg_ms: None,
                    mos: Some(4.3),
                    ..StreamSummary::default()
                },
                StreamSummary {
                    ssrc: 0x8000,
                    codec: Some("PCMU".into()),
                    flow: Some(Flow5Tuple {
                        proto: Proto::Udp,
                        src: "10.20.0.8:30014".parse().unwrap(),
                        dst: "10.10.0.8:20014".parse().unwrap(),
                    }),
                    packets: 700,
                    lost: 2,
                    loss_pct: 0.3,
                    jitter_ms: Some(1.0),
                    rtt_avg_ms: Some(10.0),
                    mos: Some(4.5),
                    ..StreamSummary::default()
                },
            ],
            ..Focus::default()
        };
        let snap = Arc::new(Mutex::new(Snapshot {
            focus: Some(focus),
            ..Snapshot::default()
        }));
        let mut app = App::new(
            snap,
            Arc::new(AtomicBool::new(false)),
            Arc::new(Mutex::new(Some("c1".to_string()))),
            Arc::new(AtomicBool::new(false)),
        );
        app.page = Page::CallDetail;
        app.detail_tab = 1; // Network

        let mut terminal = Terminal::new(TestBackend::new(150, 44)).unwrap();
        terminal
            .draw(|f| crate::ui::render(f, &mut app))
            .unwrap();
        let buf = terminal.backend().buffer().clone();

        // Every media-table header must appear on the same continuous line as
        // "SSRC" (i.e. the header never wraps onto a second row).
        let headers = ["SSRC", "Codec", "Flow", "Leg", "Pkts", "Lost", "Loss%", "Jitter", "RTT", "MOS"];
        let joined: Vec<String> = (0..buf.area.height)
            .map(|y| {
                (0..buf.area.width)
                    .map(|x| buf[(x, y)].symbol().to_string())
                    .collect::<String>()
            })
            .collect();
        let header_line = joined
            .iter()
            .find(|l| l.contains("SSRC"))
            .expect("media table header row must be rendered");
        for h in headers {
            assert!(
                header_line.contains(h),
                "header {h} must be on the single SSRC header row (no wrap)"
            );
        }
    }

    #[test]
    fn network_table_fits_narrow_terminal() {
        let focus = Focus {
            call_id: "c1".into(),
            state: Some(crate::model::sip::CallState::Active),
            from_user: Some("alice".into()),
            to_user: Some("bob".into()),
            streams: vec![StreamSummary {
                ssrc: 0x1000,
                codec: Some("PCMU".into()),
                flow: Some(Flow5Tuple {
                    proto: Proto::Udp,
                    src: "10.10.0.8:20014".parse().unwrap(),
                    dst: "10.20.0.8:30014".parse().unwrap(),
                }),
                ..StreamSummary::default()
            }],
            ..Focus::default()
        };
        let snap = Arc::new(Mutex::new(Snapshot {
            focus: Some(focus),
            ..Snapshot::default()
        }));
        let mut app = App::new(
            snap,
            Arc::new(AtomicBool::new(false)),
            Arc::new(Mutex::new(Some("c1".to_string()))),
            Arc::new(AtomicBool::new(false)),
        );
        app.page = Page::CallDetail;
        app.detail_tab = 1;

        // At a 114-column terminal (55% right pane ≈ 63 cols) the render must
        // not panic and the table should still produce the header row.
        let mut terminal = Terminal::new(TestBackend::new(114, 44)).unwrap();
        terminal
            .draw(|f| crate::ui::render(f, &mut app))
            .unwrap();
        let buf = terminal.backend().buffer().clone();
        let has_ssrc = (0..buf.area.height).any(|y| {
            (0..buf.area.width)
                .any(|x| buf[(x, y)].symbol() == "S" && buf[(x + 1, y)].symbol() == "S")
        });
        assert!(has_ssrc, "SSRC header should still be rendered");
    }
}
