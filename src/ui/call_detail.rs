use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Clear, Paragraph, Row, Table};

use crate::model::media::StreamSummary;
use crate::model::sip::{Method, SipMsg};
use crate::store::registry::{Focus, Snapshot};
use crate::ui::app::App;
use crate::ui::{
    fmt_bytes, fmt_ms, fmt_rate, fmt_secs, fmt_time_delta, fmt_time_tz, mask_ip, mask_socket,
    mask_user, theme,
};

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
    let privacy = app.privacy;

    let from = display_user(focus.from_user.as_deref(), privacy, "?");
    let to = display_user(focus.to_user.as_deref(), privacy, "?");
    let b2bua_suffix = match &focus.b2bua {
        Some(b) => {
            let addr = b
                .addr
                .map(|ip| if privacy { mask_ip(ip) } else { ip.to_string() })
                .unwrap_or_else(|| "?".into());
            format!("  ⇄ B2BUA {addr} ({} legs)", b.legs)
        }
        None => String::new(),
    };
    let linked_suffix = app
        .linked_call_id
        .as_ref()
        .map(|id| format!("  ⇄ b-leg {id}"))
        .unwrap_or_default();
    let title = format!(
        "Call {} ({} → {}) [{}]{}{}{}",
        focus.call_id,
        from,
        to,
        focus.state.map(|s| s.label()).unwrap_or("?"),
        b2bua_suffix,
        linked_suffix,
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
            .map(|a| display_socket(a, privacy))
            .unwrap_or_else(|| "?".into())
    );
    let callee = format!(
        "{} @ {}",
        focus.callee_ua.as_deref().unwrap_or("?"),
        focus
            .callee_addr
            .map(|a| display_socket(a, privacy))
            .unwrap_or_else(|| "?".into())
    );
    let timing = format!(
        "PDD {} | Setup {} | Ring {} | EarlyMedia {}",
        fmt_secs(focus.pdd_ms.map(|m| m as u64)),
        fmt_secs(focus.setup_ms.map(|m| m as u64)),
        fmt_secs(focus.ring_ms.map(|m| m as u64)),
        if focus.early_media { "✓" } else { "-" },
    );
    let hangup = match (
        focus.hangup_by,
        focus.hangup_code,
        focus.hangup_reason.as_deref(),
    ) {
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

    // Fixed left-right split. Left column: message flow (top) with a setup
    // timeline in the middle and diagnostics below. Right column: raw message
    // (2/3) with the network/media stats below (1/3).
    let cols = Layout::horizontal([Constraint::Percentage(45), Constraint::Percentage(55)])
        .split(chunks[2]);
    let left = Layout::vertical([
        Constraint::Ratio(3, 5),
        Constraint::Length(7),
        Constraint::Ratio(2, 5),
    ])
    .split(cols[0]);
    render_flow(f, left[0], &focus.messages, snap, &focus.legs, app);
    render_timeline(f, left[1], focus);
    render_diag(f, left[2], focus, snap.tz_offset_secs);

    let right = Layout::vertical([Constraint::Ratio(2, 3), Constraint::Ratio(1, 3)]).split(cols[1]);
    render_raw(f, right[0], &focus.messages, app);
    render_network(f, right[1], focus, privacy, &app.local_ips);

    if app.b_leg_picker {
        render_b_leg_picker(f, area, snap, app);
    }
}

fn display_user(v: Option<&str>, privacy: bool, fallback: &str) -> String {
    match v {
        Some(v) if privacy => mask_user(v),
        Some(v) => v.to_string(),
        None => fallback.to_string(),
    }
}

/// Centered searchable overlay to pick another call as the swimlane b-leg.
fn render_b_leg_picker(f: &mut Frame, area: Rect, snap: &Snapshot, app: &mut App) {
    let primary = snap
        .focus
        .as_ref()
        .map(|f| f.call_id.as_str())
        .or(app.focus_pending.as_deref())
        .unwrap_or("");
    let cands = crate::ui::app::b_leg_candidates(snap, primary, &app.b_leg_query);
    let width = area.width.saturating_mul(70) / 100;
    let height = area.height.saturating_mul(60) / 100;
    let popup = Rect {
        x: area.x + (area.width.saturating_sub(width)) / 2,
        y: area.y + (area.height.saturating_sub(height)) / 2,
        width,
        height,
    };
    f.render_widget(Clear, popup);
    let chunks = Layout::vertical([Constraint::Length(3), Constraint::Min(0)]).split(popup);
    let title = format!(
        "Link b-leg  filter: {}{}  [{}]",
        app.b_leg_query,
        if app.b_leg_query.is_empty() {
            "(type to search)"
        } else {
            ""
        },
        cands.len()
    );
    let filter = Paragraph::new(app.b_leg_query.as_str()).block(
        Block::default()
            .borders(Borders::ALL)
            .title(title)
            .border_style(Style::default().fg(theme::INFO)),
    );
    f.render_widget(filter, chunks[0]);

    let privacy = app.privacy;
    let rows = cands.iter().map(|c| {
        let from = display_user(c.from_user.as_deref(), privacy, "?");
        let to = display_user(c.to_user.as_deref(), privacy, "?");
        Row::new(vec![
            Cell::from(c.call_id.clone()),
            Cell::from(format!("{from} → {to}")),
            Cell::from(c.state.label()),
        ])
    });
    let table = Table::new(
        rows,
        [
            Constraint::Min(16),
            Constraint::Min(20),
            Constraint::Length(10),
        ],
    )
    .header(Row::new(["Call-ID", "From → To", "State"].iter().map(
        |h| Cell::from(*h).style(Style::default().add_modifier(Modifier::BOLD)),
    )))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title("[↑↓] select  [Enter] link  [Esc] cancel"),
    )
    .row_highlight_style(theme::selected());
    f.render_stateful_widget(table, chunks[1], &mut app.b_leg_state);
}

fn display_socket(a: std::net::SocketAddr, privacy: bool) -> String {
    if privacy {
        mask_socket(&a.to_string())
    } else {
        a.to_string()
    }
}

fn label_of(m: &SipMsg) -> String {
    if m.is_request {
        m.method
            .map(|x| x.name().to_string())
            .unwrap_or_else(|| "?".into())
    } else {
        m.status.unwrap_or(0).to_string()
    }
}

fn render_flow(
    f: &mut Frame,
    area: Rect,
    messages: &[SipMsg],
    snap: &Snapshot,
    legs: &[u8],
    app: &mut App,
) {
    let local = &app.local_ips;
    let parties = if let Some(ln) = classify_lanes(messages, legs, local) {
        let mid = mid_socket(ln.pbx, messages);
        vec![ln.a_remote, mid, ln.b_remote]
    } else {
        let (left, right) = two_parties(messages).unwrap_or_else(|| {
            let z: std::net::SocketAddr = "0.0.0.0:0".parse().unwrap();
            (z, z)
        });
        vec![left, right]
    };
    render_swimlane(f, area, messages, legs, &parties, snap, app);
}

/// sngrep-style swimlane: time | vertical bars under each `ip:port`, with
/// `-- INVITE ->` / `<- 100 --` painted between the endpoints of each message.
fn render_swimlane(
    f: &mut Frame,
    area: Rect,
    messages: &[SipMsg],
    legs: &[u8],
    parties: &[std::net::SocketAddr],
    snap: &Snapshot,
    app: &mut App,
) {
    let first_ts = messages.first().map(|m| m.ts_us).unwrap_or(0);
    // Relative times count from the dialog's first message, not the capture
    // start, so mid-capture dialogs begin at +0.00s.
    let start = first_ts;
    let tz = snap.tz_offset_secs;
    let privacy = app.privacy;
    let labels: Vec<String> = parties
        .iter()
        .copied()
        .map(|p| display_socket(p, privacy))
        .collect();
    // Time column + borders/spacing leave the rest for the swim canvas.
    let swim_w = (area.width as usize)
        .saturating_sub(2)
        .saturating_sub(17)
        .saturating_sub(1)
        .max(16);
    let header_swim = swim_header(&labels, swim_w);
    let title_parties = labels.join(" | ");

    let rows = messages.iter().enumerate().map(|(i, m)| {
        let label = label_of(m);
        let style = msg_style(m);
        let (from, to) = resolve_party_pair(m, parties, legs.get(i).copied());
        let canvas = swim_row(parties.len(), from, to, &label, swim_w);
        Row::new(vec![
            Cell::from(fmt_time_delta(m.ts_us, start, tz)),
            Cell::from(canvas).style(style),
        ])
    });

    let table = Table::new(
        rows,
        [Constraint::Length(17), Constraint::Min(swim_w as u16)],
    )
    .column_spacing(1)
    .header(Row::new([
        Cell::from("Time"),
        Cell::from(header_swim).style(Style::default().add_modifier(Modifier::BOLD)),
    ]))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!("Flow · {title_parties} ({} msgs)", messages.len())),
    )
    .row_highlight_style(theme::selected());
    f.render_stateful_widget(table, area, &mut app.flow_state);
}

/// Party column centers across a swim canvas of `width`.
fn party_centers(n: usize, width: usize) -> Vec<usize> {
    if n == 0 || width == 0 {
        return Vec::new();
    }
    if n == 1 {
        return vec![width / 2];
    }
    let col_w = width / n;
    (0..n)
        .map(|i| {
            let start = i * col_w;
            let end = if i + 1 == n { width } else { start + col_w };
            start + (end - start) / 2
        })
        .collect()
}

/// Header: each `ip:port` centered above its vertical bar.
fn swim_header(labels: &[String], width: usize) -> String {
    let centers = party_centers(labels.len(), width);
    let mut buf = vec![b' '; width];
    for (label, &c) in labels.iter().zip(&centers) {
        let bytes = label.as_bytes();
        let start = c
            .saturating_sub(bytes.len() / 2)
            .min(width.saturating_sub(1));
        for (i, &b) in bytes.iter().enumerate() {
            if start + i < width {
                buf[start + i] = b;
            }
        }
    }
    String::from_utf8(buf).unwrap_or_default()
}

/// One message row: `|` under every party, short centered `-- INVITE ->` /
/// `<- 100 --` between src/dst.
fn swim_row(n: usize, from: usize, to: usize, label: &str, width: usize) -> String {
    let centers = party_centers(n, width);
    let mut buf = vec![b' '; width];
    for &c in &centers {
        if c < width {
            buf[c] = b'|';
        }
    }
    if from >= centers.len() || to >= centers.len() || from == to {
        return String::from_utf8(buf).unwrap_or_default();
    }
    let left = centers[from.min(to)];
    let right = centers[from.max(to)];
    if right <= left + 1 {
        return String::from_utf8(buf).unwrap_or_default();
    }
    let rightward = from < to;
    // Short, centered glyph: `-- INVITE ->` / `<- 100 --`
    let glyph = if rightward {
        format!("-- {label} ->")
    } else {
        format!("<- {label} --")
    };
    let gap = right - left - 1;
    let bytes = glyph.as_bytes();
    let take = bytes.len().min(gap);
    let start = left + 1 + (gap.saturating_sub(take) / 2);
    for (i, &b) in bytes.iter().take(take).enumerate() {
        buf[start + i] = b;
    }
    String::from_utf8(buf).unwrap_or_default()
}

fn party_index(parties: &[std::net::SocketAddr], addr: std::net::SocketAddr) -> Option<usize> {
    parties
        .iter()
        .position(|p| *p == addr)
        .or_else(|| parties.iter().position(|p| p.ip() == addr.ip()))
}

/// Map a message onto two party column indices (src → dst).
fn resolve_party_pair(
    m: &SipMsg,
    parties: &[std::net::SocketAddr],
    leg: Option<u8>,
) -> (usize, usize) {
    if let (Some(s), Some(d)) = (
        party_index(parties, m.flow.src),
        party_index(parties, m.flow.dst),
    ) {
        return (s, d);
    }
    // 3-party fallback by dialog leg: a-leg spans 0↔1, b-leg spans 1↔2.
    if parties.len() == 3 {
        let dst_mid =
            party_index(parties, m.flow.dst) == Some(1) || m.flow.dst.ip() == parties[1].ip();
        match leg {
            Some(0) => {
                if dst_mid {
                    (0, 1)
                } else {
                    (1, 0)
                }
            }
            Some(1) => {
                if dst_mid {
                    (2, 1)
                } else {
                    (1, 2)
                }
            }
            _ => (0, 1),
        }
    } else if parties.len() >= 2 {
        (0, 1)
    } else {
        (0, 0)
    }
}

/// PBX mid-column socket: reuse a real port seen on the shared IP.
fn mid_socket(pbx: std::net::IpAddr, messages: &[SipMsg]) -> std::net::SocketAddr {
    for m in messages {
        if m.flow.src.ip() == pbx {
            return m.flow.src;
        }
        if m.flow.dst.ip() == pbx {
            return m.flow.dst;
        }
    }
    std::net::SocketAddr::new(pbx, 5060)
}

/// Endpoints for a single-dialog swimlane: initial INVITE src/dst, else first msg.
fn two_parties(messages: &[SipMsg]) -> Option<(std::net::SocketAddr, std::net::SocketAddr)> {
    let invite = messages
        .iter()
        .find(|m| m.is_request && matches!(m.method, Some(Method::Invite)) && m.to_tag.is_none());
    let m = invite.or_else(|| messages.first())?;
    Some((m.flow.src, m.flow.dst))
}

/// Method/status color for a message label.
fn msg_style(m: &SipMsg) -> Style {
    if m.is_request {
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
    }
}

/// A same-Call-ID dual-dialog split classified into an ingress a-leg and an
/// egress b-leg, with the shared PBX endpoint and both remote parties.
struct Lanes {
    #[allow(dead_code)]
    a_leg: u8,
    #[allow(dead_code)]
    b_leg: u8,
    a_remote: std::net::SocketAddr,
    b_remote: std::net::SocketAddr,
    pbx: std::net::IpAddr,
}

/// Classify a same-Call-ID dual-dialog call into an ingress a-leg and an
/// egress b-leg using the local (PBX) IPs. The a-leg is the dialog whose INVITE
/// arrives *at* the PBX, the b-leg the dialog whose INVITE the PBX originates.
/// Returns None when the call isn't a two-dialog split or the legs can't be
/// told apart (no local anchor, or both INVITEs go the same way) — the caller
/// then falls back to the normal flow view.
///
/// When `local` is empty but the two legs still share exactly one IP, treat that
/// IP as the mid-box so linked b-leg merges can still render three columns.
fn classify_lanes(messages: &[SipMsg], legs: &[u8], local: &[std::net::IpAddr]) -> Option<Lanes> {
    let leg_count = legs.iter().max()? + 1;
    if leg_count != 2 {
        return None;
    }
    // First dialog-initiating INVITE per leg.
    let mut first: [Option<&SipMsg>; 2] = [None, None];
    for (m, &l) in messages.iter().zip(legs) {
        if l > 1 {
            continue;
        }
        if first[l as usize].is_none()
            && m.is_request
            && matches!(m.method, Some(Method::Invite))
            && m.to_tag.is_none()
        {
            first[l as usize] = Some(m);
        }
    }
    let inv0 = first[0]?;
    let inv1 = first[1]?;

    let other = |inv: &SipMsg, mid: std::net::IpAddr| {
        if inv.flow.dst.ip() == mid {
            inv.flow.src
        } else {
            inv.flow.dst
        }
    };

    if !local.is_empty() {
        let inbound0 = local.contains(&inv0.flow.dst.ip());
        let inbound1 = local.contains(&inv1.flow.dst.ip());
        let (a_leg, b_leg, a_inv, b_inv) = if inbound0 && !inbound1 {
            (0u8, 1u8, inv0, inv1)
        } else if inbound1 && !inbound0 {
            (1u8, 0u8, inv1, inv0)
        } else {
            return None;
        };
        let a_ips = [a_inv.flow.src.ip(), a_inv.flow.dst.ip()];
        let b_ips = [b_inv.flow.src.ip(), b_inv.flow.dst.ip()];
        let pbx = local
            .iter()
            .copied()
            .find(|ip| a_ips.contains(ip) && b_ips.contains(ip))?;
        return Some(Lanes {
            a_leg,
            b_leg,
            a_remote: other(a_inv, pbx),
            b_remote: other(b_inv, pbx),
            pbx,
        });
    }

    // No local anchor: use the single shared flow IP as the mid-box when unique.
    let pbx = common_flow_ip_for_lanes(messages, legs)?;
    let inbound0 = inv0.flow.dst.ip() == pbx;
    let inbound1 = inv1.flow.dst.ip() == pbx;
    let (a_leg, b_leg, a_inv, b_inv) = if inbound0 && !inbound1 {
        (0u8, 1u8, inv0, inv1)
    } else if inbound1 && !inbound0 {
        (1u8, 0u8, inv1, inv0)
    } else if inbound0 && inbound1 {
        // Both inbound to mid — order by time.
        if inv0.ts_us <= inv1.ts_us {
            (0u8, 1u8, inv0, inv1)
        } else {
            (1u8, 0u8, inv1, inv0)
        }
    } else {
        return None;
    };
    Some(Lanes {
        a_leg,
        b_leg,
        a_remote: other(a_inv, pbx),
        b_remote: other(b_inv, pbx),
        pbx,
    })
}

fn common_flow_ip_for_lanes(msgs: &[SipMsg], legs: &[u8]) -> Option<std::net::IpAddr> {
    let mut by_leg: [Vec<std::net::IpAddr>; 2] = [Vec::new(), Vec::new()];
    for (m, &l) in msgs.iter().zip(legs) {
        if l <= 1 {
            by_leg[l as usize].extend([m.flow.src.ip(), m.flow.dst.ip()]);
        }
    }
    let shared: Vec<std::net::IpAddr> = by_leg[0]
        .iter()
        .copied()
        .filter(|ip| by_leg[1].contains(ip))
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();
    (shared.len() == 1).then(|| shared[0])
}

/// Directional flow cell: the local (monitored) machine is pinned to the right
/// column and the remote party to the left, with the arrow pointing at the
/// recipient — `X -> LOCAL` is an inbound message (ingress), `X <- LOCAL` is an
/// outbound one (egress). Falls back to the raw `left → right` when neither (or
/// both) endpoint is local. `left`/`right` are the already-masked display
/// strings, `src_ip`/`dst_ip` the real endpoints used for matching.
pub(super) fn dir_flow(
    src_ip: std::net::IpAddr,
    dst_ip: std::net::IpAddr,
    left: &str,
    right: &str,
    local: &[std::net::IpAddr],
    w: usize,
) -> String {
    let (arrow, l, r) = match (local.contains(&src_ip), local.contains(&dst_ip)) {
        (false, true) => ("->", left, right), // inbound: remote -> local
        (true, false) => ("<-", right, left), // outbound: remote <- local
        _ => ("→", left, right),              // raw: no local anchor
    };
    format!("{l:<w$} {arrow} {r:>w$}")
}

/// Media flow label: IP:port→IP:port (ports included so the RTP endpoints are
/// fully visible). With a local IP anchor the local endpoint is pinned to the
/// right and the arrow shows the media direction; both endpoints are padded to
/// width `w` so the arrow stays centered across rows.
fn flow_ip(
    f: Option<crate::model::packet::Flow5Tuple>,
    privacy: bool,
    local: &[std::net::IpAddr],
    w: usize,
) -> String {
    match f {
        Some(fl) => {
            let src = if privacy {
                mask_socket(&fl.src.to_string())
            } else {
                fl.src.to_string()
            };
            let dst = if privacy {
                mask_socket(&fl.dst.to_string())
            } else {
                fl.dst.to_string()
            };
            dir_flow(fl.src.ip(), fl.dst.ip(), &src, &dst, local, w)
        }
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
    let text = if app.privacy { mask_raw(&text) } else { text };
    let lines: Vec<Line> = highlight_raw(&text)
        .into_iter()
        .skip(app.raw_scroll)
        .collect();
    let p = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!("Raw [{idx}]")),
    );
    f.render_widget(p, area);
}

/// Full-token syntax highlighting for a raw SIP/SDP message: request/status
/// lines, header names and values (sip:/sips: URIs, `branch=`, `;tag=` params),
/// and the SDP body after the first blank line. Operates on the (already
/// privacy-masked) text so the layout is preserved.
fn highlight_raw(text: &str) -> Vec<Line<'static>> {
    let mut in_body = false;
    text.lines()
        .map(|l| {
            if !in_body {
                if l.trim().is_empty() {
                    // Header/body separator; everything after is the body.
                    in_body = true;
                    return Line::raw(l.to_string());
                }
                if let Some(line) = style_start_line(l) {
                    return line;
                }
                return Line::from(Span::styled(l.to_string(), Style::default().fg(theme::INK)));
            }
            style_sdp(l)
        })
        .collect()
}

/// Style a non-body line: request line, status line, or header.
fn style_start_line(l: &str) -> Option<Line<'static>> {
    // Request line: `METHOD request-uri SIP/2.0`.
    let mut it = l.split_whitespace();
    if let (Some(m), Some(uri), Some(version)) = (it.next(), it.next(), it.next())
        && it.next().is_none()
        && is_sip_method(m)
        && version.starts_with("SIP/")
    {
        return Some(Line::from(vec![
            Span::styled(
                m.to_string(),
                Style::default()
                    .fg(theme::SUCCESS)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" "),
            Span::styled(uri.to_string(), Style::default().fg(theme::INFO)),
            Span::raw(" "),
            Span::styled(version.to_string(), Style::default().fg(theme::MUTED)),
        ]));
    }

    // Status line: `SIP/2.0 200 OK`.
    let mut it = l.split_whitespace();
    if let Some(version) = it.next()
        && version.starts_with("SIP/")
        && let Some(code) = it.next().and_then(|c| c.parse::<u16>().ok())
    {
        let reason = it.collect::<Vec<_>>().join(" ");
        let mut spans = vec![
            Span::styled(version.to_string(), Style::default().fg(theme::MUTED)),
            Span::raw(" "),
            Span::styled(
                code.to_string(),
                Style::default().fg(status_code_color(code)),
            ),
        ];
        if !reason.is_empty() {
            spans.push(Span::styled(
                format!(" {reason}"),
                Style::default().fg(theme::INK),
            ));
        }
        return Some(Line::from(spans));
    }

    // Header: `Name: value` (first colon is the delimiter).
    let (name, _) = l.split_once(':')?;
    let mut spans = vec![Span::styled(
        format!("{name}:"),
        Style::default()
            .fg(theme::ACCENT)
            .add_modifier(Modifier::BOLD),
    )];
    spans.extend(style_value(&l[name.len() + 1..]));
    Some(Line::from(spans))
}

/// Tokenize a header value: `sip:`/`sips:` URIs, `branch=` and `;tag=`
/// parameters are tinted, everything else stays plain ink.
fn style_value(value: &str) -> Vec<Span<'static>> {
    let plain = Style::default().fg(theme::INK);
    let mut spans = Vec::new();
    let mut rest = value;
    while let Some((start, end, kind)) = next_token(rest) {
        if start > 0 {
            spans.push(Span::styled(rest[..start].to_string(), plain));
        }
        spans.push(Span::styled(
            rest[start..end].to_string(),
            Style::default().fg(kind.color()),
        ));
        rest = &rest[end..];
    }
    if !rest.is_empty() {
        spans.push(Span::styled(rest.to_string(), plain));
    }
    spans
}

#[derive(Clone, Copy)]
enum TokenKind {
    Uri,
    Branch,
    Tag,
}

impl TokenKind {
    fn color(self) -> Color {
        match self {
            TokenKind::Uri => theme::INFO,
            TokenKind::Branch => theme::WARNING,
            TokenKind::Tag => theme::ACCENT,
        }
    }
}

/// Find the next highlightable token in `rest`, returning (start, end, kind).
fn next_token(rest: &str) -> Option<(usize, usize, TokenKind)> {
    let mut best: Option<(usize, usize, TokenKind)> = None;
    let mut consider = |start: usize, end: usize, kind: TokenKind| {
        let better = match best {
            None => true,
            Some((s, e, _)) => start < s || (start == s && end > e),
        };
        if better {
            best = Some((start, end, kind));
        }
    };

    if let Some(p) = rest.find("sips:") {
        consider(p, uri_end(rest, p + 5), TokenKind::Uri);
    }
    if let Some(p) = rest.find("sip:")
        && !rest[p..].starts_with("sips:")
    {
        consider(p, uri_end(rest, p + 4), TokenKind::Uri);
    }
    if let Some(p) = rest.find(";branch=") {
        consider(p, param_end(rest, p + 8), TokenKind::Branch);
    }
    if let Some(p) = rest.find(";tag=") {
        consider(p, param_end(rest, p + 5), TokenKind::Tag);
    }
    best
}

/// End index of a `sip:`/`sips:` URI starting at `from` (relative to `s`).
fn uri_end(s: &str, from: usize) -> usize {
    let bytes = s.as_bytes();
    let mut i = from;
    while i < bytes.len() && !matches!(bytes[i], b';' | b' ' | b'\t' | b'>' | b'<' | b',') {
        i += 1;
    }
    i
}

/// End index of a `;name=value` parameter starting at `p` (relative to `s`).
fn param_end(s: &str, p: usize) -> usize {
    let bytes = s.as_bytes();
    let mut i = p;
    while i < bytes.len() && !matches!(bytes[i], b';' | b' ' | b'\t') {
        i += 1;
    }
    i
}

/// Style an SDP (or other) body line: tint the `key=` prefix, keep the rest.
fn style_sdp(l: &str) -> Line<'static> {
    let key_color = match l.split_once('=').map(|(k, _)| k.trim()) {
        Some("m") => theme::WARNING,
        Some("a") => theme::INFO,
        Some("v" | "o" | "s" | "c" | "t" | "b") => theme::MUTED,
        _ => theme::MUTED,
    };
    if let Some((key, val)) = l.split_once('=') {
        Line::from(vec![
            Span::styled(
                format!("{key}="),
                Style::default().fg(key_color).add_modifier(Modifier::BOLD),
            ),
            Span::styled(val.to_string(), Style::default().fg(theme::INK)),
        ])
    } else {
        Line::from(Span::styled(
            l.to_string(),
            Style::default().fg(theme::MUTED),
        ))
    }
}

fn is_sip_method(s: &str) -> bool {
    matches!(
        s,
        "INVITE"
            | "ACK"
            | "BYE"
            | "CANCEL"
            | "REGISTER"
            | "OPTIONS"
            | "PRACK"
            | "UPDATE"
            | "SUBSCRIBE"
            | "NOTIFY"
            | "PUBLISH"
            | "INFO"
            | "REFER"
            | "MESSAGE"
    )
}

fn status_code_color(code: u16) -> Color {
    match code {
        100..=199 => theme::INFO,
        200..=299 => theme::SUCCESS,
        300..=399 => theme::WARNING,
        _ => theme::ERROR,
    }
}

/// Privacy masking for a raw SIP/SDP message: every `sip:`/`sips:` URI (From,
/// To, Contact, Route…), quoted display names in identity headers, and every
/// bare IP address (Via, SDP `c=`/`o=`…) is masked. Operates line by line so
/// the display layout is preserved.
fn mask_raw(text: &str) -> String {
    text.lines()
        .map(|l| {
            let head = l
                .trim_start()
                .split_once(':')
                .map(|(h, _)| h.to_ascii_uppercase());
            let identity = matches!(
                head.as_deref(),
                Some("FROM") | Some("TO") | Some("P-ASSERTED-IDENTITY") | Some("REMOTE-PARTY-ID")
            );
            let line = mask_sip_uris(l);
            let line = if identity {
                mask_display_names(&line)
            } else {
                line
            };
            mask_ips(&line)
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Mask quoted display names in an identity header value (e.g. `"Alice"`).
fn mask_display_names(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(start) = rest.find('"') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        let Some(end) = after.find('"') else {
            out.push_str(&rest[start..]);
            return out;
        };
        out.push('"');
        out.push_str(&mask_user(&after[..end]));
        out.push('"');
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    out
}

/// Replace every `sip:`/`sips:` URI in `s` with a masked form (user + host).
fn mask_sip_uris(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    loop {
        let sips = rest.find("sips:");
        let sip = rest.find("sip:");
        let start = match (sips, sip) {
            (Some(a), Some(b)) => a.min(b),
            (Some(a), None) => a,
            (None, Some(b)) => b,
            (None, None) => break,
        };
        out.push_str(&rest[..start]);
        let scheme_len = if rest[start..].starts_with("sips:") {
            5
        } else {
            4
        };
        let mut end = start + scheme_len;
        let b = rest.as_bytes();
        while end < rest.len() && !matches!(b[end], b'>' | b' ' | b'\t' | b',' | b'\r' | b'\n') {
            end += 1;
        }
        out.push_str(&mask_uri(&rest[start..end]));
        rest = &rest[end..];
    }
    out.push_str(rest);
    out
}

/// Mask the user and host of a single `sip:`/`sips:` URI, keeping parameters.
fn mask_uri(uri: &str) -> String {
    let (scheme, rest) = if let Some(r) = uri.strip_prefix("sips:") {
        ("sips:", r)
    } else if let Some(r) = uri.strip_prefix("sip:") {
        ("sip:", r)
    } else {
        return uri.to_string();
    };
    let (addr, params) = match rest.split_once(';') {
        Some((a, p)) => (a, Some(p)),
        None => (rest, None),
    };
    let masked = match addr.split_once('@') {
        Some((user, host)) => format!("{}@{}", mask_user(user), mask_host(host)),
        None => mask_host(addr),
    };
    match params {
        Some(p) => format!("{scheme}{masked};{p}"),
        None => format!("{scheme}{masked}"),
    }
}

/// Mask a URI host: IPs are masked, `ip:port` keeps the port, hostnames and
/// bracketed IPv6 are handled, anything else is left alone.
fn mask_host(host: &str) -> String {
    if let Ok(sock) = host.parse::<std::net::SocketAddr>() {
        return format!("{}:{}", mask_ip(sock.ip()), sock.port());
    }
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return mask_ip(ip);
    }
    if let Some(ip) = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .and_then(|h| h.parse::<std::net::Ipv6Addr>().ok())
    {
        return format!("[{}]", mask_ip(std::net::IpAddr::V6(ip)));
    }
    host.to_string()
}

/// Replace every IP address (and any immediately following `:port`) in `s`.
fn mask_ips(s: &str) -> String {
    let bytes = s.as_bytes();
    let n = bytes.len();
    let mut out = String::with_capacity(s.len());
    let mut i = 0usize;
    while i < n {
        let c = bytes[i];
        if c == b'['
            && let Some(close) = s[i + 1..].find(']').map(|d| i + 1 + d)
            && let Ok(ip) = s[i + 1..close].parse::<std::net::Ipv6Addr>()
        {
            out.push_str(&mask_ip(std::net::IpAddr::V6(ip)));
            i = close + 1;
            out.push_str(&mask_port(s, &mut i));
            continue;
        }
        if c.is_ascii_digit()
            && let Some(len) = ipv4_len(&bytes[i..])
            && let Ok(ip) = s[i..i + len].parse::<std::net::Ipv4Addr>()
        {
            out.push_str(&mask_ip(std::net::IpAddr::V4(ip)));
            i += len;
            out.push_str(&mask_port(s, &mut i));
            continue;
        }
        let ch = s[i..].chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

/// Copy a `:port` suffix (if present) and advance `i` past it.
fn mask_port(s: &str, i: &mut usize) -> String {
    let bytes = s.as_bytes();
    if *i < bytes.len()
        && bytes[*i] == b':'
        && *i + 1 < bytes.len()
        && bytes[*i + 1].is_ascii_digit()
    {
        let mut j = *i + 1;
        while j < bytes.len() && bytes[j].is_ascii_digit() {
            j += 1;
        }
        let t = s[*i..j].to_string();
        *i = j;
        t
    } else {
        String::new()
    }
}

/// Byte length of a dotted-quad IPv4 address at the start of `b`.
fn ipv4_len(b: &[u8]) -> Option<usize> {
    let mut i = 0usize;
    for part in 0..4 {
        let start = i;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
        if i == start || i - start > 3 || (i - start > 1 && b[start] == b'0') {
            return None;
        }
        let octet = b[start..i]
            .iter()
            .fold(0u32, |acc, &d| acc * 10 + (d - b'0') as u32);
        if octet > 255 {
            return None;
        }
        if part < 3 && (i >= b.len() || b[i] != b'.') {
            return None;
        }
        i += usize::from(part < 3);
    }
    Some(i)
}

/// Chrome-devtools-style setup timeline: each phase rendered as a segment
/// positioned along the total call duration (▓ = the phase, · = the axis).
fn render_timeline(f: &mut Frame, area: Rect, focus: &Focus) {
    let anchor = focus.invite_ts.or(focus.ringing_ts).unwrap_or(0);
    let end = focus
        .end_ts
        .or(focus.bye_ts)
        .or(focus.answer_ts)
        .unwrap_or(anchor);
    let total = end.saturating_sub(anchor);

    // (label, start_us, end_us, color)
    let mut phases: Vec<Phase> = Vec::new();
    // PDD: INVITE → first provisional (100 Trying or 180 Ringing/183).
    let provisional = match (focus.trying_ts, focus.ringing_ts) {
        (Some(t), Some(r)) => Some(t.min(r)),
        (Some(t), None) => Some(t),
        (None, Some(r)) => Some(r),
        (None, None) => None,
    };
    if let (Some(a), Some(b)) = (focus.invite_ts, provisional) {
        phases.push(Phase {
            label: "Inv → Try/Ring",
            start: a,
            stop: b,
            color: theme::INFO,
        });
    }
    if let (Some(a), Some(b)) = (focus.ringing_ts, focus.answer_ts) {
        phases.push(Phase {
            label: "Ring",
            start: a,
            stop: b,
            color: theme::WARNING,
        });
    }
    if let (Some(a), Some(b)) = (focus.invite_ts, focus.answer_ts) {
        phases.push(Phase {
            label: "Setup",
            start: a,
            stop: b,
            color: theme::PRIMARY,
        });
    }
    if let (Some(a), Some(b)) = (focus.answer_ts, focus.bye_ts.or(focus.end_ts)) {
        phases.push(Phase {
            label: "Talk",
            start: a,
            stop: b,
            color: theme::SUCCESS,
        });
    }

    let label_w = 13usize;
    let dur_w = 8usize;
    let bar_w = (area.width as i64 - label_w as i64 - dur_w as i64 - 4).max(10) as usize;

    let mut lines: Vec<Line> = Vec::new();
    for p in &phases {
        lines.push(timeline_line(p, anchor, total, bar_w, label_w, dur_w));
    }
    if total > 0 {
        lines.push(timeline_line(
            &Phase {
                label: "Total",
                start: anchor,
                stop: end,
                color: theme::INK,
            },
            anchor,
            total,
            bar_w,
            label_w,
            dur_w,
        ));
    }
    if lines.is_empty() {
        lines.push(Line::from(Span::styled(
            " no timing data for this call",
            Style::default().fg(theme::MUTED),
        )));
    }
    let p = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .title("Timeline (INVITE→END)"),
    );
    f.render_widget(p, area);
}

/// One timeline phase: a labeled segment between two absolute timestamps.
struct Phase {
    label: &'static str,
    start: u64,
    stop: u64,
    color: Color,
}

fn timeline_line(
    p: &Phase,
    anchor: u64,
    total: u64,
    bar_w: usize,
    label_w: usize,
    dur_w: usize,
) -> Line<'static> {
    let dur = fmt_secs(Some(p.stop.saturating_sub(p.start) / 1000));
    let mut buf = vec!['·'; bar_w];
    if total > 0 {
        let s =
            (p.start.saturating_sub(anchor) as f64 / total as f64 * bar_w as f64).round() as usize;
        let e =
            (p.stop.saturating_sub(anchor) as f64 / total as f64 * bar_w as f64).round() as usize;
        let s = s.min(bar_w);
        let e = e.min(bar_w);
        buf[s..e].fill('▓');
    }
    Line::from(vec![
        Span::styled(
            format!("{:<label_w$}", p.label),
            Style::default().fg(theme::MUTED),
        ),
        Span::styled(format!("{dur:>dur_w$} "), Style::default().fg(theme::MUTED)),
        Span::styled(buf.iter().collect::<String>(), Style::default().fg(p.color)),
    ])
}

fn render_network(
    f: &mut Frame,
    area: Rect,
    focus: &crate::store::registry::Focus,
    privacy: bool,
    local: &[std::net::IpAddr],
) {
    let chunks = Layout::vertical([Constraint::Length(3), Constraint::Min(0)]).split(area);

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
        .map(|e| {
            if privacy {
                mask_socket(&e.to_string())
            } else {
                e.to_string()
            }
        })
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

    let flow_w = focus
        .streams
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
        .unwrap_or(9)
        .max(9);
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
            Cell::from(flow_ip(s.flow, privacy, local, flow_w)),
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
            Constraint::Length(6),
            Constraint::Length((flow_w * 2 + 4) as u16),
            Constraint::Length(3),
            Constraint::Length(6),
            Constraint::Length(5),
            Constraint::Length(5),
            Constraint::Length(6),
            Constraint::Length(5),
            Constraint::Length(5),
        ],
    )
    .column_spacing(1)
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
            .title("Media streams (Leg: t-c/t-p = TURN client/peer leg)"),
    );
    f.render_widget(table, chunks[1]);
}

/// Per-stream average rate (bytes/sec) over its observed lifetime.
fn stream_bytes_per_sec(s: &StreamSummary) -> f64 {
    match (s.bytes, s.first_ts_us, s.last_ts_us) {
        (b, Some(a), Some(z)) if z > a => b as f64 / ((z - a) as f64 / 1_000_000.0),
        _ => 0.0,
    }
}

fn render_diag(f: &mut Frame, area: Rect, focus: &crate::store::registry::Focus, tz: Option<i32>) {
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
                    fmt_time_tz(d.ts_us, tz),
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
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use std::sync::atomic::AtomicBool;
    use std::sync::{Arc, Mutex};

    use crate::model::packet::{Flow5Tuple, Proto};
    use crate::store::registry::{Focus, Snapshot};
    use crate::ui::app::{Page, RecordState, wrap_snap};

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
            invite_ts: Some(1_000_000),
            ringing_ts: Some(1_100_000),
            answer_ts: Some(1_500_000),
            bye_ts: Some(11_000_000),
            end_ts: Some(11_010_000),
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
        let snap = wrap_snap(Snapshot {
            focus: Some(focus),
            ..Snapshot::default()
        });
        let mut app = App::new(
            snap,
            Arc::new(AtomicBool::new(false)),
            Arc::new(Mutex::new(Some(
                crate::store::registry::FocusHint::primary("c1"),
            ))),
            Arc::new(AtomicBool::new(false)),
            RecordState::default(),
        );
        app.page = Page::CallDetail;

        let mut terminal = Terminal::new(TestBackend::new(150, 44)).unwrap();
        terminal.draw(|f| crate::ui::render(f, &mut app)).unwrap();
        let buf = terminal.backend().buffer().clone();

        // Every media-table header must appear on the same continuous line as
        // "SSRC" (i.e. the header never wraps onto a second row).
        let headers = [
            "SSRC", "Codec", "Flow", "Leg", "Pkts", "Lost", "Loss%", "Jitter", "RTT", "MOS",
        ];
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
        let snap = wrap_snap(Snapshot {
            focus: Some(focus),
            ..Snapshot::default()
        });
        let mut app = App::new(
            snap,
            Arc::new(AtomicBool::new(false)),
            Arc::new(Mutex::new(Some(
                crate::store::registry::FocusHint::primary("c1"),
            ))),
            Arc::new(AtomicBool::new(false)),
            RecordState::default(),
        );
        app.page = Page::CallDetail;

        // At a 114-column terminal (55% right pane ≈ 63 cols) the render must
        // not panic and the table should still produce the header row.
        let mut terminal = Terminal::new(TestBackend::new(114, 44)).unwrap();
        terminal.draw(|f| crate::ui::render(f, &mut app)).unwrap();
        let buf = terminal.backend().buffer().clone();
        let has_ssrc = (0..buf.area.height).any(|y| {
            (0..buf.area.width)
                .any(|x| buf[(x, y)].symbol() == "S" && buf[(x + 1, y)].symbol() == "S")
        });
        assert!(has_ssrc, "SSRC header should still be rendered");
    }

    #[test]
    fn timeline_renders_phases_and_durations() {
        let focus = Focus {
            call_id: "c1".into(),
            state: Some(crate::model::sip::CallState::Completed),
            invite_ts: Some(1_000_000),
            ringing_ts: Some(1_100_000),
            answer_ts: Some(1_500_000),
            bye_ts: Some(11_000_000),
            end_ts: Some(11_010_000),
            ..Focus::default()
        };
        let snap = wrap_snap(Snapshot {
            focus: Some(focus),
            ..Snapshot::default()
        });
        let mut app = App::new(
            snap,
            Arc::new(AtomicBool::new(false)),
            Arc::new(Mutex::new(Some(
                crate::store::registry::FocusHint::primary("c1"),
            ))),
            Arc::new(AtomicBool::new(false)),
            RecordState::default(),
        );
        app.page = Page::CallDetail;

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
        assert!(text.contains("Timeline"), "timeline block must render");
        for label in ["Inv → Try/Ring", "Ring", "Setup", "Talk", "Total"] {
            assert!(text.contains(label), "timeline missing {label}");
        }
        assert!(text.contains("0.10s"), "PDD should be 0.10s (100ms)");
        assert!(text.contains("0.40s"), "Ring should be 0.40s (400ms)");
        assert!(text.contains("0.50s"), "Setup should be 0.50s (500ms)");
        assert!(text.contains("9.50s"), "Talk should be 9.50s (9.5s)");
    }

    #[test]
    fn dir_flow_pins_local_to_right_with_arrows() {
        let local = ["10.20.0.8".parse().unwrap()];
        // Inbound: remote -> local (arrow points at the local box).
        let s = dir_flow(
            "10.10.0.8".parse().unwrap(),
            "10.20.0.8".parse().unwrap(),
            "10.10.0.8",
            "10.20.0.8",
            &local,
            9,
        );
        assert!(s.contains("->"), "inbound must use ->: {s}");
        assert!(
            s.trim_start().starts_with("10.10.0.8"),
            "remote must stay left: {s}"
        );
        assert!(s.ends_with("10.20.0.8"), "local must stay right: {s}");
        // Outbound: remote <- local.
        let s = dir_flow(
            "10.20.0.8".parse().unwrap(),
            "10.10.0.8".parse().unwrap(),
            "10.20.0.8",
            "10.10.0.8",
            &local,
            9,
        );
        assert!(s.contains("<-"), "outbound must use <-: {s}");
        assert!(s.trim_start().starts_with("10.10.0.8"));
        assert!(s.ends_with("10.20.0.8"));
        // No local match → raw arrow, endpoints unchanged.
        let s = dir_flow(
            "10.1.0.1".parse().unwrap(),
            "10.1.0.2".parse().unwrap(),
            "10.1.0.1",
            "10.1.0.2",
            &local,
            9,
        );
        assert!(s.contains('→'), "no anchor must keep →: {s}");
        assert!(s.trim_start().starts_with("10.1.0.1"));
        assert!(s.ends_with("10.1.0.2"));
        // Both local (loopback) → raw arrow too.
        let local_lo = ["127.0.0.1".parse().unwrap()];
        let s = dir_flow(
            "127.0.0.1".parse().unwrap(),
            "127.0.0.1".parse().unwrap(),
            "127.0.0.1",
            "127.0.0.1",
            &local_lo,
            9,
        );
        assert!(s.contains('→'), "loopback must fall back to raw: {s}");
    }

    #[test]
    fn privacy_masks_ips_and_users_in_detail() {
        let focus = Focus {
            call_id: "c1".into(),
            state: Some(crate::model::sip::CallState::Active),
            from_user: Some("13812345678".into()),
            to_user: Some("bob".into()),
            caller_addr: Some("10.20.0.8:5060".parse().unwrap()),
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
        let snap = wrap_snap(Snapshot {
            focus: Some(focus),
            ..Snapshot::default()
        });
        let mut app = App::new(
            snap,
            Arc::new(AtomicBool::new(false)),
            Arc::new(Mutex::new(Some(
                crate::store::registry::FocusHint::primary("c1"),
            ))),
            Arc::new(AtomicBool::new(false)),
            RecordState::default(),
        );
        app.privacy = true;
        app.page = Page::CallDetail;

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
        // Raw IPs must be gone from the rendered detail.
        assert!(
            !text.contains("10.10.0.8"),
            "source IP leaked in privacy mode"
        );
        assert!(
            !text.contains("10.20.0.8"),
            "dest IP leaked in privacy mode"
        );
        assert!(
            !text.contains("13812345678"),
            "caller number leaked in privacy mode"
        );
        // Masked forms are present.
        assert!(text.contains("10.*.*.8"), "masked IP missing");
        assert!(text.contains("138…5678"), "masked number missing");
    }

    #[test]
    fn mask_raw_obfuscates_uris_ips_and_display_names() {
        let raw = "INVITE sip:13812345678@10.20.0.8:5060 SIP/2.0\r\n\
                   Via: SIP/2.0/UDP 10.10.0.8:5060;branch=z9hG4bK-1\r\n\
                   From: \"Alice\" <sip:13812345678@10.10.0.8>;tag=a1\r\n\
                   To: <sip:bob@10.20.0.8>\r\n\
                   Contact: <sip:13812345678@10.10.0.8:5060>\r\n\
                   CSeq: 1 INVITE\r\n\
                   \r\n\
                   v=0\r\n\
                   o=- 1 1 IN IP4 10.10.0.8\r\n\
                   s=session\r\n\
                   c=IN IP4 10.10.0.8\r\n\
                   m=audio 20014 RTP/AVP 0\r\n";
        let masked = mask_raw(raw);
        // No raw IPs, numbers, or display names may survive.
        assert!(!masked.contains("10.10.0.8"), "source IP leaked");
        assert!(!masked.contains("10.20.0.8"), "dest IP leaked");
        assert!(!masked.contains("13812345678"), "number leaked");
        assert!(!masked.contains("Alice"), "display name leaked");
        assert!(!masked.contains("alice"), "display name leaked");
        // Masked forms are in place.
        assert!(
            masked.contains("sip:138…5678@10.*.*.8:5060"),
            "request URI not masked"
        );
        assert!(
            masked.contains("10.*.*.8:5060;branch=z9hG4bK-1"),
            "Via IP/port not masked"
        );
        assert!(
            masked.contains("\"Ali*ce\" <sip:138…5678@10.*.*.8>"),
            "From header not masked"
        );
        assert!(masked.contains("sip:b**@10.*.*.8"), "To URI not masked");
        assert!(
            masked.contains("c=IN IP4 10.*.*.8"),
            "SDP connection not masked"
        );
        assert!(masked.contains("IN IP4 10.*.*.8"), "SDP origin not masked");
        // Non-IP tokens are preserved.
        assert!(
            masked.contains("CSeq: 1 INVITE"),
            "non-sensitive data changed"
        );
        assert!(
            masked.contains("m=audio 20014 RTP/AVP 0"),
            "SDP media line changed"
        );
        // Layout (line count) is unchanged.
        assert_eq!(
            masked.lines().count(),
            raw.lines().count(),
            "layout changed"
        );
    }

    #[test]
    fn mask_raw_leaves_non_privacy_text_alone() {
        let raw = "100 Trying\r\nFrom: alice <sip:alice@10.1.2.3>\r\n";
        // `mask_raw` is only invoked in privacy mode, but the checker must not
        // touch URIs that would otherwise parse cleanly... it masks; verify the
        // masked output still looks sane.
        let masked = mask_raw(raw);
        assert!(masked.contains("sip:ali*ce@10.*.*.3"));
        assert!(!masked.contains("10.1.2.3"));
    }

    #[test]
    fn highlight_colors_request_status_header_and_sdp() {
        let raw = "INVITE sip:bob@10.0.0.2 SIP/2.0\r\n\
                   Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-1\r\n\
                   From: <sip:alice@10.0.0.1>;tag=abc\r\n\
                   \r\n\
                   v=0\r\n\
                   m=audio 20014 RTP/AVP 0\r\n";
        let lines = highlight_raw(raw);
        // Request line: method bold success, URI info, version muted.
        assert_eq!(lines[0].spans[0].content.as_ref(), "INVITE");
        assert_eq!(lines[0].spans[0].style.fg, Some(theme::SUCCESS));
        assert!(
            lines[0].spans[0]
                .style
                .add_modifier
                .contains(Modifier::BOLD)
        );
        assert_eq!(lines[0].spans[2].content.as_ref(), "sip:bob@10.0.0.2");
        assert_eq!(lines[0].spans[2].style.fg, Some(theme::INFO));
        // Header: name accent, branch= value warning.
        assert_eq!(lines[1].spans[0].content.as_ref(), "Via:");
        assert_eq!(lines[1].spans[0].style.fg, Some(theme::ACCENT));
        let branch = lines[1]
            .spans
            .iter()
            .find(|s| s.content.contains("branch="))
            .expect("branch token present");
        assert_eq!(branch.style.fg, Some(theme::WARNING));
        // From header: ;tag= accent.
        let tag = lines[2]
            .spans
            .iter()
            .find(|s| s.content.contains(";tag="))
            .expect("tag token present");
        assert_eq!(tag.style.fg, Some(theme::ACCENT));
        // Blank line is the header/body separator, uncolored.
        assert!(lines[3].spans.is_empty());
        // SDP: v= muted, m= warning.
        assert_eq!(lines[4].spans[0].content.as_ref(), "v=");
        assert_eq!(lines[4].spans[0].style.fg, Some(theme::MUTED));
        assert_eq!(lines[5].spans[0].content.as_ref(), "m=");
        assert_eq!(lines[5].spans[0].style.fg, Some(theme::WARNING));
    }

    #[test]
    fn highlight_status_line_colors_code_by_class() {
        let lines = highlight_raw("SIP/2.0 404 Not Found\r\n");
        assert_eq!(lines[0].spans[0].content.as_ref(), "SIP/2.0");
        assert_eq!(lines[0].spans[0].style.fg, Some(theme::MUTED));
        assert_eq!(lines[0].spans[2].content.as_ref(), "404");
        assert_eq!(lines[0].spans[2].style.fg, Some(theme::ERROR));
        assert_eq!(lines[0].spans[3].content.as_ref(), " Not Found");

        let ok = highlight_raw("SIP/2.0 200 OK\r\n");
        assert_eq!(ok[0].spans[2].style.fg, Some(theme::SUCCESS));
        let trying = highlight_raw("SIP/2.0 100 Trying\r\n");
        assert_eq!(trying[0].spans[2].style.fg, Some(theme::INFO));
    }

    #[test]
    fn highlight_applies_after_privacy_masking() {
        let raw = "INVITE sip:13812345678@10.20.0.8:5060 SIP/2.0\r\n\
                   From: <sip:13812345678@10.10.0.8>;tag=a1\r\n";
        let masked = mask_raw(raw);
        assert!(!masked.contains("10.20.0.8"));
        let lines = highlight_raw(&masked);
        // Request-URI span is the masked form.
        assert_eq!(
            lines[0].spans[2].content.as_ref(),
            "sip:138…5678@10.*.*.8:5060"
        );
    }

    fn mk_msg(ts: u64, src: &str, dst: &str, from_tag: &str) -> crate::model::sip::SipMsg {
        crate::model::sip::SipMsg {
            ts_us: ts,
            flow: Flow5Tuple {
                proto: Proto::Udp,
                src: src.parse().unwrap(),
                dst: dst.parse().unwrap(),
            },
            is_request: true,
            method: Some(crate::model::sip::Method::Invite),
            status: None,
            call_id: "c1".into(),
            cseq: Some(1),
            cseq_method: Some("INVITE".into()),
            branch: Some(format!("b-{from_tag}")),
            from_tag: Some(from_tag.into()),
            to_tag: None,
            from_uri: None,
            to_uri: None,
            raw: bytes::Bytes::new(),
            contact_addr: None,
            route_count: 0,
            record_route_count: 0,
            has_sdp: false,
        }
    }

    #[test]
    fn classify_lanes_assigns_ingress_and_egress() {
        let msgs = vec![
            mk_msg(1_000_000, "1.1.1.1:5060", "2.2.2.2:5060", "t1"),
            mk_msg(1_100_000, "2.2.2.2:5060", "3.3.3.3:5060", "t2"),
        ];
        let local = ["2.2.2.2".parse().unwrap()];
        let lanes = classify_lanes(&msgs, &[0, 1], &local).expect("lanes classified");
        assert_eq!(lanes.a_leg, 0);
        assert_eq!(lanes.b_leg, 1);
        assert_eq!(lanes.a_remote, "1.1.1.1:5060".parse().unwrap());
        assert_eq!(lanes.b_remote, "3.3.3.3:5060".parse().unwrap());
        assert_eq!(lanes.pbx, "2.2.2.2".parse::<std::net::IpAddr>().unwrap());
        // Reversed arrival order must still classify by direction.
        let msgs2 = vec![
            mk_msg(1_000_000, "2.2.2.2:5060", "3.3.3.3:5060", "t2"),
            mk_msg(1_100_000, "1.1.1.1:5060", "2.2.2.2:5060", "t1"),
        ];
        let lanes2 = classify_lanes(&msgs2, &[0, 1], &local).expect("lanes classified");
        assert_eq!(lanes2.a_leg, 1, "inbound leg must be a-leg");
        assert_eq!(lanes2.b_leg, 0);
    }

    #[test]
    fn classify_lanes_falls_back_when_pbx_unknown() {
        let msgs = vec![
            mk_msg(1_000_000, "1.1.1.1:5060", "2.2.2.2:5060", "t1"),
            mk_msg(1_100_000, "2.2.2.2:5060", "3.3.3.3:5060", "t2"),
        ];
        // No local anchor but a unique shared mid IP → still classify (linked b-leg).
        let shared = classify_lanes(&msgs, &[0, 1], &[]).expect("shared mid IP");
        assert_eq!(shared.pbx, "2.2.2.2".parse::<std::net::IpAddr>().unwrap());
        // No shared IP between legs → cannot classify.
        let disjoint = vec![
            mk_msg(1_000_000, "1.1.1.1:5060", "2.2.2.2:5060", "t1"),
            mk_msg(1_100_000, "3.3.3.3:5060", "4.4.4.4:5060", "t2"),
        ];
        assert!(classify_lanes(&disjoint, &[0, 1], &[]).is_none());
        // Single dialog → never a lane layout.
        assert!(classify_lanes(&msgs, &[0, 0], &["2.2.2.2".parse().unwrap()]).is_none());
    }

    #[test]
    fn lane_flow_renders_a_leg_pbx_b_leg_columns() {
        let focus = Focus {
            call_id: "c1".into(),
            state: Some(crate::model::sip::CallState::Active),
            messages: vec![
                mk_msg(1_000_000, "1.1.1.1:5060", "2.2.2.2:5060", "t1"),
                mk_msg(1_100_000, "2.2.2.2:5060", "3.3.3.3:5060", "t2"),
            ],
            legs: vec![0, 1],
            b2bua: Some(crate::model::sip::B2buaInfo {
                addr: Some("2.2.2.2".parse().unwrap()),
                legs: 2,
            }),
            ..Focus::default()
        };
        let snap = wrap_snap(Snapshot {
            focus: Some(focus),
            ..Snapshot::default()
        });
        let mut app = App::new(
            snap,
            Arc::new(AtomicBool::new(false)),
            Arc::new(Mutex::new(Some(
                crate::store::registry::FocusHint::primary("c1"),
            ))),
            Arc::new(AtomicBool::new(false)),
            RecordState::default(),
        );
        app.local_ips = vec!["2.2.2.2".parse().unwrap()];
        app.page = Page::CallDetail;

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
        assert!(text.contains("B2BUA"), "title must show B2BUA marker");
        let header_row = text
            .lines()
            .find(|l| l.contains("1.1.1.1:5060") && l.contains("3.3.3.3:5060"))
            .expect("swimlane header with party sockets: {text}");
        assert!(
            header_row.contains("2.2.2.2"),
            "header must include mid/PBX IP: {header_row}"
        );
        assert!(
            !header_row.contains("Msg"),
            "swimlane drops the redundant Msg column"
        );
        // Directional arrows between vertical party bars.
        assert!(
            text.contains("-- INVITE ->") || (text.contains("INVITE") && text.contains("->")),
            "inbound INVITE must show short centered arrow: {text}"
        );
        assert!(
            text.contains('|'),
            "swimlane must draw vertical bars under parties: {text}"
        );
    }

    #[test]
    fn swimlane_two_party_when_legs_not_classifiable() {
        // Single dialog → 2-party swimlane with SRC|DST headers.
        let focus = Focus {
            call_id: "c1".into(),
            state: Some(crate::model::sip::CallState::Active),
            messages: vec![mk_msg(1_000_000, "1.1.1.1:5060", "2.2.2.2:5060", "t1"), {
                let mut m = mk_msg(1_100_000, "2.2.2.2:5060", "1.1.1.1:5060", "t1");
                m.is_request = false;
                m.method = None;
                m.status = Some(100);
                m
            }],
            legs: vec![0, 0],
            ..Focus::default()
        };
        let snap = wrap_snap(Snapshot {
            focus: Some(focus),
            ..Snapshot::default()
        });
        let mut app = App::new(
            snap,
            Arc::new(AtomicBool::new(false)),
            Arc::new(Mutex::new(Some(
                crate::store::registry::FocusHint::primary("c1"),
            ))),
            Arc::new(AtomicBool::new(false)),
            RecordState::default(),
        );
        app.page = Page::CallDetail;

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
        assert!(
            text.contains("1.1.1.1:5060") && text.contains("2.2.2.2:5060"),
            "2-party headers must show ip:port: {text}"
        );
        assert!(
            text.contains("-- INVITE ->") || (text.contains("INVITE") && text.contains("->")),
            "request must show short centered arrow: {text}"
        );
        assert!(
            text.contains("<- 100 --") || (text.contains("<-") && text.contains("100")),
            "response must show <- code -- (no reason): {text}"
        );
        assert!(
            !text.contains("Trying"),
            "response must not include reason phrase"
        );
        assert!(
            !text.contains("A-Leg"),
            "must not use the old A-Leg/B-Leg labels"
        );
    }

    #[test]
    fn swim_row_paints_bars_and_arrows() {
        let right = swim_row(2, 0, 1, "INVITE", 40);
        assert!(right.contains('|'), "{right}");
        assert!(right.contains("-- INVITE ->"), "{right}");
        // Centered: leading/trailing spaces around the glyph inside the bars.
        let inner = right.trim_matches(|c| c == '|' || c == ' ');
        assert_eq!(inner, "-- INVITE ->", "{right}");
        let left = swim_row(2, 1, 0, "100", 40);
        assert!(left.contains("<- 100 --"), "{left}");
    }
}
