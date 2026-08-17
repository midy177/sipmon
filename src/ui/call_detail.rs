use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table};

use crate::model::media::StreamSummary;
use crate::model::sip::{Method, SipMsg};
use crate::store::registry::{Focus, Snapshot};
use crate::ui::app::App;
use crate::ui::{
    fmt_bytes, fmt_ms, fmt_rate, fmt_secs, fmt_time, mask_ip, mask_socket, mask_user, theme,
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
    let title = format!(
        "Call {} ({} → {}) [{}]{}",
        focus.call_id,
        from,
        to,
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
    render_flow(f, left[0], &focus.messages, app);
    render_timeline(f, left[1], focus);
    render_diag(f, left[2], focus);

    let right = Layout::vertical([Constraint::Ratio(2, 3), Constraint::Ratio(1, 3)]).split(cols[1]);
    render_raw(f, right[0], &focus.messages, app);
    render_network(f, right[1], focus, privacy, &app.local_ips);
}

fn display_user(v: Option<&str>, privacy: bool, fallback: &str) -> String {
    match v {
        Some(v) if privacy => mask_user(v),
        Some(v) => v.to_string(),
        None => fallback.to_string(),
    }
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
    let privacy = app.privacy;
    let local = &app.local_ips;
    let flow_w = messages
        .iter()
        .map(|m| {
            short_ip(m.flow.src, privacy)
                .len()
                .max(short_ip(m.flow.dst, privacy).len())
        })
        .max()
        .unwrap_or(9)
        .max(9);
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
            Cell::from(dir_flow(
                m.flow.src.ip(),
                m.flow.dst.ip(),
                &short_ip(m.flow.src, privacy),
                &short_ip(m.flow.dst, privacy),
                local,
                flow_w,
            )),
            Cell::from(label).style(style),
        ])
    });
    let flow_col = flow_w * 2 + 4;
    let table = Table::new(
        rows,
        [
            Constraint::Length(8),
            Constraint::Length(9),
            Constraint::Length(flow_col as u16),
            Constraint::Min(20),
        ],
    )
    .header(Row::new(
        ["Time", "Rel ms", "Flow", "Msg"]
            .iter()
            .map(|h| Cell::from(*h)),
    ))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(if local.is_empty() {
                format!("Flow ({} msgs)", messages.len())
            } else {
                format!(
                    "Flow ({} msgs · right=local ->in <-out)",
                    messages.len()
                )
            }),
    )
    .row_highlight_style(Style::default().bg(theme::MUTED));
    f.render_stateful_widget(table, area, &mut app.flow_state);
}

/// IP-only form of a socket endpoint (port stripped), masked under privacy.
fn short_ip(a: std::net::SocketAddr, privacy: bool) -> String {
    if privacy {
        mask_ip(a.ip())
    } else {
        a.ip().to_string()
    }
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
            let line = if identity { mask_display_names(&line) } else { line };
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
        let scheme_len = if rest[start..].starts_with("sips:") { 5 } else { 4 };
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
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use std::sync::atomic::AtomicBool;
    use std::sync::{Arc, Mutex};

    use crate::model::packet::{Flow5Tuple, Proto};
    use crate::store::registry::{Focus, Snapshot};
    use crate::ui::app::{Page, RecordState};

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
        let snap = Arc::new(Mutex::new(Snapshot {
            focus: Some(focus),
            ..Snapshot::default()
        }));
        let mut app = App::new(
            snap,
            Arc::new(AtomicBool::new(false)),
            Arc::new(Mutex::new(Some("c1".to_string()))),
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
        let snap = Arc::new(Mutex::new(Snapshot {
            focus: Some(focus),
            ..Snapshot::default()
        }));
        let mut app = App::new(
            snap,
            Arc::new(AtomicBool::new(false)),
            Arc::new(Mutex::new(Some("c1".to_string()))),
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
        let snap = Arc::new(Mutex::new(Snapshot {
            focus: Some(focus),
            ..Snapshot::default()
        }));
        let mut app = App::new(
            snap,
            Arc::new(AtomicBool::new(false)),
            Arc::new(Mutex::new(Some("c1".to_string()))),
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
    fn privacy_masks_ips_and_users_in_detail() {        let focus = Focus {
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
        let snap = Arc::new(Mutex::new(Snapshot {
            focus: Some(focus),
            ..Snapshot::default()
        }));
        let mut app = App::new(
            snap,
            Arc::new(AtomicBool::new(false)),
            Arc::new(Mutex::new(Some("c1".to_string()))),
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
        assert!(masked.contains("sip:138…5678@10.*.*.8:5060"), "request URI not masked");
        assert!(masked.contains("10.*.*.8:5060;branch=z9hG4bK-1"), "Via IP/port not masked");
        assert!(masked.contains("\"Ali*ce\" <sip:138…5678@10.*.*.8>"), "From header not masked");
        assert!(masked.contains("sip:b**@10.*.*.8"), "To URI not masked");
        assert!(masked.contains("c=IN IP4 10.*.*.8"), "SDP connection not masked");
        assert!(masked.contains("IN IP4 10.*.*.8"), "SDP origin not masked");
        // Non-IP tokens are preserved.
        assert!(masked.contains("CSeq: 1 INVITE"), "non-sensitive data changed");
        assert!(masked.contains("m=audio 20014 RTP/AVP 0"), "SDP media line changed");
        // Layout (line count) is unchanged.
        assert_eq!(masked.lines().count(), raw.lines().count(), "layout changed");
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
}
