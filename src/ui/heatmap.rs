//! Page 4: SIP signaling stats. Top: per-IP request/response distribution
//! (INV/BYE/CANCEL/OPTIONS/INFO/other × 100/180/183/200/486/404/403/3xx/4xx/
//! 5xx/6xx/other). Bottom: INVITE answer-rate heatmap with a global ALL row
//! plus per-IP rows. Colors are relative to the window's global ASR baseline
//! so a naturally-low-ASR environment (e.g. 40% outbound) doesn't paint the
//! whole screen red — only real degradation stands out.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Style};
use ratatui::widgets::{Block, Borders, Cell, Row, Table};

use crate::store::registry::Snapshot;
use crate::store::sipstats::{REQ_LABELS, RESP_LABELS, SipIpRow};
use crate::ui::app::{App, SipSort};
use crate::ui::{fmt_time_tz, mask_ip, theme};

/// Samples below this per cell are shown dim gray: 1-2 invites can swing the
/// rate to 0/50/100% and would strobe the alarm colors.
const MIN_SAMPLES: u64 = 3;

pub fn render(f: &mut Frame, area: Rect, snap: &Snapshot, app: &mut App) {
    let chunks = Layout::vertical([
        Constraint::Length(3),
        Constraint::Percentage(55),
        Constraint::Min(0),
    ])
    .split(area);
    super::render_topbar(f, chunks[0], snap, app);
    let rows = ordered_rows(snap, app);
    render_distribution(f, chunks[1], snap, app, &rows);
    render_asr_heatmap(f, chunks[2], snap, app, &rows);
}

/// Per-IP rows (the global ALL row is fetched separately) ordered by the
/// current sort mode.
fn ordered_rows<'a>(snap: &'a Snapshot, app: &App) -> Vec<&'a SipIpRow> {
    let mut rows: Vec<&SipIpRow> = snap.sip_stats.iter().filter(|r| r.ip.is_some()).collect();
    let by_ip = |a: &SipIpRow, b: &SipIpRow| a.ip.cmp(&b.ip);
    match app.sip_sort {
        SipSort::Invites => rows.sort_by(|a, b| {
            b.stats.req[0]
                .cmp(&a.stats.req[0])
                .then_with(|| by_ip(a, b))
        }),
        SipSort::Errors => rows.sort_by(|a, b| {
            b.stats
                .resp_errors()
                .cmp(&a.stats.resp_errors())
                .then_with(|| by_ip(a, b))
        }),
        SipSort::Asr => rows.sort_by(|a, b| {
            let ka = a
                .stats
                .asr_pct(app.sip_window_secs)
                .unwrap_or(f64::INFINITY);
            let kb = b
                .stats
                .asr_pct(app.sip_window_secs)
                .unwrap_or(f64::INFINITY);
            ka.partial_cmp(&kb)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| by_ip(a, b))
        }),
    }
    rows
}

/// Compact counter: `·` for zero, k/M suffixes above 10k.
fn fmt_count(v: u64) -> String {
    if v == 0 {
        "·".into()
    } else if v < 10_000 {
        v.to_string()
    } else if v < 1_000_000 {
        format!("{:.1}k", v as f64 / 1_000.0)
    } else {
        format!("{:.1}M", v as f64 / 1_000_000.0)
    }
}

fn count_cell(v: u64, color: Color) -> Cell<'static> {
    if v == 0 {
        Cell::from("·").style(Style::default().fg(theme::MUTED))
    } else {
        Cell::from(fmt_count(v)).style(Style::default().fg(color))
    }
}

/// Response-column colors: 200 green, the specific failure codes (486/404/
/// 403/408/480) orange, the 4xx/5xx/6xx classes red. 487 (the normal CANCEL
/// response) stays neutral.
fn resp_color(col: usize) -> Color {
    match col {
        3 => theme::SUCCESS,
        4..=8 => theme::WARNING,
        11..=13 => theme::ERROR,
        _ => theme::INK,
    }
}

fn render_distribution(
    f: &mut Frame,
    area: Rect,
    snap: &Snapshot,
    app: &mut App,
    rows: &[&SipIpRow],
) {
    let all = snap.sip_stats.iter().find(|r| r.ip.is_none());

    let mut head = vec![Cell::from("IP")];
    head.extend(REQ_LABELS.iter().map(|l| Cell::from(*l)));
    head.extend(RESP_LABELS.iter().map(|l| Cell::from(*l)));
    let privacy = app.privacy;
    let mk_row = |r: &SipIpRow| {
        let label = match r.ip {
            None => "ALL".to_string(),
            Some(ip) if privacy => mask_ip(ip),
            Some(ip) => ip.to_string(),
        };
        let mut cells = vec![Cell::from(label)];
        for (i, v) in r.stats.req.iter().enumerate() {
            cells.push(count_cell(
                *v,
                if i == 0 { theme::ACCENT } else { theme::INK },
            ));
        }
        for (i, v) in r.stats.resp.iter().enumerate() {
            cells.push(count_cell(*v, resp_color(i)));
        }
        Row::new(cells)
    };

    let mut body = Vec::new();
    if let Some(a) = all {
        body.push(mk_row(a));
    }
    body.extend(rows.iter().map(|r| mk_row(r)));

    // Column width follows the header label (full method names like REGISTER
    // would be truncated by a fixed 5-char column); counts stay ≤4 chars via
    // the k/M suffixes.
    let mut widths = vec![Constraint::Length(16)];
    widths.extend(
        REQ_LABELS
            .iter()
            .map(|l| Constraint::Length((l.chars().count() + 1).max(4) as u16)),
    );
    widths.extend(
        RESP_LABELS
            .iter()
            .map(|l| Constraint::Length((l.chars().count() + 1).max(4) as u16)),
    );

    let table = Table::new(body, widths)
        .header(
            Row::new(head).style(
                Style::default()
                    .fg(theme::WARNING)
                    .add_modifier(ratatui::style::Modifier::BOLD),
            ),
        )
        .block(Block::default().borders(Borders::ALL).title(format!(
            "SIP requests/responses per IP ({} IPs) — s=sort:{} w=ASR bucket",
            rows.len(),
            app.sip_sort.label()
        )))
        .row_highlight_style(theme::selected());
    f.render_stateful_widget(table, area, &mut app.sip_table_state);
}

/// Deviation color for an ASR value against the window baseline.
fn asr_color(asr: f64, base: Option<f64>, samples: u64) -> Color {
    if samples < MIN_SAMPLES {
        return theme::DIM;
    }
    match base {
        None => {
            // Baseline not established yet: absolute fallback.
            if asr >= 60.0 {
                theme::SUCCESS
            } else if asr >= 30.0 {
                theme::WARNING
            } else {
                theme::ERROR
            }
        }
        Some(b) => {
            let dev = asr - b;
            if dev >= 10.0 {
                theme::SUCCESS
            } else if dev >= -10.0 {
                theme::INFO
            } else if dev >= -25.0 {
                theme::WARNING
            } else {
                theme::ERROR
            }
        }
    }
}

/// One heatmap cell: block height tracks the absolute rate, the color tracks
/// the deviation from the global baseline (dim gray for tiny samples).
fn asr_cell(invites: u64, answered: u64, base: Option<f64>) -> Cell<'static> {
    if invites == 0 {
        return Cell::from("·").style(Style::default().fg(theme::MUTED));
    }
    let asr = answered.min(invites) as f64 / invites as f64 * 100.0;
    let ch = if asr < 20.0 {
        "▁"
    } else if asr < 40.0 {
        "▃"
    } else if asr < 60.0 {
        "▅"
    } else if asr < 80.0 {
        "▇"
    } else {
        "█"
    };
    Cell::from(ch).style(Style::default().fg(asr_color(asr, base, invites)))
}

fn bucket_label(secs: u64) -> &'static str {
    match secs {
        300 => "5m",
        900 => "15m",
        _ => "1m",
    }
}

fn render_asr_heatmap(
    f: &mut Frame,
    area: Rect,
    snap: &Snapshot,
    app: &mut App,
    rows: &[&SipIpRow],
) {
    let bucket_secs = app.sip_window_secs;
    let bucket_us = bucket_secs * 1_000_000;
    const COLS: usize = 60;

    let all = snap.sip_stats.iter().find(|r| r.ip.is_none());
    let base = all.and_then(|a| a.stats.asr_pct(bucket_secs));

    // Time axis from the newest bucket any row still retains.
    let last_key = snap
        .sip_stats
        .iter()
        .filter_map(|r| r.stats.series(bucket_secs).last().map(|e| e.0))
        .max()
        .unwrap_or(0);
    let axis_start = last_key.saturating_sub(bucket_us * (COLS - 1) as u64);
    let tz = snap.tz_offset_secs;

    let head = vec![
        Cell::from("IP"),
        Cell::from("ASR"),
        Cell::from("INV"),
        Cell::from(format!(
            "{}..{}",
            fmt_time_tz(axis_start, tz),
            fmt_time_tz(last_key + bucket_us, tz)
        )),
    ];

    // ALL row pinned first; per-IP rows follow the distribution-table
    // selection so scrolling keeps both panes on the same IP.
    let start = app
        .sip_table_state
        .selected()
        .unwrap_or(0)
        .saturating_sub(1);
    let height = area.height.saturating_sub(3) as usize; // borders + header
    let privacy = app.privacy;
    let mk_row = |r: &SipIpRow| {
        let label = match r.ip {
            None => "ALL".to_string(),
            Some(ip) if privacy => mask_ip(ip),
            Some(ip) => ip.to_string(),
        };
        let (inv, _) = r.stats.series_totals(bucket_secs);
        let asr = r.stats.asr_pct(bucket_secs);
        let mut cells = vec![Cell::from(label)];
        match asr {
            Some(p) => cells.push(
                Cell::from(format!("{p:.0}")).style(Style::default().fg(asr_color(p, base, inv))),
            ),
            None => cells.push(Cell::from("-").style(Style::default().fg(theme::MUTED))),
        }
        cells.push(Cell::from(fmt_count(inv)).style(Style::default().fg(theme::INK)));

        let mut grid: Vec<Option<(u64, u64)>> = vec![None; COLS];
        for (k, i, a) in r.stats.series(bucket_secs) {
            if *k <= axis_start {
                continue;
            }
            let idx = ((k.saturating_sub(axis_start)) / bucket_us) as usize;
            if idx < COLS {
                grid[idx] = Some((*i, *a));
            }
        }
        cells.extend(grid.into_iter().map(|e| match e {
            Some((i, a)) => asr_cell(i, a, base),
            None => Cell::from("·").style(Style::default().fg(theme::MUTED)),
        }));
        Row::new(cells)
    };

    let mut body = Vec::new();
    if let Some(a) = all {
        body.push(mk_row(a));
    }
    body.extend(
        rows.iter()
            .skip(start)
            .take(height.saturating_sub(1))
            .map(|r| mk_row(r)),
    );

    let mut widths = vec![
        Constraint::Length(16),
        Constraint::Length(4),
        Constraint::Length(4),
    ];
    widths.extend(std::iter::repeat_n(Constraint::Length(1), COLS));

    let base_txt = base
        .map(|b| format!("{b:.0}%"))
        .unwrap_or_else(|| "-".into());
    let table = Table::new(body, widths).header(Row::new(head)).block(
        Block::default().borders(Borders::ALL).title(format!(
            "INVITE ASR heatmap ({} / cell, base=ALL {base_txt}) — green≥+10 cyan±10 orange−25 red<−25 · gray<{MIN_SAMPLES} samples",
            bucket_label(bucket_secs)
        )),
    );
    f.render_widget(table, area);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::sipstats::{SipObs, SipStatsStore};
    use crate::ui::app::{Page, RecordState, wrap_snap};
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use std::sync::atomic::AtomicBool;
    use std::sync::{Arc, Mutex};

    fn sample_snapshot() -> Snapshot {
        let mut st = SipStatsStore::new();
        let t0 = 1_800_000_000_000_000u64; // bucket-aligned minute
        let caller: std::net::IpAddr = "10.10.0.8".parse().unwrap();
        let sbc: std::net::IpAddr = "10.20.0.8".parse().unwrap();
        // 10 initial INVITEs from the caller, 6 answered by the SBC.
        for i in 0..10u64 {
            st.observe(&SipObs {
                ip: caller,
                ts_us: t0 + i * 1_000_000,
                is_request: true,
                method: Some(crate::model::sip::Method::Invite),
                status: None,
                answer_for_ip: None,
                initial_invite: true,
            });
            if i < 6 {
                st.observe(&SipObs {
                    ip: sbc,
                    ts_us: t0 + i * 1_000_000 + 500_000,
                    is_request: false,
                    method: None,
                    status: Some(200),
                    answer_for_ip: Some(caller),
                    initial_invite: false,
                });
            }
            // A couple of OPTIONS keepalive exchanges.
            st.observe(&SipObs {
                ip: caller,
                ts_us: t0 + i * 1_000_000 + 100_000,
                is_request: true,
                method: Some(crate::model::sip::Method::Options),
                status: None,
                answer_for_ip: None,
                initial_invite: false,
            });
        }
        // Two 404s from a third endpoint.
        let gw: std::net::IpAddr = "10.30.0.8".parse().unwrap();
        for i in 0..2u64 {
            st.observe(&SipObs {
                ip: gw,
                ts_us: t0 + i * 1_000_000,
                is_request: false,
                method: None,
                status: Some(404),
                answer_for_ip: None,
                initial_invite: false,
            });
        }
        Snapshot {
            sip_stats: st.snapshot(),
            ..Snapshot::default()
        }
    }

    fn app(snap: Snapshot) -> App {
        let mut a = App::new(
            wrap_snap(snap),
            Arc::new(AtomicBool::new(false)),
            Arc::new(Mutex::new(None)),
            Arc::new(AtomicBool::new(false)),
            RecordState::default(),
        );
        a.page = Page::Heatmap;
        a
    }

    fn render_text(a: &mut App) -> String {
        let mut terminal = Terminal::new(TestBackend::new(150, 44)).unwrap();
        terminal.draw(|f| crate::ui::render(f, a)).unwrap();
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
    fn sip_page_renders_distribution_and_heatmap() {
        let mut a = app(sample_snapshot());
        let text = render_text(&mut a);
        assert!(text.contains("SIP requests/responses per IP"), "{text}");
        assert!(text.contains("INVITE ASR heatmap"), "{text}");
        assert!(text.contains("ALL"), "{text}");
        assert!(text.contains("10.10.0.8"), "{text}");
        // Column headers for the distribution and the ASR row head.
        assert!(text.contains("486"), "{text}");
        assert!(text.contains("ASR"), "{text}");
        // ALL row ASR: 6/10 = 60%.
        assert!(text.contains("60"), "{text}");
    }

    #[test]
    fn privacy_masks_sip_ips() {
        let mut a = app(sample_snapshot());
        a.privacy = true;
        let text = render_text(&mut a);
        assert!(!text.contains("10.10.0.8"), "{text}");
        assert!(text.contains("10.*.*.8"), "{text}");
    }

    #[test]
    fn empty_snapshot_renders_without_panic() {
        let mut a = app(Snapshot::default());
        let text = render_text(&mut a);
        assert!(text.contains("INVITE ASR heatmap"), "{text}");
    }
}
