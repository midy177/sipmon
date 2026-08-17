use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::widgets::TableState;

use crate::model::sip::CallState;
use crate::store::registry::{CallSummary, Snapshot};

/// Overview call-list filter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallFilter {
    All,
    Dialing,
    Ringing,
    Active,
    Completed,
    Failed,
    Canceled,
}

impl CallFilter {
    pub const ALL: [CallFilter; 7] = [
        CallFilter::All,
        CallFilter::Dialing,
        CallFilter::Ringing,
        CallFilter::Active,
        CallFilter::Completed,
        CallFilter::Failed,
        CallFilter::Canceled,
    ];
    pub fn label(self) -> &'static str {
        match self {
            CallFilter::All => "all",
            CallFilter::Dialing => "dialing",
            CallFilter::Ringing => "ringing",
            CallFilter::Active => "active",
            CallFilter::Completed => "success",
            CallFilter::Failed => "failed",
            CallFilter::Canceled => "canceled",
        }
    }
    pub fn matches(self, s: CallState) -> bool {
        match self {
            CallFilter::All => true,
            CallFilter::Dialing => s == CallState::Dialing,
            CallFilter::Ringing => s == CallState::Ringing,
            CallFilter::Active => s == CallState::Active,
            CallFilter::Completed => s == CallState::Completed,
            CallFilter::Failed => s == CallState::Failed,
            CallFilter::Canceled => s == CallState::Canceled,
        }
    }
    pub fn next(self) -> CallFilter {
        let i = Self::ALL.iter().position(|&x| x == self).unwrap_or(0);
        Self::ALL[(i + 1) % Self::ALL.len()]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Page {
    Overview,
    Search,
    CallDetail,
    Heatmap,
    Streams,
    EventLog,
    IpStats,
}

impl Page {
    pub fn title(self) -> &'static str {
        match self {
            Page::Overview => "Overview",
            Page::Search => "Search",
            Page::CallDetail => "Call Detail",
            Page::Heatmap => "Heatmap",
            Page::Streams => "Streams",
            Page::EventLog => "Event Log",
            Page::IpStats => "IP Stats",
        }
    }
    pub const ALL: [Page; 7] = [
        Page::Overview,
        Page::Search,
        Page::CallDetail,
        Page::Heatmap,
        Page::Streams,
        Page::EventLog,
        Page::IpStats,
    ];

    /// 0-based position within `ALL` (used by the bottom 1-7 tab bar).
    pub fn index(self) -> usize {
        Self::ALL.iter().position(|p| *p == self).unwrap_or(0)
    }
}

/// Sort modes for the per-IP network-stats page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpSort {
    /// Most recently active first.
    Newest,
    /// Highest all-time loss first.
    MaxLoss,
    /// Lowest all-time loss first.
    MinLoss,
}

impl IpSort {
    pub const ALL: [IpSort; 3] = [IpSort::Newest, IpSort::MaxLoss, IpSort::MinLoss];
    pub fn label(self) -> &'static str {
        match self {
            IpSort::Newest => "newest",
            IpSort::MaxLoss => "max-loss",
            IpSort::MinLoss => "min-loss",
        }
    }
    pub fn next(self) -> IpSort {
        let i = Self::ALL.iter().position(|&x| x == self).unwrap_or(0);
        Self::ALL[(i + 1) % Self::ALL.len()]
    }
}

/// Live event-log recording state surfaced by the top bar (`record`/`-w`
/// mode): whether the pipeline is writing an evlog, its path, and the bytes
/// written so far.
#[derive(Clone, Default)]
pub struct RecordState {
    pub active: Arc<AtomicBool>,
    pub path: Arc<Mutex<Option<PathBuf>>>,
    pub bytes: Arc<AtomicU64>,
}

pub struct App {
    pub snap: Arc<Mutex<Snapshot>>,
    pub pause: Arc<AtomicBool>,
    pub focus_id: Arc<Mutex<Option<String>>>,
    pub clear: Arc<AtomicBool>,
    pub page: Page,
    pub search_query: String,
    pub search_editing: bool,
    pub search_state: TableState,
    pub table_state: TableState,
    /// Call-id the user just selected (Enter) but whose focus detail the worker
    /// has not republished into the snapshot yet — used to avoid a misleading
    /// "No call selected" flash on the Call Detail page.
    pub focus_pending: Option<String>,
    /// Call-id currently selected in the Overview table (anchored so new calls
    /// don't shift the highlight).
    pub selected_call: Option<String>,
    pub filter: CallFilter,
    pub streams_state: TableState,
    pub eventlog_scroll: u16,
    pub raw_scroll: usize,
    pub flow_state: TableState,
    pub should_quit: bool,
    pub status: String,
    pub export_path: Option<std::path::PathBuf>,
    /// Per-IP network-stats page state.
    pub ip_table_state: TableState,
    pub ip_sort: IpSort,
    /// Cached row order (IPs) so the list doesn't reshuffle on every frame;
    /// re-derived at most once per `SORT_REFRESH` (see ipstats::ordered_rows).
    pub ip_sort_order: Vec<std::net::IpAddr>,
    pub ip_sort_last: Instant,
    /// Loss-only summary mode: table collapses to just the directional loss.
    pub ip_loss_only: bool,
    /// Loss window shown in loss-only mode (secs, 0 = all-time).
    pub ip_summary_window: u64,
    pub ip_window_secs: u64, // heatmap window: 60s / 10m / 1h
    pub ip_drill: Option<std::net::IpAddr>,
    pub ip_drill_state: TableState,
    /// Live evlog recording state (blinking top-bar indicator).
    pub record: RecordState,
    /// Privacy mode: masks IPs and caller/callee identifiers (screenshot-safe).
    pub privacy: bool,
}

impl App {
    pub fn new(
        snap: Arc<Mutex<Snapshot>>,
        pause: Arc<AtomicBool>,
        focus: Arc<Mutex<Option<String>>>,
        clear: Arc<AtomicBool>,
        record: RecordState,
    ) -> Self {
        Self {
            snap,
            pause,
            focus_id: focus,
            clear,
            page: Page::Overview,
            search_query: String::new(),
            search_editing: false,
            search_state: TableState::default(),
            table_state: TableState::default(),
            focus_pending: None,
            selected_call: None,
            filter: CallFilter::All,
            streams_state: TableState::default(),
            eventlog_scroll: 0,
            raw_scroll: 0,
            flow_state: TableState::default(),
            should_quit: false,
            status: String::new(),
            export_path: None,
            ip_table_state: TableState::default(),
            ip_sort: IpSort::Newest,
            ip_sort_order: Vec::new(),
            ip_sort_last: Instant::now(),
            ip_loss_only: false,
            ip_summary_window: 0,
            ip_window_secs: 60,
            ip_drill: None,
            ip_drill_state: TableState::default(),
            record,
            privacy: false,
        }
    }

    pub fn snapshot(&self) -> Snapshot {
        self.snap.lock().map(|s| s.clone()).unwrap_or_default()
    }

    pub fn set_status(&mut self, s: impl Into<String>) {
        self.status = s.into();
    }

    /// Main event loop tick. Returns false when the app should exit.
    pub fn poll(&mut self, timeout: Duration) -> bool {
        if event::poll(timeout).unwrap_or(false)
            && let Ok(Event::Key(key)) = event::read()
            && key.kind == KeyEventKind::Press
        {
            self.on_key(key.code, key.modifiers);
        }
        !self.should_quit
    }

    fn cycle_page(&mut self, fwd: bool) {
        let idx = Page::ALL.iter().position(|p| *p == self.page).unwrap_or(0);
        let n = Page::ALL.len();
        let next = if fwd {
            (idx + 1) % n
        } else {
            (idx + n - 1) % n
        };
        self.page = Page::ALL[next];
    }

    fn on_key(&mut self, code: KeyCode, mods: KeyModifiers) {
        // Global: quit / pause / page switching / export.
        if self.search_editing {
            match code {
                KeyCode::Esc => {
                    self.search_editing = false;
                }
                KeyCode::Enter => {
                    self.search_editing = false;
                    self.search_state.select(Some(0));
                }
                KeyCode::Backspace => {
                    self.search_query.pop();
                }
                KeyCode::Char(c) => self.search_query.push(c),
                _ => {}
            }
            return;
        }

        match code {
            KeyCode::Char('c') if mods.contains(KeyModifiers::CONTROL) => self.should_quit = true,
            KeyCode::Char('q') | KeyCode::Esc => {
                if self.page == Page::CallDetail {
                    // Esc goes back to the previous list view.
                    self.page = Page::Overview;
                    self.focus_pending = None;
                    self.focus_id.lock().ok().map(|mut f| f.take());
                } else if self.page == Page::IpStats && self.ip_drill.is_some() {
                    // Esc closes the per-IP call drill-down.
                    self.ip_drill = None;
                } else {
                    self.should_quit = true;
                }
            }
            KeyCode::Left => {
                if self.page == Page::CallDetail {
                    self.page = Page::Overview;
                    self.focus_pending = None;
                    self.focus_id.lock().ok().map(|mut f| f.take());
                } else if self.page == Page::IpStats && self.ip_drill.is_some() {
                    self.ip_drill = None;
                }
            }
            KeyCode::Tab => self.cycle_page(true),
            KeyCode::BackTab => self.cycle_page(false),
            KeyCode::Char(' ') => {
                let paused = !self.pause.load(Ordering::Relaxed);
                self.pause.store(paused, Ordering::Relaxed);
                self.set_status(if paused { "paused" } else { "resumed" });
            }
            KeyCode::Char('1') => self.page = Page::Overview,
            KeyCode::Char('2') => self.page = Page::Search,
            KeyCode::Char('3') => self.page = Page::CallDetail,
            KeyCode::Char('4') => self.page = Page::Heatmap,
            KeyCode::Char('5') => self.page = Page::Streams,
            KeyCode::Char('6') => self.page = Page::EventLog,
            KeyCode::Char('7') => self.page = Page::IpStats,
            KeyCode::Char('/') => {
                self.page = Page::Search;
                self.search_editing = true;
            }
            KeyCode::Char('e') => self.do_export(),
            KeyCode::Char('p') => {
                self.privacy = !self.privacy;
                self.set_status(if self.privacy {
                    "privacy on — IPs and numbers masked"
                } else {
                    "privacy off"
                });
            }
            KeyCode::Char('f') => {
                self.filter = self.filter.next();
                self.set_status(format!("filter = {}", self.filter.label()));
            }
            KeyCode::Char('x') => {
                self.clear.store(true, Ordering::Relaxed);
                self.set_status("cleared all calls/stats");
                // Drop the stale selection anchors.
                self.selected_call = None;
                self.focus_pending = None;
                self.ip_drill = None;
            }
            _ => self.page_key(code),
        }
    }

    /// Cycle the loss-heatmap window: 60s → 10m → 1h → 60s.
    fn cycle_ip_window(&mut self) {
        self.ip_window_secs = match self.ip_window_secs {
            60 => 600,
            600 => 3600,
            _ => 60,
        };
        self.set_status(format!("IP heatmap window = {}s", self.ip_window_secs));
    }

    /// Cycle the loss-only summary window through the supported windows.
    fn cycle_ip_summary_window(&mut self) {
        let vals = crate::store::ipstats::WINDOWS.map(|(s, _)| s);
        let i = vals
            .iter()
            .position(|&x| x == self.ip_summary_window)
            .unwrap_or(0);
        self.ip_summary_window = vals[(i + 1) % vals.len()];
        let label = crate::store::ipstats::WINDOWS
            .iter()
            .find(|(s, _)| *s == self.ip_summary_window)
            .map(|(_, l)| *l)
            .unwrap_or("all");
        self.set_status(format!("IP loss window = {label}"));
    }

    fn do_export(&mut self) {
        let snap = self.snapshot();
        let path = std::path::PathBuf::from(format!(
            "sipmon-export-{}.jsonl",
            chrono::Utc::now().format("%Y%m%d%H%M%S")
        ));
        match crate::export::jsonl::export_snapshot(&path, &snap) {
            Ok(()) => {
                self.set_status(format!("exported {}", path.display()));
                self.export_path = Some(path);
            }
            Err(e) => self.set_status(format!("export failed: {e}")),
        }
    }

    /// Request the focus detail for `call_id` and switch to the Call Detail
    /// page. `focus_pending` hides the "No call selected" placeholder until the
    /// pipeline republishes the snapshot with the focused detail.
    fn open_detail(&mut self, call_id: String) {
        self.selected_call = Some(call_id.clone());
        if let Ok(mut f) = self.focus_id.lock() {
            *f = Some(call_id.clone());
        }
        self.focus_pending = Some(call_id);
        self.page = Page::CallDetail;
        self.raw_scroll = 0;
    }

    /// Calls currently visible under `filter`, in display order.
    fn filtered_calls<'a>(&self, snap: &'a Snapshot) -> Vec<&'a CallSummary> {
        snap.calls
            .iter()
            .filter(|c| self.filter.matches(c.state))
            .collect()
    }

    /// Re-anchor the Overview selection to `selected_call`, which is stable
    /// across list reorderings/insertions (new calls only shift the index).
    /// Called from the render path only.
    pub fn anchor_overview_selection(&mut self, snap: &Snapshot) {
        let visible = self.filtered_calls(snap);
        if let Some(id) = self.selected_call.clone() {
            self.table_state
                .select(visible.iter().position(|c| c.call_id == id));
        } else if let Some(i) = self.table_state.selected() {
            self.selected_call = visible.get(i).map(|c| c.call_id.clone());
        }
    }

    /// Record the call-id at the current table index as the selection anchor.
    /// Called right after Up/Down so subsequent anchors follow the new row.
    fn sync_overview_selection(&mut self, snap: &Snapshot) {
        let visible = self.filtered_calls(snap);
        self.selected_call = self
            .table_state
            .selected()
            .and_then(|i| visible.get(i))
            .map(|c| c.call_id.clone());
    }

    fn page_key(&mut self, code: KeyCode) {
        let snap = self.snapshot();
        match self.page {
            Page::Overview => match code {
                KeyCode::Down => {
                    self.table_state.select_next();
                    self.sync_overview_selection(&snap);
                }
                KeyCode::Up => {
                    self.table_state.select_previous();
                    self.sync_overview_selection(&snap);
                }
                KeyCode::Enter => {
                    // Enter opens the selected call (first row when none is
                    // selected yet).
                    let visible = self.filtered_calls(&snap);
                    let idx = self
                        .table_state
                        .selected()
                        .or_else(|| (!visible.is_empty()).then_some(0));
                    if let Some(i) = idx
                        && let Some(c) = visible.get(i)
                    {
                        self.open_detail(c.call_id.clone());
                    }
                }
                _ => {}
            },
            Page::Search => match code {
                KeyCode::Down => self.search_state.select_next(),
                KeyCode::Up => self.search_state.select_previous(),
                KeyCode::Enter => {
                    let results = search_results(&snap, &self.search_query);
                    let idx = self
                        .search_state
                        .selected()
                        .or_else(|| (!results.is_empty()).then_some(0));
                    if let Some(i) = idx
                        && let Some(c) = results.get(i)
                    {
                        self.open_detail(c.call_id.clone());
                    }
                }
                _ => {}
            },
            Page::CallDetail => match code {
                KeyCode::Down => self.flow_state.select_next(),
                KeyCode::Up => self.flow_state.select_previous(),
                KeyCode::PageDown => self.raw_scroll = self.raw_scroll.saturating_add(1),
                KeyCode::PageUp => self.raw_scroll = self.raw_scroll.saturating_sub(1),
                _ => {}
            },
            Page::Streams => match code {
                KeyCode::Down => self.streams_state.select_next(),
                KeyCode::Up => self.streams_state.select_previous(),
                _ => {}
            },
            Page::EventLog => match code {
                KeyCode::Down => self.eventlog_scroll = self.eventlog_scroll.saturating_add(1),
                KeyCode::Up => self.eventlog_scroll = self.eventlog_scroll.saturating_sub(1),
                _ => {}
            },
            Page::IpStats => self.ip_key(code, &snap),
            Page::Heatmap => match code {
                KeyCode::Char('s') => self.next_ip_sort(),
                KeyCode::Char('w') => self.cycle_ip_window(),
                _ => {}
            },
        }
    }

    fn next_ip_sort(&mut self) {
        self.ip_sort = self.ip_sort.next();
        // Drop the cached row order so the new sort applies right away.
        self.ip_sort_order.clear();
        self.set_status(format!("IP sort = {}", self.ip_sort.label()));
    }

    fn ip_key(&mut self, code: KeyCode, snap: &Snapshot) {
        if self.ip_drill.is_some() {
            // Drill-down: navigate the selected IP's calls, Enter opens one.
            match code {
                KeyCode::Down => self.ip_drill_state.select_next(),
                KeyCode::Up => self.ip_drill_state.select_previous(),
                KeyCode::Enter => {
                    let calls = crate::ui::ipstats::calls_for_ip(snap, self.ip_drill);
                    let idx = self
                        .ip_drill_state
                        .selected()
                        .or_else(|| (!calls.is_empty()).then_some(0));
                    if let Some(i) = idx
                        && let Some(c) = calls.get(i)
                    {
                        self.open_detail(c.call_id.clone());
                    }
                }
                _ => {}
            }
            return;
        }
        match code {
            KeyCode::Down => {
                self.ip_table_state.select_next();
            }
            KeyCode::Up => {
                self.ip_table_state.select_previous();
            }
            KeyCode::Enter => {
                let rows = crate::ui::ipstats::ordered_rows(snap, self);
                let idx = self
                    .ip_table_state
                    .selected()
                    .or_else(|| (!rows.is_empty()).then_some(0));
                if let Some(i) = idx
                    && let Some(r) = rows.get(i)
                {
                    self.ip_drill = Some(r.ip);
                    self.ip_drill_state = TableState::default();
                    self.set_status(format!("IP {} — calls (Enter to open, Esc back)", r.ip));
                }
            }
            KeyCode::Char('s') => self.next_ip_sort(),
            KeyCode::Char('w') => {
                if self.ip_loss_only {
                    self.cycle_ip_summary_window();
                } else {
                    self.cycle_ip_window();
                }
            }
            KeyCode::Char('c') => {
                self.ip_loss_only = !self.ip_loss_only;
                self.set_status(if self.ip_loss_only {
                    "IP view: loss-only summary"
                } else {
                    "IP view: full"
                });
            }
            _ => {}
        }
    }
}

/// sngrep-style search: Call-ID / From / To / remote IP / SSRC substring.
pub fn search_results<'a>(
    snap: &'a Snapshot,
    query: &str,
) -> Vec<&'a crate::store::registry::CallSummary> {
    let q = query.trim().to_ascii_lowercase();
    snap.calls
        .iter()
        .filter(|c| {
            if q.is_empty() {
                return true;
            }
            c.call_id.to_ascii_lowercase().contains(&q)
                || c.from_user
                    .as_deref()
                    .map(|v| v.to_ascii_lowercase().contains(&q))
                    .unwrap_or(false)
                || c.to_user
                    .as_deref()
                    .map(|v| v.to_ascii_lowercase().contains(&q))
                    .unwrap_or(false)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    fn app() -> App {
        App::new(
            Arc::new(Mutex::new(Snapshot::default())),
            Arc::new(AtomicBool::new(false)),
            Arc::new(Mutex::new(None)),
            Arc::new(AtomicBool::new(false)),
            RecordState::default(),
        )
    }

    #[test]
    fn tab_cycles_all_seven_pages_including_call_detail() {
        let mut a = app();
        // From Call Detail, Tab advances to the next page (not the pane).
        a.page = Page::CallDetail;
        a.on_key(KeyCode::Tab, KeyModifiers::NONE);
        assert_eq!(a.page, Page::Heatmap);
        // Shift-Tab goes back to the previous page.
        a.on_key(KeyCode::BackTab, KeyModifiers::NONE);
        assert_eq!(a.page, Page::CallDetail);
        // A full wrap of 7 Tab presses lands back on the start page.
        a.page = Page::Overview;
        for _ in 0..Page::ALL.len() {
            a.on_key(KeyCode::Tab, KeyModifiers::NONE);
        }
        assert_eq!(a.page, Page::Overview);
    }

    #[test]
    fn bottom_tab_bar_renders_and_highlights_selected() {
        let mut a = app();
        a.page = Page::IpStats;
        let mut terminal = Terminal::new(TestBackend::new(120, 24)).unwrap();
        terminal.draw(|f| crate::ui::render(f, &mut a)).unwrap();
        let buf = terminal.backend().buffer().clone();
        let last_y = buf.area.height - 1;
        let row: String = (0..buf.area.width)
            .map(|x| buf[(x, last_y)].symbol())
            .collect();
        for label in [
            "1 Overview",
            "2 Search",
            "3 Detail",
            "4 Heatmap",
            "5 Streams",
            "6 EventLog",
            "7 IP Stats",
        ] {
            assert!(row.contains(label), "tab bar missing {label}: {row:?}");
        }
        // The selected page (7 IP Stats) is highlighted with the accent bg.
        let start = row.find("7 IP Stats").unwrap();
        assert_eq!(
            buf[(start as u16, last_y)].bg,
            crate::ui::theme::ACCENT,
            "selected tab must be highlighted"
        );
    }

    #[test]
    fn topbar_shows_blinking_recording_indicator() {
        let mut a = app();
        a.record = RecordState {
            active: Arc::new(AtomicBool::new(true)),
            path: Arc::new(Mutex::new(Some(PathBuf::from("/tmp/capture.evlog")))),
            bytes: Arc::new(AtomicU64::new(2048)),
        };
        let mut terminal = Terminal::new(TestBackend::new(150, 24)).unwrap();
        terminal.draw(|f| crate::ui::render(f, &mut a)).unwrap();
        let buf = terminal.backend().buffer().clone();
        let top: String = (0..buf.area.width).map(|x| buf[(x, 0)].symbol()).collect();
        // The indicator must carry the file name and the formatted size.
        assert!(
            top.contains("REC capture.evlog"),
            "top bar missing recording indicator: {top:?}"
        );
        assert!(
            top.contains("2.0 KB"),
            "top bar missing recording size: {top:?}"
        );
        // The dot glyph is the blinking part; either phase must be rendered.
        assert!(
            top.contains("● REC") || top.contains("○ REC"),
            "top bar must render the recording dot: {top:?}"
        );
        // No recording → no indicator.
        a.record
            .active
            .store(false, std::sync::atomic::Ordering::Relaxed);
        let mut terminal = Terminal::new(TestBackend::new(150, 24)).unwrap();
        terminal.draw(|f| crate::ui::render(f, &mut a)).unwrap();
        let buf = terminal.backend().buffer().clone();
        let top: String = (0..buf.area.width).map(|x| buf[(x, 0)].symbol()).collect();
        assert!(
            !top.contains("REC"),
            "indicator must be hidden when idle: {top:?}"
        );
    }
}
