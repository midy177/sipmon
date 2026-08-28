use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::widgets::TableState;

use crate::model::sip::CallState;
use crate::store::registry::{CallSummary, FocusHint, Snapshot};

/// Shared snapshot cell: the pipeline publishes a new `Arc` so the TUI can
/// cheaply clone the pointer every frame instead of cloning the whole tree.
pub type SnapLock = Arc<Mutex<Arc<Snapshot>>>;

#[cfg(test)]
pub fn wrap_snap(s: Snapshot) -> SnapLock {
    Arc::new(Mutex::new(Arc::new(s)))
}

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
            Page::CallDetail => "Call Detail",
            Page::Heatmap => "SIP Stats",
            Page::Streams => "Streams",
            Page::EventLog => "Event Log",
            Page::IpStats => "IP Stats",
        }
    }
    pub const ALL: [Page; 6] = [
        Page::Overview,
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

/// Sort modes for the SIP Stats page (request/response distribution).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SipSort {
    /// Most INVITEs first.
    Invites,
    /// Most error responses (486/404/403/4xx/5xx/6xx) first.
    Errors,
    /// Lowest window ASR first (rows without INVITEs last).
    Asr,
}

impl SipSort {
    pub const ALL: [SipSort; 3] = [SipSort::Invites, SipSort::Errors, SipSort::Asr];
    pub fn label(self) -> &'static str {
        match self {
            SipSort::Invites => "invites",
            SipSort::Errors => "errors",
            SipSort::Asr => "asr",
        }
    }
    pub fn next(self) -> SipSort {
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
    pub snap: SnapLock,
    pub pause: Arc<AtomicBool>,
    pub focus_id: Arc<Mutex<Option<FocusHint>>>,
    /// Current filter query (rule syntax: `ip:`/`caller:`/`callee:`/`callid:`
    /// tokens AND-ed together), published to the pipeline so matching calls
    /// are pinned (eviction-proof and always included in snapshots).
    pub search_pin: Arc<Mutex<Option<String>>>,
    pub clear: Arc<AtomicBool>,
    pub page: Page,
    /// Overview filter query; live-applied while typing.
    pub filter_query: String,
    /// True while the filter bar captures keystrokes.
    pub filter_editing: bool,
    /// Query snapshot taken when editing started, restored by Esc.
    pub filter_backup: String,
    pub table_state: TableState,
    /// Call-id the user just selected (Enter) but whose focus detail the worker
    /// has not republished into the snapshot yet — used to avoid a misleading
    /// "No call selected" flash on the Call Detail page.
    pub focus_pending: Option<String>,
    /// Call-id currently selected in the Overview table (anchored so new calls
    /// don't shift the highlight).
    pub selected_call: Option<String>,
    /// Optional b-leg Call-ID linked into the focused call's swimlane.
    pub linked_call_id: Option<String>,
    /// When set, Call Detail shows a searchable overlay to pick a b-leg.
    pub b_leg_picker: bool,
    pub b_leg_query: String,
    pub b_leg_state: TableState,
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
    /// SIP Stats page state: table selection, sort mode, ASR bucket width.
    pub sip_table_state: TableState,
    pub sip_sort: SipSort,
    /// ASR heatmap bucket width: 60s / 300s / 900s (cell granularity).
    pub sip_window_secs: u64,
    /// Live evlog recording state (blinking top-bar indicator).
    pub record: RecordState,
    /// Privacy mode: masks IPs and caller/callee identifiers (screenshot-safe).
    pub privacy: bool,
    /// Local (monitored) machine IPs: the Call Detail flow/media views pin the
    /// local endpoint to the right and draw ingress/egress arrows (`->`/`<-`).
    pub local_ips: Vec<std::net::IpAddr>,
}

impl App {
    pub fn new(
        snap: SnapLock,
        pause: Arc<AtomicBool>,
        focus: Arc<Mutex<Option<FocusHint>>>,
        clear: Arc<AtomicBool>,
        record: RecordState,
    ) -> Self {
        Self {
            snap,
            pause,
            focus_id: focus,
            search_pin: Arc::new(Mutex::new(None)),
            clear,
            page: Page::Overview,
            filter_query: String::new(),
            filter_editing: false,
            filter_backup: String::new(),
            table_state: TableState::default(),
            focus_pending: None,
            selected_call: None,
            linked_call_id: None,
            b_leg_picker: false,
            b_leg_query: String::new(),
            b_leg_state: TableState::default(),
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
            sip_table_state: TableState::default(),
            sip_sort: SipSort::Invites,
            sip_window_secs: 60,
            record,
            privacy: false,
            local_ips: Vec::new(),
        }
    }

    pub fn snapshot(&self) -> Arc<Snapshot> {
        self.snap
            .lock()
            .map(|s| s.clone())
            .unwrap_or_else(|_| Arc::new(Snapshot::default()))
    }

    pub fn set_status(&mut self, s: impl Into<String>) {
        self.status = s.into();
    }

    /// Main event loop tick. Returns false when the app should exit.
    pub fn poll(&mut self, timeout: Duration) -> bool {
        if event::poll(timeout).unwrap_or(false)
            && let Ok(Event::Key(key)) = event::read()
            && (key.kind == KeyEventKind::Press
                || (key.kind == KeyEventKind::Repeat && is_nav_key(key.code)))
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

    /// Push the current filter query to the pipeline (pins matching calls).
    /// Empty queries clear the pin.
    fn sync_search_pin(&self) {
        let q = self.filter_query.trim().to_string();
        if let Ok(mut s) = self.search_pin.lock() {
            *s = (!q.is_empty()).then_some(q);
        }
    }

    /// Keep the Overview selection inside the (possibly shrunken) filtered
    /// set while the query is being typed, and default to the first row so
    /// the highlight is visible right away.
    fn clamp_overview_selection(&mut self) {
        let snap = self.snapshot();
        let n = self.filtered_calls(&snap).len();
        let idx = match self.table_state.selected() {
            Some(i) if i < n => Some(i),
            _ => (n > 0).then_some(0),
        };
        self.table_state.select(idx);
        self.sync_overview_selection(&snap);
    }

    fn on_key(&mut self, code: KeyCode, mods: KeyModifiers) {
        // B-leg picker captures keys while open (search + navigate).
        if self.b_leg_picker {
            self.b_leg_picker_key(code);
            return;
        }
        // Global: quit / pause / page switching / export.
        if self.filter_editing {
            // The Overview list stays live while typing: ↑↓/PgUp/PgDn move
            // the selection without leaving edit mode; Enter commits the
            // filter, Esc rolls back to the pre-edit query.
            let snap = self.snapshot();
            let n = self.filtered_calls(&snap).len();
            match code {
                KeyCode::Char('c') if mods.contains(KeyModifiers::CONTROL) => {
                    self.should_quit = true;
                    return;
                }
                KeyCode::Char('u') if mods.contains(KeyModifiers::CONTROL) => {
                    self.filter_query.clear();
                    self.clamp_overview_selection();
                }
                KeyCode::Esc => {
                    self.filter_query = self.filter_backup.clone();
                    self.filter_editing = false;
                }
                KeyCode::Enter => {
                    self.filter_editing = false;
                }
                KeyCode::Down => {
                    table_nudge(&mut self.table_state, 1, n);
                    self.sync_overview_selection(&snap);
                }
                KeyCode::Up => {
                    table_nudge(&mut self.table_state, -1, n);
                    self.sync_overview_selection(&snap);
                }
                KeyCode::PageDown => {
                    table_nudge(&mut self.table_state, PAGE_ROWS, n);
                    self.sync_overview_selection(&snap);
                }
                KeyCode::PageUp => {
                    table_nudge(&mut self.table_state, -PAGE_ROWS, n);
                    self.sync_overview_selection(&snap);
                }
                KeyCode::Backspace => {
                    self.filter_query.pop();
                    self.clamp_overview_selection();
                }
                KeyCode::Char(c) => {
                    self.filter_query.push(c);
                    self.clamp_overview_selection();
                }
                _ => {}
            }
            self.sync_search_pin();
            return;
        }

        match code {
            KeyCode::Char('c') if mods.contains(KeyModifiers::CONTROL) => self.should_quit = true,
            KeyCode::Char('q') | KeyCode::Esc => {
                if self.page == Page::CallDetail {
                    // Esc goes back to the previous list view.
                    self.close_detail();
                } else if self.page == Page::IpStats && self.ip_drill.is_some() {
                    // Esc closes the per-IP call drill-down.
                    self.ip_drill = None;
                } else {
                    self.should_quit = true;
                }
            }
            KeyCode::Left => {
                if self.page == Page::CallDetail {
                    self.close_detail();
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
            KeyCode::Char('2') => self.page = Page::CallDetail,
            KeyCode::Char('3') => self.page = Page::Heatmap,
            KeyCode::Char('4') => self.page = Page::Streams,
            KeyCode::Char('5') => self.page = Page::EventLog,
            KeyCode::Char('6') => self.page = Page::IpStats,
            KeyCode::Char('/') => {
                // The filter bar lives on the Overview page.
                self.page = Page::Overview;
                self.filter_editing = true;
                self.filter_backup = self.filter_query.clone();
                self.clamp_overview_selection();
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
                self.linked_call_id = None;
                self.b_leg_picker = false;
                self.ip_drill = None;
            }
            _ => self.page_key(code),
        }
    }

    fn close_detail(&mut self) {
        self.page = Page::Overview;
        self.focus_pending = None;
        self.linked_call_id = None;
        self.b_leg_picker = false;
        self.b_leg_query.clear();
        self.focus_id.lock().ok().map(|mut f| f.take());
    }

    /// Publish the current primary (+ optional linked) focus hint to the pipeline.
    fn publish_focus(&mut self, primary: String) {
        let hint = match &self.linked_call_id {
            Some(linked) => FocusHint::with_linked(primary.clone(), linked.clone()),
            None => FocusHint::primary(primary.clone()),
        };
        if let Ok(mut f) = self.focus_id.lock() {
            *f = Some(hint);
        }
        self.focus_pending = Some(primary);
    }

    fn open_b_leg_picker(&mut self) {
        self.b_leg_picker = true;
        self.b_leg_query.clear();
        self.b_leg_state.select(Some(0));
        self.set_status("pick b-leg Call-ID (Enter) — Esc cancel");
    }

    fn clear_b_leg_link(&mut self) {
        self.linked_call_id = None;
        self.b_leg_picker = false;
        if let Some(id) = self
            .focus_pending
            .clone()
            .or_else(|| self.selected_call.clone())
        {
            self.publish_focus(id);
            self.set_status("b-leg unlinked");
        }
    }

    fn b_leg_picker_key(&mut self, code: KeyCode) {
        let snap = self.snapshot();
        let primary = snap
            .focus
            .as_ref()
            .map(|f| f.call_id.as_str())
            .or(self.focus_pending.as_deref())
            .or(self.selected_call.as_deref())
            .unwrap_or("");
        let n = b_leg_candidates(&snap, primary, &self.b_leg_query).len();
        match code {
            KeyCode::Esc => {
                self.b_leg_picker = false;
                self.b_leg_query.clear();
                self.set_status("b-leg pick cancelled");
            }
            KeyCode::Enter => {
                let cands = b_leg_candidates(&snap, primary, &self.b_leg_query);
                let idx = self
                    .b_leg_state
                    .selected()
                    .or_else(|| (!cands.is_empty()).then_some(0));
                if let Some(i) = idx
                    && let Some(c) = cands.get(i)
                {
                    let linked = c.call_id.clone();
                    let primary = primary.to_string();
                    self.linked_call_id = Some(linked.clone());
                    self.b_leg_picker = false;
                    self.b_leg_query.clear();
                    self.publish_focus(primary);
                    self.set_status(format!("b-leg linked: {linked}"));
                }
            }
            KeyCode::Down => table_nudge(&mut self.b_leg_state, 1, n),
            KeyCode::Up => table_nudge(&mut self.b_leg_state, -1, n),
            KeyCode::PageDown => table_nudge(&mut self.b_leg_state, PAGE_ROWS, n),
            KeyCode::PageUp => table_nudge(&mut self.b_leg_state, -PAGE_ROWS, n),
            KeyCode::Backspace => {
                self.b_leg_query.pop();
            }
            KeyCode::Char(c) => self.b_leg_query.push(c),
            _ => {}
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
        self.linked_call_id = None;
        self.b_leg_picker = false;
        self.b_leg_query.clear();
        self.publish_focus(call_id);
        self.page = Page::CallDetail;
        self.raw_scroll = 0;
        self.flow_state.select(Some(0));
    }

    /// Calls currently visible under the state filter (`f`) AND the rule
    /// filter bar query, in display order.
    pub fn filtered_calls<'a>(&self, snap: &'a Snapshot) -> Vec<&'a CallSummary> {
        let rules = crate::filter::parse(&self.filter_query);
        snap.calls
            .iter()
            .filter(|c| self.filter.matches(c.state))
            .filter(|c| crate::filter::matches(*c, &rules))
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
        let overview_n = self.filtered_calls(&snap).len();
        let flow_n = snap.focus.as_ref().map(|f| f.messages.len()).unwrap_or(0);
        match self.page {
            Page::Overview => match code {
                KeyCode::Down => {
                    table_nudge(&mut self.table_state, 1, overview_n);
                    self.sync_overview_selection(&snap);
                }
                KeyCode::Up => {
                    table_nudge(&mut self.table_state, -1, overview_n);
                    self.sync_overview_selection(&snap);
                }
                KeyCode::PageDown => {
                    table_nudge(&mut self.table_state, PAGE_ROWS, overview_n);
                    self.sync_overview_selection(&snap);
                }
                KeyCode::PageUp => {
                    table_nudge(&mut self.table_state, -PAGE_ROWS, overview_n);
                    self.sync_overview_selection(&snap);
                }
                KeyCode::Char('c') => {
                    if self.filter_query.is_empty() {
                        self.set_status("no filter to clear");
                    } else {
                        self.filter_query.clear();
                        self.filter_editing = false;
                        self.sync_search_pin();
                        self.clamp_overview_selection();
                        self.set_status("filter cleared");
                    }
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
            Page::CallDetail => match code {
                KeyCode::Down => table_nudge(&mut self.flow_state, 1, flow_n),
                KeyCode::Up => table_nudge(&mut self.flow_state, -1, flow_n),
                KeyCode::PageDown => {
                    self.raw_scroll = self.raw_scroll.saturating_add(PAGE_ROWS as usize);
                }
                KeyCode::PageUp => {
                    self.raw_scroll = self.raw_scroll.saturating_sub(PAGE_ROWS as usize);
                }
                KeyCode::Char('l') => self.open_b_leg_picker(),
                KeyCode::Char('L') => self.clear_b_leg_link(),
                _ => {}
            },
            Page::Streams => match code {
                KeyCode::Down => table_nudge(&mut self.streams_state, 1, snap.streams.len()),
                KeyCode::Up => table_nudge(&mut self.streams_state, -1, snap.streams.len()),
                KeyCode::PageDown => {
                    table_nudge(&mut self.streams_state, PAGE_ROWS, snap.streams.len())
                }
                KeyCode::PageUp => {
                    table_nudge(&mut self.streams_state, -PAGE_ROWS, snap.streams.len())
                }
                _ => {}
            },
            Page::EventLog => match code {
                KeyCode::Down => self.eventlog_scroll = self.eventlog_scroll.saturating_add(1),
                KeyCode::Up => self.eventlog_scroll = self.eventlog_scroll.saturating_sub(1),
                KeyCode::PageDown => {
                    self.eventlog_scroll = self.eventlog_scroll.saturating_add(PAGE_ROWS as u16);
                }
                KeyCode::PageUp => {
                    self.eventlog_scroll = self.eventlog_scroll.saturating_sub(PAGE_ROWS as u16);
                }
                _ => {}
            },
            Page::IpStats => self.ip_key(code, &snap),
            Page::Heatmap => {
                // Rows = ALL row + per-IP rows.
                let n = snap.sip_stats.len().max(1);
                match code {
                    KeyCode::Char('s') => {
                        self.sip_sort = self.sip_sort.next();
                        self.set_status(format!("SIP sort = {}", self.sip_sort.label()));
                    }
                    KeyCode::Char('w') => {
                        let vals = crate::store::sipstats::SERIES_BUCKETS;
                        let i = vals
                            .iter()
                            .position(|&s| s == self.sip_window_secs)
                            .unwrap_or(0);
                        self.sip_window_secs = vals[(i + 1) % vals.len()];
                        self.set_status(format!("ASR bucket = {}s", self.sip_window_secs));
                    }
                    KeyCode::Down => table_nudge(&mut self.sip_table_state, 1, n),
                    KeyCode::Up => table_nudge(&mut self.sip_table_state, -1, n),
                    KeyCode::PageDown => table_nudge(&mut self.sip_table_state, PAGE_ROWS, n),
                    KeyCode::PageUp => table_nudge(&mut self.sip_table_state, -PAGE_ROWS, n),
                    _ => {}
                }
            }
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
            let calls_len = crate::ui::ipstats::calls_for_ip(snap, self.ip_drill).len();
            match code {
                KeyCode::Down => {
                    table_nudge(&mut self.ip_drill_state, 1, calls_len);
                }
                KeyCode::Up => {
                    table_nudge(&mut self.ip_drill_state, -1, calls_len);
                }
                KeyCode::PageDown => {
                    table_nudge(&mut self.ip_drill_state, PAGE_ROWS, calls_len);
                }
                KeyCode::PageUp => {
                    table_nudge(&mut self.ip_drill_state, -PAGE_ROWS, calls_len);
                }
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
        let n = snap.ip_stats.len();
        match code {
            KeyCode::Down => {
                table_nudge(&mut self.ip_table_state, 1, n);
            }
            KeyCode::Up => {
                table_nudge(&mut self.ip_table_state, -1, n);
            }
            KeyCode::PageDown => {
                table_nudge(&mut self.ip_table_state, PAGE_ROWS, n);
            }
            KeyCode::PageUp => {
                table_nudge(&mut self.ip_table_state, -PAGE_ROWS, n);
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

/// Rows jumped by PageUp / PageDown on tables and the event log.
const PAGE_ROWS: i32 = 10;

fn is_nav_key(code: KeyCode) -> bool {
    matches!(
        code,
        KeyCode::Up
            | KeyCode::Down
            | KeyCode::Left
            | KeyCode::Right
            | KeyCode::PageUp
            | KeyCode::PageDown
            | KeyCode::Tab
            | KeyCode::BackTab
            | KeyCode::Home
            | KeyCode::End
    )
}

fn table_nudge(state: &mut TableState, delta: i32, len: usize) {
    if len == 0 {
        return;
    }
    let max = (len - 1) as i32;
    // No selection yet: Down/PageDown start before row 0 so the first Down
    // lands on 0 (matching TableState::select_next). Up/PageUp stay at 0.
    let cur = match state.selected() {
        Some(i) => i as i32,
        None if delta > 0 => -1,
        None => 0,
    };
    let next = (cur + delta).clamp(0, max) as usize;
    state.select(Some(next));
}

/// Candidates for the b-leg picker: every call except the focused primary,
/// filtered by the same rule syntax as the Overview filter bar.
pub fn b_leg_candidates<'a>(
    snap: &'a Snapshot,
    primary: &str,
    query: &str,
) -> Vec<&'a CallSummary> {
    let rules = crate::filter::parse(query);
    snap.calls
        .iter()
        .filter(|c| c.call_id != primary)
        .filter(|c| crate::filter::matches(*c, &rules))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    fn app() -> App {
        App::new(
            wrap_snap(Snapshot::default()),
            Arc::new(AtomicBool::new(false)),
            Arc::new(Mutex::new(None)),
            Arc::new(AtomicBool::new(false)),
            RecordState::default(),
        )
    }

    fn app_with_snap(snap: Snapshot) -> App {
        App::new(
            wrap_snap(snap),
            Arc::new(AtomicBool::new(false)),
            Arc::new(Mutex::new(None)),
            Arc::new(AtomicBool::new(false)),
            RecordState::default(),
        )
    }

    #[test]
    fn tab_cycles_all_six_pages_including_call_detail() {
        let mut a = app();
        // From Call Detail, Tab advances to the next page (not the pane).
        a.page = Page::CallDetail;
        a.on_key(KeyCode::Tab, KeyModifiers::NONE);
        assert_eq!(a.page, Page::Heatmap);
        // Shift-Tab goes back to the previous page.
        a.on_key(KeyCode::BackTab, KeyModifiers::NONE);
        assert_eq!(a.page, Page::CallDetail);
        // A full wrap of 6 Tab presses lands back on the start page.
        a.page = Page::Overview;
        for _ in 0..Page::ALL.len() {
            a.on_key(KeyCode::Tab, KeyModifiers::NONE);
        }
        assert_eq!(a.page, Page::Overview);
    }

    #[test]
    fn call_detail_l_opens_picker_and_unlinks() {
        let mut a = app();
        a.page = Page::CallDetail;
        a.selected_call = Some("a".into());
        a.focus_pending = Some("a".into());
        a.on_key(KeyCode::Char('l'), KeyModifiers::NONE);
        assert!(a.b_leg_picker, "l must open the b-leg picker");
        a.on_key(KeyCode::Esc, KeyModifiers::NONE);
        assert!(!a.b_leg_picker, "Esc closes picker without leaving detail");
        assert_eq!(a.page, Page::CallDetail);

        a.linked_call_id = Some("b".into());
        a.on_key(KeyCode::Char('L'), KeyModifiers::NONE);
        assert!(a.linked_call_id.is_none(), "L unlinks the b-leg");
        let hint = a.focus_id.lock().unwrap().clone();
        assert_eq!(
            hint,
            Some(FocusHint::primary("a")),
            "unlinking republishes primary-only focus"
        );
    }

    #[test]
    fn filter_edit_mode_navigates_and_enter_commits() {
        let mut a = app_with_calls();
        // `/` jumps to Overview and enters edit mode with row 0 preselected.
        a.page = Page::IpStats;
        a.on_key(KeyCode::Char('/'), KeyModifiers::NONE);
        assert_eq!(a.page, Page::Overview);
        assert!(a.filter_editing);
        assert_eq!(a.table_state.selected(), Some(0), "row 0 preselected");
        // Typing filters live; ↑↓ move the selection without leaving edit mode.
        for c in "bob".chars() {
            a.on_key(KeyCode::Char(c), KeyModifiers::NONE);
        }
        assert!(a.filter_editing);
        a.on_key(KeyCode::Down, KeyModifiers::NONE);
        assert!(a.filter_editing, "arrows stay in edit mode");
        // Enter commits the filter (no page change), then opens the selected
        // call on a second Enter.
        a.on_key(KeyCode::Enter, KeyModifiers::NONE);
        assert!(!a.filter_editing);
        assert_eq!(a.page, Page::Overview);
        a.on_key(KeyCode::Enter, KeyModifiers::NONE);
        assert_eq!(a.page, Page::CallDetail);
        assert_eq!(
            a.selected_call.as_deref(),
            Some("call-bobby"),
            "Enter must open the highlighted row, not the first match"
        );
    }

    #[test]
    fn filter_esc_rolls_back_and_c_clears() {
        let mut a = app_with_calls();
        a.filter_query = "caller:alice".into();
        a.on_key(KeyCode::Char('/'), KeyModifiers::NONE);
        for c in "caller:zzz".chars() {
            a.on_key(KeyCode::Char(c), KeyModifiers::NONE);
        }
        // Esc restores the pre-edit query (backup taken at `/`).
        a.on_key(KeyCode::Esc, KeyModifiers::NONE);
        assert_eq!(a.filter_query, "caller:alice", "Esc must roll back");
        // `c` on Overview clears the filter in one keystroke.
        a.on_key(KeyCode::Char('c'), KeyModifiers::NONE);
        assert!(a.filter_query.is_empty());
        let pin = a.search_pin.lock().unwrap().clone();
        assert!(pin.is_none(), "cleared filter must drop the pin");
        // `c` with no filter is a harmless no-op.
        a.on_key(KeyCode::Char('c'), KeyModifiers::NONE);
        assert!(a.filter_query.is_empty());
    }

    #[test]
    fn filter_selection_clamps_when_query_shrinks_results() {
        let mut a = app_with_calls();
        a.on_key(KeyCode::Char('/'), KeyModifiers::NONE);
        for c in "999".chars() {
            a.on_key(KeyCode::Char(c), KeyModifiers::NONE);
        }
        assert_eq!(a.table_state.selected(), None, "no results: no selection");
        // Removing the query restores a valid selection.
        a.on_key(KeyCode::Backspace, KeyModifiers::NONE);
        a.on_key(KeyCode::Backspace, KeyModifiers::NONE);
        a.on_key(KeyCode::Backspace, KeyModifiers::NONE);
        assert_eq!(a.table_state.selected(), Some(0));
    }

    fn app_with_calls() -> App {
        use crate::model::sip::{CallState, Outcome};
        use crate::store::registry::CallSummary;
        let mut snap = Snapshot::default();
        for (id, user) in [
            ("call-alice", "alice"),
            ("call-bob", "bob"),
            ("call-bobby", "bobby"),
        ] {
            snap.calls.push(CallSummary {
                call_id: id.into(),
                from_user: Some(user.into()),
                to_user: Some("x".into()),
                caller_ip: None,
                caller_src: None,
                state: CallState::Completed,
                outcome: Outcome::Answered,
                invite_ts: Some(1_000_000),
                duration_ms: Some(1_000),
                pdd_ms: None,
                setup_ms: None,
                ring_ms: None,
                ring_code: None,
                early_media: false,
                hangup_by: None,
                hangup_code: None,
                pkts_sip: 1,
                pkts_rtp: 0,
                best_mos: None,
                warn_count: 0,
                critical_count: 0,
                stream_count: 0,
                via_turn: false,
                ips: vec!["10.0.0.1".parse().unwrap()],
            });
        }
        let a = app();
        *a.snap.lock().unwrap() = Arc::new(snap);
        a
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
            "2 Detail",
            "3 SIP Stats",
            "4 Streams",
            "5 EventLog",
            "6 IP Stats",
        ] {
            assert!(row.contains(label), "tab bar missing {label}: {row:?}");
        }
        // The selected page (7 IP Stats → now 6 IP Stats) is highlighted with
        // the accent bg.
        let start = row.find("6 IP Stats").unwrap();
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

    #[test]
    fn topbar_distinguishes_pcap_and_interface_drops() {
        let mut a = app_with_snap(Snapshot {
            source: "live:any".into(),
            pkts_pcap_recv: 88,
            pkts_pcap_drop: 12,
            pkts_if_drop: 3,
            ..Snapshot::default()
        });
        let mut terminal = Terminal::new(TestBackend::new(150, 24)).unwrap();
        terminal.draw(|f| crate::ui::render(f, &mut a)).unwrap();
        let buf = terminal.backend().buffer().clone();
        let top: String = (0..buf.area.width).map(|x| buf[(x, 0)].symbol()).collect();
        assert!(
            top.contains("pcap_drop 12 (12.0%)"),
            "top bar missing libpcap drop counter: {top:?}"
        );
        assert!(
            top.contains("if_drop 3 (3.3%)"),
            "top bar missing interface drop counter: {top:?}"
        );
        assert!(
            !top.contains("ifdrop"),
            "top bar must not conflate libpcap drops with ifdrop: {top:?}"
        );
    }

    #[test]
    fn page_up_down_scrolls_lists() {
        let mut a = app();
        // Event log: PageDown used to be a no-op.
        a.page = Page::EventLog;
        a.on_key(KeyCode::PageDown, KeyModifiers::NONE);
        assert_eq!(a.eventlog_scroll, PAGE_ROWS as u16);
        a.on_key(KeyCode::PageUp, KeyModifiers::NONE);
        assert_eq!(a.eventlog_scroll, 0);

        // Call Detail raw pane: jump a page of lines, not one.
        a.page = Page::CallDetail;
        a.on_key(KeyCode::PageDown, KeyModifiers::NONE);
        assert_eq!(a.raw_scroll, PAGE_ROWS as usize);
        a.on_key(KeyCode::PageUp, KeyModifiers::NONE);
        assert_eq!(a.raw_scroll, 0);

        // IP Stats: PageDown selects a row (empty list stays unselected).
        a.page = Page::IpStats;
        a.on_key(KeyCode::PageDown, KeyModifiers::NONE);
        assert_eq!(a.ip_table_state.selected(), None);
    }
}
