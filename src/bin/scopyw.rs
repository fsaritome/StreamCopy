//! scopyw.exe — the sync tray app (Windows, `cargo build --release --features gui`). DESIGN-SYNC phase 5, first slice.
//!
//! - `scopyw` (started by the sync service in each user session once the user's agent runs): an icon in the
//!   notification area — green up to date, blue syncing, orange paused, red retrying, grey not running — with the
//!   state as tooltip and a menu: status window, sync now, pause/resume, open the folder, open the log, quit.
//! - `scopyw --window`: the status window (egui): every folder with its last round or error, the next round, the
//!   agent's recent log lines, the same buttons.
//!
//! It only reads what the agent publishes (status.rs: `status.toml`, the agent's mutex) and talks back through the
//! `paused` file and the wake-up event; it never connects to the receiver itself.

#![windows_subsystem = "windows"]

#[path = "../status.rs"]
mod status;

use eframe::egui::{self, Color32, RichText};
use status::{FolderStatus, Status};
use std::time::{Duration, Instant};
use tray_icon::menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem};
use tray_icon::{Icon, MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, ERROR_ALREADY_EXISTS};
use windows_sys::Win32::System::Threading::{CreateMutexW, OpenEventW, OpenMutexW, SetEvent, EVENT_MODIFY_STATE, SYNCHRONIZATION_SYNCHRONIZE};
use windows_sys::Win32::UI::Shell::ShellExecuteW;
use windows_sys::Win32::UI::WindowsAndMessaging::{DispatchMessageW, GetMessageW, PostQuitMessage, SetTimer, TranslateMessage, MSG, SW_SHOWNORMAL, WM_TIMER};

fn main() {
    let window = std::env::args().any(|a| a == "--window");
    // One tray icon and one status window per session.
    if !first_instance(if window { "Local\\scopy-status-window" } else { "Local\\scopy-tray" }) {
        return;
    }
    if window {
        let _ = run_window();
    } else if status::dir().join("sync.toml").exists() {
        run_tray();
    }
}

// ---- what to show ----

#[derive(Clone, Copy, PartialEq)]
enum Light {
    Ok,
    Syncing,
    Paused,
    Trouble,
    Off,
}

impl Light {
    fn color(self) -> Color32 {
        match self {
            Light::Ok => Color32::from_rgb(46, 160, 67),
            Light::Syncing => Color32::from_rgb(47, 129, 247),
            Light::Paused => Color32::from_rgb(210, 153, 34),
            Light::Trouble => Color32::from_rgb(218, 54, 51),
            Light::Off => Color32::from_rgb(130, 130, 130),
        }
    }
}

/// The agent's state as one light, a headline and a detail line.
struct View {
    light: Light,
    headline: String,
    detail: String,
    status: Option<Status>,
    running: bool,
    paused: bool,
}

fn view() -> View {
    let running = agent_running();
    let paused = status::pause_path().exists();
    let st = Status::load();
    let now = status::now();
    let (light, headline, detail) = match (&st, running) {
        (_, false) => (Light::Off, "Sync is not running".to_string(), "The sync service starts it at logon.".to_string()),
        (None, true) => (Light::Syncing, "Starting…".to_string(), String::new()),
        (Some(s), true) => {
            let errors: Vec<&FolderStatus> = s.folder.iter().filter(|f| !f.last_error.is_empty()).collect();
            let next = if s.next_round > now { format!("next round in {}", span(s.next_round - now)) } else { String::new() };
            let held: Vec<&FolderStatus> = s.folder.iter().filter(|f| f.held > 0).collect();
            if paused || s.state == "paused" {
                (Light::Paused, "Sync paused".into(), "Changes are kept and sent when you resume.".into())
            } else if let Some(h) = held.first() {
                (Light::Paused, "Deletes held".into(), format!("{} files removed from {} on this PC are still on the server", h.held, h.name))
            } else if let Some(b) = s.folder.iter().find(|f| !f.busy.is_empty()) {
                let first = b.busy[0].rsplit('/').next().unwrap_or(&b.busy[0]).to_string();
                let more = if b.busy.len() > 1 { format!(" and {} more", b.busy.len() - 1) } else { String::new() };
                (Light::Paused, "Waiting for open files".into(), format!("{first}{more} changed elsewhere: synced once closed here"))
            } else if s.state == "syncing" || s.state == "starting" {
                let names: Vec<&str> = s.folder.iter().filter(|f| f.syncing).map(|f| f.name.as_str()).collect();
                (Light::Syncing, format!("Syncing {}", if names.is_empty() { "…".to_string() } else { names.join(", ") }), format!("to {}", s.server))
            } else if !errors.is_empty() {
                (Light::Trouble, format!("Can't reach {}", s.server), format!("{} — {next}", short(&errors[0].last_error)))
            } else {
                let last = s.folder.iter().map(|f| f.last_ok).max().unwrap_or(0);
                let here: usize = s.folder.iter().map(|f| f.open_here.len()).sum();
                let there: usize = s.folder.iter().map(|f| f.open_elsewhere.len()).sum();
                let open = match (here, there) {
                    (0, 0) => String::new(),
                    (h, 0) => format!(" · {h} open here (locked for others)"),
                    (0, t) => format!(" · {t} open elsewhere (read-only here)"),
                    (h, t) => format!(" · {h} open here, {t} elsewhere"),
                };
                // With the server's change feed connected, server changes come down at once, not "next round in …".
                let next = if s.feed { "live".to_string() } else { next };
                (Light::Ok, "Up to date".into(), format!("last sync {} ago, {next}{open}", span(now.saturating_sub(last))))
            }
        }
    };
    View { light, headline, detail, status: st, running, paused }
}

fn span(secs: u64) -> String {
    match secs {
        0..=59 => format!("{secs} s"),
        60..=3599 => format!("{} min", secs / 60),
        3600..=86399 => format!("{} h {} min", secs / 3600, secs % 3600 / 60),
        _ => format!("{} days", secs / 86400),
    }
}

fn short(s: &str) -> String {
    let s = s.lines().next().unwrap_or("");
    if s.chars().count() > 90 {
        format!("{}…", s.chars().take(90).collect::<String>())
    } else {
        s.to_string()
    }
}

// ---- actions ----

fn sync_now() {
    let name = wide(status::WAKE_EVENT);
    // SAFETY: opens the agent's named event if it exists, signals it, closes the handle.
    unsafe {
        let h = OpenEventW(EVENT_MODIFY_STATE, 0, name.as_ptr());
        if !h.is_null() {
            SetEvent(h);
            CloseHandle(h);
        }
    }
}

fn set_paused(pause: bool) {
    let p = status::pause_path();
    if pause {
        let _ = std::fs::write(&p, b"paused from the tray app\n");
    } else {
        let _ = std::fs::remove_file(&p);
    }
    sync_now();
}

/// The user's answer to a held delete: removes them on the server too, or brings them back to this PC.
fn resolve_held(folder: &str, held: u64, delete: bool) {
    let (q, path) = if delete {
        (format!("Delete the {held} files removed from {folder} on the server too?\n\nThey go into the server's recycle bin and can be recovered from there."), status::confirm_path(folder))
    } else {
        (format!("Copy the {held} files back from the server into {folder} on this PC?"), status::restore_path(folder))
    };
    if ask(&q) {
        let _ = std::fs::write(&path, b"from the tray app\n");
        sync_now();
    }
}

fn ask(question: &str) -> bool {
    use windows_sys::Win32::UI::WindowsAndMessaging::{MessageBoxW, IDYES, MB_ICONQUESTION, MB_SETFOREGROUND, MB_YESNO};
    let (q, title) = (wide(question), wide("scopy sync"));
    // SAFETY: a modal message box with NUL-terminated strings.
    unsafe { MessageBoxW(std::ptr::null_mut(), q.as_ptr(), title.as_ptr(), MB_YESNO | MB_ICONQUESTION | MB_SETFOREGROUND) == IDYES }
}

/// The first folder with held deletes: (name, files).
fn held_folder(v: &View) -> Option<(String, u64)> {
    v.status.as_ref()?.folder.iter().find(|f| f.held > 0).map(|f| (f.name.clone(), f.held))
}

fn open(path: &str) {
    let (verb, file) = (wide("open"), wide(path));
    // SAFETY: plain ShellExecute with NUL-terminated strings.
    unsafe { ShellExecuteW(std::ptr::null_mut(), verb.as_ptr(), file.as_ptr(), std::ptr::null(), std::ptr::null(), SW_SHOWNORMAL) };
}

fn open_window() {
    if let Ok(exe) = std::env::current_exe() {
        let _ = std::process::Command::new(exe).arg("--window").spawn();
    }
}

fn first_folder() -> Option<String> {
    Status::load().and_then(|s| s.folder.first().map(|f| f.local.clone()))
}

fn agent_running() -> bool {
    let name = wide(status::AGENT_MUTEX);
    // SAFETY: only checks whether the agent's named mutex exists; the handle is closed at once.
    unsafe {
        let h = OpenMutexW(SYNCHRONIZATION_SYNCHRONIZE, 0, name.as_ptr());
        if h.is_null() {
            return false;
        }
        CloseHandle(h);
        true
    }
}

fn first_instance(name: &str) -> bool {
    let n = wide(name);
    // SAFETY: a named mutex held (leaked) for the life of the process.
    unsafe {
        let h = CreateMutexW(std::ptr::null(), 0, n.as_ptr());
        !h.is_null() && GetLastError() != ERROR_ALREADY_EXISTS
    }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain([0]).collect()
}

// ---- tray icon ----

/// A round light with a soft rim, drawn in code (no image files).
fn light_icon(light: Light) -> Icon {
    const N: u32 = 32;
    let c = light.color();
    let mut rgba = Vec::with_capacity((N * N * 4) as usize);
    let mid = (N as f32 - 1.0) / 2.0;
    for y in 0..N {
        for x in 0..N {
            let d = ((x as f32 - mid).powi(2) + (y as f32 - mid).powi(2)).sqrt();
            let alpha = (14.5 - d).clamp(0.0, 1.0); // anti-aliased edge
            let shade = if d > 11.5 { 0.75 } else { 1.0 }; // darker rim
            let hi = if ((x as f32 - mid + 4.0).powi(2) + (y as f32 - mid + 4.0).powi(2)).sqrt() < 4.0 { 40.0 } else { 0.0 };
            let ch = |v: u8| ((v as f32 * shade + hi).min(255.0)) as u8;
            rgba.extend_from_slice(&[ch(c.r()), ch(c.g()), ch(c.b()), (alpha * 255.0) as u8]);
        }
    }
    Icon::from_rgba(rgba, N, N).expect("icon")
}

fn run_tray() {
    let state = MenuItem::new("scopy sync", false, None);
    let detail = MenuItem::new("", false, None);
    let window = MenuItem::new("Open status window", true, None);
    let now = MenuItem::new("Sync now", true, None);
    let pause = MenuItem::new("Pause sync", true, None);
    let folder = MenuItem::new("Open synced folder", true, None);
    let del_held = MenuItem::new("Delete them on the server too…", false, None);
    let restore_held = MenuItem::new("Restore them to this PC…", false, None);
    let log = MenuItem::new("Open log", true, None);
    let bin = MenuItem::new("Open recycle bin", true, None);
    let quit = MenuItem::new("Quit tray icon", true, None);
    let menu = Menu::new();
    let _ = menu.append_items(&[
        &state,
        &detail,
        &del_held,
        &restore_held,
        &PredefinedMenuItem::separator(),
        &window,
        &now,
        &pause,
        &folder,
        &log,
        &bin,
        &PredefinedMenuItem::separator(),
        &quit,
    ]);
    let mut v = view();
    let Ok(tray) = TrayIconBuilder::new().with_menu(Box::new(menu)).with_tooltip(tip(&v)).with_icon(light_icon(v.light)).build() else {
        return;
    };
    // SAFETY: a thread timer (no window) that wakes the message loop four times a second.
    unsafe { SetTimer(std::ptr::null_mut(), 0, 250, None) };
    let mut last = Instant::now();
    let mut light = v.light;
    let mut msg: MSG = unsafe { std::mem::zeroed() };
    // SAFETY: the standard Win32 message loop of this thread (tray-icon's hidden window lives on it).
    while unsafe { GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) } > 0 {
        unsafe {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        if msg.message != WM_TIMER {
            continue;
        }
        while let Ok(ev) = MenuEvent::receiver().try_recv() {
            let id = ev.id();
            if id == window.id() {
                open_window();
            } else if id == now.id() {
                sync_now();
            } else if id == pause.id() {
                set_paused(!v.paused);
                last = Instant::now() - Duration::from_secs(5); // show it at once
            } else if id == folder.id() {
                if let Some(f) = first_folder() {
                    open(&f);
                }
            } else if id == del_held.id() || id == restore_held.id() {
                if let Some((name, n)) = held_folder(&v) {
                    resolve_held(&name, n, id == del_held.id());
                }
            } else if id == log.id() {
                open(&status::log_path().display().to_string());
            } else if id == bin.id() {
                open_recycle_bin();
            } else if id == quit.id() {
                unsafe { PostQuitMessage(0) };
            }
        }
        while let Ok(ev) = TrayIconEvent::receiver().try_recv() {
            match ev {
                TrayIconEvent::Click { button: MouseButton::Left, button_state: MouseButtonState::Up, .. } | TrayIconEvent::DoubleClick { .. } => open_window(),
                _ => {}
            }
        }
        if last.elapsed() >= Duration::from_secs(1) {
            last = Instant::now();
            v = view();
            if v.light != light {
                light = v.light;
                let _ = tray.set_icon(Some(light_icon(light)));
            }
            let _ = tray.set_tooltip(Some(tip(&v)));
            state.set_text(&v.headline);
            detail.set_text(if v.detail.is_empty() { " " } else { &v.detail });
            pause.set_text(if v.paused { "Resume sync" } else { "Pause sync" });
            now.set_enabled(v.running && !v.paused);
            let held = held_folder(&v).is_some() && v.running;
            del_held.set_enabled(held);
            restore_held.set_enabled(held);
        }
    }
}

/// The tooltip (Windows allows 127 characters).
fn tip(v: &View) -> String {
    let t = if v.detail.is_empty() { format!("scopy sync: {}", v.headline) } else { format!("scopy sync: {}\n{}", v.headline, v.detail) };
    t.chars().take(127).collect()
}

// ---- status window ----

fn run_window() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_title("scopy sync").with_inner_size([560.0, 600.0]).with_min_inner_size([420.0, 360.0]),
        ..Default::default()
    };
    eframe::run_native("scopy sync", options, Box::new(|_cc| Ok(Box::new(StatusWindow::new()))))
}

struct StatusWindow {
    v: View,
    log: Vec<String>,
    refreshed: Instant,
    options: Option<Options>,
}

/// The Options panel's working copy: the agent's settings and the folder choice (from sync.toml).
struct Options {
    settings: status::Settings,
    ask: bool,
    folders: Vec<(String, bool, String)>,
    message: String,
}

/// The folders a user can sync, and for each whether it is enabled and where it is on this PC.
const FOLDERS: [&str; 3] = ["Desktop", "Documents", "Downloads"];

fn enrolled() -> (String, u16, Vec<(String, String)>) {
    let v: toml::Value = std::fs::read_to_string(status::dir().join("sync.toml")).ok().and_then(|t| toml::from_str(&t).ok()).unwrap_or(toml::Value::Table(Default::default()));
    let server = v.get("server").and_then(|s| s.as_str()).unwrap_or_default().to_string();
    let port = v.get("port").and_then(|p| p.as_integer()).unwrap_or(7788) as u16;
    let folders = v
        .get("folder")
        .and_then(|f| f.as_array())
        .map(|a| a.iter().filter_map(|f| Some((f.get("name")?.as_str()?.to_string(), f.get("local")?.as_str()?.to_string()))).collect())
        .unwrap_or_default();
    (server, port, folders)
}

impl Options {
    fn load() -> Self {
        let settings = status::Settings::load();
        let (_, _, on) = enrolled();
        let folders = FOLDERS
            .iter()
            .map(|n| {
                let local = on.iter().find(|(name, _)| name.eq_ignore_ascii_case(n)).map(|(_, l)| l.clone());
                (n.to_string(), local.is_some(), local.unwrap_or_default())
            })
            .collect();
        Options { ask: settings.confirm_deletes_over > 0, settings, folders, message: String::new() }
    }

    /// Saves the settings (the agent reads them every round) and, if the folder choice changed, enrols again
    /// (`scopy sync enable`, which rewrites sync.toml; the agent then restarts with the new folders).
    fn apply(&mut self) {
        if !self.ask {
            self.settings.confirm_deletes_over = 0;
        }
        self.message = match self.settings.save() {
            Ok(()) => "Saved.".into(),
            Err(e) => format!("Cannot save the options: {e}"),
        };
        let (server, port, on) = enrolled();
        let want: Vec<&str> = self.folders.iter().filter(|f| f.1).map(|f| f.0.as_str()).collect();
        let now: Vec<&str> = FOLDERS.iter().copied().filter(|n| on.iter().any(|(o, _)| o.eq_ignore_ascii_case(n))).collect();
        if want != now && !server.is_empty() {
            if want.is_empty() {
                self.message = "Keep at least one folder (to stop syncing, quit the tray icon and ask your admin).".into();
                return;
            }
            let exe = std::env::current_exe().map(|e| e.with_file_name("scopy.exe")).unwrap_or_default();
            let mut cmd = std::process::Command::new(exe);
            cmd.args(["sync", "enable", "--server", &server, "--port", &port.to_string()]);
            for w in &want {
                cmd.args(["--folder", w]);
            }
            use std::os::windows::process::CommandExt;
            self.message = match cmd.creation_flags(0x0800_0000).output() {
                Ok(o) if o.status.success() => format!("Saved. Now syncing: {}.", want.join(", ")),
                Ok(o) => format!("The server refused: {}", String::from_utf8_lossy(&o.stderr).lines().last().unwrap_or("")),
                Err(e) => format!("Cannot run scopy.exe: {e}"),
            };
            *self = Options { message: std::mem::take(&mut self.message), ..Options::load() };
        }
        sync_now();
    }
}

impl StatusWindow {
    fn new() -> Self {
        let mut w = Self { v: view(), log: Vec::new(), refreshed: Instant::now(), options: None };
        w.log = log_tail(60);
        w
    }

    fn options_ui(&mut self, ui: &mut egui::Ui) {
        let Some(o) = &mut self.options else { return };
        let mut apply = false;
        egui::Frame::group(ui.style()).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.label(RichText::new("Options").size(16.0).strong());
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.label("Check the server for changes every");
                ui.add(egui::DragValue::new(&mut o.settings.check_secs).range(15..=3600).suffix(" s"));
            });
            ui.label(RichText::new("Changes made elsewhere (another PC, a terminal server) normally come down within a second through the server's change feed; this check is the fallback when the feed is not connected.").weak().small());
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                if ui.checkbox(&mut o.ask, "Ask before deleting more than").changed() && o.ask && o.settings.confirm_deletes_over == 0 {
                    o.settings.confirm_deletes_over = 100;
                }
                ui.add_enabled(o.ask, egui::DragValue::new(&mut o.settings.confirm_deletes_over).range(1..=1_000_000));
                ui.label("files on the server at once");
            });
            ui.label(RichText::new("Off: what you delete here is deleted on the server too (into its recycle bin), like any other change.").weak().small());
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.label("Keep files sync removed from this PC for");
                ui.add(egui::DragValue::new(&mut o.settings.recycle_days).range(0..=3650).suffix(" days"));
            });
            ui.label(RichText::new("In this PC's scopy recycle bin (menu: Open recycle bin); 0 = for ever. The server keeps its own recycle bin.").weak().small());
            ui.add_space(6.0);
            ui.label(RichText::new("Folders").strong());
            for (name, on, local) in &mut o.folders {
                ui.horizontal(|ui| {
                    ui.checkbox(on, name.as_str());
                    if local.starts_with(r"\\") {
                        ui.label(RichText::new(format!("{local} — redirected to the network, not synced")).color(Light::Trouble.color()).small());
                    } else if !local.is_empty() {
                        ui.label(RichText::new(local.as_str()).weak().small());
                    }
                });
            }
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                apply = ui.button("Save").clicked();
                if ui.button("Close").clicked() {
                    o.message = "close".into();
                }
                if o.message != "close" && !o.message.is_empty() {
                    ui.label(RichText::new(&o.message).weak());
                }
            });
        });
        if apply {
            o.apply();
        }
        if o.message == "close" {
            self.options = None;
        }
    }

    fn refresh(&mut self) {
        self.v = view();
        self.log = log_tail(60);
        self.refreshed = Instant::now();
    }
}

fn log_tail(n: usize) -> Vec<String> {
    let text = std::fs::read(status::log_path()).map(|b| String::from_utf8_lossy(&b[b.len().saturating_sub(64 * 1024)..]).into_owned()).unwrap_or_default();
    let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    lines[lines.len().saturating_sub(n)..].iter().map(|s| s.to_string()).collect()
}

/// The agent's latest progress line (`[01:20] 761/904 files (84.2%) | 571.4 MB / 18.4 GB (3.0%) | … | ETA 45:20`) as
/// the share of bytes sent and a short text.
/// This PC's scopy recycle bin (files a sync round removed or replaced here), created if it isn't there yet.
fn open_recycle_bin() {
    let bin = status::dir().join("recycle");
    let _ = std::fs::create_dir_all(&bin);
    open(&bin.display().to_string());
}

fn progress(log: &[String]) -> Option<(f32, String)> {
    let l = log.last().filter(|l| l.starts_with('[') && l.contains(" files ("))?;
    let parts: Vec<&str> = l.split(" | ").collect();
    let bytes = parts.get(1)?;
    let pct: f32 = bytes.rsplit_once('(')?.1.trim_end_matches(')').trim_end_matches('%').parse().ok()?;
    let size = bytes.rsplit_once(" (")?.0;
    let speed = parts.get(2).and_then(|s| s.split(" data").next()).unwrap_or("");
    let eta = parts.iter().find_map(|p| p.strip_prefix("ETA ")).unwrap_or("");
    Some((pct / 100.0, format!("{size}  ·  {speed}  ·  {eta} left")))
}

fn dot(ui: &mut egui::Ui, light: Light, r: f32) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(r * 2.0 + 4.0, r * 2.0 + 4.0), egui::Sense::hover());
    ui.painter().circle_filled(rect.center(), r, light.color());
}

impl eframe::App for StatusWindow {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        if self.refreshed.elapsed() >= Duration::from_secs(1) {
            self.refresh();
        }
        ui.ctx().request_repaint_after(Duration::from_millis(1000));
        egui::CentralPanel::default().show(ui, |ui| {
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                dot(ui, self.v.light, 11.0);
                ui.vertical(|ui| {
                    ui.label(RichText::new(&self.v.headline).size(22.0).strong());
                    if !self.v.detail.is_empty() {
                        ui.label(RichText::new(&self.v.detail).weak());
                    }
                });
            });
            if let Some(s) = &self.v.status {
                ui.label(RichText::new(format!("{} on {}   ·   scopy {}", s.user, s.server, s.version)).small().weak());
            }
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                if ui.add_enabled(self.v.running && !self.v.paused, egui::Button::new("Sync now")).clicked() {
                    sync_now();
                }
                let label = if self.v.paused { "Resume" } else { "Pause" };
                if ui.add_enabled(self.v.running, egui::Button::new(label)).clicked() {
                    set_paused(!self.v.paused);
                    self.refreshed = Instant::now() - Duration::from_secs(5);
                }
                if ui.button("Open log").clicked() {
                    open(&status::log_path().display().to_string());
                }
                if ui.button("Recycle bin").clicked() {
                    open_recycle_bin();
                }
                if ui.button("Options").clicked() {
                    self.options = if self.options.is_some() { None } else { Some(Options::load()) };
                }
            });
            ui.add_space(8.0);
            self.options_ui(ui);
            ui.separator();
            let now = status::now();
            let folders = self.v.status.as_ref().map(|s| s.folder.clone()).unwrap_or_default();
            if folders.is_empty() {
                ui.label(RichText::new("No folders yet (scopy sync enable).").weak());
            }
            for f in &folders {
                egui::Frame::group(ui.style()).show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.horizontal(|ui| {
                        let light = if f.syncing {
                            Light::Syncing
                        } else if f.held > 0 || !f.busy.is_empty() {
                            Light::Paused
                        } else if !f.last_error.is_empty() {
                            Light::Trouble
                        } else if f.last_ok > 0 {
                            Light::Ok
                        } else {
                            Light::Off
                        };
                        dot(ui, light, 6.0);
                        ui.label(RichText::new(&f.name).size(16.0).strong());
                        if f.syncing {
                            ui.spinner();
                        }
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.small_button("Open").clicked() {
                                open(&f.local);
                            }
                        });
                    });
                    ui.label(RichText::new(format!("{}   to   {}", f.local, f.remote)).weak());
                    if f.held > 0 && !f.syncing {
                        egui::Frame::new().fill(Light::Paused.color().gamma_multiply(0.18)).corner_radius(4.0).inner_margin(8.0).show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            ui.label(RichText::new(format!("{} files deleted on this PC are still on the server.", f.held)).strong());
                            ui.label(RichText::new("You asked to confirm deleting this many at once (Options). What should happen?").weak());
                            ui.horizontal(|ui| {
                                if ui.add_enabled(self.v.running, egui::Button::new("Delete them on the server too")).clicked() {
                                    resolve_held(&f.name, f.held, true);
                                }
                                if ui.add_enabled(self.v.running, egui::Button::new("Restore them to this PC")).clicked() {
                                    resolve_held(&f.name, f.held, false);
                                }
                                ui.label(RichText::new("or leave it: they stay on the server").weak().small());
                            });
                        });
                    }
                    if !f.busy.is_empty() && !f.syncing {
                        egui::Frame::new().fill(Light::Paused.color().gamma_multiply(0.18)).corner_radius(4.0).inner_margin(8.0).show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            ui.label(RichText::new(format!("{} files are open here and wait:", f.busy.len())).strong());
                            for b in f.busy.iter().take(8) {
                                ui.label(RichText::new(b).monospace().small());
                            }
                            ui.label(RichText::new("They changed or were deleted elsewhere. Close them and they are synced; if you save one first, your version wins (or becomes a conflict copy).").weak().small());
                        });
                    }
                    if !f.open_here.is_empty() {
                        ui.label(RichText::new(format!("Open here, locked on the server for everyone else: {}", f.open_here.join(", "))).color(Light::Syncing.color()));
                    }
                    for e in &f.open_elsewhere {
                        ui.label(RichText::new(format!("{e} — read-only here until it is closed there")).color(Light::Syncing.color()));
                    }
                    if f.pushed + f.pulled + f.renamed + f.recycled + f.deleted_here + f.conflicts > 0 && !f.syncing {
                        let mut parts = Vec::new();
                        for (n, what) in [
                            (f.pushed, "sent up"),
                            (f.pulled, "fetched from the server"),
                            (f.renamed, "moved or renamed"),
                            (f.recycled, "deleted on the server"),
                            (f.deleted_here, "deleted here (removed elsewhere)"),
                            (f.conflicts, "conflicts (your version kept as a copy)"),
                        ] {
                            if n > 0 {
                                parts.push(format!("{n} {what}"));
                            }
                        }
                        ui.label(RichText::new(format!("Last change: {}", parts.join(", "))).weak());
                    }
                    if f.syncing {
                        match progress(&self.log) {
                            Some((share, text)) => {
                                ui.add(egui::ProgressBar::new(share).text(text));
                            }
                            None => {
                                ui.label("Sending changes…");
                            }
                        }
                    } else if !f.last_error.is_empty() {
                        ui.label(RichText::new(short(&f.last_error)).color(Light::Trouble.color()));
                    }
                    if f.last_ok > 0 {
                        ui.label(format!("Last synced {} ago (the round took {:.1} s)", span(now.saturating_sub(f.last_ok)), f.last_secs));
                    }
                });
                ui.add_space(4.0);
            }
            ui.add_space(6.0);
            egui::CollapsingHeader::new("Recent activity").default_open(true).show(ui, |ui| {
                egui::ScrollArea::vertical().stick_to_bottom(true).auto_shrink([false, false]).show(ui, |ui| {
                    for l in &self.log {
                        ui.label(RichText::new(l).monospace().small());
                    }
                });
            });
        });
    }
}
