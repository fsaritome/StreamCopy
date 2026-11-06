//! What the sync agent (`scopy sync run`) tells the tray app (`scopyw.exe`), and how the tray app talks back. Shared by
//! both binaries (scopyw includes this file with `#[path]`), so it depends only on std, serde and toml.
//!
//! - The agent rewrites `status.toml` next to `sync.toml` whenever its state changes (write to a temporary file, then
//!   rename, so a reader never sees half a file).
//! - The tray app pauses the agent by creating `paused` there and resumes it by removing it; after either, and for
//!   "sync now", it signals the named event WAKE_EVENT, which the agent waits on.
//! - Whether an agent runs at all: the agent holds the named mutex AGENT_MUTEX for its whole life.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Held by a running agent (one per session). Windows named objects; on other systems the agent doesn't use them
/// yet (a lock file / socket would be the equivalent).
#[cfg_attr(not(windows), allow(dead_code))]
pub const AGENT_MUTEX: &str = "Local\\scopy-sync-run";
/// Signalled by the tray app: "look again now" (sync now, pause, resume).
#[cfg_attr(not(windows), allow(dead_code))]
pub const WAKE_EVENT: &str = "Local\\scopy-sync-wake";

#[derive(Serialize, Deserialize, Default, Clone, PartialEq)]
pub struct Status {
    pub version: String,
    pub pid: u32,
    pub user: String,
    pub server: String,
    /// `starting`, `syncing`, `ok`, `held` (deletes kept on the server, see FolderStatus::held), `retrying` or `paused`.
    pub state: String,
    /// Unix seconds of this status.
    pub updated: u64,
    /// Unix seconds of the next planned round (full round, or the retry after a failure).
    pub next_round: u64,
    /// The receiver's change feed is connected: server changes come down within seconds, not only at `next_round`.
    #[serde(default)]
    pub feed: bool,
    pub folder: Vec<FolderStatus>,
}

#[derive(Serialize, Deserialize, Default, Clone, PartialEq)]
pub struct FolderStatus {
    pub name: String,
    pub local: String,
    pub remote: String,
    pub syncing: bool,
    /// Unix seconds of the last round that finished cleanly (0 = none yet).
    pub last_ok: u64,
    /// How long that round took, seconds.
    pub last_secs: f64,
    /// The last round's error ("" = it went well).
    pub last_error: String,
    /// Files removed on the PC that the receiver kept (more than the guard allows); 0 = nothing held.
    #[serde(default)]
    pub held: u64,
    /// The receiver's note on the last round (why something was held).
    #[serde(default)]
    pub note: String,
    /// Last round: moves/renames done on the receiver, and entries moved into the recycle bin.
    #[serde(default)]
    pub renamed: u64,
    #[serde(default)]
    pub recycled: u64,
    /// Last round: files sent up, fetched down, deleted on this PC (the server deleted them), conflicts.
    #[serde(default)]
    pub pushed: u64,
    #[serde(default)]
    pub pulled: u64,
    #[serde(default)]
    pub deleted_here: u64,
    #[serde(default)]
    pub conflicts: u64,
    /// Files waiting because a program has them open on this PC (deleted or changed on the server meanwhile).
    #[serde(default)]
    pub busy: Vec<String>,
    /// Documents open on this PC, locked on the server for everyone else.
    #[serde(default)]
    pub open_here: Vec<String>,
    /// Documents open on another PC or on the server ("path — open on PC …"); read-only here meanwhile.
    #[serde(default)]
    pub open_elsewhere: Vec<String>,
}

/// The user's options (`settings.toml` next to sync.toml), set in the tray app's window, read by the agent every
/// round: no restart needed.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
#[serde(default)]
pub struct Settings {
    /// How often the server is asked for changes (seconds; 15–3600). Changes on this PC go up within seconds anyway.
    pub check_secs: u64,
    /// Ask before deleting more than this many files on the server in one round; 0 = never ask (deletes are synced).
    pub confirm_deletes_over: u64,
    /// How long files deleted or replaced on this PC by a sync round stay in its scopy recycle bin, in days; 0 = for
    /// ever.
    pub recycle_days: u64,
}

impl Default for Settings {
    fn default() -> Self {
        Settings { check_secs: 60, confirm_deletes_over: 0, recycle_days: 30 }
    }
}

#[allow(dead_code)] // each binary uses one half
impl Settings {
    pub fn path() -> PathBuf {
        dir().join("settings.toml")
    }

    pub fn load() -> Settings {
        std::fs::read_to_string(Self::path()).ok().and_then(|t| toml::from_str(&t).ok()).unwrap_or_default()
    }

    pub fn save(&self) -> std::io::Result<()> {
        std::fs::write(Self::path(), toml::to_string(self).unwrap_or_default())
    }
}

/// `%LOCALAPPDATA%\scopy` (Linux: `$XDG_CONFIG_HOME/scopy` or `~/.config/scopy`).
pub fn dir() -> PathBuf {
    let base = if cfg!(windows) {
        std::env::var_os("LOCALAPPDATA").map(PathBuf::from)
    } else {
        std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from).or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
    };
    base.unwrap_or_else(|| PathBuf::from(".")).join("scopy")
}

pub fn status_path() -> PathBuf {
    dir().join("status.toml")
}

pub fn log_path() -> PathBuf {
    dir().join("sync.log")
}

pub fn pause_path() -> PathBuf {
    dir().join("paused")
}

/// Tray app → agent: "delete them on the server too" for a folder whose deletes are held (used by the next round).
pub fn confirm_path(folder: &str) -> PathBuf {
    dir().join(format!("delete-held.{folder}"))
}

/// Tray app → agent: "restore them to this PC" (the next round pulls the server's copy back first).
pub fn restore_path(folder: &str) -> PathBuf {
    dir().join(format!("restore-held.{folder}"))
}

pub fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

#[allow(dead_code)] // each binary uses one half
impl Status {
    pub fn load() -> Option<Status> {
        toml::from_str(&std::fs::read_to_string(status_path()).ok()?).ok()
    }

    pub fn save(&mut self) {
        self.updated = now();
        let path = status_path();
        let tmp = path.with_extension("toml.tmp");
        if let Ok(text) = toml::to_string(self) {
            if std::fs::write(&tmp, text).is_ok() {
                let _ = std::fs::rename(&tmp, &path);
            }
        }
    }
}
