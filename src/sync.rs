//! Sync, phase 1 step 3 (DESIGN-SYNC.md sections 6–7): the receiver's sync configuration and enrolment.
//!
//! The receiver owns where users' folders live: `scopy.toml` next to scopy.exe names one general root and the folder
//! names a client may sync. When a user enables sync on a PC, the client signs in (auth.rs) and asks to enrol; the
//! receiver — not the client — creates `<root>\<user>\<folder>` with home-folder permissions (owner = the user; full
//! control for the user, SYSTEM and Administrators; nothing inherited from the root). A client never names a path,
//! only folder names from the receiver's list. The root must lie in a share: that is where terminal servers
//! redirect to and how clients address the folders over SMB.
//!
//! Wire (KIND_ENROL): C→R sign-in, folders:u32 + names (none = all allowed);
//! R→C status, user:str, base:str (`share\path\user`), folders:u32 + names, created:u8.

use crate::auth;
use crate::proto::*;
use crate::shares::Shares;
use crate::tls::Binding;
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Receiver side: the `[sync]` section of `scopy.toml`.
#[derive(Deserialize)]
pub struct ReceiverSync {
    /// The general root (a local folder on the receiver, inside a share).
    pub root: PathBuf,
    /// The only folder names clients may sync, e.g. Desktop, Documents, Downloads.
    pub folders: Vec<String>,
    /// How long a file open on a PC stays locked here after that PC's last call (asleep, offline), in minutes.
    #[serde(default = "default_lock_minutes")]
    pub lock_minutes: u64,
    /// How long deleted and replaced files stay in the users' recycle bins here (`.scopy-recycle`), in days; 0 = for
    /// ever.
    #[serde(default = "default_recycle_days")]
    pub recycle_days: u64,
}

fn default_recycle_days() -> u64 {
    crate::recycle::DEFAULT_DAYS
}

/// Receiver: empties what is older than `[sync] recycle_days` from every user's recycle bin below the sync root
/// (as the service; links are not followed). Nothing to do without a `[sync]` section.
pub fn purge_receiver_bins() {
    let Ok(cfg) = receiver_config() else { return };
    let Ok(users) = fs::read_dir(&cfg.root) else { return };
    for u in users.flatten() {
        let bin = u.path().join(".scopy-recycle");
        // Unix daemon: empty each user's bin as that user (the owner of their folder), never as root inside a tree
        // the user controls.
        #[cfg(unix)]
        let _act = {
            use std::os::unix::fs::MetadataExt;
            let Ok(md) = fs::symlink_metadata(u.path()) else { continue };
            if !md.is_dir() {
                continue;
            }
            match auth::Identity::for_uid(md.uid()).and_then(|id| id.enter()) {
                Ok(a) => a,
                Err(e) => {
                    crate::logln!("recycle: {}: {e:#}", u.path().display());
                    continue;
                }
            }
        };
        let p = crate::recycle::purge(&bin, cfg.recycle_days, crate::status::now());
        if p.rounds > 0 {
            crate::logln!("recycle: {} older than {} days removed from {}: {} files, {}", p.rounds, cfg.recycle_days, bin.display(), p.files, crate::util::fmt_bytes(p.bytes));
        }
    }
}

/// PC: empties what is older than the retention (tray Options) from this PC's scopy recycle bin.
fn purge_pc_bin() {
    let days = crate::status::Settings::load().recycle_days;
    let bin = crate::status::dir().join("recycle");
    let p = crate::recycle::purge(&bin, days, crate::status::now());
    if p.rounds > 0 {
        eprintln!("[{}] recycle bin: {} rounds older than {days} days removed ({} files, {})", crate::util::utc_stamp(), p.rounds, p.files, crate::util::fmt_bytes(p.bytes));
    }
}

fn default_lock_minutes() -> u64 {
    120
}

/// The lock lease (`[sync] lock_minutes` in scopy.toml; 120 if unset).
pub fn lock_lease() -> std::time::Duration {
    std::time::Duration::from_secs(receiver_config().map_or(default_lock_minutes(), |c| c.lock_minutes).max(1) * 60)
}

#[derive(Deserialize)]
struct ReceiverFile {
    sync: Option<ReceiverSync>,
}

/// `scopy.toml` next to the executable (Linux/Unix: /etc/scopy/scopy.toml where it exists). Read when a user enrols
/// (rare), so a change needs no restart.
pub fn receiver_config_path() -> PathBuf {
    #[cfg(unix)]
    {
        let etc = PathBuf::from("/etc/scopy/scopy.toml");
        if etc.exists() {
            return etc;
        }
    }
    std::env::current_exe().map(|p| p.with_file_name("scopy.toml")).unwrap_or_else(|_| PathBuf::from("scopy.toml"))
}

fn receiver_config() -> Result<ReceiverSync> {
    let path = receiver_config_path();
    let text = auth::as_service(|| fs::read_to_string(&path))
        .with_context(|| format!("sync is not set up on this receiver (no {})", path.display()))?;
    let file: ReceiverFile = toml::from_str(&text).with_context(|| format!("{} is not valid", path.display()))?;
    file.sync.with_context(|| format!("sync is not set up on this receiver (no [sync] in {})", path.display()))
}

/// Client side: what `scopy sync enable` set up, for the sync agent (phase 1 step 4).
#[derive(Serialize, Deserialize)]
pub struct ClientConfig {
    pub server: String,
    pub port: u16,
    /// A Linux daemon: the SSH destination to sign in through (`ssh <it> scopy token`) before syncing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh: Option<String>,
    pub user: String,
    pub folder: Vec<ClientFolder>,
}

#[derive(Serialize, Deserialize)]
pub struct ClientFolder {
    pub name: String,
    /// The folder on this PC.
    pub local: PathBuf,
    /// The user's folder on the receiver, over SMB.
    pub remote: String,
}

/// `%LOCALAPPDATA%\scopy\sync.toml` (Linux: `$XDG_CONFIG_HOME/scopy` or `~/.config/scopy`).
pub fn client_config_path() -> PathBuf {
    crate::status::dir().join("sync.toml")
}

/// A user name usable as one folder name (no separators, no dots-only names, nothing Windows forbids).
fn folder_name(user: &str) -> Result<String> {
    let bad = |c: char| c.is_control() || r#"\/:*?"<>|"#.contains(c);
    if user.is_empty() || user.chars().any(bad) || user.trim_matches('.').is_empty() {
        bail!("user name {user:?} cannot be used as a folder name");
    }
    Ok(user.to_string())
}

/// Receiver: handles one enrolment.
pub fn handle_enrol(mut r: impl Read, mut w: impl Write, shares: &Shares, bind: &Binding) -> Result<()> {
    let Some(user) = auth::server(&mut r, &mut w, bind)? else {
        w.put_err("enrolling for sync needs a sign-in (Windows sign-in, or on Linux `scopy sync enable user@host::`)")?;
        bail!("enrolment without sign-in refused");
    };
    let n = r.get_u32()?.min(64);
    let asked: Vec<String> = (0..n).map(|_| r.get_str()).collect::<Result<_>>()?;
    match enrol(&user, &asked, shares) {
        Ok((base, folders, created)) => {
            crate::logln!("enrol {}: {} ({}), folders {}", user.user, base, if created { "created" } else { "already there" }, folders.join(", "));
            w.put_ok()?;
            w.put_str(&user.user)?;
            w.put_str(&base)?;
            w.put_u32(folders.len() as u32)?;
            for f in &folders {
                w.put_str(f)?;
            }
            w.put_u8(created as u8)?;
            w.flush()?;
            Ok(())
        }
        Err(e) => {
            w.put_err(&format!("{e:#}"))?;
            w.flush()?;
            bail!("enrol {}: {e:#}", user.user)
        }
    }
}

/// Creates the user's folders; returns (SMB path `share\…\user`, folder names, whether the user folder was new).
fn enrol(user: &auth::Identity, asked: &[String], shares: &Shares) -> Result<(String, Vec<String>, bool)> {
    let cfg = receiver_config()?;
    // Only names from the receiver's list, in the receiver's spelling.
    let folders: Vec<String> = if asked.is_empty() {
        cfg.folders.clone()
    } else {
        asked
            .iter()
            .map(|a| cfg.folders.iter().find(|f| f.eq_ignore_ascii_case(a)).cloned().with_context(|| format!("folder {a:?} is not offered by this receiver (allowed: {})", cfg.folders.join(", "))))
            .collect::<Result<_>>()?
    };
    let (share, rel) = shares
        .share_for(&cfg.root)
        .with_context(|| format!("the sync root {} is not inside a share on this receiver: share it (terminal servers redirect there)", cfg.root.display()))?;
    if !cfg.root.is_dir() {
        bail!("the sync root {} does not exist on the receiver", cfg.root.display());
    }
    let name = folder_name(&user.short_name())?;
    let dir = cfg.root.join(&name);
    crate::confine::no_links_below(&cfg.root, &dir)?;
    // scopy creates and secures the folders itself, as the service: the user needs no rights on the root.
    let created = auth::as_service(|| make_folders(&dir, user, &folders))?;
    let mut base = PathBuf::from(&share);
    if !rel.as_os_str().is_empty() {
        base.push(&rel);
    }
    base.push(&name);
    Ok((base.display().to_string(), folders, created))
}

/// `<root>\<user>` (secured like a home folder when it is new) and its sync folders, owned by the user.
#[cfg(windows)]
fn make_folders(dir: &Path, user: &auth::Identity, folders: &[String]) -> Result<bool> {
    let sid = user.sid()?;
    let created = !dir.exists();
    if created {
        fs::create_dir(dir).with_context(|| format!("cannot create {}", dir.display()))?;
        // An existing user folder keeps whatever permissions an admin gave it.
        acl(dir, &["/inheritance:r", "/grant:r", &format!("*{sid}:(OI)(CI)F"), "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F"])?;
        acl(dir, &["/setowner", &format!("*{sid}")])?;
    }
    for f in folders {
        let d = dir.join(f);
        if !d.exists() {
            fs::create_dir(&d).with_context(|| format!("cannot create {}", d.display()))?;
            acl(&d, &["/setowner", &format!("*{sid}")])?;
        }
    }
    Ok(created)
}

/// Sets permissions or the owner with icacls (it enables the privileges needed to give the folder to the user).
#[cfg(windows)]
fn acl(path: &Path, args: &[&str]) -> Result<()> {
    let out = std::process::Command::new("icacls").arg(path).args(args).arg("/Q").output().context("cannot run icacls")?;
    if !out.status.success() {
        bail!("icacls {} {}: {}", path.display(), args.join(" "), String::from_utf8_lossy(&out.stdout).trim());
    }
    Ok(())
}

/// Unix: `<root>/<user>` like a home folder (owner the user and their primary group, 0700) when it is new, and its
/// sync folders owned by the user. Made by root (the daemon): never through a link, and only folders it creates
/// itself are given away (`mkdir` fails on anything already there, so nothing the user planted is chowned).
#[cfg(unix)]
fn make_folders(dir: &Path, user: &auth::Identity, folders: &[String]) -> Result<bool> {
    use std::os::unix::fs::{lchown, MetadataExt, PermissionsExt};
    let give = |d: &Path, mode: u32| -> Result<()> {
        lchown(d, Some(user.uid), Some(user.gid)).with_context(|| format!("cannot give {} to {}", d.display(), user.user))?;
        fs::set_permissions(d, fs::Permissions::from_mode(mode)).with_context(|| d.display().to_string())
    };
    let created = match fs::create_dir(dir) {
        Ok(()) => {
            give(dir, 0o700)?;
            true
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => false,
        Err(e) => return Err(e).with_context(|| format!("cannot create {}", dir.display())),
    };
    let md = fs::symlink_metadata(dir)?;
    if !md.is_dir() || md.uid() != user.uid {
        bail!("{} exists but is not a folder of {}: ask the administrator", dir.display(), user.user);
    }
    for f in folders {
        let d = dir.join(f);
        match fs::create_dir(&d) {
            Ok(()) => give(&d, 0o700)?,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                if fs::symlink_metadata(&d).map_or(true, |m| !m.is_dir() || m.file_type().is_symlink()) {
                    bail!("{} is not a folder", d.display());
                }
            }
            Err(e) => return Err(e).with_context(|| format!("cannot create {}", d.display())),
        }
    }
    Ok(created)
}

/// A mirror round may delete on the receiver, so it is only allowed into the signed-in user's own sync folder:
/// `base` must be exactly `<root>\<user>\<folder>` for a folder the receiver offers.
pub fn check_mirror_target(user: Option<&auth::Identity>, base: &Path) -> Result<()> {
    let Some(user) = user else { bail!("mirroring (removing files on the receiver) needs a sign-in") };
    let cfg = receiver_config()?;
    let dir = cfg.root.join(folder_name(&user.short_name())?);
    // Windows paths are case-insensitive, Unix paths are not.
    let same = |a: &str, b: &str| if cfg!(windows) { a.eq_ignore_ascii_case(b) } else { a == b };
    let ok = cfg.folders.iter().any(|f| same(&dir.join(f).to_string_lossy(), &base.to_string_lossy()));
    if !ok {
        bail!("mirroring is only allowed into your own sync folders ({}\\<{}>)", dir.display(), cfg.folders.join("|"));
    }
    Ok(())
}

/// A part file or journal untouched this long, whose file is not part of the round, is removed by a sync round.
const ORPHAN_AGE: std::time::Duration = std::time::Duration::from_secs(3600);

/// Receiver, a sync round's deletes (decided by the PC: gone there, unchanged here since the last sync): each goes
/// into `<user folder>\.scopy-recycle\<folder>\<time>\…`, recoverable, if it is still exactly the version the PC
/// knew; a folder only once no file is left in it (so a file added here meanwhile keeps it). Files first, then
/// folders, deepest first. Returns (moved into the recycle bin, kept).
pub fn apply_deletes(base: &Path, deletes: &[Delete]) -> (u64, u64) {
    let stamp = crate::util::utc_stamp();
    let Some(bin) = base.parent().zip(base.file_name()).map(|(p, n)| p.join(".scopy-recycle").join(n).join(&stamp)) else { return (0, deletes.len() as u64) };
    let (mut done, mut kept) = (0u64, 0u64);
    let mut order: Vec<&Delete> = deletes.iter().collect();
    order.sort_by_key(|d| (d.dir, std::cmp::Reverse(d.path.matches('/').count())));
    for d in order {
        let r = (|| -> Result<bool> {
            if d.path.contains(".scopy-") {
                return Ok(false);
            }
            let from = base.join(crate::util::sanitize_rel(&d.path, false)?);
            let Ok(md) = fs::symlink_metadata(&from) else { return Ok(false) }; // already gone
            if md.file_type().is_symlink() || md.is_dir() != d.dir {
                return Ok(false);
            }
            if d.dir {
                if count_files(&from) > 0 {
                    return Ok(false);
                }
            } else if md.len() != d.size || (crate::meta::read(&md).mtime - d.mtime).abs() > 1_000_000 {
                return Ok(false); // changed here: the PC gets this version next round
            }
            let to = bin.join(crate::util::sanitize_rel(&d.path, false)?);
            if d.dir && to.is_dir() {
                // Its files went into the recycle bin a moment ago (the folder is there already): an empty folder
                // has nothing more to keep.
                fs::remove_dir_all(&from)?;
                return Ok(true);
            }
            if let Some(p) = to.parent() {
                fs::create_dir_all(p)?;
            }
            fs::rename(&from, &to)?;
            Ok(true)
        })();
        match r {
            Ok(true) => done += 1,
            Ok(false) => kept += 1,
            Err(e) => {
                kept += 1;
                crate::logln!("  delete {}: {e:#}", d.path);
            }
        }
    }
    if done > 0 {
        if let Some(top) = bin.parent().and_then(Path::parent) {
            let _ = crate::meta::set_attrs(top, crate::meta::ATTR_HIDDEN);
        }
    }
    (done, kept)
}

/// Receiver, after a clean sync round: part files and journals of interrupted transfers whose file is not in this
/// round (`entries`) and that nobody touched for an hour — incomplete data that no round will finish. Removed, not
/// recycled. Returns how many.
pub fn remove_orphans(base: &Path, entries: &[Entry]) -> usize {
    let norm = |s: &str| if cfg!(windows) { s.to_lowercase() } else { s.to_string() };
    let keep: std::collections::HashSet<String> = entries.iter().map(|e| norm(&e.path)).collect();
    let mut n = 0;
    let mut stack = vec![(base.to_path_buf(), String::new())];
    while let Some((dir, rel)) = stack.pop() {
        let Ok(rd) = fs::read_dir(&dir) else { continue };
        for ent in rd.flatten() {
            let name = ent.file_name().to_string_lossy().into_owned();
            let Ok(ft) = ent.file_type() else { continue };
            if ft.is_dir() && !ft.is_symlink() {
                stack.push((ent.path(), if rel.is_empty() { name } else { format!("{rel}/{name}") }));
                continue;
            }
            let Some(of) = name.strip_suffix(".scopy-part").or_else(|| name.strip_suffix(".scopy-journal")) else { continue };
            let r = if rel.is_empty() { of.to_string() } else { format!("{rel}/{of}") };
            let idle = ent.metadata().and_then(|m| m.modified()).ok().and_then(|t| t.elapsed().ok()).is_some_and(|d| d >= ORPHAN_AGE);
            if idle && !keep.contains(&norm(&r)) && fs::remove_file(ent.path()).is_ok() {
                n += 1;
            }
        }
    }
    n
}
/// Receiver, before a sync round's plan: does the renames and moves the PC saw (relative to `base`, the user's sync
/// folder; already checked by `check_mirror_target`). A move that doesn't fit — source gone or changed, target
/// taken, a link on the way — is skipped: the round then simply sends that file. Returns (done, skipped).
pub fn apply_moves(root: &Path, base: &Path, moves: &[Move]) -> (u64, u64) {
    let (mut done, mut skipped) = (0, 0);
    for m in moves {
        match move_one(root, base, m) {
            Ok(()) => done += 1,
            Err(e) => {
                skipped += 1;
                if skipped <= 20 {
                    crate::logln!("  move {} -> {}: {e:#}", m.from, m.to);
                }
            }
        }
    }
    (done, skipped)
}

fn move_one(root: &Path, base: &Path, m: &Move) -> Result<()> {
    if m.from.contains(".scopy-") || m.to.contains(".scopy-") {
        bail!("scopy's own files are not moved");
    }
    let from = base.join(crate::util::sanitize_rel(&m.from, false)?);
    let to = base.join(crate::util::sanitize_rel(&m.to, false)?);
    let parent = to.parent().context("no parent folder")?;
    crate::confine::no_links_below(root, &from)?;
    crate::confine::no_links_below(root, parent)?;
    let md = fs::symlink_metadata(&from).context("not here (any more)")?;
    if md.is_dir() != m.dir {
        bail!("a {} here", if md.is_dir() { "folder" } else { "file" });
    }
    if !m.dir && (md.len() != m.size || (crate::meta::read(&md).mtime - m.mtime).abs() > 1_000_000) {
        bail!("changed here since the PC synced it");
    }
    // NTFS names are case-insensitive: a rename that only changes case finds its own target.
    let case_only = cfg!(windows) && m.from.to_lowercase() == m.to.to_lowercase();
    if !case_only && fs::symlink_metadata(&to).is_ok() {
        bail!("the target exists");
    }
    fs::create_dir_all(parent)?;
    fs::rename(&from, &to)?;
    Ok(())
}

// ---- the PC's sync state: what each folder looked like after its last clean round ----

/// One file or folder as last synced: its file id (NTFS file id with sequence number; inode on Unix) recognises it
/// after a rename or move.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct Known {
    /// This PC's file id (NTFS), or the receiver's in a map built from its listing.
    id: u64,
    dir: bool,
    size: u64,
    mtime: i64,
    /// The receiver's file id of the synced version (0 = unknown): finds renames and moves made on the server.
    rid: u64,
}

pub(crate) type State = std::collections::HashMap<String, Known>;

fn state_path(folder: &str) -> PathBuf {
    crate::status::dir().join("state").join(format!("{folder}.tsv"))
}

/// Everything below `root` the way a sync round sees it (scopy's own and excluded files left out).
fn scan_state(root: &Path) -> State {
    let mut out = State::new();
    let mut stack = vec![(root.to_path_buf(), String::new())];
    while let Some((dir, rel)) = stack.pop() {
        #[cfg(windows)]
        let ids = crate::meta::dir_entry_ids(&dir);
        let Ok(rd) = fs::read_dir(&dir) else { continue };
        for ent in rd.flatten() {
            let name = ent.file_name();
            let n = name.to_string_lossy().into_owned();
            // On Windows a directory entry's metadata comes with the listing (no call per file, ~5x faster on 20,000
            // files); like symlink_metadata it does not follow links.
            let Ok(md) = ent.metadata() else { continue };
            let lower = n.to_lowercase();
            if md.file_type().is_symlink() || lower.contains(".scopy-") || (md.is_file() && SYNC_EXCLUDES.iter().any(|x| crate::util::wildcard(x, &lower))) {
                continue;
            }
            #[cfg(windows)]
            let id = ids.get(&name).copied().unwrap_or(0);
            #[cfg(not(windows))]
            let id = crate::meta::file_id(&md);
            let r = if rel.is_empty() { n } else { format!("{rel}/{n}") };
            if md.is_dir() {
                stack.push((ent.path(), r.clone()));
                out.insert(r, Known { id, dir: true, size: 0, mtime: 0, rid: 0 });
            } else {
                out.insert(r, Known { id, dir: false, size: md.len(), mtime: crate::meta::read(&md).mtime, rid: 0 });
            }
        }
    }
    out
}

/// `state` (a scan of `root`) brought up to date for the paths `rels` only: each is removed with everything below
/// it and, where it exists now, looked at again (a folder with its whole contents), by the same rules as
/// `scan_state`.
/// `a/b/c`, `a/b`, `a`.
fn self_or_ancestors(p: &str) -> impl Iterator<Item = &str> {
    std::iter::successors(Some(p), |q| q.rsplit_once('/').map(|(head, _)| head))
}

fn restat(root: &Path, state: &mut State, rels: Vec<String>) {
    let mut rels = rels;
    rels.sort_by_key(|p| (p.matches('/').count(), p.clone()));
    rels.dedup();
    // Everything at or below a path looked at again goes first, in one pass over the state (once per path was
    // quadratic: 85,000 paths in a 200,000-entry state took 165 s).
    let looked: std::collections::HashSet<&str> = rels.iter().map(String::as_str).collect();
    state.retain(|p, _| !self_or_ancestors(p).any(|a| looked.contains(a)));
    let mut relisted: std::collections::HashSet<String> = Default::default();
    // As `scan_state` sees it: never through a link, under the exact on-disk spelling.
    let mut look = crate::source::Look::new(root, true);
    #[cfg(windows)]
    let mut ids: std::collections::HashMap<PathBuf, std::collections::HashMap<std::ffi::OsString, u64>> = Default::default();
    for rel in rels {
        if self_or_ancestors(&rel).skip(1).any(|a| relisted.contains(a)) {
            continue;
        }
        let Ok(sub) = crate::util::sanitize_rel(&rel, false) else { continue };
        let full = root.join(sub);
        let crate::source::Seen::Here(md) = look.at(&rel) else { continue };
        let name = rel.rsplit('/').next().unwrap_or(&rel).to_lowercase();
        if md.file_type().is_symlink() || rel.to_lowercase().contains(".scopy-") || (md.is_file() && SYNC_EXCLUDES.iter().any(|x| crate::util::wildcard(x, &name))) {
            continue;
        }
        #[cfg(windows)]
        let id = {
            let parent = full.parent().unwrap_or(root).to_path_buf();
            ids.entry(parent.clone()).or_insert_with(|| crate::meta::dir_entry_ids(&parent)).get(full.file_name().unwrap_or_default()).copied().unwrap_or(0)
        };
        #[cfg(not(windows))]
        let id = crate::meta::file_id(&md);
        if md.is_dir() {
            state.insert(rel.clone(), Known { id, dir: true, size: 0, mtime: 0, rid: 0 });
            for (p, k) in scan_state(&full) {
                state.insert(format!("{rel}/{p}"), k);
            }
            relisted.insert(rel);
        } else {
            state.insert(rel, Known { id, dir: false, size: md.len(), mtime: crate::meta::read(&md).mtime, rid: 0 });
        }
    }
}

fn load_state(folder: &str) -> Option<State> {
    let text = fs::read_to_string(state_path(folder)).ok()?;
    let mut s = State::new();
    for l in text.lines() {
        let mut p = l.splitn(5, '\t');
        let (Some(id), Some(dir), Some(size), Some(mtime), Some(path)) = (p.next(), p.next(), p.next(), p.next(), p.next()) else { continue };
        // `id` or `id:rid` (0.20+: with the receiver's file id).
        let (id, rid) = id.split_once(':').unwrap_or((id, "0"));
        let (Ok(id), Ok(rid), Ok(size), Ok(mtime)) = (id.parse(), rid.parse(), size.parse(), mtime.parse()) else { continue };
        s.insert(path.to_string(), Known { id, dir: dir == "d", size, mtime, rid });
    }
    Some(s)
}

fn save_state(folder: &str, s: &State) {
    let path = state_path(folder);
    let _ = fs::create_dir_all(path.parent().unwrap());
    let mut text = String::new();
    for (p, k) in s {
        text.push_str(&format!("{}:{}\t{}\t{}\t{}\t{p}\n", k.id, k.rid, if k.dir { "d" } else { "f" }, k.size, k.mtime));
    }
    let tmp = path.with_extension("tsv.tmp");
    if fs::write(&tmp, text).is_ok() {
        let _ = fs::rename(&tmp, &path);
    }
}

/// The renames and moves between two states: same id, new path (a file also unchanged in size and time; one that
/// changed while moving is simply sent again). A folder's move covers everything that moved with it; the moves are
/// in the order the receiver must do them, each `from` as the receiver has it at that point.
fn detect_moves(prev: &State, cur: &State) -> Vec<Move> {
    let by_id: std::collections::HashMap<u64, (&String, &Known)> = cur.iter().filter(|(_, k)| k.id != 0).map(|(p, k)| (k.id, (p, k))).collect();
    let mut cands: Vec<(&String, &String, &Known)> = prev
        .iter()
        .filter_map(|(old, k)| {
            let (new, nk) = by_id.get(&k.id)?;
            let moved = *new != old && nk.dir == k.dir && !cur.contains_key(old);
            let same = k.dir || same(Ver { size: nk.size, mtime: nk.mtime }, Ver { size: k.size, mtime: k.mtime });
            (k.id != 0 && moved && same).then_some((old, *new, k))
        })
        .collect();
    // Folders first, outermost first; then files.
    cands.sort_by_key(|(old, _, k)| (!k.dir, old.matches('/').count(), (*old).clone()));
    let mut done: Vec<(String, String)> = Vec::new();
    let mut out = Vec::new();
    for (old, new, k) in cands {
        let mut at = old.clone();
        for (f, t) in &done {
            if at == *f {
                at = t.clone();
            } else if let Some(rest) = at.strip_prefix(&format!("{f}/")) {
                at = format!("{t}/{rest}");
            }
        }
        if at == *new {
            continue; // moved along with its folder
        }
        out.push(Move { from: at.clone(), to: new.clone(), dir: k.dir, size: k.size, mtime: k.mtime });
        if k.dir {
            done.push((at, new.clone()));
        }
    }
    out
}

fn count_files(dir: &Path) -> usize {
    fs::read_dir(dir)
        .map(|d| d.flatten().map(|e| if e.file_type().is_ok_and(|t| t.is_dir()) { count_files(&e.path()) } else { 1 }).sum())
        .unwrap_or(0)
}

/// Files a sync round leaves out: Office lock files, temporary files and downloads still in progress.
pub const SYNC_EXCLUDES: &[&str] = &["~$*", "*.tmp", "*.crdownload", "*.part", "*.partial", "*.download", ".~lock.*", "desktop.ini", "thumbs.db"];

/// Whether a local folder is really a network path (e.g. still folder-redirected): syncing it would copy a share to a share.
fn is_network(p: &Path) -> bool {
    let s = p.to_string_lossy();
    s.starts_with(r"\\") || s.starts_with("//")
}

/// Exit code of `scopy sync run` when this user has not enrolled (the sync service then just checks again later).
pub const EXIT_NOT_ENROLLED: i32 = 3;
/// Exit code when sync.toml changed (folders added or removed): the sync service starts the agent again at once.
pub const EXIT_RESTART: i32 = 4;

/// `--background` (started by the sync service): output goes to `sync.log` next to `sync.toml`, the previous log is
/// kept as `sync.log.old` once it passes this size.
const LOG_MAX: u64 = 8 << 20;

/// `scopy sync run`: mirrors every enabled folder to the receiver, then watches the folders and sends each burst
/// of changes after a few quiet seconds, with a full round every 10 minutes as a safety net. A round that fails
/// (receiver unreachable, PC offline) is tried again after 30 s, growing to 5 min. Runs as the user.
pub fn run(once: bool, background: bool) -> Result<()> {
    use crate::status::{self, FolderStatus, Status};
    use notify::{RecursiveMode, Watcher};
    use std::time::{Duration, Instant};
    let path = client_config_path();
    let Ok(text) = fs::read_to_string(&path) else {
        let msg = format!("not enrolled ({} missing): run `scopy sync enable` first", path.display());
        if background && path.parent().is_some_and(Path::is_dir) {
            let _ = fs::OpenOptions::new().create(true).append(true).open(status::log_path()).and_then(|mut f| writeln!(f, "[{}] {msg}", crate::util::utc_stamp()));
        }
        eprintln!("{msg}");
        std::process::exit(EXIT_NOT_ENROLLED);
    };
    if background {
        log_to(&status::log_path())?;
    }
    let _single = one_per_session()?;
    eprintln!("[{}] scopy {} sync run (pid {})", crate::util::utc_stamp(), env!("CARGO_PKG_VERSION"), std::process::id());
    let cfg: ClientConfig = toml::from_str(&text).with_context(|| format!("{} is not valid", path.display()))?;
    let folders: Vec<&ClientFolder> = cfg
        .folder
        .iter()
        .filter(|f| {
            if is_network(&f.local) {
                eprintln!("{}: {} is a network folder (folder redirection?) — not synced", f.name, f.local.display());
                false
            } else if !f.local.is_dir() {
                eprintln!("{}: {} does not exist — not synced", f.name, f.local.display());
                false
            } else {
                true
            }
        })
        .collect();
    if folders.is_empty() {
        bail!("no local folder to sync");
    }
    // A Linux daemon: sign in through SSH (the token is renewed below, and after failures).
    let port = match &cfg.ssh {
        Some(dest) => crate::ssh::open_daemon(dest)?.1,
        None => cfg.port,
    };
    let mut opts = crate::sync_client_options(port);
    let mut pull_opts = crate::sync_client_options(port);
    // Access proofs are remembered for a few minutes (proofs.rs): one SMB check per folder and direction, not one per
    // push and pull.
    let tokens = Some(Default::default());
    (opts.tokens, pull_opts.tokens) = (tokens.clone(), tokens);
    opts.pc = pc_name();
    opts.mirror = true;
    opts.exclude = SYNC_EXCLUDES.iter().map(|s| s.to_string()).collect();

    enum Msg {
        Fs(notify::Result<notify::Event>),
        Wake,
        /// The receiver's change feed: folder i changed on the server; None = connected again (look at everything,
        /// changes while it was down were not reported).
        Feed(Option<(usize, (u64, u64))>),
    }
    let (tx, rx) = std::sync::mpsc::channel::<Msg>();
    let fs_tx = tx.clone();
    let mut watcher = notify::recommended_watcher(move |ev| {
        let _ = fs_tx.send(Msg::Fs(ev));
    })?;
    for f in &folders {
        watcher.watch(&f.local, RecursiveMode::Recursive).with_context(|| format!("cannot watch {}", f.local.display()))?;
    }
    let feed_tx = tx.clone();
    on_wake(move || tx.send(Msg::Wake).is_ok());
    let live = Arc::new(AtomicBool::new(false));
    if !once {
        let remotes: Vec<String> = folders.iter().map(|f| f.remote.clone()).collect();
        let (live, pc) = (live.clone(), opts.pc.clone());
        std::thread::spawn(move || watch_server(&remotes, port, &pc, &live, |m| feed_tx.send(Msg::Feed(m)).is_ok()));
    }

    let mut st = Status {
        version: env!("CARGO_PKG_VERSION").into(),
        pid: std::process::id(),
        user: cfg.user.clone(),
        server: cfg.server.clone(),
        state: "starting".into(),
        folder: folders
            .iter()
            .map(|f| FolderStatus { name: f.name.clone(), local: f.local.display().to_string(), remote: f.remote.clone(), ..Default::default() })
            .collect(),
        ..Default::default()
    };
    st.save();
    const QUIET: Duration = Duration::from_secs(3);
    // The server is asked for its listing this often (Options), after every change here and whenever its change feed
    // reports one; while the feed is connected the timed listing is only a safety net.
    let check = || {
        let c = Duration::from_secs(status::Settings::load().check_secs.clamp(15, 3600));
        if live.load(Ordering::Relaxed) { c.max(FEED_CHECK) } else { c }
    };
    let mut dirty: Vec<bool> = vec![true; folders.len()];
    // Each folder as its last round left it (for telling the round's own writes from new changes).
    let mut left: Vec<State> = folders.iter().map(|f| load_state(&f.name).unwrap_or_default()).collect();
    // Paths the folder watch named since each folder's last round (looked at on their own by the next one).
    let mut hints: Vec<std::collections::HashSet<String>> = vec![Default::default(); folders.len()];
    // Each folder's listing cursor (how far its cached server listing goes).
    let mut cursors: Vec<(u64, u64)> = folders.iter().map(|f| load_remote_cache(&f.name).map_or((0, 0), |c| c.0)).collect();
    let mut failures = 0u32;
    let mut next_full = Instant::now() + check();
    let config_time = fs::metadata(&path).and_then(|m| m.modified()).ok();
    let mut next_purge = Instant::now();
    loop {
        if !once && Instant::now() >= next_purge {
            purge_pc_bin();
            next_purge = Instant::now() + Duration::from_secs(3600);
        }
        // Folders enabled or disabled (Options, `scopy sync enable`): start over with the new list.
        if fs::metadata(&path).and_then(|m| m.modified()).ok() != config_time {
            eprintln!("[{}] {} changed: restarting", crate::util::utc_stamp(), path.display());
            std::process::exit(EXIT_RESTART);
        }
        // A daemon token lasts 12 hours (the daemon says how long): renewed at half of that.
        if crate::ssh::renewal_due() {
            crate::ssh::sign_in_again();
        }
        let paused = status::pause_path().exists();
        let mut failed = false;
        for (i, (f, d)) in folders.iter().zip(dirty.iter_mut()).enumerate() {
            if !*d || paused {
                continue;
            }
            *d = false;
            st.state = "syncing".into();
            st.folder[i].syncing = true;
            st.save();
            let t = Instant::now();
            let settings = status::Settings::load();
            let fs_ = &mut st.folder[i];
            fs_.syncing = false;
            let hint = std::mem::take(&mut hints[i]);
            match sync_folder(f, &opts, &pull_opts, &settings, hint.iter().cloned().collect()) {
                Ok(mut r) => {
                    left[i] = std::mem::take(&mut r.state);
                    cursors[i] = r.cursor;
                    fs_.last_ok = status::now();
                    fs_.last_secs = t.elapsed().as_secs_f64();
                    fs_.last_error.clear();
                    (fs_.pushed, fs_.pulled, fs_.renamed, fs_.recycled) = (r.pushed, r.pulled, r.renamed, r.recycled);
                    (fs_.deleted_here, fs_.conflicts, fs_.held) = (r.deleted_here, r.conflicts, r.held);
                    fs_.busy = r.busy.into_iter().take(20).collect();
                    fs_.open_here = r.open_here.into_iter().take(20).collect();
                    fs_.open_elsewhere = r.open_elsewhere.into_iter().take(20).collect();
                    fs_.note = if r.held > 0 {
                        format!("{} files deleted on this PC are kept on the server until you confirm (Options: ask before deleting more than {})", r.held, settings.confirm_deletes_over)
                    } else {
                        String::new()
                    };
                }
                Err(e) => {
                    eprintln!("[{}] sync {}: {e:#}", crate::util::utc_stamp(), f.name);
                    fs_.last_error = format!("{e:#}");
                    failed = true;
                    *d = true; // tried again after the pause (or with the next change)
                    hints[i].extend(hint);
                }
            }
        }        if once {
            st.state = if failed { "retrying" } else { "ok" }.into();
            st.save();
            return if failed { bail!("the round did not finish") } else { Ok(()) };
        }
        failures = if failed { failures + 1 } else { 0 };
        if failed {
            // A Linux daemon that restarted forgot our token and has a new key: sign in again before the retry.
            crate::ssh::sign_in_again();
        }
        let wait = if failures > 0 && !paused { retry_pause(failures) } else { next_full.saturating_duration_since(Instant::now()) };
        if failures > 0 && !paused {
            eprintln!("next try in {} s", wait.as_secs());
        }
        let held = st.folder.iter().any(|f| f.held > 0);
        st.state = if paused { "paused" } else if failures > 0 { "retrying" } else if held { "held" } else { "ok" }.into();
        st.next_round = status::now() + wait.as_secs();
        st.feed = live.load(Ordering::Relaxed);
        st.save();
        // Wait for a change, a wake-up from the tray app, the retry or the full round; after a change, until the
        // folder has been quiet for a moment.
        let changed = |m: Msg, dirty: &mut Vec<bool>, hints: &mut Vec<std::collections::HashSet<String>>| -> bool {
            match m {
                Msg::Wake => {
                    // Sync now / resume: everything once more (a pause just ends the wait; the loop sees the file).
                    dirty.iter_mut().for_each(|d| *d = true);
                    true
                }
                Msg::Fs(Ok(ev)) => {
                    for p in ev.paths {
                        let name = p.file_name().map(|n| n.to_string_lossy().to_lowercase()).unwrap_or_default();
                        // An Office owner file appearing or going means a document was opened or closed: claim or release its lock now.
                        if name.contains(".scopy-") || (!name.starts_with("~$") && SYNC_EXCLUDES.iter().any(|x| crate::util::wildcard(x, &name))) {
                            continue;
                        }
                        for (i, f) in folders.iter().enumerate() {
                            // An owner file always counts (locks); anything else only if it differs from what the
                            // last round left (not the round's own pull, delete or move).
                            let Ok(rel) = p.strip_prefix(&f.local) else { continue };
                            let rel = rel.to_string_lossy().replace('\\', "/");
                            if !rel.is_empty() && hints[i].len() < HINTS_MAX {
                                hints[i].insert(rel);
                            }
                            if name.starts_with("~$") || !as_left(&f.local, &left[i], &p) {
                                dirty[i] = true;
                            }
                        }
                    }
                    false
                }
                Msg::Fs(Err(_)) => false,
                Msg::Feed(i) => {
                    // The receiver already waited for the burst to end.
                    match i {
                        // Covered by a listing the folder got since (its round was running when the ping came).
                        Some((i, (epoch, seq))) if i < dirty.len() && cursors[i].0 == epoch && seq <= cursors[i].1 => {}
                        Some((i, _)) if i < dirty.len() => {
                            eprintln!("[{}] server change feed: {} changed on the server", crate::util::utc_stamp(), folders[i].name);
                            dirty[i] = true
                        }
                        _ => dirty.iter_mut().for_each(|d| *d = true),
                    }
                    true
                }
            }
        };
        let woke = match rx.recv_timeout(wait) {
            Ok(m) => changed(m, &mut dirty, &mut hints),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                if Instant::now() >= next_full {
                    dirty.iter_mut().for_each(|d| *d = true);
                    next_full = Instant::now() + check();
                }
                true // a timer: no need to wait for quiet
            }
            Err(e) => bail!("folder watch ended: {e}"),
        };
        if !woke {
            while let Ok(m) = rx.recv_timeout(QUIET) {
                if changed(m, &mut dirty, &mut hints) {
                    break;
                }
            }
        }
    }
}

/// At most this many paths are remembered from the folder watch between two rounds (beyond it the scan alone).
const HINTS_MAX: usize = 10_000;

/// While the receiver's change feed is connected, the timed listing comes at most this often.
const FEED_CHECK: std::time::Duration = std::time::Duration::from_secs(600);

/// Keeps the receiver's change feed connected for the agent's life: `send(Feed(Some(i)))` when folder i changed on
/// the server, `send(Feed(None))` after a reconnect. A receiver without a feed (older protocol) is asked again
/// every 10 minutes; `live` says whether the feed is up.
fn watch_server(remotes: &[String], port: u16, pc: &str, live: &AtomicBool, send: impl Fn(Option<(usize, (u64, u64))>) -> bool) {
    use std::time::{Duration, Instant};
    let (mut ever_up, mut fails) = (false, 0usize);
    loop {
        let started = Instant::now();
        let again = ever_up;
        let res = crate::client::watch(
            remotes,
            port,
            pc,
            || {
                live.store(true, Ordering::Relaxed);
                eprintln!("[{}] server change feed connected", crate::util::utc_stamp());
                if again {
                    send(None);
                }
            },
            |i, at| send(Some((i, at))),
        );
        let was_up = live.swap(false, Ordering::Relaxed);
        ever_up |= was_up;
        let Err(e) = res else { return }; // the agent is ending
        let e = format!("{e:#}");
        // A Linux daemon that restarted forgot our token (and has a new key): sign in again.
        crate::ssh::sign_in_again();
        if was_up || fails == 0 {
            eprintln!("[{}] server change feed: {e}", crate::util::utc_stamp());
        }
        if was_up && started.elapsed() > Duration::from_secs(300) {
            fails = 0;
        }
        // An older receiver has no feed: ask again now and then (it may be updated); otherwise back off.
        let pause = if e.contains("unknown connection kind") || e.contains("version mismatch") { 600 } else { [5, 15, 60, 300][fails.min(3)] };
        fails += 1;
        std::thread::sleep(Duration::from_secs(pause));
    }
}

/// Calls `f` each time the tray app signals WAKE_EVENT, until `f` returns false.
#[cfg(windows)]
fn on_wake(f: impl Fn() -> bool + Send + 'static) {
    use windows_sys::Win32::System::Threading::{CreateEventW, WaitForSingleObject, INFINITE};
    let name: Vec<u16> = crate::status::WAKE_EVENT.encode_utf16().chain([0]).collect();
    // SAFETY: an auto-reset named event in this session's namespace, kept open for the life of the process.
    let h = unsafe { CreateEventW(std::ptr::null(), 0, 0, name.as_ptr()) } as usize;
    if h == 0 {
        eprintln!("no wake-up event ({}): the tray app's \"sync now\" will wait for the next round", std::io::Error::last_os_error());
        return;
    }
    std::thread::spawn(move || {
        // SAFETY: the event handle stays open (never closed).
        while unsafe { WaitForSingleObject(h as _, INFINITE) } == 0 && f() {}
    });
}

#[cfg(not(windows))]
fn on_wake(_f: impl Fn() -> bool + Send + 'static) {}
// ---- two-way: one round of one folder ----

/// A file's version as both sides see it: size and modification time (scopy keeps the mtime exact).
#[derive(Clone, Copy, Debug, PartialEq)]
struct Ver {
    size: u64,
    mtime: i64,
}

fn same(a: Ver, b: Ver) -> bool {
    a.size == b.size && (a.mtime - b.mtime).abs() <= 1_000_000
}

/// What to do with one file, from the last synced version (`p`), the PC's (`l`) and the server's (`r`).
#[derive(Clone, Copy, Debug, PartialEq)]
enum Act {
    /// The same on both sides.
    Synced,
    /// New or changed on the PC (or changed on the PC after the server deleted it: kept).
    Push,
    /// New or changed on the server (or changed there after the PC deleted it: kept).
    Pull,
    /// Deleted on the PC, unchanged on the server: into the server's recycle bin.
    DeleteRemote,
    /// Deleted on the server (another PC, a terminal server), unchanged here: into this PC's recycle bin.
    DeleteLocal,
    /// Changed on both sides: the server's version keeps the name, this PC's becomes a conflict copy.
    Conflict,
    /// Gone on both sides.
    Gone,
}

fn decide(p: Option<Ver>, l: Option<Ver>, r: Option<Ver>) -> Act {
    match (l, r) {
        (Some(l), Some(r)) if same(l, r) => Act::Synced,
        (None, None) => Act::Gone,
        (Some(l), None) => match p {
            Some(p) if same(l, p) => Act::DeleteLocal,
            _ => Act::Push,
        },
        (None, Some(r)) => match p {
            Some(p) if same(r, p) => Act::DeleteRemote,
            _ => Act::Pull,
        },
        (Some(l), Some(r)) => match p {
            Some(p) if same(l, p) => Act::Pull,
            Some(p) if same(r, p) => Act::Push,
            _ => Act::Conflict,
        },
    }
}

/// A file the receiver doesn't trust (an interrupted job may have left it with the right size and time but without
/// its data, e.g. zero-filled after a hard reset): never synced or fetched as it is. Where this PC has the file, it
/// is sent again (the receiver re-sends it even though it looks up to date); a delete stays a delete; where only
/// the server has it, it waits (fetching it could bring zeros here) until the PC that wrote it sends it again.
fn untrusted(act: Act, here: bool, held: &mut u64) -> Act {
    match act {
        _ if here => Act::Push,
        Act::Pull => {
            *held += 1;
            Act::Gone // nothing done, nothing remembered: the next round decides again
        }
        _ => act,
    }
}

/// What a round of one folder did.
#[derive(Debug, Default)]
struct Round {
    pushed: u64,
    pulled: u64,
    renamed: u64,
    recycled: u64,
    deleted_here: u64,
    conflicts: u64,
    held: u64,
    /// Files waiting because a program has them open here.
    busy: Vec<String>,
    /// Documents open here, locked on the receiver for everyone else.
    open_here: Vec<String>,
    /// Documents open on another PC or on the server ("path — open on PC …").
    open_elsewhere: Vec<String>,
    /// The folder as this round left it (its saved state): events that match it are the round's own writes.
    state: State,
    /// The cursor of the round's last server listing.
    cursor: (u64, u64),
}

/// Test tool (`scopy sync claim`): claims files of an enrolled folder as open on PC `pc` for `secs` seconds (renewed
/// every 10 s), then lets go — a second notebook with a document open, without a second notebook.
pub fn claim_test(folder: &str, paths: &[String], pc: &str, secs: u64) -> Result<()> {
    let text = fs::read_to_string(client_config_path()).context("not enrolled")?;
    let cfg: ClientConfig = toml::from_str(&text)?;
    let f = cfg.folder.iter().find(|f| f.name.eq_ignore_ascii_case(folder)).with_context(|| format!("{folder} is not enrolled"))?;
    let claims: Vec<LockClaim> = paths
        .iter()
        .map(|p| {
            let name = p.rsplit('/').next().unwrap_or(p);
            LockClaim { path: p.clone(), owner_name: format!("~${name}"), owner: format!("{pc} test").into_bytes() }
        })
        .collect();
    let end = std::time::Instant::now() + std::time::Duration::from_secs(secs);
    while std::time::Instant::now() < end {
        let (states, others) = crate::client::locks(&f.remote, cfg.port, pc, &claims)?;
        eprintln!("[{}] claims as {pc}: {states:?}; others: {}", crate::util::utc_stamp(), others.iter().map(|o| format!("{} ({})", o.path, o.pc)).collect::<Vec<_>>().join(", "));
        std::thread::sleep(std::time::Duration::from_secs(10).min(end.saturating_duration_since(std::time::Instant::now())));
    }
    crate::client::locks(&f.remote, cfg.port, pc, &[])?;
    eprintln!("released");
    Ok(())
}

/// This PC's name, as the receiver and the other PCs see it.
pub fn pc_name() -> String {
    std::env::var("COMPUTERNAME").or_else(|_| std::env::var("HOSTNAME")).unwrap_or_else(|_| "PC".into())
}

/// Documents open in Office here: Office puts an owner file `~$…` next to each open document (named after it, with
/// the first two characters left out for longer names) and keeps the document open. A leftover owner file (Office
/// crashed) does not count: the document must really be in use.
fn open_docs(root: &Path) -> Vec<LockClaim> {
    let mut out = Vec::new();
    let mut stack = vec![(root.to_path_buf(), String::new())];
    while let Some((dir, rel)) = stack.pop() {
        let Ok(rd) = fs::read_dir(&dir) else { continue };
        let ents: Vec<(String, bool)> = rd.flatten().map(|e| (e.file_name().to_string_lossy().into_owned(), e.file_type().is_ok_and(|t| t.is_dir() && !t.is_symlink()))).collect();
        for (name, is_dir) in &ents {
            if *is_dir {
                if !name.contains(".scopy-") {
                    stack.push((dir.join(name), if rel.is_empty() { name.clone() } else { format!("{rel}/{name}") }));
                }
                continue;
            }
            let Some(tail) = name.strip_prefix("~$").filter(|t| !t.is_empty()) else { continue };
            let tail_l = tail.to_lowercase();
            for (doc, d) in &ents {
                let n = doc.chars().count();
                if *d || doc.starts_with("~$") || !doc.to_lowercase().ends_with(&tail_l) || n > tail.chars().count() + 2 {
                    continue;
                }
                if in_use(&dir.join(doc)) {
                    let owner = fs::read(dir.join(name)).ok().filter(|b| b.len() <= 4096).unwrap_or_default();
                    out.push(LockClaim { path: if rel.is_empty() { doc.clone() } else { format!("{rel}/{doc}") }, owner_name: name.clone(), owner });
                }
            }
        }
    }
    out
}

/// The files this agent marked read-only (`state\<folder>.ro`) under their new names after renames and moves done
/// here, so the mark is still taken back when the lock ends.
fn ro_follow(folder: &str, moves: &[Move]) {
    let list = crate::status::dir().join("state").join(format!("{folder}.ro"));
    let Ok(text) = fs::read_to_string(&list) else { return };
    let mut marked: std::collections::HashMap<String, ()> = text.lines().filter(|l| !l.is_empty()).map(|l| (l.to_string(), ())).collect();
    let before: std::collections::BTreeSet<String> = marked.keys().cloned().collect();
    apply_moves_to(&mut marked, moves);
    let after: std::collections::BTreeSet<String> = marked.into_keys().collect();
    if after != before {
        let _ = fs::write(&list, after.into_iter().collect::<Vec<_>>().join("\n"));
    }
}

/// Files another PC has open are kept read-only here (Office then opens them read-only), and writable again once
/// the lock is gone. Only files this agent marked are touched (`state\<folder>.ro`).
fn mark_read_only(folder: &str, root: &Path, elsewhere: &std::collections::HashMap<String, LockInfo>) {
    let list = crate::status::dir().join("state").join(format!("{folder}.ro"));
    use std::collections::HashSet;
    let marked: HashSet<String> = fs::read_to_string(&list).map(|t| t.lines().map(String::from).collect()).unwrap_or_default();
    let mut now: HashSet<String> = HashSet::new();
    for p in elsewhere.keys() {
        let full = root.join(p);
        let Ok(md) = fs::metadata(&full) else { continue };
        if md.permissions().readonly() && !marked.contains(p) {
            continue; // read-only by the user's own choice: not ours to undo later
        }
        if !md.permissions().readonly() && !in_use(&full) {
            let mut perm = md.permissions();
            perm.set_readonly(true);
            if fs::set_permissions(&full, perm).is_err() {
                continue;
            }
        }
        now.insert(p.clone());
    }
    for p in marked.difference(&now) {
        let _ = crate::meta::clear_readonly(&root.join(p));
    }
    if now != marked {
        let _ = fs::create_dir_all(list.parent().unwrap());
        let _ = fs::write(&list, now.iter().cloned().collect::<Vec<_>>().join("\n"));
    }
}

/// Whether a program has the file open (so it must not be deleted, replaced or renamed now): an exclusive open
/// fails with a sharing violation.
#[cfg(windows)]
fn in_use(p: &Path) -> bool {
    use std::os::windows::fs::OpenOptionsExt;
    matches!(fs::OpenOptions::new().read(true).share_mode(0).open(p), Err(e) if matches!(e.raw_os_error(), Some(32) | Some(33)))
}

/// Whether the file is locked so that it cannot even be read (e.g. a mailbox file of a running mail program).
#[cfg(windows)]
fn locked(p: &Path) -> bool {
    matches!(fs::File::open(p), Err(e) if matches!(e.raw_os_error(), Some(32) | Some(33)))
}

#[cfg(not(windows))]
fn in_use(_p: &Path) -> bool {
    false
}

#[cfg(not(windows))]
fn locked(_p: &Path) -> bool {
    false
}

/// Renames paths in a listing the way the moves do on the receiver (a folder's move takes its contents along).
fn apply_moves_to<V>(map: &mut std::collections::HashMap<String, V>, moves: &[Move]) {
    for m in moves {
        let keys: Vec<String> = map.keys().filter(|k| **k == m.from || k.starts_with(&format!("{}/", m.from))).cloned().collect();
        for k in keys {
            let v = map.remove(&k).unwrap();
            map.insert(format!("{}{}", m.to, &k[m.from.len()..]), v);
        }
    }
}

/// The server's listing is cached per folder (`state\<folder>.remote.tsv`, with the receiver's cursor): while the
/// PC's change feed is connected, a round fetches only what changed since (a delta) and applies it to the cache.
/// A full listing at least this often anyway, and whenever the receiver can't answer the cursor.
const FULL_LISTING: u64 = 600;

fn remote_cache_path(folder: &str) -> PathBuf {
    crate::status::dir().join("state").join(format!("{folder}.remote.tsv"))
}

/// The cached listing: cursor, Unix time of its last full listing, entries (id = rid = the receiver's file id).
/// The cursor of the cached listing and the time of its last full listing (`<folder>.remote.cursor`: rewritten every
/// round, while the listing itself is rewritten only when it changed).
fn remote_cursor_path(folder: &str) -> PathBuf {
    crate::status::dir().join("state").join(format!("{folder}.remote.cursor"))
}

fn load_remote_cache(folder: &str) -> Option<((u64, u64), u64, State)> {
    let head: Vec<u64> = fs::read_to_string(remote_cursor_path(folder)).ok()?.split_whitespace().filter_map(|x| x.parse().ok()).collect();
    let [epoch, seq, full] = head[..] else { return None };
    let text = fs::read_to_string(remote_cache_path(folder)).ok()?;
    let mut s = State::new();
    for l in text.lines().filter(|l| !l.starts_with('#')) {
        let mut p = l.splitn(5, '\t');
        let (Some(rid), Some(dir), Some(size), Some(mtime), Some(path)) = (p.next(), p.next(), p.next(), p.next(), p.next()) else { return None };
        let (Ok(rid), Ok(size), Ok(mtime)) = (rid.parse(), size.parse(), mtime.parse()) else { return None };
        s.insert(path.to_string(), Known { id: rid, dir: dir == "d", size, mtime, rid });
    }
    Some(((epoch, seq), full, s))
}

/// Saves the cursor, and the listing too when `changed`.
fn save_remote_cache(folder: &str, cursor: (u64, u64), full: u64, s: &State, changed: bool) {
    let path = remote_cache_path(folder);
    let _ = fs::create_dir_all(path.parent().unwrap());
    let write = |path: &Path, text: String| {
        let tmp = PathBuf::from(format!("{}.tmp", path.display()));
        fs::write(&tmp, text).is_ok() && fs::rename(&tmp, path).is_ok()
    };
    if changed {
        let mut text = String::new();
        for (p, k) in s {
            text.push_str(&format!("{}\t{}\t{}\t{}\t{p}\n", k.rid, if k.dir { "d" } else { "f" }, k.size, k.mtime));
        }
        if !write(&path, text) {
            let _ = fs::remove_file(remote_cursor_path(folder)); // no cursor for a listing that wasn't saved
            return;
        }
    }
    write(&remote_cursor_path(folder), format!("{} {} {full}\n", cursor.0, cursor.1));
}

/// A delta applied to a cached listing: removed paths go with everything below them, then the entries go in.
pub(crate) fn apply_delta(cache: &mut State, removed: &[String], entries: &[Entry], ids: &[u64]) {
    for r in removed {
        let below = format!("{r}/");
        cache.retain(|p, _| p != r && !p.starts_with(&below));
    }
    for (e, &rid) in entries.iter().zip(ids) {
        cache.insert(e.path.clone(), Known { id: rid, dir: !e.is_file(), size: e.size, mtime: e.mtime, rid });
    }
}

/// The server's folder as it is now (id = rid = the receiver's file id): from a delta on the cached listing when
/// the receiver can give one, else in full. The cache is saved either way. Also the files the receiver doesn't
/// trust (an interrupted job may have left them without their data).
fn server_listing(f: &ClientFolder, port: u16, pc: &str) -> Result<(State, (u64, u64), std::collections::HashSet<String>)> {
    let now = crate::status::now();
    let cache = load_remote_cache(&f.name).filter(|(_, full, _)| now.saturating_sub(*full) < FULL_LISTING);
    let cursor = cache.as_ref().map_or((0, 0), |(c, _, _)| *c);
    let t = std::time::Instant::now();
    let l = crate::client::list(&f.remote, port, pc, cursor)?;
    let (state, full, changed) = match (l.removed, cache) {
        (Some(removed), Some((_, full, mut s))) => {
            apply_delta(&mut s, &removed, &l.entries, &l.ids);
            eprintln!("[{}] sync {}: server listing: delta of {} changes in {:.2} s", crate::util::utc_stamp(), f.name, removed.len(), t.elapsed().as_secs_f64());
            let changed = !removed.is_empty() || !l.entries.is_empty();
            (s, full, changed)
        }
        (Some(_), None) => bail!("the receiver sent a delta for a listing this PC doesn't have"),
        (None, _) => {
            let mut s = State::new();
            apply_delta(&mut s, &[], &l.entries, &l.ids);
            eprintln!("[{}] sync {}: server listing: full, {} entries in {:.2} s", crate::util::utc_stamp(), f.name, s.len(), t.elapsed().as_secs_f64());
            (s, now, true)
        }
    };
    save_remote_cache(&f.name, l.cursor, full, &state, changed);
    Ok((state, l.cursor, l.suspect.into_iter().collect()))
}

/// Renames and moves made on the server since the last round (receiver file ids, `detect_moves` on its listing),
/// done in the PC's folder too where that is safe: the PC's copy is unchanged since the last round (a folder: is
/// there), no program has the file open, nothing is at the new path, and the PC didn't move the same thing itself.
/// `prev` and `local` are updated for each one done; what isn't done falls back to the normal decision (the copy
/// here is deleted or kept, the file fetched again). Returns the moves done.
fn server_moves_here(f: &ClientFolder, prev: &mut State, local: &mut State, remote: &State, own: &[Move]) -> Vec<Move> {
    let was: State = prev.iter().filter(|(_, k)| k.rid != 0).map(|(p, k)| (p.clone(), Known { id: k.rid, ..*k })).collect();
    let cands = detect_moves(&was, remote);
    let near = |a: &str, b: &str| a == b || a.starts_with(&format!("{b}/")) || b.starts_with(&format!("{a}/"));
    let mut done = Vec::new();
    for m in cands {
        if own.iter().any(|o| near(&m.from, &o.from) || near(&m.from, &o.to) || near(&m.to, &o.to)) {
            continue; // moved here too: the PC's move goes to the receiver as usual
        }
        let ok = (|| -> Result<()> {
            let from = f.local.join(crate::util::sanitize_rel(&m.from, false)?);
            let to = f.local.join(crate::util::sanitize_rel(&m.to, false)?);
            let here = local.get(&m.from).copied().context("not here")?;
            let synced = prev.get(&m.from).copied().context("not synced")?;
            if here.dir != m.dir || (!m.dir && !same(Ver { size: here.size, mtime: here.mtime }, Ver { size: synced.size, mtime: synced.mtime })) {
                bail!("changed here");
            }
            let md = fs::symlink_metadata(&from)?;
            if md.file_type().is_symlink() || md.is_dir() != m.dir {
                bail!("not the same kind here");
            }
            // NTFS names are case-insensitive: a rename that only changes case finds its own target.
            let case_only = cfg!(windows) && m.from.to_lowercase() == m.to.to_lowercase();
            if !case_only && (fs::symlink_metadata(&to).is_ok() || local.contains_key(&m.to)) {
                bail!("something is at the new path here");
            }
            if !m.dir && in_use(&from) {
                bail!("open here");
            }
            if let Some(parent) = to.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::rename(&from, &to)?;
            Ok(())
        })();
        match ok {
            Ok(()) => {
                apply_moves_to(prev, std::slice::from_ref(&m));
                apply_moves_to(local, std::slice::from_ref(&m));
                done.push(m);
            }
            Err(e) => eprintln!("[{}] sync {}: {} -> {} (moved on the server) not done here: {e:#}; synced the usual way", crate::util::utc_stamp(), f.name, m.from, m.to),
        }
    }
    done
}

/// `name.ext` -> `name (conflict PC 20261104-071500).ext`, next to it.
fn conflict_name(rel: &str) -> String {
    let (dir, file) = rel.rsplit_once('/').map_or(("", rel), |(d, f)| (d, f));
    let (stem, ext) = match file.rsplit_once('.') {
        Some((s, e)) if !s.is_empty() => (s, format!(".{e}")),
        _ => (file, String::new()),
    };
    let pc = std::env::var("COMPUTERNAME").or_else(|_| std::env::var("HOSTNAME")).unwrap_or_else(|_| "this PC".into());
    let name = format!("{stem} (conflict {pc} {}){ext}", crate::util::utc_stamp());
    if dir.is_empty() { name } else { format!("{dir}/{name}") }
}

/// Moves a file or (empty) folder of this PC into `%LOCALAPPDATA%\scopy\recycle\<folder>\<time>\…`.
fn recycle_here(folder: &str, stamp: &str, root: &Path, rel: &str) -> Result<()> {
    let from = root.join(rel);
    let to = crate::status::dir().join("recycle").join(folder).join(stamp).join(rel);
    fs::create_dir_all(to.parent().unwrap())?;
    if fs::rename(&from, &to).is_err() {
        // Another volume: copy, then remove.
        if fs::metadata(&from)?.is_dir() {
            fs::create_dir_all(&to)?;
            fs::remove_dir_all(&from)?;
        } else {
            fs::copy(&from, &to)?;
            fs::remove_file(&from)?;
        }
    }
    Ok(())
}

/// One two-way round of one folder: the PC's state now, the server's listing and the state after the last round
/// decide, per file, what goes up, what comes down and what is deleted where (see `decide`). One push carries the
/// moves, the deletes and the files to send; one pull fetches only the files to fetch.
fn sync_folder(f: &ClientFolder, opts: &crate::client::ClientOptions, pull_opts: &crate::client::ClientOptions, settings: &crate::status::Settings, hint: Vec<String>) -> Result<Round> {
    use std::collections::{HashMap, HashSet};
    let stamp = crate::util::utc_stamp();
    // Open-file locks first: what is open here is locked on the receiver for everyone else; what another PC has open
    // is not sent from here and stays read-only here (protocol 15; an older receiver just has no locks).
    // Where a round's time goes (logged at the end).
    let t_round = std::time::Instant::now();
    let mut times: Vec<(&str, f64)> = Vec::new();
    let mut lap = {
        let mut t = std::time::Instant::now();
        move |what: &'static str, times: &mut Vec<(&str, f64)>| {
            times.push((what, t.elapsed().as_secs_f64()));
            t = std::time::Instant::now();
        }
    };
    let claims = open_docs(&f.local);
    lap("open docs", &mut times);
    let (states, others) = match crate::client::locks(&f.remote, opts.port, &opts.pc, &claims) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("[{}] sync {}: no open-file locks ({e:#})", crate::util::utc_stamp(), f.name);
            (Vec::new(), Vec::new())
        }
    };
    let open_here: Vec<String> = claims.iter().zip(&states).filter(|(_, s)| **s == LOCK_HELD).map(|(c, _)| c.path.clone()).collect();
    let open_there: Vec<String> = claims.iter().zip(&states).filter(|(_, s)| **s == LOCK_OPEN_THERE).map(|(c, _)| c.path.clone()).collect();
    let elsewhere: HashMap<String, LockInfo> = others.into_iter().map(|l| (l.path.clone(), l)).collect();
    mark_read_only(&f.name, &f.local, &elsewhere);
    lap("locks", &mut times);
    let mut local = scan_state(&f.local);
    // The scan takes sizes and times from the folder index, which lags for a file a program holds open for
    // writing; the paths the folder watch named since the last round are looked at on their own.
    let hint: Vec<String> = hint.into_iter().filter(|p| !local.get(p).is_some_and(|k| k.dir)).collect();
    if !hint.is_empty() {
        restat(&f.local, &mut local, hint);
    }
    lap("scan here", &mut times);
    let prev = load_state(&f.name);
    let saved = prev.clone(); // the state file as it is: rewritten at the end only if the round changed it
    let moves = prev.as_ref().map(|p| detect_moves(p, &local)).unwrap_or_default();
    let mut prev = prev.unwrap_or_default();
    let (listed, mut cursor, suspect) = server_listing(f, opts.port, &opts.pc).context("cannot list the server's folder")?;
    lap("listing", &mut times);
    let mut remote: State = listed
        .into_iter()
        .filter(|(p, k)| {
            let n = p.rsplit('/').next().unwrap_or(p).to_lowercase();
            !(!k.dir && SYNC_EXCLUDES.iter().any(|x| crate::util::wildcard(x, &n)))
        })
        .collect();
    // Renamed or moved on the server (same receiver file id at a new path): done here too, instead of deleting the
    // PC's copy and fetching the file again.
    let server_moves = server_moves_here(f, &mut prev, &mut local, &remote, &moves);
    if !server_moves.is_empty() {
        eprintln!("[{}] sync {}: {} renamed or moved on the server, done here too", crate::util::utc_stamp(), f.name, server_moves.len());
        ro_follow(&f.name, &server_moves);
    }
    // The moves happen first on the receiver: decide on the state after them.
    apply_moves_to(&mut prev, &moves);
    apply_moves_to(&mut remote, &moves);
    let ver = |k: &Known| Ver { size: k.size, mtime: k.mtime };
    let file = |m: &HashMap<String, Known>, p: &str| m.get(p).filter(|k| !k.dir).map(ver);
    let is_dir = |m: &HashMap<String, Known>, p: &str| m.get(p).is_some_and(|k| k.dir);

    let mut paths: Vec<&String> = local.keys().chain(remote.keys()).chain(prev.keys()).collect();
    paths.sort();
    paths.dedup();
    let (mut push, mut pull) = (HashSet::new(), HashSet::new());
    let (mut deletes, mut delete_here, mut conflicts) = (Vec::new(), Vec::new(), Vec::new());
    // The version each path will have on both sides after the round (the next round's `prev`).
    let mut expect: HashMap<String, Known> = HashMap::new();
    let (mut new_dir_here, mut new_dir_there) = (false, false);
    let mut suspect_held = 0u64;
    for p in paths {
        let (pd, ld, rd) = (is_dir(&prev, p), is_dir(&local, p), is_dir(&remote, p));
        if pd || ld || rd {
            // Folders: created where missing, deleted where the other side deleted them (once empty).
            match (pd, ld, rd) {
                (_, true, true) => {}
                (true, false, true) => deletes.push(Delete { path: p.clone(), dir: true, size: 0, mtime: 0 }),
                (true, true, false) => delete_here.push((p.clone(), true)),
                (false, true, false) => new_dir_here = true,
                (false, false, true) => new_dir_there = true,
                _ => {}
            }
            if (ld && rd) || (!pd && (ld || rd)) {
                expect.insert(p.clone(), Known { id: 0, dir: true, size: 0, mtime: 0, rid: 0 });
            }
            // A path that is a folder on some side is handled as a file only where it is one.
            if file(&local, p).is_none() && file(&remote, p).is_none() {
                continue;
            }
        }
        let (pv, lv, rv) = (file(&prev, p), file(&local, p), file(&remote, p));
        let keep = |v: Ver| Known { id: 0, dir: false, size: v.size, mtime: v.mtime, rid: 0 };
        let act = decide(pv, lv, rv);
        let act = if rv.is_some() && suspect.contains(p) { untrusted(act, lv.is_some(), &mut suspect_held) } else { act };
        match act {
            Act::Synced => {
                expect.insert(p.clone(), keep(lv.unwrap()));
            }
            Act::Push => {
                push.insert(p.clone());
                expect.insert(p.clone(), keep(lv.unwrap()));
            }
            Act::Pull => {
                pull.insert(p.clone());
                expect.insert(p.clone(), keep(rv.unwrap()));
            }
            Act::DeleteRemote => {
                let r = rv.unwrap();
                deletes.push(Delete { path: p.clone(), dir: false, size: r.size, mtime: r.mtime });
                expect.insert(p.clone(), keep(r)); // dropped below once the delete was sent
            }
            Act::DeleteLocal => delete_here.push((p.clone(), false)),
            Act::Conflict => {
                conflicts.push(p.clone());
                pull.insert(p.clone());
                expect.insert(p.clone(), keep(rv.unwrap()));
            }
            Act::Gone => {}
        }
    }

    if !suspect.is_empty() {
        eprintln!(
            "[{}] sync {}: the server lists {} files an interrupted job may have left without their data: sent again from here where this PC has them{}",
            crate::util::utc_stamp(),
            f.name,
            suspect.len(),
            if suspect_held > 0 { format!(", {suspect_held} not fetched (this PC has no copy)") } else { String::new() }
        );
    }
    // Ask first before deleting many files on the server? (Options; off by default: deletes are synced.)
    let file_deletes = deletes.iter().filter(|d| !d.dir).count() as u64;
    let confirm = crate::status::confirm_path(&f.name);
    let restore = crate::status::restore_path(&f.name);
    let mut held = 0;
    if settings.confirm_deletes_over > 0 && file_deletes > settings.confirm_deletes_over && !confirm.exists() {
        if restore.exists() {
            // "Restore to this PC": fetch them back instead of deleting them.
            for d in deletes.drain(..).filter(|d| !d.dir) {
                pull.insert(d.path);
            }
        } else {
            held = file_deletes;
            deletes.clear(); // kept in `expect`, so they stay "deleted on this PC" until decided
        }
    } else {
        for d in &deletes {
            expect.remove(&d.path);
        }
    }

    // A file in use is never forced (as OneDrive, Dropbox and Syncthing do it): what would delete, replace or set it
    // aside here waits while a program has it open, and what is locked against reading waits to be sent. It keeps
    // its last synced state, so the next round decides again — and if it was saved meanwhile, the change wins.
    let mut busy: Vec<String> = Vec::new();
    let wait = |p: &str, expect: &mut HashMap<String, Known>, busy: &mut Vec<String>| {
        match prev.get(p) {
            Some(k) => expect.insert(p.to_string(), *k),
            None => expect.remove(p),
        };
        busy.push(p.to_string());
    };
    for p in pull.iter().filter(|p| !conflicts.contains(p)).filter(|p| in_use(&f.local.join(p))).cloned().collect::<Vec<_>>() {
        pull.remove(&p);
        wait(&p, &mut expect, &mut busy);
    }
    for p in push.iter().filter(|p| locked(&f.local.join(p))).cloned().collect::<Vec<_>>() {
        push.remove(&p);
        wait(&p, &mut expect, &mut busy);
    }
    // Open on another PC, or on the server itself: not sent or deleted from here meanwhile (it would be a conflict).
    let mut blocked: Vec<String> = Vec::new();
    for p in push.iter().filter(|p| elsewhere.contains_key(*p) || open_there.contains(p)).cloned().collect::<Vec<_>>() {
        push.remove(&p);
        wait(&p, &mut expect, &mut blocked);
    }
    for d in deletes.iter().filter(|d| elsewhere.contains_key(&d.path)).cloned().collect::<Vec<_>>() {
        deletes.retain(|x| x.path != d.path);
        wait(&d.path, &mut expect, &mut blocked);
    }

    // This PC first: what the server deleted, and the conflict copies of what changed on both sides.
    delete_here.sort_by_key(|(p, dir)| (*dir, std::cmp::Reverse(p.matches('/').count())));
    let mut deleted_here = 0;
    for (p, dir) in &delete_here {
        let full = f.local.join(p);
        if *dir {
            if fs::symlink_metadata(&full).is_ok_and(|m| m.is_dir()) && count_files(&full) == 0 && recycle_here(&f.name, &stamp, &f.local, p).is_ok() {
                deleted_here += 1;
            }
            continue;
        }
        // Only the version the scan saw: a file changed since is kept and sent (the change wins over the delete).
        let unchanged = fs::symlink_metadata(&full).is_ok_and(|m| file(&local, p).is_some_and(|l| same(l, Ver { size: m.len(), mtime: crate::meta::read(&m).mtime })));
        if !unchanged {
            if full.exists() {
                push.insert(p.clone());
            }
        } else if in_use(&full) || recycle_here(&f.name, &stamp, &f.local, p).is_err() {
            wait(p, &mut expect, &mut busy); // open here: deleted once it is closed — never sent back up
        } else {
            deleted_here += 1;
        }
    }
    let mut conflicted = 0;
    for p in &conflicts {
        let copy = conflict_name(p);
        if !in_use(&f.local.join(p)) && fs::rename(f.local.join(p), f.local.join(&copy)).is_ok() {
            eprintln!("conflict: {p} changed on this PC and on the server; this PC's version is kept as {copy}");
            conflicted += 1;
            push.insert(copy.clone());
            if let Some(l) = file(&local, p) {
                expect.insert(copy, Known { id: 0, dir: false, size: l.size, mtime: l.mtime, rid: 0 });
            }
        } else {
            pull.remove(p); // open here: set aside once it is closed
            wait(p, &mut expect, &mut busy);
        }
    }
    if !busy.is_empty() {
        eprintln!("[{}] sync {}: {} files wait because they are open here: {}", crate::util::utc_stamp(), f.name, busy.len(), busy.iter().take(5).cloned().collect::<Vec<_>>().join(", "));
    }

    let now_s = crate::status::now();
    let open_elsewhere: Vec<String> = elsewhere
        .values()
        .map(|l| format!("{} — open on {} ({}) for {} min", l.path, l.pc, l.user, now_s.saturating_sub(l.since) / 60))
        .chain(open_there.iter().map(|p| format!("{p} — open on the server itself (e.g. a terminal server)")))
        .collect();
    if !blocked.is_empty() {
        eprintln!("[{}] sync {}: {} files wait because they are open elsewhere: {}", crate::util::utc_stamp(), f.name, blocked.len(), blocked.iter().take(5).cloned().collect::<Vec<_>>().join(", "));
    }
    let mut out = Round { deleted_here, conflicts: conflicted, held, busy, open_here, open_elsewhere, ..Default::default() };
    if !push.is_empty() || !moves.is_empty() || !deletes.is_empty() || new_dir_here {
        let n = push.len();
        let mut o = opts.clone();
        // All the PC's folders go with it, as with a whole-folder scan (folders always; overlap check).
        let mut named = push;
        named.extend(local.iter().filter(|(_, k)| k.dir).map(|(p, _)| p.clone()));
        o.only = Some(std::sync::Arc::new(named));
        eprintln!(
            "[{}] sync {}: up {n} files{}{} -> {}",
            crate::util::utc_stamp(),
            f.name,
            if moves.is_empty() { String::new() } else { format!(", {} moves", moves.len()) },
            if deletes.is_empty() { String::new() } else { format!(", {} deletes", deletes.len()) },
            f.remote
        );
        lap("decide", &mut times);
        let r = crate::client::push_with(&f.local, &f.remote, &o, &moves, &deletes)?;
        lap("up", &mut times);
        (out.pushed, out.renamed, out.recycled) = (n as u64, r.renamed, r.recycled);
    }
    if !pull.is_empty() || new_dir_there {
        let n = pull.len();
        // Folders only the server has are named too (a named pull creates nothing else).
        pull.extend(remote.iter().filter(|(p, k)| k.dir && !local.contains_key(*p)).map(|(p, _)| p.clone()));
        let mut o = pull_opts.clone();
        o.only = Some(std::sync::Arc::new(pull));
        eprintln!("[{}] sync {}: down {n} files <- {}", crate::util::utc_stamp(), f.name, f.remote);
        // A file the server is still writing (a copy onto the share in progress) arrives incomplete and is not
        // written here: it keeps its last synced state, and the feed's next ping (or round) fetches it once done.
        lap("decide", &mut times);
        let crate::client::Pulled { unfinished, versions } = crate::client::pull_with(&f.remote, &f.local, &o, true)?;
        lap("down", &mut times);
        // A fetched file is here as the server had it when the pull read it, which may be newer than the listing
        // (a file still being written there): that is the version both sides had, or the next round takes the
        // newer one here for a change on this PC too and makes a conflict copy of a half-written file (measured:
        // 3 of 10,000 files copied onto the server over SMB).
        for (p, (size, mtime)) in &versions {
            if let Some(e) = expect.get_mut(p).filter(|e| !e.dir && !same(ver(e), Ver { size: *size, mtime: *mtime })) {
                (e.size, e.mtime) = (*size, *mtime);
            }
        }
        if !unfinished.is_empty() {
            eprintln!("[{}] sync {}: {} files still being written on the server, fetched later: {}", crate::util::utc_stamp(), f.name, unfinished.len(), unfinished.iter().take(5).cloned().collect::<Vec<_>>().join(", "));
            for p in &unfinished {
                match prev.get(p) {
                    Some(k) => expect.insert(p.clone(), *k),
                    None => expect.remove(p),
                };
            }
        }
        out.pulled = (n - unfinished.len()) as u64;
    }
    if deleted_here + out.pushed + out.pulled + out.recycled + out.renamed > 0 {
        eprintln!(
            "[{}] sync {}: {} up, {} down, {} moved, {} into the server's recycle bin, {} deleted here{}",
            crate::util::utc_stamp(),
            f.name,
            out.pushed,
            out.pulled,
            out.renamed,
            out.recycled,
            deleted_here,
            if held > 0 { format!(", {held} deletes held") } else { String::new() }
        );
    }
    if held == 0 {
        let _ = fs::remove_file(&confirm); // used (or not needed any more)
    }
    let _ = fs::remove_file(&restore);

    // The next round's `prev`: what both sides now have, with this PC's file ids (for the next moves). A file that
    // changed here during the round keeps the version that was synced, so the next round sends the change.
    lap("apply", &mut times);
    // The folder as the round left it: the scan from the start, looked at again only where the round meant to
    // change something here (pulled, deleted, conflict copies, new folders). A change someone made here meanwhile
    // comes as an event and is seen by the next round.
    let touched: Vec<String> = expect
        .iter()
        .filter(|(p, e)| !local.get(*p).is_some_and(|l| l.dir == e.dir && (e.dir || same(ver(l), ver(e)))))
        .map(|(p, _)| p.clone())
        .chain(local.keys().filter(|p| !expect.contains_key(*p)).cloned())
        .collect();
    let n_touched = touched.len();
    let mut now = local.clone();
    restat(&f.local, &mut now, touched);
    lap("rescan here", &mut times);
    // What this round sent has new ids on the receiver: one more listing picks them up, so a rename there right
    // after is still seen as a rename.
    let after: Option<State> = (out.pushed + out.renamed > 0).then(|| server_listing(f, opts.port, &opts.pc).ok()).flatten().map(|(s, c, _)| {
        cursor = c;
        s
    });
    let ids_now = after.as_ref().unwrap_or(&remote);
    let state: State = expect
        .into_iter()
        .map(|(p, e)| {
            let mut k = match now.get(&p) {
                Some(n) if n.dir == e.dir && (e.dir || same(ver(n), ver(&e))) => *n,
                Some(n) => Known { id: n.id, ..e },
                None => e,
            };
            // The receiver's id of what is there now.
            k.rid = ids_now.get(&p).filter(|r| r.dir == k.dir && (k.dir || same(ver(r), ver(&k)))).map_or(0, |r| r.rid);
            (p, k)
        })
        .collect();
    if saved.as_ref() != Some(&state) {
        save_state(&f.name, &state);
    }
    out.state = state;
    out.cursor = cursor;
    lap("save", &mut times);
    eprintln!(
        "[{}] sync {}: round {:.2} s, {n_touched} paths looked at again ({})",
        crate::util::utc_stamp(),
        f.name,
        t_round.elapsed().as_secs_f64(),
        times.iter().filter(|(_, t)| *t >= 0.01).map(|(w, t)| format!("{w} {t:.2}")).collect::<Vec<_>>().join(", ")
    );
    Ok(out)
}

/// Whether a change event on `p` in the folder at `root` leaves things as the last round left them (`state`): the
/// round's own writes (pulls, deletes, moves here) come back as events and would otherwise start an empty round.
fn as_left(root: &Path, state: &State, p: &Path) -> bool {
    let Ok(rel) = p.strip_prefix(root) else { return false };
    let rel = rel.to_string_lossy().replace('\\', "/");
    if rel.is_empty() {
        return true; // the folder itself
    }
    match fs::symlink_metadata(p) {
        Ok(md) if md.is_dir() => state.get(&rel).is_some_and(|k| k.dir),
        Ok(md) => state.get(&rel).is_some_and(|k| !k.dir && same(Ver { size: md.len(), mtime: crate::meta::read(&md).mtime }, Ver { size: k.size, mtime: k.mtime })),
        Err(_) => !state.contains_key(&rel),
    }
}

/// After a failed round: 30 s, 1, 2, 4 min, then 5 min.
fn retry_pause(failures: u32) -> std::time::Duration {
    std::time::Duration::from_secs((30u64 << failures.saturating_sub(1).min(4)).min(300))
}

/// Sends this process's output (stdout, stderr and log lines) to `path`, keeping one older log.
fn log_to(path: &Path) -> Result<()> {
    if fs::metadata(path).is_ok_and(|m| m.len() > LOG_MAX) {
        let _ = fs::rename(path, path.with_extension("log.old"));
    }
    crate::util::log_to_file(path)?;
    let f = fs::OpenOptions::new().create(true).append(true).open(path).with_context(|| format!("cannot write {}", path.display()))?;
    #[cfg(windows)]
    {
        use std::os::windows::io::IntoRawHandle;
        use windows_sys::Win32::System::Console::{SetStdHandle, STD_ERROR_HANDLE, STD_OUTPUT_HANDLE};
        let h = f.into_raw_handle();
        // SAFETY: the handle stays open for the life of the process (it is never closed).
        unsafe {
            SetStdHandle(STD_OUTPUT_HANDLE, h);
            SetStdHandle(STD_ERROR_HANDLE, h);
        }
    }
    #[cfg(not(windows))]
    {
        use std::os::fd::IntoRawFd;
        let fd = f.into_raw_fd();
        // SAFETY: duplicates an open descriptor onto stdout and stderr.
        unsafe {
            libc_dup2(fd, 1);
            libc_dup2(fd, 2);
        }
    }
    Ok(())
}

#[cfg(not(windows))]
extern "C" {
    #[link_name = "dup2"]
    fn libc_dup2(old: i32, new: i32) -> i32;
}

/// One agent per user session: a second `scopy sync run` (by hand next to the service's) refuses to start.
#[cfg(windows)]
fn one_per_session() -> Result<impl Drop> {
    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, ERROR_ALREADY_EXISTS, HANDLE};
    use windows_sys::Win32::System::Threading::CreateMutexW;
    struct Held(HANDLE);
    impl Drop for Held {
        fn drop(&mut self) {
            // SAFETY: the mutex handle is owned and closed once.
            unsafe { CloseHandle(self.0) };
        }
    }
    let name: Vec<u16> = crate::status::AGENT_MUTEX.encode_utf16().chain([0]).collect();
    // SAFETY: a named mutex in this session's namespace; the handle is owned by `Held`.
    let h = unsafe { CreateMutexW(std::ptr::null(), 0, name.as_ptr()) };
    if h.is_null() {
        bail!("cannot create the session lock: {}", std::io::Error::last_os_error());
    }
    let held = Held(h);
    // SAFETY: reads the calling thread's last error, set by CreateMutexW.
    if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
        bail!("scopy sync run is already running in this session (the sync service starts it at logon)");
    }
    Ok(held)
}

#[cfg(not(windows))]
fn one_per_session() -> Result<()> {
    Ok(())
}

/// Client: `scopy sync enable` — enrols this PC's user with the receiver and writes the client config.
pub fn enable(server: &str, port: u16, folders: &[String]) -> Result<()> {
    // `user@host::` = a Linux daemon: sign in through SSH first.
    let (ssh, server, port) = match server.strip_suffix("::") {
        Some(dest) => {
            let (host, port) = crate::ssh::open_daemon(dest)?;
            (Some(dest.to_string()), host, port)
        }
        None => (None, server.to_string(), port),
    };
    let server = server.as_str();
    let ((mut r, mut w), bind) = crate::client::connect(server, port, KIND_ENROL)?;
    auth::client(&mut r, &mut w, server, &bind)?;
    w.put_u32(folders.len() as u32)?;
    for f in folders {
        w.put_str(f)?;
    }
    w.flush()?;
    r.get_status()?;
    let user = r.get_str()?;
    let base = r.get_str()?;
    let n = r.get_u32()?;
    let names: Vec<String> = (0..n).map(|_| r.get_str()).collect::<Result<_>>()?;
    let created = r.get_u8()? != 0;
    let cfg = ClientConfig {
        server: server.to_string(),
        port,
        ssh,
        user: user.clone(),
        folder: names
            .iter()
            .map(|n| ClientFolder { name: n.clone(), local: local_folder(n), remote: format!(r"\\{server}\{}\{n}", base.replace('/', "\\")) })
            .collect(),
    };
    let path = client_config_path();
    fs::create_dir_all(path.parent().unwrap())?;
    fs::write(&path, toml::to_string_pretty(&cfg)?).with_context(|| format!("cannot write {}", path.display()))?;
    eprintln!("enrolled {user} with {server} ({})", if created { "user folder created" } else { "user folder already there" });
    for f in &cfg.folder {
        eprintln!("  {:<10} {}  <->  {}", f.name, f.local.display(), f.remote);
    }
    eprintln!("config: {}", path.display());
    Ok(())
}

/// Where a known folder (Desktop, Documents, Downloads, …) is on this PC — it may be redirected or moved.
#[cfg(windows)]
fn local_folder(name: &str) -> PathBuf {
    use windows_sys::core::GUID;
    use windows_sys::Win32::System::Com::CoTaskMemFree;
    use windows_sys::Win32::UI::Shell::{FOLDERID_Desktop, FOLDERID_Documents, FOLDERID_Downloads, FOLDERID_Music, FOLDERID_Pictures, FOLDERID_Videos, SHGetKnownFolderPath};
    let id: Option<GUID> = match name.to_ascii_lowercase().as_str() {
        "desktop" => Some(FOLDERID_Desktop),
        "documents" => Some(FOLDERID_Documents),
        "downloads" => Some(FOLDERID_Downloads),
        "pictures" => Some(FOLDERID_Pictures),
        "music" => Some(FOLDERID_Music),
        "videos" => Some(FOLDERID_Videos),
        _ => None,
    };
    let fallback = || std::env::var_os("USERPROFILE").map(PathBuf::from).unwrap_or_default().join(name);
    let Some(id) = id else { return fallback() };
    let mut p: windows_sys::core::PWSTR = std::ptr::null_mut();
    // SAFETY: `id` is a known folder id; the returned string is freed with CoTaskMemFree.
    let hr = unsafe { SHGetKnownFolderPath(&id, 0, std::ptr::null_mut(), &mut p) };
    if hr != 0 || p.is_null() {
        return fallback();
    }
    let s = unsafe {
        let n = (0..).take_while(|&i| *p.add(i) != 0).count();
        let s = String::from_utf16_lossy(std::slice::from_raw_parts(p, n));
        CoTaskMemFree(p.cast());
        s
    };
    PathBuf::from(s)
}

#[cfg(not(windows))]
fn local_folder(name: &str) -> PathBuf {
    std::env::var_os("HOME").map(PathBuf::from).unwrap_or_default().join(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_folder_names_are_checked() {
        assert_eq!(folder_name("user").unwrap(), "user");
        for bad in ["", "..", "a\\b", "a/b", "c:", "x*y"] {
            assert!(folder_name(bad).is_err(), "{bad:?}");
        }
    }

    fn file(path: &str) -> Entry {
        Entry { kind: ENTRY_FILE, path: path.into(), size: 1, mtime: 0, ctime: 0, attrs: 0, ..Entry::default() }
    }

    #[test]
    fn deletes_take_only_the_version_the_pc_knew() {
        let t = std::env::temp_dir().join(format!("scopy-del-{}", crate::util::random_hex(4)));
        let base = t.join("user").join("Downloads");
        fs::create_dir_all(base.join("gone-dir/sub")).unwrap();
        fs::create_dir_all(base.join("busy-dir")).unwrap();
        for f in ["old.txt", "changed.txt", "gone-dir/sub/b.txt", "busy-dir/new-on-server.txt"] {
            fs::write(base.join(f), b"x").unwrap();
        }
        let mt = |p: &str| crate::meta::read(&fs::metadata(base.join(p)).unwrap()).mtime;
        let del = |path: &str, dir: bool, size: u64, mtime: i64| Delete { path: path.into(), dir, size, mtime };
        let deletes = vec![
            del("old.txt", false, 1, mt("old.txt")),
            del("changed.txt", false, 5, mt("changed.txt")), // the server has another version: kept
            del("gone-dir/sub/b.txt", false, 1, mt("gone-dir/sub/b.txt")),
            del("gone-dir/sub", true, 0, 0),
            del("gone-dir", true, 0, 0),
            del("busy-dir", true, 0, 0), // a file was added on the server: the folder stays
        ];
        assert_eq!(apply_deletes(&base, &deletes), (4, 2));
        assert!(!base.join("old.txt").exists() && !base.join("gone-dir").exists());
        assert!(base.join("changed.txt").exists() && base.join("busy-dir/new-on-server.txt").exists());
        let bin = t.join("user").join(".scopy-recycle").join("Downloads");
        let stamp = fs::read_dir(&bin).unwrap().next().unwrap().unwrap().path();
        assert!(stamp.join("old.txt").exists() && stamp.join("gone-dir/sub/b.txt").exists());
        fs::remove_dir_all(&t).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn files_in_use_are_recognised() {
        use std::os::windows::fs::OpenOptionsExt;
        let p = std::env::temp_dir().join(format!("scopy-inuse-{}.pdf", crate::util::random_hex(4)));
        fs::write(&p, b"x").unwrap();
        assert!(!in_use(&p) && !locked(&p));
        {
            let _viewer = fs::OpenOptions::new().read(true).share_mode(1).open(&p).unwrap(); // others may read (Word, a PDF viewer)
            assert!(in_use(&p) && !locked(&p));
        }
        {
            let _mail = fs::OpenOptions::new().read(true).share_mode(0).open(&p).unwrap(); // nobody else (a mailbox file)
            assert!(in_use(&p) && locked(&p));
        }
        assert!(!in_use(&p));
        fs::remove_file(&p).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn open_office_documents_are_found_by_their_owner_files() {
        use std::os::windows::fs::OpenOptionsExt;
        let t = std::env::temp_dir().join(format!("scopy-owner-{}", crate::util::random_hex(4)));
        fs::create_dir_all(t.join("sub")).unwrap();
        for (f, body) in [("sub/Document.docx", "doc"), ("sub/~$cument.docx", "A. User"), ("Budget.xlsx", "x"), ("~$Budget.xlsx", "A. User"), ("old.docx", "o"), ("~$old.docx", "stale")] {
            fs::write(t.join(f), body).unwrap();
        }
        // Word keeps Document.docx open; Excel has closed Budget.xlsx but left its owner file behind; old.docx too.
        let _word = fs::OpenOptions::new().read(true).share_mode(1).open(t.join("sub/Document.docx")).unwrap();
        let c = open_docs(&t);
        assert_eq!(c.len(), 1, "{c:?}");
        assert_eq!((c[0].path.as_str(), c[0].owner_name.as_str(), c[0].owner.as_slice()), ("sub/Document.docx", "~$cument.docx", b"A. User".as_slice()));
        drop(_word);
        fs::remove_dir_all(&t).unwrap();
    }

    #[test]
    fn files_the_receiver_distrusts_are_sent_again_never_fetched() {
        let mut held = 0;
        // Same size and time on both sides (zero-filled there after a reset): sent again, not taken as synced.
        assert_eq!(untrusted(Act::Synced, true, &mut held), Act::Push);
        assert_eq!(untrusted(Act::Pull, true, &mut held), Act::Push);
        assert_eq!(untrusted(Act::Conflict, true, &mut held), Act::Push);
        // Only the server has it: not fetched, decided again next round.
        assert_eq!(untrusted(Act::Pull, false, &mut held), Act::Gone);
        // Deleted here: the delete still goes to the server.
        assert_eq!(untrusted(Act::DeleteRemote, false, &mut held), Act::DeleteRemote);
        assert_eq!(held, 1);
    }

    #[test]
    fn three_way_decisions() {
        let v = |s: u64, m: i64| Some(Ver { size: s, mtime: m * 1_000_000_000 });
        let (a, b, c) = (v(1, 1), v(2, 2), v(3, 3));
        use Act::*;
        let cases = [
            ((None, a, None), Push),        // new here
            ((None, None, a), Pull),        // new on the server (copied there, a terminal server)
            ((None, a, a), Synced),
            ((None, a, b), Conflict),       // created on both sides differently
            ((a, a, a), Synced),
            ((a, b, a), Push),              // changed here
            ((a, a, b), Pull),              // changed on the server
            ((a, b, c), Conflict),          // changed on both
            ((a, b, b), Synced),            // the same change on both
            ((a, None, a), DeleteRemote),   // deleted here
            ((a, a, None), DeleteLocal),    // deleted on the server
            ((a, None, b), Pull),           // deleted here, changed there: the server's version comes back
            ((a, b, None), Push),           // deleted there, changed here: this PC's version goes back
            ((a, None, None), Gone),
        ];
        for ((p, l, r), want) in cases {
            assert_eq!(decide(p, l, r), want, "{p:?} {l:?} {r:?}");
        }
    }

    #[test]
    fn conflict_copies_keep_the_extension() {
        let c = conflict_name("docs/report.final.docx");
        assert!(c.starts_with("docs/report.final (conflict ") && c.ends_with(").docx"), "{c}");
        assert!(conflict_name("README").starts_with("README (conflict "));
    }

    #[test]
    fn moves_rename_a_listing_with_contents() {
        let mut m: std::collections::HashMap<String, u8> = [("docs", 1), ("docs/a.txt", 2), ("docsx.txt", 3)].iter().map(|(k, v)| (k.to_string(), *v)).collect();
        apply_moves_to(&mut m, &[Move { from: "docs".into(), to: "papers".into(), dir: true, size: 0, mtime: 0 }]);
        assert_eq!(m.get("papers/a.txt"), Some(&2));
        assert_eq!(m.get("docsx.txt"), Some(&3)); // only the folder and what is inside it
        assert!(!m.contains_key("docs"));
    }
    fn known(id: u64, dir: bool) -> Known {
        Known { id, dir, size: if dir { 0 } else { id * 10 }, mtime: if dir { 0 } else { id as i64 }, rid: 0 }
    }

    fn state(items: &[(&str, u64, bool)]) -> State {
        items.iter().map(|(p, id, d)| (p.to_string(), known(*id, *d))).collect()
    }

    #[test]
    fn orphan_part_files_go_once_idle() {
        let t = std::env::temp_dir().join(format!("scopy-orphan-{}", crate::util::random_hex(4)));
        let base = t.join("user").join("Downloads");
        fs::create_dir_all(&base).unwrap();
        let old = std::time::SystemTime::now() - ORPHAN_AGE - std::time::Duration::from_secs(60);
        for f in ["gone.zip.scopy-part", "gone.zip.scopy-journal", "kept.zip.scopy-part", "fresh.zip.scopy-part"] {
            let file = fs::File::create(base.join(f)).unwrap();
            if f != "fresh.zip.scopy-part" {
                file.set_modified(old).unwrap();
            }
        }
        let entries = vec![file("kept.zip")];
        assert_eq!(remove_orphans(&base, &entries), 2);
        assert!(!base.join("gone.zip.scopy-part").exists() && !base.join("gone.zip.scopy-journal").exists());
        assert!(base.join("kept.zip.scopy-part").exists() && base.join("fresh.zip.scopy-part").exists());
        fs::remove_dir_all(&t).unwrap();
    }

    #[test]
    fn renames_and_moves_are_found_by_file_id() {
        let prev = state(&[("a.txt", 1, false), ("docs", 2, true), ("docs/b.txt", 3, false), ("docs/sub", 4, true), ("docs/sub/c.txt", 5, false), ("d.txt", 6, false)]);
        // a.txt renamed; docs renamed to papers (everything inside moves with it); c.txt then moved up into papers;
        // d.txt changed while moving (not a move: sent again).
        let mut cur = state(&[("A2.txt", 1, false), ("papers", 2, true), ("papers/b.txt", 3, false), ("papers/sub", 4, true), ("papers/c.txt", 5, false)]);
        cur.insert("e.txt".into(), Known { id: 6, dir: false, size: 999, mtime: 6, rid: 0 });
        let m = detect_moves(&prev, &cur);
        let got: Vec<(&str, &str)> = m.iter().map(|m| (m.from.as_str(), m.to.as_str())).collect();
        assert_eq!(got, [("docs", "papers"), ("a.txt", "A2.txt"), ("papers/sub/c.txt", "papers/c.txt")]);
        assert!(m[0].dir && !m[1].dir && m[1].size == 10);
        assert!(detect_moves(&prev, &prev).is_empty());
    }

    #[test]
    fn a_named_pull_looks_at_just_those_paths_and_their_folders() {
        let root = std::env::temp_dir().join(format!("scopy-only-{}", crate::util::random_hex(6)));
        for rel in ["a/b/c.txt", "a/other.txt", "big/1.txt", "big/2.txt", ".scopy-recycle/x.txt"] {
            let p = root.join(rel);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(p, rel).unwrap();
        }
        fs::create_dir_all(root.join("newdir")).unwrap();
        let rels: Vec<String> = ["a/b/c.txt", "newdir", "missing.txt", ".scopy-recycle/x.txt"].iter().map(|x| x.to_string()).collect();
        let scan = crate::source::scan_only(&root, &rels).unwrap();
        let got: Vec<(String, bool)> = scan.manifest().into_iter().map(|e| (e.path.clone(), e.is_file())).collect();
        assert_eq!(got, [("a".into(), false), ("a/b".into(), false), ("a/b/c.txt".into(), true), ("newdir".into(), false)]);
        assert_eq!(scan.manifest()[2].size, 9);
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_named_push_scan_equals_the_filtered_whole_scan() {
        let root = std::env::temp_dir().join(format!("scopy-pushscan-{}", crate::util::random_hex(6)));
        for rel in ["a.txt", "docs/b.txt", "docs/sub/c.txt", "docs/sub/d.txt", "empty/.keep", "x/y/z.txt"] {
            let p = root.join(rel);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(p, rel).unwrap();
        }
        fs::remove_file(root.join("empty/.keep")).unwrap();
        let send: std::collections::HashSet<String> = ["docs/sub/c.txt", "a.txt"].iter().map(|x| x.to_string()).collect();
        // the old way: whole scan, then only the files to send (folders always)
        let mut whole = crate::source::scan(&root).unwrap();
        whole.entries.retain(|l| !l.e.is_file() || send.contains(&l.e.path));
        // the new way: the files to send and every folder the PC knows
        let mut named: Vec<String> = send.iter().cloned().collect();
        named.extend(scan_state(&root).into_iter().filter(|(_, k)| k.dir).map(|(p, _)| p));
        let scoped = crate::source::scan_only(&root, &named).unwrap();
        assert_eq!(scoped.manifest(), whole.manifest());
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn restat_on_the_touched_paths_equals_a_fresh_scan() {
        let root = std::env::temp_dir().join(format!("scopy-restat-{}", crate::util::random_hex(6)));
        let put = |rel: &str, data: &str| {
            let p = root.join(rel);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(p, data).unwrap();
        };
        for (rel, data) in [("a.txt", "a"), ("gone.txt", "g"), ("docs/b.txt", "bb"), ("old/x.txt", "x")] {
            put(rel, data);
        }
        let mut s = scan_state(&root);
        put("a.txt", "pulled, newer");
        put("new/deep/n.txt", "n");
        put("new/~$lock.docx", "excluded");
        put("conflict (PC).txt", "copy");
        fs::remove_file(root.join("gone.txt")).unwrap();
        fs::remove_dir_all(root.join("old")).unwrap();
        restat(&root, &mut s, ["a.txt", "new", "new/deep/n.txt", "conflict (PC).txt", "gone.txt", "old", "old/x.txt"].iter().map(|x| x.to_string()).collect());
        assert_eq!(s, scan_state(&root));
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_rounds_own_writes_are_told_from_new_changes() {
        let root = std::env::temp_dir().join(format!("scopy-left-{}", crate::util::random_hex(6)));
        fs::create_dir_all(root.join("sub")).unwrap();
        fs::write(root.join("pulled.txt"), "from the server").unwrap();
        fs::write(root.join("sub/other.txt"), "x").unwrap();
        let state = scan_state(&root);
        // what the round wrote or removed itself
        assert!(as_left(&root, &state, &root.join("pulled.txt")));
        assert!(as_left(&root, &state, &root.join("sub")));
        assert!(as_left(&root, &state, &root.join("deleted-by-the-round.txt")));
        assert!(as_left(&root, &state, &root));
        // real changes
        fs::write(root.join("pulled.txt"), "edited right after").unwrap();
        assert!(!as_left(&root, &state, &root.join("pulled.txt")));
        fs::write(root.join("new.txt"), "n").unwrap();
        assert!(!as_left(&root, &state, &root.join("new.txt")));
        fs::remove_file(root.join("sub/other.txt")).unwrap();
        assert!(!as_left(&root, &state, &root.join("sub/other.txt")));
        fs::remove_dir_all(&root).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn deltas_and_named_scans_never_look_through_a_junction() {
        let t = std::env::temp_dir().join(format!("scopy-junction-{}", crate::util::random_hex(6)));
        let (base, outside) = (t.join("base"), t.join("outside"));
        fs::create_dir_all(base.join("real")).unwrap();
        fs::create_dir_all(&outside).unwrap();
        fs::write(base.join("real/x.txt"), "x").unwrap();
        fs::write(outside.join("secret.txt"), "outside the share").unwrap();
        let ok = std::process::Command::new("cmd").args(["/c", "mklink", "/J"]).arg(base.join("link")).arg(&outside).output().unwrap().status.success();
        assert!(ok, "mklink /J failed");
        let mut look = crate::source::Look::new(&base, false);
        assert!(matches!(look.at("link/secret.txt"), crate::source::Seen::Missing));
        assert!(matches!(look.at("real/x.txt"), crate::source::Seen::Here(_)));
        let (_, entries) = crate::server::delta(&base, vec!["link".into(), "link/secret.txt".into(), "real/x.txt".into()]).unwrap();
        let paths: Vec<&str> = entries.iter().map(|e| e.path.as_str()).collect();
        assert_eq!(paths, ["real/x.txt"]);
        let named = crate::source::scan_only(&base, &["link/secret.txt".to_string(), "real/x.txt".to_string()]).unwrap();
        let paths: Vec<String> = named.manifest().into_iter().map(|e| e.path).collect();
        assert_eq!(paths, ["real", "real/x.txt"]);
        let mut s = scan_state(&base);
        restat(&base, &mut s, vec!["link/secret.txt".into()]);
        assert!(!s.contains_key("link/secret.txt"));
        let _ = fs::remove_dir(base.join("link"));
        fs::remove_dir_all(&t).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn a_case_only_rename_is_listed_under_its_new_spelling_only() {
        let base = std::env::temp_dir().join(format!("scopy-case-{}", crate::util::random_hex(6)));
        fs::create_dir_all(base.join("Docs")).unwrap();
        fs::write(base.join("Docs/x.txt"), "x").unwrap();
        fs::rename(base.join("Docs"), base.join("docs")).unwrap();
        let (removed, entries) = crate::server::delta(&base, vec!["Docs".into(), "docs".into(), "Docs/x.txt".into()]).unwrap();
        let paths: Vec<&str> = entries.iter().map(|e| e.path.as_str()).collect();
        assert_eq!(paths, ["docs", "docs/x.txt"]);
        assert!(removed.contains(&"Docs".to_string()));
        let mut s = scan_state(&base);
        restat(&base, &mut s, vec!["Docs".into(), "docs".into()]);
        assert_eq!(s, scan_state(&base));
        fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn a_delta_on_the_cached_listing_equals_a_fresh_full_listing() {
        let base = std::env::temp_dir().join(format!("scopy-delta-{}", crate::util::random_hex(6)));
        let put = |rel: &str, data: &str| {
            let p = base.join(rel);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(p, data).unwrap();
        };
        let full = || -> State {
            let mut s = State::new();
            let es: Vec<Entry> = crate::source::scan(&base).unwrap().manifest().into_iter().filter(|e| !e.path.contains(".scopy-")).collect();
            apply_delta(&mut s, &[], &es, &vec![0; es.len()]);
            s
        };
        for (rel, data) in [("a.txt", "a"), ("gone.txt", "g"), ("docs/b.txt", "bb"), ("docs/sub/c.txt", "ccc"), ("keep/k.txt", "k"), ("old-dir/x.txt", "x")] {
            put(rel, data);
        }
        let mut cache = full();
        // Changes, and the paths their events would name
        put("a.txt", "changed");
        put("new/deep/n.txt", "n");
        put(".scopy-recycle/Downloads/20261104-000000/r.txt", "scopy's own");
        fs::remove_file(base.join("gone.txt")).unwrap();
        fs::rename(base.join("docs"), base.join("papers")).unwrap();
        fs::rename(base.join("keep/k.txt"), base.join("papers/k.txt")).unwrap();
        fs::remove_dir_all(base.join("old-dir")).unwrap();
        let touched = ["a.txt", "new", "new/deep", "new/deep/n.txt", "gone.txt", "docs", "papers", "keep/k.txt", "papers/k.txt", "keep", "old-dir/x.txt", "old-dir"];
        let (removed, entries) = crate::server::delta(&base, touched.iter().map(|s| s.to_string()).collect()).unwrap();
        apply_delta(&mut cache, &removed, &entries, &vec![0; entries.len()]);
        let fresh = full();
        let view = |s: &State| -> std::collections::BTreeMap<String, (bool, u64, i64)> { s.iter().map(|(p, k)| (p.clone(), (k.dir, k.size, if k.dir { 0 } else { k.mtime }))).collect() };
        assert_eq!(view(&cache), view(&fresh));
        assert!(cache.contains_key("papers/sub/c.txt") && !cache.contains_key("docs/b.txt") && !cache.contains_key("gone.txt"));
        // A delta only names what changed: here 12 paths, not the whole folder
        assert!(entries.len() < fresh.len() + 2);
        fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn moves_made_on_the_server_are_done_here_when_safe() {
        let root = std::env::temp_dir().join(format!("scopy-smoves-{}", crate::util::random_hex(6)));
        let put = |rel: &str, data: &str| {
            let p = root.join(rel);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(p, data).unwrap();
        };
        for (rel, data) in [("a.txt", "a"), ("docs/b.txt", "bb"), ("docs/sub/c.txt", "ccc"), ("changed.txt", "old"), ("taken.txt", "t"), ("busy.txt", "x")] {
            put(rel, data);
        }
        put("new-name.txt", "someone else");
        let f = ClientFolder { name: "T".into(), local: root.clone(), remote: String::new() };
        // The last synced state, with the receiver's ids (rid); this PC's state = a fresh scan.
        let mut local = scan_state(&root);
        let mut prev: State = local.iter().map(|(p, k)| (p.clone(), Known { rid: 100 + p.len() as u64, ..*k })).collect();
        // changed.txt was changed here after the last round
        prev.get_mut("changed.txt").unwrap().size = 99;
        let rid = |p: &str| prev[p].rid;
        let mut remote = State::new();
        let mut at = |p: &str, from: &str| {
            let k = prev[from];
            remote.insert(p.to_string(), Known { id: k.rid, ..k });
        };
        // On the server: a.txt renamed (case and name), docs renamed with its contents, changed.txt and taken.txt
        // renamed (not doable here: changed here / target taken), busy.txt stays.
        at("A-renamed.txt", "a.txt");
        at("papers", "docs");
        at("papers/b.txt", "docs/b.txt");
        at("papers/sub", "docs/sub");
        at("papers/sub/c.txt", "docs/sub/c.txt");
        at("changed-moved.txt", "changed.txt");
        at("new-name.txt", "taken.txt");
        at("busy.txt", "busy.txt");
        assert_eq!(remote["papers"].id, rid("docs"));
        let done = server_moves_here(&f, &mut prev, &mut local, &remote, &[]);
        let got: Vec<(&str, &str)> = done.iter().map(|m| (m.from.as_str(), m.to.as_str())).collect();
        assert_eq!(got, [("docs", "papers"), ("a.txt", "A-renamed.txt")]);
        assert_eq!(fs::read_to_string(root.join("papers/sub/c.txt")).unwrap(), "ccc");
        assert_eq!(fs::read_to_string(root.join("A-renamed.txt")).unwrap(), "a");
        assert!(!root.join("docs").exists() && !root.join("a.txt").exists());
        assert!(root.join("changed.txt").exists() && root.join("taken.txt").exists());
        assert_eq!(fs::read_to_string(root.join("new-name.txt")).unwrap(), "someone else");
        // The maps follow: the round now sees the moved files as synced.
        assert!(prev.contains_key("papers/sub/c.txt") && local.contains_key("papers/sub/c.txt") && !local.contains_key("docs/b.txt"));
        // The PC's own move of the same file wins: nothing is done here.
        put("x.txt", "x");
        let mut local2 = scan_state(&root);
        let mut prev2: State = local2.iter().map(|(p, k)| (p.clone(), Known { rid: 7, ..*k })).filter(|(p, _)| p == "x.txt").collect();
        let remote2: State = [("y.txt".to_string(), Known { id: 7, ..prev2["x.txt"] })].into();
        let own = [Move { from: "x.txt".into(), to: "z.txt".into(), dir: false, size: 1, mtime: 0 }];
        assert!(server_moves_here(&f, &mut prev2, &mut local2, &remote2, &own).is_empty());
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn the_receiver_moves_only_what_still_matches() {
        let t = std::env::temp_dir().join(format!("scopy-moves-{}", crate::util::random_hex(4)));
        let base = t.join("user").join("Downloads");
        fs::create_dir_all(base.join("docs")).unwrap();
        fs::write(base.join("docs/b.txt"), b"bb").unwrap();
        fs::write(base.join("a.txt"), b"a").unwrap();
        fs::write(base.join("taken.txt"), b"t").unwrap();
        let mt = |p: &str| crate::meta::read(&fs::metadata(base.join(p)).unwrap()).mtime;
        let mv = |from: &str, to: &str, dir: bool, size: u64, mtime: i64| Move { from: from.into(), to: to.into(), dir, size, mtime };
        let moves = vec![
            mv("docs", "new/papers", true, 0, 0),           // folder, into a new parent
            mv("a.txt", "A.txt", false, 1, mt("a.txt")),    // case-only rename
            mv("taken.txt", "new/papers/b.txt", false, 1, mt("taken.txt")), // target exists: skipped
            mv("gone.txt", "x.txt", false, 1, 0),           // not there: skipped
            mv("A.txt", "z.txt", false, 5, 0),              // changed since: skipped
        ];
        assert_eq!(apply_moves(&t, &base, &moves), (2, 3));
        assert_eq!(fs::read(base.join("new/papers/b.txt")).unwrap(), b"bb");
        assert!(!base.join("docs").exists() && base.join("taken.txt").exists());
        assert!(fs::read_dir(&base).unwrap().flatten().any(|e| e.file_name() == "A.txt"));
        fs::remove_dir_all(&t).unwrap();
    }

    #[test]
    fn state_survives_a_save_and_sees_a_real_rename() {
        let t = std::env::temp_dir().join(format!("scopy-state-{}", crate::util::random_hex(4)));
        fs::create_dir_all(t.join("sub")).unwrap();
        fs::write(t.join("sub/one.txt"), b"1").unwrap();
        fs::write(t.join("~$lock.docx"), b"x").unwrap();
        let before = scan_state(&t);
        assert_eq!(before.len(), 2, "{before:?}"); // the Office lock file is left out
        assert!(before.values().all(|k| k.id != 0));
        fs::rename(t.join("sub"), t.join("renamed")).unwrap();
        let m = detect_moves(&before, &scan_state(&t));
        assert_eq!((m.len(), m[0].from.as_str(), m[0].to.as_str()), (1, "sub", "renamed"));
        fs::remove_dir_all(&t).unwrap();
    }

    #[test]
    fn failed_rounds_are_retried_sooner_than_the_full_round() {
        let s: Vec<u64> = (1..=7).map(|f| retry_pause(f).as_secs()).collect();
        assert_eq!(s, [30, 60, 120, 240, 300, 300, 300]);
    }

    #[test]
    fn wildcards_and_stamps() {
        use crate::util::{utc_stamp, wildcard};
        assert!(wildcard("~$*", "~$Report.docx") && wildcard("*.TMP", "a.tmp") && wildcard("*.crdownload", "x.zip.crdownload"));
        assert!(!wildcard("*.tmp", "a.tmpx") && !wildcard("~$*", "report.docx") && wildcard("desktop.ini", "Desktop.ini"));
        let s = utc_stamp();
        assert_eq!(s.len(), 15, "{s}");
        assert!(s.starts_with("20") && s.as_bytes()[8] == b'-');
    }

    #[test]
    fn receiver_config_parses() {
        let f: ReceiverFile = toml::from_str("[sync]\nroot = 'D:\\data\\users'\nfolders = ['Desktop', 'Documents']\n").unwrap();
        let s = f.sync.unwrap();
        assert_eq!(s.root, PathBuf::from(r"D:\data\users"));
        assert_eq!(s.folders, ["Desktop", "Documents"]);
        assert!(toml::from_str::<ReceiverFile>("[other]\nx = 1\n").unwrap().sync.is_none());
    }
}
