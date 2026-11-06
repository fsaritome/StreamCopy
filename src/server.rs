//! `scopy serve`: accepts push jobs (we are the destination) and pull jobs (we are the source).

use crate::auth;
use crate::compress;
use crate::dest::{self, DestSession};
use crate::logln;
use crate::proto::*;
use crate::shares::Shares;
use crate::tls::{self, Binding};
use crate::source::{self, Item, SourceCtx};
use crossbeam_channel::Receiver;
use crate::util::{fmt_bytes, random_hex, sanitize_rel, Progress};
use anyhow::{bail, Context, Result};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{BufReader, BufWriter, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

pub struct ServeOptions {
    pub port: u16,
    pub shares: Vec<(String, PathBuf)>,
    /// Only these published shares are reachable (empty = all of them); `shares` mappings always are.
    pub only_shares: Vec<String>,
    /// Administrative drive shares (C$, D$, ...) are reachable.
    pub allow_admin_shares: bool,
    /// Accepted for compatibility with installed service command lines; writers are now tuned per job.
    #[allow(dead_code)]
    pub writers: usize,
    /// Accept `--sink` benchmark jobs (data discarded instead of written).
    pub allow_sink: bool,
    /// Linux/Unix: where users get their sign-in tokens (`scopy token`, daemon.rs). Default: /run/scopy/token.sock
    /// when running as root, none otherwise.
    #[cfg_attr(not(unix), allow(dead_code))]
    pub token_socket: Option<PathBuf>,
    /// How long a daemon token is accepted (tests only; default `daemon::LIFETIME`).
    #[cfg_attr(not(unix), allow(dead_code))]
    pub token_lifetime: Option<Duration>,
    /// Unix, running as root: also accept clients without a token (the SMB ticket of a Windows client through
    /// Samba). They then write as root, so this is off by default.
    pub allow_ticket: bool,
}

enum Session {
    Dest(Arc<DestSession>),
    Source(Arc<SourceJob>),
}

struct SourceJob {
    ctx: Arc<SourceCtx>,
    /// Read data for the current round's data connections.
    feed: Mutex<Option<Receiver<Item>>>,
}

struct Ctx {
    shares: Shares,
    allow_sink: bool,
    /// Job records found after a restart, as (sid, destination); see `pending_dir`.
    interrupted: Mutex<Vec<crate::record::Record>>,
    records: crate::record::Records,
    sessions: Mutex<HashMap<String, Session>>,
    /// TLS binding of each session's control connection: data and feedback connections must show its token.
    binds: Mutex<HashMap<String, Binding>>,
    /// Outcomes of recent push jobs by session id.
    jobs: Mutex<HashMap<String, JobState>>,
    /// Two-way sync: files open on a PC, locked here for everyone else (locks.rs).
    locks: crate::locks::Locks,
    /// Two-way sync: what running sync pushes write, so the change feed leaves a PC's own writes out (feed.rs).
    writes: crate::feed::Writes,
    /// Two-way sync: what changed in each connected PC's folders, for delta listings (feed.rs).
    journals: crate::feed::Journals,
    /// Access proofs made recently (tokens instead of an SMB ticket on every push and pull, proofs.rs).
    proofs: crate::proofs::Proofs,
    /// Open change feed connections per Windows user (SID), for the limits below.
    feeds: Mutex<HashMap<String, usize>>,
    /// SSH session mode (`scopy session`, ssh.rs): every connection must first show this token; the process runs as
    /// the user who logged in over SSH, so the SMB access ticket is not needed.
    session: Option<String>,
    /// Linux daemon (daemon.rs): the sign-in tokens handed out through the token socket. A connection that shows one
    /// is served as its user (the kernel checks every access, no SMB ticket).
    tokens: Option<Arc<Tokens>>,
    /// Daemon: clients without a token are accepted too (`--allow-ticket`).
    allow_ticket: bool,
}

#[cfg(unix)]
use crate::daemon::Tokens;

/// No daemon sign-in on Windows (Windows sign-in instead).
#[cfg(not(unix))]
struct Tokens;

#[cfg(not(unix))]
impl Tokens {
    fn check(&self, _token: &str) -> Option<Arc<crate::auth::Identity>> {
        None
    }
}

/// Whether the operating system checks every access of this connection (we run as the user, or act as the user a
/// daemon token signed in): then no SMB ticket is needed.
fn os_checks(ctx: &Ctx, user: Option<&Arc<crate::auth::Identity>>) -> bool {
    ctx.session.is_some() || (ctx.tokens.is_some() && user.is_some())
}

/// Change feed connections allowed per Windows user (several PCs and terminal server sessions) and in all: each
/// holds a thread, a directory watch per folder and a change log.
const FEEDS_PER_USER: usize = 16;
const FEEDS_MAX: usize = 2_000;

/// One counted feed connection; uncounted again when dropped.
struct FeedSlot<'a>(&'a Mutex<HashMap<String, usize>>, String);
impl Drop for FeedSlot<'_> {
    fn drop(&mut self) {
        let mut m = self.0.lock().unwrap();
        if let Some(n) = m.get_mut(&self.1) {
            *n -= 1;
            if *n == 0 {
                m.remove(&self.1);
            }
        }
    }
}

enum JobState {
    Committing,
    Done(JobResult),
    /// Found as a pending-commit marker after a restart: the commit never finished.
    Interrupted,
}

impl Ctx {
    fn remember(&self, sid: &str, state: JobState) {
        const KEEP: usize = 200;
        let mut jobs = self.jobs.lock().unwrap();
        if jobs.len() >= KEEP {
            // Forget finished jobs first; committing ones must stay queryable.
            let old: Vec<String> =
                jobs.iter().filter(|(_, s)| !matches!(s, JobState::Committing)).map(|(k, _)| k.clone()).take(KEEP / 4).collect();
            for k in old {
                jobs.remove(&k);
            }
        }
        jobs.insert(sid.to_string(), state);
    }
}

/// Folder for the receiver's job records (see `record.rs`): next to the executable; on Unix as root in the state
/// folder (`$STATE_DIRECTORY` under systemd, else /var/lib/scopy), since an installed binary's folder is no place
/// for them.
fn pending_dir() -> PathBuf {
    #[cfg(unix)]
    if crate::meta::is_root() {
        let state = std::env::var("STATE_DIRECTORY").ok().and_then(|s| s.split(':').next().map(PathBuf::from));
        return state.unwrap_or_else(|| PathBuf::from("/var/lib/scopy")).join("pending");
    }
    std::env::current_exe().map(|p| p.with_file_name("scopy-pending")).unwrap_or_else(|_| PathBuf::from("scopy-pending"))
}

/// An SSH session's job records: per user (the session runs as the user, and an installed scopy's own folder is not
/// theirs to write): `$XDG_STATE_HOME/scopy/pending`, else `~/.local/state/scopy/pending`.
fn session_pending_dir() -> PathBuf {
    std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local").join("state")))
        .map(|d| d.join("scopy").join("pending"))
        .unwrap_or_else(pending_dir)
}

fn load_interrupted(ctx: &Ctx) {
    let (found, removed) = ctx.records.load();
    for sid in removed {
        logln!("job {sid}: job record without a destination, removed (a copy interrupted then may need --force once)");
    }
    for (sid, base) in found {
        logln!("job {sid}: interrupted before its data was on disk (destination {base}); the next copy there re-sends its files");
        ctx.remember(&sid, JobState::Interrupted);
        ctx.interrupted.lock().unwrap().push((sid, base));
    }
}

/// Files that interrupted jobs to `base` may have left without their data.
fn suspects_for(ctx: &Ctx, base: &Path) -> HashSet<String> {
    ctx.records.suspects(&ctx.interrupted.lock().unwrap(), base)
}

/// After `finish()` (everything this job wrote is flushed): what it wrote without an error settles older records for
/// the destination; its own record keeps only the files that failed or did not arrive completely (none: removed).
fn close_record(ctx: &Ctx, sid: &str, sess: &DestSession, full_plan: &[PlanItem], res: &JobResult) {
    let failed: HashSet<&str> = res.errors.iter().map(|(i, _)| sess.entries[*i as usize].path.as_str()).collect();
    let covered: HashSet<String> = sess.plan_paths(full_plan).into_iter().filter(|p| !failed.contains(p.as_str())).collect();
    settle_interrupted(ctx, &sess.base, &covered);
    if failed.is_empty() {
        ctx.records.drop_record(sid);
    } else {
        ctx.interrupted.lock().unwrap().push((sid.to_string(), sess.base.display().to_string()));
        let rest: Vec<&str> = failed.into_iter().collect();
        let _ = ctx.records.replace_list(sid, &rest);
    }
}

/// A job to `base` finished with everything on disk: settles older records for `base`.
fn settle_interrupted(ctx: &Ctx, base: &Path, covered: &HashSet<String>) {
    for sid in ctx.records.settle(&mut ctx.interrupted.lock().unwrap(), base, covered) {
        logln!("job {sid}: interrupted earlier; all its files are now on disk");
    }
}

/// `scopy session` (hidden): one copy job for a client that started us over SSH (ssh.rs). We run as the user SSH
/// logged in, so the operating system's permissions apply as for any program of theirs; the only folder we serve is
/// `path` (share `ssh`). Announces `SCOPY-SESSION <port> <token> <certificate fingerprint>` on stdout, then serves
/// connections that show the token, and ends when the client closes the SSH channel (our stdin) — or after two
/// minutes without any connection.
pub fn session(path: &Path, push: bool) -> Result<()> {
    if push {
        fs::create_dir_all(path).with_context(|| format!("cannot create {}", path.display()))?;
    }
    let path = fs::canonicalize(path).with_context(|| format!("{} not found", path.display()))?;
    let shares = Shares::discover(&[("ssh".to_string(), path.clone())], &["ssh".to_string()], false);
    let listener = TcpListener::bind(("0.0.0.0", 0)).context("cannot open a port for the session")?;
    let port = listener.local_addr()?.port();
    let token = random_hex(32);
    let fp = tls::server_fingerprint()?;
    {
        let mut out = std::io::stdout().lock();
        writeln!(out, "SCOPY-SESSION {port} {token} {fp}")?;
        out.flush()?;
    }
    logln!("scopy {} session for {} on port {port} ({})", env!("CARGO_PKG_VERSION"), path.display(), if push { "push" } else { "pull" });
    let ctx = Arc::new(Ctx {
        shares,
        allow_sink: false,
        interrupted: Mutex::new(Vec::new()),
        records: crate::record::Records::new(session_pending_dir()),
        sessions: Mutex::new(HashMap::new()),
        binds: Mutex::new(HashMap::new()),
        jobs: Mutex::new(HashMap::new()),
        locks: Default::default(),
        writes: Default::default(),
        journals: Default::default(),
        proofs: Default::default(),
        feeds: Default::default(),
        session: Some(token),
        tokens: None,
        allow_ticket: false,
    });
    // A session that crashed (power loss, reset) before its files were on disk left its record: this push re-sends
    // those files even where they look up to date.
    load_interrupted(&ctx);
    // The client closes the SSH channel when it is done (or gone): then we are too — but only once every push has
    // been written and flushed (with --stage/--detach the client leaves while the files are still in our RAM).
    thread::spawn(|| {
        let mut sink = [0u8; 256];
        while matches!(std::io::stdin().read(&mut sink), Ok(n) if n > 0) {}
        while PUSHES.load(std::sync::atomic::Ordering::SeqCst) > 0 {
            thread::sleep(Duration::from_millis(100));
        }
        std::process::exit(0);
    });
    let used = Arc::new(std::sync::atomic::AtomicBool::new(false));
    {
        let used = used.clone();
        thread::spawn(move || {
            thread::sleep(Duration::from_secs(120));
            if !used.load(std::sync::atomic::Ordering::Relaxed) {
                logln!("session: nobody connected within 2 minutes, ending");
                std::process::exit(1);
            }
        });
    }
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        used.store(true, std::sync::atomic::Ordering::Relaxed);
        let ctx = ctx.clone();
        thread::spawn(move || {
            if let Err(e) = handle(stream, &ctx) {
                logln!("session: {e:#}");
            }
        });
    }
    Ok(())
}

pub fn serve(o: &ServeOptions) -> Result<()> {
    let shares = Shares::discover(&o.shares, &o.only_shares, o.allow_admin_shares);
    let listener = TcpListener::bind(("0.0.0.0", o.port)).with_context(|| format!("cannot listen on port {}", o.port))?;
    logln!("scopy {} receiver listening on 0.0.0.0:{}  (writers per job: tuned automatically unless the client fixes them)", env!("CARGO_PKG_VERSION"), o.port);
    logln!("shares:");
    for (name, path) in shares.list() {
        logln!("  {name:<16} -> {}", path.display());
    }
    if cfg!(windows) && shares.admin_allowed() {
        logln!("  (plus administrative drive shares C$, D$, ...)");
    }
    if o.allow_sink {
        logln!("benchmark jobs allowed: `send --sink` discards the data instead of writing it");
    }
    // Unix: running as root, the daemon signs users in through its token socket (daemon.rs).
    #[cfg(unix)]
    let tokens = {
        let path = o.token_socket.clone().or_else(|| crate::meta::is_root().then(|| PathBuf::from(crate::daemon::DEFAULT_SOCKET)));
        match path {
            Some(p) => {
                let t = Arc::new(o.token_lifetime.map_or_else(Tokens::default, Tokens::new));
                crate::daemon::serve_tokens(&p, t.clone(), o.port, tls::server_fingerprint()?)?;
                if !o.allow_ticket {
                    logln!("clients sign in with a token (`ssh <host> scopy token`); clients without one are refused");
                }
                Some(t)
            }
            None => None,
        }
    };
    #[cfg(not(unix))]
    let tokens: Option<Arc<Tokens>> = None;
    let ctx = Arc::new(Ctx {
        shares,
        allow_sink: o.allow_sink,
        interrupted: Mutex::new(Vec::new()),
        records: crate::record::Records::new(pending_dir()),
        sessions: Mutex::new(HashMap::new()),
        binds: Mutex::new(HashMap::new()),
        jobs: Mutex::new(HashMap::new()),
        locks: Default::default(),
        writes: Default::default(),
        journals: Default::default(),
        proofs: Default::default(),
        feeds: Default::default(),
        session: None,
        tokens,
        allow_ticket: o.allow_ticket,
    });
    load_interrupted(&ctx);
    // Two-way sync: the users' recycle bins keep `[sync] recycle_days` (first look a minute after the start).
    thread::spawn(|| loop {
        thread::sleep(Duration::from_secs(60));
        crate::sync::purge_receiver_bins();
        thread::sleep(Duration::from_secs(3540));
    });
    {
        // Locks of PCs that stopped claiming them (asleep, offline) end after the lease.
        let ctx = ctx.clone();
        thread::spawn(move || loop {
            thread::sleep(Duration::from_secs(15));
            ctx.locks.expire();
        });
    }
    for stream in listener.incoming() {
        let stream = match stream {
            Ok(s) => s,
            Err(e) => {
                logln!("accept failed: {e}");
                continue;
            }
        };
        let ctx = ctx.clone();
        thread::spawn(move || {
            let peer = stream.peer_addr().map(|a| a.to_string()).unwrap_or_default();
            if let Err(e) = handle(stream, &ctx) {
                logln!("[{peer}] {e:#}");
            }
        });
    }
    Ok(())
}

fn handle(stream: TcpStream, ctx: &Ctx) -> Result<()> {
    crate::util::tune_socket(&stream)?;
    if tls::is_plain_scopy(&stream) {
        // A client older than 0.9 speaks plain scopy: answer in its format, so it shows why. Close our side first
        // and read what it already sent: closing with unread data makes Windows reset the connection, and the
        // reset would swallow the message.
        let mut w = BufWriter::new(stream.try_clone()?);
        w.put_err("this receiver runs scopy 0.9 or newer (TLS): update scopy on the client")?;
        w.flush()?;
        drop(w);
        let _ = stream.shutdown(std::net::Shutdown::Write);
        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
        let mut sink = [0u8; 4096];
        while matches!((&stream).read(&mut sink), Ok(n) if n > 0) {}
        bail!("refused a client older than 0.9 (no TLS)");
    }
    let (t, bind) = tls::accept(stream)?;
    let mut r = BufReader::with_capacity(4 << 20, t.clone());
    let mut w = BufWriter::with_capacity(1 << 20, t);
    if let Some(token) = &ctx.session {
        // SSH session: only the client that started us (it got the token over SSH) may connect.
        if r.get_str()? != *token {
            w.put_err("wrong session token")?;
            w.flush()?;
            bail!("session: connection with a wrong token refused");
        }
    }
    // Daemon: a client that signed in through SSH starts with its token (a string), any other with the hello.
    let mut head = Vec::new();
    if let Some(tokens) = &ctx.tokens {
        let mut first = [0u8; 4];
        r.read_exact(&mut first)?;
        if &first == MAGIC {
            if !ctx.allow_ticket {
                w.put_err("this receiver signs users in through SSH: copy to host::share/path (scopy gets a token with `ssh host scopy token`)")?;
                w.flush()?;
                bail!("refused a client without a token");
            }
            head.extend_from_slice(&first);
        } else {
            let n = u32::from_le_bytes(first);
            if n > 256 {
                bail!("protocol error: bad token");
            }
            let mut tok = vec![0u8; n as usize];
            r.read_exact(&mut tok)?;
            match tokens.check(&String::from_utf8_lossy(&tok)) {
                Some(user) => crate::auth::preauth(user),
                None => {
                    w.put_err("unknown or expired token: sign in again (`ssh host scopy token`)")?;
                    w.flush()?;
                    bail!("refused a connection with an unknown token");
                }
            }
        }
    }
    let mut r = std::io::Cursor::new(head).chain(r);
    match r.get_hello()? {
        KIND_PUSH => handle_push(r, w, ctx, &bind),
        KIND_PULL => handle_pull(r, w, ctx, &bind),
        KIND_DATA => handle_data(r, w, ctx),
        KIND_STATUS => handle_status(r, w, ctx),
        KIND_FEEDBACK => handle_feedback(r, w, ctx),
        KIND_ENROL => crate::sync::handle_enrol(r, w, &ctx.shares, &bind),
        KIND_LIST => handle_list(r, w, ctx, &bind),
        KIND_LOCKS => handle_locks(r, w, ctx, &bind),
        KIND_WATCH => handle_watch(r, w, ctx, &bind),
        k => {
            w.put_err(&format!("unknown connection kind {k}"))?;
            bail!("unknown connection kind {k}")
        }
    }
}

/// Resolves share + subpath to (share root, local path).
fn resolve(ctx: &Ctx, share: &str, sub: &str) -> Result<(PathBuf, PathBuf)> {
    let root = ctx.shares.resolve(share)?;
    let base = root.join(sanitize_rel(sub, true)?);
    crate::confine::no_links_below(&root, &base)?;
    Ok((root, base))
}

/// Takes suspended locks again when the push ends, however it ends.
struct Resume<'a>(&'a crate::locks::Locks, Vec<String>);
impl Drop for Resume<'_> {
    fn drop(&mut self) {
        if !self.1.is_empty() {
            self.0.resume(&self.1);
        }
    }
}

/// Removes a temporary file when dropped.
struct TempFile(PathBuf);
impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

/// A delta listing with more changed paths than this is sent as a full listing instead.
const DELTA_MAX: usize = 5_000;

/// Two-way sync: the signed-in user's folder as this receiver has it (read as the user; scopy's own files left out):
/// in full, or — when the PC's feed is connected and its cursor is still answerable — only what changed since.
fn handle_list(mut r: impl Read, mut w: impl Write, ctx: &Ctx, bind: &Binding) -> Result<()> {
    let Some(user) = auth::server(&mut r, &mut w, bind)? else {
        w.put_err("listing a folder needs a Windows sign-in")?;
        bail!("list without sign-in refused");
    };
    let _act = user.enter()?;
    let share = r.get_str()?;
    let sub = r.get_str()?;
    let pc = r.get_str()?;
    let (epoch, seq) = (r.get_u64()?, r.get_u64()?);
    // Only the change log of this user's own feed (a log belongs to the SID that opened it).
    let usid = user.sid().unwrap_or_default();
    let mut journal = None;
    let listed = resolve(ctx, &share, &sub).and_then(|(_, base)| {
        // The cursor is taken before the folder is looked at: what changes meanwhile is in the next delta too.
        journal = ctx.journals.get(&pc, &base).filter(|j| !usid.is_empty() && j.lock().unwrap().sid == usid);
        let (cursor, changed) = match &journal {
            Some(j) => {
                let j = j.lock().unwrap();
                (j.cursor(), j.since(epoch, seq))
            }
            None => ((0, 0), None),
        };
        if !base.is_dir() {
            return Ok((None, Vec::new(), Vec::new(), cursor, Vec::new()));
        }
        // Files an interrupted job may have left with the right size and time but without their data (a hard reset
        // loses the write cache): the PC must not take them as synced, it sends them again (measured: 1,019 files
        // zero-filled on TEST-B after a reset during an upload, taken as synced because size and time matched).
        // One that is gone from the folder (deleted, moved away) can't be bad any more: settled, or it would be
        // listed and re-sent for ever (measured: 124 files of a job cut off hours earlier, long deleted).
        let (gone, mut suspect): (Vec<String>, Vec<String>) = suspects_for(ctx, &base).into_iter().partition(|p| {
            sanitize_rel(p, false).is_ok_and(|rel| fs::symlink_metadata(base.join(rel)).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound))
        });
        if !gone.is_empty() {
            settle_interrupted(ctx, &base, &gone.into_iter().collect());
        }
        suspect.sort();
        if let Some(changed) = changed.filter(|c| c.len() <= DELTA_MAX) {
            if let Some((removed, entries)) = delta(&base, changed) {
                let ids = entry_ids(&base, &entries);
                return Ok((Some(removed), entries, ids, cursor, suspect));
            }
        }
        let entries = source::scan(&base)?.manifest();
        let entries: Vec<_> = entries.into_iter().filter(|e| !e.is_link() && !e.path.split('/').any(|c| c.contains(".scopy-"))).collect();
        let ids = entry_ids(&base, &entries);
        Ok((None, entries, ids, cursor, suspect))
    });
    match listed {
        Ok((removed, entries, ids, (epoch, seq), suspect)) => {
            w.put_ok()?;
            match removed {
                Some(removed) => {
                    w.put_u8(LIST_DELTA)?;
                    w.put_u32(removed.len() as u32)?;
                    for p in &removed {
                        w.put_str(p)?;
                    }
                }
                None => w.put_u8(LIST_FULL)?,
            }
            put_manifest(&mut w, &entries)?;
            w.put_u32(ids.len() as u32)?;
            for id in ids {
                w.put_u64(id)?;
            }
            w.put_u64(epoch)?;
            w.put_u64(seq)?;
            w.put_u32(suspect.len() as u32)?;
            for p in &suspect {
                w.put_str(p)?;
            }
            w.flush()?;
            // Only a listing that reached the PC covers the events before its cursor (no ping needed for them).
            if let Some(j) = &journal {
                j.lock().unwrap().listed(seq);
            }
            Ok(())
        }
        Err(e) => {
            w.put_err(&format!("{e:#}"))?;
            w.flush()?;
            bail!("list {share}/{sub} as {}: {e:#}", user.user)
        }
    }
}

/// The changed paths of a delta as they are now: every path is removed (with everything below it) and, where it
/// still exists, listed again (a folder with its whole contents). Same rules as the full listing: links and
/// special files are left out, so are scopy's own files. None = something could not be read (send it all).
pub(crate) fn delta(base: &Path, mut changed: Vec<String>) -> Option<(Vec<String>, Vec<Entry>)> {
    // Outer paths first; anything below a folder that is listed again anyway is covered by it.
    changed.sort_by_key(|p| (p.matches('/').count(), p.clone()));
    let (mut removed, mut entries): (Vec<String>, Vec<Entry>) = (Vec::new(), Vec::new());
    let mut relisted: Vec<String> = Vec::new();
    // As the whole-folder scan sees it: never through a link, and under the exact on-disk spelling.
    let mut look = source::Look::new(base, true);
    for rel in changed {
        if relisted.iter().any(|d| rel.starts_with(&format!("{d}/"))) {
            continue;
        }
        let full = base.join(sanitize_rel(&rel, false).ok()?);
        removed.push(rel.clone());
        let md = match look.at(&rel) {
            source::Seen::Here(md) => md,
            source::Seen::Missing => continue,
            source::Seen::Unreadable => return None,
        };
        if md.is_dir() && !md.file_type().is_symlink() {
            entries.push(crate::meta::entry(ENTRY_DIR, rel.clone(), &fs::metadata(&full).ok()?, String::new()));
            for mut e in source::scan(&full).ok()?.manifest() {
                // Sync lists files and folders only (links are a Unix copy feature).
                if e.is_link() || e.path.split('/').any(|c| c.contains(".scopy-")) {
                    continue;
                }
                e.path = format!("{rel}/{}", e.path);
                entries.push(e);
            }
            relisted.push(rel);
        } else if md.is_file() {
            entries.push(crate::meta::entry(ENTRY_FILE, rel, &md, String::new()));
        }
    }
    Some((removed, entries))
}

/// The file ids of a listing's entries (NTFS: MFT record + sequence number, read per folder without opening a file;
/// 0 if unknown): the same after a rename or move, so a PC can tell a move on the server from a delete + new file.
fn entry_ids(base: &Path, entries: &[Entry]) -> Vec<u64> {
    let mut by_dir: HashMap<&str, HashMap<std::ffi::OsString, u64>> = HashMap::new();
    entries
        .iter()
        .map(|e| {
            let (dir, name) = e.path.rsplit_once('/').unwrap_or(("", &e.path));
            let ids = by_dir.entry(dir).or_insert_with(|| {
                #[cfg(windows)]
                return crate::meta::dir_entry_ids(&base.join(dir));
                #[cfg(not(windows))]
                fs::read_dir(base.join(dir))
                    .map(|rd| rd.flatten().filter_map(|d| Some((d.file_name(), crate::meta::file_id(&fs::symlink_metadata(d.path()).ok()?)))).collect())
                    .unwrap_or_default()
            });
            ids.get(std::ffi::OsStr::new(name)).copied().unwrap_or(0)
        })
        .collect()
}

/// Two-way sync: the files open on a PC (its claims for one sync folder); answers with the locks other PCs hold there.
fn handle_locks(mut r: impl Read, mut w: impl Write, ctx: &Ctx, bind: &Binding) -> Result<()> {
    let Some(user) = auth::server(&mut r, &mut w, bind)? else {
        w.put_err("locks need a Windows sign-in")?;
        bail!("locks without sign-in refused");
    };
    let _act = user.enter()?;
    let share = r.get_str()?;
    let sub = r.get_str()?;
    let pc = r.get_str()?;
    let claims = get_claims(&mut r)?;
    let checked = resolve(ctx, &share, &sub).and_then(|(_, base)| {
        crate::sync::check_mirror_target(Some(&user), &base)?;
        Ok((base, user.sid()?))
    });
    let (base, sid) = match checked {
        Ok(x) => x,
        Err(e) => {
            w.put_err(&format!("{e:#}"))?;
            w.flush()?;
            bail!("locks {share}/{sub} as {}: {e:#}", user.user);
        }
    };
    let states = ctx.locks.claim(&base, &sid, &user.user, &pc, &claims, crate::sync::lock_lease());
    let others = ctx.locks.others(&base, &sid, &pc);
    w.put_ok()?;
    w.put_u32(states.len() as u32)?;
    for s in states {
        w.put_u8(s)?;
    }
    put_lock_infos(&mut w, &others)?;
    w.flush()?;
    Ok(())
}

/// Two-way sync, change feed: C→R sign-in (required), pc:str, n:u32, n × (share:str, subpath:str) — the PC's sync
/// folders. R→C status, then for as long as the connection lasts: a folder index (u32) each time something changed
/// in that folder that this PC did not write itself, or feed::ALIVE every feed::HEARTBEAT.
fn handle_watch(mut r: impl Read, mut w: impl Write, ctx: &Ctx, bind: &Binding) -> Result<()> {
    use crate::feed::{self, Folder};
    use notify::{RecursiveMode, Watcher};
    use std::sync::mpsc::{channel, RecvTimeoutError};
    let Some(user) = auth::server(&mut r, &mut w, bind)? else {
        w.put_err("the change feed needs a Windows sign-in")?;
        bail!("watch without sign-in refused");
    };
    let pc = r.get_str()?;
    let n = r.get_u32()?;
    let usid = user.sid().unwrap_or_default();
    let _slot = {
        let mut m = ctx.feeds.lock().unwrap();
        let (mine, all) = (m.get(&usid).copied().unwrap_or(0), m.values().sum::<usize>());
        if mine >= FEEDS_PER_USER || all >= FEEDS_MAX {
            drop(m);
            w.put_err(&format!("too many change feed connections ({mine} for this user, {all} in all; at most {FEEDS_PER_USER} / {FEEDS_MAX})"))?;
            w.flush()?;
            bail!("watch from {pc} as {} refused: {mine} feeds for this user, {all} in all", user.user);
        }
        *m.entry(usid.clone()).or_default() += 1;
        FeedSlot(&ctx.feeds, usid.clone())
    };
    if n == 0 || n > feed::MAX_FOLDERS {
        w.put_err(&format!("1 to {} folders per change feed", feed::MAX_FOLDERS))?;
        bail!("watch: {n} folders refused");
    }
    let mut asked = Vec::new();
    for _ in 0..n {
        asked.push((r.get_str()?, r.get_str()?));
    }
    let (tx, rx) = channel::<notify::Result<notify::Event>>();
    let mut watcher = notify::recommended_watcher(move |ev| {
        let _ = tx.send(ev);
    })?;
    // Only the user's own sync folders, checked and opened as the user.
    let folders = (|| -> Result<Vec<Folder>> {
        let _act = user.enter()?;
        let mut folders = Vec::new();
        for (share, sub) in &asked {
            let (_, base) = resolve(ctx, share, sub)?;
            crate::sync::check_mirror_target(Some(&user), &base)?;
            watcher.watch(&base, RecursiveMode::Recursive).with_context(|| format!("cannot watch {}", base.display()))?;
            folders.push(Folder::new(base));
        }
        Ok(folders)
    })();
    let folders = match folders {
        Ok(f) => f,
        Err(e) => {
            w.put_err(&format!("{e:#}"))?;
            w.flush()?;
            bail!("watch as {} from {pc}: {e:#}", user.user);
        }
    };
    w.put_ok()?;
    w.flush()?;
    logln!("feed: {pc} ({}) watches {}", user.user, folders.iter().map(|f| f.base.display().to_string()).collect::<Vec<_>>().join(", "));
    // Every event goes into the folder's change log (own writes too: the log says what the folder looks like).
    let journals: Vec<_> = folders.iter().map(|f| ctx.journals.open(&pc, &f.key, &usid)).collect();
    let note = |ev: &notify::Result<notify::Event>| match ev {
        Ok(ev) if !ev.need_rescan() => {
            for p in &ev.paths {
                for (f, j) in folders.iter().zip(&journals) {
                    if let Some(rel) = feed::rel_in(f, p) {
                        j.lock().unwrap().note(rel);
                    }
                }
            }
        }
        _ => journals.iter().for_each(|j| j.lock().unwrap().lost()),
    };
    let res = (|| -> Result<()> {
        loop {
            let first = match rx.recv_timeout(feed::HEARTBEAT) {
                Ok(ev) => {
                    note(&ev);
                    ev
                }
                Err(RecvTimeoutError::Timeout) => {
                    w.put_u32(feed::ALIVE)?;
                    w.put_u64(0)?;
                    w.put_u64(0)?;
                    w.flush()?;
                    continue;
                }
                Err(RecvTimeoutError::Disconnected) => bail!("the folder watch ended"),
            };
            // A save is a burst of events: collect them for a moment, then tell the PC once per folder.
            let until = Instant::now() + feed::DEBOUNCE;
            let (mut paths, mut rescan) = (Vec::new(), false);
            let mut take = |ev: notify::Result<notify::Event>| match ev {
                Ok(ev) => {
                    rescan |= ev.need_rescan();
                    paths.extend(ev.paths);
                }
                Err(_) => rescan = true,
            };
            take(first);
            while let Some(left) = until.checked_duration_since(Instant::now()) {
                match rx.recv_timeout(left) {
                    Ok(ev) => {
                        note(&ev);
                        take(ev)
                    }
                    Err(_) => break,
                }
            }
            for i in feed::changed(&folders, &ctx.writes, &pc, &paths, rescan) {
                // A listing since these events (the PC's round was already running) covered them.
                let j = journals[i as usize].lock().unwrap();
                if j.news() {
                    w.put_u32(i)?;
                    w.put_u64(j.epoch)?;
                    w.put_u64(j.last_event)?;
                }
            }
            w.flush()?;
        }
    })();
    for (f, j) in folders.iter().zip(&journals) {
        let epoch = j.lock().unwrap().epoch;
        ctx.journals.close(&pc, &f.key, epoch);
    }
    logln!("feed: {pc} ({}) gone: {}", user.user, res.as_ref().err().map(|e| format!("{e:#}")).unwrap_or_default());
    Ok(())
}

/// Pushes being received or committed right now. An SSH session waits for 0 before it ends (a detached client has
/// closed the channel while its files may still be in our RAM).
static PUSHES: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

struct PushGuard;
impl PushGuard {
    fn enter() -> PushGuard {
        PUSHES.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        PushGuard
    }
}
impl Drop for PushGuard {
    fn drop(&mut self) {
        PUSHES.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}

fn handle_push(mut r: impl Read, mut w: impl Write, ctx: &Ctx, bind: &Binding) -> Result<()> {
    let _busy = PushGuard::enter();
    // From here on this thread acts as the signed-in user; scopy's housekeeping switches back (auth::as_service).
    let user = auth::server(&mut r, &mut w, bind)?;
    let _act = user.as_ref().map(|u| u.enter()).transpose()?;
    let who = user.as_ref().map_or("the service (no Windows sign-in)".to_string(), |u| u.user.clone());
    let share = r.get_str()?;
    let sub = r.get_str()?;
    let token = r.get_str()?;
    let (root, base) = match resolve(ctx, &share, &sub) {
        Ok(x) => x,
        Err(e) => {
            w.put_err(&e.to_string())?;
            return Err(e);
        }
    };

    // Access: a token for a write proof this signed-in user made for this folder within the last minutes
    // (proofs.rs), or the ticket — written by the client over SMB, proving write access.
    let usid = user.as_ref().and_then(|u| u.sid().ok());
    // In an SSH session we run as the user: the operating system checks every write, no ticket needed.
    let proven = os_checks(ctx, user.as_ref()) || usid.as_deref().is_some_and(|s| ctx.proofs.check(&token, s, &base, true));
    w.put_ok()?;
    if proven {
        w.put_u8(ACCESS_TOKEN)?;
    } else {
        let ticket_name = format!(".scopy-ticket-{}", random_hex(8));
        let nonce = random_hex(32);
        w.put_u8(ACCESS_TICKET)?;
        w.put_str(&ticket_name)?;
        w.put_str(&nonce)?;
        w.flush()?;
        match r.get_u8()? {
            MSG_TICKET_WRITTEN => {}
            MSG_ABORT => return Ok(()),
            m => bail!("protocol error: unexpected message {m}"),
        }
        let ticket_path = base.join(&ticket_name);
        let found = fs::read_to_string(&ticket_path).ok();
        let _ = fs::remove_file(&ticket_path);
        // The ticket must carry this TLS session's binding: a man in the middle runs a different session.
        if let Err(e) = tls::check_ticket(found.as_deref().unwrap_or_default(), &nonce, bind) {
            w.put_err(&format!("{e:#}"))?;
            bail!("{e:#} ({share}/{sub}, {})", ticket_path.display());
        }
    }
    // A signed-in user gets a token for the next pushes here (the same one while it lasts).
    let next_token = match &usid {
        Some(_) if proven => token,
        Some(s) => ctx.proofs.issue(s, &base, true),
        None => String::new(),
    };

    // Only now, for a client that proved its access: the overlap probe, which the client looks for in its source
    // tree (so nobody can make the receiver write files before the access check).
    let sid = random_hex(16);
    let probe = dest::place_probe(&base, Some(&root));
    w.put_ok()?;
    w.put_str(&sid)?;
    w.put_str(&probe.name)?;
    w.put_u8(probe.dest_exists as u8)?;
    w.put_str(&next_token)?;
    w.flush()?;
    match r.get_u8()? {
        MSG_GO => {}
        MSG_ABORT => return Ok(()),
        m => bail!("protocol error: unexpected message {m}"),
    }
    drop(probe);

    let opts = get_options(&mut r)?;
    // A sync round sends the renames and moves the PC saw before its manifest.
    let moves = if opts.mirror() { get_moves(&mut r)? } else { Vec::new() };
    let deletes = if opts.mirror() { get_deletes(&mut r)? } else { Vec::new() };
    let pc = if opts.mirror() { r.get_str()? } else { String::new() };
    let t_manifest = Instant::now();
    let entries = get_manifest(&mut r, !opts.numeric_ids())?;
    let t_manifest = t_manifest.elapsed();
    let t0 = Instant::now();
    if opts.mirror() {
        if let Err(e) = crate::sync::check_mirror_target(user.as_deref(), &base) {
            w.put_err(&format!("{e:#}"))?;
            bail!("push: mirror refused: {e:#}");
        }
    }
    let mut outcome = MirrorOutcome::default();
    // The lock owner's own round (a document saved while open on that PC): its locks on what it sends step aside
    // for the moment the files are replaced.
    let suspended = match (opts.mirror(), user.as_ref().and_then(|u| u.sid().ok())) {
        (true, Some(usid)) => {
            let rels: HashSet<String> = entries.iter().filter(|e| e.is_file()).map(|e| e.path.clone()).collect();
            ctx.locks.suspend(&base, &usid, &pc, &rels)
        }
        _ => Vec::new(),
    };
    let _resume = Resume(&ctx.locks, suspended);
    // The change feed leaves what this round writes out of the pings to this PC (it knows already).
    let _own = opts.mirror().then(|| {
        let rels = entries.iter().map(|e| e.path.clone());
        let moved = moves.iter().flat_map(|m| [m.from.clone(), m.to.clone()]);
        let deleted = deletes.iter().map(|d| d.path.clone());
        ctx.writes.begin(&base, &pc, rels.chain(moved).chain(deleted).collect::<Vec<_>>())
    });
    if !moves.is_empty() {
        // Before the plan: a moved file is then found at its new path and not sent again.
        let (done, skipped) = crate::sync::apply_moves(&root, &base, &moves);
        outcome.renamed = done;
        logln!("push {sid}: {done} moves done{}", if skipped > 0 { format!(", {skipped} skipped (those files are sent instead)") } else { String::new() });
    }
    if !deletes.is_empty() {
        // Deletes the PC decided: only what is still the version the PC last synced goes into the recycle bin.
        let (done, skipped) = crate::sync::apply_deletes(&base, &deletes);
        outcome.recycled = done;
        logln!("push {sid}: {done} deletes into the recycle bin{}", if skipped > 0 { format!(", {skipped} kept (changed here or not empty)") } else { String::new() });
    }
    // Moves and deletes are renames: on disk before the PC hears they are done, or a crash brings the files back
    // and the PC, which saved them as deleted, takes them for new ones on the server (seen in the crash test:
    // 3,457 deleted files back on both sides). A round with file data flushes again at its end.
    if outcome.renamed + outcome.recycled > 0 {
        let t = Instant::now();
        match crate::auth::as_service(|| crate::meta::flush_volume(&base)) {
            Ok(()) => logln!("push {sid}: moves and deletes flushed to disk in {:.2}s", t.elapsed().as_secs_f64()),
            Err(e) => logln!("push {sid}: cannot flush the moves and deletes to disk ({e}); a crash now could bring them back"),
        }
    }
    if opts.sink() && !ctx.allow_sink {
        w.put_err("this receiver does not accept --sink benchmark jobs (start it with --allow-sink)")?;
        bail!("push {sid}: --sink refused (receiver not started with --allow-sink)");
    }
    logln!(
        "push {sid}: {} entries -> {} as {who} (zstd {}, verify {}, writers {}){}",
        entries.len(),
        base.display(),
        opts.level,
        opts.verify(),
        if opts.writers > 0 { opts.writers.to_string() } else { "auto".to_string() },
        if opts.sink() { " SINK: data discarded, nothing written" } else { "" }
    );
    // The client may fix a writer count; otherwise it is tuned automatically from our own throughput.
    let tuner = dest::writer_tuner(opts.writers.min(MAX_THREADS) as usize);
    let sess = match DestSession::new(base, entries, opts, tuner, Arc::new(Progress::default())) {
        Ok(s) => s,
        Err(e) => {
            w.put_err(&format!("{e:#}"))?;
            return Err(e);
        }
    };
    if let Some(u) = &user {
        sess.act_as(u.clone());
    }
    if let Err(e) = sess.confine(&root) {
        w.put_err(&format!("{e:#}"))?;
        sess.finish();
        return Err(e);
    }
    let suspect = suspects_for(ctx, &sess.base);
    if !suspect.is_empty() {
        logln!("push {sid}: {} files of an interrupted earlier job are re-sent even if they look up to date", suspect.len());
    }
    sess.set_suspect(suspect);
    let t_survey = Instant::now();
    let (needed, missing) = sess.survey_dirs();
    if let Err(e) = sess.check_links() {
        w.put_err(&format!("{e:#}"))?;
        sess.finish();
        bail!("push {sid}: {e:#}");
    }
    let (t_survey, t_plan) = (t_survey.elapsed(), Instant::now());
    let mut plan = sess.initial_plan();
    let t_plan = t_plan.elapsed();
    // The folders are created while data already flows.
    let s = sid.clone();
    if let Err(e) = sess.start_create_dirs(move |n, d| logln!("push {s}: {n} folders created in {:.2}s (in the background)", d.as_secs_f64())) {
        w.put_err(&format!("{e:#}"))?;
        sess.finish();
        return Err(e);
    }
    logln!(
        "push {sid}: manifest {:.2}s, folders surveyed {:.2}s ({missing} of {needed} new), plan {:.2}s ({} files to receive)",
        t_manifest.as_secs_f64(),
        t_survey.as_secs_f64(),
        t_plan.as_secs_f64(),
        plan.len()
    );
    let full_plan = plan.clone();
    // The job record is on disk before any file data can be (data only flows after the plan reply), and stays
    // until everything is on disk.
    let record = !sess.opts.sink() && !full_plan.is_empty();
    if record {
        let t = Instant::now();
        match ctx.records.write(&sid, &sess.base, &sess.plan_paths(&full_plan)) {
            Ok(()) => logln!("push {sid}: job record written in {:.2}s", t.elapsed().as_secs_f64()),
            Err(e) => logln!("push {sid}: cannot write the job record ({e}); a crash before the end could not be detected"),
        }
    }
    {
        let (sess, sid) = (sess.clone(), sid.clone());
        thread::spawn(move || sess.run_writer_tuner(&|m| logln!("push {sid}: {m}")));
    }
    ctx.binds.lock().unwrap().insert(sid.clone(), *bind);
    ctx.sessions.lock().unwrap().insert(sid.clone(), Session::Dest(sess.clone()));

    let rounds = (|| -> Result<()> {
        w.put_ok()?;
        put_plan(&mut w, &plan)?;
        w.flush()?;
        // The client trains a dictionary on what it will actually send, and sends it next.
        sess.set_dict(r.get_blob()?);
        w.put_ok()?;
        w.flush()?;
        loop {
            match r.get_u8()? {
                MSG_ROUND_DONE => {
                    let n = r.get_u32()?;
                    sess.wait_round(n)?;
                    plan = sess.incomplete(&plan);
                    w.put_ok()?;
                    put_plan(&mut w, &plan)?;
                    w.flush()?;
                }
                MSG_FINISH => return Ok(()),
                m => bail!("protocol error: unexpected message {m}"),
            }
        }
    })();
    ctx.sessions.lock().unwrap().remove(&sid);
    ctx.binds.lock().unwrap().remove(&sid);
    if let Err(e) = rounds {
        // Broken off (client gone, PC asleep, network lost) while this receiver keeps running: finish() still
        // writes what was queued and flushes it to disk, so the files that arrived completely are as safe as after
        // a clean end. Only the incomplete ones stay in the record; the next job re-sends just those (big files
        // resume from their part file) instead of everything this job planned.
        let res = sess.finish();
        if record {
            close_record(ctx, &sid, &sess, &full_plan, &res);
        }
        logln!("push {sid}: broken off ({e:#}); {} files complete and on disk, {} kept for the next job", res.files_ok, res.errors.len());
        return Err(e);
    }

    // 1. "Received": everything is in our RAM. With staging the writers may still be busy; a client may
    //    disconnect now (--detach) and ask for the outcome later, so nothing below may depend on the socket.
    let received = sess.received_count(&full_plan);
    let received_bytes = sess.progress.raw.load(std::sync::atomic::Ordering::Relaxed);
    let _ = (|| -> Result<()> {
        w.put_ok()?;
        w.put_u64(received)?;
        w.put_u64(received_bytes)?;
        w.flush()?;
        Ok(())
    })();
    ctx.remember(&sid, JobState::Committing);
    if sess.staged() {
        logln!("push {sid}: received {received} files ({}), committing from RAM", fmt_bytes(received_bytes));
    }

    // 2. "Committed": written, flushed to disk, verified if asked.
    let res = sess.finish();
    ctx.remember(&sid, JobState::Done(res.clone()));
    if record {
        close_record(ctx, &sid, &sess, &full_plan, &res);
    }
    let secs = t0.elapsed().as_secs_f64().max(1e-9);
    logln!(
        "push {sid}: wrote {} files, {} in {secs:.1}s ({:.0} files/s), {} skipped, {} errors",
        res.files_ok,
        fmt_bytes(res.bytes_ok),
        res.files_ok as f64 / secs,
        sess.skipped.load(std::sync::atomic::Ordering::Relaxed),
        res.errors.len()
    );
    for (idx, msg) in res.errors.iter().take(20) {
        logln!("  {}: {msg}", sess.entries[*idx as usize].path);
    }
    // A sync round: part files of interrupted transfers that no round will finish any more are removed.
    if sess.opts.mirror() && res.errors.is_empty() {
        let n = crate::sync::remove_orphans(&sess.base, &sess.entries);
        if n > 0 {
            logln!("push {sid}: removed {n} part files of interrupted transfers");
        }
    }
    // The client may have detached after "received"; then it asks via KIND_STATUS instead.
    let _ = (|| -> Result<()> {
        w.put_ok()?;
        put_result(&mut w, &res)?;
        if sess.opts.mirror() {
            put_mirror_outcome(&mut w, &outcome)?;
        }
        w.flush()?;
        Ok(())
    })();
    Ok(())
}

/// Streams the receiver's state to the sender every second until the job finishes, so the sender can tune
/// (compression level etc.) on what the receiver experiences.
fn handle_feedback(mut r: impl Read, mut w: impl Write, ctx: &Ctx) -> Result<()> {
    let sid = r.get_str()?;
    if let Err(e) = check_join(ctx, &sid, &r.get_str()?) {
        w.put_err(&format!("{e:#}"))?;
        return Err(e);
    }
    let Some(Session::Dest(sess)) = ctx.sessions.lock().unwrap().get(&sid).map(|s| match s {
        Session::Dest(d) => Session::Dest(d.clone()),
        Session::Source(j) => Session::Source(j.clone()),
    }) else {
        w.put_err("no such push job")?;
        bail!("feedback for unknown job");
    };
    w.put_ok()?;
    w.flush()?;
    let mut prev = (Instant::now(), 0u64, 0u64);
    loop {
        thread::sleep(Duration::from_secs(1));
        let f = sess.feedback(&mut prev);
        if put_feedback(&mut w, &f).and_then(|_| w.flush()).is_err() || f.end == 1 {
            return Ok(());
        }
    }
}

/// Answers "how is job <session id> doing?" for clients that detached after "received".
fn handle_status(mut r: impl Read, mut w: impl Write, ctx: &Ctx) -> Result<()> {
    let sid = r.get_str()?;
    w.put_ok()?;
    match ctx.jobs.lock().unwrap().get(&sid) {
        None => w.put_u8(JOB_UNKNOWN)?,
        Some(JobState::Committing) => w.put_u8(JOB_COMMITTING)?,
        Some(JobState::Interrupted) => w.put_u8(JOB_INTERRUPTED)?,
        Some(JobState::Done(res)) => {
            w.put_u8(JOB_DONE)?;
            put_result(&mut w, res)?;
        }
    }
    w.flush()?;
    Ok(())
}

fn handle_pull(mut r: impl Read, mut w: impl Write, ctx: &Ctx, bind: &Binding) -> Result<()> {
    let user = auth::server(&mut r, &mut w, bind)?;
    let _act = user.as_ref().map(|u| u.enter()).transpose()?;
    let who = user.as_ref().map_or("the service (no Windows sign-in)".to_string(), |u| u.user.clone());
    let share = r.get_str()?;
    let sub = r.get_str()?;
    let token = r.get_str()?;
    let (root, base) = match resolve(ctx, &share, &sub) {
        // As the user sees it: a folder they may not look into says "Permission denied" (as `ls` would), not
        // "not found" (`exists()` can't tell the two apart).
        Ok(x) => match std::fs::metadata(&x.1) {
            Ok(_) => x,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                w.put_err("source not found")?;
                bail!("pull of missing {share}/{sub}");
            }
            Err(e) => {
                w.put_err(&format!("cannot read {share}/{sub}: {e}"))?;
                bail!("pull of {share}/{sub}: {e}");
            }
        },
        Err(e) => {
            w.put_err(&e.to_string())?;
            return Err(e);
        }
    };

    // Access: a token for a read proof this signed-in user made for this folder within the last minutes
    // (proofs.rs), or the check: we place a nonce in the source folder; the client can only echo it back if it
    // can read that folder over SMB.
    let usid = user.as_ref().and_then(|u| u.sid().ok());
    let proven = os_checks(ctx, user.as_ref()) || usid.as_deref().is_some_and(|s| ctx.proofs.check(&token, s, &base, false));
    if proven {
        w.put_ok()?;
        w.put_u8(ACCESS_TOKEN)?;
    } else {
        let ticket_dir = if base.is_dir() { base.clone() } else { base.parent().map(Path::to_path_buf).unwrap_or_default() };
        let ticket_name = format!(".scopy-ticket-{}", random_hex(8));
        let nonce = random_hex(32);
        let ticket = TempFile(ticket_dir.join(&ticket_name));
        // scopy's own file: written as the service, since the user may only have read access here.
        if let Err(e) = auth::as_service(|| fs::write(&ticket.0, tls::ticket(&nonce, bind))) {
            w.put_err("server cannot place the access ticket in the source folder")?;
            bail!("cannot write {}: {e}", ticket.0.display());
        }
        w.put_ok()?;
        w.put_u8(ACCESS_TICKET)?;
        w.put_str(&ticket_name)?;
        w.flush()?;
        let echoed = r.get_str()?;
        auth::as_service(|| drop(ticket));
        if echoed != nonce {
            w.put_err("access check failed: wrong ticket")?;
            bail!("access check failed for pull of {share}/{sub}");
        }
    }
    let next_token = match &usid {
        Some(_) if proven => token,
        Some(s) => ctx.proofs.issue(s, &base, false),
        None => String::new(),
    };
    let sid = random_hex(16);
    w.put_ok()?;
    w.put_str(&sid)?;
    w.put_str(&next_token)?;
    w.flush()?;

    let mut opts = get_options(&mut r)?;
    let probe_name = r.get_str()?;
    let dest_exists = r.get_u8()? != 0;
    let only = if opts.flags & OPT_ONLY != 0 {
        let n = r.get_u32()?;
        if n > END_OF_STREAM {
            bail!("pull: {n} named paths refused");
        }
        Some((0..n).map(|_| r.get_str()).collect::<Result<Vec<String>>>()?)
    } else {
        None
    };
    let t0 = Instant::now();
    let scanned = match &only {
        Some(rels) if base.is_dir() => source::scan_only(&base, rels),
        _ => source::scan(&base),
    };
    let scan = match scanned {
        Ok(s) => s,
        Err(e) => {
            w.put_err(&format!("{e:#}"))?;
            return Err(e);
        }
    };
    let scan_secs = t0.elapsed().as_secs_f64();
    if source::overlap(&scan, &probe_name, dest_exists).is_some() {
        w.put_err("destination overlaps the source — refusing to copy")?;
        bail!("pull of {share}/{sub} refused: overlap");
    }
    let want_dict = opts.level > 0 && opts.flags & OPT_NO_DICT == 0;
    opts.dict.clear();
    let manifest = scan.manifest();
    w.put_ok()?;
    put_options(&mut w, &opts)?;
    put_manifest(&mut w, &manifest)?;
    w.put_u64((scan_secs * 1e6) as u64)?;
    w.flush()?;
    logln!("pull {sid}: {} entries from {} as {who} (zstd {})", manifest.len(), base.display(), opts.level);

    let entries = Arc::new(scan.entries);
    let job = Arc::new(SourceJob {
        ctx: Arc::new(SourceCtx::new(entries.clone(), opts.level as i32, Vec::new(), opts.verify(), Arc::new(Progress::default()))),
        feed: Mutex::new(None),
    });
    // The readers stay inside the share (the scan already skips links; this also covers one swapped in later).
    if let Some(u) = &user {
        let _ = job.ctx.user.set(u.clone());
    }
    let _ = job.ctx.jail.set(crate::confine::Jail::new(&root).with_context(|| format!("cannot open the share root {}", root.display()))?);
    ctx.binds.lock().unwrap().insert(sid.clone(), *bind);
    ctx.sessions.lock().unwrap().insert(sid.clone(), Session::Source(job.clone()));
    // The current round's queue: ended when the next round starts or the pull ends (also on errors), so parked
    // readers of a broken-off pull don't stay behind as threads.
    let current: Mutex<Option<Arc<source::Queue>>> = Mutex::new(None);
    let rounds = (|| -> Result<()> {
        let mut first = true;
        let mut disk_keys: Option<Vec<u64>> = None;
        loop {
            match r.get_u8()? {
                MSG_PLAN => {
                    let plan = get_plan(&mut r, manifest.len())?;
                    if first {
                        let (keys, why) = source::decide_disk_order(opts.disk_order, &entries, &plan);
                        logln!("pull {sid}: {why}");
                        disk_keys = keys;
                    }
                    // Train the dictionary once, on what the client actually needs.
                    let dict = if first && want_dict {
                        compress::train_dict(&source::dict_samples(&entries, &plan)).unwrap_or_default()
                    } else {
                        Vec::new()
                    };
                    if !dict.is_empty() {
                        job.ctx.set_dict(dict.clone());
                    }
                    first = false;
                    let queue = Arc::new(source::build_queue(&manifest, &plan, opts.order, disk_keys.as_deref()));
                    if let Some(old) = current.lock().unwrap().replace(queue.clone()) {
                        old.abort();
                    }
                    let (q, progress) = (queue.clone(), job.ctx.progress.clone());
                    let s = sid.clone();
                    thread::spawn(move || source::run_auto_order(&q, &progress.wire, &|m| logln!("pull {s}: {m}")));
                    // Readers run detached; they stop when the queue is done (or this feed is replaced).
                    let tuner = source::reader_tuner(opts.readers as usize);
                    let (feed, _readers) = source::start_readers(job.ctx.clone(), queue.clone(), tuner.clone());
                    let (c, s) = (job.ctx.clone(), sid.clone());
                    thread::spawn(move || {
                        let starved = crate::util::Starved {
                            wait_us: &|| c.t_feed_wait.micros(),
                            consumers: &|| c.streams_active.load(std::sync::atomic::Ordering::Relaxed),
                        };
                        crate::util::run_tuner(&tuner, &c.read_items, Some(starved), &|| queue.done(), "readers", &|m| {
                            logln!("pull {s}: {m}")
                        })
                    });
                    *job.feed.lock().unwrap() = Some(feed);
                    w.put_ok()?;
                    w.put_blob(&dict)?;
                    w.flush()?;
                }
                MSG_FINISH => return Ok(()),
                m => bail!("protocol error: unexpected message {m}"),
            }
        }
    })();
    if let Some(q) = current.lock().unwrap().take() {
        q.abort();
    }
    ctx.sessions.lock().unwrap().remove(&sid);
    ctx.binds.lock().unwrap().remove(&sid);
    rounds?;
    let errors = job.ctx.errors.lock().unwrap().clone();
    logln!("pull {sid}: done in {:.1}s, {} read errors", t0.elapsed().as_secs_f64(), errors.len());
    w.put_ok()?;
    put_stats(&mut w, &job.ctx.stats())?;
    w.put_u32(errors.len() as u32)?;
    for e in &errors {
        w.put_str(e)?;
    }
    w.flush()?;
    Ok(())
}

/// Counts a finished data connection for the round, however its handler exits.
struct ConnGuard(Arc<DestSession>);
impl Drop for ConnGuard {
    fn drop(&mut self) {
        self.0.conn_finished();
    }
}

/// A data or feedback connection may join session `sid` only with the token of the session's control connection.
fn check_join(ctx: &Ctx, sid: &str, token: &str) -> Result<()> {
    match ctx.binds.lock().unwrap().get(sid) {
        Some(b) if tls::join_token(b, sid) == token => Ok(()),
        Some(_) => bail!("data connection refused: wrong token for session {sid}"),
        None => bail!("data connection for unknown session"),
    }
}

fn handle_data(mut r: impl Read, mut w: impl Write, ctx: &Ctx) -> Result<()> {
    let sid = r.get_str()?;
    if let Err(e) = check_join(ctx, &sid, &r.get_str()?) {
        w.put_err(&format!("{e:#}"))?;
        return Err(e);
    }
    let session = match ctx.sessions.lock().unwrap().get(&sid) {
        Some(Session::Dest(d)) => Session::Dest(d.clone()),
        Some(Session::Source(s)) => Session::Source(s.clone()),
        None => {
            w.put_err("unknown session")?;
            bail!("data connection for unknown session");
        }
    };
    match session {
        Session::Dest(sess) => {
            let _guard = ConnGuard(sess.clone());
            w.put_ok()?;
            w.flush()?;
            dest::recv_frames(&mut r, &sess)
        }
        Session::Source(job) => {
            let Some(feed) = job.feed.lock().unwrap().clone() else {
                w.put_err("no plan yet")?;
                bail!("data connection before the first plan");
            };
            w.put_ok()?;
            source::stream_work(&mut w, &job.ctx, &feed)?;
            put_end(&mut w)?;
            w.flush()?;
            Ok(())
        }
    }
}
