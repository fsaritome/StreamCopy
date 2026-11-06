//! Client side: `scopy send` (push: we are the source) and `scopy get` (pull: we are the destination).

use crate::auth;
use crate::compress::{self, Policy};
use crate::dest::{self, DestSession};
use crate::proto::*;
use crate::record;
use crate::tls::{self, Binding, Tls};
use crate::source::{self, Item, Queue, SourceCtx};
use crossbeam_channel::Receiver;
use crate::util::{self, fmt_bytes, fmt_secs, show, spawn_reporter, Phases, Progress};
use anyhow::{bail, Context, Result};
use std::fs;
use std::io::{BufReader, BufWriter, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// `--compress auto`: the sender adjusts the level on the fly (push only; a pull uses the start level).
pub const LEVEL_AUTO: i32 = -1;
/// Measured on the archive (BENCHMARKS.md): level 1 puts about as much on the wire as 3 (11.2 vs 11.1 GB) for a
/// third less CPU, and was faster on every path (across hosts 0:16 vs 0:17–0:18). The tuner raises it on slow links.
const AUTO_START_LEVEL: i32 = 1;

#[derive(Clone)]
pub struct ClientOptions {
    pub streams: usize,
    pub port: u16,
    pub host: Option<String>,
    pub force: bool,
    /// zstd level, 0 = off, LEVEL_AUTO = adjusted while sending.
    pub level: i32,
    pub no_dict: bool,
    pub verify: bool,
    pub no_meta: bool,
    /// Unix owners/groups by number, not mapped by name (rsync --numeric-ids).
    pub numeric_ids: bool,
    pub retries: u32,
    /// One of the ORDER_* constants.
    pub order: u8,
    pub progress_secs: u64,
    /// Writer threads on the destination (asked of the server for a push, local for a pull); 0 = default.
    pub writers: usize,
    /// Reader threads on the source (local for a push, asked of the server for a pull); 0 = automatic.
    pub readers: usize,
    /// One of the DISK_ORDER_* constants.
    pub disk_order: u8,
    /// Receiver RAM staging in MB (push); 0 = off.
    pub stage_mb: u32,
    /// Push: return once the server has everything in RAM, without waiting for the commit.
    pub detach: bool,
    /// Push, benchmark only: the receiver discards the file data instead of writing it.
    pub sink: bool,
    /// Push, sync: the receiver removes (into the user's recycle bin) what the source no longer has.
    pub mirror: bool,
    /// Sync rounds: only these files (relative paths) are sent (push) or fetched (pull); folders always. None = all.
    pub only: Option<Arc<std::collections::HashSet<String>>>,
    /// Sync rounds: this PC's name (the receiver lets this PC's own open-file locks step aside for its push).
    pub pc: String,
    /// The sync agent: access tokens the receiver handed out, by (folder, write) — shown instead of proving access
    /// over SMB again (proofs.rs). None = always prove (the command line).
    pub tokens: Option<Arc<std::sync::Mutex<std::collections::HashMap<(String, bool), String>>>>,
    /// Push: file names left out (`*` wildcards, case-insensitive).
    pub exclude: Vec<String>,
}

impl ClientOptions {
    fn options(&self) -> Options {
        let mut flags = 0;
        if self.force {
            flags |= OPT_FORCE;
        }
        if self.verify {
            flags |= OPT_VERIFY;
        }
        if self.no_meta {
            flags |= OPT_NO_META;
        }
        if self.no_dict {
            flags |= OPT_NO_DICT;
        }
        if self.sink {
            flags |= OPT_SINK;
        }
        if self.mirror {
            flags |= OPT_MIRROR;
        }
        if self.numeric_ids {
            flags |= OPT_NUMERIC_IDS;
        }
        Options {
            flags,
            level: if self.level == LEVEL_AUTO { AUTO_START_LEVEL as i8 } else { self.level.clamp(0, 19) as i8 },
            order: self.order,
            readers: self.readers.min(MAX_THREADS as usize) as u16,
            writers: self.writers.min(MAX_THREADS as usize) as u16,
            disk_order: self.disk_order,
            stage_mb: self.stage_mb,
            dict: Vec::new(),
        }
    }
}

/// Splits `\\host\share\sub\dir` (or `//host/share/...`) into (host, share, "sub/dir").
pub fn parse_unc(path: &str) -> Result<(String, String, String)> {
    let norm = path.replace('/', "\\");
    let Some(rest) = norm.strip_prefix("\\\\") else {
        bail!("expected a network path like \\\\server\\share\\folder, got {path}");
    };
    let mut parts = rest.split('\\').filter(|s| !s.is_empty());
    let host = parts.next().context("missing server name")?.to_string();
    let share = parts.next().context("missing share name")?.to_string();
    let sub = parts.collect::<Vec<_>>().join("/");
    Ok((host, share, sub))
}

pub(crate) type Conn = (BufReader<Tls>, BufWriter<Tls>);

/// SSH mode (ssh.rs): the session's one-time token, sent first on every connection.
/// The token every connection shows first: from an SSH session, or from a daemon sign-in (which a long-running sync
/// agent renews, so it can change).
static SESSION_TOKEN: std::sync::RwLock<Option<String>> = std::sync::RwLock::new(None);

pub fn set_session(token: &str) {
    *SESSION_TOKEN.write().unwrap() = Some(token.to_string());
}

/// Whether this process copies through an SSH session (or a daemon it signed in to through SSH).
pub fn in_session() -> bool {
    SESSION_TOKEN.read().unwrap().is_some()
}

fn token_for(o: &ClientOptions, remote: &str, write: bool) -> String {
    o.tokens.as_ref().and_then(|t| t.lock().unwrap().get(&(remote.to_lowercase(), write)).cloned()).unwrap_or_default()
}

fn keep_token(o: &ClientOptions, remote: &str, write: bool, token: String) {
    if let Some(t) = &o.tokens {
        let mut t = t.lock().unwrap();
        if token.is_empty() {
            t.remove(&(remote.to_lowercase(), write));
        } else {
            t.insert((remote.to_lowercase(), write), token);
        }
    }
}

/// Connects over TLS and returns the connection with its binding (see tls.rs).
pub(crate) fn connect(host: &str, port: u16, kind: u8) -> Result<(Conn, Binding)> {
    connect_with(host, port, kind, None)
}

/// `connect`, with a read timeout on the socket (a long-lived connection that must notice a dead peer).
fn connect_with(host: &str, port: u16, kind: u8, read_timeout: Option<std::time::Duration>) -> Result<(Conn, Binding)> {
    let s = TcpStream::connect((host, port))
        .with_context(|| format!("cannot connect to {host}:{port} — is `scopy serve` running there?"))?;
    util::tune_socket(&s)?;
    s.set_read_timeout(read_timeout)?;
    let (t, bind) = tls::connect(s).with_context(|| format!("no TLS session with {host}:{port}"))?;
    let r = BufReader::with_capacity(4 << 20, t.clone());
    let mut w = BufWriter::with_capacity(1 << 20, t);
    if let Some(token) = SESSION_TOKEN.read().unwrap().clone() {
        w.put_str(&token)?;
    }
    w.put_hello(kind)?;
    Ok(((r, w), bind))
}

/// A data connection joins session `sid` with the token of the control connection's binding `bind`.
fn join_data(host: &str, port: u16, sid: &str, bind: &Binding) -> Result<Conn> {
    let ((mut r, mut w), _) = connect(host, port, KIND_DATA)?;
    w.put_str(sid)?;
    w.put_str(&tls::join_token(bind, sid))?;
    w.flush()?;
    r.get_status()?;
    Ok((r, w))
}

fn planned_bytes(entries: &[Entry], plan: &[PlanItem]) -> u64 {
    plan.iter()
        .map(|p| {
            let e = &entries[p.idx as usize];
            match &p.chunks {
                None => e.size,
                Some(bits) => (0..chunk_count(e.size))
                    .filter(|&c| bit(bits, c))
                    .map(|c| CHUNK.min(e.size - c as u64 * CHUNK))
                    .sum(),
            }
        })
        .sum()
}

pub fn push(src: &Path, dest: &str, o: &ClientOptions) -> Result<()> {
    push_with(src, dest, o, &[], &[]).map(|_| ())
}

/// A push; for a sync round (`o.mirror`) the PC's moves and deletes go first, and the result says what the
/// receiver did besides copying (renamed, recycled).
pub fn push_with(src: &Path, dest: &str, o: &ClientOptions, moves: &[Move], deletes: &[Delete]) -> Result<MirrorOutcome> {
    let start = Instant::now();
    let phases = Phases::default();
    let (unc_host, share, sub) = parse_unc(dest)?;
    let host = o.host.clone().unwrap_or(unc_host.clone());

    // A sync round names what it sends (its files and all the PC's folders): only those are looked at, not the
    // whole folder; the manifest is the same as a full scan filtered to them.
    let mut scan = match &o.only {
        Some(only) if src.is_dir() => phases.run("scan source", || source::scan_only(src, &only.iter().cloned().collect::<Vec<_>>()))?,
        _ => phases.run("scan source", || source::scan(src))?,
    };
    if !o.exclude.is_empty() {
        scan.entries.retain(|l| {
            let name = l.e.path.rsplit('/').next().unwrap_or(&l.e.path);
            !(!l.e.is_dir() && o.exclude.iter().any(|x| util::wildcard(x, name)))
        });
    }
    if let Some(only) = &o.only {
        scan.entries.retain(|l| l.e.is_dir() || only.contains(&l.e.path));
    }
    let nfiles = scan.entries.iter().filter(|l| l.e.is_file()).count();
    let nlinks = scan.entries.iter().filter(|l| l.e.is_link()).count();
    let total: u64 = scan.entries.iter().map(|l| l.e.size).sum();
    let links = if nlinks > 0 { format!(", {nlinks} symbolic links") } else { String::new() };
    eprintln!("scanned {nfiles} files, {} folders{links}, {}", scan.entries.len() - nfiles - nlinks, fmt_bytes(total));
    if scan.skipped_special > 0 {
        eprintln!("warning: skipped {} {}", scan.skipped_special, if cfg!(unix) { "special files (devices, sockets, pipes)" } else { "symlinks/special files" });
    }

    let t = Instant::now();
    let ((mut cr, mut cw), bind) = connect(&host, o.port, KIND_PUSH)?;
    // Sign in as the logged-on user: the receiver then writes with the user's own rights.
    auth::client(&mut cr, &mut cw, &unc_host, &bind)?;
    cw.put_str(&share)?;
    cw.put_str(&sub)?;
    cw.put_str(&token_for(o, dest, true))?;
    cw.flush()?;
    cr.get_status()?;
    if cr.get_u8()? == ACCESS_TICKET {
        let ticket_name = cr.get_str()?;
        let nonce = cr.get_str()?;
        // Prove write access the normal way: through SMB, with the user's own credentials.
        let dest_dir = PathBuf::from(dest);
        fs::create_dir_all(&dest_dir).with_context(|| format!("cannot create {} over SMB", dest_dir.display()))?;
        let ticket = dest_dir.join(&ticket_name);
        // The ticket carries this TLS session's binding: a man in the middle would show the receiver a different one.
        fs::write(&ticket, tls::ticket(&nonce, &bind)).with_context(|| format!("cannot write to {} over SMB — no write access?", dest_dir.display()))?;
        cw.put_u8(MSG_TICKET_WRITTEN)?;
        cw.flush()?;
        let status = cr.get_status();
        let _ = fs::remove_file(&ticket);
        status?;
        eprintln!("access: write access checked over SMB");
    } else {
        // A write proof from the last minutes (proofs.rs): no SMB round trips this time.
        if in_session() { eprintln!("access: SSH session (the other side writes as your user)"); } else { eprintln!("access: write access proven earlier (token from an SMB check in the last {} min)", crate::proofs::LIFETIME.as_secs() / 60); }
        cr.get_status()?;
    }
    let sid = cr.get_str()?;
    let probe_name = cr.get_str()?;
    let dest_exists = cr.get_u8()? != 0;
    keep_token(o, dest, true, cr.get_str()?);
    if let Some(dir) = source::overlap(&scan, &probe_name, dest_exists) {
        cw.put_u8(MSG_ABORT)?;
        cw.flush()?;
        bail!("destination overlaps the source (it lies in or above {}) — refusing to copy", show(&dir));
    }
    cw.put_u8(MSG_GO)?;
    phases.add("connect + access check", t.elapsed());

    let mut opts = o.options();
    let manifest = scan.manifest();
    let t = Instant::now();
    put_options(&mut cw, &opts)?;
    if o.mirror {
        put_moves(&mut cw, moves)?;
        put_deletes(&mut cw, deletes)?;
        cw.put_str(&o.pc)?;
    }
    put_manifest(&mut cw, &manifest)?;
    cw.flush()?;
    cr.get_status()?;
    let mut plan = get_plan(&mut cr, manifest.len())?;
    phases.add("manifest + plan (folders follow in the background)", t.elapsed());
    // Dictionary for many small files, trained only on what will actually be sent.
    if opts.level > 0 && !o.no_dict {
        opts.dict = phases.run("train dictionary", || compress::train_dict(&source::dict_samples(&scan.entries, &plan))).unwrap_or_default();
    }
    cw.put_blob(&opts.dict)?;
    cw.flush()?;
    cr.get_status()?;

    let need_files = plan.len() as u64;
    let need_bytes = planned_bytes(&manifest, &plan);
    let skipped = nfiles as u64 - need_files;
    eprintln!(
        "sending {need_files} files ({}), {skipped} up to date, {} streams, zstd {}{}{}",
        fmt_bytes(need_bytes),
        o.streams,
        match opts.level {
            0 => "off".into(),
            l if o.level == LEVEL_AUTO => format!("auto (starting at {l})"),
            l => l.to_string(),
        },
        if opts.dict.is_empty() { String::new() } else { format!(" + {} dictionary", fmt_bytes(opts.dict.len() as u64)) },
        if o.verify { ", verify on" } else { "" }
    );

    let (disk_keys, why) = source::decide_disk_order(o.disk_order, &scan.entries, &plan);
    eprintln!("{why}");
    let progress = Arc::new(Progress::default());
    progress.total_files.store(need_files, Ordering::Relaxed);
    progress.total_bytes.store(need_bytes, Ordering::Relaxed);
    let stop = Arc::new(AtomicBool::new(false));
    let reporter = spawn_reporter(progress.clone(), Duration::from_secs(o.progress_secs.max(1)), stop.clone());
    let ctx = Arc::new(SourceCtx::new(Arc::new(scan.entries), opts.level as i32, opts.dict.clone(), o.verify, progress.clone()));
    let mut final_readers = 0;
    let mut readers_summary = String::new();
    // Live receiver state (writer queue, RAM stage) for the compression tuner; optional.
    let feedback = Arc::new(Mutex::new(None));
    start_feedback(&host, o.port, &sid, &bind, feedback.clone());
    let transfer_done = Arc::new(AtomicBool::new(false));
    let level_tuning = (o.level == LEVEL_AUTO && opts.level > 0).then(|| {
        let (ctx, feedback, done, streams) = (ctx.clone(), feedback.clone(), transfer_done.clone(), o.streams);
        thread::spawn(move || {
            source::run_level_tuner(&ctx, streams, &feedback, &|| done.load(Ordering::Relaxed), &|m| eprintln!("{m}"))
        })
    });

    let t = Instant::now();
    let mut decisions = Vec::new();
    for round in 0..=o.retries {
        if plan.is_empty() {
            break;
        }
        if round > 0 {
            eprintln!("retry round {round}: {} files incomplete, re-sending what is missing", plan.len());
        }
        let queue = Arc::new(source::build_queue(&manifest, &plan, o.order, disk_keys.as_deref()));
        let scheduler = {
            let (queue, progress) = (queue.clone(), progress.clone());
            thread::spawn(move || source::run_auto_order(&queue, &progress.wire, &|m| eprintln!("{m}")))
        };
        let attached = Arc::new(AtomicU32::new(0));
        let tuner = source::reader_tuner(o.readers);
        let readers_start = tuner.active();
        let (feed, readers) = source::start_readers(ctx.clone(), queue.clone(), tuner.clone());
        let n = o.streams.min(queue.len()).max(1);
        let reader_tuning = {
            let (tuner, ctx, queue) = (tuner.clone(), ctx.clone(), queue.clone());
            thread::spawn(move || {
                let starved = util::Starved {
                    wait_us: &|| ctx.t_feed_wait.micros(),
                    consumers: &|| ctx.streams_active.load(Ordering::Relaxed),
                };
                util::run_tuner(&tuner, &ctx.read_items, Some(starved), &|| queue.done(), "readers", &|m| eprintln!("{m}"))
            })
        };
        let handles: Vec<_> = (0..n)
            .map(|_| {
                let (ctx, queue, feed, attached) = (ctx.clone(), queue.clone(), feed.clone(), attached.clone());
                let (host, sid, port) = (host.clone(), sid.clone(), o.port);
                thread::spawn(move || push_stream(&host, port, &sid, &bind, &ctx, &queue, &feed, &attached))
            })
            .collect();
        // Only the streams hold the feed now; if they all die, the readers' sends fail and they stop.
        drop(feed);
        for h in handles {
            let _ = h.join();
        }
        // All streams are gone: whatever is left belongs to the next round (or to an error).
        queue.abort();
        for h in readers {
            let _ = h.join();
        }
        let _ = reader_tuning.join();
        if round == 0 {
            readers_summary = tuner.summary("readers", readers_start);
        }
        final_readers = tuner.active();
        let _ = scheduler.join();
        decisions.extend(queue.decisions.lock().unwrap().drain(..));
        cw.put_u8(MSG_ROUND_DONE)?;
        cw.put_u32(attached.load(Ordering::Relaxed))?;
        cw.flush()?;
        cr.get_status()?;
        plan = get_plan(&mut cr, manifest.len())?;
    }
    phases.add("transfer", t.elapsed());
    transfer_done.store(true, Ordering::Relaxed);
    if let Some(h) = level_tuning {
        let _ = h.join();
    }
    stop.store(true, Ordering::Relaxed);
    let _ = reporter.join();

    let t = Instant::now();
    cw.put_u8(MSG_FINISH)?;
    cw.flush()?;
    cr.get_status()?;
    let received_files = cr.get_u64()?;
    let received_bytes = cr.get_u64()?;
    phases.add("received by server", t.elapsed());
    if opts.stage_mb > 0 {
        eprintln!(
            "received by the server: {received_files} files, {} after {} — committing to disk",
            fmt_bytes(received_bytes),
            fmt_secs(start.elapsed().as_secs_f64())
        );
    }
    if o.detach {
        println!("detached: the server keeps committing job {sid}");
        println!("check with: scopy status {host} {sid}");
        return Ok(MirrorOutcome::default());
    }
    let t = Instant::now();
    cr.get_status()?;
    let res = get_result(&mut cr)?;
    let outcome = if o.mirror { get_mirror_outcome(&mut cr)? } else { MirrorOutcome::default() };
    phases.add("committed (written, flushed, metadata)", t.elapsed());

    let local_errors = ctx.errors.lock().unwrap().clone();
    let remote_errors: Vec<String> = res
        .errors
        .iter()
        .map(|(i, m)| format!("{}: {m}", manifest.get(*i as usize).map(|e| e.path.as_str()).unwrap_or("?")))
        .collect();
    let report = Report {
        verb: "sent",
        elapsed: start.elapsed(),
        need_files,
        files_ok: res.files_ok,
        bytes_ok: res.bytes_ok,
        skipped,
        progress: &progress,
        phases: phases.list(),
        stats: [
            ctx.stats(),
            vec![
                ("source.readers_final".into(), final_readers as u64),
                ("source.level_final".into(), ctx.level_target.load(Ordering::Relaxed) as u64),
            ],
            res.stats,
        ]
        .concat(),
        policy: Some(&ctx.policy),
        order: [order_line(o.order, &decisions), why, format!("tuning: {readers_summary}; {}", level_summary(o.level, &ctx))].join("\n       "),
        errors: local_errors.into_iter().chain(remote_errors).collect(),
    };
    report.print();
    report.into_result()?;
    Ok(outcome)
}

/// Short report line for the compression level.
fn level_summary(requested: i32, ctx: &SourceCtx) -> String {
    let now = ctx.level_target.load(Ordering::Relaxed);
    if requested != LEVEL_AUTO {
        return format!("compression: fixed at {}", if now == 0 { "off".into() } else { now.to_string() });
    }
    let changes = ctx.level_decisions.lock().unwrap().len();
    format!("compression: auto {AUTO_START_LEVEL} -> {now} ({changes} changes)")
}

/// Subscribes to the receiver's live feedback (about once a second) until the job ends. Without it the
/// tuners just work from the sender's own measurements.
fn start_feedback(host: &str, port: u16, sid: &str, bind: &Binding, slot: Arc<Mutex<Option<Feedback>>>) {
    let (host, sid, bind) = (host.to_string(), sid.to_string(), *bind);
    thread::spawn(move || {
        let r = (|| -> Result<()> {
            let ((mut r, mut w), _) = connect(&host, port, KIND_FEEDBACK)?;
            w.put_str(&sid)?;
            w.put_str(&tls::join_token(&bind, &sid))?;
            w.flush()?;
            r.get_status()?;
            loop {
                let f = get_feedback(&mut r)?;
                *slot.lock().unwrap() = Some(f);
                if f.end == 1 {
                    return Ok(());
                }
            }
        })();
        if let Err(e) = r {
            if slot.lock().unwrap().is_none() {
                eprintln!("note: no live feedback from the receiver ({e:#}); tuning from local measurements only");
            }
        }
    });
}

/// One sending data connection; reconnects a few times if the connection drops.
fn push_stream(host: &str, port: u16, sid: &str, bind: &Binding, ctx: &SourceCtx, queue: &Queue, feed: &Receiver<Item>, attached: &AtomicU32) {
    for attempt in 0..4 {
        if attempt > 0 {
            if queue.done() && feed.is_empty() {
                return;
            }
            thread::sleep(Duration::from_secs(1));
        }
        let (_r, mut w) = match join_data(host, port, sid, bind) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("data connection failed: {e:#}");
                continue;
            }
        };
        attached.fetch_add(1, Ordering::Relaxed);
        let r = source::stream_work(&mut w, ctx, feed).and_then(|_| {
            put_end(&mut w)?;
            w.flush()?;
            Ok(())
        });
        match r {
            Ok(()) => return,
            Err(e) => eprintln!("data connection lost ({e:#}); reconnecting"),
        }
    }
}

pub fn pull(src: &str, dest: &Path, o: &ClientOptions) -> Result<()> {
    pull_with(src, dest, o, false).map(|_| ())
}

/// `pull`; with `unfinished_ok` (sync rounds) files that did not arrive complete — the server was still writing them
/// (a copy onto the share in progress) — are not an error: they are returned, and nothing was written for them.
pub fn pull_with(src: &str, dest: &Path, o: &ClientOptions, unfinished_ok: bool) -> Result<Pulled> {
    if o.sink {
        bail!("--sink is for `scopy send` only (it makes the receiving server discard the data)");
    }
    let start = Instant::now();
    let phases = Phases::default();
    let (unc_host, share, sub) = parse_unc(src)?;
    let host = o.host.clone().unwrap_or(unc_host.clone());

    let t = Instant::now();
    let ((mut cr, mut cw), bind) = connect(&host, o.port, KIND_PULL)?;
    auth::client(&mut cr, &mut cw, &unc_host, &bind)?;
    cw.put_str(&share)?;
    cw.put_str(&sub)?;
    cw.put_str(&token_for(o, src, false))?;
    cw.flush()?;
    cr.get_status()?;
    if cr.get_u8()? == ACCESS_TICKET {
        let ticket_name = cr.get_str()?;
        // Prove read access the normal way: read the server's ticket over SMB.
        let unc = PathBuf::from(src);
        let ticket_dir = if fs::metadata(&unc).map(|m| m.is_file()).unwrap_or(false) {
            unc.parent().map(Path::to_path_buf).unwrap_or_default()
        } else {
            unc.clone()
        };
        // "Not found" can be the SMB client's directory cache (a copy into the same folder is running): the server
        // has just written it, so look again for a moment before calling it a refusal. Access denied fails at once.
        let read_ticket = || fs::read_to_string(ticket_dir.join(&ticket_name));
        let mut found = read_ticket();
        for _ in 0..10 {
            match &found {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    std::thread::sleep(std::time::Duration::from_millis(300));
                    found = read_ticket();
                }
                _ => break,
            }
        }
        let found = found.with_context(|| format!("cannot read {} over SMB — no read access?", ticket_dir.display()))?;
        // The receiver wrote `nonce:binding`; a binding other than ours means another TLS session sits in between.
        let nonce = found.trim_end().split(':').next().unwrap_or_default().to_string();
        tls::check_ticket(&found, &nonce, &bind).context("refusing the pull")?;
        cw.put_str(&nonce)?;
        cw.flush()?;
        cr.get_status()?;
        eprintln!("access: read access checked over SMB");
    } else {
        // A read proof from the last minutes (proofs.rs): no SMB round trips this time.
        if in_session() { eprintln!("access: SSH session (the other side reads as your user)"); } else { eprintln!("access: read access proven earlier (token from an SMB check in the last {} min)", crate::proofs::LIFETIME.as_secs() / 60); }
        cr.get_status()?;
    }
    let sid = cr.get_str()?;
    keep_token(o, src, false, cr.get_str()?);
    phases.add("connect + access check", t.elapsed());

    let probe = dest::place_probe(dest, None);
    let t = Instant::now();
    let mut opts = o.options();
    if o.only.is_some() {
        opts.flags |= OPT_ONLY;
    }
    put_options(&mut cw, &opts)?;
    cw.put_str(&probe.name)?;
    cw.put_u8(probe.dest_exists as u8)?;
    if let Some(only) = &o.only {
        // A sync pull names what it fetches: the receiver looks at just that, not the whole folder.
        cw.put_u32(only.len() as u32)?;
        for p in only.iter() {
            cw.put_str(p)?;
        }
    }
    cw.flush()?;
    cr.get_status()?;
    drop(probe);
    let opts = get_options(&mut cr)?;
    let manifest = get_manifest(&mut cr, !o.numeric_ids)?;
    let remote_scan_us = cr.get_u64()?;
    phases.add("server scan + manifest", t.elapsed());
    let nfiles = manifest.iter().filter(|e| e.is_file()).count() as u64;
    let nlinks = manifest.iter().filter(|e| e.is_link()).count() as u64;
    let links = if nlinks > 0 { format!(", {nlinks} symbolic links") } else { String::new() };
    eprintln!(
        "source has {nfiles} files, {} folders{links}, {} (server scan {:.1}s)",
        manifest.len() as u64 - nfiles - nlinks,
        fmt_bytes(manifest.iter().map(|e| e.size).sum()),
        remote_scan_us as f64 / 1e6
    );

    let progress = Arc::new(Progress::default());
    let t = Instant::now();
    let sess = DestSession::new(dest.to_path_buf(), manifest.clone(), opts.clone(), dest::writer_tuner(o.writers), progress.clone())?;
    {
        let sess = sess.clone();
        thread::spawn(move || sess.run_writer_tuner(&|m| eprintln!("{m}")));
    }
    // Unix: the job stays inside the destination folder, as a receiver's job stays inside its share: nothing is
    // written through a symbolic link that leads out (one left by an earlier copy, or made while this one runs).
    #[cfg(unix)]
    {
        fs::create_dir_all(dest).with_context(|| format!("cannot create {}", dest.display()))?;
        sess.confine(dest)?;
    }
    sess.survey_dirs();
    sess.check_links()?;
    sess.create_dirs()?;
    // Job records, as on the receiver for pushes: files an interrupted earlier `get` to this folder was writing
    // may have the right size and time without their data (a power cut of this PC), so they are not trusted.
    let records = record::Records::new(record::client_dir());
    let (mut earlier, removed) = records.load();
    for r in removed {
        eprintln!("note: removed an unreadable job record ({r})");
    }
    let key = fs::canonicalize(dest).unwrap_or_else(|_| dest.to_path_buf());
    let suspect = records.suspects(&earlier, &key);
    if !suspect.is_empty() {
        eprintln!("{} files of an interrupted earlier copy to this folder are fetched again even if they look up to date", suspect.len());
    }
    sess.set_suspect(suspect);
    let mut plan = sess.initial_plan();
    if let Some(only) = &o.only {
        // Files the round did not decide on (e.g. new on the server since its listing) are left for the next round.
        plan.retain(|p| {
            let keep = only.contains(&manifest[p.idx as usize].path);
            if !keep {
                sess.leave_out(p.idx);
            }
            keep
        });
    }
    let full_plan = plan.clone();
    let recorded = !full_plan.is_empty() && records.write(&sid, &key, &sess.plan_paths(&full_plan)).is_ok();
    phases.add("create folders + plan", t.elapsed());
    let need_files = plan.len() as u64;
    let need_bytes = planned_bytes(&manifest, &plan);
    let skipped = sess.skipped.load(Ordering::Relaxed);
    eprintln!(
        "receiving {need_files} files ({}), {skipped} up to date, {} streams, zstd {}",
        fmt_bytes(need_bytes),
        o.streams,
        if opts.level > 0 { opts.level.to_string() } else { "off".into() }
    );
    progress.total_files.store(need_files, Ordering::Relaxed);
    progress.total_bytes.store(need_bytes, Ordering::Relaxed);
    let stop = Arc::new(AtomicBool::new(false));
    let reporter = spawn_reporter(progress.clone(), Duration::from_secs(o.progress_secs.max(1)), stop.clone());

    let t = Instant::now();
    let mut round_result = Ok(());
    for round in 0..=o.retries {
        if plan.is_empty() {
            break;
        }
        if round > 0 {
            eprintln!("retry round {round}: {} files incomplete, asking for what is missing", plan.len());
        }
        cw.put_u8(MSG_PLAN)?;
        put_plan(&mut cw, &plan)?;
        cw.flush()?;
        cr.get_status()?;
        let dict = cr.get_blob()?;
        if !dict.is_empty() {
            eprintln!("server trained a {} compression dictionary", fmt_bytes(dict.len() as u64));
            sess.set_dict(dict);
        }
        let handles: Vec<_> = (0..o.streams.max(1))
            .map(|_| {
                let (sess, host, sid, port) = (sess.clone(), host.clone(), sid.clone(), o.port);
                thread::spawn(move || {
                    let r = join_data(&host, port, &sid, &bind).and_then(|(mut r, _w)| dest::recv_frames(&mut r, &sess));
                    if let Err(e) = r {
                        eprintln!("data connection lost: {e:#}");
                    }
                })
            })
            .collect();
        for h in handles {
            let _ = h.join();
        }
        round_result = sess.wait_round(0);
        if round_result.is_err() {
            break;
        }
        plan = sess.incomplete(&plan);
    }
    phases.add("transfer", t.elapsed());
    stop.store(true, Ordering::Relaxed);
    let _ = reporter.join();

    let t = Instant::now();
    cw.put_u8(MSG_FINISH)?;
    cw.flush()?;
    cr.get_status()?;
    let remote_stats = get_stats(&mut cr)?;
    let n = cr.get_u32()?;
    let mut errors = Vec::new();
    for _ in 0..n {
        errors.push(cr.get_str()?);
    }
    let res = sess.finish();
    phases.add("finish (folder metadata)", t.elapsed());
    round_result?;
    if recorded {
        // What arrived without an error is on disk now (finish flushed it): settle this job's and older records.
        let failed: std::collections::HashSet<&str> = res.errors.iter().map(|(i, _)| manifest[*i as usize].path.as_str()).collect();
        let covered = sess.plan_paths(&full_plan).into_iter().filter(|p| !failed.contains(p.as_str())).collect();
        records.settle(&mut earlier, &key, &covered);
        if failed.is_empty() {
            records.drop_record(&sid);
        } else {
            let _ = records.replace_list(&sid, &failed.into_iter().collect::<Vec<_>>());
        }
    }

    let mut unfinished: Vec<String> = if unfinished_ok {
        res.errors.iter().filter(|(_, m)| m.starts_with("incomplete")).map(|(i, _)| manifest[*i as usize].path.clone()).collect()
    } else {
        Vec::new()
    };
    if unfinished_ok {
        // Files the server was still changing, or that were deleted or moved there meanwhile (a copy onto the share
        // in progress, a folder renamed while we fetched it): not a failed round, the next round decides on them.
        let later = |e: &String| e.strip_suffix(crate::source::GONE).or_else(|| e.strip_suffix(crate::source::CHANGED)).map(str::to_string);
        let (moved, other): (Vec<String>, Vec<String>) = errors.drain(..).partition(|e| later(e).is_some());
        let known: std::collections::HashSet<String> = unfinished.iter().cloned().collect();
        unfinished.extend(moved.iter().filter_map(later).filter(|p| !known.contains(p)));
        errors = other;
    }
    errors.extend(res.errors.iter().filter(|(_, m)| !(unfinished_ok && m.starts_with("incomplete"))).map(|(i, m)| format!("{}: {m}", manifest[*i as usize].path)));
    let report = Report {
        verb: "received",
        elapsed: start.elapsed(),
        need_files: need_files - unfinished.len() as u64,
        files_ok: res.files_ok,
        bytes_ok: res.bytes_ok,
        skipped,
        progress: &progress,
        phases: phases.list(),
        stats: [remote_stats, res.stats].concat(),
        policy: None,
        order: format!("{} (decided on the server; see its log)", order_name(o.order)),
        errors,
    };
    report.print();
    report.into_result()?;
    // The version each file has here now: the server's as this job read it, which can be newer than the listing a
    // sync round decided on (a file still being written there).
    let versions = manifest.iter().filter(|e| e.is_file()).map(|e| (e.path.clone(), (e.size, e.mtime))).collect();
    Ok(Pulled { unfinished, versions })
}

/// What a pull did, for a sync round.
pub struct Pulled {
    /// Files that did not arrive complete (nothing written for them).
    pub unfinished: Vec<String>,
    /// Size and time (ns) of each file as the server had it when this job read it.
    pub versions: std::collections::HashMap<String, (u64, i64)>,
}

/// A two-way sync listing: the whole folder, or (`removed` = Some) only what changed since the cursor sent.
pub struct Listing {
    /// Delta only: paths gone or replaced, each with everything below it (applied before `entries`).
    pub removed: Option<Vec<String>>,
    pub entries: Vec<Entry>,
    /// The receiver's file id of each entry (0 = unknown).
    pub ids: Vec<u64>,
    /// Where the next listing can continue from (epoch 0: no delta possible).
    pub cursor: (u64, u64),
    /// Files an interrupted job on the receiver may have left without their data (always the whole set, also with
    /// a delta): never taken as synced.
    pub suspect: Vec<String>,
}

/// Two-way sync: the user's folder as the receiver has it — or only what changed since `cursor` ((0, 0) = all).
pub fn list(remote: &str, port: u16, pc: &str, cursor: (u64, u64)) -> Result<Listing> {
    let (unc_host, share, sub) = parse_unc(remote)?;
    let ((mut r, mut w), bind) = connect(&unc_host, port, KIND_LIST)?;
    auth::client(&mut r, &mut w, &unc_host, &bind)?;
    w.put_str(&share)?;
    w.put_str(&sub)?;
    w.put_str(pc)?;
    w.put_u64(cursor.0)?;
    w.put_u64(cursor.1)?;
    w.flush()?;
    r.get_status()?;
    let removed = match r.get_u8()? {
        LIST_FULL => None,
        LIST_DELTA => {
            let n = r.get_u32()?;
            Some((0..n).map(|_| r.get_str()).collect::<Result<Vec<String>>>()?)
        }
        m => bail!("protocol error: listing mode {m}"),
    };
    let entries = get_manifest(&mut r, false)?;
    let n = r.get_u32()? as usize;
    if n != entries.len() {
        bail!("the receiver sent {n} file ids for {} entries", entries.len());
    }
    let ids = (0..n).map(|_| r.get_u64()).collect::<std::io::Result<Vec<u64>>>()?;
    let cursor = (r.get_u64()?, r.get_u64()?);
    let n = r.get_u32()?;
    let suspect = (0..n).map(|_| r.get_str()).collect::<Result<Vec<String>>>()?;
    Ok(Listing { removed, entries, ids, cursor, suspect })
}

/// Two-way sync: tells the receiver which files are open on this PC (it locks them for everyone else); returns a
/// LOCK_* state per claim and the locks other PCs hold in the folder.
pub fn locks(remote: &str, port: u16, pc: &str, claims: &[LockClaim]) -> Result<(Vec<u8>, Vec<LockInfo>)> {
    let (unc_host, share, sub) = parse_unc(remote)?;
    let ((mut r, mut w), bind) = connect(&unc_host, port, KIND_LOCKS)?;
    auth::client(&mut r, &mut w, &unc_host, &bind)?;
    w.put_str(&share)?;
    w.put_str(&sub)?;
    w.put_str(pc)?;
    put_claims(&mut w, claims)?;
    w.flush()?;
    r.get_status()?;
    let n = r.get_u32()?;
    let states = (0..n).map(|_| r.get_u8()).collect::<std::io::Result<Vec<u8>>>()?;
    Ok((states, get_lock_infos(&mut r)?))
}

/// Two-way sync: the receiver's change feed for this PC's sync folders (all on one receiver). Calls `up` once the
/// receiver watches them and `changed(i, at)` each time folder `i` changed there (not by this PC; `at` = its change
/// log position, see KIND_WATCH); returns when the
/// connection ends (error) or `changed` returns false.
pub fn watch(remotes: &[String], port: u16, pc: &str, up: impl FnOnce(), mut changed: impl FnMut(usize, (u64, u64)) -> bool) -> Result<()> {
    let mut host = String::new();
    let mut folders = Vec::new();
    for r in remotes {
        let (h, share, sub) = parse_unc(r)?;
        if !host.is_empty() && !h.eq_ignore_ascii_case(&host) {
            bail!("the sync folders are on different servers ({host}, {h})");
        }
        host = h;
        folders.push((share, sub));
    }
    // Three missed heartbeats: the receiver or the network is gone.
    let ((mut r, mut w), bind) = connect_with(&host, port, KIND_WATCH, Some(crate::feed::HEARTBEAT * 3))?;
    auth::client(&mut r, &mut w, &host, &bind)?;
    w.put_str(pc)?;
    w.put_u32(folders.len() as u32)?;
    for (share, sub) in &folders {
        w.put_str(share)?;
        w.put_str(sub)?;
    }
    w.flush()?;
    r.get_status()?;
    up();
    loop {
        let i = r.get_u32()?;
        let at = (r.get_u64()?, r.get_u64()?);
        if i != crate::feed::ALIVE && (i as usize) < remotes.len() && !changed(i as usize, at) {
            return Ok(());
        }
    }
}

/// `scopy status <host> <job>`: asks a receiver how a (detached) push job is doing.
pub fn status(host: &str, port: u16, job: &str) -> Result<()> {
    let ((mut r, mut w), _) = connect(host, port, KIND_STATUS)?;
    w.put_str(job)?;
    w.flush()?;
    r.get_status()?;
    match r.get_u8()? {
        JOB_COMMITTING => println!("job {job}: still committing to disk"),
        JOB_INTERRUPTED => bail!(
            "job {job} was interrupted: the receiver stopped before everything was committed - run the copy again \
             (it only re-sends what is missing)"
        ),
        JOB_DONE => {
            let res = get_result(&mut r)?;
            println!("job {job}: committed — {} files, {} written, {} errors", res.files_ok, fmt_bytes(res.bytes_ok), res.errors.len());
            for (i, m) in res.errors.iter().take(20) {
                eprintln!("  error: entry {i}: {m}");
            }
            if !res.errors.is_empty() {
                bail!("{} errors", res.errors.len());
            }
        }
        _ => bail!("job {job} unknown to {host} (finished long ago, or the receiver restarted)"),
    }
    Ok(())
}

struct Report<'a> {
    verb: &'static str,
    elapsed: Duration,
    need_files: u64,
    files_ok: u64,
    bytes_ok: u64,
    skipped: u64,
    progress: &'a Progress,
    phases: Vec<(String, Duration)>,
    stats: Stats,
    policy: Option<&'a Policy>,
    order: String,
    errors: Vec<String>,
}

fn order_line(order: u8, decisions: &[String]) -> String {
    match decisions.last() {
        Some(last) => format!("{} → {}", order_name(order), last.trim_start_matches("auto order: ")),
        None if order == ORDER_AUTO => "auto → small files first (no probe needed)".into(),
        None => order_name(order).into(),
    }
}

impl Report<'_> {
    fn print(&self) {
        let secs = self.elapsed.as_secs_f64().max(1e-9);
        let raw = self.progress.raw.load(Ordering::Relaxed);
        let wire = self.progress.wire.load(Ordering::Relaxed);
        let transfer = self.phases.iter().find(|(n, _)| n == "transfer").map(|p| p.1.as_secs_f64()).unwrap_or(secs).max(1e-9);
        println!(
            "done: {}/{} files {}, {} in {} — {:.0} files/s, {}/s ({} skipped as up to date)",
            self.files_ok,
            self.need_files,
            self.verb,
            fmt_bytes(self.bytes_ok),
            fmt_secs(secs),
            self.files_ok as f64 / secs,
            fmt_bytes((self.bytes_ok as f64 / secs) as u64),
            self.skipped
        );
        if wire > 0 {
            println!(
                "network: {} on the wire for {} of data ({:.2}x), {}/s on the wire during transfer",
                fmt_bytes(wire),
                fmt_bytes(raw),
                raw as f64 / wire as f64,
                fmt_bytes((wire as f64 / transfer) as u64)
            );
        }
        println!("order: {}", self.order);
        println!("phases:");
        for (name, d) in &self.phases {
            println!("  {name:<42} {:>9.2}s", d.as_secs_f64());
        }
        // Where the time went inside the transfer (summed over all threads, so it can exceed wall time).
        println!("thread time (summed over threads):");
        for (k, v) in &self.stats {
            if let Some(name) = k.strip_suffix("_us") {
                if *v > 0 {
                    println!("  {name:<42} {:>9.2}s", *v as f64 / 1e6);
                }
            }
        }
        let stat = |k: &str| self.stats.iter().find(|(n, _)| n == k).map(|s| s.1).unwrap_or(0);
        if stat("dest.resumed_files") > 0 {
            println!("resumed {} big files from their journal (only missing chunks sent)", stat("dest.resumed_files"));
        }
        match stat("dest.flush_mode") {
            1 => println!("flushed to disk: whole volume in {:.2}s", stat("dest.flush_us") as f64 / 1e6),
            2 => println!("flushed to disk: file by file in {:.2}s (no rights for a volume flush)", stat("dest.flush_us") as f64 / 1e6),
            3 => println!(
                "flushed to disk: each file while writing ({:.2}s summed over the writers; no rights for a volume flush)",
                stat("dest.flush_us") as f64 / 1e6
            ),
            _ => {}
        }
        if stat("dest.sink") > 0 {
            println!("SINK (benchmark): received, decompressed and checked; folders created; NO file data written");
        }
        if stat("dest.stage_mb") > 0 {
            println!(
                "receiver RAM stage: {} MB allowed, peak {} MB used",
                stat("dest.stage_mb"),
                stat("dest.stage_peak_mb")
            );
        }
        if let Some(policy) = self.policy {
            let summary = policy.summary();
            if !summary.is_empty() {
                println!("compression by file type:");
                for (ext, r, w) in summary.iter().take(8) {
                    let ext = if ext.is_empty() { "(none)" } else { ext };
                    println!("  {ext:<10} {:>10} -> {:>10}  ({:.2}x)", fmt_bytes(*r), fmt_bytes(*w), *r as f64 / (*w).max(1) as f64);
                }
            }
        }
        for e in self.errors.iter().take(50) {
            eprintln!("  error: {e}");
        }
        if self.errors.len() > 50 {
            eprintln!("  ... and {} more errors", self.errors.len() - 50);
        }
    }

    fn into_result(self) -> Result<()> {
        if !self.errors.is_empty() || self.files_ok != self.need_files {
            bail!(
                "{} errors, {} of {} files not written",
                self.errors.len(),
                self.need_files - self.files_ok.min(self.need_files),
                self.need_files
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unc_parsing() {
        let (h, s, p) = parse_unc(r"\\nas\photos\2026\summer").unwrap();
        assert_eq!((h.as_str(), s.as_str(), p.as_str()), ("nas", "photos", "2026/summer"));
        let (h, s, p) = parse_unc("//10.0.0.5/data/").unwrap();
        assert_eq!((h.as_str(), s.as_str(), p.as_str()), ("10.0.0.5", "data", ""));
        assert!(parse_unc(r"C:\temp").is_err());
        assert!(parse_unc(r"\\nas").is_err());
    }
}
