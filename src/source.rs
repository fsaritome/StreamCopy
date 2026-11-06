//! Source side of a job: scanning the local tree, ordering the work, and streaming frames.

use crate::compress::{ext_of, known_incompressible, FrameEncoder, Policy};
use crate::meta;
use crate::proto::*;
use crate::util::{Progress, Timer, Tuner};
use anyhow::{bail, Context, Result};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use crossbeam_channel::{bounded, Receiver, Sender};
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// Work items handed out to data connections in batches, so each connection sees runs of similar
/// files (better compression) and the shared cursor isn't contended.
const BATCH: usize = 32;

pub struct LocalEntry {
    pub e: Entry,
    pub local: PathBuf,
    /// On-disk order hint (NTFS file ID / inode); 0 = unknown.
    pub disk_key: u64,
}

pub struct Scan {
    pub root: PathBuf,
    pub is_file: bool,
    pub entries: Vec<LocalEntry>,
    pub skipped_special: usize,
}

impl Scan {
    pub fn manifest(&self) -> Vec<Entry> {
        self.entries.iter().map(|l| l.e.clone()).collect()
    }
}

/// What a single path below a folder is, seen the way the whole-folder scan sees it.
pub enum Seen {
    /// Not there — or only through a link on the way, or (with exact case) under another spelling.
    Missing,
    Here(fs::Metadata),
    /// Could not be read (access, I/O): the caller can't tell.
    Unreadable,
}

/// Looks at single paths below `base` by the rules of `scan`, which never enters a link: no folder on the way may be a
/// junction or symbolic link (the last component may be one; its metadata says so). With `exact_case` (deltas and
/// re-checks, where the path comes from a change event) every component must also have exactly this spelling on
/// disk — on a case-insensitive volume "Docs" also opens "docs", and a delta must not list both. Folder listings
/// and link checks are cached for the life of the lookup.
pub struct Look {
    base: PathBuf,
    exact_case: bool,
    dirs: std::collections::HashMap<PathBuf, Option<bool>>,
    names: std::collections::HashMap<PathBuf, Option<std::collections::HashSet<std::ffi::OsString>>>,
}

impl Look {
    pub fn new(base: &Path, exact_case: bool) -> Look {
        Look { base: base.to_path_buf(), exact_case: exact_case && cfg!(windows), dirs: Default::default(), names: Default::default() }
    }

    pub fn at(&mut self, rel: &str) -> Seen {
        let Ok(sub) = crate::util::sanitize_rel(rel, false) else { return Seen::Missing };
        let comps: Vec<std::ffi::OsString> = sub.components().map(|c| c.as_os_str().to_owned()).collect();
        let mut p = self.base.clone();
        for (i, c) in comps.iter().enumerate() {
            if self.exact_case {
                let names = self.names.entry(p.clone()).or_insert_with(|| fs::read_dir(&p).ok().map(|rd| rd.flatten().map(|e| e.file_name()).collect()));
                match names {
                    None => return Seen::Unreadable,
                    Some(n) if !n.contains(c) => return Seen::Missing,
                    Some(_) => {}
                }
            }
            p.push(c);
            if i + 1 < comps.len() {
                // A folder on the way: a real folder (Some(true)), not one / a link (Some(false)), unreadable (None).
                let ok = *self.dirs.entry(p.clone()).or_insert_with(|| match fs::symlink_metadata(&p) {
                    Ok(m) => Some(m.is_dir() && !m.file_type().is_symlink()),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => Some(false),
                    Err(_) => None,
                });
                match ok {
                    Some(true) => {}
                    Some(false) => return Seen::Missing,
                    None => return Seen::Unreadable,
                }
            }
        }
        match fs::symlink_metadata(&p) {
            Ok(m) => Seen::Here(m),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Seen::Missing,
            Err(_) => Seen::Unreadable,
        }
    }
}

/// Like `scan` of the folder `src`, but only the paths `rels` (relative, '/'-separated) and their parent folders,
/// each looked at on its own: what a sync pull fetches, without walking the whole folder. Missing paths, links and
/// special files are left out; a named folder is listed without its contents.
pub fn scan_only(src: &Path, rels: &[String]) -> Result<Scan> {
    let mut seen = std::collections::HashSet::new();
    let mut entries = Vec::new();
    // The names come from the other side: never through a link, like the whole-folder scan.
    let mut look = Look::new(src, false);
    let mut add = |rel: &str, entries: &mut Vec<LocalEntry>| -> Result<()> {
        if !seen.insert(rel.to_string()) {
            return Ok(());
        }
        let local = src.join(crate::util::sanitize_rel(rel, false)?);
        let Seen::Here(md) = look.at(rel) else { return Ok(()) };
        if md.file_type().is_symlink() || !(md.is_dir() || md.is_file()) {
            return Ok(());
        }
        let kind = if md.is_dir() { ENTRY_DIR } else { ENTRY_FILE };
        entries.push(LocalEntry { e: meta::entry(kind, rel.to_string(), &md, String::new()), local, disk_key: 0 });
        Ok(())
    };
    for rel in rels {
        if rel.split('/').any(|c| c.contains(".scopy-")) {
            continue;
        }
        let parts: Vec<&str> = rel.split('/').collect();
        for i in 1..parts.len() {
            add(&parts[..i].join("/"), &mut entries)?;
        }
        add(rel, &mut entries)?;
    }
    if entries.len() >= END_OF_STREAM as usize {
        bail!("too many files for one job");
    }
    entries.sort_unstable_by(|a, b| a.e.path.split('/').cmp(b.e.path.split('/')));
    Ok(Scan { root: src.to_path_buf(), is_file: false, entries, skipped_special: 0 })
}

pub fn scan(src: &Path) -> Result<Scan> {
    let md = fs::metadata(src).with_context(|| format!("cannot read {}", src.display()))?;
    if md.is_file() {
        let name = src.file_name().context("bad source path")?.to_string_lossy().into_owned();
        let e = meta::entry(ENTRY_FILE, name, &md, String::new());
        return Ok(Scan {
            root: src.to_path_buf(),
            is_file: true,
            entries: vec![LocalEntry { e, local: src.to_path_buf(), disk_key: 0 }],
            skipped_special: 0,
        });
    }
    let (mut entries, skipped_special) = scan_tree(src, SCAN_THREADS)?;
    if entries.len() >= END_OF_STREAM as usize {
        bail!("too many files for one job");
    }
    // Workers finish folders in any order; sort by path components so the result is deterministic and every
    // folder comes before its contents (as with a sequential walk).
    entries.sort_unstable_by(|a, b| a.e.path.split('/').cmp(b.e.path.split('/')));
    Ok(Scan { root: src.to_path_buf(), is_file: false, entries, skipped_special })
}

/// Folders listed in parallel. Measured on TEST-A (85,513 files, 37,897 folders): a sequential walk took 3.0 s,
/// a third of a warm 20 s copy; each folder is one directory listing, so they overlap well on SMB and SAN storage.
const SCAN_THREADS: usize = 16;

/// What one worker found: entries, skipped specials, warnings, and the first hard error.
#[derive(Default)]
struct Found {
    entries: Vec<LocalEntry>,
    skipped: usize,
    error: Option<anyhow::Error>,
}

/// Walks `src` with `threads` workers sharing a queue of folders. Special files are skipped, and symbolic links on
/// Windows (on Unix they go along as links),
/// unreadable folders give a warning (like the sequential walk did), a non-Unicode path is an error.
fn scan_tree(src: &Path, threads: usize) -> Result<(Vec<LocalEntry>, usize)> {
    let (tx, rx) = crossbeam_channel::unbounded::<PathBuf>();
    // Folders queued or being listed; the walk is over when it drops to 0.
    let pending = AtomicUsize::new(1);
    tx.send(src.to_path_buf()).unwrap();
    // The workers list folders as whoever the calling thread acts as (on a receiver: the signed-in user).
    let who = &crate::auth::capture();
    let found: Vec<Found> = std::thread::scope(|s| {
        let workers: Vec<_> = (0..threads.max(1))
            .map(|_| {
                let (tx, rx, pending) = (tx.clone(), rx.clone(), &pending);
                s.spawn(move || {
                    let _act = who.enter();
                    let mut f = Found::default();
                    loop {
                        match rx.recv_timeout(Duration::from_millis(5)) {
                            Ok(dir) => {
                                if f.error.is_none() {
                                    if let Err(e) = scan_dir(src, &dir, &mut f, &|sub| {
                                        pending.fetch_add(1, Ordering::SeqCst);
                                        tx.send(sub).unwrap();
                                    }) {
                                        f.error = Some(e);
                                    }
                                }
                                pending.fetch_sub(1, Ordering::SeqCst);
                            }
                            Err(_) if pending.load(Ordering::SeqCst) == 0 => return f,
                            Err(_) => {}
                        }
                    }
                })
            })
            .collect();
        workers.into_iter().map(|w| w.join().unwrap()).collect()
    });
    let mut entries = Vec::with_capacity(found.iter().map(|f| f.entries.len()).sum());
    let mut skipped = 0;
    for f in found {
        if let Some(e) = f.error {
            return Err(e);
        }
        entries.extend(f.entries);
        skipped += f.skipped;
    }
    Ok((entries, skipped))
}

/// Lists one folder: records its files and subfolders, and queues the subfolders with `queue`.
fn scan_dir(src: &Path, dir: &Path, f: &mut Found, queue: &dyn Fn(PathBuf)) -> Result<()> {
    let list = match fs::read_dir(dir) {
        Ok(l) => l,
        // The folder that was asked for must be readable; a subfolder that isn't is left out with a warning.
        Err(e) if dir == src => bail!("cannot read {}: {e}", dir.display()),
        Err(e) => {
            eprintln!("warning: {}: {e}", dir.display());
            return Ok(());
        }
    };
    #[cfg(windows)]
    let mut ids: Option<std::collections::HashMap<std::ffi::OsString, u64>> = None;
    for ent in list {
        let ent = match ent {
            Ok(e) => e,
            Err(e) => {
                eprintln!("warning: {}: {e}", dir.display());
                continue;
            }
        };
        let path = ent.path();
        let ft = match ent.file_type() {
            Ok(t) => t,
            Err(e) => {
                eprintln!("warning: {}: {e}", path.display());
                continue;
            }
        };
        // Unix: a symbolic link goes along as a link (as with rsync -a), never followed. Windows: links and junctions
        // are left out (creating them needs rights a normal user doesn't have).
        let link = cfg!(unix) && ft.is_symlink();
        if !ft.is_dir() && !ft.is_file() && !link {
            f.skipped += 1;
            continue;
        }
        let mut rel = String::new();
        for c in path.strip_prefix(src)?.components() {
            let Some(s) = c.as_os_str().to_str() else {
                bail!("path is not valid Unicode: {}", path.display());
            };
            if !rel.is_empty() {
                rel.push('/');
            }
            rel.push_str(s);
        }
        if link {
            let target = match fs::read_link(&path) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("warning: {}: {e}", path.display());
                    continue;
                }
            };
            let Some(target) = target.to_str().filter(|t| !t.is_empty()).map(str::to_string) else {
                eprintln!("warning: {}: link target is not valid Unicode, skipped", path.display());
                f.skipped += 1;
                continue;
            };
            // DirEntry::metadata does not follow the link: these are the link's own owner and time.
            let md = ent.metadata()?;
            f.entries.push(LocalEntry { e: meta::entry(ENTRY_LINK, rel, &md, target), local: path, disk_key: 0 });
            continue;
        }
        // On Windows a listing's metadata comes from the parent's directory index, which can hold stale
        // timestamps for folders; ask the folder itself (cheap: folders are few).
        let md = if ft.is_dir() { fs::metadata(&path)? } else { ent.metadata()? };
        let kind = if ft.is_dir() { ENTRY_DIR } else { ENTRY_FILE };
        let disk_key = if ft.is_file() {
            #[cfg(windows)]
            {
                ids.get_or_insert_with(|| meta::dir_file_ids(dir)).get(&ent.file_name()).copied().unwrap_or(0)
            }
            #[cfg(unix)]
            {
                meta::file_id(&md)
            }
        } else {
            0
        };
        if ft.is_dir() {
            queue(path.clone());
        }
        f.entries.push(LocalEntry {
            e: meta::entry(kind, rel, &md, String::new()),
            local: path,
            disk_key,
        });
    }
    Ok(())
}

/// The destination side wrote `probe_name` into the deepest destination folder that already exists.
/// If it shows up in the source tree, the trees overlap and copying could overwrite files that are
/// still being read. Returns the source folder where it appeared.
pub fn overlap(scan: &Scan, probe_name: &str, dest_exists: bool) -> Option<PathBuf> {
    let root = fs::canonicalize(&scan.root).unwrap_or_else(|_| scan.root.clone());
    if scan.is_file {
        // A single file only collides with itself: destination folder == the file's own folder.
        let parent = root.parent()?.to_path_buf();
        return (dest_exists && parent.join(probe_name).exists()).then_some(parent);
    }
    let subdirs = scan.entries.iter().filter(|l| !l.e.is_file()).map(|l| l.local.clone());
    // Destination inside the source: the probe sits in the source root or one of its folders.
    // Source inside an existing destination: the probe sits in a folder above the source.
    let above = root.ancestors().skip(1).map(Path::to_path_buf).filter(|_| dest_exists);
    std::iter::once(root.clone()).chain(subdirs).chain(above).find(|d| d.join(probe_name).exists())
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Work {
    Whole(u32),
    Part { idx: u32, offset: u64, len: u32 },
}

/// Big-file chunks handed out per grab (2 MB each), so the byte share can be steered finely.
const BIG_BATCH: usize = 4;

/// The planned work as two lanes: small files and big-file chunks. Data connections take batches
/// from either lane; `share` (per mille of bytes) says how much should come from the big lane.
/// 0 = small files first (big chunks only once the small lane is empty).
pub struct Queue {
    small: Vec<Work>,
    small_sizes: Vec<u64>,
    big: Vec<Work>,
    small_cur: AtomicUsize,
    big_cur: AtomicUsize,
    small_sent: AtomicU64,
    big_sent: AtomicU64,
    share: AtomicU32,
    /// The big lane's natural share of the bytes, used when mixing.
    mixed_share: u32,
    pub order: u8,
    pub decisions: Mutex<Vec<String>>,
    /// Set when every stream of the round has ended: what is left goes to the next round, so readers and helper
    /// threads stop instead of waiting for work that nobody will take.
    aborted: AtomicBool,
}

/// Orders the planned work. Small files: compressible types first, then already-compressed ones,
/// each grouped by type and folder (similar content back to back compresses better). Big files:
/// split into chunks, compressible files before already-compressed ones.
/// With `disk_keys` (per-entry on-disk order hints), files are read in disk order instead of grouped by
/// type: on spinning disks with cold data that turns random reads into sweeps.
pub fn build_queue(entries: &[Entry], plan: &[PlanItem], order: u8, disk_keys: Option<&[u64]>) -> Queue {
    let mut small: Vec<u32> = Vec::new();
    let (mut big_text, mut big_packed): (Vec<Work>, Vec<Work>) = (Vec::new(), Vec::new());
    for p in plan {
        let e = &entries[p.idx as usize];
        if !e.is_file() {
            continue;
        }
        if !e.is_chunked() {
            small.push(p.idx);
            continue;
        }
        let lane = if known_incompressible(&ext_of(&e.path)) { &mut big_packed } else { &mut big_text };
        for c in 0..chunk_count(e.size) {
            if p.chunks.as_deref().is_none_or(|bits| bit(bits, c)) {
                let offset = c as u64 * CHUNK;
                lane.push(Work::Part { idx: p.idx, offset, len: CHUNK.min(e.size - offset) as u32 });
            }
        }
    }
    let big: Vec<Work> = match disk_keys {
        Some(keys) => {
            small.sort_by_key(|&i| keys[i as usize]);
            let mut all: Vec<Work> = big_text.into_iter().chain(big_packed).collect();
            all.sort_by_key(|w| match *w {
                Work::Part { idx, offset, .. } => (keys[idx as usize], offset),
                Work::Whole(idx) => (keys[idx as usize], 0),
            });
            all
        }
        None => {
            small.sort_by_cached_key(|&i| {
                let path = &entries[i as usize].path;
                let ext = ext_of(path);
                (known_incompressible(&ext), ext, path.clone())
            });
            big_text.into_iter().chain(big_packed).collect()
        }
    };
    let small_sizes: Vec<u64> = small.iter().map(|&i| entries[i as usize].size).collect();

    let small_bytes: u64 = small_sizes.iter().sum();
    let big_bytes: u64 = big.iter().map(Work::len).sum();
    let mixed_share = (big_bytes as u128 * 1000 / (small_bytes + big_bytes).max(1) as u128) as u32;
    let share = if order == ORDER_MIXED { mixed_share } else { 0 };
    Queue {
        small: small.into_iter().map(Work::Whole).collect(),
        small_sizes,
        big,
        small_cur: AtomicUsize::new(0),
        big_cur: AtomicUsize::new(0),
        small_sent: AtomicU64::new(0),
        big_sent: AtomicU64::new(0),
        share: AtomicU32::new(share),
        mixed_share,
        order,
        decisions: Mutex::new(Vec::new()),
        aborted: AtomicBool::new(false),
    }
}

impl Work {
    fn len(&self) -> u64 {
        match self {
            Work::Part { len, .. } => *len as u64,
            Work::Whole(_) => 0,
        }
    }
}

impl Queue {
    pub fn len(&self) -> usize {
        self.small.len() + self.big.len()
    }

    fn small_done(&self) -> bool {
        self.small_cur.load(Ordering::Relaxed) >= self.small.len()
    }

    fn big_done(&self) -> bool {
        self.big_cur.load(Ordering::Relaxed) >= self.big.len()
    }

    pub fn done(&self) -> bool {
        self.aborted.load(Ordering::Relaxed) || (self.small_done() && self.big_done())
    }

    /// Ends the round's queue early. Measured on a hard reset of the receiver: all streams died, but readers the
    /// tuner had parked waited for the queue to drain, and the client hung with 109 threads.
    pub fn abort(&self) {
        self.aborted.store(true, Ordering::Relaxed);
    }

    /// Hands out the next batch, from whichever lane is behind its byte share.
    pub fn next_batch(&self) -> Option<&[Work]> {
        if self.aborted.load(Ordering::Relaxed) {
            return None;
        }
        loop {
            let (small_left, big_left) = (!self.small_done(), !self.big_done());
            if !small_left && !big_left {
                return None;
            }
            let share = self.share.load(Ordering::Relaxed) as u128;
            let s = self.small_sent.load(Ordering::Relaxed) as u128;
            let b = self.big_sent.load(Ordering::Relaxed) as u128;
            let want_big = big_left && (!small_left || b * 1000 < share * (s + b).max(1));
            if want_big {
                let start = self.big_cur.fetch_add(BIG_BATCH, Ordering::Relaxed);
                if start < self.big.len() {
                    let batch = &self.big[start..(start + BIG_BATCH).min(self.big.len())];
                    self.big_sent.fetch_add(batch.iter().map(Work::len).sum(), Ordering::Relaxed);
                    return Some(batch);
                }
            } else {
                let start = self.small_cur.fetch_add(BATCH, Ordering::Relaxed);
                if start < self.small.len() {
                    let end = (start + BATCH).min(self.small.len());
                    self.small_sent.fetch_add(self.small_sizes[start..end].iter().sum(), Ordering::Relaxed);
                    return Some(&self.small[start..end]);
                }
            }
            // That lane ran dry under us; try again with the other one.
        }
    }
}

/// Median time to open a file and read its first 4 KB, over a small sample of the planned small files.
/// Cached or SSD-backed data answers in well under a millisecond; cold data on spinning disks takes several.
pub fn probe_read_latency(entries: &[LocalEntry], plan: &[PlanItem]) -> Option<Duration> {
    const SAMPLES: usize = 24;
    let cands: Vec<&LocalEntry> = plan
        .iter()
        .map(|p| &entries[p.idx as usize])
        .filter(|l| l.e.is_file() && l.e.size > 0 && !l.e.is_chunked())
        .collect();
    if cands.len() < SAMPLES {
        return None;
    }
    let step = cands.len() / SAMPLES;
    let mut times: Vec<Duration> = cands
        .iter()
        .step_by(step)
        .take(SAMPLES)
        .filter_map(|l| {
            let t = Instant::now();
            let mut buf = [0u8; 4096];
            File::open(&l.local).ok()?.read(&mut buf).ok()?;
            Some(t.elapsed())
        })
        .collect();
    times.sort();
    times.get(times.len() / 2).copied()
}

/// Decides whether to read in disk order. `mode`: DISK_ORDER_AUTO / _ON / _OFF. Returns the per-entry keys
/// when disk order is used, plus a one-line explanation.
pub fn decide_disk_order(mode: u8, entries: &[LocalEntry], plan: &[PlanItem]) -> (Option<Vec<u64>>, String) {
    const SLOW: Duration = Duration::from_millis(4);
    let keys = || entries.iter().map(|l| l.disk_key).collect::<Vec<u64>>();
    let known = entries.iter().any(|l| l.disk_key != 0);
    match mode {
        DISK_ORDER_OFF => (None, "disk order: off".into()),
        DISK_ORDER_ON if known => (Some(keys()), "disk order: on".into()),
        DISK_ORDER_ON => (None, "disk order: requested, but no on-disk hints available".into()),
        _ => match probe_read_latency(entries, plan) {
            Some(lat) if lat >= SLOW && known => {
                (Some(keys()), format!("disk order: on (median read latency {:.1} ms → cold/spinning source)", lat.as_secs_f64() * 1e3))
            }
            Some(lat) => (None, format!("disk order: off (median read latency {:.2} ms)", lat.as_secs_f64() * 1e3)),
            None => (None, "disk order: off (too few small files to probe)".into()),
        },
    }
}

/// Automatic compression level (`--compress auto`), from scopy-internal signals only, every 5 s (a change needs
/// two windows in a row that agree):
/// - the streams spend most of their time blocked sending, compression takes little CPU, and the receiver is
///   keeping up (its writer queue / RAM stage isn't full) → the link is the limit → compress harder (+2);
/// - compression takes most of the streams' time → the CPU is the limit → compress less (−2).
///
/// Range 1..=9: above 9 zstd gets much slower for little gain on this kind of data.
pub fn run_level_tuner(ctx: &SourceCtx, streams: usize, feedback: &Mutex<Option<Feedback>>, done: &dyn Fn() -> bool, say: &dyn Fn(String)) {
    const INTERVAL: Duration = Duration::from_secs(5);
    let (min, max) = (1, 9);
    let mut last = (ctx.t_net.micros(), ctx.t_compress.micros());
    let mut pending = 0i32;
    loop {
        if !sleep_until_done(done, INTERVAL) {
            return;
        }
        let now = (ctx.t_net.micros(), ctx.t_compress.micros());
        let slots = (streams.max(1) as f64) * INTERVAL.as_micros() as f64;
        let net = (now.0 - last.0) as f64 / slots;
        let cpu = (now.1 - last.1) as f64 / slots;
        last = now;
        let fb = *feedback.lock().unwrap();
        let receiver_busy = fb.is_some_and(|f| {
            if f.stage_limit_mb > 0 {
                f.staged_bytes * 10 >= ((f.stage_limit_mb as u64) << 20) * 8
            } else {
                f.queued >= 48
            }
        });
        let level = ctx.level_target.load(Ordering::Relaxed);
        let want = if cpu > 0.5 && level > min {
            -1
        } else if net > 0.6 && (0.02..0.25).contains(&cpu) && !receiver_busy && level < max {
            // cpu >= 2%: something is actually being compressed (not just already-compressed files sent raw).
            1
        } else {
            0
        };
        // Act only when two windows in a row agree: a single 5 s window can be dominated by one burst of
        // small files (measured: 3 -> 1 -> 3 within 10 s on the big test set).
        let agreed = want != 0 && want == pending;
        pending = want;
        if !agreed {
            continue;
        }
        pending = 0;
        let (new, why) = if want < 0 {
            ((level - 2).max(min), format!("compression uses {:.0}% of stream time", cpu * 100.0))
        } else {
            ((level + 2).min(max), format!("streams blocked on the link {:.0}% of the time, CPU {:.0}%", net * 100.0, cpu * 100.0))
        };
        ctx.level_target.store(new, Ordering::Relaxed);
        let msg = format!("compression level {level} -> {new} ({why})");
        say(msg.clone());
        ctx.level_decisions.lock().unwrap().push(msg);
    }
}

fn sleep_until_done(done: &dyn Fn() -> bool, d: Duration) -> bool {
    let end = Instant::now() + d;
    while Instant::now() < end {
        if done() {
            return false;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    true
}

/// For `ORDER_AUTO`: starts small-files-first, then compares throughput on the wire with small files
/// only against small files mixed with big chunks. Mixing only wins when something other than the
/// link limits the small files (e.g. the receiver creating files), because then big chunks can use
/// the idle bandwidth. Re-checks every minute while both lanes have work.
pub fn run_auto_order(q: &Queue, wire: &AtomicU64, say: &dyn Fn(String)) {
    const WARMUP: Duration = Duration::from_secs(3);
    const PROBE: Duration = Duration::from_secs(4);
    const RECHECK: Duration = Duration::from_secs(60);
    const GAIN: f64 = 1.15;
    if q.order != ORDER_AUTO || !sleep_unless_done(q, WARMUP) {
        return;
    }
    loop {
        if q.small_done() || q.big_done() {
            return;
        }
        q.share.store(0, Ordering::Relaxed);
        let Some(small_only) = measure_wire(q, wire, PROBE) else { return };
        if q.small_done() || q.big_done() {
            return;
        }
        q.share.store(q.mixed_share, Ordering::Relaxed);
        let Some(mixed) = measure_wire(q, wire, PROBE) else { return };
        let mix = mixed > small_only * GAIN;
        if !mix {
            q.share.store(0, Ordering::Relaxed);
        }
        let msg = format!(
            "auto order: {} (on the wire: small files only {}/s, mixed {}/s)",
            if mix { "mixing big files in" } else { "small files first" },
            crate::util::fmt_bytes(small_only as u64),
            crate::util::fmt_bytes(mixed as u64)
        );
        say(msg.clone());
        q.decisions.lock().unwrap().push(msg);
        if !sleep_unless_done(q, RECHECK) {
            return;
        }
    }
}

fn sleep_unless_done(q: &Queue, d: Duration) -> bool {
    let end = Instant::now() + d;
    while Instant::now() < end {
        if q.done() {
            return false;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    true
}

fn measure_wire(q: &Queue, wire: &AtomicU64, d: Duration) -> Option<f64> {
    let (start, t) = (wire.load(Ordering::Relaxed), Instant::now());
    if !sleep_unless_done(q, d) {
        return None;
    }
    Some(wire.load(Ordering::Relaxed).saturating_sub(start) as f64 / t.elapsed().as_secs_f64())
}

/// Everything a sending data connection needs, shared by all of them.
pub struct SourceCtx {
    pub entries: Arc<Vec<LocalEntry>>,
    pub policy: Policy,
    dict: Mutex<Arc<Vec<u8>>>,
    pub verify: bool,
    pub progress: Arc<Progress>,
    pub errors: Mutex<Vec<String>>,
    pub t_read: Timer,
    pub t_compress: Timer,
    pub t_hash: Timer,
    pub t_net: Timer,
    /// Time streams waited for read data.
    pub t_feed_wait: Timer,
    /// Streams currently sending (the consumers behind `t_feed_wait`).
    pub streams_active: AtomicUsize,
    /// Pieces read so far: the reader tuner's throughput signal.
    pub read_items: AtomicU64,
    /// Compression level the streams should use; changed on the fly by `run_level_tuner`.
    pub level_target: AtomicI32,
    pub level_decisions: Mutex<Vec<String>>,
    pub frames: AtomicU64,
    /// Test hook (SCOPY_TEST_DROP_AFTER): the first connection fails after this many frames.
    pub drop_after: Option<u64>,
    drop_armed: AtomicU64,
    /// On a receiver serving a pull: the share the readers must stay inside (see `confine.rs`).
    pub jail: OnceLock<crate::confine::Jail>,
    /// On a receiver serving a pull: the signed-in user the readers act as (see `auth.rs`).
    pub user: OnceLock<Arc<crate::auth::Identity>>,
}

impl SourceCtx {
    pub fn new(entries: Arc<Vec<LocalEntry>>, level: i32, dict: Vec<u8>, verify: bool, progress: Arc<Progress>) -> Self {
        let drop_after = std::env::var("SCOPY_TEST_DROP_AFTER").ok().and_then(|v| v.parse().ok());
        SourceCtx {
            entries,
            policy: Policy::new(level),
            dict: Mutex::new(Arc::new(dict)),
            verify,
            progress,
            errors: Mutex::new(Vec::new()),
            t_read: Timer::default(),
            t_compress: Timer::default(),
            t_hash: Timer::default(),
            t_net: Timer::default(),
            t_feed_wait: Timer::default(),
            streams_active: AtomicUsize::new(0),
            read_items: AtomicU64::new(0),
            level_target: AtomicI32::new(level),
            level_decisions: Mutex::new(Vec::new()),
            frames: AtomicU64::new(0),
            drop_after,
            drop_armed: AtomicU64::new(1),
            jail: OnceLock::new(),
            user: OnceLock::new(),
        }
    }

    /// Sets the compression dictionary; must happen before data connections start.
    pub fn set_dict(&self, dict: Vec<u8>) {
        *self.dict.lock().unwrap() = Arc::new(dict);
    }

    pub fn stats(&self) -> Stats {
        vec![
            ("source.read_us".into(), self.t_read.micros()),
            ("source.compress_us".into(), self.t_compress.micros()),
            ("source.hash_us".into(), self.t_hash.micros()),
            ("source.net_write_us".into(), self.t_net.micros()),
            ("source.feed_wait_us".into(), self.t_feed_wait.micros()),
            ("source.frames".into(), self.frames.load(Ordering::Relaxed)),
            ("source.read_errors".into(), self.errors.lock().unwrap().len() as u64),
        ]
    }

    fn error(&self, msg: String) {
        self.errors.lock().unwrap().push(msg);
    }
}

/// How a file that changed or vanished on the source while it was being sent is reported (the client of a sync
/// round fetches it later instead of failing the round: see `client::pull_with`).
pub const CHANGED: &str = ": changed while copying";
pub const GONE: &str = ": gone from the source (deleted or moved meanwhile)";

fn read_error(path: &str, e: &std::io::Error) -> String {
    if e.kind() == std::io::ErrorKind::NotFound { format!("{path}{GONE}") } else { format!("{path}: {e}") }
}

/// Reader pool limits for automatic tuning. Measured on a cold SAS source: beyond the storage's IOPS
/// limit more readers only add latency, so the tuner starts moderate and only grows while it pays off.
pub const AUTO_READERS: (usize, usize, usize) = (16, 4, 128); // start, min, max

/// Reader count: fixed when given, otherwise tuned automatically.
pub fn reader_tuner(requested: usize) -> Arc<Tuner> {
    let (start, min, max) = AUTO_READERS;
    Arc::new(if requested > 0 { Tuner::fixed(requested) } else { Tuner::auto(start, min, max) })
}

/// A piece of a file that has been read and waits to be sent.
pub struct Item {
    idx: u32,
    offset: u64,
    data: Vec<u8>,
}

/// Starts the reader pool (as many threads as the tuner's maximum; only the active ones work). Read data
/// goes to the streams through a bounded channel (~64 pieces of at most 2 MB). The threads stop when the
/// queue is done or when every stream has dropped its receiver.
pub fn start_readers(ctx: Arc<SourceCtx>, q: Arc<Queue>, tuner: Arc<Tuner>) -> (Receiver<Item>, Vec<JoinHandle<()>>) {
    let (tx, rx) = bounded::<Item>(64);
    let handles = (0..tuner.max)
        .map(|i| {
            let (ctx, q, tx, tuner) = (ctx.clone(), q.clone(), tx.clone(), tuner.clone());
            std::thread::spawn(move || read_loop(i, &ctx, &q, &tx, &tuner))
        })
        .collect();
    (rx, handles)
}

fn read_loop(me: usize, ctx: &SourceCtx, q: &Queue, tx: &Sender<Item>, tuner: &Tuner) {
    let _user = ctx.user.get().and_then(|u| u.enter().map_err(|e| eprintln!("{e:#}")).ok());
    let mut cached: Option<(u32, File)> = None;
    loop {
        while !tuner.is_active(me) {
            if q.done() {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let Some(batch) = q.next_batch() else { return };
        for job in batch {
            let item = match *job {
                Work::Whole(idx) => {
                    let le = &ctx.entries[idx as usize];
                    let t = Instant::now();
                    let r = match ctx.jail.get() {
                        None => fs::read(&le.local),
                        // Opened, then checked where it really is, then read.
                        Some(j) => File::open(&le.local).and_then(|mut f| {
                            j.check(&f, &le.local)?;
                            let mut d = Vec::with_capacity(le.e.size as usize);
                            f.read_to_end(&mut d).map(|_| d)
                        }),
                    };
                    ctx.t_read.add(t);
                    match r {
                        Ok(d) if d.len() as u64 == le.e.size => Item { idx, offset: 0, data: d },
                        Ok(_) => {
                            ctx.error(format!("{}{CHANGED}", le.e.path));
                            continue;
                        }
                        Err(e) => {
                            ctx.error(read_error(&le.e.path, &e));
                            continue;
                        }
                    }
                }
                Work::Part { idx, offset, len } => {
                    let le = &ctx.entries[idx as usize];
                    if cached.as_ref().map(|c| c.0) != Some(idx) {
                        let opened = File::open(&le.local).and_then(|f| match ctx.jail.get() {
                            Some(j) => j.check(&f, &le.local).map(|_| f),
                            None => Ok(f),
                        });
                        match opened {
                            Ok(f) => cached = Some((idx, f)),
                            Err(e) => {
                                ctx.error(read_error(&le.e.path, &e));
                                continue;
                            }
                        }
                    }
                    let mut data = vec![0u8; len as usize];
                    let t = Instant::now();
                    let r = read_at(&cached.as_ref().unwrap().1, &mut data, offset);
                    ctx.t_read.add(t);
                    if let Err(e) = r {
                        ctx.error(read_error(&le.e.path, &e));
                        continue;
                    }
                    Item { idx, offset, data }
                }
            };
            ctx.read_items.fetch_add(1, Ordering::Relaxed);
            if tx.send(item).is_err() {
                return; // every stream is gone
            }
        }
    }
}

/// Sends read pieces as frames until the readers are done. Network errors end the connection (the
/// caller may reconnect; a piece in flight is lost and re-planned in the next round).
pub fn stream_work(w: &mut impl Write, ctx: &SourceCtx, feed: &Receiver<Item>) -> Result<()> {
    struct Active<'a>(&'a AtomicUsize);
    impl Drop for Active<'_> {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::Relaxed);
        }
    }
    ctx.streams_active.fetch_add(1, Ordering::Relaxed);
    let _active = Active(&ctx.streams_active);
    let dict = ctx.dict.lock().unwrap().clone();
    let mut enc = if ctx.policy.level > 0 { Some(FrameEncoder::new(ctx.policy.level, &dict)?) } else { None };
    let drop_at = match ctx.drop_after {
        Some(n) if ctx.drop_armed.swap(0, Ordering::Relaxed) == 1 => Some(n),
        _ => None,
    };
    let mut sent = 0u64;
    let mut wire = Vec::new();
    let mut level = ctx.policy.level;
    loop {
        if let Some(enc) = enc.as_mut() {
            let want = ctx.level_target.load(Ordering::Relaxed);
            if want != level && enc.set_level(want).is_ok() {
                level = want;
            }
        }
        // Time spent waiting here means the source's reading is the brake (internal tuning signal).
        let t = Instant::now();
        let Ok(item) = feed.recv() else { return Ok(()) };
        ctx.t_feed_wait.add(t);
        if drop_at.is_some_and(|n| sent >= n) {
            bail!("test hook: dropping this data connection after {sent} frames");
        }
        let le = &ctx.entries[item.idx as usize];
        send_frame(w, ctx, enc.as_mut(), &mut wire, item.idx, item.offset, &item.data, &ext_of(&le.e.path))?;
        sent += 1;
        let p = &ctx.progress;
        p.raw.fetch_add(item.data.len() as u64, Ordering::Relaxed);
        if item.offset + item.data.len() as u64 == le.e.size {
            p.files.fetch_add(1, Ordering::Relaxed);
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn send_frame(
    w: &mut impl Write,
    ctx: &SourceCtx,
    enc: Option<&mut FrameEncoder>,
    wire: &mut Vec<u8>,
    idx: u32,
    offset: u64,
    data: &[u8],
    ext: &str,
) -> Result<()> {
    let hash = ctx.verify.then(|| {
        let t = Instant::now();
        let h = *blake3::hash(data).as_bytes();
        ctx.t_hash.add(t);
        h
    });
    let mut flags = if hash.is_some() { F_HASH } else { 0 };
    let payload: &[u8] = match enc {
        Some(enc) if ctx.policy.should_compress(ext) => {
            let t = Instant::now();
            enc.compress(data, wire)?;
            ctx.t_compress.add(t);
            ctx.policy.record(ext, data.len() as u64, wire.len() as u64);
            flags |= F_ZSTD;
            wire
        }
        _ => data,
    };
    let hdr = FrameHeader { idx, offset, raw_len: data.len() as u32, flags, wire_len: payload.len() as u32, hash };
    let t = Instant::now();
    put_frame(w, &hdr, payload)?;
    ctx.t_net.add(t);
    ctx.frames.fetch_add(1, Ordering::Relaxed);
    ctx.progress.wire.fetch_add(payload.len() as u64, Ordering::Relaxed);
    Ok(())
}

/// Picks sample content from the small, compressible files that will actually be sent, for
/// dictionary training. Empty when there are too few for a dictionary to pay off.
pub fn dict_samples(entries: &[LocalEntry], plan: &[PlanItem]) -> Vec<Vec<u8>> {
    const MIN_FILES: usize = 1000;
    const SAMPLES: usize = 600;
    const SAMPLE_BYTES: u64 = 8 * 1024;
    let cands: Vec<&LocalEntry> = plan
        .iter()
        .map(|p| &entries[p.idx as usize])
        .filter(|l| l.e.is_file() && l.e.size > 0 && l.e.size <= 64 * 1024 && !known_incompressible(&ext_of(&l.e.path)))
        .collect();
    if cands.len() < MIN_FILES {
        return Vec::new();
    }
    let step = (cands.len() / SAMPLES).max(1);
    cands
        .iter()
        .step_by(step)
        .take(SAMPLES)
        .filter_map(|l| {
            let mut v = Vec::new();
            File::open(&l.local).ok()?.take(SAMPLE_BYTES).read_to_end(&mut v).ok()?;
            Some(v)
        })
        .collect()
}

#[cfg(windows)]
pub fn read_at(f: &File, mut buf: &mut [u8], mut off: u64) -> io::Result<()> {
    use std::os::windows::fs::FileExt;
    while !buf.is_empty() {
        let n = f.seek_read(buf, off)?;
        if n == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        buf = &mut buf[n..];
        off += n as u64;
    }
    Ok(())
}

#[cfg(unix)]
pub fn read_at(f: &File, buf: &mut [u8], off: u64) -> io::Result<()> {
    use std::os::unix::fs::FileExt;
    f.read_exact_at(buf, off)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(path: &str, size: u64) -> Entry {
        Entry { kind: ENTRY_FILE, path: path.into(), size, mtime: 0, ctime: 0, attrs: 0, ..Entry::default() }
    }

    fn drain(q: &Queue) -> Vec<Work> {
        let mut out = Vec::new();
        while let Some(b) = q.next_batch() {
            out.extend_from_slice(b);
        }
        out
    }

    fn entries() -> Vec<Entry> {
        vec![
            file("b/1.xml", 1000),
            file("a/2.txt", 1000),
            file("a/3.xml", 1000),
            file("big.zip", 4 * CHUNK),
            file("a/4.txt", 1000),
            file("a/5.jpg", 1000),
            file("big.xml", 3 * CHUNK),
        ]
    }

    fn all(entries: &[Entry]) -> Vec<PlanItem> {
        (0..entries.len() as u32).map(|i| PlanItem { idx: i, chunks: None }).collect()
    }

    #[test]
    fn parked_readers_stop_when_the_round_is_aborted() {
        // Every stream died (receiver crashed): the feed is gone, work is left in the queue. Readers the tuner had
        // parked must not wait for the queue to drain (the client hung with 109 threads like this).
        let dir = std::env::temp_dir().join(format!("scopy-abort-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let mut local = Vec::new();
        for i in 0..200 {
            let p = dir.join(format!("f{i}.txt"));
            fs::write(&p, b"data").unwrap();
            local.push(LocalEntry { e: file(&format!("f{i}.txt"), 4), local: p, disk_key: 0 });
        }
        let manifest: Vec<Entry> = local.iter().map(|l| l.e.clone()).collect();
        let queue = Arc::new(build_queue(&manifest, &all(&manifest), ORDER_SMALL_FIRST, None));
        let ctx = Arc::new(SourceCtx::new(Arc::new(local), 0, Vec::new(), false, Arc::new(Progress::default())));
        let tuner = Arc::new(Tuner::auto(1, 1, 4)); // one active reader, three parked
        let (feed, readers) = start_readers(ctx, queue.clone(), tuner);
        drop(feed); // no stream left to take the data
        queue.abort();
        let (tx, rx) = crossbeam_channel::bounded(1);
        std::thread::spawn(move || {
            for h in readers {
                let _ = h.join();
            }
            let _ = tx.send(());
        });
        let stopped = rx.recv_timeout(Duration::from_secs(10)).is_ok();
        fs::remove_dir_all(&dir).unwrap();
        assert!(stopped, "readers still running after abort");
        assert!(queue.done() && queue.next_batch().is_none());
    }

    #[cfg(unix)]
    #[test]
    fn unix_scan_keeps_modes_and_links_without_following_them() {
        use std::os::unix::fs::PermissionsExt;
        let root = std::env::temp_dir().join(format!("scopy-scan-unix-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("bin")).unwrap();
        fs::write(root.join("bin/run.sh"), b"#!/bin/sh").unwrap();
        fs::set_permissions(root.join("bin/run.sh"), fs::Permissions::from_mode(0o751)).unwrap();
        std::os::unix::fs::symlink("run.sh", root.join("bin/go")).unwrap();
        // A link to a folder is not walked into.
        std::os::unix::fs::symlink("/usr", root.join("usr")).unwrap();
        let scan = scan(&root).unwrap();
        let got = |p: &str| scan.entries.iter().find(|l| l.e.path == p).map(|l| l.e.clone()).unwrap();
        assert_eq!(got("bin/run.sh").mode, MODE_SET | 0o751);
        let go = got("bin/go");
        assert!(go.is_link() && go.link == "run.sh" && go.size == 0);
        assert!(got("usr").is_link());
        assert_eq!(scan.entries.len(), 4, "{:?}", scan.entries.iter().map(|l| &l.e.path).collect::<Vec<_>>());
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn parallel_scan_finds_everything_parents_first() {
        let root = std::env::temp_dir().join(format!("scopy-scan-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        for d in 0..6 {
            for s in 0..4 {
                let dir = root.join(format!("d{d}")).join(format!("s{s}")).join("deep");
                fs::create_dir_all(&dir).unwrap();
                for f in 0..5 {
                    fs::write(dir.join(format!("f{f}.txt")), vec![b'x'; f * 10]).unwrap();
                }
            }
        }
        let one = scan(&root).unwrap();
        let (mut many, skipped) = scan_tree(&root, 8).unwrap();
        many.sort_unstable_by(|a, b| a.e.path.split('/').cmp(b.e.path.split('/')));
        fs::remove_dir_all(&root).unwrap();
        // 6 + 24 + 24 folders, 120 files.
        assert_eq!(one.entries.len(), 6 + 24 + 24 + 120);
        assert_eq!(skipped, 0);
        let paths = |v: &[LocalEntry]| v.iter().map(|l| l.e.path.clone()).collect::<Vec<_>>();
        assert_eq!(paths(&one.entries), paths(&many));
        assert_eq!(one.entries.iter().map(|l| l.e.size).sum::<u64>(), 24 * (10 + 20 + 30 + 40));
        // Every folder is listed before anything inside it.
        let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
        for l in &one.entries {
            if let Some((parent, _)) = l.e.path.rsplit_once('/') {
                assert!(seen.contains(parent), "{} before its folder", l.e.path);
            }
            seen.insert(l.e.path.as_str());
        }
    }

    #[test]
    fn small_first_orders_compressible_then_packed_then_big() {
        let e = entries();
        let work = drain(&build_queue(&e, &all(&e), ORDER_SMALL_FIRST, None));
        let order: Vec<u32> = work.iter().map(|w| match w { Work::Whole(i) => *i, Work::Part { idx, .. } => *idx }).collect();
        // txt, xml (by path), then the already-compressed jpg, then big.xml's chunks, then big.zip's.
        assert_eq!(order, vec![1, 4, 2, 0, 5, 6, 6, 6, 3, 3, 3, 3]);
    }

    #[test]
    fn mixed_interleaves_big_chunks() {
        let e = entries();
        let work = drain(&build_queue(&e, &all(&e), ORDER_MIXED, None));
        assert_eq!(work.len(), 12);
        // Big chunks start right away instead of waiting for the small files.
        assert!(matches!(work[0], Work::Part { .. }));
        let first_small = work.iter().position(|w| matches!(w, Work::Whole(_))).unwrap();
        assert!(first_small < 8, "small files must not wait for all big chunks");
    }

    #[test]
    fn disk_order_sorts_by_disk_key() {
        let e = entries();
        // keys: 1.xml=50, 2.txt=10, 3.xml=40, big.zip=5, 4.txt=30, 5.jpg=20, big.xml=1
        let keys = vec![50, 10, 40, 5, 30, 20, 1];
        let work = drain(&build_queue(&e, &all(&e), ORDER_SMALL_FIRST, Some(&keys)));
        let order: Vec<u32> = work.iter().map(|w| match w { Work::Whole(i) => *i, Work::Part { idx, .. } => *idx }).collect();
        // small files by key (2.txt, 5.jpg, 4.txt, 3.xml, 1.xml), then big files by key (big.xml, big.zip)
        assert_eq!(order, vec![1, 5, 4, 2, 0, 6, 6, 6, 3, 3, 3, 3]);
    }

    #[test]
    fn partial_plan_sends_only_missing_chunks() {
        let entries = vec![file("big.bin", 3 * CHUNK + 5)];
        let plan = vec![PlanItem { idx: 0, chunks: Some(vec![0b1010]) }];
        assert_eq!(
            drain(&build_queue(&entries, &plan, ORDER_AUTO, None)),
            vec![
                Work::Part { idx: 0, offset: CHUNK, len: CHUNK as u32 },
                Work::Part { idx: 0, offset: 3 * CHUNK, len: 5 }
            ]
        );
    }
}
