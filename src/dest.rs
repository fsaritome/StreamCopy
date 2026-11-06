//! Destination side of a job: creates folders, decides what is still needed, receives frames,
//! writes files with a pool of writer threads, and keeps a journal so big files can resume.

use crate::compress::FrameDecoder;
use crate::confine::Jail;
use crate::meta;
use crate::proto::*;
use crate::source::read_at;
use crate::util::{sanitize_rel, to_nanos, Progress, Timer, Tuner};
use anyhow::{bail, Context, Result};
use crossbeam_channel::{bounded, Receiver, Sender};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

/// Existing files whose size matches and whose mtime is within this tolerance are skipped.
const MTIME_TOLERANCE_NS: i64 = 1_000_000;
const ROUND_TIMEOUT: Duration = Duration::from_secs(600);

const JOURNAL_MAGIC: &[u8; 4] = b"SCPJ";
const JOURNAL_HEADER: u64 = 4 + 4 + 8 + 8 + 8 + 4;

pub struct Job {
    idx: u32,
    offset: u64,
    data: Vec<u8>,
    hash: Option<[u8; 32]>,
}

/// Chunks of a big file are synced to disk in batches of this many (64 MB) before the journal may claim them.
const SYNC_CHUNKS: usize = 32;

struct Large {
    file: Option<Arc<File>>,
    journal: Option<File>,
    /// Chunks written (possibly still in the OS cache); a resent chunk that is set here is skipped.
    bits: Vec<u8>,
    /// Chunks known to be on disk: the only ones the journal may claim, so a crash can't leave a journal that
    /// promises data the disk never got.
    durable: Vec<u8>,
    /// Written chunks not yet synced.
    unsynced: Vec<u32>,
    remaining: u32,
    /// The part file already exists from an earlier run (open it without truncating).
    resumed: bool,
    failed: bool,
}

pub struct DestSession {
    pub base: PathBuf,
    pub entries: Vec<Entry>,
    rel: Vec<PathBuf>,
    pub opts: Options,
    /// Compression dictionary; arrives after the plan, before any data connection.
    dict: Mutex<Arc<Vec<u8>>>,
    done: Vec<AtomicBool>,
    large: Mutex<HashMap<u32, Large>>,
    tx: Mutex<Option<Sender<Job>>>,
    writers: Mutex<Vec<JoinHandle<()>>>,
    pending: AtomicU64,
    pub files_ok: AtomicU64,
    pub bytes_ok: AtomicU64,
    pub skipped: AtomicU64,
    resumed_files: AtomicU64,
    errors: Mutex<BTreeMap<u32, String>>,
    pub progress: Arc<Progress>,
    conns_done: Mutex<u32>,
    conns_cv: Condvar,
    t_net: Timer,
    t_decompress: Timer,
    t_queue: Timer,
    t_create: Timer,
    t_write: Timer,
    t_verify: Timer,
    t_meta: Timer,
    t_journal: Timer,
    /// How many writers may work; tuned automatically unless the client fixed a number.
    pub tuner: Arc<Tuner>,
    /// Jobs written so far: the writer tuner's throughput signal.
    jobs_done: AtomicU64,
    closing: AtomicBool,
    /// RAM staging: bytes the queue may hold (0 = not staged) and bytes currently held.
    stage_limit: u64,
    buffered: AtomicU64,
    stage_peak: AtomicU64,
    /// "Received" (in RAM, not necessarily written): small files, and received chunks of big files.
    received: Vec<AtomicBool>,
    recv_chunks: Mutex<HashMap<u32, Vec<u8>>>,
    /// Paths (manifest form) an earlier job to this destination was writing when it was interrupted before its final
    /// flush: they may have the right size and time without their data, so the plan doesn't trust them.
    suspect: Mutex<HashSet<String>>,
    /// Files written by this job (not skipped ones): what a file-by-file flush has to sync.
    written: Vec<AtomicBool>,
    t_flush: Timer,
    /// How the final flush went: 0 not needed / not run, 1 whole volume, 2 file by file, 3 each file while writing.
    flush_mode: AtomicU64,
    /// No rights for a volume flush (e.g. `scopy get` as a normal user): writers sync each file right after writing
    /// it, overlapped with the transfer. Measured on a laptop: syncing 16k files one by one at the end took 16 s of 36 s.
    sync_each: AtomicBool,
    /// Folders (relative) that did not exist before this job, from `survey_dirs`; "" = the destination itself.
    /// Files in them can't match anything, so the plan doesn't look for them.
    missing_dirs: Mutex<HashSet<PathBuf>>,
    /// The destination was empty (or missing) before this job: every folder is new, nothing needs surveying.
    all_new: AtomicBool,
    /// Background folder creation (`start_create_dirs`); joined before folder timestamps are restored.
    dirs_thread: Mutex<Option<JoinHandle<()>>>,
    /// On a receiver: the share this job must stay inside (see `confine.rs`). Not set for `scopy get`, which
    /// writes with the user's own rights.
    jail: OnceLock<Jail>,
    /// Existing folders the job needs that are junctions or symbolic links (found by `survey_dirs` in a jail, and
    /// always on Unix).
    links: Mutex<Vec<PathBuf>>,
    /// Up-to-date files whose Unix mode, owner or group differ from the sender's (fixed in `finish`, not re-sent).
    fix_meta: Mutex<Vec<u32>>,
    /// On a receiver: the signed-in user every writer thread acts as (see `auth.rs`).
    user: OnceLock<Arc<crate::auth::Identity>>,
}

/// Writer count: fixed when the client asked for one, otherwise tuned automatically.
pub fn writer_tuner(requested: usize) -> Arc<Tuner> {
    Arc::new(if requested > 0 { Tuner::fixed(requested) } else { Tuner::auto(16, 4, 96) })
}

impl DestSession {
    pub fn new(base: PathBuf, entries: Vec<Entry>, opts: Options, tuner: Arc<Tuner>, progress: Arc<Progress>) -> Result<Arc<Self>> {
        let rel = entries.iter().map(|e| sanitize_rel(&e.path, false)).collect::<Result<Vec<_>>>()?;
        no_entries_below_links(&entries)?;
        let entry_count = entries.len();
        // Staging: the queue may hold up to `stage_mb` of data (bounded by bytes, see recv_frames);
        // without staging a short queue keeps memory low and the network paced by the disk.
        let staged = opts.stage_mb > 0;
        let stage_limit = match opts.stage_mb {
            0 => 0,
            // Auto: half of the RAM that is free right now, at most 16 GB, at least 256 MB.
            STAGE_AUTO => (meta::available_memory().unwrap_or(0) / 2).clamp(256 << 20, 16 << 30),
            mb => (mb.min(65536) as u64) << 20,
        };
        let (tx, rx) = bounded::<Job>(if staged { 1 << 20 } else { 64 });
        let sess = Arc::new(DestSession {
            base,
            done: entries.iter().map(|_| AtomicBool::new(false)).collect(),
            entries,
            rel,
            dict: Mutex::new(Arc::new(opts.dict.clone())),
            opts,
            large: Mutex::new(HashMap::new()),
            tx: Mutex::new(Some(tx)),
            writers: Mutex::new(Vec::new()),
            pending: AtomicU64::new(0),
            files_ok: AtomicU64::new(0),
            bytes_ok: AtomicU64::new(0),
            skipped: AtomicU64::new(0),
            resumed_files: AtomicU64::new(0),
            errors: Mutex::new(BTreeMap::new()),
            progress,
            conns_done: Mutex::new(0),
            conns_cv: Condvar::new(),
            t_net: Timer::default(),
            t_decompress: Timer::default(),
            t_queue: Timer::default(),
            t_create: Timer::default(),
            t_write: Timer::default(),
            t_verify: Timer::default(),
            t_meta: Timer::default(),
            t_journal: Timer::default(),
            jobs_done: AtomicU64::new(0),
            closing: AtomicBool::new(false),
            stage_limit,
            buffered: AtomicU64::new(0),
            stage_peak: AtomicU64::new(0),
            received: (0..entry_count).map(|_| AtomicBool::new(false)).collect(),
            recv_chunks: Mutex::new(HashMap::new()),
            suspect: Mutex::new(HashSet::new()),
            written: (0..entry_count).map(|_| AtomicBool::new(false)).collect(),
            t_flush: Timer::default(),
            flush_mode: AtomicU64::new(0),
            sync_each: AtomicBool::new(false),
            missing_dirs: Mutex::new(HashSet::new()),
            all_new: AtomicBool::new(false),
            dirs_thread: Mutex::new(None),
            jail: OnceLock::new(),
            links: Mutex::new(Vec::new()),
            fix_meta: Mutex::new(Vec::new()),
            user: OnceLock::new(),
            tuner,
        });
        let handles = (0..sess.tuner.max)
            .map(|i| {
                let (sess, rx) = (sess.clone(), rx.clone());
                thread::spawn(move || writer(i, &sess, rx))
            })
            .collect();
        *sess.writers.lock().unwrap() = handles;
        Ok(sess)
    }

    fn path(&self, idx: u32) -> PathBuf {
        self.base.join(&self.rel[idx as usize])
    }

    pub fn set_dict(&self, dict: Vec<u8>) {
        *self.dict.lock().unwrap() = Arc::new(dict);
    }

    /// Keeps this job inside `share_root`: no writing through junctions or symbolic links. Call before `survey_dirs`.
    pub fn confine(&self, share_root: &Path) -> Result<()> {
        let jail = Jail::new(share_root).with_context(|| format!("cannot open the share root {}", share_root.display()))?;
        let _ = self.jail.set(jail);
        Ok(())
    }

    /// Writers and folder creation act as `user` (call before any data arrives).
    pub fn act_as(&self, user: Arc<crate::auth::Identity>) {
        let _ = self.user.set(user);
    }

    /// Acts as the session's user on this thread, if there is one.
    fn enter_user(&self) -> Option<crate::auth::Act> {
        let u = self.user.get()?;
        match u.enter() {
            Ok(a) => Some(a),
            Err(e) => {
                eprintln!("{e:#}");
                None
            }
        }
    }

    /// After `survey_dirs` in a jail: fails if a folder the job needs is a junction or symbolic link.
    pub fn check_links(&self) -> Result<()> {
        if let Some(l) = self.links.lock().unwrap().first() {
            bail!("{} is a junction or symbolic link: scopy does not write through links", self.base.join(l).display());
        }
        Ok(())
    }

    /// Fails if `f` (opened as `p`) is outside the job's share.
    fn check_inside(&self, f: &File, p: &Path) -> io::Result<()> {
        self.jail.get().map_or(Ok(()), |j| j.check(f, p))
    }

    fn error(&self, idx: u32, msg: String) {
        self.errors.lock().unwrap().insert(idx, msg);
    }

    /// Every folder the manifest needs (relative), grouped by depth: level 0 holds the top-level folders.
    fn dir_levels(&self) -> Vec<Vec<PathBuf>> {
        let mut dirs = BTreeSet::new();
        for (e, p) in self.entries.iter().zip(&self.rel) {
            let d = if e.is_dir() { Some(p.clone()) } else { p.parent().map(Path::to_path_buf) };
            if let Some(d) = d.filter(|d| !d.as_os_str().is_empty()) {
                dirs.insert(d);
            }
        }
        let mut levels: Vec<Vec<PathBuf>> = Vec::new();
        for d in dirs {
            let depth = d.components().count();
            if levels.len() < depth {
                levels.resize_with(depth, Vec::new);
            }
            levels[depth - 1].push(d);
        }
        levels
    }

    /// Finds which needed folders don't exist yet, top-down: below a missing folder nothing is checked (an empty
    /// destination costs one check instead of one per folder). Returns (folders needed, missing).
    pub fn survey_dirs(&self) -> (usize, usize) {
        // Empty or missing destination (the usual first copy): every folder is new. Skips building the folder
        // list here; measured on TEST-B that took 0.6 s for 37,897 folders, before any data could flow.
        if fs::read_dir(&self.base).map_or(true, |mut d| d.next().is_none()) {
            self.all_new.store(true, Ordering::Relaxed);
            let n = self.entries.iter().filter(|e| e.is_dir()).count();
            return (n, n);
        }
        let levels = self.dir_levels();
        let mut missing = HashSet::new();
        if !self.base.is_dir() {
            missing.insert(PathBuf::new());
        }
        for level in &levels {
            let known: Vec<bool> = level.iter().map(|d| missing.contains(d.parent().unwrap_or(Path::new("")))).collect();
            let check: Vec<&PathBuf> = level.iter().zip(&known).filter(|(_, &k)| !k).map(|(d, _)| d).collect();
            // Unix: never through a link, also without a jail (a link left by an earlier copy must not lead a
            // later one outside the destination).
            let jailed = self.jail.get().is_some() || cfg!(unix);
            let exists = par_map(&check, |d| {
                if !jailed {
                    return self.base.join(d).is_dir();
                }
                // Same one lookup, without following a link (a junction is not a folder here).
                match fs::symlink_metadata(self.base.join(d)) {
                    Ok(m) if m.file_type().is_symlink() => {
                        self.links.lock().unwrap().push(d.to_path_buf());
                        false
                    }
                    Ok(m) => m.is_dir(),
                    Err(_) => false,
                }
            });
            missing.extend(level.iter().zip(known).filter(|(_, k)| *k).map(|(d, _)| d.clone()));
            missing.extend(check.into_iter().zip(exists).filter(|(_, e)| !e).map(|(d, _)| d.clone()));
        }
        let needed = levels.iter().map(Vec::len).sum();
        let n = missing.iter().filter(|d| !d.as_os_str().is_empty()).count();
        *self.missing_dirs.lock().unwrap() = missing;
        (needed, n)
    }

    /// Files an interrupted earlier job may have left without their data (see `suspect`); call before the plan.
    pub fn set_suspect(&self, paths: HashSet<String>) {
        *self.suspect.lock().unwrap() = paths;
    }

    /// Manifest paths of the files in `plan` (what this job will write).
    pub fn plan_paths(&self, plan: &[PlanItem]) -> Vec<String> {
        plan.iter().map(|p| self.entries[p.idx as usize].path.clone()).collect()
    }

    /// Whether the file's folder did not exist before this job (so the file can't be there either).
    fn in_new_dir(&self, idx: u32) -> bool {
        if self.all_new.load(Ordering::Relaxed) {
            return true;
        }
        let parent = self.rel[idx as usize].parent().unwrap_or(Path::new(""));
        self.missing_dirs.lock().unwrap().contains(parent)
    }

    /// Creates the destination and every missing folder, one depth level at a time, each level in parallel
    /// (a level only needs the one above). Needs `survey_dirs` first. Returns how many folders it created.
    pub fn create_dirs(&self) -> Result<usize> {
        fs::create_dir_all(&self.base).with_context(|| format!("cannot create {}", self.base.display()))?;
        let missing = self.missing_dirs.lock().unwrap().clone();
        let all_new = self.all_new.load(Ordering::Relaxed);
        let mut created = 0;
        for level in self.dir_levels() {
            let todo: Vec<PathBuf> =
                level.into_iter().filter(|d| all_new || missing.contains(d)).map(|d| self.base.join(d)).collect();
            created += todo.len();
            par_map(&todo, |d| {
                // create_dir_all also covers a parent that failed on the level above, or a writer racing us.
                if let Err(e) = with_parent(d, || fs::create_dir(d)).or_else(|_| fs::create_dir_all(d)) {
                    eprintln!("cannot create {}: {e}", d.display());
                }
            });
        }
        Ok(created)
    }

    /// Creates the destination now and the missing folders in the background, so data can flow meanwhile
    /// (writers create a folder themselves if they get there first). Measured on TEST-B: 37,897 folders took ~2 s
    /// of the ~3.4 s before the first byte. `done` is called with (folders created, time) when finished.
    pub fn start_create_dirs(self: &Arc<Self>, done: impl FnOnce(usize, Duration) + Send + 'static) -> Result<()> {
        fs::create_dir_all(&self.base).with_context(|| format!("cannot create {}", self.base.display()))?;
        let sess = self.clone();
        *self.dirs_thread.lock().unwrap() = Some(thread::spawn(move || {
            let _user = sess.enter_user();
            let t = Instant::now();
            if let Ok(n) = sess.create_dirs() {
                done(n, t.elapsed());
            }
        }));
        Ok(())
    }

    /// Works out what must be sent: skips files that already match, and resumes big files from
    /// their journal.
    pub fn initial_plan(&self) -> Vec<PlanItem> {
        // A sink run always receives everything: what is on disk doesn't matter, since nothing gets written.
        let force = self.opts.force() || self.opts.sink();
        if !self.opts.sink() {
            // The volume flush is scopy's own job (needs the service's rights), not the user's.
            self.sync_each.store(!crate::auth::as_service(|| meta::volume_flush_allowed(&self.base)), Ordering::Relaxed);
        }
        let files: Vec<u32> = (0..self.entries.len() as u32).filter(|&i| self.entries[i as usize].is_file()).collect();
        // Files in folders that didn't exist before this job can't match, nor have a journal: don't look.
        // Measured on TEST-B: checking 85,513 files that weren't there took 1.1 s.
        let fresh: Vec<bool> = files.iter().map(|&i| self.in_new_dir(i)).collect();
        let suspect = self.suspect.lock().unwrap().clone();
        let matches: Vec<bool> = if force {
            vec![false; files.len()]
        } else {
            let todo: Vec<(u32, bool)> = files.iter().copied().zip(fresh.iter().copied()).collect();
            par_map(&todo, |&(i, new)| !new && !suspect.contains(&self.entries[i as usize].path) && self.matches_existing(i))
        };

        let mut plan = Vec::new();
        let mut large = self.large.lock().unwrap();
        for ((&i, matched), new) in files.iter().zip(matches).zip(fresh) {
            let e = &self.entries[i as usize];
            if matched {
                self.done[i as usize].store(true, Ordering::Relaxed);
                self.skipped.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            if !e.is_chunked() {
                plan.push(PlanItem { idx: i, chunks: None });
                continue;
            }
            let n = chunk_count(e.size);
            let (part, jpath) = (self.part_path(i), self.journal_path(i));
            let resumed = if force || new { None } else { load_journal(&jpath, &part, e) };
            match resumed {
                Some((bits, journal)) => {
                    let have = (0..n).filter(|&c| bit(&bits, c)).count() as u32;
                    if have == n {
                        // Interrupted between the last chunk and the final rename.
                        drop(journal);
                        if let Err(err) = self.finalize_large(i, None) {
                            self.error(i, format!("{err:#}"));
                        }
                        continue;
                    }
                    let mut need = vec![0u8; bits.len()];
                    for c in (0..n).filter(|&c| !bit(&bits, c)) {
                        set_bit(&mut need, c);
                    }
                    self.resumed_files.fetch_add(1, Ordering::Relaxed);
                    let durable = bits.clone();
                    large.insert(
                        i,
                        Large {
                            file: None,
                            journal: Some(journal),
                            bits,
                            durable,
                            unsynced: Vec::new(),
                            remaining: n - have,
                            resumed: true,
                            failed: false,
                        },
                    );
                    plan.push(PlanItem { idx: i, chunks: Some(need) });
                }
                None => {
                    if !self.opts.sink() && !new {
                        let _ = fs::remove_file(&part);
                        let _ = fs::remove_file(&jpath);
                    }
                    let bits = vec![0u8; (n as usize).div_ceil(8)];
                    let durable = bits.clone();
                    large.insert(
                        i,
                        Large { file: None, journal: None, bits, durable, unsynced: Vec::new(), remaining: n, resumed: false, failed: false },
                    );
                    plan.push(PlanItem { idx: i, chunks: None });
                }
            }
        }
        plan
    }

    fn matches_existing(&self, idx: u32) -> bool {
        let e = &self.entries[idx as usize];
        // Not through a link: a link where a file belongs is replaced by the file.
        let Ok(md) = fs::symlink_metadata(self.path(idx)) else { return false };
        let Ok(mtime) = md.modified() else { return false };
        let same = md.is_file() && md.len() == e.size && (to_nanos(mtime) - e.mtime).abs() <= MTIME_TOLERANCE_NS;
        if same && self.opts.meta() && meta::unix_differs(&md, e.mode, e.uid, e.gid) {
            self.fix_meta.lock().unwrap().push(idx);
        }
        same
    }

    fn part_path(&self, idx: u32) -> PathBuf {
        with_suffix(&self.path(idx), ".scopy-part")
    }

    fn journal_path(&self, idx: u32) -> PathBuf {
        with_suffix(&self.path(idx), ".scopy-journal")
    }

    pub fn staged(&self) -> bool {
        self.stage_limit > 0
    }

    pub fn is_closing(&self) -> bool {
        self.closing.load(Ordering::Relaxed)
    }

    /// A snapshot for the sender's tuning. `prev` carries (time, jobs done, create+write µs) between calls.
    pub fn feedback(&self, prev: &mut (Instant, u64, u64)) -> Feedback {
        let jobs = self.jobs_done.load(Ordering::Relaxed);
        let busy = self.t_create.micros() + self.t_write.micros();
        let written = jobs.saturating_sub(prev.1);
        let write_us = if written > 0 { busy.saturating_sub(prev.2) / written } else { 0 };
        *prev = (Instant::now(), jobs, busy);
        Feedback {
            queued: self.pending.load(Ordering::Relaxed).min(u32::MAX as u64) as u32,
            staged_bytes: self.buffered.load(Ordering::Relaxed),
            stage_limit_mb: (self.stage_limit >> 20) as u32,
            write_us: write_us.min(u32::MAX as u64) as u32,
            written: written.min(u32::MAX as u64) as u32,
            writers: self.tuner.active() as u16,
            end: self.is_closing() as u8,
        }
    }

    /// Records that a frame is in our RAM (staging decides rounds on "received", not "written").
    fn mark_received(&self, idx: u32, offset: u64) {
        let e = &self.entries[idx as usize];
        if !e.is_chunked() {
            self.received[idx as usize].store(true, Ordering::Relaxed);
            return;
        }
        let n = chunk_count(e.size) as usize;
        let mut m = self.recv_chunks.lock().unwrap();
        set_bit(m.entry(idx).or_insert_with(|| vec![0u8; n.div_ceil(8)]), (offset / CHUNK) as u32);
    }

    /// With staging: what of `plan` has not even reached our RAM (a chunk counts if it is on disk from an
    /// earlier run or received now).
    fn not_received(&self, plan: &[PlanItem]) -> Vec<PlanItem> {
        let large = self.large.lock().unwrap();
        let recv = self.recv_chunks.lock().unwrap();
        let mut out = Vec::new();
        for p in plan {
            let i = p.idx as usize;
            if self.done[i].load(Ordering::Relaxed) || self.received[i].load(Ordering::Relaxed) {
                continue;
            }
            let e = &self.entries[i];
            if !e.is_chunked() {
                out.push(PlanItem { idx: p.idx, chunks: None });
                continue;
            }
            let n = chunk_count(e.size);
            let on_disk = large.get(&p.idx).map(|l| l.bits.as_slice());
            let got = recv.get(&p.idx).map(|b| b.as_slice());
            let mut need = vec![0u8; (n as usize).div_ceil(8)];
            let mut any = false;
            for c in 0..n {
                if !on_disk.is_some_and(|b| bit(b, c)) && !got.is_some_and(|b| bit(b, c)) {
                    set_bit(&mut need, c);
                    any = true;
                }
            }
            if any {
                out.push(PlanItem { idx: p.idx, chunks: Some(need) });
            }
        }
        out
    }

    /// Files of `plan` that are received (staging) or written.
    pub fn received_count(&self, plan: &[PlanItem]) -> u64 {
        let missing = if self.staged() { self.not_received(plan).len() } else { self.incomplete(plan).len() };
        (plan.len() - missing) as u64
    }

    /// What is still missing out of `plan` after a round.
    pub fn incomplete(&self, plan: &[PlanItem]) -> Vec<PlanItem> {
        if self.staged() {
            return self.not_received(plan);
        }
        let mut large = self.large.lock().unwrap();
        let mut out = Vec::new();
        for p in plan {
            if self.done[p.idx as usize].load(Ordering::Relaxed) {
                continue;
            }
            let e = &self.entries[p.idx as usize];
            match large.get_mut(&p.idx) {
                Some(l) if e.is_chunked() => {
                    if l.failed {
                        // Try opening it again next round.
                        l.failed = false;
                        l.file = None;
                    }
                    let n = chunk_count(e.size);
                    let mut need = vec![0u8; l.bits.len()];
                    for c in (0..n).filter(|&c| !bit(&l.bits, c)) {
                        set_bit(&mut need, c);
                    }
                    out.push(PlanItem { idx: p.idx, chunks: Some(need) });
                }
                _ => out.push(PlanItem { idx: p.idx, chunks: None }),
            }
        }
        out
    }

    /// Waits until `n` data connections of this round have ended and all their data is written.
    pub fn wait_round(&self, n: u32) -> Result<()> {
        let guard = self.conns_done.lock().unwrap();
        let (mut done, timeout) = self.conns_cv.wait_timeout_while(guard, ROUND_TIMEOUT, |d| *d < n).unwrap();
        if timeout.timed_out() {
            bail!("timed out waiting for data connections");
        }
        *done -= n;
        drop(done);
        if self.staged() {
            return Ok(()); // the writers keep committing in the background
        }
        let start = Instant::now();
        while self.pending.load(Ordering::Acquire) > 0 {
            if start.elapsed() > ROUND_TIMEOUT {
                bail!("timed out waiting for writers");
            }
            thread::sleep(Duration::from_millis(5));
        }
        Ok(())
    }

    pub fn conn_finished(&self) {
        *self.conns_done.lock().unwrap() += 1;
        self.conns_cv.notify_all();
    }

    /// Stops the writers, restores folder timestamps, and reports the outcome.
    /// Runs the writer tuner until the session closes (call from its own thread).
    pub fn run_writer_tuner(&self, say: &dyn Fn(String)) {
        crate::util::run_tuner(&self.tuner, &self.jobs_done, None, &||self.closing.load(Ordering::Relaxed), "writers", say);
    }

    pub fn finish(&self) -> JobResult {
        self.closing.store(true, Ordering::Relaxed);
        self.tx.lock().unwrap().take();
        for h in std::mem::take(&mut *self.writers.lock().unwrap()) {
            let _ = h.join();
        }
        // Folder timestamps go last, so every folder must exist by now.
        if let Some(h) = self.dirs_thread.lock().unwrap().take() {
            let _ = h.join();
        }
        // Links after the files (none of them lies below a link, see `no_entries_below_links`) and before the folder
        // timestamps (creating a link changes its folder's time).
        if !self.opts.sink() {
            self.make_links();
        }
        if self.opts.meta() {
            let t = Instant::now();
            self.fix_unchanged();
            let mut dirs: Vec<u32> = (0..self.entries.len() as u32).filter(|&i| self.entries[i as usize].is_dir()).collect();
            dirs.sort_by_key(|&i| std::cmp::Reverse(self.rel[i as usize].components().count()));
            for i in dirs {
                let e = &self.entries[i as usize];
                let p = self.path(i);
                let r = meta::open_dir(&p).and_then(|f| {
                    self.check_inside(&f, &p)?;
                    meta::set_times(&f, e.mtime, e.ctime)?;
                    meta::set_unix(&f, e.mode, e.uid, e.gid)
                });
                let r = r.and_then(|_| if uses_attrs(e) { meta::set_attrs(&p, e.attrs) } else { Ok(()) });
                if let Err(err) = r {
                    eprintln!("folder metadata {}: {err}", p.display());
                }
            }
            self.t_meta.add(t);
        }
        self.relock_dirs();
        if !self.opts.sink() && self.written.iter().any(|w| w.load(Ordering::Relaxed)) {
            self.flush_to_disk();
        }
        let mut errors = std::mem::take(&mut *self.errors.lock().unwrap());
        for (i, e) in self.entries.iter().enumerate() {
            if e.is_file() && !self.done[i].load(Ordering::Relaxed) {
                errors.entry(i as u32).or_insert_with(|| "incomplete: not all data arrived".into());
            }
        }
        JobResult {
            files_ok: self.files_ok.load(Ordering::Relaxed),
            bytes_ok: self.bytes_ok.load(Ordering::Relaxed),
            errors: errors.into_iter().collect(),
            stats: self.stats(),
        }
    }

    /// Creates the job's symbolic links (Unix): an existing file or link of that name is replaced, a folder is not.
    /// Never through a link: the parent folder was checked by `survey_dirs`, and in a jail it is checked again.
    #[cfg(unix)]
    fn make_links(&self) {
        let t = Instant::now();
        let mut made = false;
        for (i, e) in self.entries.iter().enumerate().filter(|(_, e)| e.is_link()) {
            let p = self.path(i as u32);
            let r = (|| -> Result<()> {
                let parent = p.parent().context("bad link path")?;
                if let Some(j) = self.jail.get() {
                    j.check(&meta::open_dir(parent).with_context(|| parent.display().to_string())?, parent)?;
                }
                let target = Path::new(&e.link);
                match fs::symlink_metadata(&p) {
                    Ok(md) if md.is_dir() => bail!("{} is a folder: not replaced by a symbolic link", p.display()),
                    Ok(md) if md.file_type().is_symlink() && fs::read_link(&p).is_ok_and(|t| t == target) => {}
                    Ok(_) => {
                        with_parent(&p, || fs::remove_file(&p)).with_context(|| p.display().to_string())?;
                        std::os::unix::fs::symlink(target, &p).with_context(|| p.display().to_string())?;
                    }
                    Err(_) => with_parent(&p, || std::os::unix::fs::symlink(target, &p)).with_context(|| p.display().to_string())?,
                }
                if self.opts.meta() {
                    meta::set_link_meta(&p, e.mtime, e.uid, e.gid, e.mode != 0).with_context(|| p.display().to_string())?;
                }
                Ok(())
            })();
            match r {
                Ok(()) => made = true,
                Err(err) => self.error(i as u32, format!("{err:#}")),
            }
        }
        if made {
            // A new link is a directory entry like a new file: part of what the final flush puts on disk.
            if let Some(w) = self.written.first() {
                w.store(true, Ordering::Relaxed);
            }
        }
        self.t_meta.add(t);
    }

    /// Windows can't take the links of a Unix sender without special rights: they are reported, not created.
    #[cfg(not(unix))]
    fn make_links(&self) {
        let n = self.entries.iter().filter(|e| e.is_link()).count();
        if n > 0 {
            eprintln!("note: {n} symbolic links from the source were not created (not supported on Windows)");
        }
    }

    /// Folders this job made writable (`unlock_dir`) get their mode back, unless the folder metadata above already
    /// gave them the sender's.
    #[cfg(unix)]
    fn relock_dirs(&self) {
        use std::os::unix::fs::PermissionsExt;
        let mine: Vec<(PathBuf, u32)> = {
            let mut all = UNLOCKED.lock().unwrap();
            let (mine, rest) = std::mem::take(&mut *all).into_iter().partition(|(d, _)| d.starts_with(&self.base));
            *all = rest;
            mine
        };
        if mine.is_empty() {
            return;
        }
        let done: HashSet<PathBuf> = if self.opts.meta() {
            self.entries.iter().enumerate().filter(|(_, e)| e.is_dir() && e.mode != 0).map(|(i, _)| self.path(i as u32)).collect()
        } else {
            HashSet::new()
        };
        for (d, mode) in mine.into_iter().rev() {
            if !done.contains(&d) {
                if let Err(e) = fs::set_permissions(&d, fs::Permissions::from_mode(mode)) {
                    eprintln!("folder mode {}: {e}", d.display());
                }
            }
        }
    }

    #[cfg(not(unix))]
    fn relock_dirs(&self) {}

    /// Up-to-date files whose Unix mode, owner or group changed on the sender: fixed without sending the data again.
    fn fix_unchanged(&self) {
        for i in std::mem::take(&mut *self.fix_meta.lock().unwrap()) {
            let e = &self.entries[i as usize];
            let p = self.path(i);
            let r = open_no_follow(&p).and_then(|f| {
                self.check_inside(&f, &p)?;
                meta::set_unix(&f, e.mode, e.uid, e.gid)
            });
            if let Err(err) = r {
                self.error(i, format!("{}: {err}", p.display()));
            }
        }
    }

    /// "Committed" means on disk, not in the OS cache: after a power loss, a cached file could come back with the
    /// right size and time but without its data, and the next run would skip it as up to date. One flush of the
    /// whole volume is cheap; without the rights for that (e.g. `scopy get` as a normal user), every file this job
    /// wrote is synced on its own. A file that can't be synced is reported as an error.
    fn flush_to_disk(&self) {
        if self.sync_each.load(Ordering::Relaxed) {
            // Every file was synced right after it was written (big files before their rename).
            self.flush_mode.store(3, Ordering::Relaxed);
            return;
        }
        let t = Instant::now();
        match crate::auth::as_service(|| meta::flush_volume(&self.base)) {
            Ok(()) => self.flush_mode.store(1, Ordering::Relaxed),
            Err(_) => {
                self.flush_mode.store(2, Ordering::Relaxed);
                let files: Vec<u32> = (0..self.entries.len() as u32).filter(|&i| self.written[i as usize].load(Ordering::Relaxed)).collect();
                let failed = par_map(&files, |&i| {
                    let p = self.path(i);
                    OpenOptions::new().write(true).open(&p).and_then(|f| f.sync_all()).err().map(|e| (i, format!("{}: not flushed to disk: {e}", p.display())))
                });
                for (i, msg) in failed.into_iter().flatten() {
                    self.error(i, msg);
                }
            }
        }
        self.t_flush.add(t);
    }

    pub fn stats(&self) -> Stats {
        vec![
            ("dest.net_read_us".into(), self.t_net.micros()),
            ("dest.decompress_us".into(), self.t_decompress.micros()),
            ("dest.queue_wait_us".into(), self.t_queue.micros()),
            ("dest.create_us".into(), self.t_create.micros()),
            ("dest.write_us".into(), self.t_write.micros()),
            ("dest.verify_us".into(), self.t_verify.micros()),
            ("dest.meta_us".into(), self.t_meta.micros()),
            ("dest.journal_us".into(), self.t_journal.micros()),
            ("dest.writers_final".into(), self.tuner.active() as u64),
            ("dest.stage_mb".into(), self.stage_limit >> 20),
            ("dest.stage_peak_mb".into(), self.stage_peak.load(Ordering::Relaxed) >> 20),
            ("dest.skipped".into(), self.skipped.load(Ordering::Relaxed)),
            ("dest.resumed_files".into(), self.resumed_files.load(Ordering::Relaxed)),
            ("dest.sink".into(), self.opts.sink() as u64),
            ("dest.flush_us".into(), self.t_flush.micros()),
            ("dest.flush_mode".into(), self.flush_mode.load(Ordering::Relaxed)),
        ]
    }

    /// A file this job does not fetch (a sync pull takes only what its round decided): not an incomplete file.
    pub fn leave_out(&self, idx: u32) {
        self.done[idx as usize].store(true, Ordering::Relaxed);
    }

    fn mark_done(&self, idx: u32) {
        self.done[idx as usize].store(true, Ordering::Relaxed);
        self.written[idx as usize].store(true, Ordering::Relaxed);
        self.errors.lock().unwrap().remove(&idx);
        self.files_ok.fetch_add(1, Ordering::Relaxed);
        self.progress.files.fetch_add(1, Ordering::Relaxed);
    }

    fn write_job(&self, job: &Job) -> Result<()> {
        if self.opts.sink() {
            return self.sink_job(job);
        }
        let e = &self.entries[job.idx as usize];
        if !e.is_chunked() {
            return self.write_whole(job, e);
        }
        let c = (job.offset / CHUNK) as u32;
        let file = {
            let mut large = self.large.lock().unwrap();
            let Some(l) = large.get_mut(&job.idx) else { return Ok(()) };
            if l.failed || bit(&l.bits, c) {
                return Ok(()); // error already recorded, or a resent chunk we already have
            }
            if l.file.is_none() {
                let t = Instant::now();
                let opened = self.open_part(job.idx, e, l.resumed);
                self.t_create.add(t);
                match opened {
                    Ok((f, j)) => {
                        l.file = Some(Arc::new(f));
                        if j.is_some() {
                            l.journal = j;
                        }
                    }
                    Err(err) => {
                        l.failed = true;
                        return Err(err);
                    }
                }
            }
            l.file.clone().unwrap()
        };
        let t = Instant::now();
        write_at(&file, &job.data, job.offset).with_context(|| self.part_path(job.idx).display().to_string())?;
        self.t_write.add(t);
        if let Some(h) = &job.hash {
            self.verify(&file, job.offset, &job.data, h)?;
        }
        drop(file);
        self.bytes_ok.fetch_add(job.data.len() as u64, Ordering::Relaxed);

        let (finished, batch) = {
            let mut large = self.large.lock().unwrap();
            let Some(l) = large.get_mut(&job.idx) else { return Ok(()) };
            set_bit(&mut l.bits, c);
            l.remaining -= 1;
            l.unsynced.push(c);
            if l.remaining == 0 {
                (large.remove(&job.idx), None)
            } else if l.journal.is_some() && l.unsynced.len() >= SYNC_CHUNKS {
                (None, Some((std::mem::take(&mut l.unsynced), l.file.clone())))
            } else {
                (None, None)
            }
        };
        if let Some((chunks, Some(file))) = batch {
            self.journal_durable(job.idx, &chunks, &file)?;
        }
        if let Some(l) = finished {
            self.finalize_large(job.idx, l.file)?;
        }
        Ok(())
    }

    /// Syncs a batch of written chunks to disk (outside the lock, other files keep going), then lets the journal
    /// claim exactly those chunks.
    fn journal_durable(&self, idx: u32, chunks: &[u32], file: &File) -> Result<()> {
        let t = Instant::now();
        file.sync_data().with_context(|| format!("{}: cannot flush to disk", self.part_path(idx).display()))?;
        let mut large = self.large.lock().unwrap();
        if let Some(l) = large.get_mut(&idx) {
            for &c in chunks {
                set_bit(&mut l.durable, c);
            }
            if let Some(j) = &l.journal {
                let mut bytes: Vec<usize> = chunks.iter().map(|&c| (c / 8) as usize).collect();
                bytes.dedup();
                for b in bytes {
                    let _ = write_at(j, &l.durable[b..b + 1], JOURNAL_HEADER + b as u64);
                }
            }
        }
        self.t_journal.add(t);
        Ok(())
    }

    /// Benchmark mode: account for the piece as if written, checking its hash in memory, without any file I/O.
    fn sink_job(&self, job: &Job) -> Result<()> {
        if let Some(h) = &job.hash {
            let t = Instant::now();
            let ok = blake3::hash(&job.data).as_bytes() == h;
            self.t_verify.add(t);
            if !ok {
                bail!("checksum mismatch: data damaged in transit");
            }
        }
        self.bytes_ok.fetch_add(job.data.len() as u64, Ordering::Relaxed);
        if !self.entries[job.idx as usize].is_chunked() {
            self.mark_done(job.idx);
            return Ok(());
        }
        let c = (job.offset / CHUNK) as u32;
        let finished = {
            let mut large = self.large.lock().unwrap();
            let Some(l) = large.get_mut(&job.idx) else { return Ok(()) };
            if bit(&l.bits, c) {
                return Ok(()); // a resent chunk we already counted
            }
            set_bit(&mut l.bits, c);
            l.remaining -= 1;
            l.remaining == 0
        };
        if finished {
            self.large.lock().unwrap().remove(&job.idx);
            self.mark_done(job.idx);
        }
        Ok(())
    }

    fn write_whole(&self, job: &Job, e: &Entry) -> Result<()> {
        let path = self.path(job.idx);
        let t = Instant::now();
        let mut f = create_file(&path, self.jail.get())?;
        self.t_create.add(t);
        let t = Instant::now();
        f.write_all(&job.data).with_context(|| path.display().to_string())?;
        self.t_write.add(t);
        if let Some(h) = &job.hash {
            self.verify(&f, 0, &job.data, h)?;
        }
        let t = Instant::now();
        let ctime = if self.opts.meta() { e.ctime } else { 0 };
        meta::set_times(&f, e.mtime, ctime).with_context(|| path.display().to_string())?;
        if self.opts.meta() {
            meta::set_unix(&f, e.mode, e.uid, e.gid).with_context(|| path.display().to_string())?;
        }
        if self.sync_each.load(Ordering::Relaxed) {
            let t = Instant::now();
            f.sync_all().with_context(|| format!("{}: cannot flush to disk", path.display()))?;
            self.t_flush.add(t);
        }
        drop(f);
        if self.opts.meta() && uses_attrs(e) {
            meta::set_attrs(&path, e.attrs).with_context(|| path.display().to_string())?;
        }
        self.t_meta.add(t);
        self.bytes_ok.fetch_add(job.data.len() as u64, Ordering::Relaxed);
        self.mark_done(job.idx);
        Ok(())
    }

    /// Reads the data back from disk (through the OS cache) and compares it with the sender's hash.
    fn verify(&self, f: &File, offset: u64, data: &[u8], expected: &[u8; 32]) -> Result<()> {
        let t = Instant::now();
        let ok_in_memory = blake3::hash(data).as_bytes() == expected;
        let mut back = vec![0u8; data.len()];
        let ok_on_disk = read_at(f, &mut back, offset).is_ok() && blake3::hash(&back).as_bytes() == expected;
        self.t_verify.add(t);
        if !ok_in_memory {
            bail!("checksum mismatch: data damaged in transit");
        }
        if !ok_on_disk {
            bail!("checksum mismatch: data read back from disk differs");
        }
        Ok(())
    }

    fn open_part(&self, idx: u32, e: &Entry, resumed: bool) -> Result<(File, Option<File>)> {
        let part = self.part_path(idx);
        if resumed {
            let f = no_follow(OpenOptions::new().read(true).write(true)).open(&part).with_context(|| part.display().to_string())?;
            self.check_inside(&f, &part)?;
            return Ok((f, None));
        }
        // In a jail: truncated only after the check, so a file reached through a link is left as it was.
        let jailed = self.jail.get().is_some();
        let f = replacing_link(&part, || with_parent(&part, || no_follow(OpenOptions::new().read(true).write(true).create(true).truncate(!jailed)).open(&part)))
            .with_context(|| part.display().to_string())?;
        if jailed {
            self.check_inside(&f, &part)?;
            f.set_len(0).with_context(|| part.display().to_string())?;
        }
        f.set_len(e.size).with_context(|| format!("cannot reserve {} bytes for {}", e.size, part.display()))?;
        // The journal sits next to the part file, which was just checked.
        let j = create_journal(&self.journal_path(idx), e).ok();
        Ok((f, j))
    }

    /// All chunks are written: restore timestamps, sync, move the part file into place, drop the journal.
    fn finalize_large(&self, idx: u32, file: Option<Arc<File>>) -> Result<()> {
        let e = &self.entries[idx as usize];
        let (part, fin) = (self.part_path(idx), self.path(idx));
        let t = Instant::now();
        let file = match file {
            Some(f) => f,
            None => {
                let f = no_follow(OpenOptions::new().write(true)).open(&part).with_context(|| part.display().to_string())?;
                self.check_inside(&f, &part)?;
                Arc::new(f)
            }
        };
        let ctime = if self.opts.meta() { e.ctime } else { 0 };
        meta::set_times(&file, e.mtime, ctime)?;
        if self.opts.meta() {
            meta::set_unix(&file, e.mode, e.uid, e.gid).with_context(|| part.display().to_string())?;
        }
        // On disk before the rename: once the journal is gone and the name is final, a crash must not leave a file
        // that has the right size and time but data that never reached the disk (the next run would skip it).
        file.sync_all().with_context(|| format!("{}: cannot flush to disk", part.display()))?;
        drop(file);
        if fin.exists() {
            let _ = meta::clear_readonly(&fin);
        }
        fs::rename(&part, &fin).with_context(|| format!("cannot move {} into place", part.display()))?;
        let _ = fs::remove_file(self.journal_path(idx));
        if self.opts.meta() && uses_attrs(e) {
            meta::set_attrs(&fin, e.attrs)?;
        }
        self.t_meta.add(t);
        self.mark_done(idx);
        Ok(())
    }
}

fn writer(me: usize, sess: &DestSession, rx: Receiver<Job>) {
    use crossbeam_channel::RecvTimeoutError;
    // Writers start before the session knows its user; each one takes on the user at its first job.
    let mut user: Option<Option<crate::auth::Act>> = None;
    loop {
        if !sess.tuner.is_active(me) {
            if sess.closing.load(Ordering::Relaxed) && rx.is_empty() {
                return;
            }
            thread::sleep(Duration::from_millis(50));
            continue;
        }
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(job) => {
                if user.is_none() {
                    user = Some(sess.enter_user());
                }
                let n = job.data.len() as u64;
                if let Err(e) = sess.write_job(&job) {
                    sess.error(job.idx, format!("{e:#}"));
                }
                if sess.staged() {
                    sess.buffered.fetch_sub(n, Ordering::AcqRel);
                }
                sess.jobs_done.fetch_add(1, Ordering::Relaxed);
                sess.pending.fetch_sub(1, Ordering::Release);
            }
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => return,
        }
    }
}

/// Receives frames from one data connection until its end marker and hands them to the writers.
pub fn recv_frames(r: &mut impl Read, sess: &DestSession) -> Result<()> {
    let tx = sess.tx.lock().unwrap().clone().context("session is closing")?;
    let mut dec: Option<FrameDecoder> = None;
    let mut wire = Vec::new();
    loop {
        let t = Instant::now();
        let Some(h) = get_frame_header(r)? else { return Ok(()) };
        let e = sess.entries.get(h.idx as usize).filter(|e| e.is_file());
        let valid = e.is_some_and(|e| {
            if e.is_chunked() {
                h.offset % CHUNK == 0 && h.offset < e.size && h.raw_len as u64 == CHUNK.min(e.size - h.offset)
            } else {
                h.offset == 0 && h.raw_len as u64 == e.size
            }
        });
        if !valid {
            bail!("protocol error: bad frame (idx {}, offset {}, len {})", h.idx, h.offset, h.raw_len);
        }
        wire.resize(h.wire_len as usize, 0);
        r.read_exact(&mut wire)?;
        sess.t_net.add(t);
        let data = if h.flags & F_ZSTD != 0 {
            let t = Instant::now();
            if dec.is_none() {
                let dict = sess.dict.lock().unwrap().clone();
                dec = Some(FrameDecoder::new(&dict)?);
            }
            let d = dec.as_mut().unwrap().decompress(&wire, h.raw_len as usize)?;
            sess.t_decompress.add(t);
            d
        } else {
            std::mem::take(&mut wire)
        };
        let p = &sess.progress;
        p.raw.fetch_add(h.raw_len as u64, Ordering::Relaxed);
        p.wire.fetch_add(h.wire_len as u64, Ordering::Relaxed);
        let t = Instant::now();
        if sess.staged() {
            // Back-pressure by bytes: wait while the RAM stage is full (one oversized frame may always pass).
            let n = data.len() as u64;
            while sess.buffered.load(Ordering::Acquire) > 0 && sess.buffered.load(Ordering::Acquire) + n > sess.stage_limit {
                thread::sleep(Duration::from_millis(2));
            }
            let now = sess.buffered.fetch_add(n, Ordering::AcqRel) + n;
            sess.stage_peak.fetch_max(now, Ordering::Relaxed);
        }
        sess.pending.fetch_add(1, Ordering::AcqRel);
        if tx.send(Job { idx: h.idx, offset: h.offset, data, hash: h.hash }).is_err() {
            sess.pending.fetch_sub(1, Ordering::AcqRel);
            bail!("writers stopped");
        }
        sess.t_queue.add(t);
        sess.mark_received(h.idx, h.offset);
    }
}

/// An overlap probe: a random-named file placed in the deepest destination folder that already
/// exists. The source side looks for it in its own tree. Removed again when dropped.
pub struct Probe {
    pub name: String,
    pub dest_exists: bool,
    path: Option<PathBuf>,
}

impl Drop for Probe {
    fn drop(&mut self) {
        if let Some(p) = &self.path {
            let _ = fs::remove_file(p);
        }
    }
}

/// Places a probe for `dest`, never above `floor` (the share root on a server).
pub fn place_probe(dest: &Path, floor: Option<&Path>) -> Probe {
    let name = format!(".scopy-probe-{}", crate::util::random_hex(8));
    let existing = dest.ancestors().take_while(|p| floor.is_none_or(|f| p.starts_with(f))).find(|p| p.is_dir());
    match existing {
        Some(dir) => {
            let path = dir.join(&name);
            let written = fs::write(&path, b"scopy overlap probe").is_ok();
            Probe { name, dest_exists: dir == dest, path: written.then_some(path) }
        }
        None => Probe { name, dest_exists: false, path: None },
    }
}

fn with_suffix(p: &Path, suffix: &str) -> PathBuf {
    let mut s: OsString = p.as_os_str().to_owned();
    s.push(suffix);
    PathBuf::from(s)
}

/// `f` over `items` on up to 16 threads, results in input order.
fn par_map<T: Sync, R: Send>(items: &[T], f: impl Fn(&T) -> R + Sync) -> Vec<R> {
    const THREADS: usize = 16;
    if items.len() < 64 {
        return items.iter().map(&f).collect();
    }
    let per = items.len().div_ceil(THREADS);
    let f = &f;
    // The helpers act as whoever the calling thread acts as (on a receiver: the signed-in user).
    let who = &crate::auth::capture();
    thread::scope(|s| {
        let handles: Vec<_> = items
            .chunks(per)
            .map(|c| {
                s.spawn(move || {
                    let _act = who.enter();
                    c.iter().map(f).collect::<Vec<R>>()
                })
            })
            .collect();
        handles.into_iter().flat_map(|h| h.join().unwrap()).collect()
    })
}

/// Runs `open`; if the folder is missing (folders are created in the background while data flows), creates it
/// and tries once more.
/// Fails if an entry lies below a symbolic link of the same manifest: writing it would go through the link (which
/// may point anywhere) once the link exists.
fn no_entries_below_links(entries: &[Entry]) -> Result<()> {
    let links: HashSet<&str> = entries.iter().filter(|e| e.is_link()).map(|e| e.path.as_str()).collect();
    if links.is_empty() {
        return Ok(());
    }
    for e in entries {
        let mut p = e.path.as_str();
        while let Some(i) = p.rfind('/') {
            p = &p[..i];
            if links.contains(p) {
                bail!("protocol error: {} lies below the symbolic link {p}", e.path);
            }
        }
    }
    Ok(())
}

/// Whether the Windows attributes apply: everywhere except on Unix when the sender sent a Unix mode (which already
/// says whether the file is writable).
fn uses_attrs(e: &Entry) -> bool {
    e.attrs != 0 && !(cfg!(unix) && e.mode != 0)
}

/// Unix: the last part of the path is never followed if it is a symbolic link (the open fails with ELOOP).
fn no_follow(o: &mut OpenOptions) -> &mut OpenOptions {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.custom_flags(libc::O_NOFOLLOW)
    }
    #[cfg(not(unix))]
    o
}

/// Opens an existing file just to set its metadata, never through a link at its own name.
fn open_no_follow(path: &Path) -> io::Result<File> {
    no_follow(OpenOptions::new().read(true)).open(path)
}

/// Runs `open`; if a symbolic link stands where the file belongs (Unix: ELOOP from O_NOFOLLOW), removes the link
/// (not what it points to) and tries once more.
fn replacing_link<T>(path: &Path, open: impl Fn() -> io::Result<T>) -> io::Result<T> {
    #[cfg(not(unix))]
    let _ = path;
    match open() {
        #[cfg(unix)]
        Err(e) if e.raw_os_error() == Some(libc::ELOOP) => {
            with_parent(path, || fs::remove_file(path))?;
            open()
        }
        r => r,
    }
}

fn with_parent<T>(path: &Path, open: impl Fn() -> io::Result<T>) -> io::Result<T> {
    let r = match open() {
        Err(e) if e.kind() == io::ErrorKind::NotFound => match path.parent() {
            Some(dir) => {
                fs::create_dir_all(dir)?;
                open()
            }
            None => Err(e),
        },
        r => r,
    };
    match r {
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied && path.parent().is_some_and(unlock_dir) => open(),
        r => r,
    }
}

/// Folders `unlock_dir` made writable, with their mode before: `DestSession::relock_dirs` puts it back.
#[cfg(unix)]
static UNLOCKED: Mutex<Vec<(PathBuf, u32)>> = Mutex::new(Vec::new());

/// Unix: a folder of ours whose mode forbids writing (e.g. 0555) gets the owner's write bit while the job writes into
/// it, as rsync does; the mode is restored at the end of the job (the sender's, or the one it had). Returns whether
/// it changed anything (then the caller tries again).
fn unlock_dir(dir: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let Ok(md) = fs::symlink_metadata(dir) else { return false };
        if !md.is_dir() || md.uid() != meta::acting_uid() {
            return false;
        }
        if md.mode() & 0o200 != 0 {
            // Another writer unlocked it a moment ago: worth one more try.
            return true;
        }
        let old = md.mode() & 0o7777;
        if fs::set_permissions(dir, fs::Permissions::from_mode(old | 0o200)).is_err() {
            return false;
        }
        UNLOCKED.lock().unwrap().push((dir.to_path_buf(), old));
        true
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
        false
    }
}

/// Creates or overwrites a file. In a jail the file is checked before it is truncated: one reached through a
/// junction or symbolic link outside the share is refused and left unchanged.
fn create_file(path: &Path, jail: Option<&Jail>) -> Result<File> {
    let open = || replacing_link(path, || with_parent(path, || no_follow(OpenOptions::new().read(true).write(true).create(true).truncate(jail.is_none())).open(path)));
    let checked = |f: File| -> Result<File> {
        if let Some(j) = jail {
            j.check(&f, path)?;
            f.set_len(0).with_context(|| path.display().to_string())?;
        }
        Ok(f)
    };
    match open() {
        Ok(f) => checked(f),
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
            // Overwriting a read-only file: clear the flag and retry once.
            if fs::metadata(path).map(|m| m.permissions().readonly()).unwrap_or(false) {
                if let Some(j) = jail {
                    // Only clear the flag of a file inside the share (opened without any access to its data).
                    j.check(&meta::open_to_look(path).with_context(|| path.display().to_string())?, path)?;
                }
                meta::clear_readonly(path)?;
                return checked(open().with_context(|| path.display().to_string())?);
            }
            Err(e).with_context(|| path.display().to_string())
        }
        Err(e) => Err(e).with_context(|| path.display().to_string()),
    }
}

fn create_journal(path: &Path, e: &Entry) -> io::Result<File> {
    let mut f = OpenOptions::new().read(true).write(true).create(true).truncate(true).open(path)?;
    let n = chunk_count(e.size);
    let mut buf = Vec::with_capacity(JOURNAL_HEADER as usize + n as usize / 8 + 1);
    buf.extend_from_slice(JOURNAL_MAGIC);
    buf.extend_from_slice(&1u32.to_le_bytes());
    buf.extend_from_slice(&e.size.to_le_bytes());
    buf.extend_from_slice(&e.mtime.to_le_bytes());
    buf.extend_from_slice(&CHUNK.to_le_bytes());
    buf.extend_from_slice(&n.to_le_bytes());
    buf.resize(JOURNAL_HEADER as usize + (n as usize).div_ceil(8), 0);
    f.write_all(&buf)?;
    let _ = meta::set_attrs(path, meta::ATTR_HIDDEN);
    Ok(f)
}

/// Loads a journal left by an interrupted run, if it belongs to this exact source file.
fn load_journal(path: &Path, part: &Path, e: &Entry) -> Option<(Vec<u8>, File)> {
    let mut f = OpenOptions::new().read(true).write(true).open(path).ok()?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf).ok()?;
    let n = chunk_count(e.size);
    let want = JOURNAL_HEADER as usize + (n as usize).div_ceil(8);
    let u64_at = |o: usize| u64::from_le_bytes(buf[o..o + 8].try_into().unwrap());
    let ok = buf.len() == want
        && &buf[0..4] == JOURNAL_MAGIC
        && buf[4..8] == 1u32.to_le_bytes()
        && u64_at(8) == e.size
        && u64_at(16) as i64 == e.mtime
        && u64_at(24) == CHUNK
        && buf[32..36] == n.to_le_bytes()
        && fs::metadata(part).is_ok_and(|m| m.len() == e.size);
    ok.then(|| (buf[JOURNAL_HEADER as usize..].to_vec(), f))
}

#[cfg(windows)]
fn write_at(f: &File, mut buf: &[u8], mut off: u64) -> io::Result<()> {
    use std::os::windows::fs::FileExt;
    while !buf.is_empty() {
        let n = f.seek_write(buf, off)?;
        if n == 0 {
            return Err(io::ErrorKind::WriteZero.into());
        }
        buf = &buf[n..];
        off += n as u64;
    }
    Ok(())
}

#[cfg(unix)]
fn write_at(f: &File, buf: &[u8], off: u64) -> io::Result<()> {
    use std::os::unix::fs::FileExt;
    f.write_all_at(buf, off)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(kind: u8, path: &str) -> Entry {
        Entry { kind, path: path.into(), size: if kind == ENTRY_FILE { 3 } else { 0 }, ..Entry::default() }
    }

    #[test]
    fn survey_skips_below_missing_folders_and_creation_fills_them() {
        let base = std::env::temp_dir().join(format!("scopy-survey-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(base.join("old")).unwrap();
        let entries = vec![
            entry(ENTRY_DIR, "old"),
            entry(ENTRY_FILE, "old/a.txt"),
            entry(ENTRY_DIR, "new"),
            entry(ENTRY_DIR, "new/deep"),
            entry(ENTRY_FILE, "new/deep/b.txt"),
            entry(ENTRY_FILE, "top.txt"),
        ];
        let sess = DestSession::new(base.clone(), entries, Options::default(), Tuner::fixed(1).into(), Arc::new(Progress::default()))
            .unwrap();
        assert_eq!(sess.survey_dirs(), (3, 2)); // old, new, new/deep needed; new and new/deep missing
        assert!(!sess.in_new_dir(1) && sess.in_new_dir(4) && !sess.in_new_dir(5));
        assert_eq!(sess.initial_plan().len(), 3);
        assert_eq!(sess.create_dirs().unwrap(), 2);
        assert!(base.join("new/deep").is_dir());
        sess.finish();
        fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn empty_destination_skips_the_survey() {
        let base = std::env::temp_dir().join(format!("scopy-empty-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).unwrap();
        let entries = vec![entry(ENTRY_DIR, "a"), entry(ENTRY_DIR, "a/b"), entry(ENTRY_FILE, "a/b/c.txt"), entry(ENTRY_FILE, "d.txt")];
        let sess = DestSession::new(base.clone(), entries, Options::default(), Tuner::fixed(1).into(), Arc::new(Progress::default()))
            .unwrap();
        assert_eq!(sess.survey_dirs(), (2, 2));
        assert!(sess.in_new_dir(2) && sess.in_new_dir(3));
        assert_eq!(sess.initial_plan().len(), 2);
        assert_eq!(sess.create_dirs().unwrap(), 2);
        assert!(base.join("a/b").is_dir());
        sess.finish();
        fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn writers_create_a_missing_folder_themselves() {
        let base = std::env::temp_dir().join(format!("scopy-parent-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let f = base.join("x").join("y").join("z.txt");
        create_file(&f, None).unwrap();
        assert!(f.is_file());
        fs::remove_dir_all(&base).unwrap();
    }

    fn session(base: &Path, entries: Vec<Entry>) -> Arc<DestSession> {
        DestSession::new(base.to_path_buf(), entries, Options::default(), Tuner::fixed(1).into(), Arc::new(Progress::default())).unwrap()
    }

    #[test]
    fn journal_never_claims_chunks_that_are_not_synced() {
        let base = std::env::temp_dir().join(format!("scopy-journal-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).unwrap();
        let big = Entry { kind: ENTRY_FILE, path: "big.bin".into(), size: 3 * CHUNK, mtime: 0, ctime: 0, attrs: 0, ..Entry::default() };
        let sess = session(&base, vec![big]);
        sess.survey_dirs();
        assert_eq!(sess.initial_plan().len(), 1);
        for c in 0..2u64 {
            sess.write_job(&Job { idx: 0, offset: c * CHUNK, data: vec![7u8; CHUNK as usize], hash: None }).unwrap();
        }
        // Two of three chunks written, fewer than a sync batch: the journal must still claim nothing.
        let journal = fs::read(sess.journal_path(0)).unwrap();
        assert!(journal[JOURNAL_HEADER as usize..].iter().all(|&b| b == 0), "journal claims unsynced chunks");
        sess.write_job(&Job { idx: 0, offset: 2 * CHUNK, data: vec![7u8; CHUNK as usize], hash: None }).unwrap();
        // Complete: synced, renamed into place, journal gone.
        assert_eq!(fs::metadata(base.join("big.bin")).unwrap().len(), 3 * CHUNK);
        assert!(!sess.journal_path(0).exists());
        sess.finish();
        fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn files_of_an_interrupted_job_are_not_trusted() {
        let base = std::env::temp_dir().join(format!("scopy-suspect-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).unwrap();
        fs::write(base.join("a.txt"), b"abc").unwrap();
        let mtime = to_nanos(fs::metadata(base.join("a.txt")).unwrap().modified().unwrap());
        let a = Entry { kind: ENTRY_FILE, path: "a.txt".into(), size: 3, mtime, ctime: 0, attrs: 0, ..Entry::default() };
        // Size and time match: normally skipped as up to date.
        let sess = session(&base, vec![a.clone()]);
        sess.survey_dirs();
        assert_eq!(sess.initial_plan().len(), 0);
        sess.finish();
        // The same file listed by an interrupted job: sent again.
        let sess = session(&base, vec![a]);
        sess.set_suspect(["a.txt".to_string()].into_iter().collect());
        sess.survey_dirs();
        assert_eq!(sess.initial_plan().len(), 1);
        sess.finish();
        fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn a_confined_job_never_writes_through_a_link() {
        let t = std::env::temp_dir().join(format!("scopy-jail-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&t);
        let (share, outside) = (t.join("share"), t.join("outside"));
        fs::create_dir_all(share.join("in")).unwrap();
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("victim.txt"), b"keep").unwrap();
        let entries = || vec![entry(ENTRY_DIR, "evil"), entry(ENTRY_FILE, "evil/victim.txt"), entry(ENTRY_FILE, "ok.txt")];
        let job = |idx| Job { idx, offset: 0, data: b"bad".to_vec(), hash: None };

        // Empty destination, so no folder survey: a link created afterwards (while the job runs) is caught when
        // the file is opened, before anything is truncated or written.
        let sess = session(&share.join("in"), entries());
        sess.confine(&share).unwrap();
        sess.survey_dirs();
        sess.initial_plan();
        assert!(crate::confine::tests::link_dir(&outside, &share.join("in").join("evil")), "cannot create a junction");
        let e = format!("{:#}", sess.write_job(&job(1)).unwrap_err());
        assert!(e.contains("outside the share"), "{e}");
        sess.write_job(&job(2)).unwrap();
        sess.finish();
        assert_eq!(fs::read(outside.join("victim.txt")).unwrap(), b"keep");

        // The link exists before the job: the folder survey refuses the whole job.
        let sess = session(&share.join("in"), entries());
        sess.confine(&share).unwrap();
        sess.survey_dirs();
        assert!(sess.check_links().unwrap_err().to_string().contains("junction or symbolic link"));
        sess.finish();
        let _ = fs::remove_dir(share.join("in").join("evil"));
        assert_eq!(fs::read(outside.join("victim.txt")).unwrap(), b"keep");
        fs::remove_dir_all(&t).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn unix_mode_and_links_arrive_and_unchanged_files_get_their_mode_fixed() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let base = std::env::temp_dir().join(format!("scopy-unix-meta-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let (uid, gid) = (unsafe { libc::geteuid() }, unsafe { libc::getegid() });
        let mtime = 1_700_000_000_123_456_789;
        let m = |mode| MODE_SET | mode;
        let entries = |run_mode| {
            vec![
                Entry { kind: ENTRY_DIR, path: "d".into(), mtime, mode: m(0o750), uid, gid, ..Entry::default() },
                Entry { kind: ENTRY_FILE, path: "d/run.sh".into(), size: 3, mtime, mode: m(run_mode), uid, gid, ..Entry::default() },
                Entry { kind: ENTRY_FILE, path: "d/secret".into(), size: 3, mtime, mode: m(0o400), uid, gid, ..Entry::default() },
                Entry { kind: ENTRY_LINK, path: "d/latest".into(), mtime, mode: m(0o777), uid, gid, link: "run.sh".into(), ..Entry::default() },
                Entry { kind: ENTRY_LINK, path: "abs".into(), mtime, mode: m(0o777), uid, gid, link: "/nonexistent/x".into(), ..Entry::default() },
            ]
        };
        let sess = session(&base, entries(0o755));
        sess.survey_dirs();
        sess.create_dirs().unwrap();
        assert_eq!(sess.initial_plan().len(), 2);
        sess.write_job(&Job { idx: 1, offset: 0, data: b"#!x".to_vec(), hash: None }).unwrap();
        sess.write_job(&Job { idx: 2, offset: 0, data: b"pss".to_vec(), hash: None }).unwrap();
        let res = sess.finish();
        assert!(res.errors.is_empty(), "{:?}", res.errors);
        let mode = |p: &str| fs::symlink_metadata(base.join(p)).unwrap().mode() & 0o7777;
        assert_eq!((mode("d"), mode("d/run.sh"), mode("d/secret")), (0o750, 0o755, 0o400));
        assert_eq!(fs::read_link(base.join("d/latest")).unwrap(), Path::new("run.sh"));
        assert_eq!(fs::read_link(base.join("abs")).unwrap(), Path::new("/nonexistent/x"));
        // The link's own time, not its target's.
        assert_eq!(to_nanos(fs::symlink_metadata(base.join("abs")).unwrap().modified().unwrap()), mtime);
        assert_eq!(to_nanos(fs::metadata(base.join("d")).unwrap().modified().unwrap()), mtime);

        // Again with run.sh now 0700 on the sender: nothing is re-sent, the mode is fixed; the links stay.
        let sess = session(&base, entries(0o700));
        sess.survey_dirs();
        assert_eq!(sess.initial_plan().len(), 0);
        let res = sess.finish();
        assert!(res.errors.is_empty(), "{:?}", res.errors);
        assert_eq!(mode("d/run.sh"), 0o700);
        assert_eq!(fs::read_link(base.join("d/latest")).unwrap(), Path::new("run.sh"));
        fs::set_permissions(base.join("d"), fs::Permissions::from_mode(0o755)).unwrap();
        fs::remove_dir_all(&base).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn never_writes_through_a_link_at_the_destination() {
        let t = std::env::temp_dir().join(format!("scopy-unix-link-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&t);
        let (base, outside) = (t.join("dest"), t.join("outside"));
        fs::create_dir_all(&base).unwrap();
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("victim.txt"), b"keep").unwrap();
        // A link where a file belongs (left by an earlier copy): replaced by the file, the target untouched.
        std::os::unix::fs::symlink(outside.join("victim.txt"), base.join("a.txt")).unwrap();
        let sess = session(&base, vec![entry(ENTRY_FILE, "a.txt")]);
        sess.survey_dirs();
        assert_eq!(sess.initial_plan().len(), 1, "a link must not count as the file being up to date");
        sess.write_job(&Job { idx: 0, offset: 0, data: b"new".to_vec(), hash: None }).unwrap();
        assert!(sess.finish().errors.is_empty());
        assert!(fs::symlink_metadata(base.join("a.txt")).unwrap().is_file());
        assert_eq!(fs::read(base.join("a.txt")).unwrap(), b"new");
        assert_eq!(fs::read(outside.join("victim.txt")).unwrap(), b"keep");

        // A link where a folder belongs: the job is refused, also without a jail.
        std::os::unix::fs::symlink(&outside, base.join("sub")).unwrap();
        let sess = session(&base, vec![entry(ENTRY_DIR, "sub"), entry(ENTRY_FILE, "sub/victim.txt")]);
        sess.survey_dirs();
        assert!(sess.check_links().unwrap_err().to_string().contains("symbolic link"));
        sess.finish();
        assert_eq!(fs::read(outside.join("victim.txt")).unwrap(), b"keep");

        // A read-only folder of ours (0555) that already exists: a new file still goes in, the mode stays.
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            fs::create_dir(base.join("ro")).unwrap();
            fs::set_permissions(base.join("ro"), fs::Permissions::from_mode(0o555)).unwrap();
            let sess = session(&base, vec![entry(ENTRY_DIR, "ro"), entry(ENTRY_FILE, "ro/new.txt")]);
            sess.survey_dirs();
            assert_eq!(sess.initial_plan().len(), 1);
            sess.write_job(&Job { idx: 1, offset: 0, data: b"new".to_vec(), hash: None }).unwrap();
            assert!(sess.finish().errors.is_empty());
            assert_eq!(fs::read(base.join("ro/new.txt")).unwrap(), b"new");
            assert_eq!(fs::metadata(base.join("ro")).unwrap().mode() & 0o7777, 0o555);
            fs::set_permissions(base.join("ro"), fs::Permissions::from_mode(0o755)).unwrap();
        }

        // A manifest with something below one of its own links is refused outright.
        let bad = vec![
            Entry { kind: ENTRY_LINK, path: "l".into(), link: "/tmp".into(), ..Entry::default() },
            entry(ENTRY_FILE, "l/x.txt"),
        ];
        let err = DestSession::new(base.clone(), bad, Options::default(), Tuner::fixed(1).into(), Arc::new(Progress::default())).err().unwrap();
        assert!(err.to_string().contains("below the symbolic link"), "{err}");
        fs::remove_dir_all(&t).unwrap();
    }

    #[test]
    fn commit_flushes_what_it_wrote() {
        let base = std::env::temp_dir().join(format!("scopy-flush-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let sess = session(&base, vec![Entry { kind: ENTRY_FILE, path: "f.txt".into(), size: 3, mtime: 0, ctime: 0, attrs: 0, ..Entry::default() }]);
        sess.survey_dirs();
        sess.create_dirs().unwrap();
        assert_eq!(sess.initial_plan().len(), 1);
        sess.write_job(&Job { idx: 0, offset: 0, data: b"xyz".to_vec(), hash: None }).unwrap();
        let res = sess.finish();
        assert!(res.errors.is_empty(), "{:?}", res.errors);
        // Whole volume (with admin rights) or file by file (without): either way it ran.
        assert!(sess.flush_mode.load(Ordering::Relaxed) > 0);
        fs::remove_dir_all(&base).unwrap();
    }
}
