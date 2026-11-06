//! Server change feed for two-way sync (protocol 16, `KIND_WATCH`).
//!
//! A PC's sync agent keeps one connection open to its receiver. The receiver watches that PC's sync folders and
//! tells it within about a second when something changed there that the PC did not write itself: a terminal server
//! saving onto the share, another PC's round, an admin copying files in. The PC then runs a round for that folder.
//! So changes on the server reach the PCs in seconds, not at the next timed listing (which stays as a safety net).
//!
//! What a PC writes itself is not reported back to it: a sync push registers the paths it touches (`Writes::begin`)
//! for as long as it runs and a few seconds after, and the feed leaves events on those paths (and their folders) out
//! for that PC only. Other PCs of the same user still hear about them.
//!
//! The feed only says *when* to look, not *what* changed: the round still lists the folder (KIND_LIST). A change
//! the feed misses (connection down, watch buffer overflow) is caught by the reconnect round, the overflow ping or
//! at the latest by the timed listing.

use crate::util::sanitize_rel;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// How long a push's paths stay "its own" after it ended (events can come in after the commit).
const LINGER: Duration = Duration::from_secs(5);
/// Events are collected this long before the PC is told (a save is a burst of events).
pub const DEBOUNCE: Duration = Duration::from_millis(800);
/// With nothing to report, the receiver says "still here" this often; the PC gives up after three missed ones.
pub const HEARTBEAT: Duration = Duration::from_secs(30);
/// The folder index that means "still here" (no change).
pub const ALIVE: u32 = u32::MAX;
/// A PC watches at most this many folders on one connection.
pub const MAX_FOLDERS: u32 = 64;

/// The key of a folder or file: NTFS names are case-insensitive.
fn key(p: &str) -> String {
    crate::util::path_key(p)
}

struct Write {
    id: u64,
    base: String,
    pc: String,
    /// Relative paths (keys) the push touches, with all their parent folders.
    paths: Arc<HashSet<String>>,
    until: Option<Instant>,
}

/// The sync pushes that are running (or just ended), so the feed can leave a PC's own writes out.
#[derive(Default)]
pub struct Writes {
    m: Mutex<Vec<Write>>,
    next: AtomicU64,
}

/// Ends a push's registration (after LINGER) when dropped.
pub struct WriteGuard<'a> {
    w: &'a Writes,
    id: u64,
}

impl Drop for WriteGuard<'_> {
    fn drop(&mut self) {
        let until = Instant::now() + LINGER;
        for x in self.w.m.lock().unwrap().iter_mut().filter(|x| x.id == self.id) {
            x.until = Some(until);
        }
    }
}

impl Writes {
    /// Registers what a sync push from `pc` into `base` touches (relative paths: files, folders, move sources and
    /// targets, deletes).
    pub fn begin<'a>(&'a self, base: &Path, pc: &str, rels: impl IntoIterator<Item = String>) -> WriteGuard<'a> {
        let mut paths = HashSet::new();
        for r in rels {
            let mut k = key(&r);
            while !k.is_empty() {
                if !paths.insert(k.clone()) {
                    break; // its parents are in already
                }
                k = k.rsplit_once('/').map(|(p, _)| p.to_string()).unwrap_or_default();
            }
        }
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let mut m = self.m.lock().unwrap();
        let now = Instant::now();
        m.retain(|x| x.until.is_none_or(|u| u > now));
        m.push(Write { id, base: key(&base.to_string_lossy()), pc: pc.to_lowercase(), paths: Arc::new(paths), until: None });
        WriteGuard { w: self, id }
    }

    /// Whether `rel` in `base` is something `pc`'s own push touches (or just touched).
    pub fn own(&self, base: &str, pc: &str, rel: &str) -> bool {
        let now = Instant::now();
        let (rel, pc) = (key(rel), pc.to_lowercase());
        self.m.lock().unwrap().iter().any(|x| x.until.is_none_or(|u| u > now) && x.base == base && x.pc == pc && x.paths.contains(&rel))
    }
}

/// A watched folder: its key and its path as the watcher reports it.
pub struct Folder {
    pub base: PathBuf,
    pub key: String,
}

impl Folder {
    pub fn new(base: PathBuf) -> Folder {
        let key = key(&base.to_string_lossy());
        Folder { base, key }
    }
}

/// Which folders a burst of changed paths concerns for `pc`: index into `folders`. Scopy's own files (tickets,
/// probes, part files, the recycle bin) and what the PC wrote itself are left out; `rescan` (the watch lost events)
/// reports every folder.
pub fn changed(folders: &[Folder], writes: &Writes, pc: &str, paths: &[PathBuf], rescan: bool) -> Vec<u32> {
    let mut hit = vec![rescan; folders.len()];
    for p in paths {
        for (i, f) in folders.iter().enumerate() {
            if hit[i] {
                continue;
            }
            let Ok(rel) = p.strip_prefix(&f.base) else { continue };
            let rel = rel.to_string_lossy().replace('\\', "/");
            if rel.is_empty() || rel.contains(".scopy-") || sanitize_rel(&rel, false).is_err() {
                continue;
            }
            if !writes.own(&f.key, pc, &rel) {
                hit[i] = true;
            }
        }
    }
    hit.iter().enumerate().filter(|(_, h)| **h).map(|(i, _)| i as u32).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pcs_own_writes_are_not_reported_back_to_it() {
        let w = Writes::default();
        let base = PathBuf::from(r"D:\data\users\ann\Documents");
        let folders = [Folder::new(base.clone())];
        let ev = |rel: &str| vec![base.join(rel)];
        let g = w.begin(&base, "LAPTOP1", ["Reports/q3.docx".to_string(), "Old.txt".to_string()]);
        // The PC's own file, its folder, the folder itself: left out for that PC ...
        assert!(changed(&folders, &w, "laptop1", &ev(r"Reports\Q3.docx"), false).is_empty());
        assert!(changed(&folders, &w, "LAPTOP1", &ev("Reports"), false).is_empty());
        assert!(changed(&folders, &w, "LAPTOP1", &ev("old.txt"), false).is_empty());
        // ... but not for another PC, and not other files
        assert_eq!(changed(&folders, &w, "TS1", &ev(r"Reports\q3.docx"), false), vec![0]);
        assert_eq!(changed(&folders, &w, "LAPTOP1", &ev(r"Reports\other.xlsx"), false), vec![0]);
        // scopy's own files never; a lost-events rescan always
        assert!(changed(&folders, &w, "TS1", &ev(r".scopy-recycle\Documents\x.txt"), false).is_empty());
        assert!(changed(&folders, &w, "TS1", &ev(r"Reports\.scopy-part-1"), false).is_empty());
        assert_eq!(changed(&folders, &w, "LAPTOP1", &[], true), vec![0]);
        // Other folders are not concerned
        assert!(changed(&folders, &w, "TS1", &[PathBuf::from(r"D:\data\users\bob\Documents\a.txt")], false).is_empty());
        // After the push the paths stay its own for LINGER, then they are reported again.
        drop(g);
        assert!(changed(&folders, &w, "LAPTOP1", &ev(r"Reports\q3.docx"), false).is_empty());
        for x in w.m.lock().unwrap().iter_mut() {
            x.until = Some(Instant::now());
        }
        assert_eq!(changed(&folders, &w, "LAPTOP1", &ev(r"Reports\q3.docx"), false), vec![0]);
    }
}

/// What changed in one watched folder while a PC's feed is connected: each path an event named, with the sequence
/// number of its last event. A listing (KIND_LIST) can then answer "what changed since seq N" with just those
/// paths, looked at as they are now, instead of the whole folder. The log lives as long as the feed connection
/// (`epoch` is new for each); lost events (watch overflow) or a log too long make older cursors unanswerable.
pub struct Journal {
    pub epoch: u64,
    /// The Windows user (SID) whose feed keeps this log: only that user's listings may use it.
    pub sid: String,
    seq: u64,
    valid_from: u64,
    touched: std::collections::HashMap<String, u64>,
    /// The sequence number of the last event, and of the cursor the PC's last listing got: a ping for events that
    /// listing already covered would only start an empty round.
    pub last_event: u64,
    listed: u64,
}

/// A log longer than this is dropped (the next listing is a full one).
const JOURNAL_MAX: usize = 50_000;

impl Journal {
    fn new(sid: &str) -> Journal {
        let epoch = u64::from_str_radix(&crate::util::random_hex(8), 16).unwrap_or(1).max(1);
        Journal { epoch, sid: sid.to_string(), seq: 1, valid_from: 1, touched: Default::default(), last_event: 0, listed: 0 }
    }

    /// An event named `rel` (relative to the folder, '/'-separated).
    pub fn note(&mut self, rel: String) {
        self.seq += 1;
        self.last_event = self.seq;
        self.touched.insert(rel, self.seq);
        if self.touched.len() > JOURNAL_MAX {
            self.lost();
        }
    }

    /// Events were lost: nothing before now can be answered from the log.
    pub fn lost(&mut self) {
        self.seq += 1;
        self.valid_from = self.seq;
        self.last_event = self.seq;
        self.touched.clear();
    }

    /// The PC got a listing as of `seq` (its new cursor).
    pub fn listed(&mut self, seq: u64) {
        self.listed = self.listed.max(seq);
    }

    /// Whether events came in that the PC's last listing does not cover yet.
    pub fn news(&self) -> bool {
        self.last_event > self.listed
    }

    pub fn cursor(&self) -> (u64, u64) {
        (self.epoch, self.seq)
    }

    /// The paths changed after cursor (`epoch`, `seq`); None if the log can't tell (another feed connection, events
    /// lost since, or no cursor).
    pub fn since(&self, epoch: u64, seq: u64) -> Option<Vec<String>> {
        if epoch != self.epoch || seq == 0 || seq < self.valid_from || seq > self.seq {
            return None;
        }
        Some(self.touched.iter().filter(|(_, s)| **s > seq).map(|(p, _)| p.clone()).collect())
    }
}

/// The change logs of the connected feeds, by PC and folder.
#[derive(Default)]
pub struct Journals {
    m: Mutex<std::collections::HashMap<String, Arc<Mutex<Journal>>>>,
}

fn jkey(pc: &str, base_key: &str) -> String {
    format!("{}|{base_key}", pc.to_lowercase())
}

impl Journals {
    /// A new log for `pc`'s folder (replaces an older connection's).
    pub fn open(&self, pc: &str, base_key: &str, sid: &str) -> Arc<Mutex<Journal>> {
        let j = Arc::new(Mutex::new(Journal::new(sid)));
        self.m.lock().unwrap().insert(jkey(pc, base_key), j.clone());
        j
    }

    /// Ends the log `epoch` when its feed connection ends (a newer connection's log stays).
    pub fn close(&self, pc: &str, base_key: &str, epoch: u64) {
        let mut m = self.m.lock().unwrap();
        let k = jkey(pc, base_key);
        if m.get(&k).is_some_and(|j| j.lock().unwrap().epoch == epoch) {
            m.remove(&k);
        }
    }

    pub fn get(&self, pc: &str, base: &Path) -> Option<Arc<Mutex<Journal>>> {
        self.m.lock().unwrap().get(&jkey(pc, &key(&base.to_string_lossy()))).cloned()
    }
}

/// The folder-relative path of an event path in `f` ('/'-separated), if it lies inside and isn't scopy's own.
pub fn rel_in(f: &Folder, p: &Path) -> Option<String> {
    let rel = p.strip_prefix(&f.base).ok()?.to_string_lossy().replace('\\', "/");
    (!rel.is_empty() && !rel.contains(".scopy-") && sanitize_rel(&rel, false).is_ok()).then_some(rel)
}

#[cfg(test)]
mod journal_tests {
    use super::*;

    #[test]
    fn a_journal_answers_only_cursors_it_can_vouch_for() {
        let mut j = Journal::new("S-1-5-21-1-1001");
        let (e, s0) = j.cursor();
        j.note("a.txt".into());
        j.note("docs/b.txt".into());
        let (_, s1) = j.cursor();
        j.note("a.txt".into());
        let mut got = j.since(e, s0).unwrap();
        got.sort();
        assert_eq!(got, ["a.txt", "docs/b.txt"]);
        assert_eq!(j.since(e, s1).unwrap(), ["a.txt"]);
        assert!(j.since(e, j.cursor().1).unwrap().is_empty());
        // another epoch, no cursor, a cursor from the future: no answer
        assert!(j.since(e ^ 1, s1).is_none() && j.since(e, 0).is_none() && j.since(e, 999).is_none());
        // lost events: older cursors can't be answered, a cursor taken after can
        j.lost();
        assert!(j.since(e, s1).is_none());
        let (_, s2) = j.cursor();
        j.note("c.txt".into());
        assert_eq!(j.since(e, s2).unwrap(), ["c.txt"]);
        // A listing that covered the last event: nothing new to ping about until the next event
        assert!(j.news());
        j.listed(j.cursor().1);
        assert!(!j.news());
        j.note("d.txt".into());
        assert!(j.news());
    }
}
