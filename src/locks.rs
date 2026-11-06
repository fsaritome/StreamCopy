//! Receiver: open-file locks for two-way sync (DESIGN-SYNC, files in use; protocol 15, KIND_LOCKS).
//!
//! While a document is open on a PC (Word, Excel, …), that PC's agent claims it. The receiver then holds the server's
//! copy open itself — others may read it, nobody may change, move or delete it — and puts the PC's Office owner file
//! (`~$…`, which names the user) next to it. Word on a terminal server, or anyone over SMB, so meets exactly what a
//! file open on the share would show: "locked for editing by …", read-only or a copy. Another PC learns of the lock
//! from its own claims call and keeps its copy read-only.
//!
//! A claim lasts as long as the PC keeps claiming it (every sync round), or for the lease time after the PC's last
//! call (asleep, offline): long enough for the "forgot to close Word, went to the terminal server" case, short enough
//! that a lost notebook doesn't block the file for good. The lock owner's own sync push lets go of the lock for the
//! moment it replaces the file, then takes it again.

use crate::logln;
use crate::proto::{LockClaim, LockInfo, LOCK_HELD, LOCK_OPEN_THERE, LOCK_REFUSED};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

struct Lock {
    sid: String,
    pc: String,
    user: String,
    /// The sync folder (lower-case key) and the file's path inside it.
    base: String,
    rel: String,
    path: PathBuf,
    since: u64,
    until: Instant,
    /// The handle that denies writing to everyone else; None while the owner's own push replaces the file.
    file: Option<File>,
    /// The owner file this lock put next to the document (removed with the lock).
    owner: Option<PathBuf>,
}

#[derive(Default)]
pub struct Locks {
    m: Mutex<HashMap<String, Lock>>,
}

fn key(p: &Path) -> String {
    let s = p.to_string_lossy();
    if cfg!(windows) { s.to_lowercase() } else { s.into_owned() }
}

/// Opens the file so that others may read it but not write, rename or delete it.
fn hold(p: &Path) -> std::io::Result<File> {
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        fs::OpenOptions::new().read(true).share_mode(1).open(p) // FILE_SHARE_READ only
    }
    #[cfg(not(windows))]
    {
        File::open(p) // advisory only on Unix: others are not blocked
    }
}

fn open_elsewhere(e: &std::io::Error) -> bool {
    matches!(e.raw_os_error(), Some(32) | Some(33)) // sharing / lock violation
}

/// Puts the PC's Office owner file next to the document (hidden), so Office on the server names the user.
fn write_owner(full: &Path, c: &LockClaim) -> Option<PathBuf> {
    if c.owner.is_empty() || c.owner.len() > 4096 || !c.owner_name.starts_with("~$") || c.owner_name.contains(['/', '\\']) {
        return None;
    }
    let p = full.parent()?.join(&c.owner_name);
    if p.exists() {
        return None; // someone's own owner file (Office running on the server): left alone
    }
    fs::write(&p, &c.owner).ok()?;
    let _ = crate::meta::set_attrs(&p, crate::meta::ATTR_HIDDEN);
    Some(p)
}

fn release(l: Lock, why: &str) {
    drop(l.file);
    if let Some(o) = &l.owner {
        let _ = fs::remove_file(o);
    }
    logln!("lock released ({why}): {} ({} on {})", l.path.display(), l.user, l.pc);
}

impl Locks {
    /// A PC's claims for one sync folder (`base`, as the receiver resolves it): takes or renews each lock and lets go
    /// of the PC's earlier claims there that it no longer makes. Returns a LOCK_* state per claim.
    pub fn claim(&self, base: &Path, sid: &str, user: &str, pc: &str, claims: &[LockClaim], lease: Duration) -> Vec<u8> {
        let mut m = self.m.lock().unwrap();
        let now = Instant::now();
        let bk = key(base);
        let wanted: HashSet<String> = claims.iter().filter_map(|c| crate::util::sanitize_rel(&c.path, false).ok().map(|r| key(&base.join(r)))).collect();
        let gone: Vec<String> = m.iter().filter(|(k, l)| l.sid == sid && l.pc == pc && l.base == bk && !wanted.contains(*k)).map(|(k, _)| k.clone()).collect();
        for k in gone {
            if let Some(l) = m.remove(&k) {
                release(l, "closed on the PC");
            }
        }
        claims
            .iter()
            .map(|c| {
                let Ok(rel) = crate::util::sanitize_rel(&c.path, false) else { return LOCK_REFUSED };
                if c.path.contains(".scopy-") {
                    return LOCK_REFUSED;
                }
                let full = base.join(&rel);
                let k = key(&full);
                if let Some(l) = m.get_mut(&k) {
                    if l.sid != sid || l.pc != pc {
                        return LOCK_REFUSED; // another PC has it open
                    }
                    l.until = now + lease;
                    if l.file.is_none() {
                        l.file = hold(&full).ok();
                    }
                    return LOCK_HELD;
                }
                if crate::confine::no_links_below(base, &full).is_err() || !full.is_file() {
                    return LOCK_REFUSED;
                }
                match hold(&full) {
                    Ok(f) => {
                        let owner = write_owner(&full, c);
                        logln!("lock: {} open on {} ({user}), locked for everyone else", full.display(), pc);
                        let l = Lock {
                            sid: sid.into(),
                            pc: pc.into(),
                            user: user.into(),
                            base: bk.clone(),
                            rel: c.path.clone(),
                            path: full,
                            since: crate::status::now(),
                            until: now + lease,
                            file: Some(f),
                            owner,
                        };
                        m.insert(k, l);
                        LOCK_HELD
                    }
                    Err(e) if open_elsewhere(&e) => LOCK_OPEN_THERE,
                    Err(_) => LOCK_REFUSED,
                }
            })
            .collect()
    }

    /// The locks in a sync folder held by other PCs (or other users).
    pub fn others(&self, base: &Path, sid: &str, pc: &str) -> Vec<LockInfo> {
        let bk = key(base);
        let m = self.m.lock().unwrap();
        m.values()
            .filter(|l| l.base == bk && !(l.sid == sid && l.pc == pc))
            .map(|l| LockInfo { path: l.rel.clone(), pc: l.pc.clone(), user: l.user.clone(), since: l.since })
            .collect()
    }

    /// The lock owner's own sync push: lets go of its locks on `rels` so the push can replace those files; `resume`
    /// takes them again afterwards.
    pub fn suspend(&self, base: &Path, sid: &str, pc: &str, rels: &HashSet<String>) -> Vec<String> {
        let bk = key(base);
        let mut m = self.m.lock().unwrap();
        let mut out = Vec::new();
        for (k, l) in m.iter_mut() {
            if l.base == bk && l.sid == sid && l.pc == pc && rels.contains(&l.rel) {
                l.file = None;
                out.push(k.clone());
            }
        }
        out
    }

    pub fn resume(&self, keys: &[String]) {
        let mut m = self.m.lock().unwrap();
        for k in keys {
            if let Some(l) = m.get_mut(k) {
                if l.file.is_none() {
                    l.file = hold(&l.path).ok();
                }
            }
        }
    }

    /// Releases the locks whose PC has not claimed them within the lease (asleep, offline, gone).
    pub fn expire(&self) {
        let now = Instant::now();
        let mut m = self.m.lock().unwrap();
        let old: Vec<String> = m.iter().filter(|(_, l)| l.until <= now).map(|(k, _)| k.clone()).collect();
        for k in old {
            if let Some(l) = m.remove(&k) {
                release(l, "lease ran out: the PC stopped claiming it");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(windows)]
    #[test]
    fn a_claimed_file_is_readable_but_not_writable_for_others() {
        let t = std::env::temp_dir().join(format!("scopy-locks-{}", crate::util::random_hex(4)));
        let base = t.join("user").join("Documents");
        fs::create_dir_all(&base).unwrap();
        fs::write(base.join("plan.docx"), b"v1").unwrap();
        let locks = Locks::default();
        let claim = LockClaim { path: "plan.docx".into(), owner_name: "~$plan.docx".into(), owner: b"A. User".to_vec() };
        let lease = Duration::from_secs(60);
        assert_eq!(locks.claim(&base, "S-1", "CORP\\user", "LAPTOP1", &[claim.clone()], lease), [LOCK_HELD]);
        assert!(fs::read(base.join("plan.docx")).is_ok()); // reading is fine
        assert!(fs::OpenOptions::new().write(true).open(base.join("plan.docx")).is_err()); // writing is not
        assert_eq!(fs::read(base.join("~$plan.docx")).unwrap(), b"A. User");
        // Another PC sees it and cannot take it.
        assert_eq!(locks.others(&base, "S-1", "TS01").len(), 1);
        assert_eq!(locks.claim(&base, "S-1", "CORP\\user", "TS01", &[claim.clone()], lease), [LOCK_REFUSED]);
        // The owner's own push may replace it in between.
        let keys = locks.suspend(&base, "S-1", "LAPTOP1", &["plan.docx".to_string()].into_iter().collect());
        fs::write(base.join("plan.docx"), b"v2").unwrap();
        locks.resume(&keys);
        assert!(fs::OpenOptions::new().write(true).open(base.join("plan.docx")).is_err());
        // Closed on the PC: released, owner file gone.
        locks.claim(&base, "S-1", "CORP\\user", "LAPTOP1", &[], lease);
        assert!(fs::OpenOptions::new().write(true).open(base.join("plan.docx")).is_ok());
        assert!(!base.join("~$plan.docx").exists());
        // A lease that runs out releases it too.
        locks.claim(&base, "S-1", "CORP\\user", "LAPTOP1", &[claim], Duration::ZERO);
        locks.expire();
        assert!(fs::OpenOptions::new().write(true).open(base.join("plan.docx")).is_ok());
        fs::remove_dir_all(&t).unwrap();
    }
}
