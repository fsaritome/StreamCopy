//! Recycle-bin retention for two-way sync. Deleted and replaced files go into a recycle bin on the side where they
//! were removed: on the receiver `<user>\.scopy-recycle\<folder>\<UTC time>\…`, on the PC
//! `%LOCALAPPDATA%\scopy\recycle\<folder>\<UTC time>\…`. One time folder per round. Time folders older than the
//! retention are removed: on the receiver hourly (`[sync] recycle_days` in scopy.toml), on the PC by the agent
//! hourly (`recycle_days` in settings.toml, tray Options). 0 days = keep everything.
//!
//! Only folders named like a scopy time stamp (`YYYYMMDD-HHMMSS`) are touched; links are never followed (a link in
//! the bin is removed as a link, a linked bin or folder is skipped).

use std::fs;
use std::path::Path;

/// Default retention in days.
pub const DEFAULT_DAYS: u64 = 30;

/// What a purge removed.
#[derive(Default, Debug, PartialEq)]
pub struct Purged {
    pub rounds: u64,
    pub files: u64,
    pub bytes: u64,
}

fn is_stamp(name: &str) -> bool {
    let b = name.as_bytes();
    b.len() == 15 && b[8] == b'-' && b.iter().enumerate().all(|(i, c)| i == 8 || c.is_ascii_digit())
}

/// A real folder (not a link or junction).
fn real_dir(p: &Path) -> bool {
    fs::symlink_metadata(p).is_ok_and(|m| m.is_dir() && !m.file_type().is_symlink())
}

/// Files and bytes below `p`, links not followed.
fn measure(p: &Path, out: &mut Purged) {
    let Ok(rd) = fs::read_dir(p) else { return };
    for e in rd.flatten() {
        let Ok(md) = fs::symlink_metadata(e.path()) else { continue };
        if md.file_type().is_symlink() {
            continue;
        }
        if md.is_dir() {
            measure(&e.path(), out);
        } else {
            out.files += 1;
            out.bytes += md.len();
        }
    }
}

/// Removes the time folders in `bin` (`bin\<folder>\<stamp>`) older than `days`, as of the time stamp `now`
/// (`util::utc_stamp`). Errors on single folders are skipped (tried again next time).
pub fn purge(bin: &Path, days: u64, now_secs: u64) -> Purged {
    let mut out = Purged::default();
    if days == 0 || !real_dir(bin) {
        return out;
    }
    let cutoff = crate::util::stamp_at(now_secs.saturating_sub(days * 86_400) as i64);
    let Ok(folders) = fs::read_dir(bin) else { return out };
    for f in folders.flatten() {
        if !real_dir(&f.path()) {
            continue;
        }
        let Ok(rounds) = fs::read_dir(f.path()) else { continue };
        for r in rounds.flatten() {
            let name = r.file_name().to_string_lossy().to_string();
            // Stamps sort like the times they stand for.
            if !is_stamp(&name) || name.as_str() >= cutoff.as_str() || !real_dir(&r.path()) {
                continue;
            }
            let mut m = Purged::default();
            measure(&r.path(), &mut m);
            if fs::remove_dir_all(r.path()).is_ok() {
                out.rounds += 1;
                out.files += m.files;
                out.bytes += m.bytes;
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_time_folders_older_than_the_retention_go() {
        let t = std::env::temp_dir().join(format!("scopy-recycle-{}", crate::util::random_hex(6)));
        let bin = t.join(".scopy-recycle");
        let put = |rel: &str, data: &[u8]| {
            let p = bin.join(rel);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(p, data).unwrap();
        };
        put("Downloads/20261001-120000/old.txt", b"12345");
        put("Downloads/20261001-120000/sub/older.txt", b"123");
        put("Documents/20260901-000000/a.docx", b"1");
        put("Downloads/20261103-120000/recent.txt", b"keep");
        put("Downloads/not-a-stamp/x.txt", b"keep");
        put("Downloads/2026100-1200000/x.txt", b"keep");
        put("loose.txt", b"keep");
        // now = 2026-11-04 00:00:00 UTC; 30 days back = 2026-10-05
        let now = 1_793_750_400;
        assert_eq!(crate::util::stamp_at(now as i64), "20261104-000000");
        let p = purge(&bin, 30, now);
        assert_eq!(p, Purged { rounds: 2, files: 3, bytes: 9 });
        assert!(!bin.join("Downloads/20261001-120000").exists());
        assert!(!bin.join("Documents/20260901-000000").exists());
        for keep in ["Downloads/20261103-120000/recent.txt", "Downloads/not-a-stamp/x.txt", "Downloads/2026100-1200000/x.txt", "loose.txt"] {
            assert!(bin.join(keep).exists(), "{keep}");
        }
        // 0 days keeps everything; a later purge with a shorter retention takes the rest
        assert_eq!(purge(&bin, 0, now), Purged::default());
        assert_eq!(purge(&bin, 1, now + 86_400).rounds, 1);
        fs::remove_dir_all(&t).unwrap();
    }
}
