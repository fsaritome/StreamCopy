//! Job records: from its plan until its final flush, every job that writes keeps a marker `<sid>` (its destination)
//! and `<sid>.files` (the files it planned) in a records folder. A record still there after a crash or restart means
//! those files may have the right size and time without their data (a power cut loses the OS write cache), so the
//! next job to the same destination re-sends them instead of trusting them. Used by the receiver for pushes (folder
//! next to its exe) and by the client for pulls (the user's state folder).

use std::collections::HashSet;
use std::fs;
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};

/// A record found on disk: job id and destination.
pub type Record = (String, String);

pub struct Records {
    dir: PathBuf,
}

/// The client's records folder: `%LOCALAPPDATA%\scopy\pending` on Windows, `$XDG_STATE_HOME/scopy/pending` or
/// `~/.local/state/scopy/pending` elsewhere — never inside the user's destination folder.
pub fn client_dir() -> PathBuf {
    let base = if cfg!(windows) {
        std::env::var_os("LOCALAPPDATA").or_else(|| std::env::var_os("APPDATA")).map(PathBuf::from)
    } else {
        std::env::var_os("XDG_STATE_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local").join("state")))
    };
    base.unwrap_or_else(std::env::temp_dir).join("scopy").join("pending")
}

impl Records {
    pub fn new(dir: PathBuf) -> Self {
        Records { dir }
    }

    fn files(&self, sid: &str) -> PathBuf {
        self.dir.join(format!("{sid}.files"))
    }

    /// The record must itself be on disk, or it is lost in exactly the crash it is for (measured: a hard reset of
    /// TEST-B 20 s into a transfer left the marker empty). Both files are synced before the call returns.
    pub fn write(&self, sid: &str, base: &Path, files: &[String]) -> io::Result<()> {
        crate::auth::as_service(|| self.write_as_me(sid, base, files))
    }

    fn write_as_me(&self, sid: &str, base: &Path, files: &[String]) -> io::Result<()> {
        fs::create_dir_all(&self.dir)?;
        let mut list = BufWriter::new(fs::File::create(self.files(sid))?);
        for f in files {
            writeln!(list, "{f}")?;
        }
        list.into_inner().map_err(|e| e.into_error())?.sync_all()?;
        let mut marker = fs::File::create(self.dir.join(sid))?;
        marker.write_all(base.display().to_string().as_bytes())?;
        marker.sync_all()
    }

    /// Replaces a record's file list crash-safely: a new file, synced, renamed over the old one (a crash leaves the
    /// old list or the new one, never an empty one).
    pub fn replace_list(&self, sid: &str, lines: &[&str]) -> io::Result<()> {
        crate::auth::as_service(|| self.replace_list_as_me(sid, lines))
    }

    fn replace_list_as_me(&self, sid: &str, lines: &[&str]) -> io::Result<()> {
        let path = self.files(sid);
        let tmp = path.with_extension("files.tmp");
        let mut f = fs::File::create(&tmp)?;
        f.write_all(lines.join("\n").as_bytes())?;
        f.sync_all()?;
        drop(f);
        fs::rename(&tmp, path)
    }

    pub fn drop_record(&self, sid: &str) {
        crate::auth::as_service(|| {
            let _ = fs::remove_file(self.dir.join(sid));
            let _ = fs::remove_file(self.files(sid));
        })
    }

    /// The records on disk, plus the ids of records that had to be removed because their destination was
    /// unreadable (a record written by 0.8.4 and lost in a hard reset kept its size but held only zero bytes).
    pub fn load(&self) -> (Vec<Record>, Vec<String>) {
        let (mut found, mut removed) = (Vec::new(), Vec::new());
        let Ok(dir) = fs::read_dir(&self.dir) else { return (found, removed) };
        for ent in dir.flatten() {
            let sid = ent.file_name().to_string_lossy().into_owned();
            if sid.contains('.') {
                continue; // a .files list; handled with its marker
            }
            let base = fs::read_to_string(ent.path()).unwrap_or_default();
            if base.trim_matches(|c: char| c.is_whitespace() || c == '\0').is_empty() {
                self.drop_record(&sid);
                removed.push(sid);
                continue;
            }
            found.push((sid, base));
        }
        (found, removed)
    }

    /// Files that the records for `base` may have left without their data.
    pub fn suspects(&self, records: &[Record], base: &Path) -> HashSet<String> {
        let base = base.display().to_string();
        let mut out = HashSet::new();
        for (sid, _) in records.iter().filter(|(_, b)| *b == base) {
            if let Ok(text) = crate::auth::as_service(|| fs::read_to_string(self.files(sid))) {
                out.extend(text.lines().map(str::to_string));
            }
        }
        out
    }

    /// A job to `base` finished with everything on disk: the files it wrote (`covered`) are good now. Records for
    /// `base` keep only what is still uncovered and go away when nothing is left. Returns the ids that went away.
    pub fn settle(&self, records: &mut Vec<Record>, base: &Path, covered: &HashSet<String>) -> Vec<String> {
        let base = base.display().to_string();
        let mut settled = Vec::new();
        records.retain(|(sid, b)| {
            if *b != base {
                return true;
            }
            let text = crate::auth::as_service(|| fs::read_to_string(self.files(sid))).unwrap_or_default();
            let rest: Vec<&str> = text.lines().filter(|l| !covered.contains(*l)).collect();
            if rest.is_empty() {
                self.drop_record(sid);
                settled.push(sid.clone());
                false
            } else {
                let _ = self.replace_list(sid, &rest);
                true
            }
        });
        settled
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_survive_until_settled() {
        let dir = std::env::temp_dir().join(format!("scopy-records-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let r = Records::new(dir.clone());
        let base = Path::new("D:\\data\\x");
        r.write("job1", base, &["a.txt".into(), "b/c.txt".into()]).unwrap();
        fs::write(dir.join("broken"), [0u8; 11]).unwrap(); // a lost record: zero bytes
        let (mut recs, removed) = r.load();
        assert_eq!(recs, vec![("job1".to_string(), base.display().to_string())]);
        assert_eq!(removed, vec!["broken".to_string()]);
        assert_eq!(r.suspects(&recs, base).len(), 2);
        assert!(r.suspects(&recs, Path::new("D:\\other")).is_empty());
        // A later job covered only a.txt: the record keeps b/c.txt.
        assert!(r.settle(&mut recs, base, &["a.txt".to_string()].into_iter().collect()).is_empty());
        assert_eq!(r.suspects(&recs, base), ["b/c.txt".to_string()].into_iter().collect());
        // Then everything: the record goes away.
        assert_eq!(r.settle(&mut recs, base, &["b/c.txt".to_string()].into_iter().collect()), vec!["job1".to_string()]);
        assert!(recs.is_empty() && r.load().0.is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }
}
