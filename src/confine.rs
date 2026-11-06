//! Keeps the receiver inside the share. The receiver writes (and, for pulls, reads) with its own rights, so a
//! junction or symbolic link that a user places below the share root must not take it anywhere else: a junction
//! `share\x -> C:\Windows` would otherwise let anyone with write access to the share write into C:\Windows.
//!
//! Two checks: before a job, no existing folder on the way (share root → destination, and every folder the job
//! needs) may be a link; and every file the receiver opens is checked by its handle afterwards (where the opened
//! file really is), which also catches a link swapped in while the job runs. On Windows `is_symlink` covers
//! junctions and mount points too (name-surrogate reparse points).

use anyhow::{bail, Result};
use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};

/// The share root as the OS sees it after resolving every link (the admin's share path may itself be one).
pub struct Jail {
    root: String,
}

impl Jail {
    pub fn new(root: &Path) -> io::Result<Self> {
        let f = crate::meta::open_to_look(root)?;
        let mut root = norm(&final_path(&f)?);
        while root.ends_with(SEP) {
            root.pop();
        }
        Ok(Jail { root })
    }

    /// Whether an opened file or folder really lies inside the share.
    pub fn contains(&self, f: &File) -> bool {
        // Where the platform can't tell (no final path), the folder checks before the job still apply.
        let Ok(p) = final_path(f) else { return cfg!(not(any(windows, target_os = "linux"))) };
        let p = norm(&p);
        p == self.root || (p.starts_with(&self.root) && p[self.root.len()..].starts_with(SEP))
    }

    /// Fails if `f` (opened as `shown`) lies outside the share.
    pub fn check(&self, f: &File, shown: &Path) -> io::Result<()> {
        if self.contains(f) {
            return Ok(());
        }
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{}: leads outside the share (through a junction or symbolic link) — refused", shown.display()),
        ))
    }
}

/// Fails if any existing folder between `root` (exclusive) and `path` (inclusive) is a junction or symbolic link.
pub fn no_links_below(root: &Path, path: &Path) -> Result<()> {
    let Ok(rel) = path.strip_prefix(root) else { bail!("{} is not inside the share {}", path.display(), root.display()) };
    let mut p = root.to_path_buf();
    for c in rel.components() {
        p.push(c);
        match fs::symlink_metadata(&p) {
            Ok(md) if md.file_type().is_symlink() => bail!("{} is a junction or symbolic link: scopy does not write or read through links", p.display()),
            Ok(_) => {}
            Err(_) => return Ok(()), // missing: nothing below it exists either
        }
    }
    Ok(())
}

#[cfg(windows)]
const SEP: char = '\\';
#[cfg(not(windows))]
const SEP: char = '/';

/// NTFS names are case-insensitive.
#[cfg(windows)]
fn norm(p: &Path) -> String {
    p.to_string_lossy().to_lowercase()
}

#[cfg(not(windows))]
fn norm(p: &Path) -> String {
    p.to_string_lossy().into_owned()
}

/// Where an open handle really is, with every link resolved. Windows: the NT form (`\Device\HarddiskVolume3\...`),
/// which needs no drive-letter lookup and is the same for every handle on the volume.
#[cfg(windows)]
fn final_path(f: &File) -> io::Result<PathBuf> {
    use std::os::windows::ffi::OsStringExt;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::GetFinalPathNameByHandleW;
    const VOLUME_NAME_NT: u32 = 0x2;
    let mut buf = vec![0u16; 512];
    loop {
        // SAFETY: the handle is open for the lifetime of `f`; `buf` is writable for the length passed.
        let n = unsafe { GetFinalPathNameByHandleW(f.as_raw_handle() as _, buf.as_mut_ptr(), buf.len() as u32, VOLUME_NAME_NT) } as usize;
        if n == 0 {
            return Err(io::Error::last_os_error());
        }
        if n < buf.len() {
            return Ok(PathBuf::from(std::ffi::OsString::from_wide(&buf[..n])));
        }
        buf.resize(n + 1, 0);
    }
}

#[cfg(target_os = "linux")]
fn final_path(f: &File) -> io::Result<PathBuf> {
    use std::os::fd::AsRawFd;
    fs::read_link(format!("/proc/self/fd/{}", f.as_raw_fd()))
}

#[cfg(not(any(windows, target_os = "linux")))]
fn final_path(_f: &File) -> io::Result<PathBuf> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "no final path on this platform"))
}

#[cfg(test)]
pub mod tests {
    use super::*;

    /// A directory link (a junction on Windows); false if the system wouldn't create one.
    pub fn link_dir(target: &Path, link: &Path) -> bool {
        #[cfg(windows)]
        {
            // A junction needs no privilege (a directory symlink would).
            std::process::Command::new("cmd")
                .args(["/c", "mklink", "/J"])
                .arg(link)
                .arg(target)
                .output()
                .is_ok_and(|o| o.status.success())
        }
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(target, link).is_ok()
        }
    }

    #[test]
    fn links_below_the_share_are_refused() {
        let t = std::env::temp_dir().join(format!("scopy-confine-{}", crate::util::random_hex(4)));
        let (share, outside) = (t.join("share"), t.join("outside"));
        fs::create_dir_all(share.join("ok/deeper")).unwrap();
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("victim.txt"), b"keep").unwrap();
        assert!(link_dir(&outside, &share.join("ok").join("evil")), "cannot create a junction for the test");

        // Folder check before a job.
        assert!(no_links_below(&share, &share.join("ok/deeper/new/also-new")).is_ok());
        let e = no_links_below(&share, &share.join("ok/evil/sub")).unwrap_err().to_string();
        assert!(e.contains("junction or symbolic link"), "{e}");

        // Handle check: a file opened through the link is outside, one opened directly is inside.
        let jail = Jail::new(&share).unwrap();
        let inside = File::create(share.join("ok/a.txt")).unwrap();
        assert!(jail.check(&inside, Path::new("ok/a.txt")).is_ok());
        let through = fs::OpenOptions::new().read(true).open(share.join("ok/evil/victim.txt")).unwrap();
        assert!(jail.check(&through, Path::new("ok/evil/victim.txt")).is_err());
        // A sibling whose name starts like the share's is not inside it.
        fs::create_dir_all(t.join("share2")).unwrap();
        let sibling = File::create(t.join("share2/x.txt")).unwrap();
        assert!(!jail.contains(&sibling));
        drop((inside, through, sibling));
        let _ = fs::remove_dir(share.join("ok").join("evil")); // removes the junction itself, not the target
        assert_eq!(fs::read(outside.join("victim.txt")).unwrap(), b"keep");
        let _ = fs::remove_dir_all(&t);
    }
}
