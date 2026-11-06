//! Reading and restoring file metadata: timestamps, (on Windows) attributes and (on Unix) mode, owner and group.

use crate::util::{from_nanos, to_nanos};
use std::fs::{self, File, FileTimes};
use std::io;
use std::path::Path;

/// Attributes we carry over: read-only, hidden, system, archive, not-content-indexed.
#[cfg(windows)]
const KEEP: u32 = 0x1 | 0x2 | 0x4 | 0x20 | 0x2000;
#[cfg_attr(windows, allow(dead_code))]
pub const ATTR_READONLY: u32 = 0x1;
pub const ATTR_HIDDEN: u32 = 0x2;

pub struct Meta {
    pub mtime: i64,
    pub ctime: i64,
    pub attrs: u32,
    /// Unix: MODE_SET | permission bits; 0 elsewhere.
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
}

pub fn read(md: &fs::Metadata) -> Meta {
    #[cfg(unix)]
    let (mode, uid, gid) = {
        use std::os::unix::fs::MetadataExt;
        (crate::proto::MODE_SET | (md.mode() & 0o7777), md.uid(), md.gid())
    };
    #[cfg(not(unix))]
    let (mode, uid, gid) = (0, 0, 0);
    Meta {
        mtime: md.modified().map(to_nanos).unwrap_or(0),
        ctime: md.created().map(to_nanos).unwrap_or(0),
        attrs: attrs_of(md),
        mode,
        uid,
        gid,
    }
}

/// A manifest entry for something that was looked at with `md` (from `symlink_metadata` for a link, whose `target`
/// then goes along).
pub fn entry(kind: u8, path: String, md: &fs::Metadata, target: String) -> crate::proto::Entry {
    let m = read(md);
    let size = if kind == crate::proto::ENTRY_FILE { md.len() } else { 0 };
    crate::proto::Entry { kind, path, size, mtime: m.mtime, ctime: m.ctime, attrs: m.attrs, mode: m.mode, uid: m.uid, gid: m.gid, link: target }
}

/// Unix: gives an open file or folder the sender's owner, group and mode. The owner only when running as root (like
/// rsync: anyone else can't); the group also as a normal user when they are in it (a refusal is not an error, as
/// with rsync). Owner before mode: changing the owner clears setuid/setgid. Does nothing for a non-Unix sender
/// (`mode` == 0) and on Windows.
#[cfg(unix)]
pub fn set_unix(f: &File, mode: u32, uid: u32, gid: u32) -> io::Result<()> {
    use std::os::unix::fs::{fchown, MetadataExt, PermissionsExt};
    if mode == 0 {
        return Ok(());
    }
    let md = f.metadata()?;
    let mut have = md.mode() & 0o7777;
    if md.uid() != uid || md.gid() != gid {
        let changed = if is_root() { fchown(f, Some(uid), Some(gid)).map(|_| true)? } else { md.gid() != gid && fchown(f, None, Some(gid)).is_ok() };
        if changed {
            // The kernel may have cleared setuid/setgid.
            have = f.metadata()?.mode() & 0o7777;
        }
    }
    let want = mode & 0o7777;
    if have != want {
        f.set_permissions(fs::Permissions::from_mode(want))?;
    }
    Ok(())
}

#[cfg(not(unix))]
pub fn set_unix(_f: &File, _mode: u32, _uid: u32, _gid: u32) -> io::Result<()> {
    Ok(())
}

/// Unix: whether an existing file's mode, owner or group differ from the sender's (what `set_unix` would change).
#[cfg(unix)]
pub fn unix_differs(md: &fs::Metadata, mode: u32, uid: u32, gid: u32) -> bool {
    use std::os::unix::fs::MetadataExt;
    mode != 0 && (md.mode() & 0o7777 != mode & 0o7777 || (is_root() && md.uid() != uid) || md.gid() != gid)
}

#[cfg(not(unix))]
pub fn unix_differs(_md: &fs::Metadata, _mode: u32, _uid: u32, _gid: u32) -> bool {
    false
}

/// The names of the Unix owners and groups `entries` use (sender side; id 0 is root everywhere and needs none). Ids
/// without a name on this machine are left out: they then arrive by number.
#[cfg(unix)]
pub fn id_names(entries: &[crate::proto::Entry]) -> (Vec<(u32, String)>, Vec<(u32, String)>) {
    let mut uids: Vec<u32> = entries.iter().filter(|e| e.mode != 0 && e.uid != 0).map(|e| e.uid).collect();
    let mut gids: Vec<u32> = entries.iter().filter(|e| e.mode != 0 && e.gid != 0).map(|e| e.gid).collect();
    uids.sort_unstable();
    uids.dedup();
    gids.sort_unstable();
    gids.dedup();
    (
        uids.into_iter().filter_map(|id| user_name(id).map(|n| (id, n))).collect(),
        gids.into_iter().filter_map(|id| group_name(id).map(|n| (id, n))).collect(),
    )
}

#[cfg(not(unix))]
pub fn id_names(_entries: &[crate::proto::Entry]) -> (Vec<(u32, String)>, Vec<(u32, String)>) {
    (Vec::new(), Vec::new())
}

/// Destination side, as rsync does without --numeric-ids: an owner or group the sender named gets this machine's id
/// of that name; one without a name here (or unnamed) keeps the sender's number; 0 (root) always stays 0.
#[cfg(unix)]
pub fn map_ids(entries: &mut [crate::proto::Entry], users: &[(u32, String)], groups: &[(u32, String)]) {
    use std::collections::HashMap;
    let users: HashMap<u32, u32> = users.iter().filter_map(|(id, n)| user_id(n).map(|l| (*id, l))).filter(|(a, b)| a != b).collect();
    let groups: HashMap<u32, u32> = groups.iter().filter_map(|(id, n)| group_id(n).map(|l| (*id, l))).filter(|(a, b)| a != b).collect();
    if users.is_empty() && groups.is_empty() {
        return;
    }
    for e in entries.iter_mut().filter(|e| e.mode != 0) {
        if let Some(&u) = users.get(&e.uid) {
            e.uid = u;
        }
        if let Some(&g) = groups.get(&e.gid) {
            e.gid = g;
        }
    }
}

#[cfg(not(unix))]
pub fn map_ids(_entries: &mut [crate::proto::Entry], _users: &[(u32, String)], _groups: &[(u32, String)]) {}

/// Looks a name or id up in the user or group database (the reentrant libc calls; a static musl build reads only
/// /etc/passwd and /etc/group, no LDAP/SSSD).
#[cfg(unix)]
fn lookup<T>(call: impl Fn(*mut T, *mut libc::c_char, usize, *mut *mut T) -> libc::c_int, pick: impl Fn(&T) -> Option<String>) -> Option<String> {
    let mut buf = vec![0 as libc::c_char; 4096];
    loop {
        // SAFETY: `ent` is plain data filled by the call; `buf` is writable for its length; `res` is set by the call.
        let mut ent: T = unsafe { std::mem::zeroed() };
        let mut res: *mut T = std::ptr::null_mut();
        let rc = call(&mut ent, buf.as_mut_ptr(), buf.len(), &mut res);
        if rc == libc::ERANGE && buf.len() < 1 << 20 {
            buf.resize(buf.len() * 4, 0);
            continue;
        }
        return if rc == 0 && !res.is_null() { pick(&ent) } else { None };
    }
}

#[cfg(unix)]
fn c_str(p: *const libc::c_char) -> Option<String> {
    // SAFETY: the libc call filled `p` with a NUL-terminated string inside the buffer it was given.
    (!p.is_null()).then(|| unsafe { std::ffi::CStr::from_ptr(p) }.to_string_lossy().into_owned())
}

#[cfg(unix)]
fn user_name(uid: u32) -> Option<String> {
    // SAFETY: the arguments are the buffers `lookup` passes, valid for the lengths given.
    lookup(|e: *mut libc::passwd, b, n, r| unsafe { libc::getpwuid_r(uid, e, b, n, r) }, |p| c_str(p.pw_name))
}

/// A local user's name and primary group (for the daemon's sign-in).
#[cfg(unix)]
pub fn user_record(uid: u32) -> Option<(String, u32)> {
    let gid = std::cell::Cell::new(None);
    // SAFETY: as in `user_name`.
    let name = lookup(|e: *mut libc::passwd, b, n, r| unsafe { libc::getpwuid_r(uid, e, b, n, r) }, |p| {
        gid.set(Some(p.pw_gid));
        c_str(p.pw_name)
    })?;
    Some((name, gid.get()?))
}

/// Every group a user is in: the primary one and the supplementary ones from the group database.
#[cfg(unix)]
pub fn user_groups(name: &str, gid: u32) -> Vec<u32> {
    let Ok(c) = std::ffi::CString::new(name) else { return vec![gid] };
    let mut n: libc::c_int = 64;
    loop {
        let mut v: Vec<libc::gid_t> = vec![0; n as usize];
        let want = n;
        // SAFETY: `v` has room for `n` ids; getgrouplist writes at most that many and sets `n` to the real count.
        let rc = unsafe { libc::getgrouplist(c.as_ptr(), gid as _, v.as_mut_ptr() as *mut _, &mut n) };
        if rc >= 0 {
            v.truncate(n.max(0) as usize);
            return v.into_iter().map(|g| g as u32).collect();
        }
        if n <= want || n > 65536 {
            return vec![gid];
        }
    }
}

#[cfg(unix)]
fn group_name(gid: u32) -> Option<String> {
    // SAFETY: as in `user_name`.
    lookup(|e: *mut libc::group, b, n, r| unsafe { libc::getgrgid_r(gid, e, b, n, r) }, |g| c_str(g.gr_name))
}

#[cfg(unix)]
fn user_id(name: &str) -> Option<u32> {
    let c = std::ffi::CString::new(name).ok()?;
    // SAFETY: as in `user_name`; `c` is NUL-terminated and outlives the call.
    lookup(|e: *mut libc::passwd, b, n, r| unsafe { libc::getpwnam_r(c.as_ptr(), e, b, n, r) }, |p| Some(p.pw_uid.to_string()))?.parse().ok()
}

#[cfg(unix)]
fn group_id(name: &str) -> Option<u32> {
    let c = std::ffi::CString::new(name).ok()?;
    // SAFETY: as in `user_id`.
    lookup(|e: *mut libc::group, b, n, r| unsafe { libc::getgrnam_r(c.as_ptr(), e, b, n, r) }, |g| Some(g.gr_gid.to_string()))?.parse().ok()
}

/// Whether this thread has root's rights for files. On Linux that is the thread's file-system uid, not the process's
/// euid: a daemon thread acting as a user (auth.rs) runs with euid 0 but must decide like that user.
#[cfg(unix)]
pub fn is_root() -> bool {
    acting_uid() == 0
}

/// The uid this thread accesses files as (Linux: the fsuid; elsewhere the euid).
#[cfg(unix)]
pub fn acting_uid() -> u32 {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: setfsuid with an invalid id changes nothing and returns the current fsuid.
        unsafe { libc::syscall(libc::SYS_setfsuid, u32::MAX) as u32 }
    }
    #[cfg(not(target_os = "linux"))]
    {
        // SAFETY: geteuid has no preconditions and cannot fail.
        unsafe { libc::geteuid() }
    }
}

/// Unix: the owner/group and modification time of a symbolic link itself (not of what it points to). A link's own
/// mode means nothing on Linux, so it is not set.
#[cfg(unix)]
pub fn set_link_meta(path: &Path, mtime: i64, uid: u32, gid: u32, owner: bool) -> io::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    if owner && is_root() {
        std::os::unix::fs::lchown(path, Some(uid), Some(gid))?;
    }
    let t = libc::timespec { tv_sec: mtime.div_euclid(1_000_000_000) as _, tv_nsec: mtime.rem_euclid(1_000_000_000) as _ };
    let times = [libc::timespec { tv_sec: 0, tv_nsec: libc::UTIME_OMIT }, t];
    // SAFETY: `c` is a NUL-terminated path and `times` holds the two timespecs utimensat reads.
    if unsafe { libc::utimensat(libc::AT_FDCWD, c.as_ptr(), times.as_ptr(), libc::AT_SYMLINK_NOFOLLOW) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(windows)]
fn attrs_of(md: &fs::Metadata) -> u32 {
    use std::os::windows::fs::MetadataExt;
    md.file_attributes() & KEEP
}

#[cfg(not(windows))]
fn attrs_of(md: &fs::Metadata) -> u32 {
    if md.permissions().readonly() {
        ATTR_READONLY
    } else {
        0
    }
}

/// Sets modification and (where the platform allows) creation time on an open handle.
pub fn set_times(f: &File, mtime: i64, ctime: i64) -> io::Result<()> {
    let times = FileTimes::new().set_modified(from_nanos(mtime));
    #[cfg(windows)]
    let times = {
        use std::os::windows::fs::FileTimesExt;
        if ctime != 0 {
            times.set_created(from_nanos(ctime))
        } else {
            times
        }
    };
    #[cfg(not(windows))]
    let _ = ctime;
    f.set_times(times)
}

/// Opens a directory so its timestamps can be set.
pub fn open_dir(path: &Path) -> io::Result<File> {
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_WRITE_ATTRIBUTES: u32 = 0x100;
        const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
        fs::OpenOptions::new()
            .access_mode(FILE_WRITE_ATTRIBUTES)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(path)
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY).open(path)
    }
    #[cfg(not(any(windows, unix)))]
    {
        File::open(path)
    }
}

/// Opens a file or folder just to look at it (where it really is), without access to its contents.
pub fn open_to_look(path: &Path) -> io::Result<File> {
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_READ_ATTRIBUTES: u32 = 0x80;
        const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
        fs::OpenOptions::new()
            .access_mode(FILE_READ_ATTRIBUTES)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(path)
    }
    #[cfg(not(windows))]
    {
        File::open(path)
    }
}

#[cfg(windows)]
pub fn set_attrs(path: &Path, attrs: u32) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::SetFileAttributesW;
    const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let value = if attrs == 0 { FILE_ATTRIBUTE_NORMAL } else { attrs };
    // SAFETY: `wide` is a NUL-terminated UTF-16 string that outlives the call.
    if unsafe { SetFileAttributesW(wide.as_ptr(), value) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(windows))]
pub fn set_attrs(path: &Path, attrs: u32) -> io::Result<()> {
    let mut perms = fs::metadata(path)?.permissions();
    let ro = attrs & ATTR_READONLY != 0;
    if perms.readonly() != ro {
        perms.set_readonly(ro);
        fs::set_permissions(path, perms)?;
    }
    Ok(())
}

/// File IDs of a directory's entries, by name: an approximation of on-disk order (NTFS MFT record number;
/// files are usually allocated near their MFT record). Read from the directory itself, so no file is opened.
#[cfg(windows)]
pub fn dir_file_ids(dir: &Path) -> std::collections::HashMap<std::ffi::OsString, u64> {
    let mut ids = dir_entry_ids(dir);
    ids.values_mut().for_each(|id| *id &= 0x0000_FFFF_FFFF_FFFF);
    ids
}

/// Full NTFS file IDs (MFT record number + reuse sequence number) of a directory's entries, by name: identifies a
/// file or folder across renames and moves on the same volume (sync move detection). No file is opened.
#[cfg(windows)]
pub fn dir_entry_ids(dir: &Path) -> std::collections::HashMap<std::ffi::OsString, u64> {
    use std::os::windows::ffi::OsStringExt;
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::GetFileInformationByHandleEx;
    const FILE_LIST_DIRECTORY: u32 = 0x1;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const ID_BOTH_DIR_INFO: i32 = 10; // FileIdBothDirectoryInfo
    const ID_BOTH_DIR_RESTART_INFO: i32 = 11; // FileIdBothDirectoryRestartInfo
    // FILE_ID_BOTH_DIR_INFO: NextEntryOffset @0, FileNameLength @60, FileId @96, FileName @104.
    const NAME_LEN: usize = 60;
    const FILE_ID: usize = 96;
    const NAME: usize = 104;

    let mut out = std::collections::HashMap::new();
    let Ok(f) = fs::OpenOptions::new().access_mode(FILE_LIST_DIRECTORY).custom_flags(FILE_FLAG_BACKUP_SEMANTICS).open(dir) else {
        return out;
    };
    let mut buf = vec![0u64; 8192]; // 64 KB, 8-byte aligned
    let mut class = ID_BOTH_DIR_RESTART_INFO;
    loop {
        // SAFETY: the handle is a valid open directory and `buf` is writable for the given length.
        let ok = unsafe { GetFileInformationByHandleEx(f.as_raw_handle() as _, class as _, buf.as_mut_ptr().cast(), (buf.len() * 8) as u32) };
        if ok == 0 {
            break; // ERROR_NO_MORE_FILES or a real error: either way, what we have is a best-effort hint
        }
        class = ID_BOTH_DIR_INFO;
        // SAFETY: reinterpreting the initialized u64 buffer as bytes.
        let bytes = unsafe { std::slice::from_raw_parts(buf.as_ptr().cast::<u8>(), buf.len() * 8) };
        let u32_at = |o: usize| u32::from_le_bytes(bytes[o..o + 4].try_into().unwrap()) as usize;
        let mut off = 0usize;
        loop {
            if off + NAME > bytes.len() {
                break;
            }
            let next = u32_at(off);
            let name_len = u32_at(off + NAME_LEN);
            if off + NAME + name_len > bytes.len() {
                break;
            }
            let id = u64::from_le_bytes(bytes[off + FILE_ID..off + FILE_ID + 8].try_into().unwrap());
            let name: Vec<u16> =
                bytes[off + NAME..off + NAME + name_len].chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
            // Low 48 bits = MFT record number; the high 16 bits are a reuse sequence number.
            out.insert(std::ffi::OsString::from_wide(&name), id);
            if next == 0 {
                break;
            }
            off += next;
        }
    }
    out
}

/// On Unix the inode number serves as the on-disk order hint.
#[cfg(unix)]
pub fn file_id(md: &fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    md.ino()
}

/// Physical memory currently available to applications, in bytes (None if unknown).
#[cfg(windows)]
pub fn available_memory() -> Option<u64> {
    use windows_sys::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};
    // SAFETY: MEMORYSTATUSEX is plain data; dwLength must be set before the call.
    let mut st: MEMORYSTATUSEX = unsafe { std::mem::zeroed() };
    st.dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as u32;
    (unsafe { GlobalMemoryStatusEx(&mut st) } != 0).then_some(st.ullAvailPhys)
}

#[cfg(not(windows))]
pub fn available_memory() -> Option<u64> {
    let text = fs::read_to_string("/proc/meminfo").ok()?;
    let line = text.lines().find(|l| l.starts_with("MemAvailable:"))?;
    let kb: u64 = line.split_whitespace().nth(1)?.parse().ok()?;
    Some(kb * 1024)
}

/// Forces everything cached for the volume that holds `path` onto the disk (one call instead of one per file).
/// Windows: needs administrator rights (the receiver service has them). Linux: syncfs(2) on the folder, which any
/// user may call. Without it, callers fall back to syncing files one by one.
#[cfg(not(target_os = "linux"))]
pub fn flush_volume(path: &Path) -> io::Result<()> {
    open_volume(path)?.sync_all()
}

#[cfg(target_os = "linux")]
pub fn flush_volume(path: &Path) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    let dir = File::open(path)?;
    // SAFETY: syncfs takes any open descriptor on the file system; `dir` stays open for the call.
    if unsafe { libc::syncfs(dir.as_raw_fd()) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Whether `flush_volume` will be allowed (opens the volume without flushing). Decided before writing starts:
/// without the rights, each file is synced right after it is written instead of all of them at the end.
#[cfg(not(target_os = "linux"))]
pub fn volume_flush_allowed(path: &Path) -> bool {
    open_volume(path).is_ok()
}

#[cfg(target_os = "linux")]
pub fn volume_flush_allowed(path: &Path) -> bool {
    // The destination may not exist yet (its folders are created while data flows): the nearest folder that does
    // is on the same file system for syncfs (a mount point below it would be created by us, so it can't be one).
    path.ancestors().any(|p| File::open(p).is_ok())
}

#[cfg(windows)]
fn open_volume(path: &Path) -> io::Result<File> {
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    use windows_sys::Win32::Storage::FileSystem::{GetVolumeNameForVolumeMountPointW, GetVolumePathNameW};
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut mount = [0u16; 1024];
    // SAFETY: both buffers are valid for the lengths passed; the results are NUL-terminated.
    if unsafe { GetVolumePathNameW(wide.as_ptr(), mount.as_mut_ptr(), mount.len() as u32) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut vol = [0u16; 64];
    if unsafe { GetVolumeNameForVolumeMountPointW(mount.as_ptr(), vol.as_mut_ptr(), vol.len() as u32) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // "\\?\Volume{guid}\" names the root folder; without the trailing backslash it is the volume itself.
    let mut name = vol[..vol.iter().position(|&c| c == 0).unwrap_or(vol.len())].to_vec();
    if name.last() == Some(&(b'\\' as u16)) {
        name.pop();
    }
    fs::OpenOptions::new().write(true).open(std::ffi::OsString::from_wide(&name))
}

#[cfg(not(any(windows, target_os = "linux")))]
fn open_volume(_path: &Path) -> io::Result<File> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "no volume flush on this platform; syncing files one by one"))
}

/// Removes the read-only flag so an existing file can be overwritten or replaced.
pub fn clear_readonly(path: &Path) -> io::Result<()> {
    let md = fs::metadata(path)?;
    if md.permissions().readonly() {
        let mut perms = md.permissions();
        #[allow(clippy::permissions_set_readonly_false)]
        perms.set_readonly(false);
        fs::set_permissions(path, perms)?;
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::proto::{Entry, ENTRY_FILE, MODE_SET};

    #[test]
    fn owners_are_matched_by_name_and_unknown_or_root_ones_keep_their_number() {
        // SAFETY: geteuid/getegid have no preconditions.
        let (me, my_group) = (unsafe { libc::geteuid() }, unsafe { libc::getegid() });
        let (name, group) = (user_name(me).unwrap(), group_name(my_group).unwrap());
        let file = |uid, gid| Entry { kind: ENTRY_FILE, path: "f".into(), mode: MODE_SET | 0o644, uid, gid, ..Entry::default() };
        let mut v = vec![file(4242, 4343), file(5000, 5001), file(0, 0)];
        let users = vec![(4242, name), (5000, "no-such-user-scopy".to_string()), (0, "someone".to_string())];
        let groups = vec![(4343, group)];
        map_ids(&mut v, &users, &groups);
        assert_eq!((v[0].uid, v[0].gid), (me, my_group));
        assert_eq!((v[1].uid, v[1].gid), (5000, 5001));
        assert_eq!((v[2].uid, v[2].gid), (0, 0));
        // The sender's side: names for the ids it uses, none for root.
        let (u, _) = id_names(&[file(me, my_group), file(0, 0)]);
        assert_eq!(u.iter().map(|(id, _)| *id).collect::<Vec<_>>(), if me == 0 { vec![] } else { vec![me] });
    }
}
