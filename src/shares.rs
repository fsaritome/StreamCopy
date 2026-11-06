//! Maps SMB share names to local folders on the server, and decides which shares scopy may use.
//!
//! Reachable: the shares published on the system (registry / smb.conf) and `--share` mappings. With `--only-share`
//! just the ones named there (plus `--share` mappings). Administrative drive shares (C$, D$, ...) cover a whole
//! drive and are off unless the receiver runs with `--allow-admin-shares`.

use anyhow::{bail, Result};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

pub struct Shares {
    map: HashMap<String, PathBuf>,
    allow_admin: bool,
}

impl Shares {
    /// Explicit `--share name=path` mappings win over shares discovered from the system; `only` (if not empty)
    /// limits the discovered ones to those names.
    pub fn discover(explicit: &[(String, PathBuf)], only: &[String], allow_admin: bool) -> Self {
        let only: HashSet<String> = only.iter().map(|s| s.to_lowercase()).collect();
        let mut map = HashMap::new();
        for (name, path) in system_shares() {
            let name = name.to_lowercase();
            if only.is_empty() || only.contains(&name) {
                map.insert(name, path);
            }
        }
        for (name, path) in explicit {
            map.insert(name.to_lowercase(), path.clone());
        }
        Shares { map, allow_admin }
    }

    pub fn resolve(&self, name: &str) -> Result<PathBuf> {
        if let Some(p) = self.map.get(&name.to_lowercase()) {
            return Ok(p.clone());
        }
        // Administrative drive shares (C$, D$, ...) are not listed in the registry.
        if let Some(drive) = admin_drive(name) {
            if !self.allow_admin {
                bail!("{name} is an administrative share, off on this receiver (start it with --allow-admin-shares to use it)");
            }
            return Ok(PathBuf::from(format!("{drive}:\\")));
        }
        bail!("share {name:?} is not enabled on this receiver")
    }

    /// The reachable share that holds `path` (the deepest one), with the path inside it: how clients and terminal
    /// servers address a local folder over SMB. Administrative shares don't count.
    pub fn share_for(&self, path: &std::path::Path) -> Option<(String, PathBuf)> {
        let low = |p: &std::path::Path| p.to_string_lossy().to_lowercase();
        let target = low(path);
        self.map
            .iter()
            .filter_map(|(name, root)| {
                let r = low(root);
                let r = r.trim_end_matches(['\\', '/']);
                let rest = target.strip_prefix(r)?;
                (rest.is_empty() || rest.starts_with(['\\', '/'])).then(|| (r.len(), name.clone(), path.to_string_lossy()[r.len()..].trim_start_matches(['\\', '/']).to_string()))
            })
            .max_by_key(|(len, _, _)| *len)
            .map(|(_, name, rest)| (name, PathBuf::from(rest)))
    }

    pub fn admin_allowed(&self) -> bool {
        self.allow_admin
    }

    pub fn list(&self) -> Vec<(&String, &PathBuf)> {
        let mut v: Vec<_> = self.map.iter().collect();
        v.sort();
        v
    }
}

/// The drive letter of an administrative drive share name (`C$` → `C`), on Windows.
fn admin_drive(name: &str) -> Option<char> {
    let b = name.as_bytes();
    (cfg!(windows) && b.len() == 2 && b[0].is_ascii_alphabetic() && b[1] == b'$').then(|| b[0] as char)
}

#[cfg(windows)]
fn system_shares() -> Vec<(String, PathBuf)> {
    use winreg::enums::HKEY_LOCAL_MACHINE;
    use winreg::RegKey;

    let mut out = Vec::new();
    let Ok(key) = RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey(r"SYSTEM\CurrentControlSet\Services\LanmanServer\Shares")
    else {
        return out;
    };
    for (name, _) in key.enum_values().flatten() {
        let Ok(lines) = key.get_value::<Vec<String>, _>(&name) else { continue };
        if let Some(path) = lines.iter().find_map(|l| l.strip_prefix("Path=")) {
            out.push((name, PathBuf::from(path)));
        }
    }
    out
}

#[cfg(not(windows))]
fn system_shares() -> Vec<(String, PathBuf)> {
    const CONFIGS: &[&str] = &["/etc/samba/smb.conf", "/etc/smb.conf", "/usr/local/etc/smb4.conf", "/etc/samba/smb.share.conf"];
    CONFIGS.iter().filter_map(|p| std::fs::read_to_string(p).ok()).flat_map(|t| parse_smb_conf(&t)).collect()
}

/// Extracts `[share]` sections with a `path = ...` from a Samba configuration.
#[cfg_attr(windows, allow(dead_code))]
pub fn parse_smb_conf(text: &str) -> Vec<(String, PathBuf)> {
    let mut out = Vec::new();
    let mut section: Option<String> = None;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            let name = name.trim();
            let special = ["global", "homes", "printers", "print$"].iter().any(|s| s.eq_ignore_ascii_case(name));
            section = (!special).then(|| name.to_string());
            continue;
        }
        let Some(name) = &section else { continue };
        if let Some((k, v)) = line.split_once('=') {
            if k.trim().eq_ignore_ascii_case("path") {
                out.push((name.clone(), PathBuf::from(v.trim().trim_matches('"'))));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn only_enabled_shares_resolve() {
        let explicit = vec![("photos".to_string(), PathBuf::from("/srv/photos"))];
        let s = Shares::discover(&explicit, &["nothing-like-this".to_string()], false);
        assert_eq!(s.resolve("Photos").unwrap(), PathBuf::from("/srv/photos"));
        assert!(s.resolve("other").unwrap_err().to_string().contains("not enabled"));
        if cfg!(windows) {
            assert!(s.resolve("C$").unwrap_err().to_string().contains("--allow-admin-shares"));
            let s = Shares::discover(&explicit, &[], true);
            assert_eq!(s.resolve("d$").unwrap(), PathBuf::from("d:\\"));
        }
    }

    #[test]
    fn the_share_holding_a_folder_is_found() {
        let explicit = vec![("data".to_string(), PathBuf::from(r"D:\data")), ("deep".to_string(), PathBuf::from(r"D:\data\users"))];
        let s = Shares::discover(&explicit, &["nothing-like-this".to_string()], false);
        assert_eq!(s.share_for(Path::new(r"D:\data\other")), Some(("data".into(), PathBuf::from("other"))));
        assert_eq!(s.share_for(Path::new(r"d:\DATA\users\user")), Some(("deep".into(), PathBuf::from("user"))));
        assert_eq!(s.share_for(Path::new(r"D:\data\users")), Some(("deep".into(), PathBuf::new())));
        assert_eq!(s.share_for(Path::new(r"D:\other")), None);
    }

    #[test]
    fn smb_conf() {
        let conf = "[global]\n  workgroup = X\n  path = /nope\n; comment\n[Photos]\n  comment = pics\n  Path = /volume1/photos\n[printers]\n path=/var/spool\n[data]\npath = \"/srv/data dir\"\n";
        assert_eq!(
            parse_smb_conf(conf),
            vec![("Photos".into(), PathBuf::from("/volume1/photos")), ("data".into(), PathBuf::from("/srv/data dir"))]
        );
    }
}
