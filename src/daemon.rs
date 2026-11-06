//! Linux daemon sign-in (DESIGN-LINUX "The daemon"): `scopy serve` running as root hands out tokens to local users
//! through a Unix socket. `ssh host scopy token` runs as the user; the daemon learns who is asking from the kernel
//! (`SO_PEERCRED`: the peer's real uid, which a process can't fake) and answers with a random token for that user,
//! its port and its certificate fingerprint — the same announcement line as an SSH session. Every connection to the
//! daemon then starts with the token; the daemon acts as the token's user (auth.rs, per-thread file-system identity).
//!
//! Tokens live in memory only (a restart forgets them: the client asks again) and expire after `LIFETIME`.

use crate::auth::Identity;
use anyhow::{bail, Context, Result};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const DEFAULT_SOCKET: &str = "/run/scopy/token.sock";
/// How long a token is accepted. A sync agent asks for a new one before (and after a daemon restart).
pub const LIFETIME: Duration = Duration::from_secs(12 * 3600);
/// Tokens kept per user; asking again beyond that forgets the oldest.
const PER_USER: usize = 32;

pub struct Tokens {
    map: Mutex<HashMap<String, (Arc<Identity>, Instant)>>,
    lifetime: Duration,
}

impl Default for Tokens {
    fn default() -> Self {
        Tokens::new(LIFETIME)
    }
}

impl Tokens {
    /// Tokens accepted for `lifetime` (`LIFETIME` except in tests: `serve --token-lifetime`).
    pub fn new(lifetime: Duration) -> Self {
        Tokens { map: Default::default(), lifetime }
    }

    /// A new token for `user`.
    pub fn issue(&self, user: Identity) -> String {
        let token = crate::util::random_hex(32);
        let mut m = self.map.lock().unwrap();
        let now = Instant::now();
        m.retain(|_, (_, until)| *until > now);
        let mut mine: Vec<(String, Instant)> = m.iter().filter(|(_, (u, _))| u.uid == user.uid).map(|(t, (_, until))| (t.clone(), *until)).collect();
        if mine.len() >= PER_USER {
            mine.sort_by_key(|(_, until)| *until);
            for (t, _) in &mine[..=mine.len() - PER_USER] {
                m.remove(t);
            }
        }
        m.insert(token.clone(), (Arc::new(user), now + self.lifetime));
        token
    }

    /// The user a token was issued to, while it is valid.
    pub fn check(&self, token: &str) -> Option<Arc<Identity>> {
        let m = self.map.lock().unwrap();
        m.get(token).filter(|(_, until)| *until > Instant::now()).map(|(u, _)| u.clone())
    }
}

/// The uid of the process at the other end of a Unix socket, as the kernel recorded it at connect time.
fn peer_uid(s: &UnixStream) -> Result<u32> {
    use std::os::fd::AsRawFd;
    let mut cred = libc::ucred { pid: 0, uid: 0, gid: 0 };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: SO_PEERCRED fills a ucred of the size passed; the socket is open for the call.
    let rc = unsafe { libc::getsockopt(s.as_raw_fd(), libc::SOL_SOCKET, libc::SO_PEERCRED, (&mut cred as *mut libc::ucred).cast(), &mut len) };
    if rc != 0 {
        bail!("cannot read the caller's identity: {}", std::io::Error::last_os_error());
    }
    Ok(cred.uid)
}

/// Serves token requests on `path` until the process ends. Any local user may connect (mode 0666); each gets a
/// token for themselves only.
pub fn serve_tokens(path: &Path, tokens: Arc<Tokens>, port: u16, fingerprint: String) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("cannot create {}", dir.display()))?;
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755));
    }
    // A socket left by an earlier run (only a socket: never remove anything else at that path).
    if std::fs::symlink_metadata(path).is_ok_and(|m| std::os::unix::fs::FileTypeExt::is_socket(&m.file_type())) {
        let _ = std::fs::remove_file(path);
    }
    let listener = UnixListener::bind(path).with_context(|| format!("cannot open the token socket {}", path.display()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666))?;
    crate::logln!("token socket {} (`ssh <host> scopy token` signs users in)", path.display());
    std::thread::spawn(move || {
        for s in listener.incoming() {
            let Ok(mut s) = s else { continue };
            let (tokens, fp) = (tokens.clone(), fingerprint.clone());
            std::thread::spawn(move || {
                let r = (|| -> Result<String> {
                    let uid = peer_uid(&s)?;
                    let user = Identity::for_uid(uid)?;
                    let name = user.user.clone();
                    let token = tokens.issue(user);
                    // The fifth word: seconds the token lasts, so a long-running client renews it before then.
                    writeln!(s, "SCOPY-SESSION {port} {token} {fp} {}", tokens.lifetime.as_secs())?;
                    Ok(name)
                })();
                match r {
                    Ok(name) => crate::logln!("token issued to {name}"),
                    Err(e) => {
                        let _ = writeln!(s, "ERROR {e:#}");
                        crate::logln!("token refused: {e:#}");
                    }
                }
            });
        }
    });
    Ok(())
}

/// `scopy token` (run by the user, usually through `ssh host scopy token`): asks the local daemon for a token and
/// prints its announcement line.
pub fn token_cmd(socket: Option<PathBuf>) -> Result<()> {
    let path = socket.or_else(|| std::env::var_os("SCOPY_TOKEN_SOCKET").map(PathBuf::from)).unwrap_or_else(|| PathBuf::from(DEFAULT_SOCKET));
    let s = UnixStream::connect(&path).with_context(|| format!("no scopy daemon at {} (is `scopy serve` running as a service?)", path.display()))?;
    s.set_read_timeout(Some(Duration::from_secs(10)))?;
    let mut line = String::new();
    BufReader::new(&s).read_line(&mut line)?;
    let line = line.trim_end();
    if let Some(e) = line.strip_prefix("ERROR ") {
        bail!("the daemon refused: {e}");
    }
    if !line.starts_with("SCOPY-SESSION ") {
        bail!("unexpected answer from the daemon: {line}");
    }
    println!("{line}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user(uid: u32) -> Identity {
        Identity { user: format!("u{uid}"), uid, gid: uid, groups: vec![uid] }
    }

    #[test]
    fn tokens_belong_to_their_user_and_are_bounded_per_user() {
        let t = Tokens::default();
        let a = t.issue(user(1001));
        let b = t.issue(user(1002));
        assert_eq!(t.check(&a).unwrap().uid, 1001);
        assert_eq!(t.check(&b).unwrap().uid, 1002);
        assert!(t.check("nope").is_none());
        let first = t.issue(user(1003));
        for _ in 0..PER_USER {
            t.issue(user(1003));
        }
        assert!(t.check(&first).is_none(), "the oldest token of a user beyond the limit is forgotten");
        assert!(t.check(&a).is_some(), "other users' tokens stay");
    }

    #[test]
    fn the_socket_names_the_caller_from_the_kernel() {
        let dir = std::env::temp_dir().join(format!("scopy-token-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("t.sock");
        let tokens = Arc::new(Tokens::default());
        serve_tokens(&path, tokens.clone(), 7788, "fp".into()).unwrap();
        let s = UnixStream::connect(&path).unwrap();
        let mut line = String::new();
        BufReader::new(&s).read_line(&mut line).unwrap();
        let parts: Vec<&str> = line.split_whitespace().collect();
        assert_eq!((parts[0], parts[1], parts[3], parts[4]), ("SCOPY-SESSION", "7788", "fp", "43200"));
        // SAFETY: geteuid has no preconditions.
        assert_eq!(tokens.check(parts[2]).unwrap().uid, unsafe { libc::geteuid() });
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
