//! SSH mode (DESIGN-LINUX.md): `scopy send <src> host:/path` and `scopy get host:/path <dest>`. SSH is the entry
//! point, as with rsync: `ssh host scopy session …` runs scopy on the other side **as the user SSH logged in** (keys,
//! whatever the user already uses), so that side's permissions apply as for any program of theirs — no AD, no
//! Kerberos, no SMB access ticket, no service. The session announces a port, a one-time token and its TLS
//! certificate fingerprint over the SSH channel; the copy itself runs over scopy's own parallel TLS streams, each
//! joining with the token, and the client accepts only that certificate (so nobody can sit in between).
//!
//! The remote scopy is `scopy` on the PATH, or `$SCOPY_REMOTE` (e.g. a build in the user's home).

use anyhow::{bail, Context, Result};
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

/// `[user@]host:/path` → (ssh destination, remote path). Not a UNC path, not a Windows drive letter (`C:\…`).
pub fn remote(spec: &str) -> Option<(String, String)> {
    if spec.starts_with("\\\\") || spec.starts_with("//") {
        return None;
    }
    let (dest, path) = spec.split_once(':')?;
    let ok = dest.len() >= 2 && !dest.contains(['/', '\\']) && !path.is_empty();
    ok.then(|| (dest.to_string(), path.to_string()))
}

/// `[user@]host::share[/path]` (rsync's daemon syntax) → (ssh destination, a function giving the UNC path the copy
/// code expects for the host the data goes to).
pub fn daemon_spec(spec: &str) -> Option<(String, impl Fn(&str) -> String)> {
    if spec.starts_with("\\\\") || spec.starts_with("//") {
        return None;
    }
    let (dest, rest) = spec.split_once("::")?;
    let rest = rest.trim_start_matches('/');
    let (share, sub) = rest.split_once('/').unwrap_or((rest, ""));
    if dest.is_empty() || dest.contains(['/', '\\']) || share.is_empty() {
        return None;
    }
    let (share, sub) = (share.to_string(), sub.trim_matches('/').replace('/', "\\"));
    Some((dest.to_string(), move |host: &str| if sub.is_empty() { format!(r"\\{host}\{share}") } else { format!(r"\\{host}\{share}\{sub}") }))
}

/// Signs in to the scopy daemon on `dest` through SSH (`ssh dest scopy token`, run as the user there): pins the
/// daemon's certificate, keeps the token for every connection, and returns where the data goes (host, port).
pub fn open_daemon(dest: &str) -> Result<(String, u16)> {
    let at = std::time::Instant::now();
    {
        let mut d = DAEMON.lock().unwrap();
        let lifetime = d.as_ref().map_or(DEFAULT_LIFETIME, |s| s.lifetime);
        *d = Some(SignIn { dest: dest.to_string(), at, lifetime });
    }
    let remote = std::env::var("SCOPY_REMOTE").unwrap_or_default();
    let words: Vec<&str> = remote.split_whitespace().collect();
    let prog = if words.is_empty() { "'scopy'".to_string() } else { words.iter().map(|w| quote(w)).collect::<Vec<_>>().join(" ") };
    let out = Command::new("ssh")
        .args(["-o", "BatchMode=yes", dest, &format!("{prog} token")])
        .stdin(Stdio::null())
        .output()
        .context("cannot start ssh (is an SSH client installed?)")?;
    let text = String::from_utf8_lossy(&out.stdout);
    let Some(line) = text.lines().find(|l| l.starts_with("SCOPY-SESSION ")) else {
        bail!("no sign-in token from {dest}: {}", String::from_utf8_lossy(&out.stderr).trim());
    };
    let parts: Vec<&str> = line.split_whitespace().collect();
    let (port, token, fp, secs) = match parts[..] {
        [_, port, token, fp] => (port, token, fp, None),
        [_, port, token, fp, secs] => (port, token, fp, secs.parse::<u64>().ok()),
        _ => bail!("unexpected answer from the daemon: {line}"),
    };
    let port: u16 = port.parse().context("bad daemon port")?;
    if let (Some(secs), Some(s)) = (secs, DAEMON.lock().unwrap().as_mut()) {
        s.lifetime = Duration::from_secs(secs.max(2));
    }
    crate::client::set_session(token);
    crate::tls::pin_server(fp);
    let host = dest.rsplit_once('@').map_or(dest, |(_, h)| h).to_string();
    eprintln!("signed in to the scopy daemon on {host} as your user there (through SSH), data on port {port}");
    Ok((host, port))
}

/// The daemon this process signed in to: `sign_in_again` renews the token.
static DAEMON: Mutex<Option<SignIn>> = Mutex::new(None);

struct SignIn {
    /// SSH destination.
    dest: String,
    at: std::time::Instant,
    /// How long the daemon accepts the token (it says so; 12 h from a daemon that doesn't).
    lifetime: Duration,
}

const DEFAULT_LIFETIME: Duration = Duration::from_secs(12 * 3600);

/// A long-running sync agent: signs in to its daemon again (expired token, daemon restarted with a new key) — at
/// most every 5 seconds. Nothing to do without a daemon sign-in.
pub fn sign_in_again() {
    let dest = {
        let d = DAEMON.lock().unwrap();
        match &*d {
            Some(s) if s.at.elapsed() > Duration::from_secs(5) => s.dest.clone(),
            _ => return,
        }
    };
    if let Err(e) = open_daemon(&dest) {
        eprintln!("[{}] sign-in to {dest} failed: {e:#}", crate::util::utc_stamp());
    }
}

/// A daemon sign-in past half its token's lifetime: time to renew it, before it expires.
pub fn renewal_due() -> bool {
    DAEMON.lock().unwrap().as_ref().is_some_and(|s| s.at.elapsed() > s.lifetime / 2)
}

/// The remote side's output, kept for a failure message.
type Tail = Arc<Mutex<Vec<String>>>;

pub struct Session {
    child: Child,
    stdin: Option<ChildStdin>,
    /// The host the data streams connect to (the SSH destination without `user@`).
    pub host: String,
    pub port: u16,
    tail: Tail,
}

/// POSIX shell quoting for the remote command line.
fn quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

fn keep(tail: &Tail, line: String) {
    let mut t = tail.lock().unwrap();
    t.push(line);
    if t.len() > 40 {
        t.remove(0);
    }
}

/// The command SSH runs on the other side. `SCOPY_REMOTE` names the remote scopy (default `scopy` on the PATH) and may
/// be a command of several words, like rsync's `--rsync-path`: `sudo -n /usr/local/bin/scopy` receives as root (owners
/// and groups then arrive too). Each word is quoted on its own, so no word is run by the remote shell as code; a
/// path with spaces can't be given this way.
fn remote_command(remote: &str, path: &str, push: bool) -> String {
    let words: Vec<&str> = remote.split_whitespace().collect();
    let words = if words.is_empty() { vec!["scopy"] } else { words };
    let prog = words.iter().map(|w| quote(w)).collect::<Vec<_>>().join(" ");
    format!("{prog} session --mode {} {}", if push { "push" } else { "pull" }, quote(path))
}

/// Starts `scopy session` on `dest` over SSH for a push into (or a pull from) `path` and waits for its announcement.
pub fn open(dest: &str, path: &str, push: bool) -> Result<Session> {
    let cmd = remote_command(&std::env::var("SCOPY_REMOTE").unwrap_or_default(), path, push);
    let mut child = Command::new("ssh")
        .args(["-o", "BatchMode=yes", dest, &cmd])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("cannot start ssh (is an SSH client installed?)")?;
    let tail: Tail = Default::default();
    let (tx, rx) = mpsc::channel::<String>();
    let out = child.stdout.take().unwrap();
    {
        let tail = tail.clone();
        std::thread::spawn(move || {
            let mut first = true;
            for line in BufReader::new(out).lines().map_while(|l| l.ok()) {
                if first && line.starts_with("SCOPY-SESSION ") {
                    let _ = tx.send(line);
                    first = false;
                } else {
                    keep(&tail, line);
                }
            }
        });
    }
    let err = child.stderr.take().unwrap();
    {
        let tail = tail.clone();
        std::thread::spawn(move || BufReader::new(err).lines().map_while(|l| l.ok()).for_each(|l| keep(&tail, l)));
    }
    let stdin = child.stdin.take();
    let line = match rx.recv_timeout(Duration::from_secs(60)) {
        Ok(l) => l,
        Err(_) => {
            let _ = child.kill();
            std::thread::sleep(Duration::from_millis(300));
            let why = tail.lock().unwrap().join("\n");
            bail!("the SSH session to {dest} did not start{}", if why.is_empty() { String::new() } else { format!(":\n{why}") });
        }
    };
    let parts: Vec<&str> = line.split_whitespace().collect();
    let [_, port, token, fp] = parts[..] else { bail!("unexpected session announcement: {line}") };
    let port: u16 = port.parse().context("bad session port")?;
    crate::client::set_session(token);
    crate::tls::pin_server(fp);
    let host = dest.rsplit_once('@').map_or(dest, |(_, h)| h).to_string();
    eprintln!("ssh session: {dest} (the other side runs as your user there), data on port {port}");
    Ok(Session { child, stdin, host, port, tail })
}

impl Session {
    /// The UNC-style destination the copy code expects: the session's only share is `ssh`.
    pub fn unc(&self) -> String {
        format!("\\\\{}\\ssh", self.host)
    }

    /// What the remote side said (for a failure message).
    pub fn tail(&self) -> String {
        self.tail.lock().unwrap().join("\n")
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        // Closing the SSH channel ends the remote session.
        if let Some(mut s) = self.stdin.take() {
            let _ = s.flush();
        }
        for _ in 0..50 {
            if matches!(self.child.try_wait(), Ok(Some(_))) {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let _ = self.child.kill();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_specs_are_told_from_local_and_unc_paths() {
        assert_eq!(remote("host2:/data/in"), Some(("host2".into(), "/data/in".into())));
        assert_eq!(remote("scopy@nas2:/data"), Some(("scopy@nas2".into(), "/data".into())));
        assert_eq!(remote("host:relative/dir"), Some(("host".into(), "relative/dir".into())));
        assert_eq!(remote(r"C:\data"), None); // a drive letter
        assert_eq!(remote(r"\\server\share\x"), None);
        assert_eq!(remote("//server/share"), None);
        assert_eq!(remote("/local/path"), None);
        assert_eq!(remote("host:"), None);
        let (d, unc) = daemon_spec("me@nas2::data/in/x").unwrap();
        assert_eq!((d.as_str(), unc("nas2").as_str()), ("me@nas2", r"\\nas2\data\in\x"));
        assert_eq!(daemon_spec("nas2::data").unwrap().1("nas2"), r"\\nas2\data");
        assert!(daemon_spec("nas2::").is_none() && daemon_spec(r"\\srv\share").is_none() && daemon_spec("host:/p").is_none());
        assert_eq!(remote_command("", "/d", true), "'scopy' session --mode push '/d'");
        assert_eq!(remote_command("sudo -n /opt/scopy", "/a b", false), "'sudo' '-n' '/opt/scopy' session --mode pull '/a b'");
        assert_eq!(remote_command("x;rm -rf ~", "/d", true), "'x;rm' '-rf' '~' session --mode push '/d'");
        assert_eq!(quote("it's"), r"'it'\''s'");
    }
}
