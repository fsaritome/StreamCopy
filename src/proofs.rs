//! Remembered access proofs (protocol 20). A push or pull proves access the normal way, through SMB with the
//! user's own credentials (the ticket in server.rs / client.rs). That costs a few SMB round trips (0.4–0.55 s over
//! a VPN) and a sync agent does it several times a minute for the same folder. So after a successful proof the
//! receiver hands out a token; for `LIFETIME` a push (write) or pull (read) of the same folder by the same signed-in
//! user may show the token instead of proving again.
//!
//! What a token is worth: nothing on its own. It is accepted only on a connection that has signed in (Kerberos,
//! bound to that connection's TLS session) as the same Windows user (SID) the proof was made for, for the same
//! folder (the resolved local path) and the same direction (a read proof doesn't stand in for a write). The
//! receiver acts as that user either way, so NTFS permissions still apply to every file; what the token skips is
//! only the repeated SMB check, so a share-level change takes effect within `LIFETIME` at the latest. Tokens live
//! in the receiver's memory only (a restart forgets them) and are not extended: a fresh proof every `LIFETIME`.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub const LIFETIME: Duration = Duration::from_secs(600);

struct Proof {
    sid: String,
    base: String,
    write: bool,
    until: Instant,
}

#[derive(Default)]
pub struct Proofs {
    m: Mutex<HashMap<String, Proof>>,
}

fn key(base: &Path) -> String {
    crate::util::path_key(&base.to_string_lossy())
}

impl Proofs {
    /// A token for `sid`'s proven access to `base` (`write`: a push's proof; otherwise a pull's).
    pub fn issue(&self, sid: &str, base: &Path, write: bool) -> String {
        let token = crate::util::random_hex(32);
        let mut m = self.m.lock().unwrap();
        let now = Instant::now();
        m.retain(|_, p| p.until > now);
        m.insert(token.clone(), Proof { sid: sid.to_string(), base: key(base), write, until: now + LIFETIME });
        token
    }

    /// Whether `token` stands for a proof `sid` made for `base` in that direction, still within its lifetime.
    pub fn check(&self, token: &str, sid: &str, base: &Path, write: bool) -> bool {
        if token.is_empty() || sid.is_empty() {
            return false;
        }
        let m = self.m.lock().unwrap();
        m.get(token).is_some_and(|p| p.until > Instant::now() && p.sid == sid && p.write == write && p.base == key(base))
    }

    #[cfg(test)]
    fn age(&self, token: &str, by: Duration) {
        if let Some(p) = self.m.lock().unwrap().get_mut(token) {
            p.until -= by;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_token_counts_only_for_its_user_folder_direction_and_time() {
        let p = Proofs::default();
        let base = Path::new(r"D:\data\users\ann\Downloads");
        let t = p.issue("S-1-5-21-1-1001", base, true);
        assert!(p.check(&t, "S-1-5-21-1-1001", base, true));
        assert!(p.check(&t, "S-1-5-21-1-1001", Path::new(r"d:\DATA\users\ann\downloads\"), true)); // same folder
        assert!(!p.check(&t, "S-1-5-21-1-1002", base, true)); // another user
        assert!(!p.check(&t, "S-1-5-21-1-1001", Path::new(r"D:\data\users\ann\Documents"), true)); // another folder
        assert!(!p.check(&t, "S-1-5-21-1-1001", Path::new(r"D:\data\users\ann"), true)); // the folder above
        assert!(!p.check(&t, "S-1-5-21-1-1001", base, false)); // a write proof is not a read proof
        assert!(!p.check("", "S-1-5-21-1-1001", base, true) && !p.check("deadbeef", "S-1-5-21-1-1001", base, true));
        assert!(!p.check(&t, "", base, true)); // no sign-in
        p.age(&t, LIFETIME);
        assert!(!p.check(&t, "S-1-5-21-1-1001", base, true)); // expired
        let r = p.issue("S-1-5-21-1-1001", base, false);
        assert!(p.check(&r, "S-1-5-21-1-1001", base, false) && !p.check(&r, "S-1-5-21-1-1001", base, true));
    }
}
