//! Sign-in as the user (protocol 11). On the control connection the client authenticates with Windows Negotiate
//! (Kerberos, NTLM as fallback) to the receiver's computer account (SPN `HOST/<server>`, which every domain computer
//! already has). The TLS binding goes in as channel binding, so a sign-in can't be relayed through a man in the middle.
//! The receiver then acts as the user: every thread that touches the share for the job impersonates the user's token,
//! so NTFS permissions, owner and quotas apply exactly as over SMB. Only scopy's own housekeeping (job records next to
//! the exe, the volume flush) runs as the service (`as_service`).
//!
//! Wire: C→R method:u8 (0 = none: a client without Windows sign-in; 1 = Negotiate), then for Negotiate rounds of
//! C→R token:blob / R→C status, done:u8, token:blob until the receiver says done.

use crate::proto::*;
use crate::tls::Binding;
use anyhow::{bail, Result};
use std::io::{Read, Write};
use std::sync::Arc;

pub const METHOD_NONE: u8 = 0;
/// Windows sign-in (Negotiate/Kerberos via SSPI). Other systems don't offer it (yet); a receiver there answers
/// METHOD_NONE clients only.
#[cfg_attr(not(windows), allow(dead_code))]
pub const METHOD_NEGOTIATE: u8 = 1;

/// Channel-binding application data: ties the sign-in to this TLS session.
#[cfg(windows)]
fn cb_data(b: &Binding) -> Vec<u8> {
    let mut v = b"scopy-tls-exporter:".to_vec();
    v.extend_from_slice(b);
    v
}

/// Client side: signs in as the logged-on user (Windows), or says it can't.
pub fn client(r: &mut impl Read, w: &mut impl Write, host: &str, bind: &Binding) -> Result<()> {
    // SSH mode: SSH has signed us in; the other side runs as our user.
    if crate::client::in_session() {
        let _ = (r, host, bind);
        w.put_u8(METHOD_NONE)?;
        w.flush()?;
        return Ok(());
    }
    #[cfg(windows)]
    {
        w.put_u8(METHOD_NEGOTIATE)?;
        sspi::client(r, w, &format!("HOST/{host}"), &cb_data(bind))
    }
    #[cfg(not(windows))]
    {
        let _ = (r, host, bind);
        w.put_u8(METHOD_NONE)?;
        w.flush()?;
        Ok(())
    }
}

thread_local! {
    /// The user a Linux daemon connection already signed in as with its token (`preauth`), for `server`.
    static PREAUTH: std::cell::RefCell<Option<Arc<Identity>>> = const { std::cell::RefCell::new(None) };
}

/// A daemon connection showed a valid token for `user` (server.rs): `server` on this thread returns that user.
pub fn preauth(user: Arc<Identity>) {
    PREAUTH.with(|p| *p.borrow_mut() = Some(user));
}

/// Receiver side: the signed-in user, or None for a client without Windows sign-in (it then works with the
/// service's rights, as before 0.11, limited by the SMB access check). On a Linux daemon a client that signed in
/// with its token sends METHOD_NONE and gets the token's user.
pub fn server(r: &mut impl Read, w: &mut impl Write, bind: &Binding) -> Result<Option<Arc<Identity>>> {
    #[cfg(not(windows))]
    let _ = bind;
    match r.get_u8()? {
        METHOD_NONE => Ok(PREAUTH.with(|p| p.borrow().clone())),
        #[cfg(windows)]
        METHOD_NEGOTIATE => Ok(Some(Arc::new(sspi::server(r, w, &cb_data(bind))?))),
        m => {
            w.put_err(&format!("sign-in method {m} not supported by this receiver"))?;
            bail!("sign-in method {m} not supported")
        }
    }
}

#[cfg(windows)]
pub use sspi::{as_service, Act, Identity};

#[cfg(windows)]
pub use sspi::capture;

#[cfg(unix)]
pub use unix::{as_service, capture, Act, Identity};

#[cfg(not(any(windows, unix)))]
pub use none::{as_service, capture, Act, Identity};

/// Linux/Unix: acting as a user = switching this thread's file-system identity (fsuid, fsgid, supplementary groups).
/// Raw syscalls on purpose: glibc's and musl's `setgroups`/`setresuid` switch every thread of the process, the
/// kernel calls only the calling one. With fsuid ≠ 0 the kernel also drops the file capabilities (CAP_DAC_OVERRIDE,
/// CAP_CHOWN, CAP_FOWNER, …) from the thread, so every access, `chown` and `chmod` is decided as for the user's own
/// programs. Only a process running as root can act as someone else.
#[cfg(unix)]
mod unix {
    use anyhow::{bail, Result};
    use std::cell::RefCell;
    use std::sync::OnceLock;

    #[derive(Clone, Debug, PartialEq)]
    struct Creds {
        uid: u32,
        gid: u32,
        groups: Vec<u32>,
    }

    /// A local user: name, uid, primary group and every group they are in.
    #[derive(Debug)]
    pub struct Identity {
        pub user: String,
        pub uid: u32,
        pub gid: u32,
        pub groups: Vec<u32>,
    }

    thread_local! {
        /// What this thread currently acts as (None = the process's own identity).
        static CURRENT: RefCell<Option<Creds>> = const { RefCell::new(None) };
    }

    /// The process's own identity, read on a thread that hasn't switched (the first switch reads it).
    static OWN: OnceLock<Creds> = OnceLock::new();

    fn own() -> &'static Creds {
        OWN.get_or_init(|| {
            // SAFETY: getgroups with a buffer of the size it reported; geteuid/getegid have no preconditions.
            let n = unsafe { libc::getgroups(0, std::ptr::null_mut()) }.max(0) as usize;
            let mut g: Vec<libc::gid_t> = vec![0; n];
            let n = unsafe { libc::getgroups(n as libc::c_int, g.as_mut_ptr()) }.max(0) as usize;
            g.truncate(n);
            Creds { uid: unsafe { libc::geteuid() }, gid: unsafe { libc::getegid() }, groups: g.into_iter().map(|x| x as u32).collect() }
        })
    }

    /// Switches the calling thread (only it) to `c`.
    fn apply(c: &Creds) -> Result<()> {
        let groups: Vec<libc::gid_t> = c.groups.iter().map(|&g| g as libc::gid_t).collect();
        // SAFETY: raw syscalls with plain integer arguments and a buffer valid for `groups.len()` ids.
        unsafe {
            if libc::syscall(libc::SYS_setgroups, groups.len(), groups.as_ptr()) != 0 {
                bail!("cannot switch groups: {}", std::io::Error::last_os_error());
            }
            libc::syscall(libc::SYS_setfsgid, c.gid);
            libc::syscall(libc::SYS_setfsuid, c.uid);
            // setfsuid/setfsgid report no errors: ask again (an invalid id leaves it unchanged and returns it).
            let (u, g) = (libc::syscall(libc::SYS_setfsuid, u32::MAX) as u32, libc::syscall(libc::SYS_setfsgid, u32::MAX) as u32);
            if u != c.uid || g != c.gid {
                bail!("cannot switch the file-system identity to {}:{} (now {u}:{g})", c.uid, c.gid);
            }
        }
        Ok(())
    }

    /// While alive, the current thread acts as the user; dropping it returns to what it was before.
    pub struct Act {
        prev: Option<Creds>,
    }

    impl Identity {
        /// The user with this uid, from the user database (the daemon's sign-in: the uid comes from the kernel).
        pub fn for_uid(uid: u32) -> Result<Identity> {
            let Some((user, gid)) = crate::meta::user_record(uid) else { bail!("uid {uid} is not a known user") };
            let groups = crate::meta::user_groups(&user, gid);
            Ok(Identity { user, uid, gid, groups })
        }

        pub fn short_name(&self) -> String {
            self.user.clone()
        }

        /// The key the receiver files a user's feeds, locks and proofs under (a Windows SID elsewhere).
        pub fn sid(&self) -> Result<String> {
            Ok(format!("unix-uid-{}", self.uid))
        }

        pub fn enter(&self) -> Result<Act> {
            let me = Creds { uid: self.uid, gid: self.gid, groups: self.groups.clone() };
            switch(Some(me)).map_err(|e| anyhow::anyhow!("cannot act as {}: {e:#}", self.user))
        }
    }

    /// Makes the thread act as `to` (None = the process itself) and returns the guard that switches back.
    fn switch(to: Option<Creds>) -> Result<Act> {
        let prev = CURRENT.with(|c| c.borrow().clone());
        let own = if prev.is_none() { own().clone() } else { OWN.get().cloned().unwrap_or_else(|| own().clone()) };
        let target = to.clone().unwrap_or_else(|| own.clone());
        if target != prev.clone().unwrap_or_else(|| own.clone()) {
            if own.uid != 0 && target.uid != own.uid {
                bail!("only a receiver running as root can act as another user");
            }
            apply(&target)?;
        }
        CURRENT.with(|c| *c.borrow_mut() = to);
        Ok(Act { prev })
    }

    impl Drop for Act {
        fn drop(&mut self) {
            let back = self.prev.clone().unwrap_or_else(|| own().clone());
            if apply(&back).is_err() {
                // Never go on with the wrong identity: a thread that can't switch back must not touch anything.
                eprintln!("fatal: cannot switch a thread back to uid {}", back.uid);
                std::process::abort();
            }
            CURRENT.with(|c| *c.borrow_mut() = self.prev.take());
        }
    }

    /// Runs `f` with the service's own rights (scopy's housekeeping), then returns to the user.
    pub fn as_service<T>(f: impl FnOnce() -> T) -> T {
        if CURRENT.with(|c| c.borrow().is_none()) {
            return f();
        }
        let guard = match switch(None) {
            Ok(g) => g,
            Err(e) => {
                eprintln!("fatal: {e:#}");
                std::process::abort();
            }
        };
        let r = f();
        drop(guard);
        r
    }

    /// What the current thread acts as, for threads it starts (`Inherit::enter` in each of them).
    pub fn capture() -> Inherit {
        Inherit(CURRENT.with(|c| c.borrow().clone()))
    }

    pub struct Inherit(Option<Creds>);

    impl Inherit {
        /// Acts as the captured identity on this (new) thread; None if there was nothing to take over. A failure to
        /// switch ends the process: the thread would otherwise run with the receiver's full rights.
        pub fn enter(&self) -> Option<Act> {
            let c = self.0.clone()?;
            match switch(Some(c)) {
                Ok(a) => Some(a),
                Err(e) => {
                    eprintln!("fatal: {e:#}");
                    std::process::abort();
                }
            }
        }
    }
}

#[cfg(not(any(windows, unix)))]
mod none {
    use anyhow::Result;
    pub struct Identity {
        pub user: String,
    }
    pub struct Act;
    impl Identity {
        pub fn enter(&self) -> Result<Act> {
            Ok(Act)
        }
        pub fn short_name(&self) -> String {
            self.user.clone()
        }
        pub fn sid(&self) -> Result<String> {
            anyhow::bail!("no SIDs on this platform")
        }
    }
    pub fn as_service<T>(f: impl FnOnce() -> T) -> T {
        f()
    }
    pub fn capture() -> Inherit {
        Inherit
    }
    pub struct Inherit;
    impl Inherit {
        pub fn enter(&self) -> Option<Act> {
            None
        }
    }
}

#[cfg(windows)]
mod sspi {
    use crate::proto::*;
    use anyhow::{bail, Context, Result};
    use std::cell::Cell;
    use std::ffi::c_void;
    use std::io::{Read, Write};
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::Authentication::Identity::*;
    use windows_sys::Win32::Security::Credentials::SecHandle;
    use windows_sys::Win32::Security::{ImpersonateLoggedOnUser, RevertToSelf};

    const SEC_E_OK: i32 = 0;
    const SEC_I_CONTINUE_NEEDED: i32 = 0x0009_0312;
    const TOKEN: u32 = 2; // SECBUFFER_TOKEN
    const CHANNEL_BINDINGS: u32 = 14; // SECBUFFER_CHANNEL_BINDINGS
    const NATIVE_DREP: u32 = 0x10;
    const ISC_FLAGS: u32 = 0x100 | 0x2 | 0x800; // ALLOCATE_MEMORY | MUTUAL_AUTH | CONNECTION
    const ASC_FLAGS: u32 = 0x100 | 0x2 | 0x800;
    const ATTR_NAMES: u32 = 1; // SECPKG_ATTR_NAMES

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(Some(0)).collect()
    }

    /// SEC_CHANNEL_BINDINGS with only application data, followed by the data.
    fn bindings(app: &[u8]) -> Vec<u8> {
        let head = std::mem::size_of::<SEC_CHANNEL_BINDINGS>();
        let mut v = vec![0u8; head + app.len()];
        let cb = SEC_CHANNEL_BINDINGS {
            dwInitiatorAddrType: 0,
            cbInitiatorLength: 0,
            dwInitiatorOffset: 0,
            dwAcceptorAddrType: 0,
            cbAcceptorLength: 0,
            dwAcceptorOffset: 0,
            cbApplicationDataLength: app.len() as u32,
            dwApplicationDataOffset: head as u32,
        };
        // SAFETY: plain-data struct copied into a buffer of at least its size.
        unsafe { std::ptr::copy_nonoverlapping((&cb as *const SEC_CHANNEL_BINDINGS).cast::<u8>(), v.as_mut_ptr(), head) };
        v[head..].copy_from_slice(app);
        v
    }

    /// Credentials and context handles, freed on drop.
    struct Ctx {
        cred: SecHandle,
        ctx: SecHandle,
        has_ctx: bool,
    }

    impl Drop for Ctx {
        fn drop(&mut self) {
            // SAFETY: handles were filled by the SSPI calls that succeeded.
            unsafe {
                if self.has_ctx {
                    DeleteSecurityContext(&self.ctx);
                }
                FreeCredentialsHandle(&self.cred);
            }
        }
    }

    fn acquire(inbound: bool) -> Result<Ctx> {
        let pkg = wide("Negotiate");
        let mut cred = SecHandle { dwLower: 0, dwUpper: 0 };
        let mut expiry = 0i64;
        let use_ = if inbound { SECPKG_CRED_INBOUND } else { SECPKG_CRED_OUTBOUND };
        // SAFETY: all pointers are valid or null as the API allows.
        let s = unsafe { AcquireCredentialsHandleW(null(), pkg.as_ptr(), use_, null(), null(), None, null(), &mut cred, &mut expiry) };
        if s != SEC_E_OK {
            bail!("cannot get Windows credentials for the sign-in (0x{s:08x})");
        }
        Ok(Ctx { cred, ctx: SecHandle { dwLower: 0, dwUpper: 0 }, has_ctx: false })
    }

    /// Takes the token SSPI allocated into an owned Vec and frees it.
    fn take_out(buf: &SecBuffer) -> Vec<u8> {
        if buf.pvBuffer.is_null() {
            return Vec::new();
        }
        // SAFETY: SSPI allocated cbBuffer bytes at pvBuffer (ALLOCATE_MEMORY).
        let v = unsafe { std::slice::from_raw_parts(buf.pvBuffer.cast::<u8>(), buf.cbBuffer as usize) }.to_vec();
        unsafe { FreeContextBuffer(buf.pvBuffer) };
        v
    }

    /// One InitializeSecurityContext / AcceptSecurityContext step: (status, output token).
    fn step(c: &mut Ctx, accept: bool, spn: &[u16], input: Option<&[u8]>, cb: &mut [u8]) -> (i32, Vec<u8>) {
        let mut ins = Vec::with_capacity(2);
        let mut tok = input.map(|i| i.to_vec()).unwrap_or_default();
        if input.is_some() {
            ins.push(SecBuffer { cbBuffer: tok.len() as u32, BufferType: TOKEN, pvBuffer: tok.as_mut_ptr().cast::<c_void>() });
        }
        ins.push(SecBuffer { cbBuffer: cb.len() as u32, BufferType: CHANNEL_BINDINGS, pvBuffer: cb.as_mut_ptr().cast::<c_void>() });
        let in_desc = SecBufferDesc { ulVersion: 0, cBuffers: ins.len() as u32, pBuffers: ins.as_mut_ptr() };
        let mut out = SecBuffer { cbBuffer: 0, BufferType: TOKEN, pvBuffer: null_mut() };
        let mut out_desc = SecBufferDesc { ulVersion: 0, cBuffers: 1, pBuffers: &mut out };
        let (mut attrs, mut expiry) = (0u32, 0i64);
        // After the first call SSPI wants the same handle as old and new context.
        let prev: *const SecHandle = if c.has_ctx { &c.ctx } else { null() };
        let mut first = SecHandle { dwLower: 0, dwUpper: 0 };
        let next: *mut SecHandle = if c.has_ctx { &mut c.ctx } else { &mut first };
        // SAFETY: buffers live until the call returns; handles are valid or null on the first call.
        let s = unsafe {
            if accept {
                AcceptSecurityContext(&c.cred, prev, &in_desc, ASC_FLAGS, NATIVE_DREP, next, &mut out_desc, &mut attrs, &mut expiry)
            } else {
                InitializeSecurityContextW(&c.cred, prev, spn.as_ptr(), ISC_FLAGS, 0, NATIVE_DREP, &in_desc, 0, next, &mut out_desc, &mut attrs, &mut expiry)
            }
        };
        if s == SEC_E_OK || s == SEC_I_CONTINUE_NEEDED {
            if !c.has_ctx {
                c.ctx = first;
                c.has_ctx = true;
            }
        }
        (s, take_out(&out))
    }

    pub fn client(r: &mut impl Read, w: &mut impl Write, spn: &str, app: &[u8]) -> Result<()> {
        let spn = wide(spn);
        let mut cb = bindings(app);
        let mut c = acquire(false)?;
        let (mut s, mut out) = step(&mut c, false, &spn, None, &mut cb);
        loop {
            if s != SEC_E_OK && s != SEC_I_CONTINUE_NEEDED {
                bail!("Windows sign-in to the receiver failed (0x{s:08x}); is this PC in the domain and the receiver's name right?");
            }
            w.put_blob(&out)?;
            w.flush()?;
            r.get_status().context("the receiver refused the Windows sign-in")?;
            let done = r.get_u8()? != 0;
            let reply = r.get_blob()?;
            if done {
                if !reply.is_empty() && s == SEC_I_CONTINUE_NEEDED {
                    // Mutual authentication: the receiver's last token proves it is the computer we asked for.
                    let (s2, _) = step(&mut c, false, &spn, Some(&reply), &mut cb);
                    if s2 != SEC_E_OK {
                        bail!("the receiver's answer to the sign-in did not verify (0x{s2:08x})");
                    }
                }
                return Ok(());
            }
            (s, out) = step(&mut c, false, &spn, Some(&reply), &mut cb);
        }
    }

    pub fn server(r: &mut impl Read, w: &mut impl Write, app: &[u8]) -> Result<Identity> {
        let mut cb = bindings(app);
        let mut c = acquire(true)?;
        for _ in 0..8 {
            let tok = r.get_blob()?;
            let (s, out) = step(&mut c, true, &[0], Some(&tok), &mut cb);
            if s == SEC_I_CONTINUE_NEEDED {
                w.put_ok()?;
                w.put_u8(0)?;
                w.put_blob(&out)?;
                w.flush()?;
                continue;
            }
            if s != SEC_E_OK {
                w.put_err("Windows sign-in refused")?;
                w.flush()?;
                bail!("Windows sign-in refused (0x{s:08x})");
            }
            let id = identity(&c)?;
            w.put_ok()?;
            w.put_u8(1)?;
            w.put_blob(&out)?;
            w.flush()?;
            return Ok(id);
        }
        bail!("Windows sign-in did not finish")
    }

    fn identity(c: &Ctx) -> Result<Identity> {
        let mut token: HANDLE = null_mut();
        // SAFETY: the context is complete; the token is ours to close.
        let s = unsafe { QuerySecurityContextToken(&c.ctx, &mut token) };
        if s != SEC_E_OK {
            bail!("cannot get the user's token (0x{s:08x})");
        }
        let mut names = SecPkgContext_NamesW { sUserName: null_mut() };
        // SAFETY: the buffer is the struct SECPKG_ATTR_NAMES fills; the name is freed below.
        let user = unsafe {
            if QueryContextAttributesW(&c.ctx, ATTR_NAMES, (&mut names as *mut SecPkgContext_NamesW).cast()) == SEC_E_OK && !names.sUserName.is_null() {
                let n = (0..).take_while(|&i| *names.sUserName.add(i) != 0).count();
                let s = String::from_utf16_lossy(std::slice::from_raw_parts(names.sUserName, n));
                FreeContextBuffer(names.sUserName.cast());
                s
            } else {
                "?".into()
            }
        };
        Ok(Identity { token: token as usize, user })
    }

    /// The signed-in user: an impersonation token.
    pub struct Identity {
        token: usize,
        pub user: String,
    }

    impl Drop for Identity {
        fn drop(&mut self) {
            // SAFETY: we own the token handle.
            unsafe { CloseHandle(self.token as HANDLE) };
        }
    }

    thread_local! {
        /// Token this thread currently impersonates (0 = none).
        static CURRENT: Cell<usize> = const { Cell::new(0) };
    }

    /// While alive, the current thread acts as the user.
    pub struct Act {
        prev: usize,
    }

    impl Identity {
        /// The account name without the domain (`CORP\user` → `user`, `user@ad.example` → `user`).
        pub fn short_name(&self) -> String {
            let u = self.user.rsplit('\\').next().unwrap_or(&self.user);
            u.split('@').next().unwrap_or(u).to_string()
        }

        /// The user's SID as text (`S-1-5-21-…`).
        pub fn sid(&self) -> Result<String> {
            use windows_sys::Win32::Foundation::LocalFree;
            use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
            use windows_sys::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_USER};
            let mut buf = vec![0u64; 64]; // 512 bytes, aligned: TOKEN_USER plus the SID
            let mut len = 0u32;
            // SAFETY: the buffer is writable for the length passed; the token is valid.
            if unsafe { GetTokenInformation(self.token as HANDLE, TokenUser, buf.as_mut_ptr().cast(), (buf.len() * 8) as u32, &mut len) } == 0 {
                bail!("cannot read the user's SID: {}", std::io::Error::last_os_error());
            }
            // SAFETY: GetTokenInformation filled a TOKEN_USER at the start of the buffer.
            let sid = unsafe { (*(buf.as_ptr() as *const TOKEN_USER)).User.Sid };
            let mut text: *mut u16 = null_mut();
            // SAFETY: `sid` points into `buf`; the string is freed with LocalFree.
            if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 {
                bail!("cannot convert the user's SID: {}", std::io::Error::last_os_error());
            }
            let s = unsafe {
                let n = (0..).take_while(|&i| *text.add(i) != 0).count();
                let s = String::from_utf16_lossy(std::slice::from_raw_parts(text, n));
                LocalFree(text.cast());
                s
            };
            Ok(s)
        }

        pub fn enter(&self) -> Result<Act> {
            // SAFETY: the token is a valid impersonation token for the lifetime of `self`.
            if unsafe { ImpersonateLoggedOnUser(self.token as HANDLE) } == 0 {
                bail!("cannot act as {}: {}", self.user, std::io::Error::last_os_error());
            }
            let prev = CURRENT.with(|c| c.replace(self.token));
            Ok(Act { prev })
        }
    }

    impl Drop for Act {
        fn drop(&mut self) {
            // SAFETY: reverting / restoring the thread's previous identity.
            unsafe {
                if self.prev == 0 {
                    RevertToSelf();
                } else {
                    ImpersonateLoggedOnUser(self.prev as HANDLE);
                }
            }
            CURRENT.with(|c| c.set(self.prev));
        }
    }

    /// What the current thread impersonates, for threads it starts (`Inherit::enter` in each of them). Only for
    /// threads that end before the impersonating thread's `Act` (scoped threads): the token belongs to it.
    pub fn capture() -> Inherit {
        Inherit(CURRENT.with(|c| c.get()))
    }

    pub struct Inherit(usize);

    impl Inherit {
        /// Impersonates the captured token on this thread; None if there was none.
        pub fn enter(&self) -> Option<Act> {
            if self.0 == 0 {
                return None;
            }
            // SAFETY: the token stays open while the starting thread's Act lives (scoped threads end before it).
            if unsafe { ImpersonateLoggedOnUser(self.0 as HANDLE) } == 0 {
                eprintln!("fatal: cannot take over the user's identity: {}", std::io::Error::last_os_error());
                std::process::abort();
            }
            let prev = CURRENT.with(|c| c.replace(self.0));
            Some(Act { prev })
        }
    }

    /// Runs `f` with the service's own rights (scopy's housekeeping), then returns to the user.
    pub fn as_service<T>(f: impl FnOnce() -> T) -> T {
        let cur = CURRENT.with(|c| c.get());
        if cur == 0 {
            return f();
        }
        // SAFETY: reverting and re-impersonating the token this thread already used.
        unsafe { RevertToSelf() };
        let r = f();
        unsafe { ImpersonateLoggedOnUser(cur as HANDLE) };
        r
    }
}


#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use std::io::{BufReader, BufWriter};
    use std::net::{TcpListener, TcpStream};

    /// Signs in to ourselves over a local socket; returns the server's result.
    fn sign_in(client_bind: Binding, server_bind: Binding) -> Result<Option<Arc<Identity>>> {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let s = l.accept().unwrap().0;
            let (mut r, mut w) = (BufReader::new(s.try_clone().unwrap()), BufWriter::new(s));
            server(&mut r, &mut w, &server_bind)
        });
        let s = TcpStream::connect(addr).unwrap();
        let (mut r, mut w) = (BufReader::new(s.try_clone().unwrap()), BufWriter::new(s));
        let _ = client(&mut r, &mut w, "localhost", &client_bind);
        server.join().unwrap()
    }

    #[test]
    fn signs_in_as_me_and_refuses_another_tls_session() {
        let me = std::env::var("USERNAME").unwrap_or_default().to_lowercase();
        let id = sign_in([7u8; 32], [7u8; 32]).unwrap().expect("signed in");
        assert!(id.user.to_lowercase().ends_with(&me), "{} vs {me}", id.user);
        {
            let _act = id.enter().unwrap();
            // Acting as the user, and back to ourselves for housekeeping (here both are the same account).
            as_service(|| ());
        }
        // A man in the middle runs two TLS sessions: the bindings differ, the sign-in must fail.
        assert!(sign_in([7u8; 32], [8u8; 32]).is_err(), "sign-in with another TLS session's binding was accepted");
    }
}
#[cfg(all(test, unix))]
mod unix_tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    /// Needs root (run the test binary with sudo); without it only the refusal is checked.
    #[test]
    fn acting_as_a_user_switches_only_this_thread_and_the_kernel_checks_as_that_user() {
        let nobody = Identity { user: "nobody".into(), uid: 65534, gid: 65534, groups: vec![65534] };
        if !crate::meta::is_root() {
            assert!(nobody.enter().is_err(), "a normal user must not act as someone else");
            return;
        }
        let dir = std::env::temp_dir().join(format!("scopy-act-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("rootonly")).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();
        std::fs::set_permissions(dir.join("rootonly"), std::fs::Permissions::from_mode(0o700)).unwrap();
        let barrier = std::sync::Barrier::new(2);
        std::thread::scope(|s| {
            s.spawn(|| {
                let act = nobody.enter().unwrap();
                barrier.wait(); // the other thread writes while this one acts as nobody
                std::fs::write(dir.join("by-nobody"), b"x").unwrap();
                assert!(std::fs::write(dir.join("rootonly/x"), b"x").is_err(), "root's 0700 folder must be closed to nobody");
                assert!(std::os::unix::fs::chown(dir.join("by-nobody"), Some(0), None).is_err(), "nobody can't give files away");
                // Housekeeping as the service, then nobody again.
                as_service(|| std::fs::write(dir.join("rootonly/svc"), b"x").unwrap());
                assert!(std::fs::write(dir.join("rootonly/y"), b"x").is_err());
                // Helper threads take the identity over.
                let who = capture();
                std::thread::scope(|s2| {
                    s2.spawn(|| {
                        let _a = who.enter();
                        std::fs::write(dir.join("by-helper"), b"x").unwrap();
                    });
                });
                drop(act);
                std::fs::write(dir.join("rootonly/z"), b"x").unwrap();
            });
            s.spawn(|| {
                barrier.wait();
                std::fs::write(dir.join("by-root"), b"x").unwrap();
            });
        });
        let owner = |p: &str| std::fs::metadata(dir.join(p)).unwrap().uid();
        assert_eq!((owner("by-nobody"), owner("by-helper"), owner("by-root"), owner("rootonly/svc")), (65534, 65534, 0, 0));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
