//! The sync service on a PC (`scopy sync service install|uninstall`, DESIGN-SYNC phase 1 step 4): one Windows
//! service (LocalSystem) that starts `scopy sync run --background` as each logged-on user — in the user's session,
//! with the user's own (UAC-limited) token, without a window, at below-normal priority — and stops it when the
//! user logs off. The agent itself is unchanged: it signs in to the receiver as the user (auth.rs), so the service
//! never acts as the user towards the receiver and never touches the user's files; it only supervises.
//!
//! Users who have not enrolled (`scopy sync enable`) get an agent that exits at once with EXIT_NOT_ENROLLED; it is
//! tried again every few minutes, so enrolling needs no restart. An agent that ends otherwise is restarted with a
//! growing pause (30 s up to 10 min). All agents are in a job object: when the service stops, they stop with it.

use crate::logln;
use crate::service::{install_as, set_state, set_status_handle, uninstall_as};
use crate::sync::{EXIT_NOT_ENROLLED, EXIT_RESTART};
use anyhow::{bail, Context, Result};
use std::collections::HashMap;
use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::mpsc;
use std::time::{Duration, Instant};
use windows_service::service::{ServiceControl, ServiceControlAccept, ServiceState};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::{define_windows_service, service_dispatcher};
use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, HANDLE, WAIT_OBJECT_0};
use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows_sys::Win32::Security::{GetTokenInformation, LookupAccountSidW, TokenUser, TOKEN_USER};
use windows_sys::Win32::System::Environment::{CreateEnvironmentBlock, DestroyEnvironmentBlock};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation, SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};
use windows_sys::Win32::System::RemoteDesktop::{WTSEnumerateSessionsW, WTSFreeMemory, WTSQueryUserToken, WTS_SESSION_INFOW};
use windows_sys::Win32::System::Threading::{
    CreateProcessAsUserW, GetExitCodeProcess, ResumeThread, TerminateProcess, WaitForSingleObject, BELOW_NORMAL_PRIORITY_CLASS, CREATE_NO_WINDOW,
    CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, PROCESS_INFORMATION, STARTUPINFOW,
};

const NAME: &str = "scopy-sync";
const DISPLAY: &str = "StreamCopy sync";

/// How often the sessions are checked besides the logon/logoff notifications.
const TICK: Duration = Duration::from_secs(15);
/// A user who has not enrolled is checked again after this long.
const NOT_ENROLLED_RETRY: Duration = Duration::from_secs(120);
/// An agent that ran this long before it ended starts over with the shortest pause.
const RAN_WELL: Duration = Duration::from_secs(600);

pub fn install() -> Result<()> {
    install_as(
        NAME,
        DISPLAY,
        "Keeps the signed-in users' folders synced with their StreamCopy (scopy) receiver.",
        vec!["sync".into(), "service".into(), "run".into()],
    )
}

pub fn uninstall() -> Result<()> {
    uninstall_as(NAME)
}

enum Event {
    Sessions,
    Stop,
}

/// Entry point when started by the service manager.
pub fn run(log: Option<PathBuf>) -> Result<()> {
    let log = log.unwrap_or_else(|| std::env::current_exe().unwrap_or_default().with_file_name("scopy-sync-service.log"));
    crate::util::log_to_file(&log)?;
    service_dispatcher::start(NAME, ffi_sync_service_main).context("not started by the service manager (use `scopy sync run` instead)")?;
    Ok(())
}

define_windows_service!(ffi_sync_service_main, sync_service_main);

fn sync_service_main(_args: Vec<OsString>) {
    if let Err(e) = run_service() {
        logln!("sync service failed: {e:#}");
        set_state(ServiceState::Stopped, 1);
    }
}

fn run_service() -> Result<()> {
    let (tx, rx) = mpsc::channel();
    let handler = move |control| match control {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            set_state(ServiceState::StopPending, 0);
            let _ = tx.send(Event::Stop);
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::SessionChange(_) => {
            let _ = tx.send(Event::Sessions);
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    };
    let handle = service_control_handler::register(NAME, handler)?;
    set_status_handle(handle, ServiceControlAccept::SESSION_CHANGE);
    set_state(ServiceState::Running, 0);
    logln!("sync service {} started", env!("CARGO_PKG_VERSION"));
    let mut sup = Supervisor::new()?;
    loop {
        sup.reconcile();
        match rx.recv_timeout(TICK) {
            Ok(Event::Stop) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
            Ok(Event::Sessions) | Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    }
    sup.stop_all();
    logln!("sync service stopped");
    set_state(ServiceState::Stopped, 0);
    Ok(())
}

/// A user logged on in a session (one entry per session).
struct Session {
    id: u32,
    sid: String,
    name: String,
    token: Handle,
}

struct Agent {
    session: u32,
    name: String,
    process: Handle,
    started: Instant,
}

/// When a user's agent may be started again.
struct Pause {
    until: Instant,
    failures: u32,
}

struct Supervisor {
    exe: PathBuf,
    job: Handle,
    agents: HashMap<String, Agent>,
    paused: HashMap<String, Pause>,
    /// The logged-on users last time, for the log.
    seen: Vec<String>,
    /// Sessions whose tray app (scopyw.exe) was started: once per logon, so quitting it is respected.
    trays: std::collections::HashSet<u32>,
}

/// The tray app is started once the session's agent has run this long (it found the user enrolled).
const TRAY_AFTER: Duration = Duration::from_secs(20);

impl Supervisor {
    fn new() -> Result<Self> {
        // SAFETY: plain Win32 calls; the limit structure is zero-initialised and sized for the call.
        let job = unsafe {
            let job = Handle(CreateJobObjectW(std::ptr::null(), std::ptr::null()));
            if job.0.is_null() {
                bail!("cannot create a job object: {}", std::io::Error::last_os_error());
            }
            let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            let size = std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32;
            if SetInformationJobObject(job.0, JobObjectExtendedLimitInformation, (&info as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(), size) == 0 {
                bail!("cannot set up the job object: {}", std::io::Error::last_os_error());
            }
            job
        };
        Ok(Self { exe: std::env::current_exe()?, job, agents: HashMap::new(), paused: HashMap::new(), seen: Vec::new(), trays: Default::default() })
    }

    /// Starts an agent for every logged-on user who has none, and stops the agents of users who logged off.
    fn reconcile(&mut self) {
        let sessions = match sessions() {
            Ok(s) => s,
            Err(e) => {
                logln!("cannot list the sessions: {e:#}");
                return;
            }
        };
        let seen: Vec<String> = sessions.iter().map(|s| format!("{} in session {}", s.name, s.id)).collect();
        if seen != self.seen {
            logln!("logged on: {}", if seen.is_empty() { "nobody".to_string() } else { seen.join(", ") });
            self.seen = seen;
        }
        let now = Instant::now();
        let sids: Vec<String> = self.agents.keys().cloned().collect();
        for sid in sids {
            let a = &self.agents[&sid];
            if let Some(code) = exit_code(&a.process) {
                let pause = if code == EXIT_NOT_ENROLLED as u32 {
                    logln!("{}: not enrolled for sync (`scopy sync enable`); checking again in {} s", a.name, NOT_ENROLLED_RETRY.as_secs());
                    Pause { until: now + NOT_ENROLLED_RETRY, failures: 0 }
                } else if code == EXIT_RESTART as u32 {
                    logln!("{}: sync folders changed, starting the agent again", a.name);
                    Pause { until: now, failures: 0 }
                } else {
                    let failures = if a.started.elapsed() > RAN_WELL { 1 } else { self.paused.get(&sid).map_or(0, |p| p.failures) + 1 };
                    let wait = backoff(failures);
                    logln!("{}: sync ended with code {code} after {} s; starting again in {} s", a.name, a.started.elapsed().as_secs(), wait.as_secs());
                    Pause { until: now + wait, failures }
                };
                self.paused.insert(sid.clone(), pause);
                self.agents.remove(&sid);
            } else if !sessions.iter().any(|s| s.id == a.session && s.sid == sid) {
                logln!("{}: logged off (session {}), sync stopped", a.name, a.session);
                // SAFETY: a process handle this supervisor owns.
                unsafe { TerminateProcess(a.process.0, 1) };
                self.agents.remove(&sid);
            }
        }
        // Forget pauses of users who are gone, so a new logon starts at once.
        self.paused.retain(|sid, _| sessions.iter().any(|s| &s.sid == sid));
        self.trays.retain(|id| sessions.iter().any(|s| s.id == *id));
        let tray = self.exe.with_file_name("scopyw.exe");
        if tray.exists() {
            for s in &sessions {
                let ready = self.agents.get(&s.sid).is_some_and(|a| a.session == s.id && a.started.elapsed() >= TRAY_AFTER);
                if ready && self.trays.insert(s.id) {
                    match self.spawn(s, &tray, "", CREATE_UNICODE_ENVIRONMENT | CREATE_SUSPENDED) {
                        Ok(_) => logln!("{}: tray app started in session {}", s.name, s.id),
                        Err(e) => logln!("{}: cannot start the tray app: {e:#}", s.name),
                    }
                }
            }
        }
        for s in &sessions {
            if self.agents.contains_key(&s.sid) || self.paused.get(&s.sid).is_some_and(|p| now < p.until) {
                continue;
            }
            match self.spawn(s, &self.exe, " sync run --background", CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW | CREATE_SUSPENDED | BELOW_NORMAL_PRIORITY_CLASS) {
                Ok(process) => {
                    logln!("{}: sync started in session {}", s.name, s.id);
                    self.agents.insert(s.sid.clone(), Agent { session: s.id, name: s.name.clone(), process, started: now });
                }
                Err(e) => {
                    logln!("{}: cannot start sync: {e:#}", s.name);
                    self.paused.insert(s.sid.clone(), Pause { until: now + backoff(5), failures: 5 });
                }
            }
        }
    }

    /// `exe args` as the session's user, in that session, in the job (the agent, or the tray app).
    fn spawn(&self, s: &Session, exe: &std::path::Path, args: &str, flags: windows_sys::Win32::System::Threading::PROCESS_CREATION_FLAGS) -> Result<Handle> {
        let mut cmd: Vec<u16> = format!("\"{}\"{args}", exe.display()).encode_utf16().chain([0]).collect();
        let mut desktop: Vec<u16> = "winsta0\\default".encode_utf16().chain([0]).collect();
        // SAFETY: the token is the session user's primary token; every buffer outlives the calls; the environment
        // block is destroyed and the thread handle closed on every path.
        unsafe {
            let mut env = std::ptr::null_mut();
            if CreateEnvironmentBlock(&mut env, s.token.0, 0) == 0 {
                bail!("cannot build the user's environment: {}", std::io::Error::last_os_error());
            }
            let mut si: STARTUPINFOW = std::mem::zeroed();
            si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
            si.lpDesktop = desktop.as_mut_ptr();
            let mut pi: PROCESS_INFORMATION = std::mem::zeroed();
            let ok = CreateProcessAsUserW(s.token.0, std::ptr::null(), cmd.as_mut_ptr(), std::ptr::null(), std::ptr::null(), 0, flags, env, std::ptr::null(), &si, &mut pi);
            let err = std::io::Error::last_os_error();
            DestroyEnvironmentBlock(env);
            if ok == 0 {
                bail!("cannot start {}: {err}", exe.display());
            }
            let process = Handle(pi.hProcess);
            if AssignProcessToJobObject(self.job.0, pi.hProcess) == 0 {
                let err = std::io::Error::last_os_error();
                TerminateProcess(pi.hProcess, 1);
                CloseHandle(pi.hThread);
                bail!("cannot put {} into the job: {err}", exe.display());
            }
            ResumeThread(pi.hThread);
            CloseHandle(pi.hThread);
            Ok(process)
        }
    }

    fn stop_all(&mut self) {
        for (_, a) in self.agents.drain() {
            // SAFETY: a process handle this supervisor owns.
            unsafe { TerminateProcess(a.process.0, 0) };
        }
    }
}

/// 30 s, 1, 2, 4, 8 min, then 10 min.
fn backoff(failures: u32) -> Duration {
    Duration::from_secs((30u64 << failures.saturating_sub(1).min(5)).min(600))
}

/// The exit code once the process has ended.
fn exit_code(p: &Handle) -> Option<u32> {
    let mut code = 0u32;
    // SAFETY: a process handle this supervisor owns.
    unsafe { (WaitForSingleObject(p.0, 0) == WAIT_OBJECT_0 && GetExitCodeProcess(p.0, &mut code) != 0).then_some(code) }
}

/// Every session with a logged-on user (WTSQueryUserToken fails for the others).
fn sessions() -> Result<Vec<Session>> {
    let mut list: *mut WTS_SESSION_INFOW = std::ptr::null_mut();
    let mut n = 0u32;
    // SAFETY: the session list is freed with WTSFreeMemory; tokens are owned by `Handle`.
    unsafe {
        if WTSEnumerateSessionsW(std::ptr::null_mut(), 0, 1, &mut list, &mut n) == 0 {
            bail!("{}", std::io::Error::last_os_error());
        }
        let ids: Vec<u32> = std::slice::from_raw_parts(list, n as usize).iter().map(|s| s.SessionId).collect();
        WTSFreeMemory(list.cast());
        let mut out = Vec::new();
        for id in ids.into_iter().filter(|&id| id != 0) {
            let mut token: HANDLE = std::ptr::null_mut();
            if WTSQueryUserToken(id, &mut token) == 0 {
                continue;
            }
            let token = Handle(token);
            if let Ok((sid, name)) = token_user(&token) {
                out.push(Session { id, sid, name, token });
            }
        }
        Ok(out)
    }
}

/// The token's user as (SID string, DOMAIN\name).
fn token_user(token: &Handle) -> Result<(String, String)> {
    // SAFETY: buffers are sized by the first call; the SID string is freed with LocalFree.
    unsafe {
        let mut len = 0u32;
        GetTokenInformation(token.0, TokenUser, std::ptr::null_mut(), 0, &mut len);
        let mut buf = vec![0u64; (len as usize).div_ceil(8)];
        if GetTokenInformation(token.0, TokenUser, buf.as_mut_ptr().cast(), len, &mut len) == 0 {
            bail!("{}", std::io::Error::last_os_error());
        }
        let psid = (*(buf.as_ptr() as *const TOKEN_USER)).User.Sid;
        let mut s: *mut u16 = std::ptr::null_mut();
        if ConvertSidToStringSidW(psid, &mut s) == 0 {
            bail!("{}", std::io::Error::last_os_error());
        }
        let sid = wide(s);
        LocalFree(s.cast());
        let (mut name, mut domain) = ([0u16; 256], [0u16; 256]);
        let (mut nl, mut dl, mut use_) = (256u32, 256u32, 0);
        let shown = if LookupAccountSidW(std::ptr::null(), psid, name.as_mut_ptr(), &mut nl, domain.as_mut_ptr(), &mut dl, &mut use_) != 0 {
            format!("{}\\{}", wide(domain.as_ptr()), wide(name.as_ptr()))
        } else {
            sid.clone()
        };
        Ok((sid, shown))
    }
}

unsafe fn wide(p: *const u16) -> String {
    let n = (0..).take_while(|&i| *p.add(i) != 0).count();
    String::from_utf16_lossy(std::slice::from_raw_parts(p, n))
}

/// An owned Win32 handle.
struct Handle(HANDLE);

impl Drop for Handle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the handle is owned and closed once.
            unsafe { CloseHandle(self.0) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restart_pauses_grow_to_ten_minutes() {
        let s: Vec<u64> = (1..=8).map(|f| backoff(f).as_secs()).collect();
        assert_eq!(s, [30, 60, 120, 240, 480, 600, 600, 600]);
    }
}
