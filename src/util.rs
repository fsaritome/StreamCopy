use anyhow::{bail, Result};
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub fn random_hex(nbytes: usize) -> String {
    let mut b = vec![0u8; nbytes];
    getrandom::getrandom(&mut b).expect("OS random number generator failed");
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn to_nanos(t: SystemTime) -> i64 {
    match t.duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_nanos() as i64,
        Err(e) => -(e.duration().as_nanos() as i64),
    }
}

pub fn from_nanos(n: i64) -> SystemTime {
    if n >= 0 {
        UNIX_EPOCH + Duration::from_nanos(n as u64)
    } else {
        UNIX_EPOCH - Duration::from_nanos(n.unsigned_abs())
    }
}

/// Turns a peer-supplied '/'-separated relative path into a safe relative PathBuf.
/// Rejects anything that could escape the destination folder or address streams/devices.
pub fn sanitize_rel(p: &str, allow_empty: bool) -> Result<PathBuf> {
    if p.is_empty() {
        if allow_empty {
            return Ok(PathBuf::new());
        }
        bail!("empty path");
    }
    let mut out = PathBuf::new();
    for comp in p.split('/') {
        if comp.is_empty() || comp == "." || comp == ".." {
            bail!("invalid path component in {p:?}");
        }
        if comp
            .chars()
            .any(|c| (c as u32) < 32 || matches!(c, '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|'))
        {
            bail!("invalid character in {p:?}");
        }
        out.push(comp);
    }
    Ok(out)
}

pub fn fmt_bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = n as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", UNITS[u])
    }
}

pub fn fmt_secs(s: f64) -> String {
    let s = s.max(0.0) as u64;
    if s >= 3600 {
        format!("{}:{:02}:{:02}", s / 3600, s / 60 % 60, s % 60)
    } else {
        format!("{:02}:{:02}", s / 60, s % 60)
    }
}

/// Shows a path without the `\\?\` prefix that canonicalize() adds on Windows.
pub fn show(p: &Path) -> String {
    p.display().to_string().trim_start_matches(r"\\?\").to_string()
}

// ---- logging (server side: console or a log file) ----

static LOG: OnceLock<Mutex<Option<File>>> = OnceLock::new();

pub fn log_to_file(path: &Path) -> Result<()> {
    let f = std::fs::OpenOptions::new().create(true).append(true).open(path)?;
    *LOG.get_or_init(|| Mutex::new(None)).lock().unwrap() = Some(f);
    Ok(())
}

pub fn log(msg: &str) {
    let line = format!("{} {msg}", timestamp());
    if let Some(m) = LOG.get() {
        if let Some(f) = m.lock().unwrap().as_mut() {
            let _ = writeln!(f, "{line}");
            return;
        }
    }
    // Not println!: that panics when stdout is gone (an SSH session whose client has left while it still commits).
    let _ = writeln!(std::io::stdout(), "{line}");
}

#[macro_export]
macro_rules! logln {
    ($($t:tt)*) => { $crate::util::log(&format!($($t)*)) };
}

fn timestamp() -> String {
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    // UTC time of day is enough to correlate log lines.
    format!("[{:02}:{:02}:{:02}Z]", secs / 3600 % 24, secs / 60 % 60, secs % 60)
}

/// UTC date and time as `YYYYMMDD-HHMMSS` (folder names, sync log lines).
pub fn utc_stamp() -> String {
    stamp_at(SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0) as i64)
}

/// A path as a map key: '/'-separated, no trailing separator, lower case (NTFS names are case-insensitive). Used for
/// folders the change feed watches (feed.rs) and access proofs (proofs.rs), which must agree on it.
pub fn path_key(p: &str) -> String {
    p.replace('\\', "/").trim_end_matches('/').to_lowercase()
}

/// `utc_stamp` for a given time (Unix seconds).
pub fn stamp_at(secs: i64) -> String {
    // Days since 1970 to a civil date (Howard Hinnant's algorithm).
    let z = secs.div_euclid(86400) + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + (m <= 2) as i64;
    let t = secs.rem_euclid(86400);
    format!("{y:04}{m:02}{d:02}-{:02}{:02}{:02}", t / 3600, t / 60 % 60, t % 60)
}

/// `*`-wildcard match of a file name, case-insensitive (`~$*`, `*.tmp`).
pub fn wildcard(pattern: &str, name: &str) -> bool {
    let (p, n): (Vec<char>, Vec<char>) = (pattern.to_lowercase().chars().collect(), name.to_lowercase().chars().collect());
    let (mut i, mut j, mut star, mut mark) = (0, 0, None, 0);
    while j < n.len() {
        if i < p.len() && p[i] == '*' {
            star = Some(i);
            mark = j;
            i += 1;
        } else if i < p.len() && p[i] == n[j] {
            i += 1;
            j += 1;
        } else if let Some(s) = star {
            i = s + 1;
            mark += 1;
            j = mark;
        } else {
            return false;
        }
    }
    p[i..].iter().all(|&c| c == '*')
}

// ---- timing ----

/// Accumulated time in microseconds, shareable across threads.
#[derive(Default)]
pub struct Timer(AtomicU64);

impl Timer {
    pub fn add(&self, since: Instant) {
        self.0.fetch_add(since.elapsed().as_micros() as u64, Ordering::Relaxed);
    }
    pub fn micros(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

/// Wall-clock phases of a job, in order, for the final report.
#[derive(Default)]
pub struct Phases(Mutex<Vec<(String, Duration)>>);

impl Phases {
    pub fn run<T>(&self, name: &str, f: impl FnOnce() -> T) -> T {
        let t = Instant::now();
        let r = f();
        self.0.lock().unwrap().push((name.to_string(), t.elapsed()));
        r
    }
    pub fn add(&self, name: &str, d: Duration) {
        self.0.lock().unwrap().push((name.to_string(), d));
    }
    pub fn list(&self) -> Vec<(String, Duration)> {
        self.0.lock().unwrap().clone()
    }
}

// ---- adaptive thread count ----

/// How many of a pool's threads may work right now. Threads with an index >= `active` idle.
pub struct Tuner {
    active: std::sync::atomic::AtomicUsize,
    pub min: usize,
    pub max: usize,
    fixed: bool,
    pub decisions: Mutex<Vec<String>>,
}

impl Tuner {
    pub fn fixed(n: usize) -> Self {
        let n = n.max(1);
        Tuner { active: n.into(), min: n, max: n, fixed: true, decisions: Mutex::new(Vec::new()) }
    }

    pub fn auto(start: usize, min: usize, max: usize) -> Self {
        Tuner { active: start.clamp(min, max).into(), min, max, fixed: false, decisions: Mutex::new(Vec::new()) }
    }

    pub fn active(&self) -> usize {
        self.active.load(Ordering::Relaxed)
    }

    /// One line for the report: where the tuner started and ended, and how many probes it made.
    pub fn summary(&self, name: &str, start: usize) -> String {
        if self.fixed {
            return format!("{name}: fixed at {}", self.active());
        }
        let d = self.decisions.lock().unwrap();
        let kept = d.iter().filter(|m| m.ends_with("kept)")).count();
        format!("{name}: {start} -> {} ({} probes, {kept} kept)", self.active(), d.len())
    }

    pub fn is_active(&self, i: usize) -> bool {
        i < self.active()
    }

    fn set(&self, n: usize) {
        self.active.store(n.clamp(self.min, self.max), Ordering::Relaxed);
    }
}

/// What the pool's consumers spend waiting on it: a cumulative wait in microseconds and how many consumers
/// wait (e.g. the streams waiting for read data). Lets the tuner see when the pool itself is the brake.
pub struct Starved<'a> {
    pub wait_us: &'a dyn Fn() -> u64,
    pub consumers: &'a dyn Fn() -> usize,
}

/// Consumers waiting at least this share of their time means the pool is the brake: never step down then.
/// Measured on a cold SAN source (TEST-A after a reboot): streams waited 67% of the time, and step-downs were
/// kept because throughput stayed flat — with fewer reads in flight the cold storage only got slower.
const STARVED_SHARE: f64 = 0.25;

/// Whether a probe step is kept: a step up only if throughput rises clearly; a step down if throughput doesn't
/// drop — unless the consumers starve (`share` = their waiting share at the new size): flat throughput there means
/// the storage is slow per request, and fewer requests in flight only make it slower.
fn keep_step(up: bool, base: f64, rate: f64, share: f64) -> bool {
    const UP_GAIN: f64 = 1.10;
    const DOWN_KEEP: f64 = 0.97;
    if up {
        rate > base * UP_GAIN
    } else {
        rate >= base * DOWN_KEEP && share < STARVED_SHARE
    }
}

/// Hill climbing on a throughput counter (items done), scopy-internal only. Every few seconds it probes
/// one step up or down, alternating: a step up is kept only if throughput rises clearly; a step down is
/// kept if throughput doesn't drop (fewer threads for the same rate means less pressure on the storage).
/// Otherwise it goes back and holds for a while. While the consumers are starved (`starved`), it only probes
/// up. Runs until `done()`.
pub fn run_tuner(
    t: &Tuner,
    counter: &AtomicU64,
    starved: Option<Starved>,
    done: &dyn Fn() -> bool,
    name: &str,
    say: &dyn Fn(String),
) {
    // Each probe averages two 4 s windows: single 3 s samples jittered too much with mixed file sizes
    // (measured: 154/s -> 277/s with nothing changed).
    const INTERVAL: Duration = Duration::from_secs(4);
    const HOLD: u32 = 4;
    if t.fixed {
        return;
    }
    let sleep = |d: Duration| -> bool {
        let end = Instant::now() + d;
        while Instant::now() < end {
            if done() {
                return false;
            }
            thread::sleep(Duration::from_millis(100));
        }
        true
    };
    let wait_us = || starved.as_ref().map_or(0, |s| (s.wait_us)());
    let consumers = || starved.as_ref().map_or(1, |s| (s.consumers)().max(1)) as f64;
    // One window: (items per second, share of the consumers' time spent waiting).
    let window = || -> Option<(f64, f64)> {
        let (c0, w0, t0) = (counter.load(Ordering::Relaxed), wait_us(), Instant::now());
        if !sleep(INTERVAL) {
            return None;
        }
        let secs = t0.elapsed().as_secs_f64();
        let share = wait_us().saturating_sub(w0) as f64 / 1e6 / (secs * consumers());
        Some((counter.load(Ordering::Relaxed).saturating_sub(c0) as f64 / secs, share))
    };
    let rate = || -> Option<(f64, f64)> {
        let ((r1, s1), (r2, s2)) = (window()?, window()?);
        Some(((r1 + r2) / 2.0, (s1 + s2) / 2.0))
    };
    let log = |msg: String| {
        say(msg.clone());
        t.decisions.lock().unwrap().push(msg);
    };
    let mut up = true;
    // Warm-up interval, then probe.
    let Some((mut base, mut share)) = rate() else { return };
    loop {
        let from = t.active();
        let hungry = share >= STARVED_SHARE;
        if hungry {
            up = true;
        }
        let to = if up { (from * 3 / 2).max(from + 1).min(t.max) } else { (from * 2 / 3).max(t.min) };
        if to == from {
            up = !up;
            let Some((r, s)) = rate() else { return };
            (base, share) = (r, s);
            continue;
        }
        t.set(to);
        let Some((r, s)) = rate() else { return };
        let keep = keep_step(up, base, r, s);
        share = s;
        let waiting = if starved.is_some() { format!(", consumers waiting {:.0}%", s * 100.0) } else { String::new() };
        if keep {
            log(format!("{name}: {from} -> {to} ({:.0}/s -> {:.0}/s{waiting}, kept)", base, r));
            base = r;
            continue; // keep moving in the same direction
        }
        t.set(from);
        log(format!("{name}: {from} -> {to} ({:.0}/s -> {:.0}/s{waiting}, back to {from})", base, r));
        up = !up;
        // Hold, tracking the baseline (and the waiting share) as moving averages.
        for _ in 0..HOLD {
            let Some((r, s)) = window() else { return };
            base = 0.5 * base + 0.5 * r;
            share = 0.5 * share + 0.5 * s;
        }
    }
}

// ---- progress ----

#[derive(Default)]
pub struct Progress {
    pub files: AtomicU64,
    pub raw: AtomicU64,
    pub wire: AtomicU64,
    pub total_files: AtomicU64,
    pub total_bytes: AtomicU64,
}

/// Prints a plain progress line every `interval` until `stop` is set, or until the job is gone (only this thread
/// still holds its progress: a job that failed early never set `stop`, and its line went on for ever).
pub fn spawn_reporter(p: Arc<Progress>, interval: Duration, stop: Arc<AtomicBool>) -> JoinHandle<()> {
    thread::spawn(move || {
        let start = Instant::now();
        let (mut last_t, mut last_raw, mut last_wire) = (Instant::now(), 0u64, 0u64);
        // ETA from a smoothed recent rate, not the whole-run average: after a fast compressed phase the
        // average badly underestimates an uncompressible tail.
        let mut smooth: Option<f64> = None;
        loop {
            let deadline = Instant::now() + interval;
            while Instant::now() < deadline {
                if stop.load(Ordering::Relaxed) || Arc::strong_count(&p) == 1 {
                    return;
                }
                thread::sleep(Duration::from_millis(100));
            }
            let (files, raw, wire) =
                (p.files.load(Ordering::Relaxed), p.raw.load(Ordering::Relaxed), p.wire.load(Ordering::Relaxed));
            let (tf, tb) = (p.total_files.load(Ordering::Relaxed), p.total_bytes.load(Ordering::Relaxed));
            let dt = last_t.elapsed().as_secs_f64().max(1e-9);
            let rate = (raw - last_raw) as f64 / dt;
            let wrate = (wire - last_wire) as f64 / dt;
            let s = match smooth {
                Some(prev) => 0.3 * rate + 0.7 * prev,
                None => rate,
            };
            smooth = Some(s);
            // Below 1 KB/s nothing meaningful can be estimated (a stalled job once printed an ETA of 10^16 hours).
            let eta = if s >= 1024.0 { fmt_secs(tb.saturating_sub(raw) as f64 / s) } else { "--:--".into() };
            let ratio = if wire > 0 { raw as f64 / wire as f64 } else { 1.0 };
            eprintln!(
                "[{}] {files}/{tf} files ({:.1}%) | {} / {} ({:.1}%) | {}/s data, {}/s on wire ({ratio:.2}x) | ETA {}",
                fmt_secs(start.elapsed().as_secs_f64()),
                pct(files, tf),
                fmt_bytes(raw),
                fmt_bytes(tb),
                pct(raw, tb),
                fmt_bytes(rate as u64),
                fmt_bytes(wrate as u64),
                eta
            );
            (last_t, last_raw, last_wire) = (Instant::now(), raw, wire);
        }
    })
}

/// Low latency and dead-peer detection for every scopy connection. Without keepalive a client waiting for an
/// answer from a receiver that crashed or rebooted waits forever (measured: a hard reset of TEST-B left the client
/// hanging for 20 minutes on connections Windows still called "established"). Idle 15 s, then a probe every 3 s:
/// a dead peer is noticed in under a minute and the blocked read fails instead of hanging.
pub fn tune_socket(s: &std::net::TcpStream) -> std::io::Result<()> {
    s.set_nodelay(true)?;
    let ka = socket2::TcpKeepalive::new().with_time(Duration::from_secs(15)).with_interval(Duration::from_secs(3));
    socket2::SockRef::from(s).set_tcp_keepalive(&ka)?;
    // Keepalive only probes an idle connection. With data sent and not acknowledged (a peer hard-reset mid-request)
    // Linux retransmits for up to ~15 min: a sync round hung 4 min after the receiver's reset. 60 s without an
    // acknowledgement ends the connection (a slow peer still acknowledges; Windows gives up after ~21 s anyway).
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        let ms: libc::c_uint = 60_000;
        // SAFETY: TCP_USER_TIMEOUT takes an unsigned int of the size passed; the socket is open for the call.
        let rc = unsafe {
            libc::setsockopt(s.as_raw_fd(), libc::IPPROTO_TCP, libc::TCP_USER_TIMEOUT, (&ms as *const libc::c_uint).cast(), std::mem::size_of::<libc::c_uint>() as libc::socklen_t)
        };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

pub fn pct(a: u64, b: u64) -> f64 {
    if b == 0 {
        100.0
    } else {
        100.0 * a as f64 / b as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_rejects_escapes() {
        assert!(sanitize_rel("a/../b", false).is_err());
        assert!(sanitize_rel("/a", false).is_err());
        assert!(sanitize_rel("C:/x", false).is_err());
        assert!(sanitize_rel("a\\b", false).is_err());
        assert!(sanitize_rel("file.txt:stream", false).is_err());
        assert!(sanitize_rel("", false).is_err());
        assert_eq!(sanitize_rel("", true).unwrap(), PathBuf::new());
        assert_eq!(sanitize_rel("a/b c/d.txt", false).unwrap(), PathBuf::from("a").join("b c").join("d.txt"));
    }

    #[test]
    fn tuner_bounds() {
        let t = Tuner::auto(16, 4, 128);
        assert_eq!(t.active(), 16);
        assert!(t.is_active(15) && !t.is_active(16));
        t.set(1000);
        assert_eq!(t.active(), 128);
        t.set(0);
        assert_eq!(t.active(), 4);
        let f = Tuner::fixed(8);
        assert_eq!((f.active(), f.max), (8, 8));
    }

    #[test]
    fn step_down_not_kept_while_starved() {
        // Flat throughput after a step down: kept when the consumers are busy, reverted when they starve
        // (cold SAN source: streams waited 67% of the time).
        assert!(keep_step(false, 1000.0, 1000.0, 0.05));
        assert!(!keep_step(false, 1000.0, 1000.0, 0.67));
        assert!(!keep_step(false, 1000.0, 900.0, 0.05));
        // Up steps need a clear gain either way.
        assert!(keep_step(true, 1000.0, 1200.0, 0.67));
        assert!(!keep_step(true, 1000.0, 1050.0, 0.67));
    }

    #[test]
    fn nanos_roundtrip() {
        let t = UNIX_EPOCH + Duration::from_nanos(1_700_000_000_123_456_700);
        assert_eq!(from_nanos(to_nanos(t)), t);
    }
}
