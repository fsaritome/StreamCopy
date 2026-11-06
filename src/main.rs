// The static Linux build (musl): musl's allocator halves scopy's speed with many threads (BENCHMARKS.md).
#[cfg(target_env = "musl")]
#[global_allocator]
static ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

mod auth;
mod client;
mod compress;
mod confine;
#[cfg(unix)]
mod daemon;
mod dest;
mod feed;
mod locks;
mod meta;
mod proofs;
#[cfg(feature = "testtools")]
mod mitm;
mod proto;
mod record;
mod recycle;
mod server;
#[cfg(windows)]
mod service;
#[cfg(target_os = "linux")]
mod unit;
mod shares;
mod ssh;
mod status;
mod source;
mod sync;
#[cfg(windows)]
mod syncsvc;
mod tls;
mod util;

use anyhow::{Context, Result};
use clap::{Args, FromArgMatches, Parser, Subcommand};
use std::path::PathBuf;

/// StreamCopy: copies many small files over the network as one fast stream.
#[derive(Parser)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the receiver on the machine that hosts the share.
    Serve(ServeArgs),
    /// Copy a local file or folder to a network share (scopy send C:\src \\nas\photos\2026) or over SSH (scopy send /src host:/dest)
    #[command(alias = "push")]
    Send {
        source: PathBuf,
        /// Destination: a UNC path (\\server\share\folder) or [user@]host:/path (SSH mode). Contents of `source` land inside it.
        dest: String,
        #[command(flatten)]
        opts: CopyArgs,
    },
    /// Copy a folder or file to this PC from a network share (scopy get \\nas\photos\2026 D:\photos) or over SSH (scopy get host:/src /dest)
    #[command(alias = "pull")]
    Get {
        /// Source: a UNC path (\\server\share\folder) or [user@]host:/path (SSH mode).
        source: String,
        /// Local destination folder. Contents of `source` land inside it.
        dest: PathBuf,
        #[command(flatten)]
        opts: CopyArgs,
    },
    /// Linux: get a sign-in token from the local scopy daemon (what `scopy send dir host::share/path` runs over SSH).
    #[cfg(unix)]
    Token {
        /// The daemon's token socket (default /run/scopy/token.sock, or $SCOPY_TOKEN_SOCKET).
        #[arg(long)]
        socket: Option<PathBuf>,
    },
    /// Internal: one copy job for a client that started us over SSH (`scopy send dir host:/path`).
    #[command(hide = true)]
    Session {
        #[arg(long)]
        mode: String,
        path: PathBuf,
    },
    /// Ask a receiver about a push job, e.g. one sent with --detach: scopy status fileserver <job-id>
    Status {
        /// Server name or address of the receiver.
        host: String,
        /// The job id printed by `scopy send --detach`.
        job: String,
        #[arg(long, default_value_t = proto::DEFAULT_PORT)]
        port: u16,
    },
    /// Sync (in development): scopy sync enable --server fileserver
    Sync {
        #[command(subcommand)]
        action: SyncCmd,
    },
    /// Test tool: relay between client and receiver; --terminate plays a man in the middle (build with
    /// --features testtools).
    #[cfg(feature = "testtools")]
    #[command(hide = true)]
    TestRelay {
        #[arg(long)]
        listen: u16,
        /// Receiver address, e.g. fileserver.corp.example:7788
        #[arg(long)]
        to: String,
        #[arg(long)]
        terminate: bool,
    },
    /// Install, remove or run the receiver as a service (Windows service; systemd unit on Linux).
    #[cfg(any(windows, target_os = "linux"))]
    Service {
        #[command(subcommand)]
        action: ServiceCmd,
    },
}

#[derive(Subcommand)]
enum SyncCmd {
    /// Enrol this PC's user with a receiver: it creates the user's sync folders (Desktop, Documents, Downloads, as the
    /// receiver's scopy.toml offers them) and this PC remembers them.
    Enable {
        /// The receiver that holds the users' folders.
        #[arg(long)]
        server: String,
        /// Only these folders (repeatable); default: every folder the receiver offers.
        #[arg(long)]
        folder: Vec<String>,
        #[arg(long, default_value_t = proto::DEFAULT_PORT)]
        port: u16,
    },
    /// Mirror the enrolled folders to the receiver and keep them mirrored (runs until stopped; --once: one round).
    Run {
        #[arg(long)]
        once: bool,
        /// Started by the sync service: output goes to sync.log next to sync.toml.
        #[arg(long, hide = true)]
        background: bool,
    },
    /// Test tool: claims files as open on another PC (`--pc`) for `--secs` seconds, like a second notebook would.
    #[command(hide = true)]
    Claim {
        #[arg(long)]
        folder: String,
        #[arg(long)]
        path: Vec<String>,
        #[arg(long)]
        pc: String,
        #[arg(long, default_value_t = 60)]
        secs: u64,
    },
    /// The sync service: starts `scopy sync run` as each user who logs on to this PC, stops it at logoff.
    #[cfg(windows)]
    Service {
        #[command(subcommand)]
        action: SyncServiceCmd,
    },
}

#[cfg(windows)]
#[derive(Subcommand)]
enum SyncServiceCmd {
    /// Install and start the sync service (needs an admin prompt). Install from where scopy.exe stays, e.g.
    /// C:\Program Files\scopy. Logs to scopy-sync-service.log next to the exe.
    Install,
    /// Stop and remove the sync service (needs an admin prompt).
    Uninstall,
    /// Used by the service manager.
    #[command(hide = true)]
    Run {
        #[arg(long)]
        log: Option<PathBuf>,
    },
}

#[derive(Args, Clone)]
struct ServeArgs {
    #[arg(long, default_value_t = proto::DEFAULT_PORT)]
    port: u16,
    /// Extra share mapping, e.g. --share photos=D:\Photos (repeatable). Needed on Linux without smb.conf.
    #[arg(long, value_parser = parse_share)]
    share: Vec<(String, PathBuf)>,
    /// Only this published share is reachable (repeatable; default: every published share). `--share` mappings
    /// always are.
    #[arg(long = "only-share")]
    only_share: Vec<String>,
    /// Allow the administrative drive shares (C$, D$, ...), which cover whole drives. Off by default.
    #[arg(long)]
    allow_admin_shares: bool,
    /// Parallel file writers per job.
    #[arg(long, default_value_t = 32)]
    writers: usize,
    /// Write log lines to this file instead of the console.
    #[arg(long)]
    log: Option<PathBuf>,
    /// Accept benchmark jobs (`scopy send --sink`) that discard the data instead of writing it. Test receivers only.
    #[arg(long)]
    allow_sink: bool,
    /// Linux: the socket where users get sign-in tokens (`ssh host scopy token`). Default when running as root:
    /// /run/scopy/token.sock.
    #[arg(long)]
    token_socket: Option<PathBuf>,
    /// Tests only: seconds a sign-in token is accepted (default 12 h).
    #[arg(long, hide = true)]
    token_lifetime: Option<u64>,
    /// Linux, running as root: also accept clients without a token (the SMB ticket of a Windows client through
    /// Samba). They write as root, so this is off by default.
    #[arg(long)]
    allow_ticket: bool,
}

impl ServeArgs {
    fn options(&self) -> server::ServeOptions {
        server::ServeOptions {
            port: self.port,
            shares: self.share.clone(),
            only_shares: self.only_share.clone(),
            allow_admin_shares: self.allow_admin_shares,
            writers: self.writers.max(1),
            allow_sink: self.allow_sink,
            token_socket: self.token_socket.clone(),
            token_lifetime: self.token_lifetime.map(std::time::Duration::from_secs),
            allow_ticket: self.allow_ticket,
        }
    }

    #[cfg(any(windows, target_os = "linux"))]
    fn to_args(&self) -> Vec<std::ffi::OsString> {
        let mut v: Vec<std::ffi::OsString> = vec!["--port".into(), self.port.to_string().into()];
        v.extend(["--writers".into(), self.writers.to_string().into()]);
        for (name, path) in &self.share {
            let mut s = std::ffi::OsString::from(format!("{name}="));
            s.push(path.as_os_str());
            v.extend(["--share".into(), s]);
        }
        for name in &self.only_share {
            v.extend(["--only-share".into(), name.into()]);
        }
        if self.allow_admin_shares {
            v.push("--allow-admin-shares".into());
        }
        if let Some(log) = &self.log {
            v.extend(["--log".into(), log.as_os_str().to_owned()]);
        }
        if self.allow_sink {
            v.push("--allow-sink".into());
        }
        if let Some(p) = &self.token_socket {
            v.extend(["--token-socket".into(), p.as_os_str().to_owned()]);
        }
        if self.allow_ticket {
            v.push("--allow-ticket".into());
        }
        if let Some(secs) = self.token_lifetime {
            v.extend(["--token-lifetime".into(), secs.to_string().into()]);
        }
        v
    }
}

#[cfg(any(windows, target_os = "linux"))]
#[derive(Subcommand)]
enum ServiceCmd {
    /// Install and start the service (needs an admin prompt / root). Windows: logs to scopy-service.log next to the
    /// exe by default. Linux: a systemd unit running `scopy serve` from where this binary is; log in the journal.
    Install(ServeArgs),
    /// Stop and remove the service (needs an admin prompt / root).
    Uninstall,
    /// Used by the service manager.
    #[cfg(windows)]
    #[command(hide = true)]
    Run(ServeArgs),
}

/// Workload profiles: defaults for a kind of job. Any explicit option overrides the profile's value.
#[derive(Clone, Copy, PartialEq, clap::ValueEnum)]
enum Profile {
    /// Maximum throughput for big jobs with many files (backups, migrations): everything tuned automatically.
    Bulk,
    /// Everyday user copies: small files first, light on the servers, quick feedback.
    Interactive,
    /// Background sync: minimal impact on other users, skips what is unchanged.
    Sync,
}

/// Profile defaults: (streams, compress, order, readers, writers, disk order, progress seconds).
fn profile_defaults(p: Profile) -> (usize, i32, u8, usize, usize, u8, u64) {
    match p {
        Profile::Bulk => (8, client::LEVEL_AUTO, proto::ORDER_AUTO, 0, 0, proto::DISK_ORDER_AUTO, 5),
        Profile::Interactive => (4, 1, proto::ORDER_SMALL_FIRST, 4, 8, proto::DISK_ORDER_OFF, 2),
        Profile::Sync => (2, 3, proto::ORDER_SMALL_FIRST, 2, 4, proto::DISK_ORDER_OFF, 10),
    }
}

#[derive(Args)]
struct CopyArgs {
    /// Defaults for the kind of job; explicit options below override them.
    #[arg(long, value_enum, default_value = "bulk")]
    profile: Profile,
    /// Number of parallel TCP streams. Profile default: bulk 8, interactive 4, sync 2.
    #[arg(long)]
    streams: Option<usize>,
    #[arg(long, default_value_t = proto::DEFAULT_PORT)]
    port: u16,
    /// Connect to this address instead of the server name in the UNC path.
    #[arg(long)]
    host: Option<String>,
    /// Copy everything, even files that already match by size and timestamp.
    #[arg(long)]
    force: bool,
    /// Push: let the receiver take up to this many MB into RAM and write in the background (for UPS-backed
    /// servers). "auto" = half the server's free RAM (256 MB..16 GB). The client still waits until
    /// everything is committed, unless --detach.
    #[arg(long, value_parser = parse_stage, default_value = "0")]
    stage: u32,
    /// Push: return as soon as the server has everything in RAM; check the outcome with `scopy status`.
    #[arg(long)]
    detach: bool,
    /// Benchmark only (send): the receiver takes in, decompresses and checks everything and creates the folders,
    /// but discards the file data — nothing is written. Measures network, CPU and protocol without touching the
    /// storage. The receiver must be started with --allow-sink.
    #[arg(long)]
    sink: bool,
    /// zstd compression level 1-19, "off", or "auto" (adjusted on the fly between 1 and 9 from scopy's own
    /// measurements: harder while the link is the limit, lighter while the CPU is). Profile default: bulk
    /// auto, interactive 1, sync 3. Already-compressed file types are always sent as-is.
    #[arg(long, value_parser = parse_level)]
    compress: Option<i32>,
    /// Train a shared compression dictionary for many small files. Off by default: on real data the
    /// per-stream context already captures the shared structure, so it hasn't paid off.
    #[arg(long)]
    dict: bool,
    /// Check every piece with BLAKE3 after it was written (read back from disk).
    #[arg(long)]
    verify: bool,
    /// Don't restore creation times, attributes and folder timestamps (modified time is always kept).
    #[arg(long)]
    no_meta: bool,
    /// Unix: keep owners and groups by number. By default they are matched by name (the destination's id of the
    /// same user or group name), as rsync does without --numeric-ids.
    #[arg(long)]
    numeric_ids: bool,
    /// Send order: small-first (small files, then big files), mixed (big files interleaved), or auto
    /// (starts small-first and mixes only if that measurably raises throughput).
    #[arg(long, value_parser = parse_order)]
    order: Option<u8>,
    /// Extra rounds for files that didn't arrive completely.
    #[arg(long, default_value_t = 2)]
    retries: u32,
    /// Seconds between progress lines.
    #[arg(long)]
    progress: Option<u64>,
    /// Writer threads on the destination (send: on the server; get: on this PC). 0 = tuned automatically.
    #[arg(long)]
    writers: Option<usize>,
    /// Reader threads on the source (send: on this PC; get: on the server). 0 = tuned automatically.
    #[arg(long)]
    readers: Option<usize>,
    /// Read files in on-disk order: auto (when reads are slow, i.e. cold data on spinning disks), on, off.
    #[arg(long, value_parser = parse_disk_order)]
    disk_order: Option<u8>,
    /// Send: leave out files whose name matches (repeatable; `*` wildcards, e.g. --exclude *.tmp).
    #[arg(long)]
    exclude: Vec<String>,
}

impl CopyArgs {
    fn options(&self) -> client::ClientOptions {
        let (streams, compress, order, readers, writers, disk_order, progress) = profile_defaults(self.profile);
        client::ClientOptions {
            streams: self.streams.unwrap_or(streams).max(1),
            port: self.port,
            host: self.host.clone(),
            force: self.force,
            level: self.compress.unwrap_or(compress),
            no_dict: !self.dict,
            verify: self.verify,
            no_meta: self.no_meta,
            numeric_ids: self.numeric_ids,
            retries: self.retries,
            order: self.order.unwrap_or(order),
            progress_secs: self.progress.unwrap_or(progress),
            writers: self.writers.unwrap_or(writers),
            readers: self.readers.unwrap_or(readers),
            disk_order: self.disk_order.unwrap_or(disk_order),
            stage_mb: self.stage,
            detach: self.detach,
            sink: self.sink,
            mirror: false,
            only: None,
            pc: String::new(),
            tokens: None,
            exclude: self.exclude.clone(),
        }
    }
}

/// Client options for a sync round: the sync profile's defaults (light on the servers, small files first).
fn sync_client_options(port: u16) -> client::ClientOptions {
    let mut a = CopyArgs::from_arg_matches(&CopyArgs::augment_args(clap::Command::new("sync")).get_matches_from(["sync", "--profile", "sync"]))
        .expect("sync profile options");
    a.port = port;
    a.options()
}

fn parse_share(s: &str) -> Result<(String, PathBuf), String> {
    let (name, path) = s.split_once('=').ok_or("expected name=path")?;
    Ok((name.to_string(), PathBuf::from(path)))
}

fn parse_disk_order(s: &str) -> Result<u8, String> {
    match s.to_ascii_lowercase().as_str() {
        "auto" => Ok(proto::DISK_ORDER_AUTO),
        "on" => Ok(proto::DISK_ORDER_ON),
        "off" => Ok(proto::DISK_ORDER_OFF),
        _ => Err("expected auto, on or off".into()),
    }
}

fn parse_order(s: &str) -> Result<u8, String> {
    match s.to_ascii_lowercase().as_str() {
        "auto" => Ok(proto::ORDER_AUTO),
        "small-first" | "small" => Ok(proto::ORDER_SMALL_FIRST),
        "mixed" | "mix" => Ok(proto::ORDER_MIXED),
        _ => Err("expected auto, small-first or mixed".into()),
    }
}

fn parse_level(s: &str) -> Result<i32, String> {
    if s.eq_ignore_ascii_case("off") || s == "0" {
        return Ok(0);
    }
    if s.eq_ignore_ascii_case("auto") {
        return Ok(client::LEVEL_AUTO);
    }
    match s.parse::<i32>() {
        Ok(n) if (1..=19).contains(&n) => Ok(n),
        _ => Err("expected a level from 1 to 19, off or auto".into()),
    }
}

fn parse_stage(s: &str) -> Result<u32, String> {
    if s.eq_ignore_ascii_case("auto") {
        return Ok(proto::STAGE_AUTO);
    }
    match s.parse::<u32>() {
        Ok(n) if n < proto::STAGE_AUTO => Ok(n),
        _ => Err("expected MB of RAM, 0 (off) or auto".into()),
    }
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Serve(a) => {
            if let Some(log) = &a.log {
                util::log_to_file(log)?;
            }
            server::serve(&a.options())
        }
        #[cfg(unix)]
        Cmd::Token { socket } => daemon::token_cmd(socket),
        Cmd::Send { source, dest, opts } if ssh::daemon_spec(&dest).is_some() => {
            let (ssh_dest, unc) = ssh::daemon_spec(&dest).unwrap();
            let (host, port) = ssh::open_daemon(&ssh_dest)?;
            let mut o = opts.options();
            o.port = port;
            client::push(&source, &unc(&host), &o).context("copy failed")
        }
        Cmd::Get { source, dest, opts } if ssh::daemon_spec(&source).is_some() => {
            let (ssh_dest, unc) = ssh::daemon_spec(&source).unwrap();
            let (host, port) = ssh::open_daemon(&ssh_dest)?;
            let mut o = opts.options();
            o.port = port;
            client::pull(&unc(&host), &dest, &o).context("copy failed")
        }
        Cmd::Send { source, dest, opts } => match ssh::remote(&dest) {
            Some((host, path)) => {
                let s = ssh::open(&host, &path, true)?;
                let mut o = opts.options();
                o.port = s.port;
                client::push(&source, &s.unc(), &o).with_context(|| format!("copy failed
{}", s.tail()))
            }
            None => client::push(&source, &dest, &opts.options()).context("copy failed"),
        },
        Cmd::Get { source, dest, opts } => match ssh::remote(&source) {
            Some((host, path)) => {
                let s = ssh::open(&host, &path, false)?;
                let mut o = opts.options();
                o.port = s.port;
                client::pull(&s.unc(), &dest, &o).with_context(|| format!("copy failed
{}", s.tail()))
            }
            None => client::pull(&source, &dest, &opts.options()).context("copy failed"),
        },
        Cmd::Session { mode, path } => server::session(&path, mode == "push"),
        Cmd::Status { host, job, port } => client::status(&host, port, &job),
        Cmd::Sync { action: SyncCmd::Enable { server, folder, port } } => sync::enable(&server, port, &folder).context("enrolment failed"),
        Cmd::Sync { action: SyncCmd::Run { once, background } } => sync::run(once, background),
        Cmd::Sync { action: SyncCmd::Claim { folder, path, pc, secs } } => sync::claim_test(&folder, &path, &pc, secs),
        #[cfg(windows)]
        Cmd::Sync { action: SyncCmd::Service { action } } => match action {
            SyncServiceCmd::Install => syncsvc::install(),
            SyncServiceCmd::Uninstall => syncsvc::uninstall(),
            SyncServiceCmd::Run { log } => syncsvc::run(log),
        },
        #[cfg(feature = "testtools")]
        Cmd::TestRelay { listen, to, terminate } => mitm::run(listen, &to, terminate),
        #[cfg(windows)]
        Cmd::Service { action } => match action {
            ServiceCmd::Install(a) => service::install(a.to_args()),
            ServiceCmd::Uninstall => service::uninstall(),
            ServiceCmd::Run(a) => service::run(a.options(), a.log.clone()),
        },
        #[cfg(target_os = "linux")]
        Cmd::Service { action } => match action {
            ServiceCmd::Install(a) => unit::install(a.to_args()),
            ServiceCmd::Uninstall => unit::uninstall(),
        },
    }
}
