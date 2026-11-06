//! Wire protocol (version 2) shared by both ends.
//!
//! Every connection starts with: MAGIC, u16 VERSION, u8 kind (PUSH / PULL / DATA).
//! The "source" side owns the files being copied; the "destination" side writes them.
//! In a push the client is the source, in a pull the server is. Data connections are always
//! opened by the client, and frames always flow from source to destination.
//!
//! Push control connection (client = source):
//!   C→R  sign-in (auth.rs: method:u8, then Negotiate rounds), share:str, subpath:str
//!   R→C  status, ticket_name:str, nonce:str
//!        (client writes `nonce:binding` into <dest>\<ticket_name> over SMB)
//!   C→R  MSG_TICKET_WRITTEN | MSG_ABORT
//!   R→C  status, session_id:str, probe_name:str, dest_exists:u8
//!        (the probe is placed only after the access check; the client looks for it in its source tree)
//!   C→R  MSG_GO | MSG_ABORT (overlap)
//!   C→R  options, manifest
//!   R→C  status, plan                         (what the destination still needs)
//!   C→R  dictionary:blob                      (trained on the planned files; may be empty)
//!   R→C  status
//!   rounds:  data connections run, then
//!   C→R  MSG_ROUND_DONE, data_conns:u32
//!   R→C  status, plan                         (whatever is still missing; empty = done)
//!   C→R  MSG_FINISH
//!   R→C  status, files_received:u64, bytes_received:u64   ("received": everything is in the server's RAM)
//!   R→C  status, result                                    ("committed": written, flushed, verified if asked)
//!        A client may disconnect after "received" (--detach); the server keeps committing and answers
//!        KIND_STATUS queries for the session id.
//!
//! Pull control connection (client = destination):
//!   C→R  sign-in (auth.rs: method:u8, then Negotiate rounds), share:str, subpath:str
//!   R→C  status, ticket_name:str               (server wrote a nonce into the source folder)
//!   C→R  nonce:str                             (read over SMB — proves read access)
//!   R→C  status, session_id:str
//!   C→R  options, probe_name:str, dest_exists:u8
//!   R→C  status, options, manifest, scan_micros:u64
//!   rounds:  C→R MSG_PLAN, plan;  R→C status, dictionary:blob (first round only, may be empty);
//!            data connections run
//!   C→R  MSG_FINISH
//!   R→C  status, stats
//!
//! Data connection:
//!   C→R  session_id:str
//!   R→C  status
//!   source→dest frames until END_OF_STREAM:
//!        idx:u32, offset:u64, raw_len:u32, flags:u8, wire_len:u32, [hash:32 if F_HASH], payload

use anyhow::{bail, Result};
use std::io::{self, Read, Write};

pub const MAGIC: &[u8; 4] = b"SCPY";
/// 8: OPT_SINK. 9: TLS on every connection, tickets bound to the TLS session, data/feedback joins with a token.
/// 10: the push's overlap probe comes after the access check (with the session id), answered by MSG_GO.
/// 11: Windows sign-in as the user on push and pull control connections (auth.rs); the receiver acts as the user.
/// 12: KIND_ENROL (sync enrolment, sync.rs).
/// 13: sync rounds (OPT_MIRROR) send their moves between options and manifest, and get a MirrorOutcome after the
/// result.
/// 14: two-way sync: KIND_LIST (the user's folder as the receiver has it); sync rounds send explicit deletes after
/// their moves and the receiver no longer removes what the manifest lacks.
/// 15: KIND_LOCKS (files open on a PC are locked on the receiver for everyone else); sync rounds send the PC's name
/// after their deletes.
/// 16: KIND_WATCH (server change feed: the receiver tells a PC when its sync folders changed, feed.rs).
/// 17: KIND_LIST sends each entry's file id after the manifest (sync sees renames and moves made on the server).
/// 18: KIND_LIST takes the PC's name and a cursor and may answer with only what changed since (a delta from the
/// receiver's change feed log, feed.rs).
/// 19: OPT_ONLY (a sync pull names its files; the receiver doesn't scan the whole folder).
/// 20: push and pull send an access token after share/subpath and learn whether the SMB ticket is needed (proofs.rs);
/// the receiver hands out a token with the session id.
/// 21: manifest entries carry Unix metadata (mode, owner, group: `mode` != 0) and symbolic links (ENTRY_LINK with
/// their target); after the entries, the names of the owners and groups they use (users n:u32 (id:u32, name:str)*,
/// then groups the same way), so the destination can map them to its own ids.
/// 22: KIND_LIST ends with the files an interrupted job may have left without their data (n:u32, path:str*): the PC
/// sends them again instead of taking them as synced.
pub const VERSION: u16 = 22;
pub const DEFAULT_PORT: u16 = 7788;

pub const KIND_PUSH: u8 = 1;
pub const KIND_DATA: u8 = 2;
pub const KIND_PULL: u8 = 3;
/// Asks a receiver about a (possibly detached) job: C→R session_id; R→C status, job state, [result].
pub const KIND_STATUS: u8 = 4;

/// Live receiver state for the sender's tuning: C→R session_id; R→C status, then a Feedback every ~1 s
/// until the job finishes (FEEDBACK_END).
pub const KIND_FEEDBACK: u8 = 5;
/// Sync enrolment: the receiver creates the signed-in user's folders (sync.rs).
pub const KIND_ENROL: u8 = 6;
/// Listing for two-way sync: C→R sign-in (required), share, subpath, pc:str, cursor (epoch:u64, seq:u64; 0 = none);
/// R→C status, then LIST_FULL: manifest of that folder as the signed-in user may read it (scopy's own files left
/// out) — or LIST_DELTA: n:u32 removed paths (each with everything below it), then a manifest of what is new or
/// changed (folders with their contents) — then n:u32 and n file ids (u64, in manifest order; 0 = unknown) that
/// stay the same across renames and moves on the receiver, and the new cursor (epoch, seq; epoch 0 = none: the
/// PC's feed is not connected, so no delta next time).
pub const KIND_LIST: u8 = 7;
pub const LIST_FULL: u8 = 0;
pub const LIST_DELTA: u8 = 1;
/// Open-file locks for two-way sync: C→R sign-in (required), share, subpath (the user's sync folder), pc:str, the
/// files open on that PC (LockClaim list; replaces the PC's earlier claims for the folder). R→C status, per claim a
/// LOCK_* state, then the locks other PCs hold in the folder (LockInfo list). A claim lasts until the PC stops
/// claiming it, or for the receiver's lease time after the PC's last call (asleep, offline).
pub const KIND_LOCKS: u8 = 8;
/// Server change feed for two-way sync (feed.rs): C→R sign-in (required), pc:str, n:u32, n × (share, subpath);
/// R→C status, then a folder index (u32) whenever that folder changed (not by this PC) with the folder's change log
/// position (epoch:u64, seq:u64; a listing whose cursor is at or past it covers the change); feed::ALIVE (0, 0) as
/// heartbeat.
pub const KIND_WATCH: u8 = 9;
pub const LOCK_HELD: u8 = 0;
/// The file is open on the receiver itself (e.g. Word on a terminal server, over SMB): not locked.
pub const LOCK_OPEN_THERE: u8 = 1;
/// Not lockable (missing on the receiver, held by another PC, refused).
pub const LOCK_REFUSED: u8 = 2;

/// A file open on the PC, with its Office owner file (`~$…`, which names the user), if any.
#[derive(Clone, Debug, PartialEq)]
pub struct LockClaim {
    pub path: String,
    pub owner_name: String,
    pub owner: Vec<u8>,
}

/// A lock another PC holds: where, who, since when (Unix seconds).
#[derive(Clone, Debug, PartialEq)]
pub struct LockInfo {
    pub path: String,
    pub pc: String,
    pub user: String,
    pub since: u64,
}

pub fn put_claims(w: &mut impl Write, claims: &[LockClaim]) -> io::Result<()> {
    w.put_u32(claims.len() as u32)?;
    for c in claims {
        w.put_str(&c.path)?;
        w.put_str(&c.owner_name)?;
        w.put_blob(&c.owner)?;
    }
    Ok(())
}

pub fn get_claims(r: &mut impl Read) -> Result<Vec<LockClaim>> {
    let n = r.get_u32()?;
    if n > 10_000 {
        bail!("too many lock claims: {n}");
    }
    (0..n).map(|_| Ok(LockClaim { path: r.get_str()?, owner_name: r.get_str()?, owner: r.get_blob()? })).collect()
}

pub fn put_lock_infos(w: &mut impl Write, locks: &[LockInfo]) -> io::Result<()> {
    w.put_u32(locks.len() as u32)?;
    for l in locks {
        w.put_str(&l.path)?;
        w.put_str(&l.pc)?;
        w.put_str(&l.user)?;
        w.put_u64(l.since)?;
    }
    Ok(())
}

pub fn get_lock_infos(r: &mut impl Read) -> Result<Vec<LockInfo>> {
    let n = r.get_u32()?;
    if n > 1_000_000 {
        bail!("too many locks: {n}");
    }
    (0..n).map(|_| Ok(LockInfo { path: r.get_str()?, pc: r.get_str()?, user: r.get_str()?, since: r.get_u64()? })).collect()
}

pub const JOB_UNKNOWN: u8 = 0;
pub const JOB_COMMITTING: u8 = 1;
pub const JOB_DONE: u8 = 2;
/// The receiver restarted while committing a staged job: rerun the copy (it skips/resumes what landed).
pub const JOB_INTERRUPTED: u8 = 3;

/// `stage_mb` value meaning "let the receiver choose" (a share of its free RAM).
pub const STAGE_AUTO: u32 = u32::MAX;

/// What the receiver reports about itself every second (scopy-internal signals only).
#[derive(Clone, Copy, Debug, Default)]
pub struct Feedback {
    /// Pieces waiting for a writer.
    pub queued: u32,
    /// Bytes held in the RAM stage (0 without staging) and the stage's size in MB (0 = not staged).
    pub staged_bytes: u64,
    pub stage_limit_mb: u32,
    /// Average create+write time per piece over the last second, in microseconds.
    pub write_us: u32,
    /// Pieces written in the last second.
    pub written: u32,
    /// Active writer threads.
    pub writers: u16,
    /// 1 = the job is finishing; no more feedback follows.
    pub end: u8,
}

pub fn put_feedback(w: &mut impl Write, f: &Feedback) -> io::Result<()> {
    w.put_u32(f.queued)?;
    w.put_u64(f.staged_bytes)?;
    w.put_u32(f.stage_limit_mb)?;
    w.put_u32(f.write_us)?;
    w.put_u32(f.written)?;
    w.put_u16(f.writers)?;
    w.put_u8(f.end)
}

pub fn get_feedback(r: &mut impl Read) -> io::Result<Feedback> {
    Ok(Feedback {
        queued: r.get_u32()?,
        staged_bytes: r.get_u64()?,
        stage_limit_mb: r.get_u32()?,
        write_us: r.get_u32()?,
        written: r.get_u32()?,
        writers: r.get_u16()?,
        end: r.get_u8()?,
    })
}

pub const STATUS_OK: u8 = 0;
pub const STATUS_ERR: u8 = 1;

pub const ENTRY_DIR: u8 = 0;
pub const ENTRY_FILE: u8 = 1;
/// A symbolic link (Unix sources only): no data, `link` holds the target as it was read (not resolved).
pub const ENTRY_LINK: u8 = 2;

/// In `Entry::mode`: the Unix fields are set (a mode of 0o000 is a real mode, so it needs a flag of its own).
#[cfg_attr(not(unix), allow(dead_code))]
pub const MODE_SET: u32 = 0x8000_0000;

pub const OPT_FORCE: u8 = 1;
pub const OPT_VERIFY: u8 = 2;
pub const OPT_NO_META: u8 = 4;
pub const OPT_NO_DICT: u8 = 8;
/// Benchmark mode: the receiver takes in, decompresses and checks everything, creates the folders, and
/// discards the file data instead of writing it. Only on receivers started with --allow-sink.
pub const OPT_SINK: u8 = 16;
/// Sync mirror round: after the commit the receiver moves what the client no longer has into the user's recycle bin.
/// Only into the signed-in user's own sync folder (sync.rs).
pub const OPT_MIRROR: u8 = 32;
/// Pull of named paths only (sync rounds): after the probe the client sends n:u32 and n relative paths (files and
/// folders); the receiver looks at just those (and their parent folders) instead of scanning the whole folder.
pub const OPT_ONLY: u8 = 64;
/// Unix owners and groups by number as sent, not mapped by name to the destination's ids (rsync --numeric-ids).
pub const OPT_NUMERIC_IDS: u8 = 128;
/// Push/pull access step (protocol 20): the SMB ticket follows / the client's token was accepted (proofs.rs).
pub const ACCESS_TICKET: u8 = 0;
pub const ACCESS_TOKEN: u8 = 1;

/// A rename or move the sync agent saw on the PC (same file id, new path), done on the receiver before the plan so
/// the file isn't sent again. Paths relative to the sync folder, `/`-separated. For a file, size and mtime must
/// still match on the receiver (it is the version the PC synced last); a folder moves with everything in it.
#[derive(Clone, Debug, PartialEq)]
pub struct Move {
    pub from: String,
    pub to: String,
    pub dir: bool,
    pub size: u64,
    pub mtime: i64,
}

pub fn put_moves(w: &mut impl Write, moves: &[Move]) -> io::Result<()> {
    w.put_u32(moves.len() as u32)?;
    for m in moves {
        w.put_str(&m.from)?;
        w.put_str(&m.to)?;
        w.put_u8(m.dir as u8)?;
        w.put_u64(m.size)?;
        w.put_u64(m.mtime as u64)?;
    }
    Ok(())
}

pub fn get_moves(r: &mut impl Read) -> Result<Vec<Move>> {
    let n = r.get_u32()?;
    if n > 10_000_000 {
        bail!("too many moves: {n}");
    }
    (0..n)
        .map(|_| Ok(Move { from: r.get_str()?, to: r.get_str()?, dir: r.get_u8()? != 0, size: r.get_u64()?, mtime: r.get_u64()? as i64 }))
        .collect()
}

/// A delete the sync agent decided (gone on the PC, unchanged on the receiver since the last sync). The receiver
/// moves it into the user's recycle bin only if it still has exactly that version; a folder only once no file is
/// left in it.
#[derive(Clone, Debug, PartialEq)]
pub struct Delete {
    pub path: String,
    pub dir: bool,
    pub size: u64,
    pub mtime: i64,
}

pub fn put_deletes(w: &mut impl Write, deletes: &[Delete]) -> io::Result<()> {
    w.put_u32(deletes.len() as u32)?;
    for d in deletes {
        w.put_str(&d.path)?;
        w.put_u8(d.dir as u8)?;
        w.put_u64(d.size)?;
        w.put_u64(d.mtime as u64)?;
    }
    Ok(())
}

pub fn get_deletes(r: &mut impl Read) -> Result<Vec<Delete>> {
    let n = r.get_u32()?;
    if n > 10_000_000 {
        bail!("too many deletes: {n}");
    }
    (0..n).map(|_| Ok(Delete { path: r.get_str()?, dir: r.get_u8()? != 0, size: r.get_u64()?, mtime: r.get_u64()? as i64 })).collect()
}

/// What a sync round did besides copying (R→C after the result, OPT_MIRROR only).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct MirrorOutcome {
    /// Moves done on the receiver.
    pub renamed: u64,
    /// Files and folders the PC no longer has, moved into the user's recycle bin.
    pub recycled: u64,
    /// Files the PC no longer has but which were kept: more than the guard allows (an emptied folder?).
    pub held: u64,
    /// Files the round kept (for the message).
    pub kept: u64,
    /// Why nothing was removed, if so.
    pub note: String,
}

pub fn put_mirror_outcome(w: &mut impl Write, m: &MirrorOutcome) -> io::Result<()> {
    w.put_u64(m.renamed)?;
    w.put_u64(m.recycled)?;
    w.put_u64(m.held)?;
    w.put_u64(m.kept)?;
    w.put_str(&m.note)
}

pub fn get_mirror_outcome(r: &mut impl Read) -> Result<MirrorOutcome> {
    Ok(MirrorOutcome { renamed: r.get_u64()?, recycled: r.get_u64()?, held: r.get_u64()?, kept: r.get_u64()?, note: r.get_str()? })
}

/// Send order. Auto starts small-files-first and measures whether mixing big files in helps.
pub const ORDER_AUTO: u8 = 0;
/// Small compressible files, then small already-compressed files, then big files' chunks.
pub const ORDER_SMALL_FIRST: u8 = 1;
/// Big files' chunks interleaved with small files in proportion to their share of the bytes.
pub const ORDER_MIXED: u8 = 2;

/// Read files in on-disk order: decide by measuring read latency / always / never.
pub const DISK_ORDER_AUTO: u8 = 0;
pub const DISK_ORDER_ON: u8 = 1;
pub const DISK_ORDER_OFF: u8 = 2;

pub fn order_name(order: u8) -> &'static str {
    match order {
        ORDER_SMALL_FIRST => "small-first",
        ORDER_MIXED => "mixed",
        _ => "auto",
    }
}

pub const MSG_TICKET_WRITTEN: u8 = 1;
pub const MSG_ROUND_DONE: u8 = 2;
pub const MSG_FINISH: u8 = 3;
pub const MSG_ABORT: u8 = 4;
pub const MSG_PLAN: u8 = 5;
pub const MSG_GO: u8 = 6;

pub const F_ZSTD: u8 = 1;
pub const F_HASH: u8 = 2;

pub const END_OF_STREAM: u32 = u32::MAX;

/// Files up to this size travel as a single frame; bigger files are split into chunks of exactly
/// this size (the last one shorter), which spread across all data connections.
pub const CHUNK: u64 = 2 << 20;
/// Upper bound for a compressed frame (zstd never expands by more than a small margin).
pub const MAX_WIRE: u32 = (CHUNK as u32) + (CHUNK as u32) / 8 + 4096;

const MAX_STR: u32 = 64 * 1024;
const MAX_BLOB: u32 = 16 << 20;

pub fn chunk_count(size: u64) -> u32 {
    size.div_ceil(CHUNK) as u32
}

pub trait WriteExt: Write {
    fn put_u8(&mut self, v: u8) -> io::Result<()> {
        self.write_all(&[v])
    }
    fn put_u16(&mut self, v: u16) -> io::Result<()> {
        self.write_all(&v.to_le_bytes())
    }
    fn put_u32(&mut self, v: u32) -> io::Result<()> {
        self.write_all(&v.to_le_bytes())
    }
    fn put_u64(&mut self, v: u64) -> io::Result<()> {
        self.write_all(&v.to_le_bytes())
    }
    fn put_i64(&mut self, v: i64) -> io::Result<()> {
        self.write_all(&v.to_le_bytes())
    }
    fn put_str(&mut self, s: &str) -> io::Result<()> {
        self.put_u32(s.len() as u32)?;
        self.write_all(s.as_bytes())
    }
    fn put_blob(&mut self, b: &[u8]) -> io::Result<()> {
        self.put_u32(b.len() as u32)?;
        self.write_all(b)
    }
    fn put_ok(&mut self) -> io::Result<()> {
        self.put_u8(STATUS_OK)
    }
    fn put_err(&mut self, msg: &str) -> io::Result<()> {
        self.put_u8(STATUS_ERR)?;
        self.put_str(msg)?;
        self.flush()
    }
    fn put_hello(&mut self, kind: u8) -> io::Result<()> {
        self.write_all(MAGIC)?;
        self.put_u16(VERSION)?;
        self.put_u8(kind)
    }
}
impl<W: Write + ?Sized> WriteExt for W {}

pub trait ReadExt: Read {
    fn get_u8(&mut self) -> io::Result<u8> {
        let mut b = [0u8; 1];
        self.read_exact(&mut b)?;
        Ok(b[0])
    }
    fn get_u16(&mut self) -> io::Result<u16> {
        let mut b = [0u8; 2];
        self.read_exact(&mut b)?;
        Ok(u16::from_le_bytes(b))
    }
    fn get_u32(&mut self) -> io::Result<u32> {
        let mut b = [0u8; 4];
        self.read_exact(&mut b)?;
        Ok(u32::from_le_bytes(b))
    }
    fn get_u64(&mut self) -> io::Result<u64> {
        let mut b = [0u8; 8];
        self.read_exact(&mut b)?;
        Ok(u64::from_le_bytes(b))
    }
    fn get_i64(&mut self) -> io::Result<i64> {
        let mut b = [0u8; 8];
        self.read_exact(&mut b)?;
        Ok(i64::from_le_bytes(b))
    }
    fn get_str(&mut self) -> Result<String> {
        let n = self.get_u32()?;
        if n > MAX_STR {
            bail!("protocol error: string too long ({n} bytes)");
        }
        let mut b = vec![0u8; n as usize];
        self.read_exact(&mut b)?;
        Ok(String::from_utf8(b)?)
    }
    fn get_blob(&mut self) -> Result<Vec<u8>> {
        let n = self.get_u32()?;
        if n > MAX_BLOB {
            bail!("protocol error: blob too long ({n} bytes)");
        }
        let mut b = vec![0u8; n as usize];
        self.read_exact(&mut b)?;
        Ok(b)
    }
    /// Reads a status byte; turns a remote error into a local one.
    fn get_status(&mut self) -> Result<()> {
        match self.get_u8()? {
            STATUS_OK => Ok(()),
            _ => bail!("remote: {}", self.get_str()?),
        }
    }
    /// Reads and validates the connection preamble, returning the connection kind.
    fn get_hello(&mut self) -> Result<u8> {
        let mut m = [0u8; 4];
        self.read_exact(&mut m)?;
        if &m != MAGIC {
            bail!("not a scopy client");
        }
        let v = self.get_u16()?;
        if v != VERSION {
            bail!("protocol version mismatch (peer {v}, ours {VERSION}) — update scopy on both machines");
        }
        Ok(self.get_u8()?)
    }
}
impl<R: Read + ?Sized> ReadExt for R {}

/// One manifest entry. Paths are relative and '/'-separated.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Entry {
    pub kind: u8,
    pub path: String,
    pub size: u64,
    /// Nanoseconds since the Unix epoch.
    pub mtime: i64,
    /// Creation time, nanoseconds since the Unix epoch; 0 = unknown.
    pub ctime: i64,
    /// Windows file attributes (read-only, hidden, system, archive, not-indexed).
    pub attrs: u32,
    /// Unix: MODE_SET | permission bits (0o7777: rwx for owner/group/others, setuid, setgid, sticky); 0 = not a
    /// Unix source (the destination then goes by `attrs`).
    pub mode: u32,
    /// Unix owner and group (numeric, as `rsync --numeric-ids`); only meaningful when `mode` != 0.
    pub uid: u32,
    pub gid: u32,
    /// ENTRY_LINK: the link's target. Empty otherwise.
    pub link: String,
}

impl Entry {
    pub fn is_file(&self) -> bool {
        self.kind == ENTRY_FILE
    }
    pub fn is_dir(&self) -> bool {
        self.kind == ENTRY_DIR
    }
    pub fn is_link(&self) -> bool {
        self.kind == ENTRY_LINK
    }
    pub fn is_chunked(&self) -> bool {
        self.is_file() && self.size > CHUNK
    }
}

pub fn put_manifest(w: &mut impl Write, entries: &[Entry]) -> io::Result<()> {
    w.put_u64(entries.len() as u64)?;
    for e in entries {
        w.put_u8(e.kind)?;
        w.put_str(&e.path)?;
        w.put_u64(e.size)?;
        w.put_i64(e.mtime)?;
        w.put_i64(e.ctime)?;
        w.put_u32(e.attrs)?;
        w.put_u32(e.mode)?;
        if e.mode != 0 {
            w.put_u32(e.uid)?;
            w.put_u32(e.gid)?;
        }
        if e.kind == ENTRY_LINK {
            w.put_str(&e.link)?;
        }
    }
    let (users, groups) = crate::meta::id_names(entries);
    for table in [users, groups] {
        w.put_u32(table.len() as u32)?;
        for (id, name) in table {
            w.put_u32(id)?;
            w.put_str(&name)?;
        }
    }
    Ok(())
}

/// Reads a manifest. With `map_ids` (a destination that keeps owners), owners and groups the sender named are
/// mapped to this machine's ids of the same names (see `meta::map_ids`); otherwise they stay as sent.
pub fn get_manifest(r: &mut impl Read, map_ids: bool) -> Result<Vec<Entry>> {
    let n = r.get_u64()?;
    if n > 50_000_000 {
        bail!("manifest too large ({n} entries)");
    }
    let mut v = Vec::with_capacity(n as usize);
    for _ in 0..n {
        let mut e = Entry {
            kind: r.get_u8()?,
            path: r.get_str()?,
            size: r.get_u64()?,
            mtime: r.get_i64()?,
            ctime: r.get_i64()?,
            attrs: r.get_u32()?,
            mode: r.get_u32()?,
            ..Entry::default()
        };
        if e.kind > ENTRY_LINK {
            bail!("protocol error: unknown entry kind {}", e.kind);
        }
        if e.mode != 0 {
            e.uid = r.get_u32()?;
            e.gid = r.get_u32()?;
        }
        if e.kind == ENTRY_LINK {
            e.link = r.get_str()?;
            if e.link.is_empty() || e.link.contains('\0') || e.size != 0 {
                bail!("protocol error: bad symbolic link entry {}", e.path);
            }
        }
        v.push(e);
    }
    let mut tables = [Vec::new(), Vec::new()];
    for t in &mut tables {
        let n = r.get_u32()?;
        if n as usize > v.len() + 1 {
            bail!("protocol error: more owner names than entries");
        }
        for _ in 0..n {
            t.push((r.get_u32()?, r.get_str()?));
        }
    }
    if map_ids {
        let [users, groups] = tables;
        crate::meta::map_ids(&mut v, &users, &groups);
    }
    Ok(v)
}

/// What the destination still needs for one file.
#[derive(Clone, Debug, PartialEq)]
pub struct PlanItem {
    pub idx: u32,
    /// None = the whole file. Some(bitmap) = only the chunks whose bit is set.
    pub chunks: Option<Vec<u8>>,
}

pub fn put_plan(w: &mut impl Write, plan: &[PlanItem]) -> io::Result<()> {
    w.put_u32(plan.len() as u32)?;
    for p in plan {
        w.put_u32(p.idx)?;
        match &p.chunks {
            None => w.put_u8(0)?,
            Some(bits) => {
                w.put_u8(1)?;
                w.put_blob(bits)?;
            }
        }
    }
    Ok(())
}

pub fn get_plan(r: &mut impl Read, entries: usize) -> Result<Vec<PlanItem>> {
    let n = r.get_u32()? as usize;
    if n > entries {
        bail!("protocol error: plan larger than manifest");
    }
    let mut v = Vec::with_capacity(n);
    for _ in 0..n {
        let idx = r.get_u32()?;
        if idx as usize >= entries {
            bail!("protocol error: plan index out of range");
        }
        let chunks = match r.get_u8()? {
            0 => None,
            _ => Some(r.get_blob()?),
        };
        v.push(PlanItem { idx, chunks });
    }
    Ok(v)
}

pub fn bit(bits: &[u8], i: u32) -> bool {
    bits.get(i as usize / 8).is_some_and(|b| b & (1 << (i % 8)) != 0)
}

pub fn set_bit(bits: &mut [u8], i: u32) {
    bits[i as usize / 8] |= 1 << (i % 8);
}

/// Job options chosen by the client (and, for pulls, the dictionary added by the server).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Options {
    pub flags: u8,
    /// zstd level; 0 = no compression.
    pub level: i8,
    /// One of the ORDER_* constants.
    pub order: u8,
    /// Reader threads on the source side; 0 = default.
    pub readers: u16,
    /// Writer threads on the destination side; 0 = automatic.
    pub writers: u16,
    /// One of the DISK_ORDER_* constants.
    pub disk_order: u8,
    /// Receiver RAM staging buffer in MB (push only); 0 = off (write through the normal queue).
    pub stage_mb: u32,
    pub dict: Vec<u8>,
}

impl Options {
    pub fn force(&self) -> bool {
        self.flags & OPT_FORCE != 0
    }
    pub fn verify(&self) -> bool {
        self.flags & OPT_VERIFY != 0
    }
    pub fn meta(&self) -> bool {
        self.flags & OPT_NO_META == 0
    }
    pub fn mirror(&self) -> bool {
        self.flags & OPT_MIRROR != 0
    }
    pub fn numeric_ids(&self) -> bool {
        self.flags & OPT_NUMERIC_IDS != 0
    }

    pub fn sink(&self) -> bool {
        self.flags & OPT_SINK != 0
    }
}

pub fn put_options(w: &mut impl Write, o: &Options) -> io::Result<()> {
    w.put_u8(o.flags)?;
    w.put_u8(o.level as u8)?;
    w.put_u8(o.order)?;
    w.put_u16(o.readers)?;
    w.put_u16(o.writers)?;
    w.put_u8(o.disk_order)?;
    w.put_u32(o.stage_mb)?;
    w.put_blob(&o.dict)
}

pub fn get_options(r: &mut impl Read) -> Result<Options> {
    Ok(Options {
        flags: r.get_u8()?,
        level: r.get_u8()? as i8,
        order: r.get_u8()?,
        readers: r.get_u16()?,
        writers: r.get_u16()?,
        disk_order: r.get_u8()?,
        stage_mb: r.get_u32()?,
        dict: r.get_blob()?,
    })
}

/// Upper bound for threads a peer may ask for.
pub const MAX_THREADS: u16 = 256;

/// Named counters (timings in microseconds, byte counts, ...) exchanged for the final report.
pub type Stats = Vec<(String, u64)>;

pub fn put_stats(w: &mut impl Write, s: &Stats) -> io::Result<()> {
    w.put_u32(s.len() as u32)?;
    for (k, v) in s {
        w.put_str(k)?;
        w.put_u64(*v)?;
    }
    Ok(())
}

pub fn get_stats(r: &mut impl Read) -> Result<Stats> {
    let n = r.get_u32()?;
    if n > 1000 {
        bail!("protocol error: too many stats");
    }
    (0..n).map(|_| Ok((r.get_str()?, r.get_u64()?))).collect()
}

/// Final outcome reported by the destination side.
#[derive(Debug, Default, Clone)]
pub struct JobResult {
    pub files_ok: u64,
    pub bytes_ok: u64,
    pub errors: Vec<(u32, String)>,
    pub stats: Stats,
}

pub fn put_result(w: &mut impl Write, res: &JobResult) -> io::Result<()> {
    w.put_u64(res.files_ok)?;
    w.put_u64(res.bytes_ok)?;
    w.put_u32(res.errors.len() as u32)?;
    for (idx, msg) in &res.errors {
        w.put_u32(*idx)?;
        w.put_str(msg)?;
    }
    put_stats(w, &res.stats)
}

pub fn get_result(r: &mut impl Read) -> Result<JobResult> {
    let files_ok = r.get_u64()?;
    let bytes_ok = r.get_u64()?;
    let n = r.get_u32()?;
    let mut errors = Vec::new();
    for _ in 0..n {
        errors.push((r.get_u32()?, r.get_str()?));
    }
    Ok(JobResult { files_ok, bytes_ok, errors, stats: get_stats(r)? })
}

pub struct FrameHeader {
    pub idx: u32,
    pub offset: u64,
    pub raw_len: u32,
    pub flags: u8,
    pub wire_len: u32,
    pub hash: Option<[u8; 32]>,
}

pub fn put_frame(w: &mut impl Write, h: &FrameHeader, payload: &[u8]) -> io::Result<()> {
    w.put_u32(h.idx)?;
    w.put_u64(h.offset)?;
    w.put_u32(h.raw_len)?;
    w.put_u8(h.flags)?;
    w.put_u32(payload.len() as u32)?;
    if let Some(hash) = &h.hash {
        w.write_all(hash)?;
    }
    w.write_all(payload)
}

pub fn put_end(w: &mut impl Write) -> io::Result<()> {
    w.put_u32(END_OF_STREAM)
}

/// Reads the next frame header; None at end of stream.
pub fn get_frame_header(r: &mut impl Read) -> Result<Option<FrameHeader>> {
    let idx = r.get_u32()?;
    if idx == END_OF_STREAM {
        return Ok(None);
    }
    let offset = r.get_u64()?;
    let raw_len = r.get_u32()?;
    let flags = r.get_u8()?;
    let wire_len = r.get_u32()?;
    if raw_len as u64 > CHUNK || wire_len > MAX_WIRE || (flags & F_ZSTD == 0 && wire_len != raw_len) {
        bail!("protocol error: bad frame lengths");
    }
    let hash = if flags & F_HASH != 0 {
        let mut h = [0u8; 32];
        r.read_exact(&mut h)?;
        Some(h)
    } else {
        None
    };
    Ok(Some(FrameHeader { idx, offset, raw_len, flags, wire_len, hash }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_plan_roundtrip() {
        let entries = vec![
            Entry { kind: ENTRY_DIR, path: "a".into(), size: 0, mtime: 5, ctime: 3, attrs: 2, ..Entry::default() },
            Entry { kind: ENTRY_FILE, path: "a/b.txt".into(), size: 10 * CHUNK + 1, mtime: -7, ctime: 0, attrs: 1, ..Entry::default() },
            Entry { kind: ENTRY_FILE, path: "a/run.sh".into(), size: 4, mtime: 9, mode: MODE_SET | 0o4755, uid: 1000, gid: 27, ..Entry::default() },
            Entry { kind: ENTRY_LINK, path: "a/latest".into(), mtime: 1, mode: MODE_SET | 0o777, link: "b.txt".into(), ..Entry::default() },
        ];
        let plan = vec![PlanItem { idx: 1, chunks: Some(vec![0b101, 0, 1]) }, PlanItem { idx: 0, chunks: None }];
        let mut buf = Vec::new();
        put_manifest(&mut buf, &entries).unwrap();
        put_plan(&mut buf, &plan).unwrap();
        let mut r = &buf[..];
        assert_eq!(get_manifest(&mut r, false).unwrap(), entries);
        assert_eq!(get_plan(&mut r, 4).unwrap(), plan);
        assert_eq!(chunk_count(entries[1].size), 11);
    }
}
