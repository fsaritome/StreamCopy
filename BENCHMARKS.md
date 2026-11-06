# Benchmarks

What was measured, and how. Every number below comes from a real run; the raw logs and the test scripts belong to a
private test environment and are not part of this repository. Times are wall-clock, from the start of the command
until the data is on disk unless a row says otherwise. MB = MiB, as scopy reports.

## Test setups

| Setup | What it is |
|---|---|
| **LAN** | two Windows Server VMs (8 vCPU) on different hypervisor hosts, a physical 10 Gbit link between the hosts |
| **WAN** | two Windows servers in different places, a routed ~40–70 Mbit/s link with real latency |
| **Laptop** | an 8-core laptop with antivirus (on-access scanning), over Wi-Fi and over cable, to a file server |
| **VPN** | the same laptop at home over a client VPN, with the sync agent running live |
| **Linux** | two Ubuntu 24.04 VMs (8 vCPU, 32 GB) on different hosts and different storage; ext4, cold caches |

| Data set | Files | Size |
|---|---|---|
| **Big set** (real-world files incl. one 7.3 GB zip; 37,897 folders) | 85,513 | 19.1 GB |
| Small text files (a subset of the big set) | 8,585 | 496 MB |
| Tiny files | 20,003 | 246 MB |
| Tiny files | 2,000 | 17 MB |
| A project (small files, typical of CAD/code/documents) | 1,975 | 140 MB |
| A larger project | 16,372 | 1.36 GB |
| Linux set (1 KB–1 MB, half text-like, half random) | 100,000 | 970 MB |

## Many small files over a WAN link: robocopy vs scopy

| Data | robocopy `/MT:32` | scopy |
|---|---|---|
| 496 MB small text files | 351.9 s | 86.1 s without compression (4.1×), **21.2 s with zstd 3 (16.6×)** |
| 20,003 tiny files | 738 s | **69 s (10.7×)** |
| 2,000 tiny files | 80 s | **5.7 s (14×)** |
| same 496 MB, pulled back | — | 12.5 s (40 MB/s effective) |
| the big set, `--order small-first` | — | all 85,128 smaller files in ~11 min (0.1: ~35 min); whole job 35:55 (0.1: 56:11), 11.0 GB on the wire for 19.1 GB |

Streaming fills the link where robocopy waits for a round trip per file; compression then cuts the bytes ~5×. The
7.3 GB zip doesn't compress and goes at raw link speed with any tool.

## LAN, 10 Gbit: the big set

| Test | Result |
|---|---|
| `--stage auto` (receiver takes the data into RAM, writes in the background) | **received after 16 s** (~1.2 GB/s of data, 5,300 files/s); on disk after 1:36 |
| start-up before the first byte (scan 85,513 files, plan, 37,897 folders) | 1.6 s |
| through the 10 Gbit link, receiver discards the data (`--sink`) | compression off 9.2 Gbit/s; zstd 1 **11.3 Gbit/s of file data at 6.6 Gbit/s on the wire**; zstd 3 10.3 / 6.0 Gbit/s |
| same with real writes, zstd 1 | 11.1 Gbit/s of file data, 6.5 Gbit/s on the wire |
| TLS 1.3 on every connection (0.9) | costs ~5–8 % on this CPU-bound path |

Over the versions (same data): on disk after 9:19 with 0.3, 6:29 with 0.4; client done after 33 s with 0.6 (RAM
staging), 16 s with 0.8.3; 0.11 (TLS, writing as the user) 18 s, on disk after 1:08.

## Laptop and file server: Explorer vs scopy

`scopy --profile interactive`, averages of two runs, including scopy's start-up:

| Project of 1,975 files | Windows Explorer | scopy |
|---|---|---|
| save, over Wi-Fi | 5:00 | **3.0 s** |
| open, over Wi-Fi | 2:30 | **5.3 s** |
| save, over cable | 1:12 | **2.0 s** |
| open, over cable | 48 s | **4.3 s** |

The larger project (16,372 files) saved in 10–12 s with scopy; with Explorer an estimated ~39 min (not run). The
laptop's antivirus caps file creation at ~600–730 files/s for any tool.

## Two-way sync over a VPN

Live agent on the laptop; changes on the server made over SMB as another machine would.

| Change | On the other side after |
|---|---|
| new file on the PC → server | 5.6 s |
| new file on the server → PC | 6.2 s (0.17); ~1 s with the server change feed (0.19+) |
| changed / deleted on the server → PC | 3.6 s / 3.1 s |
| deleted on the PC → server | 4.6 s |
| conflict resolved (both versions kept) | 1.9 s |
| Word opened on the PC → locked on the server / closed → released | 3.3 s / 3.5 s |
| a change on the share with 20,000 files in the folder (delta listings, 0.21+) | ~1.3 s |
| two machines syncing through one receiver: changes, renames, conflicts, locks, deletes | 4–5 s |

Renames and moves travel as moves: nothing is sent again.

## Crash tests

Hard resets of a VM (like pulling the plug: the write cache is lost), then every file compared by SHA-256.

| Test | Result |
|---|---|
| receiver reset during copies (no stage, RAM stage, detached), then the same copy again | all files identical; the job record makes the repeat re-send what the reset may have left without data |
| receiver reset, client waiting | the client gives up within 22–49 s instead of hanging |
| the pulling PC reset during `scopy get` | the repeat fetched everything again; identical |
| Linux SSH mode and Linux daemon (5 + 3 resets) | all identical |
| **sync**, Windows and Linux: reset during an upload, during a download, 1 s after a folder delete, and right after the server moved a deleted folder into its recycle bin | all PASS on 0.26.1 (both sides identical, deleted files stay deleted) |

What the sync crash tests found and fixed (0.25–0.26): files a reset left zero-filled with the right size and time
were taken as synced (now the server lists the files of interrupted jobs and the PC sends them again); confirmed
deletes still in the server's write cache came back (now flushed before confirming); a round hung for minutes on a
dead connection (`TCP_USER_TIMEOUT` on Linux); a folder renamed on the server during a download sent half of it
back. A further test wrote files on the server the way a big copy does (final size first, data over a few seconds)
while the agent synced: 18 of 20 became conflict copies with 0.26.0, none with 0.26.1.

## Linux

**Against the fastest Linux copy methods** (Linux set, cold caches on both sides, `sync` on the target included,
median of 3, every target tree SHA-256-checked):

| method | RAM → RAM | **disk → disk** | encrypted |
|---|---|---|---|
| **scopy** (SSH mode, default) | 3.3 s | **5.0 s** | yes (TLS) |
| scopy `--compress off` | 2.7 s | 5.1 s | yes |
| rsync daemon ×8 in parallel | 3.0 s | 7.7 s | no |
| tar \| nc ×8 in parallel | 2.4 s | 8.1 s | no |
| fpsync ×16 | 12.9 s | 14.6 s | yes |
| rsync -a (over SSH) | 5.8 s | 36.9 s | yes |
| rclone sftp, 32 transfers | 87.6 s | 88.5 s | yes |

Wherever a disk is involved scopy is the fastest, encrypted: reading in on-disk (inode) order and parallel writers
are what the single-stream tools lack. Without any disk a hand-built 8-way tar pipe is 0.3 s ahead — unencrypted
and unchecked. The static release binary (musl) needed mimalloc as its allocator: musl's own made it twice as slow.

**Unix metadata** (0.25): a tree with every case (setuid/setgid/sticky, 0600 in 0700, read-only folders, symbolic
links relative/absolute/dangling/to folders, nanosecond times) arrives identical to the source in type, mode, owner,
group, time and link target, as a normal user and as root; `rsync -a` got three link times wrong (it compares to
the second). No speed cost.

**Linux daemon** (0.25): copies through the daemon 4.7–4.9 s for the Linux set (SSH session mode 5.0–5.6 s), every
file owned by the signed-in user. Two users sending 100,000 files each at the same time: 4–5 s each, every file
owned by its user, neither can write into or read the other's folders. Two-way sync between a Linux PC and the
daemon: a change on the server on the PC in ~1.2 s; tokens renewed before they expire (0 errors with 60 s tokens).
