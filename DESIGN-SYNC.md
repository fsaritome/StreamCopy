# Design: two-way sync

How scopy keeps a user's folders (Desktop, Documents, Downloads, …) in sync between their PCs and a file server.
Status: works and is crash-tested; still in development (see the issues).

## Goals

| Situation | Wanted |
|---|---|
| PC in the office | changes reach the server within seconds; a fast logon (no waiting for a sync) |
| PC on the road | works fully offline; catches up when back, without a full rescan |
| The same user on a terminal server and a PC | a file saved on one shows up on the other within seconds |
| Several PCs per user | every change reaches every machine; nothing is lost when two change the same file |

Compared with the usual options: folder redirection with Offline Files caches whole files and handles conflicts
badly; cloud sync (OneDrive and similar) moves the data out of the organisation; DFS-R replicates whole shares
between servers, not a user's folders to their PCs. scopy keeps the data on the organisation's own file server and
moves it with its fast copy engine.

## Pieces

```
 PC (agent, as the user)                              file server (receiver, acts as the user)
 scopy sync run ── listing / push / pull / locks ──▶  scopy serve, [sync] root = D:\sync\users
   watches the folders                                  <root>\<user>\Desktop, Documents, …
   state DB (what both sides had after the last round)  change feed: tells the PC when its folders changed
 tray app scopyw.exe (status, pause, options)          recycle bin .scopy-recycle (kept 30 days)
```

- **Enrolment**: `scopy sync enable --server <host>` as the user; the receiver creates the user's folders, owned by
  them and readable only by them (Windows: the user's SID; Linux: mode 0700).
- **Identity**: the agent signs in as the user (Kerberos bound to the TLS session on Windows, a token through SSH
  on Linux); the receiver reads and writes as that user, so the file system's permissions decide everything.
- **The PC service** (`scopy sync service install`) starts the agent in each user's session at logon and restarts it;
  the tray app shows its state.

## A round

1. Scan the PC's folders (only the paths the folder watch named since the last round, after the first).
2. Get the server's listing — in full, or only what changed since the last round (the receiver keeps a change log
   per folder while the PC's change feed is connected).
3. Decide per file from three versions: the last synced one, the PC's and the server's (size and modification time;
   file ids to recognise renames and moves on either side).
4. Do it: moves and renames as moves, deletes into a recycle bin on the side that deletes, pushes and pulls through
   the copy engine (only the named files).
5. Save the new state — the versions that were actually written, so a file that changed again meanwhile is seen as
   changed in the next round.

## Rules

- **Conflicts**: a file changed on both sides keeps the server's version under its name; the PC's becomes
  `name (conflict PC time).ext` on both sides. Nothing is overwritten silently.
- **Deletes** go into a recycle bin on either side, kept 30 days (configurable). Asking before many deletes is an
  option (off by default). A wiped folder is never followed silently.
- **Open files**: a file a program has open on the PC is never replaced, deleted or renamed under it. An Office
  document open on a PC is locked on the server for everyone else (Word elsewhere opens it read-only) until it is
  closed, or until a lease runs out after the PC went silent.
- **Left out**: Office owner files (`~$*`), temp files and downloads in progress; a "local" folder that is itself a
  network path is refused.
- **Files still being written on the server** (a big copy onto the share) are fetched once they are complete.

## Crash safety

- The receiver confirms nothing before it is on disk: file data, and also moves and deletes (a rename is a write).
- A job cut off by a crash leaves a record of the files it was writing; they may have the right size and time but no
  data. The receiver lists them to the PC with every listing, and the PC sends them again instead of taking them as
  synced; a PC never fetches them as they are.
- Tested with hard resets of the receiver during uploads, downloads, deletes and recycle-bin moves, on Windows and
  Linux: both sides identical afterwards, deleted files stay deleted ([BENCHMARKS.md](BENCHMARKS.md)).

## Open

The agent as a user service on Linux; open-file locks on Linux; files on demand (placeholders); a size cap for the
recycle bin; a crash of the PC side.
