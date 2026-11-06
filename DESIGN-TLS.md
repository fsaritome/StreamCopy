# Design: TLS bound to the SMB proof

Status: **built in 0.9.0**; measured cost 5–8 % ([BENCHMARKS.md](BENCHMARKS.md)). Goal: scopy can leave the
trusted LAN and sync can run unattended, without a PKI, certificates to manage, or a second password.

## Today
- Control and data connections are plain TCP. Anyone on the path can read the data and, knowing a session id,
  join a data connection.
- Access is proven through SMB: **push** — the receiver hands out a ticket name and a nonce, the client writes the
  nonce into the destination over SMB with the user's own credentials, the receiver checks the file on its disk;
  **pull** — the receiver writes the nonce into the source folder, the client reads it over SMB and sends it back.
  SMB itself is authenticated (Kerberos), so only someone who can write (read) there gets a session.

## Idea
Wrap every connection in TLS 1.3 (rustls) with an **ephemeral, self-signed server key** (no CA, nothing to
deploy), and **bind the TLS session to the SMB proof**:

1. Client connects with TLS and accepts any server key (no certificate check — authentication comes from step 3).
2. Both sides derive the TLS exporter `E = exporter("scopy-ticket-v1", 32 bytes)` (RFC 5705 / 8446 §7.5). E is
   identical on both ends of one TLS session and different on every other session.
3. **Push:** the client writes `nonce || hex(E)` into the SMB ticket. The receiver accepts only if the ticket on its
   disk carries *its own* E. **Pull:** the receiver writes `nonce || hex(E)`; the client accepts only if it reads its
   own E.
4. A man in the middle terminates two TLS sessions with different exporters. It can't rewrite the ticket (that
   needs the user's SMB/Kerberos credentials), so the receiver sees the wrong E and refuses: **MITM detected, no PKI**.
5. **Data connections** join over TLS too, with `HMAC(E, "data" || sid)` sent inside TLS instead of the bare
   session id. Only the client that holds E can open them; a sniffed session id is useless.

## What it costs
- Measured ceiling today: ~780 MB/s on the wire over 8 streams on 8 vCPU ≈ 100 MB/s per stream.
  AES-256-GCM / ChaCha20 in rustls encrypts ~1.5–3 GB/s per core with AES-NI, so a few % CPU per side.
- CPU is already the brake on the fast LAN path: expect **up to ~5–10 %** there, nothing measurable on Wi-Fi/WAN.
- Measure with `--sink` across two hosts (TLS on vs off) before deciding whether it may ever be switched off.

## Build choices
- **rustls 0.23 with the `ring` provider** (pure Rust + asm; no CMake/NASM toolchain on Windows build machines,
  unlike the default aws-lc-rs) and **rcgen** for the ephemeral key. Both cross-compile for Linux/NAS (zigbuild).
- Protocol **9**: TLS is mandatory; a 0.8 peer is refused with a clear message (only our own clients and receivers
  exist, so no long mixed phase). Deploy receivers first, then clients.
- `--insecure-plain` (receiver) only if the measurement shows a cost worth an opt-out on trusted LANs — decide
  after measuring, default stays TLS.

## Follow-ups that build on it
- Bind `scopy status` to the TLS identity of the job's client.
- Move the overlap probe after the access check (it is written before authentication today).
- Later: write as the user (SSPI/Kerberos, impersonation) — the identity part of the sync service design
  (done in 0.11: the receiver acts as the signed-in user).

## Remembered access proofs (0.23.0, protocol 20, src/proofs.rs)

Every push and pull proves access through SMB (the ticket above). For the sync agent that is several SMB round trips
(0.4–0.55 s over a VPN) on every round, for the same folder, again and again. Now:

- After a successful ticket check the receiver hands the client a random token (128 bit) with the session id. It
  stands for: *this Windows user (SID) proved read — or write — access to this folder (the resolved local path) at
  this time*. It lives 10 minutes in the receiver's memory and is not extended; a restart forgets all tokens.
- A push or pull sends its token (or nothing) after share/subpath. The receiver accepts it only if the connection
  has signed in (Kerberos bound to this connection's TLS session, as before) as the **same SID**, for the **same
  folder** and the **same direction**, within the lifetime. Then it answers ACCESS_TOKEN and the ticket step is
  skipped; otherwise ACCESS_TICKET and the ticket check runs as before (and a new token is handed out).
- Without a sign-in there is no token (and the service identity never gets one). Only the agent keeps tokens (in
  memory); `scopy send`/`get` always prove over SMB.

What it changes in the security model: a stolen token is worth nothing without signing in as that user, which a man
in the middle cannot do (the sign-in is bound to the TLS session; the MITM test still refuses a terminating relay
at the sign-in). The receiver acts as the user either way, so NTFS permissions apply to every file at once; what can
lag by up to 10 minutes is a change that SMB alone enforces (share permissions, a user locked out of the share).
Measured: connect + access check 0.41–0.54 s with the ticket, 0.11–0.12 s with a token.

## Test plan
1. Unit: exporter equal on both ends; ticket with a foreign E is refused; data join with a wrong HMAC is refused.
2. Loopback: push/pull, `--sink`, crash test (record logic unchanged).
3. Two VMs across hosts: sink TLS on/off (cost), real run, client test over cable.
4. A deliberate MITM (a TCP relay that re-terminates TLS) must be refused. **Done** (
   relay = hidden `test-relay` in a `--features testtools` build): locally and from a laptop to a test receiver, a forwarding relay lets
   push and pull through; a terminating relay is refused in both directions ("the ticket belongs to a different TLS
   session") and **no file is written**. Repeated with 0.23.0 (tokens): forward passes, terminate is refused at the
   Windows sign-in in both directions.
