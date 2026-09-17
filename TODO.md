# --kerb: Kerberos ticket dump — TODO

## Goal

Add a `--kerb` flag to `titan dump` that dumps all Kerberos tickets cached on
the remote host to a local `.ccache` file, mirroring what
[klist2ccache](https://github.com/jakeotte/klist2ccache) does but using Titanis
binaries only (no impacket).  Primary target: TGTs left in LSASS from
interactive/RDP sessions — e.g. a domain admin who RDP'd in and logged out but
whose ticket is still cached.

## Approach

Use `Tsch` (MS-TSCH over SMB named pipe, port 445) instead of WMI (DCOM) for
remote command execution — Tsch avoids the Kerberos SPN failure that WMI/DCOM
hits when targeting by IP address (`RPCSS/<ip>` doesn't exist as an SPN).

1. `Tsch create/run` → `klist sessions` → capture output → pull via `Smb2Client`
2. Parse session list with regex; keep only `Kerberos:*` auth sessions (NTLM/Negotiate have no tickets)
3. Per LUID: `Tsch create/run` → `klist tickets /export -lh <H> -li <L>` in a per-LUID subdir
4. `Smb2Client get` → pull all `.kirbi` files
5. `Kerb select -From <files> -Into {host}_tickets.ccache -Overwrite`
6. `Tsch delete` all tasks + `rmdir` remote temp tree

## Known issues to resolve

### `klist tickets /export` not supported on all Windows versions
`klist.exe` on Windows Server 2019 build 17763 does not recognise `/export`.
The abbreviated help shows only `[tickets]` and `sessions` — no `/export` flag.
**Fix to investigate**: `klist tickets /export` was added in later Server 2019
cumulative updates and Windows 10 1903+.  Possible fallback: use `klist tgt
-lh <H> -li <L>` to get TGT data as text (hex dump), then parse it into ccache
format directly in Python (the klist2ccache approach — no impacket needed, just
struct/bytes).

### klist -li requires signed decimal, not hex, for values > 0x7fffffff
Windows `klist` parses `-li` as a signed 32-bit integer.  LUIDs with the high
bit set (e.g. `0xcf48b94b`) must be passed as their signed decimal equivalent
(`ctypes.c_int32(int(luid, 16)).value`) or klist silently clamps to
`0x7fffffff` and targets the wrong session.  **This is already worked out.**

### Network logon sessions are transient
`Kerberos:Network` sessions in `klist sessions` are created per-connection and
terminated when the connection closes.  They are typically gone before we can
enumerate and export.  The valuable targets are interactive/RDP sessions
(`Kerberos:Interactive` or `Kerberos:RemoteInteractive`) — those persist in
LSASS even after the user logs out.  Test against a machine where a domain
admin has RDP'd in, not a server with only service connections.

---

# Proxychains / ntlmrelayx --socks relay support — TODO

## Goal
Make `proxychains titan shell --scm DOMAIN/USER@<ip> --no-pass` work
transparently with ntlmrelayx `--socks` relay sessions on engagement machines.

## What was tried

### 1. relay_proxy.py — SMB2 credit-booster proxy
A SOCKS5 proxy thread that sat between Titanis and ntlmrelayx, patching
CreditRequestResponse (1 → 64) and MaxTransactSize (65536 → 8MB) in forged
NEGOTIATE/SESSION_SETUP responses. Removed because the root problem was
socket routing, not credits.

### 2. proxychains 3.x → 4.x lib substitution
`activate_relay_mode()` detected proxychains 3.x in LD_PRELOAD and tried to
swap in libproxychains.so.4 so .NET CoreCLR sockets would be intercepted.
Worked on machines that had proxychains4 installed; engagement machine
(cts-mantis-037) had neither libproxychains.so.4 nor proxychains4.

### 3. Python/impacket SCM exec path (`--socks` flag, susinternals pattern)
Replaced Titanis Scm (.NET binary, not hooked by proxychains 3.x) with a
pure Python/impacket SCM exec on a single SMBConnection. Rationale: Python
uses libc sockets, which proxychains 3.x *should* hook. In practice,
proxychains 3.x on cts-mantis-037 did NOT hook Python socket calls either
(likely ABI/version issue with the installed libproxychains.so.3).

### 4. Local TCP→SOCKS5 forwarder thread
When proxychains-ng 4.x was NOT in LD_PRELOAD, spun up an in-process
forwarder thread that connected directly to ntlmrelayx at 127.0.0.1:1080
(no proxychains hook needed — ntlmrelayx is local) and provided a local port
for SMBConnection to connect to. Also added SOCKS5 username:password auth
(method 0x02, username = DOMAIN/USER) to handle ntlmrelayx versions that
require it. Removed with everything else — did not get to confirm if it
worked before engagement priorities shifted.

## Root causes

- **proxychains 3.x on cts-mantis-037** does not hook .NET CoreCLR OR Python
  socket calls — the installed libproxychains.so.3 appears to have an ABI
  issue with the system libc version.
- **No proxychains4** (`apt install proxychains4`) on the engagement machine.

## Recommended fix (if revisiting)

1. Get proxychains4 on the engagement machine (`apt install proxychains4` or
   copy libproxychains.so.4 from another host into /tmp and point LD_PRELOAD
   at it manually).
2. Either approach then works: the Titanis Scm .NET binary (proxychains4
   hooks CoreCLR) or the Python/impacket path (proxychains4 hooks Python).
3. Alternatively, re-add the local forwarder approach from attempt #4 —
   it is proxychains-independent and only needs ntlmrelayx running on
   localhost:1080.
