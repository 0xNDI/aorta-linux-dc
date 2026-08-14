#!/usr/bin/env python3
"""
victim-enum.py - anonymous recon of the victim forest (no credentials).

Two INDEPENDENT null-session probes; either may fail without taking the
other down - start-aorta-dc.sh merges whatever is collected here with CLI
flags and cached discovered.env values:
  - rpcclient 'lsaquery' over anonymous SMB/LSARPC (like enum4linux):
    NetBIOS domain name + domain SID           -> TARGET_NETBIOS / TARGET_SID
  - anonymous LDAP RootDSE: dnsHostName (DC FQDN) and rootDomainNamingContext
    (=> DNS domain name / realm)               -> TARGET_DC_FQDN / TARGET_REALM

Usage:  python3 victim-enum.py <victim_dc_ip>
Stdout: one TARGET_*=value line per collected field (TARGET_DC_IP always -
it is the input address). Per-probe failures are reported on stderr; exits
non-zero only when BOTH probes fail and nothing could be collected.
"""
import re
import subprocess
import sys


def rpc_lsaquery(ip: str) -> tuple[str | None, str | None]:
    """Anonymous rpcclient lsaquery -> (netbios_domain, domain_sid)."""
    try:
        p = subprocess.run(
            ["rpcclient", "-U", "", "-N", ip, "-c", "lsaquery"],
            capture_output=True, text=True, timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        print(f"[-] lsaquery against {ip}: {e}", file=sys.stderr)
        return None, None
    out = p.stdout
    m_netbios = re.search(r"^Domain Name:\s*(\S+)", out, re.M)
    m_sid = re.search(r"^Domain Sid:\s*(S-\d+-\d+-\d+-\d+-\d+-\d+)", out, re.M)
    if not m_netbios or not m_sid:
        print(f"[-] anonymous lsaquery failed against {ip} "
              f"(null session blocked / SMB unreachable?):\n{out}{p.stderr}",
              file=sys.stderr)
        return None, None
    return m_netbios.group(1), m_sid.group(1)


def rootdse(ip: str) -> tuple[str | None, str | None]:
    """Anonymous RootDSE -> (dc_fqdn, dns_domain)."""
    try:
        import ldap3
        srv = ldap3.Server(ip, get_info=ldap3.NONE, connect_timeout=5)
        conn = ldap3.Connection(srv, authentication=ldap3.ANONYMOUS, auto_bind=True,
                                receive_timeout=5)
        conn.search("", "(objectClass=*)", search_scope=ldap3.BASE,
                    attributes=["dnsHostName", "rootDomainNamingContext"])
        e = conn.entries[0]
        fqdn = str(e["dnsHostName"])
        nc = str(e["rootDomainNamingContext"])          # DC=victim,DC=local
        conn.unbind()
    except Exception as e:  # noqa: BLE001
        print(f"[-] anonymous RootDSE failed against {ip}: {e}", file=sys.stderr)
        return None, None
    domain = ".".join(p[3:] for p in nc.split(",") if p.startswith("DC="))
    return fqdn.lower(), domain.lower()


def main() -> None:
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    ip = sys.argv[1]

    netbios, sid = rpc_lsaquery(ip)
    dc_fqdn, domain = rootdse(ip)
    if netbios is None and dc_fqdn is None:
        sys.exit(f"[-] both probes failed against {ip}; nothing collected")

    if netbios:
        print(f"TARGET_NETBIOS={netbios}")
    if sid:
        print(f"TARGET_SID={sid}")
    if domain:
        print(f"TARGET_REALM={domain}")
    if dc_fqdn:
        print(f"TARGET_DC_FQDN={dc_fqdn}")
    print(f"TARGET_DC_IP={ip}")


if __name__ == "__main__":
    main()
