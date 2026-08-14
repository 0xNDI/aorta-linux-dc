#!/usr/bin/env python3
"""
validate-trust.py - Linux equivalent of `nltest /sc_verify:<domain>` over MS-NRPC.

`nltest /sc_verify:<TrustedDomain>` (optionally `/server:<target>`) tells the
Netlogon service on a machine to VERIFY -- and if needed re-establish -- its
secure channel to a DC of <TrustedDomain>. That maps 1:1 to the MS-NRPC call

    NetrLogonControl2Ex  (opnum 18)
        ServerName   = target machine (NULL = the RPC endpoint we bound to)
        FunctionCode = NETLOGON_CONTROL_TC_VERIFY  (0x0000000A)
        QueryLevel   = 2                            (mandatory for TC_VERIFY)
        Data         = union NETLOGON_CONTROL_DATA_INFORMATION
                       { tag 0x0A -> TrustedDomainName: "<domain>" }
        Buffer       = union NETLOGON_CONTROL_QUERY_INFORMATION
                       { tag 2 -> NETLOGON_INFO_2 }

Per MS-NRPC 3.5.4.9.1 the server then "calls any Netlogon method that
requires a secure channel to the DC in the domain name provided in the
TrustedDomainName field" - i.e. the target actively re-validates the trust,
generating fresh authentication traffic towards that domain's DCs.

WIRE NOTES (verified against the local Samba DC; both deviations are
rejected with RPC_X_BAD_STUB_DATA):
  * The Data union carries its discriminant tag on the wire and - being a
    top-level [in,ref] parameter - has NO pointer field in front of it.
    impacket's stock nrpc.NetrLogonControl2Ex encodes exactly that.
  * NDR conformant strings include the trailing NUL in max/actual count and
    data. impacket's LPWSTR packing omits it (same quirk trust-create.py's
    make_trust_string patches for RPC_UNICODE_STRING), so we append an
    explicit \\x00 to the domain name.

DIRECTION (mirrors nltest exactly):
  target         = the machine whose Netlogon service does the validation
  trusted-domain = the domain it validates its secure channel TO

  # attacker side, zero-arg wrapper over defaults.env / discovered.env:
  # (= nltest /sc_verify:victim.local on a Windows attacker DC)
  ./samba/validate-trust.sh

  # ...which is shorthand for:
  python3 samba/validate-trust.py --dc 127.0.0.1 --trusted-domain victim.local \
      -d BYTESTORM -u Administrator -p 'Password__42'

  # make the VICTIM DC validate toward you (fresh auth back to your DC)
  # (= nltest /server:dc.victim.local /sc_verify:bytestorm.local)
  python3 samba/validate-trust.py --dc dc.victim.local --trusted-domain bytestorm.local \
      -d VICTIM -u <user> -p '<pw>'

ACCESS (Windows targets): the Netlogon RPC interface is registered with
D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)
  (A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)
so remote callers need an admin (BA) or SYSTEM-equivalent context on the
TARGET machine; on a victim DC that means victim-domain admin unless a
SYSTEM foothold is already present. Plain low-priv users get
ERROR_ACCESS_DENIED (5). Against your own Samba DC the local Administrator
is enough - and unlike `samba-tool domain trust validate` this does only
the Netlogon call: no remote LSA/LDAP legs (which is what forces the
victim-domain admin requirement there). Uses NTLM, so no Kerberos clock
skew concerns even with the faketime-synced container.

Samba's own `samba-tool domain trust validate <dom>` issues exactly these
RPCs (python/samba/netcmd/domain/trust.py): TC_VERIFY level 2, then
REDISCOVER level 2 with "<domain>\\<dc>"; --validate-location=local keeps it
on your own DC.
"""
import argparse
import sys

from impacket import nt_errors
from impacket.dcerpc.v5 import nrpc, transport
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5.rpcrt import DCERPCException

# netlog2_flags bit (MS-NRPC 2.2.1.7.3 / Samba netlogon.idl): when set,
# netlog2_pdc_connection_status carries the trust-verification result
# rather than just the cached channel status.
NETLOGON_VERIFY_STATUS_RETURNED = 0x00000001

# Values that can appear in netlog2_*_connection_status (NET_API_STATUS
# fields that may carry NTSTATUS values) or in the call's error code.
STATUS_NAMES = {
    0x00000000: "STATUS_SUCCESS",
    0x00000005: "ERROR_ACCESS_DENIED",
    0x00000057: "ERROR_INVALID_PARAMETER",
    0x0000054B: "ERROR_NO_SUCH_DOMAIN",
    0x000008CA: "ERROR_NO_SUCH_DOMAIN",
    0x000008D3: "ERROR_NO_LOGON_SERVERS",
    0xC0000022: "STATUS_ACCESS_DENIED",
    0xC000005E: "STATUS_NO_LOGON_SERVERS",
    0xC000006A: "STATUS_WRONG_PASSWORD",
    0xC00000DF: "STATUS_NO_SUCH_DOMAIN",
    0xC0000428: "STATUS_DOMAIN_TRUST_INCONSISTENT",
}


def status_str(v: int) -> str:
    v &= 0xFFFFFFFF
    name = STATUS_NAMES.get(v, nt_errors.ERROR_MESSAGES.get(v, ("", ""))[0])
    return f"0x{v:08x} ({name})" if name else f"0x{v:08x}"


def sc_verify(dc: str, trusted_domain: str, user: str, password: str,
              domain: str, lmhash: str = "", nthash: str = "",
              server_name: str | None = None, debug: bool = False) -> int:
    rpctransport = transport.DCERPCTransportFactory(
        rf"ncacn_np:{dc}[\PIPE\netlogon]"
    )
    rpctransport.set_credentials(user, password, domain, lmhash, nthash)
    dce = rpctransport.get_dce_rpc()
    dce.connect()
    dce.bind(nrpc.MSRPC_UUID_NRPC)

    request = nrpc.NetrLogonControl2Ex()
    request["ServerName"] = server_name if server_name else NULL
    request["FunctionCode"] = nrpc.NETLOGON_CONTROL_TC_VERIFY
    request["QueryLevel"] = 2
    request["Data"]["tag"] = nrpc.NETLOGON_CONTROL_TC_VERIFY
    # NUL-terminated conformant string (see module docstring: impacket's
    # default LPWSTR packing omits the terminator and the server rejects
    # the stub with RPC_X_BAD_STUB_DATA).
    request["Data"]["TrustedDomainName"] = trusted_domain + "\x00"
    if debug:
        print("[*] stub:", request.getData().hex())

    print(f"[*] NetrLogonControl2Ex(TC_VERIFY) on {dc} for '{trusted_domain}' ...")
    try:
        # checkError=False: the NET_API_STATUS comes back in resp['ErrorCode']
        # and we want to report it ourselves.
        resp = dce.request(request, checkError=False)
    except DCERPCException as e:
        code = getattr(e, "error_code", None)
        print(f"[-] RPC fault: 0x{code:08x} - {e}" if code else f"[-] RPC fault: {e}")
        return 2
    finally:
        dce.disconnect()

    err = resp["ErrorCode"] & 0xFFFFFFFF
    if err != 0:
        print(f"[-] NetrLogonControl2Ex failed: {status_str(err)}")
        return 1

    # the union arm access auto-unwraps PNETLOGON_INFO_2 -> NETLOGON_INFO_2
    info = resp["Buffer"]["NetlogonInfo2"]
    flags = int(info["netlog2_flags"]) & 0xFFFFFFFF
    pdc_status = int(info["netlog2_pdc_connection_status"]) & 0xFFFFFFFF
    tc_status = int(info["netlog2_tc_connection_status"]) & 0xFFFFFFFF
    dc_name = (info["netlog2_trusted_dc_name"] or "(none)").replace("\x00", "").rstrip()

    print(f"[+] Trusted DC:        {dc_name}")
    print(f"[+] flags:             0x{flags:08x}"
          + (" (NETLOGON_VERIFY_STATUS_RETURNED)" if flags & NETLOGON_VERIFY_STATUS_RETURNED else ""))
    print(f"[+] PDC conn status:   {status_str(pdc_status)}")
    print(f"[+] TC conn status:    {status_str(tc_status)}")

    if flags & NETLOGON_VERIFY_STATUS_RETURNED and pdc_status == 0:
        print("[+] Trust verified OK (fresh secure-channel validation performed)")
        return 0
    if tc_status == 0 and pdc_status == 0:
        print("[+] Secure channel to the trusted domain is healthy")
        return 0
    print("[!] Secure channel to the trusted domain is NOT healthy (see statuses)")
    return 1


def main() -> int:
    p = argparse.ArgumentParser(
        prog="validate-trust.py",
        description="nltest /sc_verify:<domain> equivalent over NetrLogonControl2Ex (MS-NRPC opnum 18)",
    )
    p.add_argument("--dc", required=True, help="target Netlogon server (the machine that performs the validation)")
    p.add_argument("--trusted-domain", required=True, help="domain to verify the secure channel TO (Data.TrustedDomainName)")
    p.add_argument("--server-name", default=None, help="ServerName argument (default: NULL; try the DC FQDN if the server errors with ERROR_INVALID_COMPUTERNAME)")
    p.add_argument("-d", "--domain", required=True, help="authentication domain (NTLM)")
    p.add_argument("-u", "--user", required=True, help="username")
    p.add_argument("-p", "--password", default="", help="password")
    p.add_argument("--hashes", default="", help="LMHASH:NTHASH instead of password")
    p.add_argument("--debug", action="store_true", help="dump the request stub bytes")
    args = p.parse_args()

    lmhash = nthash = ""
    if args.hashes:
        lmhash, _, nthash = args.hashes.partition(":")
    return sc_verify(args.dc, args.trusted_domain, args.user, args.password,
                     args.domain, lmhash, nthash, args.server_name, args.debug)


if __name__ == "__main__":
    sys.exit(main())
