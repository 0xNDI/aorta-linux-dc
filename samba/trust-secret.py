#!/usr/bin/env python3
"""
trust-secret.py - store the shared trust password on a Samba TDO.

Run INSIDE the samba-dc container (piped to `python3 -` by start-aorta-dc.sh):

    docker compose exec -T samba-dc python3 - <partner-dns> <shared-secret> \
        < samba/trust-secret.py

WHY THIS EXISTS: Samba's lsa_CreateTrustedDomainEx (LSARPC opnum 51) ignores
the AuthenticationInformation argument entirely ("do not create secrets for
now", source4/rpc_server/lsa/dcesrv_lsa.c) - it creates the TDO with NO
password, so the KDC derives no trust keys and cross-realm referral TGTs fail
with KRB_AP_ERR_NOT_US ("The ticket isn't for us"). Windows AD stores the
secret for opnum 51, which is why the victim-side aorta tool works unchanged.

samba-tool avoids this via lsa_CreateTrustedDomainEx2 (NDR-serialized
trustDomainPasswords blob). We mirror the resulting on-disk state instead:
ndr_pack(trustAuthInOutBlob) written as the TDO's trustAuthOutgoing attribute
through a system-session LDB - byte-identical to what dcesrv_lsa would store.
"""
import sys

import ldb as ldb_mod
from samba import Ldb
from samba.auth import system_session
from samba.dcerpc import drsblobs, lsa
from samba.ndr import ndr_pack, ndr_unpack
from samba.param import LoadParm

SAM_LDB = "/var/lib/samba/private/sam.ldb"


def build_blob(pw_utf16: bytes, nttime_now: int) -> bytes:
    info = drsblobs.AuthenticationInformation()
    info.LastUpdateTime = nttime_now
    info.AuthType = lsa.TRUST_AUTH_TYPE_CLEAR
    info.AuthInfo.size = len(pw_utf16)
    info.AuthInfo.password = list(pw_utf16)

    arr = drsblobs.AuthenticationInformationArray()
    arr.count = 1
    arr.array = [info]

    blob = drsblobs.trustAuthInOutBlob()
    blob.count = 1
    blob.current = arr
    blob.previous = arr  # dcesrv copies current into previous when absent
    return ndr_pack(blob)


def main() -> int:
    partner, secret = sys.argv[1], sys.argv[2]
    pw_utf16 = secret.encode("utf-16-le")

    import time

    nttime_now = int((time.time() + 11644473600) * 10_000_000)

    lp = LoadParm()
    sam = Ldb(SAM_LDB, session_info=system_session(), lp=lp)
    res = sam.search(
        expression=f"(&(objectClass=trustedDomain)(trustPartner={partner}))",
        attrs=["trustDirection"],
    )
    if len(res) != 1:
        print(f"[-] expected exactly 1 TDO for {partner}, found {len(res)}")
        return 1
    direction = int(res.msgs[0]["trustDirection"][0])
    if not direction & 2:  # OUTBOUND
        print(f"[-] TDO for {partner} is not OUTBOUND (direction={direction})")
        return 1

    data = build_blob(pw_utf16, nttime_now)
    msg = ldb_mod.Message()
    msg.dn = ldb_mod.Dn(sam, str(res.msgs[0].dn))
    msg["trustAuthOutgoing"] = ldb_mod.MessageElement(
        [data], ldb_mod.FLAG_MOD_REPLACE, "trustAuthOutgoing"
    )
    sam.modify(msg)
    print(f"[+] trustAuthOutgoing written to {msg.dn}")

    # read back and verify
    res2 = sam.search(base=msg.dn, scope=ldb_mod.SCOPE_BASE, attrs=["trustAuthOutgoing"])
    io = ndr_unpack(drsblobs.trustAuthInOutBlob, bytes(res2.msgs[0]["trustAuthOutgoing"][0]))
    ai = io.current.array[0]
    stored = bytes(ai.AuthInfo.password[: ai.AuthInfo.size])
    ok = ai.AuthType == lsa.TRUST_AUTH_TYPE_CLEAR and stored == pw_utf16
    print(f"[{'+' if ok else '-'}] read-back: AuthType={ai.AuthType} "
          f"LastUpdateTime={ai.LastUpdateTime} password_match={stored == pw_utf16}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
