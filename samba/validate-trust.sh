#!/usr/bin/env bash
# =============================================================================
# validate-trust.sh - validate the attacker-side AORTA forest trust. No args.
#
#   ./samba/validate-trust.sh
#
# `nltest /sc_verify:victim.local` equivalent: makes YOUR DC (dc01.bytestorm.local)
# re-validate its secure channel toward the victim forest via raw
# NetrLogonControl2Ex (MS-NRPC opnum 18, NETLOGON_CONTROL_TC_VERIFY), wrapped
# by samba/validate-trust.py. Fresh trust auth traffic dc01 -> dc.victim.local,
# NTLM-authenticated (no clock-skew / faketime concerns).
#
# Everything comes from the environment - no arguments needed:
#   defaults.env            WORKGROUP, ADMIN_PASS (used by entrypoint + here)
#   discovered.env          TARGET_REALM (written by ./samba/start-aorta-dc.sh)
#   DC_HOST (optional)      Netlogon endpoint (default 127.0.0.1; compose
#                           publishes SMB loopback-only)
# Extra flags (e.g. --debug) are passed through to validate-trust.py.
#
# Exit codes (from validate-trust.py): 0 = verified/healthy, 1 = app-level
# failure (e.g. ERROR_NO_SUCH_DOMAIN), 2 = RPC fault.
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")/.."

# shellcheck disable=SC1091
source defaults.env
if [ -f discovered.env ]; then
  # shellcheck disable=SC1091
  source discovered.env
fi

: "${TARGET_REALM:?TARGET_REALM unset - run ./samba/start-aorta-dc.sh first (recon writes discovered.env)}"

: "${ADMIN_PASS:?ADMIN_PASS unset in defaults.env}"
ADMIN_PW="${ADMIN_PASS}"
if [ -z "${ADMIN_PW}" ]; then
  echo "[-] empty Administrator password (ADMIN_PASS)" >&2
  exit 1
fi

DC_HOST="${DC_HOST:-127.0.0.1}"

# Preflight: loopback SMB only answers while the DC container is up.
if ! docker ps --format '{{.Names}}' 2>/dev/null | grep -qx aorta-samba-dc; then
  echo "[-] aorta-samba-dc container not running - bring up the stack first: ./samba/start-aorta-dc.sh" >&2
  exit 1
fi

echo "[*] Validating attacker trust: ${REALM} -> ${TARGET_REALM} (Netlogon on ${DC_HOST})"
exec python3 samba/validate-trust.py \
  --dc "${DC_HOST}" \
  --trusted-domain "${TARGET_REALM}" \
  -d "${WORKGROUP}" \
  -u Administrator \
  -p "${ADMIN_PW}" \
  "$@"
