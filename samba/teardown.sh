#!/usr/bin/env bash
# teardown.sh - stop the attacker DC and wipe AD state
set -euo pipefail
cd "$(dirname "$0")/.."
# No .env in this repo - point compose at the two env files explicitly.
COMPOSE_ENV_FILES="defaults.env"
[ -f discovered.env ] && COMPOSE_ENV_FILES="${COMPOSE_ENV_FILES},discovered.env"
export COMPOSE_ENV_FILES

docker compose down -v
