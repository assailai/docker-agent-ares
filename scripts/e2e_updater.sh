#!/usr/bin/env bash
# =============================================================================
# End-to-end check for the companion updater (Docker backend) against the local
# Docker daemon. Two real alpine tags stand in for the agent so the full recreate
# / verify-then-swap path runs for real, then we assert the agent moved (happy
# path) or stayed put (fail-closed, fail-safe).
#
# Usage:  bash scripts/e2e_updater.sh   (needs Docker + uv; pulls alpine:3.18/3.19)
# =============================================================================
set -uo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
NAME="ares-agent-e2e"
T="$(mktemp -d)"
PASS=0 FAIL=0

cleanup() { docker rm -f "$NAME" "${NAME}-next" >/dev/null 2>&1; rm -rf "$T"; }
trap cleanup EXIT

ok()  { echo "  PASS: $1"; PASS=$((PASS + 1)); }
bad() { echo "  FAIL: $1"; FAIL=$((FAIL + 1)); }
image_of() { docker inspect -f '{{.Config.Image}}' "$NAME" 2>/dev/null; }
state_of() { docker inspect -f '{{.State.Status}}' "$NAME" 2>/dev/null; }

fresh_agent() {  # $1 = starting image
  docker rm -f "$NAME" "${NAME}-next" >/dev/null 2>&1
  docker run -d --name "$NAME" "$1" sleep infinity >/dev/null
}

tick() {  # caller sets ARES_UPDATE_* in the environment; runs one updater tick
  # this ticks from the host, not from an updater container: never let it reach for an
  # ares-updater container of the machine's own (scripts/e2e_self_update.sh covers self-update)
  ( cd "$REPO_DIR" && ARES_UPDATE_SELF_UPDATE=false uv run --no-project --with httpx --with pydantic-settings python -c "
from updater import main
from updater.dockerd import DockerBackend
try:
    main._tick(DockerBackend())
except Exception as exc:
    print('tick raised:', exc)
" ) 2>&1 | sed 's/^/    /'
}

echo "==> Test 1: happy path (alpine:3.18 -> alpine:3.19)"
fresh_agent alpine:3.18
printf '{"version":"3.19"}' >"$T/t.json"
ARES_UPDATE_CONTAINER="$NAME" ARES_UPDATE_REQUIRE_SIGNATURE=false ARES_UPDATE_TARGET_FILE="$T/t.json" tick
[ "$(image_of)" = "alpine:3.19" ] && ok "agent moved to alpine:3.19" || bad "expected alpine:3.19, got $(image_of)"

echo "==> Test 2: fail-closed (require signature, none configured -> refuse)"
fresh_agent alpine:3.18
printf '{"version":"3.19"}' >"$T/t.json"
ARES_UPDATE_CONTAINER="$NAME" ARES_UPDATE_REQUIRE_SIGNATURE=true ARES_UPDATE_TARGET_FILE="$T/t.json" tick
[ "$(image_of)" = "alpine:3.18" ] && ok "refused; agent stayed on alpine:3.18" || bad "expected alpine:3.18, got $(image_of)"

echo "==> Test 3: fail-safe (target version does not exist -> agent unharmed)"
fresh_agent alpine:3.18
printf '{"version":"99.99.99-nope"}' >"$T/t.json"
ARES_UPDATE_CONTAINER="$NAME" ARES_UPDATE_REQUIRE_SIGNATURE=false ARES_UPDATE_TARGET_FILE="$T/t.json" tick
{ [ "$(image_of)" = "alpine:3.18" ] && [ "$(state_of)" = "running" ]; } && ok "bad target ignored; agent still running alpine:3.18" || bad "agent harmed: image=$(image_of) state=$(state_of)"

echo ""
echo "e2e_updater: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] || exit 1