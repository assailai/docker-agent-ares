#!/usr/bin/env bash
# =============================================================================
# end-to-end check that the companion updater updates the agent AND itself (ARES-2049), on a real
# Docker engine, with the real updater image and a local registry.
#
#   1.0.0 -> 1.0.1   the updater moves the agent, then hands itself over to a 1.0.1 successor
#   1.0.1 -> 1.0.2   that successor does the same again (a stamp it inherited would break this)
#   1.0.2 -> 9.9.9   the 9.9.9 updater crashes on start: the agent moves, the 1.0.2 updater stays
#                    in charge and leaves nothing behind
#   self-update off  ARES_UPDATE_SELF_UPDATE=false moves the agent only
#
# signature checks are off: these images are built here, unsigned. The cosign gate is the same
# verify() path for the updater as for the agent, covered by tests/test_updater.py and exercised by
# every production update.
#
# Usage:  bash scripts/e2e_self_update.sh
#   E2E_UPDATER_IMAGE=<ref>  use a prebuilt updater image instead of building Dockerfile.updater
#   E2E_REGISTRY_PORT=<port> local registry port (default 5000)
# needs Docker; pulls registry:2 and alpine:3.20.
# =============================================================================
set -uo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PORT="${E2E_REGISTRY_PORT:-5000}"
REG="localhost:${PORT}/assailai"
AGENT=ares-agent-e2e
UPDATER=ares-updater-e2e
VOLUME=ares-agent-data-e2e
REGISTRY=ares-e2e-registry
PASS=0
FAIL=0

cleanup() {
    docker rm -f "$AGENT" "${AGENT}-next" "$UPDATER" "${UPDATER}-next" "${UPDATER}-old" \
        "$REGISTRY" >/dev/null 2>&1
    docker volume rm "$VOLUME" >/dev/null 2>&1
}
trap cleanup EXIT

ok() { echo "  PASS: $1"; PASS=$((PASS + 1)); }
bad() { echo "  FAIL: $1"; FAIL=$((FAIL + 1)); }
image_of() { docker inspect -f '{{.Config.Image}}' "$1" 2>/dev/null; }
id_of() { docker inspect -f '{{.Id}}' "$1" 2>/dev/null; }
leftovers() { docker ps -a --format '{{.Names}}' | grep -E "^(${UPDATER}-(next|old)|${AGENT}-next)$"; }
target() { docker exec "$AGENT" sh -c "printf '{\"version\": \"$1\"}' > /data/update-target.json"; }
updater_logs() { echo "  --- updater logs ---"; docker logs --tail 30 "$UPDATER" 2>&1 | sed 's/^/  /'; }

# wait_for <seconds> <description> <command...>: poll until the command succeeds
wait_for() {
    local seconds=$1 what=$2
    shift 2
    for _ in $(seq 1 "$seconds"); do
        "$@" && return 0
        sleep 1
    done
    echo "  timed out waiting for: $what"
    return 1
}
on_versions() {  # on_versions <agent version> <updater version>: both moved and nothing left over
    [ "$(image_of "$AGENT")" = "$REG/ares-agent:$1" ] &&
        [ "$(image_of "$UPDATER")" = "$REG/ares-updater:$2" ] &&
        [ -z "$(leftovers)" ]
}

start_updater() {  # start_updater <version> [extra docker run args...]
    local version=$1
    shift
    docker rm -f "$UPDATER" >/dev/null 2>&1
    docker run -d --name "$UPDATER" \
        -e "ARES_UPDATE_CONTAINER=$AGENT" \
        -e "ARES_UPDATE_SELF_CONTAINER_NAME=$UPDATER" \
        -e ARES_UPDATE_REQUIRE_SIGNATURE=false \
        -e ARES_UPDATE_POLL_SECONDS=2 \
        -v "$VOLUME:/data:ro" \
        -v /var/run/docker.sock:/var/run/docker.sock \
        --restart=always "$@" "$REG/ares-updater:$version" >/dev/null
}

echo "==> Local registry on :$PORT"
docker rm -f "$REGISTRY" >/dev/null 2>&1
docker run -d --name "$REGISTRY" -p "$PORT:5000" registry:2 >/dev/null || exit 1

BASE="${E2E_UPDATER_IMAGE:-}"
if [ -z "$BASE" ]; then
    echo "==> Build the updater image (Dockerfile.updater)"
    docker build -q -f "$REPO_DIR/Dockerfile.updater" -t ares-updater:e2e "$REPO_DIR" >/dev/null || exit 1
    BASE=ares-updater:e2e
fi

echo "==> Publish agent and updater versions 1.0.0, 1.0.1, 1.0.2 and 9.9.9"
for v in 1.0.0 1.0.1 1.0.2 9.9.9; do
    printf 'FROM alpine:3.20\nLABEL e2e.version=%s\nCMD ["sleep", "infinity"]\n' "$v" |
        docker build -q -t "$REG/ares-agent:$v" - >/dev/null || exit 1
    if [ "$v" = 9.9.9 ]; then
        # an updater that dies as soon as it starts: the successor that must never take over
        printf 'FROM %s\nLABEL e2e.version=%s\nENTRYPOINT ["sh", "-c", "exit 1"]\n' "$BASE" "$v"
    else
        printf 'FROM %s\nLABEL e2e.version=%s\n' "$BASE" "$v"
    fi | docker build -q -t "$REG/ares-updater:$v" - >/dev/null || exit 1
    docker push -q "$REG/ares-agent:$v" >/dev/null && docker push -q "$REG/ares-updater:$v" >/dev/null || exit 1
done

echo "==> Agent and updater at 1.0.0"
docker volume create "$VOLUME" >/dev/null
docker run -d --name "$AGENT" -v "$VOLUME:/data" "$REG/ares-agent:1.0.0" >/dev/null || exit 1
start_updater 1.0.0
FIRST="$(id_of "$UPDATER")"

echo "==> Test 1: 1.0.0 -> 1.0.1 moves the agent, then the updater"
target 1.0.1
if wait_for 120 "agent and updater on 1.0.1" on_versions 1.0.1 1.0.1; then
    ok "agent on 1.0.1, updater on 1.0.1, no -next/-old left behind"
    [ "$(id_of "$UPDATER")" != "$FIRST" ] && ok "the updater is a new container (the 1.0.0 one removed itself)" ||
        bad "the updater container did not change"
    [ "$(docker inspect -f '{{.State.Running}}' "$UPDATER")" = true ] && ok "the new updater is running" ||
        bad "the new updater is not running"
else
    bad "agent=$(image_of "$AGENT") updater=$(image_of "$UPDATER") leftovers=$(leftovers | tr '\n' ' ')"
    updater_logs
fi

echo "==> Test 2: 1.0.1 -> 1.0.2, done by the updater the first handoff started"
SECOND="$(id_of "$UPDATER")"
target 1.0.2
if wait_for 120 "agent and updater on 1.0.2" on_versions 1.0.2 1.0.2; then
    ok "the successor moved the agent and handed itself over in turn"
    [ "$(id_of "$UPDATER")" != "$SECOND" ] && ok "a third updater container now holds the name" ||
        bad "the updater container did not change"
else
    bad "agent=$(image_of "$AGENT") updater=$(image_of "$UPDATER") leftovers=$(leftovers | tr '\n' ' ')"
    updater_logs
fi

echo "==> Test 3: a 9.9.9 updater that crashes never takes over"
THIRD="$(id_of "$UPDATER")"
target 9.9.9
if wait_for 120 "agent on 9.9.9" sh -c "[ \"\$(docker inspect -f '{{.Config.Image}}' $AGENT)\" = '$REG/ares-agent:9.9.9' ]"; then
    ok "the agent moved to 9.9.9"
else
    bad "agent=$(image_of "$AGENT")"
fi
if wait_for 60 "the failed handoff to be logged" sh -c "docker logs $UPDATER 2>&1 | grep -q 'did not stay up'"; then
    { [ "$(id_of "$UPDATER")" = "$THIRD" ] && [ "$(image_of "$UPDATER")" = "$REG/ares-updater:1.0.2" ]; } &&
        ok "the 1.0.2 updater still holds its name" || bad "updater=$(image_of "$UPDATER")"
    [ "$(docker inspect -f '{{.State.Running}}' "$UPDATER")" = true ] && ok "and is still running" ||
        bad "the 1.0.2 updater stopped"
    [ -z "$(leftovers)" ] && ok "the crashed successor was removed" ||
        bad "left behind: $(leftovers | tr '\n' ' ')"
else
    bad "the updater never reported the failed handoff"
    updater_logs
fi

echo "==> Test 4: ARES_UPDATE_SELF_UPDATE=false moves the agent only"
start_updater 1.0.2 -e ARES_UPDATE_SELF_UPDATE=false
target 1.0.1
if wait_for 120 "agent on 1.0.1" sh -c "[ \"\$(docker inspect -f '{{.Config.Image}}' $AGENT)\" = '$REG/ares-agent:1.0.1' ]"; then
    sleep 6  # several poll intervals: long enough for a handoff it should not start
    [ "$(image_of "$UPDATER")" = "$REG/ares-updater:1.0.2" ] && [ -z "$(leftovers)" ] &&
        ok "the agent moved to 1.0.1 and the updater stayed on 1.0.2" ||
        bad "updater=$(image_of "$UPDATER") leftovers=$(leftovers | tr '\n' ' ')"
else
    bad "agent=$(image_of "$AGENT")"
    updater_logs
fi

echo ""
echo "e2e_self_update: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
