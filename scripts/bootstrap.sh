#!/usr/bin/env bash
# =============================================================================
# Ares Docker Agent - Bootstrap Script
# =============================================================================
# Zero-touch installer: picks the container runtime (Docker or Podman), starts the agent and its
# auto-update companion, and waits until the agent reports online. Cross-platform (macOS, Linux,
# Windows Git Bash / WSL). On rootless Podman it also enables linger + the user podman services so
# the agent survives the operator logging out. Set ARES_DISABLE_AUTOUPDATE to install the agent
# alone (no self-update).
#
# Usage:
#   ARES_TOKEN=<token> bash scripts/bootstrap.sh
#   bash scripts/bootstrap.sh <token>
#   bash <(curl -fsSL https://raw.githubusercontent.com/assailai/ares-agent/main/scripts/bootstrap.sh)
#
# Optional env (passed through to the container when set): ARES_URL,
# ARES_NETWORKS, ARES_AGENT_NAME, ARES_INSECURE, ARES_SCAN_SCOPE.
#
# Re-installing over an existing agent replaces the containers but keeps the data volume, which
# holds the agent's identity. Handed a registration token for a *different* agent, the agent
# re-enrolls under it by itself; set ARES_RESET=1 to discard the stored identity up front instead,
# for the case it cannot fix (the token is already spent).
# =============================================================================

set -euo pipefail

# Defaults to the current pinned release; override with ARES_VERSION=X.Y.Z or ARES_IMAGE=<full ref>.
IMAGE="${ARES_IMAGE:-assailai/ares-agent:${ARES_VERSION:-3.12.0}}"
# The companion updater keeps the agent on the release the dashboard marks current; it is the only
# component that touches the Docker socket (the agent stays unprivileged). Set ARES_DISABLE_AUTOUPDATE
# to opt out (change-control-sensitive hosts). Override the image with ARES_UPDATER_IMAGE=<full ref>.
UPDATER_IMAGE="${ARES_UPDATER_IMAGE:-assailai/ares-updater:${ARES_VERSION:-3.12.0}}"
CONTAINER_NAME="ares-agent"
UPDATER_CONTAINER_NAME="ares-updater"
VOLUME_NAME="ares-agent-data"
ONLINE_TIMEOUT=120
ONLINE_INTERVAL=3
# how long a freshly started updater must stay up before it counts as started (see start_updater).
UPDATER_SETTLE_SECONDS=5
# why the updater could not run, if it could not; reported after the summary.
AUTOUPDATE_FAILURE=""
# rootful Podman's API socket, socket-activated by the system podman.socket unit.
PODMAN_ROOTFUL_SOCK="/run/podman/podman.sock"

if [ -t 1 ]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'
else
    RED='' GREEN='' YELLOW='' BLUE='' BOLD='' NC=''
fi

info()  { printf "${GREEN}[INFO]${NC}  %s\n" "$1"; }
warn()  { printf "${YELLOW}[WARN]${NC}  %s\n" "$1"; }
error() { printf "${RED}[ERROR]${NC} %s\n" "$1"; }
step()  { printf "\n${BLUE}${BOLD}==> %s${NC}\n" "$1"; }

detect_platform() {
    case "$(uname -s)" in
        Darwin) PLATFORM="macos" ;;
        Linux)  grep -qiE "microsoft|wsl" /proc/version 2>/dev/null && PLATFORM="wsl" || PLATFORM="linux" ;;
        MINGW*|MSYS*|CYGWIN*) PLATFORM="windows" ;;
        *) PLATFORM="unknown" ;;
    esac
}

check_runtime() {
    step "Checking container runtime"
    # Prefer docker if present (on many hosts it is a wrapper around Podman), else fall back to podman.
    if command -v docker >/dev/null 2>&1; then
        RUNTIME="docker"
    elif command -v podman >/dev/null 2>&1; then
        RUNTIME="podman"
    else
        error "Neither Docker nor Podman is installed. Install Docker (https://docs.docker.com/get-docker/) or Podman (https://podman.io/docs/installation)."
        exit 1
    fi
    if ! "$RUNTIME" info >/dev/null 2>&1; then
        case "$PLATFORM" in
            linux) error "The container engine is not available. For Docker: sudo systemctl start docker. For rootless Podman: systemctl --user start podman.socket" ;;
            *)     error "The container engine is not running. Start Docker Desktop (or run 'podman machine start') and try again." ;;
        esac
        exit 1
    fi
    # detect whether `docker` is really Podman: rootless Podman needs extra setup to survive logout
    # (see setup_persistence), and its engine socket lives at a different path than Docker's.
    IS_PODMAN=false
    if "$RUNTIME" --version 2>/dev/null | grep -qi podman; then
        IS_PODMAN=true
    fi
    ENGINE_SOCK="/var/run/docker.sock"
    info "Using $("$RUNTIME" --version 2>/dev/null || echo "$RUNTIME")."
}

setup_persistence() {
    # Rootless Podman has no daemon, so a --restart policy is not enough on its own: without linger
    # the container is killed when the operator's login session ends, and the user podman-restart /
    # podman.socket services are what bring it back after a reboot and expose the engine socket to
    # the updater. Docker persists via its daemon; rootful Podman is setup_rootful_podman's.
    { [ "$IS_PODMAN" = true ] && [ "$(id -u)" -ne 0 ]; } || return 0
    step "Enabling rootless Podman persistence"
    if sudo loginctl enable-linger "$(id -un)"; then
        info "Enabled linger so the agent keeps running after you log out."
    else
        warn "Could not enable linger (needs sudo); the agent may stop when you log out."
    fi
    systemctl --user enable --now podman.socket podman-restart.service 2>/dev/null || true
    ENGINE_SOCK="${XDG_RUNTIME_DIR}/podman/podman.sock"
}

setup_rootful_podman() {
    # Rootful Podman is not Docker with another name: it has no daemon and no Docker socket, and
    # both used to be assumed here (ARES-1725).
    { [ "$IS_PODMAN" = true ] && [ "$(id -u)" -eq 0 ]; } || return 0
    step "Setting up rootful Podman"
    # With no daemon, --restart=always does not survive a reboot on its own; podman-restart starts
    # those containers at boot. Without it the agent goes offline at the host's first restart.
    if systemctl enable podman-restart.service >/dev/null 2>&1; then
        info "Enabled podman-restart.service so the agent comes back after a reboot."
    else
        warn "Could not enable podman-restart.service; the agent will not restart after a reboot."
    fi
    [ -z "${ARES_DISABLE_AUTOUPDATE:-}" ] || return 0
    # /var/run/docker.sock exists only when podman-docker is installed AND the system podman.socket
    # is active, and a stock RHEL host has neither, so the updater used to be handed a path that
    # was not there: Podman refused the mount ("statfs /var/run/docker.sock: no such file or
    # directory"), the agent came up without its updater, and it never moved off the version it
    # was installed at. Podman's own API socket is activated by podman.socket, at every boot too.
    ENGINE_SOCK="$PODMAN_ROOTFUL_SOCK"
    [ -S "$ENGINE_SOCK" ] && return 0
    if systemctl enable --now podman.socket >/dev/null 2>&1 && [ -S "$ENGINE_SOCK" ]; then
        info "Enabled podman.socket ($ENGINE_SOCK) for the auto-update companion."
    else
        warn "Could not enable podman.socket; the auto-update companion needs it."
    fi
}

resolve_token() {
    # Precedence: positional argument, then ARES_TOKEN env, then interactive prompt.
    TOKEN="${1:-${ARES_TOKEN:-}}"
    if [ -z "$TOKEN" ] && [ -t 0 ]; then
        printf "Paste your registration token (from the dashboard, Settings -> Agents): "
        read -r TOKEN
    fi
    if [ -z "$TOKEN" ]; then
        error "No registration token provided. Pass it as ARES_TOKEN=... or as the first argument."
        exit 1
    fi
}

replace_existing() {
    local name="$1"
    "$RUNTIME" ps -a --format '{{.Names}}' | grep -q "^${name}$" || return 0
    warn "A container named '${name}' already exists; replacing it (the data volume is kept)."
    "$RUNTIME" rm -f "$name" >/dev/null 2>&1 || true
}

reset_state() {
    # Opt-in hard reset: throw away the agent's stored identity so the next start enrolls from
    # scratch. Deliberately not the default. Keeping the volume across a re-install is what lets
    # an agent survive being recreated, and the agent now re-enrolls on its own when it is handed
    # a registration token it was not minted from. This is the escape hatch for the one case it
    # cannot fix by itself: the supplied token is already spent, and the operator wants this host
    # to become a new agent regardless.
    [ -n "${ARES_RESET:-}" ] || return 0
    step "Discarding the stored agent identity (ARES_RESET)"
    # Both containers first: the updater mounts the same volume read-only, and the engine refuses
    # to remove a volume any container still references, however stopped it is.
    "$RUNTIME" rm -f "$CONTAINER_NAME" "$UPDATER_CONTAINER_NAME" >/dev/null 2>&1 || true
    if ! "$RUNTIME" volume inspect "$VOLUME_NAME" >/dev/null 2>&1; then
        info "There was no '${VOLUME_NAME}' volume; this host enrolls from scratch anyway."
        return 0
    fi
    # Fail loudly rather than carry on: continuing here would start the agent on the very
    # identity the operator just asked to be rid of, which is the failure this flag exists for.
    if ! "$RUNTIME" volume rm "$VOLUME_NAME" >/dev/null 2>&1; then
        error "Could not remove the data volume '${VOLUME_NAME}'; something else still uses it."
        error "Find it with: $RUNTIME ps -a --filter volume=${VOLUME_NAME}"
        exit 1
    fi
    warn "Discarded '${VOLUME_NAME}'. The agent enrolls as a new agent and loses its old identity."
}

# Echo this host's CA directory, or nothing when there is none to hand over.
#
# A network that inspects TLS terminates every outbound connection and re-signs it with its own
# root, which a container has no reason to trust. The host does, though: the customer's IT had to
# make it trusted there or nothing on the machine could browse. So we hand the container the
# host's own store and the whole problem disappears with nothing for the operator to configure.
#
# Echo the *directory* the bundle resolves to, not the file: `update-ca-certificates` rewrites the
# bundle to a fresh inode, which a file mount would not follow. `readlink -f` is what covers the
# distros, landing on /etc/ssl/certs (Debian, Ubuntu, Alpine, SUSE) or
# /etc/pki/ca-trust/extracted/pem (RHEL, Fedora, Amazon Linux).
#
# Linux only. On Docker Desktop the container runs in a VM whose /etc/ssl has nothing to do with
# the Mac or Windows trust store, and mounting a system path there needs file-sharing permission
# we should not demand of a dev machine. Keep this list identical to the one the dashboard's
# install command uses (apps/web/src/lib/agent-install.ts in ares-v2), so the two install paths
# cannot diagnose the same host differently.
host_ca_dir() {
    [ "$PLATFORM" = "linux" ] || return 0
    local bundle resolved
    for bundle in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt; do
        [ -r "$bundle" ] || continue
        resolved="$(readlink -f "$bundle" 2>/dev/null)" || continue
        [ -n "$resolved" ] || continue
        dirname "$resolved"
        return 0
    done
}

start_container() {
    step "Starting the agent"
    replace_existing "$CONTAINER_NAME"

    local run_args=(-d --name "$CONTAINER_NAME" -e "ARES_TOKEN=$TOKEN")

    # On native Linux run on the host network so the agent sees the real interfaces and auto-scopes
    # the LAN with no extra config. Docker Desktop (macOS/Windows/WSL) runs Linux containers in a VM
    # where host networking would bind to that VM, not the machine, so we stay on bridge there: the
    # agent still enrolls and comes online (the LAN is scanned from a Linux host).
    if [ "$PLATFORM" = "linux" ]; then
        run_args+=(--network host)
    fi

    local var
    for var in ARES_URL ARES_NETWORKS ARES_AGENT_NAME ARES_INSECURE ARES_SCAN_SCOPE ARES_CA_BUNDLE \
               ARES_HOST_ALIASES; do
        [ -n "${!var:-}" ] && run_args+=(-e "$var=${!var}")
    done
    # Trust whatever this host trusts, so a TLS-inspecting network needs no configuration.
    local ca_dir
    ca_dir="$(host_ca_dir)"
    if [ -n "$ca_dir" ]; then
        run_args+=(-v "$ca_dir:/host-ca:ro")
    fi
    # Resolve whatever this host resolves, for the same reason we trust what it trusts. A container
    # gets docker's own /etc/hosts even under --network host (host networking shares the network
    # namespace, not the mount namespace), so a name someone pinned on the machine is invisible to
    # the agent -- and "I added it to /etc/hosts and nothing changed" is a genuinely hard afternoon
    # to debug. Mounted read-only and re-read on change, so a later edit needs no recreate.
    #
    # Linux only, exactly like host_ca_dir: on Docker Desktop the container runs in a VM whose
    # /etc/hosts is not the Mac's or Windows', and bind-mounting a host system path there needs
    # file-sharing permission we should not demand of a dev machine (it would fail the run).
    if [ "$PLATFORM" = "linux" ] && [ -r /etc/hosts ]; then
        run_args+=(-v "/etc/hosts:/host-hosts:ro")
    fi
    # Extra resolvers, for a host whose own resolver cannot answer an internal name.
    if [ -n "${ARES_DNS:-}" ]; then
        local dns
        for dns in ${ARES_DNS//,/ }; do
            run_args+=(--dns "$dns")
        done
    fi
    # --restart=always pairs with the persistence set up in setup_persistence (linger on rootless
    # Podman; the system daemon on Docker), so the agent comes back after logout and reboot.
    run_args+=(-v "${VOLUME_NAME}:/data" --restart=always)

    if ! "$RUNTIME" run "${run_args[@]}" "$IMAGE" >/dev/null; then
        error "Failed to start the container. Try: $RUNTIME pull $IMAGE"
        exit 1
    fi
    info "Container started."
}

start_updater() {
    if [ -n "${ARES_DISABLE_AUTOUPDATE:-}" ]; then
        info "Auto-update disabled (ARES_DISABLE_AUTOUPDATE set); the agent will not self-update."
        return 0
    fi
    step "Starting the auto-update companion"
    replace_existing "$UPDATER_CONTAINER_NAME"
    # Only the updater touches the engine socket; it recreates the agent on a new, cosign-verified
    # image when the dashboard marks a release current (the signer identity is baked into the image).
    # ENGINE_SOCK is the Docker socket, or the Podman one (rootless: setup_persistence, rootful:
    # setup_rootful_podman).
    # The updater needs the host CAs too: cosign has to reach the registry and the Sigstore log
    # through the same inspecting proxy, and it fails closed when it cannot verify a signature.
    local updater_args=(-d --name "$UPDATER_CONTAINER_NAME")
    updater_args+=(-e "ARES_UPDATE_CONTAINER=$CONTAINER_NAME")
    updater_args+=(-v "${VOLUME_NAME}:/data:ro")
    updater_args+=(-v "${ENGINE_SOCK}:/var/run/docker.sock")
    # Under SELinux (enforcing by default on RHEL and Fedora) a container may not connect to the
    # engine socket, so the updater would start and then fail every check with "Permission
    # denied". Lifting the label confines nothing that matters here: whoever holds the engine
    # socket already holds the host. Docker and Podman both accept it where SELinux is off.
    updater_args+=(--security-opt label=disable)
    local ca_dir
    ca_dir="$(host_ca_dir)"
    if [ -n "$ca_dir" ]; then
        updater_args+=(-v "$ca_dir:/host-ca:ro")
    fi
    updater_args+=(--restart=always)

    # The agent runs either way, so this does not stop the install, but it is reported as a failure
    # in the summary and the exit status. It used to be one warning in the middle of the output,
    # followed by "Done", and a missing updater is invisible from the dashboard until the next
    # release, where it only reads as an agent that never arrived.
    local out
    if ! out="$("$RUNTIME" run "${updater_args[@]}" "$UPDATER_IMAGE" 2>&1)"; then
        AUTOUPDATE_FAILURE="$(printf '%s' "$out" | tail -n 1)"
        return 0
    fi
    # Started is not the same as working: an updater that cannot use the socket exits and is
    # restarted in a loop. Give it a moment and check it is still up.
    sleep "$UPDATER_SETTLE_SECONDS"
    if [ "$("$RUNTIME" inspect -f '{{.State.Running}} {{.RestartCount}}' "$UPDATER_CONTAINER_NAME" 2>/dev/null)" != "true 0" ]; then
        AUTOUPDATE_FAILURE="$("$RUNTIME" logs --tail 1 "$UPDATER_CONTAINER_NAME" 2>&1 || true)"
        return 0
    fi
    info "Auto-update companion started."
}

report_autoupdate_failure() {
    [ -n "$AUTOUPDATE_FAILURE" ] || return 0
    printf "\n"
    error "Auto-update is NOT working on this host: the ares-updater companion could not run."
    error "  $AUTOUPDATE_FAILURE"
    error "The agent itself is running, but it will stay on this version until this is fixed."
    if [ "$IS_PODMAN" = true ] && [ "$(id -u)" -eq 0 ]; then
        error "Enable Podman's API socket with 'systemctl enable --now podman.socket', then re-run this installer."
    elif [ "$IS_PODMAN" = true ]; then
        error "Enable Podman's API socket with 'systemctl --user enable --now podman.socket', then re-run this installer."
    else
        error "Check that $ENGINE_SOCK exists and the engine is running, then re-run this installer."
    fi
    error "Re-running keeps this agent's identity. To install without auto-update, set ARES_DISABLE_AUTOUPDATE=1."
    exit 1
}

wait_until_online() {
    step "Waiting for the agent to come online"
    local elapsed=0 logs
    while [ "$elapsed" -lt "$ONLINE_TIMEOUT" ]; do
        if [ "$("$RUNTIME" inspect -f '{{.State.Status}}' "$CONTAINER_NAME" 2>/dev/null)" = "exited" ]; then
            error "The agent exited unexpectedly. Recent logs:"
            "$RUNTIME" logs --tail 20 "$CONTAINER_NAME" 2>&1
            exit 1
        fi
        logs="$("$RUNTIME" logs "$CONTAINER_NAME" 2>&1 || true)"
        case "$logs" in
            # Checked ahead of "Agent online", which is also in the log by now: the agent IS
            # online, just as the agent it already was. Reporting that as a success is exactly how
            # a re-install used to look like it had worked while the new agent sat at "Offline".
            *"Keeping the existing agent identity"*)
                printf "\n"
                error "This host stayed enrolled as the agent it already was: the token you supplied is already spent, so it could not enrol as a new one."
                error "Generate a fresh token in the dashboard (Settings -> Agents), or re-run this installer with ARES_RESET=1 to discard the stored identity first."
                warn  "Nothing was taken down - the existing agent is still running and healthy."
                exit 1 ;;
            *"Agent online"*)
                printf "\n"
                case "$logs" in
                    *"Re-enrolled as a new agent"*)
                        info "This host was already enrolled; it has re-enrolled as the new agent, and the previous one goes offline." ;;
                esac
                case "$logs" in
                    *"differs from ARES_AGENT_NAME"*)
                        warn "Ares knows this agent by a different name than ARES_AGENT_NAME asked for. If you meant to install a new agent here, see: $RUNTIME logs $CONTAINER_NAME" ;;
                esac
                info "The agent is online."; return 0 ;;
            *"Registration token rejected"*)
                printf "\n"; error "The registration token was rejected (expired or already used). Generate a fresh one in the dashboard."; exit 1 ;;
            *"Refusing to start"*)
                printf "\n"; error "The agent refused to start. Recent logs:"; "$RUNTIME" logs --tail 20 "$CONTAINER_NAME" 2>&1; exit 1 ;;
        esac
        printf "  waiting... %ds/%ds   \r" "$elapsed" "$ONLINE_TIMEOUT"
        sleep "$ONLINE_INTERVAL"
        elapsed=$((elapsed + ONLINE_INTERVAL))
    done
    printf "\n"
    warn "The agent did not report online within ${ONLINE_TIMEOUT}s. It may still be retrying."
    warn "Follow its progress with: docker logs -f $CONTAINER_NAME"
}

print_summary() {
    printf "\n"
    info "Done. The agent now appears in your Ares dashboard under Settings -> Agents."
    printf "\n"
    info "Useful commands:"
    info "  $RUNTIME logs -f ares-agent     follow the agent's logs"
    info "  $RUNTIME restart ares-agent     restart the agent"
    info "  $RUNTIME rm -f ares-agent       stop and remove it (the data volume is kept)"
    if [ -z "${ARES_DISABLE_AUTOUPDATE:-}" ]; then
        info "  $RUNTIME logs -f ares-updater   follow the auto-update companion"
    fi
    printf "\n"
    info "Re-running this installer keeps the agent's identity. To make this host a *new* agent,"
    info "re-run it with a fresh token, or with ARES_RESET=1 to discard the stored identity."
}

main() {
    printf "\n${BOLD}Ares Docker Agent - Bootstrap${NC}\n================================\n"
    detect_platform
    check_runtime
    resolve_token "$@"
    setup_persistence
    setup_rootful_podman
    reset_state
    start_container
    start_updater
    wait_until_online
    print_summary
    report_autoupdate_failure
}

main "$@"
