#!/usr/bin/env bash
# =============================================================================
# Ares Docker Agent - Bootstrap Script
# =============================================================================
# Cross-platform: macOS, Linux, Windows (Git Bash / WSL)
#
# Usage:
#   bash scripts/bootstrap.sh
#   # or
#   bash <(curl -fsSL https://raw.githubusercontent.com/assailai/ares-agent/main/scripts/bootstrap.sh)
#
# =============================================================================

set -euo pipefail

IMAGE="assailai/ares-agent:latest"
CONTAINER_NAME="ares-agent"
PORT=8443
VOLUME_NAME="ares-agent-data"
HEALTH_TIMEOUT=90
HEALTH_INTERVAL=3

if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    BOLD='\033[1m'
    NC='\033[0m'
else
    RED='' GREEN='' YELLOW='' BLUE='' BOLD='' NC=''
fi

info()  { printf "${GREEN}[INFO]${NC}  %s\n" "$1"; }
warn()  { printf "${YELLOW}[WARN]${NC}  %s\n" "$1"; }
error() { printf "${RED}[ERROR]${NC} %s\n" "$1"; }
step()  { printf "\n${BLUE}${BOLD}==> %s${NC}\n" "$1"; }

detect_platform() {
    local os
    os="$(uname -s)"

    case "$os" in
        Darwin)
            PLATFORM="macos"
            OPEN_CMD="open"
            ;;
        Linux)
            if grep -qiE "microsoft|wsl" /proc/version 2>/dev/null; then
                PLATFORM="wsl"
                OPEN_CMD="wslview"
            else
                PLATFORM="linux"
                OPEN_CMD="${BROWSER:-$(command -v xdg-open || command -v sensible-browser || echo "")}"
            fi
            ;;
        MINGW*|MSYS*|CYGWIN*)
            PLATFORM="windows"
            OPEN_CMD="start"
            ;;
        *)
            PLATFORM="unknown"
            OPEN_CMD=""
            ;;
    esac

    info "Detected platform: $PLATFORM"
}

check_docker() {
    step "Checking Docker"

    if ! command -v docker >/dev/null 2>&1; then
        error "Docker is not installed."
        case "$PLATFORM" in
            macos)   error "Install Docker Desktop: https://docs.docker.com/desktop/install/mac-install/" ;;
            linux)   error "Install Docker Engine: https://docs.docker.com/engine/install/" ;;
            wsl)     error "Install Docker Desktop for Windows with WSL 2 backend: https://docs.docker.com/desktop/install/windows-install/" ;;
            windows) error "Install Docker Desktop: https://docs.docker.com/desktop/install/windows-install/" ;;
        esac
        exit 1
    fi

    if ! docker info >/dev/null 2>&1; then
        error "Docker daemon is not running."
        case "$PLATFORM" in
            macos|windows|wsl) error "Start Docker Desktop and try again." ;;
            linux)             error "Run: sudo systemctl start docker" ;;
        esac
        exit 1
    fi

    local docker_version
    docker_version="$(docker version --format '{{.Server.Version}}' 2>/dev/null || echo "unknown")"
    info "Docker version: $docker_version"
}

check_existing_container() {
    if ! docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
        return
    fi

    warn "Container '${CONTAINER_NAME}' already exists."

    local state
    state="$(docker inspect --format '{{.State.Status}}' "$CONTAINER_NAME" 2>/dev/null || echo "unknown")"
    info "Current state: $state"

    # When stdin is not a terminal (e.g. curl | bash), only remove the container
    # but preserve the data volume (WireGuard keys, TLS certs, database)
    if [ ! -t 0 ]; then
        warn "Non-interactive mode: removing existing container (data volume preserved)."
        docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
        return
    fi

    printf "\n"
    printf "  ${BOLD}[r]${NC} Remove and recreate (fresh install)\n"
    printf "  ${BOLD}[k]${NC} Keep existing and exit\n"
    printf "\n"
    printf "  Choice [r/k]: "
    read -r choice

    case "$choice" in
        r|R)
            info "Removing existing container and volume..."
            docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
            docker volume rm "$VOLUME_NAME" >/dev/null 2>&1 || true
            info "Removed."
            ;;
        *)
            info "Keeping existing container. Exiting."
            if [ "$state" = "running" ]; then
                printf "\n"
                info "To get the password: docker logs $CONTAINER_NAME 2>&1 | grep 'Initial Password'"
                info "Web interface: https://localhost:${PORT}"
            fi
            exit 0
            ;;
    esac
}

pull_image() {
    step "Pulling Ares Agent image"
    info "Image: $IMAGE"

    if ! docker pull --platform linux/amd64 "$IMAGE"; then
        error "Failed to pull image. Check your internet connection and try again."
        error "Alternative registry: ghcr.io/assailai/ares-agent:latest"
        exit 1
    fi

    info "Image pulled successfully."
}

start_container() {
    step "Starting Ares Agent"

    if ! docker run -d --name "$CONTAINER_NAME" \
        --platform linux/amd64 \
        --user root \
        --cap-add=NET_ADMIN \
        --device /dev/net/tun:/dev/net/tun \
        --sysctl net.ipv4.ip_forward=1 \
        -e ARES_RUN_AS_ROOT=true \
        -p "${PORT}:8443" \
        -v "${VOLUME_NAME}:/data" \
        --restart unless-stopped \
        "$IMAGE" >/dev/null; then

        error "Failed to start container."
        error "Check that port ${PORT} is not in use: lsof -i :${PORT}"
        exit 1
    fi

    info "Container started."
}

wait_for_healthy() {
    step "Waiting for agent to become healthy"

    local elapsed=0
    local status=""

    while [ "$elapsed" -lt "$HEALTH_TIMEOUT" ]; do
        status="$(docker inspect --format='{{.State.Health.Status}}' "$CONTAINER_NAME" 2>/dev/null || echo "starting")"

        case "$status" in
            healthy)
                printf "\n"
                info "Agent is healthy!"
                return 0
                ;;
            unhealthy)
                printf "\n"
                warn "Health check failed. Checking logs..."
                docker logs --tail 20 "$CONTAINER_NAME" 2>&1
                error "Agent failed to start properly. Check: docker logs $CONTAINER_NAME"
                exit 1
                ;;
        esac

        printf "  Waiting... %ds/%ds [%s]   \r" "$elapsed" "$HEALTH_TIMEOUT" "$status"
        sleep "$HEALTH_INTERVAL"
        elapsed=$((elapsed + HEALTH_INTERVAL))
    done

    printf "\n"
    warn "Health check timed out after ${HEALTH_TIMEOUT}s. The agent may still be starting."
    warn "Check status: docker logs $CONTAINER_NAME"
}

extract_password() {
    step "Retrieving initial password"

    INITIAL_PASSWORD=""
    local attempts=0

    sleep 2

    while [ "$attempts" -lt 5 ] && [ -z "$INITIAL_PASSWORD" ]; do
        INITIAL_PASSWORD="$(docker logs "$CONTAINER_NAME" 2>&1 \
            | sed -n 's/.*Initial Password:[[:space:]]*\([^[:space:]║]*\).*/\1/p' \
            | head -1 || true)"

        if [ -z "$INITIAL_PASSWORD" ]; then
            sleep 2
            attempts=$((attempts + 1))
        fi
    done

    if [ -z "$INITIAL_PASSWORD" ]; then
        warn "Could not extract password automatically."
        warn "Run: docker logs $CONTAINER_NAME"
    fi
}

CERT_TRUSTED=false

trust_certificate() {
    step "Trusting TLS certificate"

    local cert_file="/tmp/ares-agent-cert.pem"
    if ! docker cp "${CONTAINER_NAME}:/data/tls/server.crt" "$cert_file" 2>/dev/null; then
        warn "Could not extract certificate. You'll need to accept the browser warning manually."
        return
    fi

    case "$PLATFORM" in
        macos)
            info "Your system may prompt you to allow the certificate to be trusted."
            if security add-trusted-cert -r trustRoot \
                -k "$HOME/Library/Keychains/login.keychain-db" \
                "$cert_file" 2>/dev/null; then
                info "Certificate trusted in macOS login keychain. No browser warning!"
                CERT_TRUSTED=true
            else
                warn "Could not add certificate to keychain. Accept the browser warning manually."
            fi
            ;;
        linux|wsl)
            info "Trusting the certificate requires sudo. You may be prompted for your password."
            if command -v update-ca-certificates >/dev/null 2>&1; then
                if sudo cp "$cert_file" /usr/local/share/ca-certificates/ares-agent.crt 2>/dev/null \
                    && sudo update-ca-certificates 2>/dev/null; then
                    info "Certificate trusted system-wide."
                    CERT_TRUSTED=true
                else
                    warn "Could not add certificate (needs sudo). Accept the browser warning manually."
                fi
            else
                warn "update-ca-certificates not found. Accept the browser warning manually."
            fi
            ;;
        *)
            warn "Auto-trust not supported on $PLATFORM. Accept the browser warning manually."
            ;;
    esac

    rm -f "$cert_file"
}

open_browser() {
    local url="https://localhost:${PORT}"

    if [ -z "$OPEN_CMD" ]; then
        return
    fi

    info "Opening browser: $url"
    $OPEN_CMD "$url" 2>/dev/null || true
}

print_summary() {
    local url="https://localhost:${PORT}"

    printf "\n"
    info "Ares Agent is running!"
    printf "\n"
    info "Web Interface : $url"
    if [ -n "$INITIAL_PASSWORD" ]; then
        info "Password      : $INITIAL_PASSWORD"
    fi
    printf "\n"
    info "Next steps:"
    local n=1
    if [ "$CERT_TRUSTED" = "false" ]; then
        info "  $n. Accept the self-signed certificate warning in your browser"
        n=$((n + 1))
    fi
    info "  $n. Log in with the initial password"; n=$((n + 1))
    info "  $n. Change your password (required)"; n=$((n + 1))
    info "  $n. Complete the setup wizard"
    printf "\n"
    info "Useful commands:"
    info "  docker logs ares-agent        View logs"
    info "  docker restart ares-agent     Restart agent"
    info "  docker stop ares-agent        Stop agent"
}

main() {
    printf "\n${BOLD}Ares Docker Agent - Bootstrap${NC}\n"
    printf "================================\n\n"

    detect_platform
    check_docker
    check_existing_container
    pull_image
    start_container
    wait_for_healthy
    extract_password
    trust_certificate
    open_browser
    print_summary
}

main "$@"
