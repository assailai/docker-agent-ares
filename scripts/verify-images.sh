#!/usr/bin/env bash
# =============================================================================
# Ares Docker Agent - verify the published images before you start them
# =============================================================================
# The project's defence against a repointed registry tag is cosign verification plus digest
# pinning: the updater applies the digest cosign verified, never the tag it was asked about. That
# defence only exists once an updater is already running, so the FIRST image has to establish it.
# scripts/bootstrap.sh does (it verifies both images and runs the verified digest). The compose and
# Kubernetes paths did not: they named docker.io/assailai/ares-updater:<version> by tag, and handed
# that container the Docker socket (compose) or a ServiceAccount that can patch its own Deployment
# (Kubernetes), with nothing checking a signature or a digest. Anyone who could write to the Docker
# Hub repositories - the CI's long-lived token, say - could repoint the release tag, and every new
# install, reinstall or fresh node pull would run the substituted updater, which then decides all
# later verification. ARES_UPDATE_REQUIRE_SIGNATURE governs later updates, not the first image.
# ARES-2351.
#
# This script closes that for both paths. It pulls each image, resolves the digest the engine
# actually got, checks the Ares publisher signed exactly those bytes, and then pins it:
#
#   bash scripts/verify-images.sh                     # writes .env for docker-compose.yml
#   bash scripts/verify-images.sh ares-agent.yaml     # rewrites a k8s manifest to the digests
#
# With no argument it verifies this release's two images and writes ARES_AGENT_IMAGE and
# ARES_UPDATER_IMAGE into ./.env, which is where docker-compose.yml reads them from - and that file
# names no image of its own, so `docker compose up` stops here rather than pulling something
# unverified. With a file it verifies every Ares image the file names and rewrites each to
# <ref>@sha256:..., leaving the file untouched if anything fails. Running it twice is a no-op.
#
# Fail-closed, with no proceed-anyway flag: a host that cannot reach ghcr.io (for cosign), Fulcio
# or Rekor fails here rather than starting a container it could not check. Point ARES_COSIGN_IMAGE
# at an internal mirror if that is your situation.
#
# Everything from `detect_platform` down to `verify_image` is a verbatim copy of scripts/
# bootstrap.sh, including the COSIGN_* constants. bootstrap.sh is fetched standalone through
# `bash <(curl ...)` and so can source nothing, and neither can this; the copy is pinned by
# tests/test_bootstrap.py, which fails if the two drift.
# =============================================================================

set -euo pipefail

# Defaults to the current pinned release; override with ARES_VERSION=X.Y.Z or ARES_IMAGE=<full ref>.
IMAGE="${ARES_IMAGE:-docker.io/assailai/ares-agent:${ARES_VERSION:-3.15.1}}"
UPDATER_IMAGE="${ARES_UPDATER_IMAGE:-docker.io/assailai/ares-updater:${ARES_VERSION:-3.15.1}}"
# cosign, to check both images before either one runs. By DIGEST, and from Sigstore rather than
# from our own updater image: a substituted ares-updater must not be the thing that vouches for
# itself. v3.1.4, the version Dockerfile.updater builds from source; the same digest is served from
# gcr.io/projectsigstore/cosign. ARES_COSIGN_IMAGE points this at an internal mirror - it changes
# WHICH cosign runs, never WHETHER one does.
COSIGN_IMAGE="${ARES_COSIGN_IMAGE:-ghcr.io/sigstore/cosign/cosign@sha256:0f06154836d2de34f887a5c273506d52ca43edaa1d9e53e6510fa78a48f69c2d}"
# Must stay identical to UpdaterSettings.cosign_identity / cosign_issuer; tests/test_bootstrap.py
# fails if they drift. refs/heads/main only: a tag ref is not protected (ARES-2327).
COSIGN_IDENTITY='^https://github\.com/assailai/docker-agent-ares/\.github/workflows/docker-build\.yml@refs/heads/main$'
COSIGN_ISSUER="https://token.actions.githubusercontent.com"
# Every Ares image reference this script will touch in a file, tag or digest form alike.
ARES_IMAGE_PATTERN='docker\.io/assailai/ares-(agent|updater):[A-Za-z0-9_][A-Za-z0-9._-]*(@sha256:[0-9a-f]{64})?'

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

# IS_PODMAN and ENGINE_SOCK are set but unused here: this is bootstrap.sh's function verbatim, and
# the two must pick the same runtime and fail on the same host for the same reason. The directive
# sits outside the body so the copy stays byte-identical to the one the parity test compares.
# shellcheck disable=SC2034
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

# The repository half of an image reference, i.e. everything but the :tag or @digest. A tag only
# counts as one when what follows the last colon has no slash in it, or a registry:port would eat
# the hostname. Both can be present at once - "repo:tag@sha256:..." is legal, and is what
# verify-images.sh writes into a Kubernetes manifest - so take the digest off first and the tag
# second. Stopping at the digest, as this did until ARES-2351, left the tag glued to the
# repository and verify_image then looked for a RepoDigest that can never exist.
repo_of() {
    local ref="${1%%@*}"
    case "$ref" in
        *:*) ;;
        *)   printf '%s' "$ref"; return ;;
    esac
    # a trailing :tag has no slash in it; "localhost:5000/foo/bar" does, and is all repository.
    case "${ref##*:}" in
        */*) printf '%s' "$ref" ;;
        *)   printf '%s' "${ref%:*}" ;;
    esac
}

# cosign has to reach the registry, Fulcio and Rekor, and on a TLS-inspecting network that means
# the host's CAs. Go reads SSL_CERT_FILE and SSL_CERT_DIR; naming the file alone would REPLACE the
# image's public roots and break the Sigstore endpoints, so always keep /etc/ssl/certs alongside.
# Only the TLS extract on a RHEL layout, matching what the agent and updater load (ARES-2327).
cosign_ca_args() {
    local ca_dir="$1"
    [ -n "$ca_dir" ] || return 0
    printf '%s\n' "-v" "$ca_dir:/host-ca:ro"
    if [ -r "$ca_dir/tls-ca-bundle.pem" ]; then
        printf '%s\n' "-e" "SSL_CERT_FILE=/host-ca/tls-ca-bundle.pem" "-e" "SSL_CERT_DIR=/etc/ssl/certs"
    else
        printf '%s\n' "-e" "SSL_CERT_DIR=/host-ca:/etc/ssl/certs"
    fi
}

# Pull an image, check the publisher signed the exact bytes we got, and print the digest reference
# to run instead of the tag. Returns non-zero when anything about that fails.
#
# Why this exists: the installer used to hand the updater the engine socket on the strength of a
# mutable registry tag. Whoever could write to the Docker Hub repositories - the CI's long-lived
# token, say - could repoint it and be root on the next host that installs or reinstalls, and the
# substituted updater then decides every later verification. It cannot forge a cosign signature,
# so this is the check it could not pass.
verify_image() {
    local ref="$1" repo digest ca_dir
    repo="$(repo_of "$ref")"
    if ! "$RUNTIME" pull "$ref" >/dev/null 2>&1; then
        error "Could not pull $ref"
        return 1
    fi
    # The digest the engine actually has, so the signature is checked against the bytes that will
    # run rather than against whatever the tag points at by the time we ask again. Docker strips
    # docker.io/ from RepoDigests while Podman keeps it, so match on the repository path and
    # rebuild the reference from $repo: the fully qualified form is what Podman's short-name
    # policy needs (ARES-1725).
    local short="${repo#docker.io/}" sha
    sha="$("$RUNTIME" image inspect "$ref" --format '{{range .RepoDigests}}{{println .}}{{end}}' 2>/dev/null \
        | grep -E "^(${repo}|${short})@sha256:" | head -1)"
    sha="${sha##*@}"
    if [ -z "$sha" ]; then
        error "Could not resolve a digest for $ref"
        return 1
    fi
    digest="${repo}@${sha}"
    ca_dir="$(host_ca_dir)"
    local cosign_args=(run --rm)
    if [ -n "$ca_dir" ]; then
        local arg
        while IFS= read -r arg; do cosign_args+=("$arg"); done < <(cosign_ca_args "$ca_dir")
    fi
    cosign_args+=("$COSIGN_IMAGE" verify "$digest"
        --certificate-identity-regexp "$COSIGN_IDENTITY"
        --certificate-oidc-issuer "$COSIGN_ISSUER")
    if ! "$RUNTIME" "${cosign_args[@]}" >/dev/null 2>&1; then
        return 1
    fi
    printf '%s' "$digest"
}

# ---- everything below is this script's own -----------------------------------------------------

# The same diagnostic the installer prints, because the causes are the same ones. $2 is whatever
# verify_image managed to say before giving up: its own `error` lines go to stdout, which the
# command substitution that calls it captures, so without this they would be lost.
cannot_verify() {
    local ref="$1" said="${2:-}"
    [ -z "$said" ] || printf '%s\n' "$said"
    error "Could not verify $ref against the Ares publisher."
    error "Nothing has been pinned. This means one of:"
    error "  * the image is not the one Assail published (report it: security@assailai.com)"
    error "  * this host cannot reach the registry, Fulcio or Rekor (a proxy, or air-gapped)"
    error "  * cosign could not be pulled: $COSIGN_IMAGE"
    error "Reproduce it with: $RUNTIME run --rm $COSIGN_IMAGE verify $ref \\"
    error "  --certificate-identity-regexp '$COSIGN_IDENTITY' \\"
    error "  --certificate-oidc-issuer $COSIGN_ISSUER"
    error "Mirroring cosign internally? Point ARES_COSIGN_IMAGE at it (by digest)."
    exit 1
}

# Replace the ARES_* image lines in .env and leave every other line alone - an operator's
# ARES_TOKEN lives in that same file. Written to a temporary file and moved into place, so an
# interrupted run cannot leave a half-written .env that compose would read.
write_env() {
    local env_file="$1" agent="$2" updater="$3" tmp
    tmp="$(mktemp "${env_file}.XXXXXX")"
    if [ -f "$env_file" ]; then
        grep -vE '^[[:space:]]*(ARES_AGENT_IMAGE|ARES_UPDATER_IMAGE)=' "$env_file" > "$tmp" || true
    fi
    {
        printf '# Written by scripts/verify-images.sh - the digests cosign verified for this\n'
        printf '# release. Re-run that script after a version bump; do not edit these by hand.\n'
        printf 'ARES_AGENT_IMAGE=%s\n' "$agent"
        printf 'ARES_UPDATER_IMAGE=%s\n' "$updater"
    } >> "$tmp"
    mv "$tmp" "$env_file"
}

# docker-compose.yml names no image of its own, so this is what lets it start at all.
pin_compose_env() {
    step "Verifying the published images"
    local agent updater
    agent="$(verify_image "$IMAGE")" || cannot_verify "$IMAGE" "$agent"
    info "Verified $IMAGE"
    updater="$(verify_image "$UPDATER_IMAGE")" || cannot_verify "$UPDATER_IMAGE" "$updater"
    info "Verified $UPDATER_IMAGE"

    write_env ".env" "$agent" "$updater"
    step "Pinned in .env"
    info "ARES_AGENT_IMAGE=$agent"
    info "ARES_UPDATER_IMAGE=$updater"
    printf '\nNow start it with your registration token:\n\n'
    printf '    ARES_TOKEN=<your-registration-token> docker compose up -d\n\n'
}

# kubectl has no variable substitution, so a manifest is pinned by rewriting it.
pin_manifest() {
    local file="$1"
    [ -r "$file" ] || { error "Cannot read $file"; exit 1; }
    step "Verifying the images $file names"

    local refs
    refs="$(grep -oE "$ARES_IMAGE_PATTERN" "$file" | sort -u)"
    if [ -z "$refs" ]; then
        error "$file names no docker.io/assailai/ares-agent or ares-updater image."
        error "Point this at the manifest you are about to apply, or run it with no argument"
        error "to pin docker-compose.yml's .env instead."
        exit 1
    fi

    # Rewrite a copy and move it over the original only once every image has verified, so a
    # failure half way through cannot leave a manifest that is pinned in part.
    local tmp
    tmp="$(mktemp "${file}.XXXXXX")"
    trap 'rm -f "$tmp"' EXIT
    cat "$file" > "$tmp"
    local ref verified
    while IFS= read -r ref; do
        [ -n "$ref" ] || continue
        # Verify the reference AS WRITTEN: if it already carries a digest, that digest is what
        # kubelet will pull, so that is what has to be signed - not whatever the tag says today.
        verified="$(verify_image "$ref")" || cannot_verify "$ref" "$verified"
        # verify_image answers in canonical repo@sha256:... form, so compare the DIGEST rather
        # than the whole reference: "repo:tag@sha256:x" and "repo@sha256:x" are the same bytes.
        if [ "${ref##*@}" = "${verified##*@}" ]; then
            info "Verified $ref (already pinned)"
            continue
        fi
        # repo:tag@sha256:... - kubelet pulls the digest, and the tag stays readable for a human.
        local pinned="${ref%@*}@${verified##*@}"
        LC_ALL=C sed -i.pinned "s|${ref}|${pinned}|g" "$tmp" && rm -f "${tmp}.pinned"
        info "Verified $ref"
        info "  pinned to ${pinned##*@}"
    done <<< "$refs"

    cat "$tmp" > "$file"
    rm -f "$tmp"
    trap - EXIT
    step "Pinned $file"
    printf '\nApply it:\n\n    kubectl apply -f %s\n\n' "$file"
}

main() {
    if [ "$#" -gt 1 ]; then
        error "Usage: $0 [manifest.yaml]"
        exit 1
    fi
    detect_platform
    check_runtime
    if [ "$#" -eq 1 ]; then
        pin_manifest "$1"
    else
        pin_compose_env
    fi
}

main "$@"
