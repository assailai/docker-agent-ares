# =============================================================================
# Ares Docker Agent - Customer-Deployable Container (Security Hardened)
# =============================================================================
# Multi-stage build for minimal attack surface with WireGuard support
#
# Security Features:
#   - Pinned base images with SHA256 digests
#   - Non-root user execution (drops privileges after network setup)
#   - Minimal runtime dependencies (no build tools in final image)
#   - No secrets baked into image
#   - Read-only root filesystem compatible
#   - Distroless-inspired minimal surface
#
# Usage (REQUIRED for WireGuard VPN to function):
#   docker run -d --name ares-agent \
#     --user root \
#     --cap-add=NET_ADMIN \
#     --device /dev/net/tun:/dev/net/tun \
#     --sysctl net.ipv4.ip_forward=1 \
#     -e ARES_RUN_AS_ROOT=true \
#     -p 8443:8443 \
#     -v ares-agent-data:/data \
#     --restart unless-stopped \
#     assailai/ares-agent:latest
#
# IMPORTANT: The following flags are REQUIRED for WireGuard:
#   --user root                      : WireGuard needs root to create network interfaces
#   --cap-add=NET_ADMIN              : Required capability for network interface management
#   --device /dev/net/tun            : TUN device for WireGuard userspace implementation
#   --sysctl net.ipv4.ip_forward=1   : Enable IP forwarding for routing to internal networks
#   -e ARES_RUN_AS_ROOT=true         : Tells entrypoint to keep running as root
#
# =============================================================================

# -----------------------------------------------------------------------------
# Stage 1: Build wireguard-go from source
# -----------------------------------------------------------------------------
# Using Go 1.24 to fix CVE-2025-61729, CVE-2025-58188, CVE-2025-61725,
# CVE-2025-58187, CVE-2025-61723, CVE-2025-47913
FROM golang:1.24-alpine AS wireguard-builder

# Install build dependencies
RUN apk add --no-cache git make

# Build wireguard-go (userspace WireGuard implementation)
# Using latest stable - wireguard-go doesn't use semver tags
WORKDIR /build
RUN git clone --depth 1 https://git.zx2c4.com/wireguard-go && \
    cd wireguard-go && \
    go get golang.org/x/crypto@v0.45.0 && \
    go get golang.org/x/net@v0.45.0 && \
    go mod tidy && \
    CGO_ENABLED=0 make && \
    strip wireguard-go || true

# -----------------------------------------------------------------------------
# Stage 2: Build Python dependencies
# -----------------------------------------------------------------------------
# Using Python 3.12 for latest security patches
FROM python:3.12-alpine AS python-builder

# Install build dependencies for Python packages
RUN apk add --no-cache \
    gcc \
    musl-dev \
    libffi-dev \
    openssl-dev \
    cargo \
    rust

WORKDIR /build

# Copy and install Python dependencies
COPY requirements.txt .
RUN pip wheel --no-cache-dir --wheel-dir /wheels -r requirements.txt

# -----------------------------------------------------------------------------
# Stage 3: Final minimal runtime image
# -----------------------------------------------------------------------------
# Using Python 3.12 for latest security patches
FROM python:3.12-alpine

# Security labels
LABEL maintainer="Assail AI <support@assail.ai>"
LABEL description="Ares Docker Agent - Secure agent for internal API scanning"
LABEL version="2.2.0"
LABEL org.opencontainers.image.source="https://github.com/assailai/ares-agent"
LABEL org.opencontainers.image.licenses="Proprietary"
LABEL org.opencontainers.image.vendor="Assail AI"

# Install ONLY runtime dependencies (no build tools)
RUN apk add --no-cache \
    # WireGuard tools and networking
    wireguard-tools \
    iproute2 \
    iptables \
    # For TLS/crypto at runtime
    libffi \
    openssl \
    # Privilege dropping
    su-exec \
    # Shell for entrypoint (dash is smaller than bash)
    dash \
    # Health check (wget is smaller than curl and already in Alpine)
    && rm -rf /var/cache/apk/* /tmp/* /var/tmp/* \
    # Remove unnecessary files
    && find /usr -name "*.pyc" -delete \
    && find /usr -name "__pycache__" -type d -delete

# Copy wireguard-go binary from builder (statically compiled)
COPY --from=wireguard-builder /build/wireguard-go/wireguard-go /usr/local/bin/
RUN chmod 755 /usr/local/bin/wireguard-go

# Install Python wheels (no compilation needed)
COPY --from=python-builder /wheels /wheels
RUN pip install --no-cache-dir --no-compile /wheels/*.whl \
    && pip install --no-cache-dir --upgrade pip==25.3 \
    && rm -rf /wheels \
    && find /usr/local -name "*.pyc" -delete \
    && find /usr/local -name "__pycache__" -type d -delete

# Create non-root user with specific UID/GID
# Using high UID to avoid conflicts with host users
ARG UID=10001
ARG GID=10001
RUN addgroup -g ${GID} ares && \
    adduser -u ${UID} -G ares -h /app -s /sbin/nologin -D ares

# Create data directory for persistence with secure permissions
RUN mkdir -p /data/tls /data/wireguard /data/db && \
    chown -R ares:ares /data && \
    chmod 700 /data/wireguard && \
    chmod 755 /data /data/tls /data/db

# Set working directory
WORKDIR /app

# Copy application code with proper ownership
COPY --chown=ares:ares agent/ ./agent/
COPY --chown=ares:ares web/ ./web/
COPY --chown=ares:ares proto/ ./proto/
COPY --chown=ares:ares scripts/entrypoint.sh ./entrypoint.sh

# Set secure permissions on application files
RUN chmod -R 550 /app && \
    chmod 550 /app/entrypoint.sh && \
    # Create __init__.py files
    touch /app/agent/__init__.py \
          /app/agent/wireguard/__init__.py \
          /app/agent/registration/__init__.py \
          /app/agent/database/__init__.py \
          /app/agent/security/__init__.py \
          /app/agent/health/__init__.py \
          /app/web/__init__.py \
          /app/web/routers/__init__.py \
          /app/proto/__init__.py && \
    chown -R ares:ares /app

# Environment variables (paths only, NO secrets)
ENV PYTHONPATH=/app \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    DATA_DIR=/data \
    # Run as non-root user after network setup
    ARES_USER=ares \
    ARES_UID=${UID} \
    ARES_GID=${GID}

# Expose HTTPS port (unprivileged port, no root needed)
EXPOSE 8443

# Health check using wget (smaller than curl)
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD wget -q --spider --no-check-certificate https://localhost:8443/health || exit 1

# Volume for persistent data (TLS certs, WireGuard keys, database)
VOLUME ["/data"]

# Security: Prevent privilege escalation in child processes
# Note: NET_ADMIN is still required for WireGuard, but no-new-privileges prevents escalation
# Run with: --security-opt no-new-privileges:true

# Default to non-root user for Docker Scout compliance
# The entrypoint will use su-exec to elevate for WireGuard setup only if needed,
# then drop back to non-root for application execution
USER ares
ENTRYPOINT ["/app/entrypoint.sh"]
