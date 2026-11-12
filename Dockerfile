# =============================================================================
# Ares Docker Agent - customer-deployable container
# =============================================================================
# Headless, outbound-only: the agent dials ares over HTTPS (control plane) and a
# WebSocket (data-plane tunnel). No inbound ports, no WireGuard, no NET_ADMIN.
#
# Usage (zero-touch: the token carries everything):
#   docker run -d --name ares-agent \
#     -e ARES_TOKEN=<registration-token> \
#     -v ares-agent-data:/data \
#     --restart unless-stopped \
#     assailai/ares-agent:3.2.1
# =============================================================================

# -----------------------------------------------------------------------------
# Stage 1: build Python wheels
# -----------------------------------------------------------------------------
FROM python:3.12-alpine AS python-builder

RUN apk add --no-cache gcc musl-dev libffi-dev openssl-dev

WORKDIR /build
COPY requirements.txt .
RUN pip wheel --no-cache-dir --wheel-dir /wheels -r requirements.txt

# -----------------------------------------------------------------------------
# Stage 2: minimal runtime
# -----------------------------------------------------------------------------
FROM python:3.12-alpine

LABEL org.opencontainers.image.title="Ares Docker Agent"
LABEL org.opencontainers.image.source="https://github.com/assailai/ares-agent"
LABEL org.opencontainers.image.vendor="Assail AI"

# iproute2 gives a full `ip` for LAN auto-detection (busybox's is too limited);
# dash is a small shell for the entrypoint; ca-certificates is named explicitly rather than
# inherited from the base image, because agent.tlsconf builds on the store it provides.
#
# `apk upgrade` first: Alpine ships a fix before the python image is rebuilt on it, and the publish
# gate refuses a fixable High/Critical. On 2026-11-07 Alpine 3.24 had zlib 1.4-r0 (CVE-2026-4738,
# Critical) while python:3.12-alpine still carried 1.3.2-r1, which blocked every build (ARES-2046).
# the `|| true` covers the cache sweep alone, so a failed upgrade or install fails the build.
#
# the ADD is what makes that upgrade RERUN. Its cache key is the base layer plus the command
# string, and neither moves when Alpine publishes: docker-build.yml passes `cache-from: type=gha`,
# so a rebuild on an unmoved `python:3.12-alpine` serves whichever packages the layer was FIRST
# built with. 2026-11-12 (ARES-2157) is the worked example: Alpine built krb5-libs 1.22.3-r0 on
# 11-10, these images were built on 11-08, the base tag last moved on 11-06, and so a plain rebuild
# would have shipped the nine High CVEs in 1.22.2-r1 again. krb5-libs is not installed here by
# name, it arrives under `.python-rundeps` via libtirpc, which is exactly why only `apk upgrade`
# ever moves it. ares-v2's surface harness keys its Debian chromium the same way (ARES-2047).
#
# BuildKit refetches the URL on every build and reruns what follows when the bytes change.
# APKINDEX.tar.gz is rewritten whenever anything in the repository is published, and dl-cdn serves
# it with an ETag. `latest-stable` rather than a pinned `v3.24`, because the base rebases onto the
# next Alpine on its own schedule and a pinned branch would quietly stop changing and freeze this
# layer again, which is the bug this line exists to prevent. x86_64's index stands for both
# architectures: it is a cache KEY, not an artifact anything reads, and Alpine publishes a fix to
# every arch from one sweep. The copy left in the image records the index this build upgraded from.
ADD https://dl-cdn.alpinelinux.org/alpine/latest-stable/main/x86_64/APKINDEX.tar.gz /usr/share/ares/apkindex.tar.gz
RUN apk upgrade --no-cache \
    && apk add --no-cache iproute2 dash openssl ca-certificates \
    && rm -rf /var/cache/apk/* \
    && { find /usr -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true; }

COPY --from=python-builder /wheels /wheels
RUN pip install --no-cache-dir --no-compile /wheels/*.whl && rm -rf /wheels

ARG UID=10001
ARG GID=10001
RUN addgroup -g ${GID} ares && adduser -u ${UID} -G ares -h /app -s /sbin/nologin -D ares \
    && mkdir -p /data && chown -R ares:ares /data && chmod 700 /data \
    # Mount points for CA trust, empty in the image. /host-ca is where the install command mounts
    # the host's own CA directory read-only, so a network that inspects TLS needs no config;
    # /certs is the manual drop-in for a root the host store does not have. Both are optional:
    # agent.tlsconf skips a directory that is not mounted. Read-only in use, hence 0555.
    && mkdir -p /host-ca /certs && chmod 555 /host-ca /certs \
    # The host's own /etc/hosts, mounted read-only by the install command. Same shape as /host-ca
    # and for the same reason: a container gets docker's /etc/hosts even under --network host, so a
    # name pinned on the machine is otherwise invisible here. Optional; agent.hostpins skips it
    # when it is not mounted. Created as an empty FILE, not a directory, to match the bind source.
    && touch /host-hosts && chmod 444 /host-hosts

WORKDIR /app
COPY --chown=ares:ares agent/ ./agent/
COPY --chown=ares:ares scripts/entrypoint.sh ./entrypoint.sh
RUN chmod 550 /app/entrypoint.sh && chown -R ares:ares /app

ENV PYTHONPATH=/app \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    ARES_DATA_DIR=/data

# The agent is outbound-only, so no port is published. Liveness reflects real contact with Ares:
# the agent refreshes its last-contact marker on every successful heartbeat/poll, so an agent that
# has gone dark reads unhealthy rather than "up" forever (see agent/healthcheck.py). Under Docker
# the in-process watchdog is what restarts a wedged agent (restart policy acts on exit, not on
# "unhealthy"); this probe drives the k8s liveness restart and honest status.
HEALTHCHECK --interval=30s --timeout=5s --start-period=90s --retries=3 \
    CMD python -m agent.healthcheck

VOLUME ["/data"]
USER ares
ENTRYPOINT ["/app/entrypoint.sh"]
