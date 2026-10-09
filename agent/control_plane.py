"""HTTPS control-plane client: every call the agent makes to ares-v2.

Outbound only. The agent registers once with a one-time token (receiving a long-lived
bearer token), then heartbeats, polls for tasks, and reports results. TLS is verified
unless ``ARES_INSECURE`` is set (local dev against plain http / self-signed).
"""

from __future__ import annotations

import os
import platform
import socket

import httpx

from agent import tlsconf
from agent.config import Settings


class RegistrationRejected(Exception):
    """The registration token was rejected (expired, already used, or unknown)."""


# What this build can do, reported on register *and* on every heartbeat. The heartbeat matters:
# a self-updating agent keeps its token and never registers again, so a register-only list would
# stay frozen at whatever the first-ever version could do and the platform would gate features on
# stale facts. ares mirrors these as ``AgentCapability`` and refuses a launch that needs one this
# agent does not report.
CAPABILITIES = [
    "local_network_scan",  # the TCP-connect discovery scan
    "tunnel_dns",  # resolve a hostname destination locally and dial it through the tunnel
    "host_identity",  # collect naming evidence (PTR, TLS cert, HTTP, NetBIOS) per live host
    "pause",  # abort the running scan and hand it back when paused from the dashboard (3.10.0)
    # follow the dashboard's "Rescan automatically" setting (the heartbeat's auto_rescan): with it
    # off, stop re-probing reachability and reuse the stored answer across restarts. ares reads its
    # absence as "this build still re-probes on its own" and says so next to the setting.
    "auto_rescan",
]
# read Services, EndpointSlices and workloads from a cluster API. Reported only when the operator
# turned it on, unlike the list above, which is what the build can do. The distinction is the
# point: this one needs credentials the agent does not otherwise hold, so an operator looking at
# the fleet needs to see which agents were actually pointed at a cluster.
KUBERNETES_CAPABILITY = "kubernetes_inventory"


def capabilities(settings: Settings) -> list[str]:
    """What to report for this install."""
    out = list(CAPABILITIES)
    if settings.identify_kubernetes:
        out.append(KUBERNETES_CAPABILITY)
    return out


def system_info() -> dict:
    arch_map = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}
    arch = arch_map.get(platform.machine().lower(), platform.machine().lower())
    try:
        with open("/proc/meminfo") as f:
            memory_mb = int(f.readline().split()[1]) // 1024
    except (OSError, ValueError, IndexError):
        memory_mb = None
    return {
        "os": platform.system().lower(),
        "arch": arch,
        "cpu_cores": os.cpu_count(),
        "memory_mb": memory_mb,
    }


def _client(settings: Settings) -> httpx.AsyncClient:
    # An explicit context, never `verify=True`: given a bare True, httpx verifies against
    # certifi's bundle inside site-packages and ignores the OS trust store entirely, so a root CA
    # installed in the container the ordinary way would do nothing here. See agent.tlsconf.
    trust = tlsconf.build_trust(insecure=settings.insecure, ca_bundle=settings.ca_bundle)
    return httpx.AsyncClient(base_url=settings.base_url, timeout=30.0, verify=trust.context)


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def register(settings: Settings, *, networks: list[str], name: str) -> dict:
    body = {
        "registration_token": settings.token.get_secret_value(),
        "internal_networks": networks,
        "name": name or None,
        "hostname": socket.gethostname(),
        "agent_version": settings.agent_version,
        "capabilities": capabilities(settings),
        "system_info": system_info(),
    }
    async with _client(settings) as client:
        resp = await client.post("/api/v1/agent/register", json=body)
    if resp.status_code == 401:
        raise RegistrationRejected(resp.text[:200])
    resp.raise_for_status()
    return resp.json()


async def heartbeat(
    settings: Settings,
    token: str,
    *,
    public_ip: str | None = None,
    last_handshake_at: str | None = None,
    cpu_percent: float | None = None,
    memory_percent: float | None = None,
    uptime_seconds: int | None = None,
    detected_networks: list[str] | None = None,
) -> dict:
    body: dict[str, object] = {
        "agent_version": settings.agent_version,
        "capabilities": capabilities(settings),
    }
    # What reachability discovery currently believes this agent can reach. Sent on the beat and
    # not only at register, because registration happens once: a self-updating agent keeps its
    # token and never registers again, so a network that came into reach afterwards would stay
    # invisible for the life of the install. Omitted entirely when there is nothing to report, so
    # ares leaves what it already holds alone rather than blanking it.
    if detected_networks:
        body["detected_networks"] = detected_networks
    if public_ip is not None:
        body["public_ip"] = public_ip
    if last_handshake_at is not None:
        body["last_handshake_at"] = last_handshake_at
    if cpu_percent is not None:
        body["cpu_percent"] = cpu_percent
    if memory_percent is not None:
        body["memory_percent"] = memory_percent
    if uptime_seconds is not None:
        body["uptime_seconds"] = uptime_seconds
    async with _client(settings) as client:
        resp = await client.post("/api/v1/agent/heartbeat", json=body, headers=_auth(token))
    resp.raise_for_status()
    return resp.json()


async def poll_tasks(settings: Settings, token: str) -> list[dict]:
    async with _client(settings) as client:
        resp = await client.get("/api/v1/agent/tasks", headers=_auth(token))
    resp.raise_for_status()
    return resp.json().get("tasks", []) or []


async def task_started(settings: Settings, token: str, task_id: str) -> None:
    async with _client(settings) as client:
        resp = await client.post(
            f"/api/v1/agent/tasks/{task_id}/start", json={}, headers=_auth(token)
        )
    resp.raise_for_status()


async def task_progress(
    settings: Settings,
    token: str,
    task_id: str,
    *,
    percent: int,
    discovered_hosts: list[dict] | None = None,
    host_evidence: list[dict] | None = None,
    hosts_scanned: int | None = None,
    hosts_total: int | None = None,
) -> None:
    """Report scan progress mid-task: a percentage plus any hosts discovered since the last call.

    Carries both signals in one request so the control plane can advance the progress bar and
    surface hosts live. Best-effort at the caller: a dropped progress post never fails the scan
    (``task_completed`` sends the authoritative full list at the end)."""
    body: dict[str, object] = {"percent": percent}
    if discovered_hosts:
        body["discovered_hosts"] = discovered_hosts
    if host_evidence:
        body["host_evidence"] = host_evidence
    if hosts_scanned is not None:
        body["hosts_scanned"] = hosts_scanned
    if hosts_total is not None:
        body["hosts_total"] = hosts_total
    async with _client(settings) as client:
        resp = await client.post(
            f"/api/v1/agent/tasks/{task_id}/progress", json=body, headers=_auth(token)
        )
    resp.raise_for_status()


async def task_completed(
    settings: Settings,
    token: str,
    task_id: str,
    discovered_hosts: list[dict],
    *,
    host_evidence: list[dict] | None = None,
) -> None:
    """The authoritative end-of-scan report: every service found, plus the naming evidence.

    Both lists are re-sent in full rather than only the delta since the last progress post, because
    this call is what a server that missed a progress report reconciles against; the server dedups.
    """
    body: dict[str, object] = {"discovered_hosts": discovered_hosts}
    if host_evidence:
        body["host_evidence"] = host_evidence
    async with _client(settings) as client:
        resp = await client.post(
            f"/api/v1/agent/tasks/{task_id}/complete",
            json=body,
            headers=_auth(token),
        )
    resp.raise_for_status()


async def task_released(settings: Settings, token: str, task_id: str) -> None:
    """Hand a task back because the agent was paused, so it reruns on Resume (ARES-1700)."""
    async with _client(settings) as client:
        resp = await client.post(
            f"/api/v1/agent/tasks/{task_id}/release", json={}, headers=_auth(token)
        )
    resp.raise_for_status()


async def task_failed(settings: Settings, token: str, task_id: str, reason: str) -> None:
    async with _client(settings) as client:
        resp = await client.post(
            f"/api/v1/agent/tasks/{task_id}/fail",
            json={"failure_reason": reason},
            headers=_auth(token),
        )
    resp.raise_for_status()
