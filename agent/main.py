"""Ares Docker Agent: headless, zero-touch control-plane client.

One command runs it: ``docker run -e ARES_TOKEN=... assailai/ares-agent``. The agent
auto-detects its internal LAN(s), registers over HTTPS, then heartbeats and polls for scan
tasks. When an internal hunt is running it opens an outbound data-plane tunnel so ares can
reach the discovered internal hosts. There is no web UI and no interactive setup; logs
narrate each step so an operator can self-diagnose.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import os
import resource
import ssl
import sys
import time
from urllib.parse import urlparse

import httpx

from agent import control_plane, netdetect, reachability, scan, tlsconf
from agent.config import settings
from agent.health.system_metrics import read_cpu_percent, read_memory_percent
from agent.hostpins import HostPins
from agent.identify import IdentityProbe
from agent.state import AgentState, fingerprint, load_state, save_state
from agent.tunnel import (
    TunnelManager,
    explain_probe_failure,
    tunnel_url,
)
from agent.tunnel import probe as tunnel_probe  # aliased: bare "probe" says too little here

logger = logging.getLogger("ares.agent")


class _AuthInvalidated(Exception):
    """The control plane rejected our agent token past the retry threshold.

    Raised out of the heartbeat loop so :func:`run` can drop the stale identity and
    re-enroll with ARES_TOKEN, rather than 401-looping forever on dead credentials.
    """

# scan concurrency resolved at startup against the file-descriptor budget (see
# _resolve_scan_limits); per-connect timeouts + range breadth come from settings.
_scan_limits = {"concurrency": 512, "reach_concurrency": 512}
# The pin table built at startup, shared with the identity phase so a discovered address can be
# named from the host's own /etc/hosts. Module-level for the same reason as _scan_limits: a scan
# task is driven by the poll loop and does not carry run()'s locals.
_host_pins: HostPins | None = None
# file-descriptor target so high scan concurrency has enough sockets (headroom left for the
# control-plane client and the data-plane tunnel).
_FD_TARGET = 65536
_FD_RESERVE = 256
# floor so a tiny fd budget still leaves the scanner usable.
_MIN_CONCURRENCY = 64
_REGISTER_RETRY_SECONDS = 10
# Consecutive 401s on the heartbeat before we attempt to re-enroll. A single 401 can be a
# momentary blip (a load balancer mid-rollover); a streak means the stored agent token was
# rejected for real (stale kept-volume creds or a decommissioned agent). The re-enroll it
# triggers is non-destructive (see _reenroll), so the streak only needs to filter blips, not
# to prove a decommission: a transient 401 on a healthy agent recovers on its own.
_REENROLL_AFTER_UNAUTHORIZED = 3
# How long to wait before serving again after a re-enroll attempt failed (the registration
# token is spent, or Ares was unreachable). Paces the retry so a decommissioned agent idles
# quietly instead of busy-looping, without ever exiting the process (which would hand the
# restart cadence to Docker and risk a fast restart storm).
_REENROLL_RETRY_SECONDS = 60
# hosts for which a plaintext / unverified ARES_URL is acceptable (local + staging only).
_INSECURE_OK_HOSTS = ("localhost", "127.0.0.1", "::1", "host.docker.internal")
# production control-plane hosts that must ALWAYS verify TLS, even though they end in the
# allowed .assailai.com suffix below. A real customer agent must never skip verification here.
_INSECURE_DENY_HOSTS = ("ares.assailai.com",)
# The networks reachability discovery last worked out, reported on every beat and refreshed on the
# cadence in ARES_REACH_REFRESH_SECONDS. Module state for the same reason _cadence is: the heartbeat
# loop and the re-detection task both need it, and threading it through every call between them
# would touch a dozen signatures to move one list.
_reachable: dict[str, list[str]] = {"networks": []}
# cadence the server hands back at register / heartbeat (sane defaults until then).
_cadence = {"heartbeat": 30, "poll": 5}
# captured at import (process start) so heartbeats can report uptime since connect.
_AGENT_START_MONOTONIC = time.monotonic()
# monotonic times of the last successful control-plane contact (heartbeat or task poll) and the
# last healthcheck-marker write. The watchdog compares last_contact to decide the agent has gone
# dark; last_marker_at throttles the marker file so it does not churn /data on every poll.
_liveness = {"last_contact": time.monotonic(), "last_marker_at": 0.0}
# how often the watchdog checks liveness (well below max_offline_seconds, so the exit is timely).
_WATCHDOG_INTERVAL_SECONDS = 30
# rewrite the healthcheck marker at most this often: the watchdog uses the in-memory clock, so the
# file only needs to stay fresh enough for the probe's max_offline_seconds grace window.
_MARKER_MIN_INTERVAL_SECONDS = 30
# bound on the threadpool-dispatched CPU sample: a pool starved by hung DNS lookups must never
# wedge the heartbeat, so the sample is skipped past this timeout.
_CPU_SAMPLE_TIMEOUT_SECONDS = 5


def _configure_logging() -> None:
    """Configure logging so ``ARES_LOG_LEVEL`` only ever raises the verbosity of *our* loggers.

    The level is deliberately NOT handed to ``basicConfig``: that sets the **root** level, which
    would turn on DEBUG for every dependency too. ``websockets`` logs each frame it sends and
    receives at DEBUG (``protocol.py``: ``logger.debug("< %s", frame)``), and a frame's repr renders
    the payload as hex - which for the data-plane tunnel is the customer's own relayed traffic, in
    plaintext whenever the target speaks http. An operator raising the log level to debug their
    agent must never start dumping that.

    Root stays at INFO so third-party DEBUG records are dropped at their own logger; ``ares.*`` gets
    the configured level. This works because the root *handler* is left at NOTSET, so a DEBUG record
    admitted by ``ares.agent`` still reaches it.
    """
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    logging.getLogger("ares").setLevel(getattr(logging, settings.log_level.upper(), logging.INFO))


def _resolve_scan_limits() -> None:
    """Raise the file-descriptor soft limit so high scan concurrency has enough sockets, then clamp
    the effective concurrency to what that budget allows (reserving headroom for the control-plane
    client and the tunnel). Degrades gracefully: if the limit cannot be raised, concurrency simply
    tracks whatever the current budget is."""
    soft = 1024
    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        target = _FD_TARGET if hard == resource.RLIM_INFINITY else min(_FD_TARGET, hard)
        if soft < target:
            resource.setrlimit(resource.RLIMIT_NOFILE, (target, hard))
            soft = target
    except (OSError, ValueError) as exc:
        logger.debug("could not raise file-descriptor limit: %s", exc)
    budget = soft - _FD_RESERVE
    concurrency = max(_MIN_CONCURRENCY, min(settings.scan_concurrency, budget))
    _scan_limits["concurrency"] = concurrency
    # The reachability probe opens sockets from the same budget and would otherwise ask for its
    # configured concurrency regardless of how many the container actually has, which is the same
    # EMFILE the clamp above exists to prevent. It is bounded separately (and lower by default)
    # because it reaches across the whole private space rather than one advertised network.
    _scan_limits["reach_concurrency"] = max(
        _MIN_CONCURRENCY, min(settings.reach_concurrency, budget)
    )
    logger.info(
        "Scan concurrency=%d, reachability concurrency=%d (file-descriptor soft limit=%d)",
        concurrency,
        _scan_limits["reach_concurrency"],
        soft,
    )


def _insecure_allowed(base_url: str) -> bool:
    """ARES_INSECURE skips TLS verification, so only allow it against local, staging, or a
    non-production ``*.assailai.com`` host. Production (``ares.assailai.com``) is always denied:
    a customer agent must keep a verified certificate there."""
    host = urlparse(base_url).hostname or ""
    if host in _INSECURE_DENY_HOSTS:
        return False
    return (
        host in _INSECURE_OK_HOSTS
        or host.endswith(".local")
        or host.endswith(".assailai.com")
        or "staging" in host
    )


def _server_name(resp: dict) -> str | None:
    """The label ares assigned this agent, or None from a control plane too old to send one.

    Worth reading rather than assuming ARES_AGENT_NAME: at enrollment the name chosen in the
    deploy wizard *overrides* what the agent reports, so the dashboard can legitimately show
    something the operator never typed into the install command.
    """
    name = resp.get("name")
    return name.strip() if isinstance(name, str) and name.strip() else None


async def _register(state: AgentState, networks: list[str]) -> AgentState:
    logger.info("Registering with %s (networks=%s)", settings.base_url, networks or "none")
    presented = settings.token.get_secret_value()
    resp = await control_plane.register(settings, networks=networks, name=settings.agent_name)
    state.agent_id = resp["agent_id"]
    state.agent_token = resp["agent_token"]
    # Bind the identity to the token that minted it. This is the whole point of the field: on a
    # later start it separates an ordinary restart (same token, keep serving) from an operator
    # re-running the installer with the token for a *different* agent. See _enroll.
    state.registration_token_fingerprint = fingerprint(presented)
    _cadence["heartbeat"] = resp.get("heartbeat_interval_seconds", _cadence["heartbeat"])
    _cadence["poll"] = resp.get("poll_interval_seconds", _cadence["poll"])
    save_state(settings.state_path, state)
    name = _server_name(resp)
    logger.info("Registered as agent %s%s", state.agent_id, f' ("{name}")' if name else "")
    return state


def _tls_hint(exc: BaseException) -> str:
    """The remedy for a rejected certificate, or "" for any other failure."""
    return tlsconf.verification_hint(
        exc, insecure=settings.insecure, ca_bundle=settings.ca_bundle
    )


async def _preflight(state: AgentState, ssl_context: ssl.SSLContext) -> None:
    """Exercise both planes at startup and say plainly whether each one works.

    The control plane proves itself by being used. The data plane does not: it is only opened
    while a hunt is running, so a network that permits our HTTPS but blocks WebSocket upgrades
    looks completely healthy right up until the first assessment, and then fails in the middle of
    it. Rehearsing it here moves that discovery to enrollment, where an operator is watching.

    Never fatal. An agent that can reach the control plane is still useful (it enrolls, heartbeats
    and reports), and refusing to start would turn a degraded deployment into no deployment. The
    log is loud instead, and the serve loop carries on.
    """
    token = state.agent_token or ""
    try:
        await control_plane.heartbeat(settings, token)
        # Worth its own line even though registration just succeeded: that used the one-time
        # registration token, and this is the first proof the long-lived agent token works.
        logger.info("Preflight: control plane OK (%s)", settings.base_url)
    except (httpx.HTTPError, OSError) as exc:
        logger.error("Preflight: control plane FAILED: %s%s", exc, _tls_hint(exc))

    url = tunnel_url(settings.base_url)
    try:
        await tunnel_probe(url, token, ssl_context=ssl_context)
        logger.info("Preflight: data-plane tunnel OK (%s)", url)
    except Exception as exc:  # noqa: BLE001 - a probe must never be the thing that stops the agent
        logger.error(
            "Preflight: data-plane tunnel FAILED: %s.%s%s Hunts that reach into your network "
            "need this; the agent will keep running and retry when one starts.",
            exc,
            _tls_hint(exc),
            explain_probe_failure(exc),
        )


def _log_repeated_failure(what: str, failures: int, exc: Exception) -> None:
    """Surface sustained trouble without spamming the log: the first failure and every
    tenth after it are WARNING (visible at the default INFO level); the rest stay DEBUG.
    The caller logs the matching recovery once the call succeeds again."""
    if failures == 1 or failures % 10 == 0:
        logger.warning("%s failing (attempt %d): %s%s", what, failures, exc, _tls_hint(exc))
    else:
        logger.debug("%s failed (attempt %d): %s", what, failures, exc)


async def _resolve_networks() -> list[str]:
    """The CIDRs this agent advertises and scans, from whichever source the operator chose.

    ARES_NETWORKS wins outright: an explicit list is a decision, and nothing should widen or
    second-guess it. Otherwise the configured scope decides, and the default one (``reachable``)
    adds the routing table, the neighbour table and an active probe of private space on top of the
    attached subnets, so an agent finds the 10.x estate it can reach rather than only the /16 its
    own interface sits in.

    Never raises: discovery is best-effort, and an agent that cannot work out its networks must
    still enroll (it can be given them in the dashboard) rather than fail to start.
    """
    override = settings.network_overrides()
    if override:
        return override
    attached = netdetect.scan_targets(settings.scan_scope)
    if settings.scan_scope != netdetect.REACHABLE_SCOPE:
        return attached
    return await reachability.discover(
        attached=attached,
        probe=settings.reach_probe,
        concurrency=_scan_limits["reach_concurrency"],
        budget_seconds=settings.reach_budget_seconds,
        timeout=settings.scan_discovery_timeout,
    )


def _allowed_hosts(value: object) -> list[str]:
    """The hostname destinations ares named on this heartbeat, ignoring anything malformed.

    A bad field must never cost us the tunnel, and it must never *widen* the allowlist either:
    anything that is not a list of strings degrades to "no pushed hosts", which leaves the
    registered-network rule as the only way in."""
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


def _write_update_target(version: str) -> None:
    """Record the version the companion updater should move this agent to.

    The updater is a separate, privileged container that reads this from the shared data
    dir and applies it (recreate / rolling update); the agent itself never touches the
    container runtime. Best-effort: if the shared dir is not mounted (no updater deployed),
    log at debug and carry on."""
    path = settings.update_target_path
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps({"version": version}))
        tmp.replace(path)
    except OSError as exc:
        logger.debug("could not write update target (%s); is the shared volume mounted?", exc)


def _record_contact() -> None:
    """Mark a successful control-plane contact: bump the watchdog's liveness clock (every call) and
    refresh the healthcheck marker file (throttled). The in-memory clock is what the watchdog reads;
    the marker only backs the container HEALTHCHECK / k8s liveness probe, so it is rewritten at most
    every _MARKER_MIN_INTERVAL_SECONDS to avoid churning /data on the ~5s poll cadence. Best-effort
    on the file."""
    now = time.monotonic()
    _liveness["last_contact"] = now
    if now - _liveness["last_marker_at"] < _MARKER_MIN_INTERVAL_SECONDS:
        return
    _liveness["last_marker_at"] = now
    try:
        marker = settings.data_dir / "last-contact"
        tmp = marker.with_suffix(".tmp")
        tmp.write_text(str(int(time.time())))
        tmp.replace(marker)
    except OSError as exc:
        logger.debug("could not write liveness marker: %s", exc)


async def _sample_cpu_percent() -> float | None:
    """Read CPU% off the loop's default thread pool, bounded by a timeout. The metric is
    best-effort: a slow or starved pool (e.g. leaked, non-cancellable getaddrinfo threads during a
    DNS outage) must never wedge the heartbeat here, so on timeout/error we skip it and let the beat
    proceed (reporting no CPU) rather than block forever."""
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(read_cpu_percent), _CPU_SAMPLE_TIMEOUT_SECONDS
        )
    except asyncio.CancelledError:
        raise
    except Exception as exc:  # noqa: BLE001 - metric is best-effort; never block or fail the beat
        logger.debug("cpu sample skipped: %s", exc)
        return None


async def _watchdog_loop() -> None:
    """Exit the process when the agent has had no successful contact with Ares for
    ``max_offline_seconds``, so the container runtime restarts it fresh (a new process re-resolves
    DNS and rebuilds its client / thread pool). This is the recovery of last resort for a wedged or
    network-isolated agent that the in-loop retries cannot rescue. It only sleeps and compares
    monotonic time, never touching the network or the shared thread pool, so the same starvation
    that can wedge the heartbeat/poll loops cannot wedge the watchdog too.

    Scope (accepted gap): the watchdog runs only while serving (started in ``_serve``), so initial
    ``_enroll`` and post-401 ``_reenroll`` are not covered. That is deliberate and low risk: those
    loops make network calls through fresh, short-timeout clients that fail-and-retry rather than
    hang, and the thread-pool starvation this guards against only arises in the long-lived serving
    loops - so there is nothing here for a last-resort exit to rescue."""
    while True:
        await asyncio.sleep(_WATCHDOG_INTERVAL_SECONDS)
        offline_for = time.monotonic() - _liveness["last_contact"]
        if offline_for >= settings.max_offline_seconds:
            logger.error(
                "No successful contact with Ares for %.0fs (limit %ds); exiting so the container "
                "restarts and reconnects.",
                offline_for,
                settings.max_offline_seconds,
            )
            os._exit(1)


def _online_label(state: AgentState, server_name: str | None) -> str:
    """How the "online" line names this agent: ares' own label, else the id and a local name.

    The fallback is marked "local" on purpose, so a line produced against a control plane too
    old to send a name never reads as confirmation that the dashboard agrees.
    """
    if server_name:
        return f'"{server_name}" (agent {state.agent_id})'
    return f'agent {state.agent_id} (local name "{settings.agent_name or "this host"}")'


def _warn_on_name_mismatch(server_name: str | None) -> None:
    """Say so when ares knows this agent by a different name than ARES_AGENT_NAME asked for.

    Two innocent causes (the deploy wizard's label overrides the agent-reported one at
    enrollment, or the agent was renamed in the dashboard) and one that is not: the container is
    serving on an identity from an earlier install. The agent cannot tell them apart, so this
    warns rather than fails - but it does put "I asked for Heffe 3 and got Heffe 2" in
    ``docker logs``, instead of leaving it to be inferred from the dashboard.
    """
    wanted = settings.agent_name.strip()
    if not wanted or not server_name or wanted.casefold() == server_name.casefold():
        return
    logger.warning(
        'Ares knows this agent as "%s", which differs from ARES_AGENT_NAME ("%s"). Expected if '
        "the name was set in the deploy wizard or changed in the dashboard; if you meant to "
        "install a *new* agent on this host, this container is serving on an earlier enrollment "
        "- re-run the installer with a fresh token, or with ARES_RESET=1.",
        server_name,
        wanted,
    )


async def _heartbeat_loop(state: AgentState, tunnel: TunnelManager) -> None:
    failures = 0
    unauthorized = 0
    online_announced = False
    name_checked = False
    while True:
        try:
            # CPU sampling reads the cgroup counter twice on the first call; keep it off the loop.
            # Bounded so a thread pool starved by hung DNS lookups can never wedge the beat here.
            cpu_percent = await _sample_cpu_percent()
            resp = await control_plane.heartbeat(
                settings,
                state.agent_token or "",
                cpu_percent=cpu_percent,
                memory_percent=read_memory_percent(),
                uptime_seconds=int(time.monotonic() - _AGENT_START_MONOTONIC),
                detected_networks=_reachable["networks"],
            )
            # Announce "online" only once the control plane has actually accepted a beat, so
            # the log never claims the agent is up while its credentials are in fact rejected.
            #
            # Name it by what *ares* calls this agent, not by ARES_AGENT_NAME. The env var is a
            # request, not the answer: the control plane may already hold a different label for
            # this identity, and printing the request as though it were the answer is precisely
            # how a container serving on an earlier install's credentials used to read as success.
            if not online_announced:
                logger.info("Agent online as %s.", _online_label(state, _server_name(resp)))
                online_announced = True
            if not name_checked:
                name_checked = True
                _warn_on_name_mismatch(_server_name(resp))
            if failures:
                logger.info("Heartbeat recovered after %d failed attempt(s).", failures)
            failures = 0
            unauthorized = 0
            _record_contact()  # feed the watchdog + refresh the healthcheck marker
            _cadence["heartbeat"] = resp.get("heartbeat_interval_seconds", _cadence["heartbeat"])
            tunnel.sync(
                bool(resp.get("tunnel_required")),
                _allowed_hosts(resp.get("tunnel_allowed_hosts")),
                # The addresses an operator put in this agent's scope. Read from the same beat and
                # parsed by the same fail-closed helper: a malformed field must cost the tunnel
                # nothing and widen it by nothing.
                _allowed_hosts(resp.get("scoped_hosts")),
            )
            if resp.get("restart_requested"):
                logger.warning("Restart requested from dashboard; exiting for container restart.")
                os._exit(0)
            if resp.get("update_pending") and resp.get("latest_version"):
                _write_update_target(resp["latest_version"])
        except asyncio.CancelledError:
            raise
        except httpx.HTTPStatusError as exc:
            failures += 1
            if exc.response.status_code == 401:
                unauthorized += 1
                if unauthorized >= _REENROLL_AFTER_UNAUTHORIZED:
                    # Sustained rejection: the stored token is dead. Surface it so run() can
                    # drop the identity and re-enroll instead of 401-looping forever.
                    raise _AuthInvalidated from exc
                logger.warning(
                    "Heartbeat unauthorized (%d/%d): the stored agent credentials look stale or "
                    "the agent was decommissioned; will re-enroll with ARES_TOKEN if this persists.",
                    unauthorized,
                    _REENROLL_AFTER_UNAUTHORIZED,
                )
            else:
                _log_repeated_failure("heartbeat", failures, exc)
        except Exception as exc:  # noqa: BLE001 - keep heartbeating through any transient error
            failures += 1
            _log_repeated_failure("heartbeat", failures, exc)
        await asyncio.sleep(_cadence["heartbeat"])


def _identity_probe() -> IdentityProbe | None:
    """The configured phase-3 naming probe, or ``None`` when the operator turned it off.

    Returning ``None`` rather than an all-sources-disabled probe matters: ``scan_cidr`` skips the
    whole phase on ``None``, so a disabled probe costs nothing at all instead of one no-op pass
    per live host.
    """
    if not settings.identify:
        return None
    return IdentityProbe(
        reverse_dns=settings.identify_reverse_dns,
        tls=settings.identify_tls,
        http=settings.identify_http,
        netbios=settings.identify_netbios,
        dns_timeout=settings.identify_dns_timeout,
        tls_timeout=settings.identify_tls_timeout,
        http_timeout=settings.identify_http_timeout,
        netbios_timeout=settings.identify_netbios_timeout,
        hosts_file_lookup=_host_pins.reverse if _host_pins is not None else None,
    )


def _local_ceiling() -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """The networks ARES_NETWORKS pins this agent to, or [] when it was not set.

    Unparseable entries are dropped rather than allowed to fail every task: ARES_NETWORKS is a
    free-form string (:meth:`agent.config.Settings.network_overrides` does not validate it), and one
    typo in a list of five should not stop the agent scanning the four that are fine. ``run`` names
    the bad entries once at startup so the typo is still visible.
    """
    ceiling: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for value in settings.network_overrides():
        try:
            ceiling.append(ipaddress.ip_network(value, strict=False))
        except ValueError:
            continue
    return ceiling


def _warn_unparseable_networks() -> None:
    """Name any ARES_NETWORKS entry that is not a CIDR, once, at startup."""
    bad = []
    for value in settings.network_overrides():
        try:
            ipaddress.ip_network(value, strict=False)
        except ValueError:
            bad.append(value)
    if bad:
        logger.warning(
            "Ignoring %d ARES_NETWORKS entr%s that %s not a CIDR: %s. The rest still apply, and "
            "they are the ceiling this agent will hold scan tasks to.",
            len(bad),
            "y" if len(bad) == 1 else "ies",
            "is" if len(bad) == 1 else "are",
            ", ".join(repr(value) for value in bad),
        )


def _warn_if_undetected(task_id: str, target: ipaddress.IPv4Network) -> None:
    """Say so when a task targets somewhere this agent never reported it could reach.

    Advisory only, and on purpose. Without ARES_NETWORKS the scope is whatever re-detection last
    worked out, which is reachability evidence rather than an authorization, and it narrows as well
    as widens - enforcing it would refuse legitimate tasks whenever a task and a re-detect crossed.
    So the scan proceeds and the operator gets the one line they need to notice drift, plus the
    knob that turns this into a hard ceiling.
    """
    detected = _reachable["networks"]
    if not detected:
        return  # nothing detected yet: the first task can easily beat the first probe
    try:
        known = [ipaddress.ip_network(net, strict=False) for net in detected]
    except ValueError:  # pragma: no cover - detection emits parseable CIDRs
        return
    if any(target.version == net.version and target.subnet_of(net) for net in known):
        return
    logger.warning(
        "Scan task %s targets %s, which is outside every network this agent detected (%s). "
        "Scanning it anyway, because auto-detected scope is evidence of reachability rather than "
        "an authorization; set ARES_NETWORKS to make the scope a hard ceiling this agent enforces.",
        task_id,
        target,
        ", ".join(detected),
    )


def _authorized_target(cidr: str) -> ipaddress.IPv4Network:
    """The network a scan task may actually scan, or raise ValueError saying why it may not.

    The agent is the last thing standing between an instruction and a customer's network, so it
    checks the destination itself rather than trusting that whoever queued the task got it right.
    An authenticated instruction is still an instruction.

    An explicit ARES_NETWORKS is a ceiling, not just a starting point - the README and
    :func:`_redetect_loop` both already say an explicit list is a decision that nothing widens, and
    that has to include a task. Containment, not overlap: ``10.0.0.0/16`` is refused against an
    approved ``10.0.1.0/24``, because a supernet is a request for everything ELSE in it too.

    Auto-detected scope is deliberately NOT a ceiling here. It is evidence of what this agent can
    reach, which is not the same as a grant, and it moves under the agent's feet as routes appear
    and disappear - a task queued against a network detected a minute ago must not start failing
    because re-detection has since narrowed. ``_run_task`` warns about that case instead.
    """
    target = ipaddress.ip_network(cidr, strict=False)
    if target.version != 4:
        # scan._plan_chunks rejects these too, but only after the task has been marked started.
        raise ValueError(f"only IPv4 ranges are supported, got {cidr}")
    if target.prefixlen == 0:
        raise ValueError(f"{target} is the whole address space, which is never a scan scope")
    ceiling = _local_ceiling()
    if ceiling and not any(
        target.version == net.version and target.subnet_of(net) for net in ceiling
    ):
        allowed = ", ".join(str(net) for net in ceiling)
        raise ValueError(f"{target} is not inside ARES_NETWORKS ({allowed})")
    return target


async def _run_task(token: str, task: dict) -> None:
    task_id = task["id"]
    cidr = task.get("target_network")
    config = task.get("tool_config") or {}
    ports = config.get("ports") or list(scan.DEFAULT_PORTS)
    budget = config.get("timeout_seconds")
    if not cidr:
        await control_plane.task_failed(settings, token, task_id, "missing target_network")
        return
    try:
        target = _authorized_target(str(cidr))
    except ValueError as exc:
        # Refused before task_started, so a task the agent will not run is never reported as one it
        # began, and before the scanner, so nothing dials anything.
        logger.warning("Refused scan task %s: %s", task_id, exc)
        await control_plane.task_failed(settings, token, task_id, f"scope refused: {exc}")
        return
    if not settings.network_overrides():
        _warn_if_undetected(task_id, target)
    cidr = str(target)
    await control_plane.task_started(settings, token, task_id)

    last_pct = 0
    # Accumulated so the completion report carries every host's identity, not only the last
    # chunk's: a progress post can be dropped, and complete is what the server reconciles against.
    identity_seen: dict[str, dict] = {}

    async def _report(
        percent: int,
        hosts: list[dict] | None = None,
        evidence: list[dict] | None = None,
    ) -> None:
        # best-effort: progress + streamed hosts are a live-UX nicety, never allowed to fail the
        # scan. task_completed sends the authoritative full list, and the server de-dups it.
        try:
            await control_plane.task_progress(
                settings,
                token,
                task_id,
                percent=percent,
                discovered_hosts=hosts,
                host_evidence=evidence,
            )
        except Exception as exc:  # noqa: BLE001 - a dropped progress post is not fatal
            logger.debug("progress report for task %s failed: %s", task_id, exc)

    async def _on_progress(percent: int) -> None:
        nonlocal last_pct
        last_pct = percent
        await _report(percent)

    async def _on_hosts(chunk: list[dict]) -> None:
        await _report(last_pct, chunk)

    async def _on_identity(chunk: list[dict]) -> None:
        for item in chunk:
            identity_seen[item["ip"]] = item
        await _report(last_pct, None, chunk)

    try:
        logger.info("Scanning %s across %d port(s)", cidr, len(ports))
        hosts = await scan.scan_cidr(
            cidr,
            ports,
            timeout=settings.scan_connect_timeout,
            discovery_timeout=settings.scan_discovery_timeout,
            concurrency=_scan_limits["concurrency"],
            max_hosts=settings.scan_max_hosts,
            chunk_prefix=settings.scan_chunk_prefix,
            budget_seconds=budget,
            on_progress=_on_progress,
            on_hosts=_on_hosts,
            on_identity=_on_identity,
            identity=_identity_probe(),
        )
        evidence = sorted(identity_seen.values(), key=lambda d: d["ip"])
        await control_plane.task_completed(
            settings, token, task_id, hosts, host_evidence=evidence
        )
        logger.info(
            "Reported %d discovered host(s) for %s (%d named)", len(hosts), cidr, len(evidence)
        )
    except asyncio.CancelledError:
        raise
    except Exception as exc:  # noqa: BLE001 - report any scan failure instead of dropping the task
        logger.error("Scan task %s failed: %s", task_id, exc)
        await control_plane.task_failed(settings, token, task_id, f"{type(exc).__name__}: {exc}")


async def _redetect_loop(tunnel: TunnelManager | None = None) -> None:
    """Work out what this agent can reach, then keep working it out.

    Runs IMMEDIATELY rather than after a sleep, because it owns the first answer as well as every
    later one: ``run`` enrolls on the attached subnets alone so the agent comes online in seconds,
    and this is what widens the scope to everything reachable a minute or two later. Then it
    repeats on the refresh cadence, because registration happens exactly once (a self-updating
    agent keeps its token and never registers again), so a VLAN or a route that appeared six months
    into an install would otherwise stay invisible for as long as the container lives.

    The result is published for the heartbeat to report; this task never calls the control plane
    itself, which is what stops a slow probe from ever delaying a beat.

    Off entirely when the networks were given explicitly (ARES_NETWORKS is a decision, and nothing
    should widen it) or when the interval is 0, which is the escape hatch for an estate that wants
    discovery to happen once and then never unprompted.
    """
    if settings.network_overrides() or settings.scan_scope != netdetect.REACHABLE_SCOPE:
        return
    logger.info(
        "Discovering reachable networks in the background (routes, neighbours%s).",
        ", and a probe of private space" if settings.reach_probe else "",
    )
    interval = settings.reach_refresh_seconds
    while True:
        try:
            networks = await _resolve_networks()
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 - a failed re-detect keeps the previous answer
            logger.debug("reachability re-detection failed: %s", exc)
            networks = _reachable["networks"]
        if networks != _reachable["networks"]:
            logger.info("Reachable networks: %s", ", ".join(networks) or "none")
            _reachable["networks"] = networks
            # Widen what the tunnel will dial as well as what ares will scan. Both halves are
            # needed and they are decided in different places: ares scans what it is told, the
            # agent dials what IT believes it can reach, so reporting the networks without
            # updating this would find hosts the tunnel then refuses. A tunnel already connected
            # keeps the snapshot it was built with until it reconnects, which is a window of one
            # reconnect on a 6-hourly cadence.
            if tunnel is not None:
                tunnel.set_networks(networks)
        if interval <= 0:
            return  # a single pass was asked for: the first answer is the only answer
        await asyncio.sleep(interval)


async def _poll_loop(state: AgentState) -> None:
    failures = 0
    while True:
        try:
            tasks = await control_plane.poll_tasks(settings, state.agent_token or "")
            if failures:
                logger.info("Task polling recovered after %d failed attempt(s).", failures)
                failures = 0
            _record_contact()  # a successful poll is also live contact with Ares
            for task in tasks:
                await _run_task(state.agent_token or "", task)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 - keep polling through any transient error
            failures += 1
            _log_repeated_failure("task poll", failures, exc)
        await asyncio.sleep(_cadence["poll"])


async def _register_with_retries(state: AgentState, networks: list[str]) -> AgentState | None:
    """Register, retrying transient connectivity forever; None *only* when the token is refused.

    Keeping those two outcomes apart is the point of the helper. Both callers act on the None,
    and "Ares was not reachable on this boot" must never be read as "this token is spent": a
    single blip during a restart would otherwise decide the host's identity for good.
    """
    while True:
        try:
            return await _register(state, networks)
        except control_plane.RegistrationRejected:
            return None
        except (httpx.HTTPError, OSError) as exc:
            logger.error(
                "Cannot reach Ares at %s: %s.%s Retrying in %ds.",
                settings.base_url,
                exc,
                _tls_hint(exc),
                _REGISTER_RETRY_SECONDS,
            )
            await asyncio.sleep(_REGISTER_RETRY_SECONDS)


async def _adopt_new_token(state: AgentState, networks: list[str], presented: str) -> AgentState:
    """Present an ARES_TOKEN this identity was not minted from; keep the identity if it fails.

    Non-destructive: the register call builds a brand-new state and is itself the only thing
    that persists one, so a refusal leaves the working credentials exactly as they were.
    """
    legacy = state.registration_token_fingerprint is None
    logger.info(
        "ARES_TOKEN is not the token this agent enrolled with; presenting it%s.",
        " (this identity predates token binding, so it may well be the original one)"
        if legacy
        else "",
    )
    adopted = await _register_with_retries(AgentState(), networks)
    if adopted is not None:
        logger.warning(
            "Re-enrolled as a new agent %s. The previous identity %s is retired: it stops "
            "heartbeating now and goes offline in the dashboard.",
            adopted.agent_id,
            state.agent_id,
        )
        return adopted
    # The token is spent. Record it against the identity we are keeping so the next restart does
    # not repeat this call, then carry on serving - these credentials still work.
    state.registration_token_fingerprint = fingerprint(presented)
    save_state(settings.state_path, state)
    if legacy:
        # Almost certainly the token that enrolled this very agent, re-supplied by an ordinary
        # restart of a container that predates the fingerprint. Nothing is wrong; say so quietly
        # rather than alarming every agent in a fleet on the day it upgrades.
        logger.info(
            "That token is already spent, which is expected for an agent that enrolled before "
            "this version; continuing as agent %s.",
            state.agent_id,
        )
    else:
        logger.warning(
            "Keeping the existing agent identity %s: the supplied ARES_TOKEN is already spent, "
            "so this host could not enrol as a new agent. Generate a fresh token in the Ares "
            "dashboard, or re-run the installer with ARES_RESET=1 to discard this identity.",
            state.agent_id,
        )
    return state


async def _enroll(networks: list[str]) -> AgentState | None:
    """Return a registered state, re-using the stored identity or enrolling with ARES_TOKEN.

    Three kinds of start arrive here:

    * A first install has no stored identity, and enrolls.
    * An ordinary restart - including the one the auto-update companion performs, which copies
      the container's env verbatim - carries an identity minted from the same ARES_TOKEN, and
      simply keeps it. No register call, so a version bump can never mint a duplicate agent.
    * An operator re-running the installer on this host with the token for a *new* agent carries
      an identity bound to a different token. That token gets presented, because the alternative
      (what this did before) is to discard it in silence and go on heartbeating as the old agent
      while the newly provisioned one sits at "Offline, never" in the dashboard forever.

    Returns None only when a *first* enrollment is refused, which is fatal and the caller
    surfaces to the operator. A refused re-enrollment is not fatal: the stored identity still
    works, so the agent keeps serving under it and says so.
    """
    state = load_state(settings.state_path)
    presented = settings.token.get_secret_value()
    if not state.registered:
        enrolled = await _register_with_retries(state, networks)
        if enrolled is None:
            logger.error(
                "Registration token rejected (expired or already used). "
                "Generate a fresh token in the Ares dashboard."
            )
        return enrolled
    # No token to compare against (a hand-run container that supplies none) leaves the stored
    # identity untouched, exactly as before.
    if not presented or state.minted_with(presented):
        return state
    return await _adopt_new_token(state, networks, presented)


async def _reenroll(networks: list[str]) -> AgentState | None:
    """Mint a fresh identity with ARES_TOKEN after the stored credentials were rejected.

    Non-destructive by design: this enrolls into a brand-new state and only persists it on
    success, so the caller can keep the existing credentials if this fails. It succeeds only
    when ARES_TOKEN is still an unused, valid registration token. It returns None when the token
    is already spent (a decommissioned agent, or a healthy agent that merely hit a transient
    401) or Ares is unreachable, so a blanket 401 never strands the agent on a one-time token.

    This is the reactive half of the pair: it recovers an agent whose *stored token* stopped
    being accepted. The proactive half is :func:`_adopt_new_token`, which notices at startup
    that a different registration token was supplied and never waits for a 401 - the kept-volume
    re-install produces no 401 at all, because the old credentials remain perfectly valid.
    """
    try:
        return await _register(AgentState(), networks)
    except control_plane.RegistrationRejected:
        return None
    except (httpx.HTTPError, OSError) as exc:
        logger.debug("re-enrollment could not reach Ares: %s", exc)
        return None


async def _serve(state: AgentState, tunnel: TunnelManager) -> None:
    """Run the heartbeat and task-poll loops until one exits. If either raises (e.g. the
    heartbeat raises _AuthInvalidated on a sustained 401), cancel its sibling and re-raise
    so the caller decides whether to re-enroll or shut down.

    A watchdog task runs alongside the loops: if the agent has no successful contact with Ares for
    ``max_offline_seconds`` it exits the process so the container restarts fresh. Reset the liveness
    clock here so each serving session (including one entered after a re-enroll) starts with a full
    grace window rather than inheriting a stale timestamp."""
    _liveness["last_contact"] = time.monotonic()
    tasks = {
        asyncio.create_task(_heartbeat_loop(state, tunnel)),
        asyncio.create_task(_redetect_loop(tunnel)),
        asyncio.create_task(_poll_loop(state)),
        asyncio.create_task(_watchdog_loop()),
    }
    try:
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_EXCEPTION)
    except asyncio.CancelledError:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        raise
    for task in pending:
        task.cancel()
    await asyncio.gather(*pending, return_exceptions=True)
    for task in done:
        exc = task.exception()
        if exc is not None:
            raise exc


async def run() -> int:
    _configure_logging()
    if not settings.token.get_secret_value():
        logger.error(
            "ARES_TOKEN is required. Generate a registration token in the Ares dashboard "
            "(Settings -> Agents) and pass it as -e ARES_TOKEN=..."
        )
        return 1
    if settings.insecure and not _insecure_allowed(settings.base_url):
        logger.error(
            "ARES_INSECURE=true skips TLS verification and is only allowed for local / staging "
            "URLs, not %s. Refusing to start.",
            settings.base_url,
        )
        return 1

    settings.data_dir.mkdir(parents=True, exist_ok=True)
    _resolve_scan_limits()
    # Say which CAs we trust *before* anything can fail on one, so `docker logs` answers "did it
    # see my corporate root?" up front rather than leaving an operator to infer it from a
    # verification error.
    trust = tlsconf.build_trust(insecure=settings.insecure, ca_bundle=settings.ca_bundle)
    logger.info("TLS trust: %s", trust.summary())
    # Same reasoning as the TLS line above: a pin silently not being picked up is exactly the
    # failure that wastes an afternoon, so say what we loaded before anything can depend on it.
    global _host_pins
    pins = HostPins(aliases=settings.host_aliases)
    _host_pins = pins
    logger.info("Host pins: %s", pins.summary())
    # The subnets this agent is ATTACHED to, which is cheap and instant. Reachability discovery is
    # deliberately NOT awaited here: on the default scope it reaches across the customer's private
    # space and takes minutes, and blocking enrollment on it would leave a freshly installed agent
    # reading "Offline, never" in the dashboard for the whole of that. It runs as a background task
    # instead (_redetect_loop) and reports through the heartbeat, so the agent is online in seconds
    # and its scope widens underneath it as discovery finishes.
    # Same reasoning again: ARES_NETWORKS is the hard ceiling _authorized_target enforces, so an
    # entry it cannot parse silently shrinks that ceiling. Name it here rather than leaving an
    # operator to work it out from refused tasks.
    _warn_unparseable_networks()
    networks = settings.network_overrides() or netdetect.scan_targets(settings.scan_scope)
    if not networks:
        logger.warning(
            "No internal LAN auto-detected and ARES_NETWORKS is unset; registering with no "
            "networks. Set ARES_NETWORKS=10.0.0.0/24,... or edit them in the dashboard."
        )
    else:
        logger.info("Scanning networks (scope=%s): %s", settings.scan_scope, ", ".join(networks))

    state = await _enroll(networks)
    if state is None:
        return 1

    await _preflight(state, trust.context)

    # Serve forever, self-healing across credential rejections. A sustained 401 means the
    # stored token was rejected (stale kept-volume creds, or a decommissioned agent); we try
    # to re-enroll with ARES_TOKEN but never discard the current credentials first, and never
    # exit the process over it. Re-enrollment replaces the identity only on success (a fresh,
    # unused token), so a transient 401 on a healthy agent recovers on its own and a spent
    # token leaves the agent intact rather than crash-looping.
    while True:
        tunnel = TunnelManager(
            tunnel_url(settings.base_url),
            state.agent_token or "",
            networks,
            ssl_context=trust.context,
            pins=pins,
        )
        try:
            await _serve(state, tunnel)
        except _AuthInvalidated:
            logger.warning(
                "Control plane rejected the stored agent credentials; attempting to "
                "re-enroll with ARES_TOKEN."
            )
            reenrolled = await _reenroll(networks)
            if reenrolled is not None:
                state = reenrolled
                logger.info("Re-enrolled with a fresh agent identity.")
            else:
                logger.error(
                    "Could not re-enroll: the registration token is spent or Ares is "
                    "unreachable. Keeping the current credentials and retrying. If this agent "
                    "was decommissioned, stop the container; to give it a new identity, "
                    "redeploy with a fresh ARES_TOKEN."
                )
                await asyncio.sleep(_REENROLL_RETRY_SECONDS)
        else:
            return 0  # both loops ended without error: nothing left to do
        finally:
            tunnel.stop()


def main() -> None:
    try:
        raise SystemExit(asyncio.run(run()))
    except KeyboardInterrupt:
        sys.exit(0)


if __name__ == "__main__":
    main()
