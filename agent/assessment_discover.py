"""Turn a verified discover job into a signed, control-plane-shaped discovery result.

This is the agent half of the Network Assessment discover step (ARES-2230 / PR-07). The flow around
it is: ``main._run_task`` verifies the signed job with ``assessment.open_signed_job`` (agent-first,
before any target field is read), then this module RE-DERIVES the scope from the verified job, the
caller runs bounded TCP discovery over exactly that scope, and ``build_discover_result`` assembles a
``DiscoverResultV1``-shaped payload bound back to the job, which ``assessment.seal_result`` signs.

Nothing here opens a socket or reads the clock: the probing and timing live in the task wiring, so
the scope re-derivation and the result assembly stay pure and unit-testable. The result shape must
match ``ares.domain.assessment.results.DiscoverResultV1`` exactly (``extra="forbid"`` on the control
plane), so the constructors below emit only the allowed keys. The cross-repo golden-fixture round
trip (ARES-2214) is the standing guard that these two definitions stay in step.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, replace

# The envelope schema and signature domain a discover RESULT is sealed under. These mirror
# ``results.SCHEMA_DISCOVER_RESULT_V1`` and ``results.SIGN_DOMAIN_DISCOVER_RESULT`` on the control
# plane; a mismatch makes every result fail schema/signature verification at ingestion, so they are
# pinned here and covered by the cross-repo fixture round trip.
RESULT_SCHEMA = "ares.network-assessment.result.discover.v1"
RESULT_DOMAIN = "ares.network-assessment.result.discover:v1"

_MAX_PORT = 65535

# The binding and probe fields a verified job must carry for the agent to act on it. Re-derivation
# refuses a job missing any of them rather than probing with a defaulted scope. The destination
# fields (``target_cidrs`` / ``target_hosts``) are NOT here because a job carries one kind or the
# other; ``derive_scope`` checks that at least one destination is present after parsing.
_REQUIRED_JOB_FIELDS = (
    "tenant_id",
    "assessment_id",
    "snapshot_id",
    "scope_revision_sha256",
    "agent_id",
    "job_id",
    "nonce",
    "tcp_ports",
)

# The ``address_policy`` token (mirror of ares.domain.assessment.enums.NetworkAddressPolicy) that
# holds every resolved destination to globally-routable space. Any other value, or its absence, is
# the internal rule (private space allowed), so an unrecognised token fails closed to the safer lane.
_PUBLIC_ONLY_POLICY = "public_only"


def _is_globally_routable(
    address: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> bool:
    """Whether ``address`` is a globally-routable unicast address a third party could own.

    The public-host lane's address rule, enforced at the agent. The control plane authorizes the host
    NAME syntactically; this is the dial-time belt that the address it actually resolved to is genuinely
    public, so a name that points into private space (the MEDIUM-067 shape) is refused rather than swept
    as an internal port scan. ``ipaddress.is_global`` already answers False for private, loopback,
    link-local (incl. the cloud metadata address), unspecified, shared-address-space and reserved
    ranges; multicast is excluded explicitly because a unicast sweep never has a destination there.
    """
    return address.is_global and not address.is_multicast

# NetworkObservationOutcome values (mirror of ares.domain.assessment.enums). A probe outcome outside
# this set is a bug in the mapping, not something to pass through to the signed result.
_OUTCOMES = frozenset(
    {
        "open",
        "refused",
        "filtered_or_timeout",
        "indeterminate",
        "resolution_failed",
        "out_of_scope",
        "cancelled",
        "internal_error",
    }
)

# NetworkCoverageState values (mirror of ares.domain.assessment.enums).
_COVERAGE_STATES = frozenset(
    {
        "assessed",
        "not_assessed",
        "unavailable",
        "unsupported",
        "prohibited",
        "skipped",
        "inconclusive",
    }
)


def parse_port_spec(spec: str) -> list[int]:
    """Expand a port spec (``"1-1023"``, ``"22,23,443"``) into a sorted list of distinct ports, or
    raise ``ValueError``.

    This MUST stay byte-identical in behaviour to ``ares.domain.assessment.tasks.parse_port_spec``
    on the control plane: the same spec bounds the task there and drives the probes here, so a drift
    would make the agent probe a different port set than the one the signed job authorised. Nothing
    checks that across the two repositories, so keep them in step by hand.
    """
    ports: set[int] = set()
    for raw_part in spec.split(","):
        part = raw_part.strip()
        if not part:
            continue
        if "-" in part:
            low_s, high_s = part.split("-", 1)
            low, high = int(low_s), int(high_s)
            if not (1 <= low <= high <= _MAX_PORT):
                raise ValueError(f"port range out of bounds: {part!r}")
            ports.update(range(low, high + 1))
        else:
            port = int(part)
            if not (1 <= port <= _MAX_PORT):
                raise ValueError(f"port out of bounds: {part!r}")
            ports.add(port)
    if not ports:
        raise ValueError("port spec selected no ports")
    return sorted(ports)


@dataclass(frozen=True, slots=True)
class DiscoverScope:
    """The concrete scope the agent re-derived from a verified job: which networks to probe, which
    to exclude, and on which ports. ``in_scope`` is the one gate every destination passes before a
    socket is opened, so an address outside the frozen scope (or inside an exclude) is never dialed
    even if the scanner is handed a wider range."""

    networks: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]
    excludes: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]
    ports: tuple[int, ...]
    # The bounded UDP operations the verified job asked for (e.g. the SNMP default-community probe).
    # A trailing field with a default, so existing constructions and the TCP-only path are unchanged.
    udp_operations: tuple[str, ...] = ()
    # The host NAMES a public-host job asks the agent to resolve and sweep (empty for the internal
    # CIDR lane). ``fold_resolved_hosts`` turns the resolved, vetted addresses into ``networks``.
    target_hosts: tuple[str, ...] = ()
    # When True (the public-host lane), a destination must be globally routable on TOP of being in a
    # network. Belt-and-suspenders with the resolution vetting, so a bug or a non-global /32 that ever
    # reached ``networks`` is still never dialed.
    public_only: bool = False

    def in_scope(self, ip: str) -> bool:
        """Whether ``ip`` is inside a target network AND outside every exclude (AND, on the public-host
        lane, globally routable). Fails closed on an address that does not parse."""
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            return False
        if not any(address in network for network in self.networks):
            return False
        if any(address in exclude for exclude in self.excludes):
            return False
        return not (self.public_only and not _is_globally_routable(address))


def derive_scope(job: dict) -> DiscoverScope:
    """Re-derive the probe scope from a VERIFIED job, or raise ``ValueError``.

    The agent trusts the signed job for its scope, never ambient config: it parses the job's own
    ``target_cidrs`` / ``exclude_cidrs`` / ``tcp_ports`` and nothing else. Called only after the
    signature has verified, so a malformed field here is a contract violation, not attacker input.
    """
    missing = [field for field in _REQUIRED_JOB_FIELDS if field not in job]
    if missing:
        raise ValueError(
            f"verified job missing required field(s): {', '.join(missing)}"
        )
    networks = tuple(
        ipaddress.ip_network(cidr, strict=False) for cidr in job.get("target_cidrs", [])
    )
    excludes = tuple(
        ipaddress.ip_network(cidr, strict=False)
        for cidr in job.get("exclude_cidrs", [])
    )
    target_hosts = tuple(
        host.strip()
        for host in job.get("target_hosts", [])
        if isinstance(host, str) and host.strip()
    )
    if not networks and not target_hosts:
        raise ValueError("verified job has no target networks or hosts")
    ports = tuple(parse_port_spec(job["tcp_ports"]))
    udp_operations = tuple(
        op for op in job.get("udp_operations", []) if isinstance(op, str) and op
    )
    public_only = job.get("address_policy") == _PUBLIC_ONLY_POLICY
    return DiscoverScope(
        networks=networks,
        excludes=excludes,
        ports=ports,
        udp_operations=udp_operations,
        target_hosts=target_hosts,
        public_only=public_only,
    )


def fold_resolved_hosts(
    scope: DiscoverScope, resolved: dict[str, list[str]]
) -> tuple[DiscoverScope, list[dict]]:
    """Fold a public-host scope's RESOLVED addresses into its networks, returning the new scope and the
    coverage entries for every host or address that was refused.

    ``resolved`` maps each ``scope.target_hosts`` name to the addresses it answered with (the agent's
    DNS step produced it; this function is pure so it is unit-testable without a resolver). Each
    globally-routable address becomes a ``/32`` / ``/128`` network the existing probe path sweeps;
    a non-global address is dropped with a ``prohibited`` coverage note (``read_host`` on the control
    plane already refused an obviously-private target, so this catches a name that resolves into
    private space at dial time), and a name that answered with nothing gets an ``unavailable`` note.
    Honest coverage: a refused or unresolved host is recorded, never silently swept to an empty result.
    """
    if not scope.target_hosts:
        return scope, []
    pinned: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    coverage: list[dict] = []
    for host in scope.target_hosts:
        addresses = resolved.get(host, [])
        if not addresses:
            coverage.append(
                coverage_entry(scope=host, state="unavailable", reason_code="resolution_failed")
            )
            continue
        host_pinned = 0
        for raw in addresses:
            try:
                address = ipaddress.ip_address(raw)
            except ValueError:
                continue
            if scope.public_only and not _is_globally_routable(address):
                coverage.append(
                    coverage_entry(
                        scope=host, state="prohibited", reason_code="non_global_address"
                    )
                )
                continue
            pinned.append(ipaddress.ip_network(address))
            host_pinned += 1
        if host_pinned == 0 and not any(
            entry["scope"] == host and entry["state"] == "prohibited" for entry in coverage
        ):
            coverage.append(
                coverage_entry(scope=host, state="unavailable", reason_code="resolution_failed")
            )
    folded = replace(scope, networks=(*scope.networks, *pinned))
    return folded, coverage


def service_observation(
    *,
    address: str,
    port: int,
    transport: str,
    outcome: str,
    protocol_id: str | None = None,
    banner_sha256: str | None = None,
    capabilities: tuple[str, ...] = (),
) -> dict:
    """One ``DiscoveredService`` entry, validated to the exact shape the control plane admits. The
    outcome is kept honest (a timeout is not a refusal is not open); ``protocol_id`` /
    ``banner_sha256`` are set only when a specialist actually read something, never inferred from
    the port. ``capabilities`` are the tokens an active specialist read (SMTP EHLO, FTP FEAT), empty
    when no specialist ran or none was read, so the absence of one is never read as a finding."""
    if transport not in ("tcp", "udp"):
        raise ValueError(f"transport must be tcp or udp, not {transport!r}")
    if not (1 <= port <= _MAX_PORT):
        raise ValueError(f"port out of bounds: {port!r}")
    if outcome not in _OUTCOMES:
        raise ValueError(f"unknown observation outcome: {outcome!r}")
    return {
        "address": address,
        "port": port,
        "transport": transport,
        "outcome": outcome,
        "protocol_id": protocol_id,
        "banner_sha256": banner_sha256,
        "capabilities": list(capabilities),
    }


def coverage_entry(*, scope: str, state: str, reason_code: str | None = None) -> dict:
    """One ``DiscoverCoverageEntry`` recording why a planned probe did or did not run, so the result
    carries honest gaps rather than an implied clean sweep."""
    if state not in _COVERAGE_STATES:
        raise ValueError(f"unknown coverage state: {state!r}")
    return {"scope": scope, "state": state, "reason_code": reason_code}


# A real host exposes a handful of ports; when nearly every probed TCP port on one address answers
# OPEN, the cause is an intermediary completing the handshake (a SYN-proxying NAT, a load balancer, a
# tarpit firewall) in front of the host, not the host, so the "open" list is a measurement artifact.
# This mirrors the recon port-sweep's saturation guard (ares/agents/recon/port_sweep.py): reporting
# nothing is far better than a false inventory of thousands of open ports, which reads as a
# catastrophic exposure rather than an artifact. The minimum probe count keeps a small, targeted
# sweep (where every requested port legitimately answering is ordinary) from ever tripping it.
_SATURATION_RATIO = 0.5
_SATURATION_MIN_TCP_PROBES = 100


def guard_saturated_inventory(
    services: list[dict], coverage: list[dict]
) -> tuple[list[dict], list[dict]]:
    """Drop the OPEN TCP observations of any address whose open fraction is implausibly high (a path
    answering, not the host), replacing them with one INCONCLUSIVE coverage entry per such address.
    Refused/filtered observations and every UDP observation pass through unchanged, as does a host
    below the minimum probe count. Pure: the same input always yields the same output."""
    by_address_tcp: dict[str, list[dict]] = {}
    for svc in services:
        if svc.get("transport") == "tcp":
            by_address_tcp.setdefault(svc["address"], []).append(svc)
    saturated = {
        address
        for address, tcp in by_address_tcp.items()
        if len(tcp) >= _SATURATION_MIN_TCP_PROBES
        and sum(1 for s in tcp if s.get("outcome") == "open")
        > len(tcp) * _SATURATION_RATIO
    }
    if not saturated:
        return services, coverage
    kept = [
        svc
        for svc in services
        if not (
            svc.get("address") in saturated
            and svc.get("transport") == "tcp"
            and svc.get("outcome") == "open"
        )
    ]
    extra = [
        coverage_entry(
            scope=address,
            state="inconclusive",
            reason_code="tcp_port_inventory_saturated",
        )
        for address in sorted(saturated)
    ]
    return kept, coverage + extra


def build_discover_result(
    job: dict,
    *,
    services: list[dict],
    coverage: list[dict],
    completed_at: str,
    partial: bool = False,
) -> dict:
    """Assemble a ``DiscoverResultV1``-shaped payload bound back to the verified job.

    The binding (tenant / assessment / snapshot / scope revision / agent / job / nonce) is carried
    straight through from the job the control plane dispatched, so ingestion can check the result
    names the exact job and snapshot it signed. ``partial`` is True when a budget or cancellation
    ended the job before every planned probe ran; its coverage then records the gap. The saturation
    guard runs here so no caller can assemble a result that reports a path-answering false inventory.
    """
    services, coverage = guard_saturated_inventory(services, coverage)
    return {
        "tenant_id": job["tenant_id"],
        "assessment_id": job["assessment_id"],
        "snapshot_id": job["snapshot_id"],
        "scope_revision_sha256": job["scope_revision_sha256"],
        "agent_id": job["agent_id"],
        "job_id": job["job_id"],
        "nonce": job["nonce"],
        "completed_at": completed_at,
        "services": list(services),
        "coverage": list(coverage),
        "partial": partial,
    }
