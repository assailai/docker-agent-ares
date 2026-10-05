"""Portable async TCP-connect scanner for ``local_network_scan`` tasks.

Deliberately dependency-free (no masscan, no root, no raw sockets) so the agent runs
anywhere a container can, and so the control-plane loop is testable on a laptop.

Two phases keep it quick at /16 scale. Phase 1 probes a few common ports across every host to
see which answer at all -- a connect or a refusal both mean the host is up, only a timeout or
unreachable means it is not. Phase 2 then sweeps the full port list against just the live hosts,
so the dead majority of a large range costs a handful of probes rather than the whole list. The
range is walked a /24 at a time, and progress and discovered hosts come back through optional
callbacks so the control plane can show a live percentage.

An optional third phase asks the live hosts what they are called (see :mod:`agent.identify`). It
runs once, after the whole range has been swept, and not per /24: naming a host means handshakes
and request/response round trips, so folding it into a chunk would serialise it behind the next
chunk's sweep and make its cost scale with how many /24s the range spans rather than with how many
hosts are actually live. On a /16 that is the difference between paying it 256 times and once.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import time
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, field

from agent.identify import IdentityProbe

logger = logging.getLogger("ares.agent.scan")

# curated ~120 TCP ports for internal networks: web, databases, remote access, file shares,
# mail, message queues, admin panels. 3000 covers Juice Shop / Grafana-style dev apps.
#
# MUST stay in step with ``_DEFAULT_SCAN_PORTS`` in the ares repo, which is the list actually sent
# on every task; this one only applies when the server sends none. Nothing checks that across two
# repositories, so a port added here without being added there simply never gets scanned.
#
# Every port added here also needs an entry in ``_COMMON_SERVICES`` below. Without one it is
# labelled "unknown", and the naming pass treats unknown ports as fair game for a TLS handshake and
# a GET, which is how a device that should never receive application-layer bytes ends up with some.
TOP_PORTS: tuple[int, ...] = (
    21, 22, 23, 25, 26, 37, 53, 80, 81, 88, 110, 111, 113, 119, 135, 139, 143, 161, 179, 199,
    389, 427, 443, 444, 445, 465, 513, 514, 515, 543, 544, 548, 554, 587, 623, 631, 636, 873,
    902, 990, 993, 995, 1025, 1080, 1099, 1433, 1521, 1723, 2049, 2082, 2083, 2181, 2222, 2375,
    2376, 2379, 3000, 3001, 3128, 3268, 3306, 3307, 3389, 3690, 4200, 4444, 5000, 5001, 5432,
    5433, 5480, 5601, 5672, 5900, 5984, 5985, 5986, 6379, 6380, 6443, 7001, 7687, 8000, 8001,
    8006, 8008, 8009, 8080, 8081, 8086, 8088, 8090, 8123, 8180, 8181, 8443, 8500, 8880, 8888,
    8983, 9000, 9042, 9090, 9091, 9100, 9160, 9200, 9300, 9418, 9443, 10000, 10250, 11211,
    15672, 27017, 27018, 27019, 50000,
)
# lean liveness set for phase 1: the ports most likely to answer on some host in a range.
DISCOVERY_PORTS: tuple[int, ...] = (80, 443, 22, 445, 3389, 8080)
# the port list a task sweeps when the control plane sends none (server usually overrides).
DEFAULT_PORTS: tuple[int, ...] = TOP_PORTS
# hosts are scanned a /24 at a time: the natural unit, and small enough to bound memory.
CHUNK_PREFIX = 24
# safety ceiling on hosts in a single task. A full /16 (~65k) is well within this; a scope that
# resolves to something enormous (e.g. an explicit 10/8) is truncated -- and *logged*, never
# silently -- rather than exhausting the box.
MAX_HOSTS = 262_144  # a /14
# fast per-connect timeout for the phase-1 liveness sweep (dead hosts cost only this).
DEFAULT_DISCOVERY_TIMEOUT = 0.5

_COMMON_SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http", 88: "kerberos",
    110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn", 143: "imap", 161: "snmp",
    389: "ldap", 443: "https", 445: "smb", 465: "smtps", 514: "syslog", 515: "printer",
    548: "afp", 554: "rtsp", 587: "submission", 623: "ipmi", 631: "ipp", 636: "ldaps",
    873: "rsync", 902: "vmware", 990: "ftps", 993: "imaps", 995: "pop3s", 1080: "socks",
    1099: "java-rmi", 1433: "mssql", 1521: "oracle", 1723: "pptp", 2049: "nfs", 2181: "zookeeper",
    2222: "ssh-alt", 2375: "docker", 2376: "docker-tls", 2379: "etcd", 3000: "http-dev",
    3001: "http-dev", 3128: "squid", 3268: "ldap-gc", 3306: "mysql", 3389: "rdp", 3690: "svn", 4444: "metasploit",
    5000: "http-alt", 5001: "http-alt", 5432: "postgres", 5601: "kibana", 5672: "amqp",
    5900: "vnc",
    5984: "couchdb", 5985: "winrm", 5986: "winrm-tls", 6379: "redis", 6443: "kubernetes-api",
    7001: "weblogic", 8000: "http-alt", 8001: "http-alt", 8008: "http-alt", 8009: "ajp",
    8080: "http-proxy",
    8081: "http-alt", 8088: "http-alt", 8180: "http-alt", 8443: "https-alt", 8500: "consul",
    8888: "http-alt", 9000: "http-alt", 9042: "cassandra", 9092: "kafka", 9200: "elasticsearch",
    9300: "elasticsearch", 9418: "git", 10000: "webmin", 11211: "memcached", 15672: "rabbitmq",
    27017: "mongodb", 27018: "mongodb", 50000: "sap",
    # alternates and second instances of things already above
    3307: "mysql", 5433: "postgres", 6380: "redis", 9160: "cassandra-thrift", 27019: "mongodb",
    # datastores and search indexes
    7687: "neo4j", 8086: "influxdb", 8123: "clickhouse", 8983: "solr",
    # web and app surfaces people actually publish containers on
    4200: "http-dev", 8090: "http-alt", 8181: "http-alt", 8880: "http-alt", 9090: "http-alt",
    9091: "http-alt", 9443: "https-alt",
    # management planes. jetdirect is labelled so the naming pass leaves it alone: 9100 prints
    # whatever it is sent, and an unlabelled port is one the fallback would probe.
    5480: "vmware-vami", 8006: "proxmox", 9100: "jetdirect", 10250: "kubelet",
    # ports that were swept but never labelled. Left unlabelled they read as "unknown", which the
    # naming pass takes as an invitation to try a handshake and a GET, and a routing daemon or an
    # rlogin service has no business receiving either. The genuinely web ones are typed as such so
    # they still get looked at.
    26: "smtp-alt", 37: "time", 81: "http-alt", 113: "ident", 119: "nntp", 179: "bgp",
    199: "smux", 427: "svrloc", 444: "snpp", 513: "rlogin", 543: "klogin", 544: "kshell",
    1025: "rpc-alt", 2082: "http-alt", 2083: "https-alt",
}

ProgressCallback = Callable[[int], Awaitable[None]]
HostsCallback = Callable[[list[dict]], Awaitable[None]]
IdentityCallback = Callable[[list[dict]], Awaitable[None]]

# identity probing (phase 3) runs far narrower than the connect sweep: these are handshakes and
# request/response round trips, not one-packet connects, so the sweep's thousands-wide concurrency
# would be a burst of real sessions against the customer's estate. It is also the cap that keeps
# reverse DNS from pinning asyncio's shared thread pool (see agent.identify.reverse_dns).
IDENTITY_CONCURRENCY = 64
# share of a scan's overall budget that naming may spend. Worth having, but never at the cost of
# the port results themselves: once this is gone, the remaining hosts report without a name.
IDENTITY_BUDGET_SHARE = 0.25
# hosts per streamed batch of names. Matches the concurrency limit, so each batch is one full
# sweep of the semaphore and names reach the dashboard roughly every round trip.
_IDENTITY_BATCH = IDENTITY_CONCURRENCY
# where the port sweep's progress stops when naming is enabled, leaving the rest of the bar for the
# naming pass. Otherwise a scan reports 100% and then keeps working, which reads as stuck.
_SWEEP_PROGRESS_CEILING = 90


def naming_allowance(budget_seconds: float | None) -> float | None:
    """How long the naming pass may spend within a scan's budget, or ``None`` when unbounded."""
    return budget_seconds * IDENTITY_BUDGET_SHARE if budget_seconds is not None else None


def _service_for(port: int) -> str:
    return _COMMON_SERVICES.get(port, "unknown")


def _hit(ip: str, port: int) -> dict:
    return {
        "ip": ip,
        "port": port,
        "service": _service_for(port),
        "protocol": "tcp",
        "evidence": f"tcp connect succeeded on {ip}:{port}",
    }


async def _connect(ip: str, port: int, timeout: float) -> str:
    """Classify a single TCP connect attempt.

    ``"open"``   -- connected (a live service);
    ``"closed"`` -- refused via RST (the host is up, this port just isn't listening);
    ``"down"``   -- timed out or unreachable (no answer).

    Both ``open`` and ``closed`` prove the host is alive, which is what phase 1 needs.
    """
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
    except (asyncio.TimeoutError, TimeoutError):
        return "down"
    except ConnectionRefusedError:
        return "closed"
    except OSError:
        # EHOSTUNREACH / ENETUNREACH / EADDRNOTAVAIL and friends: treat as no answer.
        return "down"
    try:
        writer.close()
        await writer.wait_closed()
    except OSError:
        pass
    return "open"


def _naming_progress(*, done: int, total: int) -> int:
    """Where the bar sits during the naming pass, which owns everything above the sweep's ceiling."""
    return _SWEEP_PROGRESS_CEILING + int(done * (100 - _SWEEP_PROGRESS_CEILING) / total)


def _usable_count(net: ipaddress.IPv4Network) -> int:
    """How many host addresses a chunk actually scans (mirrors ``list(net.hosts())`` length)."""
    if net.prefixlen >= 31:  # /31 and /32 have no network/broadcast to exclude
        return net.num_addresses
    return net.num_addresses - 2


def _chunk_hosts(net: ipaddress.IPv4Network) -> list[str]:
    hosts = [str(h) for h in net.hosts()]
    if not hosts:  # a bare host address (/32) has no "hosts"; scan it directly.
        hosts = [str(net.network_address)]
    return hosts


def _plan_chunks(
    cidr: str, *, chunk_prefix: int, max_hosts: int
) -> tuple[list[ipaddress.IPv4Network], int]:
    """Split ``cidr`` into <= /``chunk_prefix`` chunks, capped at ``max_hosts`` total hosts.

    Returns ``(chunks, total_hosts)``. Truncation is logged, never silent.
    """
    network = ipaddress.ip_network(cidr, strict=False)
    if not isinstance(network, ipaddress.IPv4Network):
        raise ValueError(f"only IPv4 ranges are supported, got {cidr}")
    if network.prefixlen < chunk_prefix:
        candidates = network.subnets(new_prefix=chunk_prefix)
    else:
        candidates = iter((network,))

    chunks: list[ipaddress.IPv4Network] = []
    total = 0
    for chunk in candidates:
        usable = max(_usable_count(chunk), 1)
        if total + usable > max_hosts:
            logger.warning(
                "%s exceeds the %d-host scan cap; scanning the first %d hosts only.",
                cidr,
                max_hosts,
                total,
            )
            break
        chunks.append(chunk)
        total += usable
    return chunks, total


@dataclass(slots=True)
class _Scan:
    """mutable state + phase logic for one scan_cidr run, kept off scan_cidr so the driver stays
    flat rather than a stack of stateful closures. progress is counted per host: a dead host is
    done after phase 1, a live host after its phase-2 sweep."""

    requested: set[int]
    discovery_ports: list[int]
    sweep_ports: list[int]
    timeout: float
    discovery_timeout: float
    total_hosts: int
    on_progress: ProgressCallback | None
    on_hosts: HostsCallback | None
    semaphore: asyncio.Semaphore
    on_identity: IdentityCallback | None = None
    identity: IdentityProbe | None = None
    identity_semaphore: asyncio.Semaphore | None = None
    # total wall clock the naming pass may spend. A ceiling on the phase, not a deadline measured
    # from the start of the scan, which would spend itself on the sweep and leave nothing.
    identity_allowance: float | None = None
    # every live host, its answering ports, and what each port looked like, collected across the
    # whole sweep so the naming pass can run once at the end (see identify_all). The service label
    # rides along so naming can tell "a port we could not identify" from "a database".
    live_ports: dict[str, dict[int, str]] = field(default_factory=dict)
    done: int = 0
    last_pct: int = -1

    @property
    def _sweep_ceiling(self) -> int:
        """How high the port sweep may drive the percentage.

        Naming runs after the sweep, so it needs room left on the bar. Without this the scan would
        report 100% and then keep working for another minute, which reads as a stuck scan.
        """
        return _SWEEP_PROGRESS_CEILING if self.identity is not None else 100

    async def _bounded(self, ip: str, port: int, timeout: float) -> str:
        async with self.semaphore:
            return await _connect(ip, port, timeout)

    async def _advance(self) -> None:
        ceiling = self._sweep_ceiling
        pct = min(ceiling, int(self.done * ceiling / self.total_hosts))
        await self._report(pct)

    async def _report(self, pct: int) -> None:
        if pct > self.last_pct:
            self.last_pct = pct
            if self.on_progress is not None:
                await self.on_progress(pct)

    async def _discover(self, ip: str) -> tuple[str, bool, list[dict]]:
        states = await asyncio.gather(
            *(self._bounded(ip, p, self.discovery_timeout) for p in self.discovery_ports)
        )
        alive = any(state in ("open", "closed") for state in states)
        # discovery ports drive liveness always, but count as a finding only when requested.
        open_hits = [
            _hit(ip, p)
            for p, state in zip(self.discovery_ports, states)
            if state == "open" and p in self.requested
        ]
        if not alive:
            self.done += 1
            await self._advance()
        return ip, alive, open_hits

    async def _sweep(self, ip: str) -> list[dict]:
        hits: list[dict] = []
        if self.sweep_ports:
            states = await asyncio.gather(
                *(self._bounded(ip, p, self.timeout) for p in self.sweep_ports)
            )
            hits = [_hit(ip, p) for p, state in zip(self.sweep_ports, states) if state == "open"]
        self.done += 1
        await self._advance()
        return hits

    async def _identify(self, ip: str, open_ports: set[int]) -> dict | None:
        """Ask one host what it is called, bounded by the naming semaphore.

        Returns the wire payload, or ``None`` when the host said nothing about itself. Never
        raises: a scan that found services must still report them if naming fails.
        """
        if self.identity is None or self.identity_semaphore is None:
            return None
        try:
            async with self.identity_semaphore:
                evidence = await self.identity.run(ip, open_ports)
        except Exception:  # noqa: BLE001 - naming is an enrichment, never a reason to fail a scan
            logger.debug("identity probe failed for %s", ip, exc_info=True)
            return None
        return None if evidence.is_empty() else evidence.as_payload()

    async def run_chunk(self, hosts: list[str]) -> list[dict]:
        results = await asyncio.gather(*(self._discover(ip) for ip in hosts))
        hits = [hit for _, _, open_hits in results for hit in open_hits]
        live = [ip for ip, alive, _ in results if alive]
        if live:
            swept = await asyncio.gather(*(self._sweep(ip) for ip in live))
            hits.extend(hit for host_hits in swept for hit in host_hits)
        if hits and self.on_hosts is not None:
            await self.on_hosts(sorted(hits, key=lambda d: (d["ip"], d["port"])))
        if self.identity is not None:
            # remember what to come back to. Naming deliberately does NOT run here: doing it per
            # chunk serialises it behind the next chunk's sweep, so its cost scales with the number
            # of /24s rather than with the number of live hosts (a /16 pays it 256 times over).
            #
            # only hosts with something OPEN, not every host that answered. A host that merely
            # refuses a connection is up, and phase 1 counts that as alive, but it exposes no
            # service for ares to attach a name to, so probing it would spend a PTR and a NetBIOS
            # query on evidence that gets discarded on ingest.
            for hit in hits:
                self.live_ports.setdefault(hit["ip"], {})[hit["port"]] = hit["service"]
        return hits

    async def identify_all(self) -> None:
        """Name every host the sweep found a service on, in one pass over the whole range.

        Run after the sweep rather than inside it, so the cost is set by how many hosts are live
        (a handful of concurrent batches) instead of by how many /24s the range spans. The port
        results are already reported by this point, so everything here is decoration on an
        inventory the operator can already see.

        Results stream in batches rather than arriving in one lump at the end: names appear as they
        are learned, and a scan that is killed mid-pass keeps whatever it had already sent.
        """
        if self.identity is None or not self.live_ports:
            return
        hosts = sorted(self.live_ports)
        started = time.monotonic()
        for index in range(0, len(hosts), _IDENTITY_BATCH):
            if self._naming_budget_spent(started, done=index, total=len(hosts)):
                break
            batch = hosts[index : index + _IDENTITY_BATCH]
            found = await asyncio.gather(*(self._identify(ip, self.live_ports[ip]) for ip in batch))
            payloads = [p for p in found if p is not None]
            if payloads and self.on_identity is not None:
                await self.on_identity(payloads)
            await self._report(_naming_progress(done=index + len(batch), total=len(hosts)))

    def _naming_budget_spent(self, started: float, *, done: int, total: int) -> bool:
        """Whether naming has used its allowance, saying so once when it has."""
        if self.identity_allowance is None:
            return False
        if time.monotonic() - started < self.identity_allowance:
            return False
        logger.warning(
            "Naming budget of %.0fs is spent after %d/%d host(s); the rest are reported without a "
            "name. Port results are unaffected.",
            self.identity_allowance,
            done,
            total,
        )
        return True

    async def finish(self) -> None:
        # a fully-consumed (or budget-truncated) scan always ends at 100.
        if self.on_progress is not None and self.last_pct < 100:
            await self.on_progress(100)


async def scan_cidr(
    cidr: str,
    ports: Sequence[int] | None = None,
    *,
    timeout: float = 2.0,
    discovery_timeout: float | None = None,
    concurrency: int = 512,
    max_hosts: int = MAX_HOSTS,
    chunk_prefix: int = CHUNK_PREFIX,
    discovery_ports: Sequence[int] = DISCOVERY_PORTS,
    budget_seconds: float | None = None,
    on_progress: ProgressCallback | None = None,
    on_hosts: HostsCallback | None = None,
    on_identity: IdentityCallback | None = None,
    identity: IdentityProbe | None = None,
) -> list[dict]:
    """Return discovered ``{ip, port, service, protocol, evidence}`` for open ports in ``cidr``.

    Two-phase and chunked (see the module docstring). ``on_progress(percent)`` is invoked as the
    integer percentage climbs; ``on_hosts(chunk)`` streams newly discovered hosts as each chunk
    finishes. ``budget_seconds`` is an overall soft deadline: once exceeded, no new chunk starts
    and whatever was found so far is returned (partial, logged).

    Passing ``identity`` adds a naming pass over the live hosts, streamed through
    ``on_identity(batch)``. It runs once, after the whole range has been swept, so its cost tracks
    the number of live hosts rather than the number of chunks; it is bounded separately from the
    sweep in both concurrency and time, so naming can degrade without the scan degrading with it.
    """
    port_list = list(ports) if ports else list(DEFAULT_PORTS)
    disc_list = list(discovery_ports)
    disc_set = set(disc_list)
    chunks, total_hosts = _plan_chunks(cidr, chunk_prefix=chunk_prefix, max_hosts=max_hosts)
    started = time.monotonic()
    scan = _Scan(
        requested=set(port_list),
        discovery_ports=disc_list,
        # phase 2 sweeps the requested ports phase 1 did not already probe (discovery ports that
        # are not requested drive liveness only and are never reported).
        sweep_ports=[p for p in port_list if p not in disc_set],
        timeout=timeout,
        discovery_timeout=(
            discovery_timeout if discovery_timeout is not None else min(timeout, DEFAULT_DISCOVERY_TIMEOUT)
        ),
        total_hosts=max(total_hosts, 1),
        on_progress=on_progress,
        on_hosts=on_hosts,
        semaphore=asyncio.Semaphore(max(1, concurrency)),
        on_identity=on_identity,
        identity=identity,
        identity_semaphore=(
            asyncio.Semaphore(min(IDENTITY_CONCURRENCY, max(1, concurrency)))
            if identity is not None
            else None
        ),
        identity_allowance=naming_allowance(budget_seconds) if identity is not None else None,
    )

    discovered: list[dict] = []
    for index, chunk in enumerate(chunks):
        if budget_seconds is not None and time.monotonic() - started > budget_seconds:
            logger.warning(
                "Scan budget of %.0fs exceeded after %d/%d chunks of %s; returning partial results.",
                budget_seconds,
                index,
                len(chunks),
                cidr,
            )
            break
        discovered.extend(await scan.run_chunk(_chunk_hosts(chunk)))

    # the sweep is done and every port hit has been reported; now go back and name what is live.
    await scan.identify_all()
    await scan.finish()
    discovered.sort(key=lambda d: (d["ip"], d["port"]))
    return discovered
