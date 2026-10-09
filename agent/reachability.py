"""Find every private network this agent can actually reach, not just the one it is attached to.

The problem this exists for. Auto-detection used to read the host's interfaces and widen each
attached subnet to its enclosing /16 (``netdetect.apply_scope``). On an agent sitting on
172.23.104.x that advertises exactly ``172.23.0.0/16``, and a customer running half their estate on
10.20.x.x has a scan that reports 1,159 hosts and misses every one of them. The interface says
where the agent IS. It says nothing about where the agent can GO, which in a routed corporate
network is almost everything else.

Three sources answer the second question, in ascending order of cost:

1. **Attached subnets** (``netdetect``). On-link by definition, and already how the agent works.
2. **The routing table.** Every private destination the kernel holds a route for, whether on-link
   or via a gateway. This is free (the kernel already knows) and it is exactly the customer case: a
   static route pointing 10.20.0.0/16 at the corporate router. Its blind spot is the standard
   bridge-networked container, whose routing table describes its own bridge and a default route,
   because the container has its own network namespace. That blind spot is the whole reason for 3.
3. **An active reachability probe** across private space. Regardless of what any table says, the
   agent can just *try* a few addresses in each candidate /24 and see what answers. A connect or a
   refusal both prove something is there and routed; only silence means nothing is. This works
   identically in a bridge-networked container, under host networking, and in Kubernetes, because
   it tests reachability rather than inferring it.

**What the probe costs, and why it is shaped this way.** Private space is 86,272 /24s once RFC 6598
carrier-NAT space is included, and probing every one of them densely would be millions of connects.
So it goes in two stages. Stage 1 samples every /24 thinly, which is cheap and finds anything with
a gateway or a server on a common address. Stage 2 goes back over the /16s stage 1 found ANY life
in and samples their /24s densely, which is what catches a sparse VLAN sitting in an otherwise
populated range. An estate is clustered, so this buys most of the depth of a dense sweep for a
fraction of a dense sweep's packets. Both stages are bounded by one wall-clock budget and report
what they did not get to, so a slow network yields a partial map and says so rather than running
until something kills it.

Nothing here sends application-layer bytes: it is TCP connect and immediate close, the same probe
``agent.scan`` phase 1 already uses. The result is a set of CIDRs to advertise and scan, and the
scan is what actually enumerates the hosts.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import subprocess
import time
from collections.abc import Iterable, Iterator

logger = logging.getLogger("ares.agent.reachability")

#: The private space a probe considers. RFC 1918 plus RFC 6598 shared address space, which is not
#: RFC 1918 and is not internet-routable either: carriers use it for CGNAT, and enterprises and
#: Kubernetes distributions hand it out internally, so an estate really does run services there and
#: leaving it out would reproduce the exact miss this module exists to fix at a different address.
PRIVATE_SPACE: tuple[str, ...] = (
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "100.64.0.0/10",
)

#: Ports the probe knocks on. Chosen so that *something* on a live segment answers: a router, a
#: switch management page, a Windows box, a Linux box, a hypervisor. A REFUSAL counts as much as a
#: connection, so a firewalled-but-present host still proves the network is there.
PROBE_PORTS: tuple[int, ...] = (443, 80, 22, 445, 3389)

#: Stage 1: the addresses sampled in every candidate /24. The two ends are where routers and
#: gateways live in practically every network anyone has ever built.
SPARSE_OCTETS: tuple[int, ...] = (1, 254)

#: Stage 2: the addresses sampled in the /24s of a /16 that showed life. Spread across the range
#: rather than clustered at the bottom, because a DHCP pool and a static server block rarely share
#: a neighbourhood.
DENSE_OCTETS: tuple[int, ...] = (1, 2, 10, 20, 50, 100, 150, 200, 250, 254)

#: Ports used in stage 1, kept to a short prefix of PROBE_PORTS. Stage 1 pays its cost 86,272 times
#: over, so each extra port there is tens of thousands of extra connects; stage 2 pays only inside
#: /16s already known to hold something, so it can afford the full list.
SPARSE_PORTS: tuple[int, ...] = PROBE_PORTS[:3]

#: Per-connect timeout. Short on purpose: on a live segment these answer in milliseconds, and this
#: value only decides what a dead address costs. It is the dominant term in the whole runtime.
PROBE_TIMEOUT = 0.35

#: Default wall clock for the whole probe. Generous because it runs at enrollment and on the
#: refresh cadence (only while automatic rescans are on), not per hunt, and a partial map of a
#: large estate is still far better than one /16.
DEFAULT_BUDGET_SECONDS = 600.0

#: Concurrent connects. The scan's own default is higher; this is deliberately below it because the
#: probe reaches across a customer's whole private space rather than one advertised network.
DEFAULT_CONCURRENCY = 1024


def _private_networks() -> list[ipaddress.IPv4Network]:
    return [ipaddress.ip_network(c) for c in PRIVATE_SPACE]


def is_private_v4(net: ipaddress.IPv4Network) -> bool:
    """Whether ``net`` sits inside the private space this module considers.

    Not ``net.is_private``, which is a broader question than the one asked here: it answers True
    for 127.0.0.0/8, 169.254.0.0/16 and 0.0.0.0/8, none of which is a customer network worth
    scanning, and False for 100.64.0.0/10, which is.
    """
    return any(net.subnet_of(space) for space in _private_networks())


# ── routing table ────────────────────────────────────────────────────────────────────────────


def routes_from_ip_route(output: str) -> list[str]:
    """Private destination prefixes parsed out of Linux ``ip route show`` output. Pure/testable.

    Every route the kernel holds is a claim that the machine knows how to reach that prefix, which
    is precisely the question. The default route is skipped because ``default`` is not a
    destination anyone can enumerate; a bare address with no prefix length is a host route and
    reads as a /32.
    """
    found: dict[str, None] = {}
    for line in output.splitlines():
        token = line.split(maxsplit=1)[0] if line.split() else ""
        if not token or token == "default":
            continue
        try:
            net = ipaddress.ip_network(token, strict=False)
        except ValueError:
            continue
        if isinstance(net, ipaddress.IPv4Network) and is_private_v4(net):
            found[str(net)] = None
    return sorted(found)


def routes_from_netstat(output: str) -> list[str]:
    """The same, from BSD/macOS ``netstat -rn -f inet``. Pure/testable.

    BSD writes a destination as a bare or partial dotted quad with the prefix length carried
    separately or not at all ("10.20" means 10.20.0.0/16), so a partial quad is padded and given
    the classful prefix its written octets imply. A named destination ("link#4") is skipped.
    """
    found: dict[str, None] = {}
    for line in output.splitlines():
        parts = line.split()
        if not parts:
            continue
        token = parts[0]
        if token in ("default", "Destination", "Internet:") or not token[0].isdigit():
            continue
        if "/" in token:
            candidate = token
        else:
            octets = token.split(".")
            if not 1 <= len(octets) <= 4:
                continue
            candidate = ".".join([*octets, *["0"] * (4 - len(octets))]) + f"/{8 * len(octets)}"
        try:
            net = ipaddress.ip_network(candidate, strict=False)
        except ValueError:
            continue
        if isinstance(net, ipaddress.IPv4Network) and is_private_v4(net):
            found[str(net)] = None
    return sorted(found)


def neighbours_from_ip_neigh(output: str) -> list[str]:
    """The /24s of the addresses in the kernel's neighbour (ARP) table. Pure/testable.

    Anything the machine has exchanged a frame with is on-link by definition, so its /24 is
    reachable whatever the routing table says. This is the cheapest evidence there is and it costs
    no packets at all, because the kernel already learned it.
    """
    found: dict[str, None] = {}
    for line in output.splitlines():
        parts = line.split()
        if not parts:
            continue
        try:
            address = ipaddress.ip_address(parts[0])
        except ValueError:
            continue
        if not isinstance(address, ipaddress.IPv4Address):
            continue
        net = ipaddress.ip_network(f"{address}/24", strict=False)
        if is_private_v4(net):
            found[str(net)] = None
    return sorted(found)


def _run(command: list[str]) -> str:
    try:
        out = subprocess.run(
            command, capture_output=True, text=True, timeout=5, check=False
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return out.stdout


def kernel_reachable() -> list[str]:
    """Private networks the kernel already knows how to reach: its routes plus its neighbours.

    Free in both senses (no packets, no wall clock), so it runs on every path regardless of whether
    the active probe is enabled. In a bridge-networked container this reports the container's own
    bridge and little else, which is not a bug in the parsing but the reason the probe exists.
    """
    found: dict[str, None] = {}
    for cidr in routes_from_ip_route(_run(["ip", "-4", "route", "show"])):
        found[cidr] = None
    for cidr in routes_from_netstat(_run(["netstat", "-rn", "-f", "inet"])):
        found[cidr] = None
    for cidr in neighbours_from_ip_neigh(_run(["ip", "-4", "neigh", "show"])):
        found[cidr] = None
    return sorted(found)


# ── active probe ─────────────────────────────────────────────────────────────────────────────


async def _answers(ip: str, port: int, timeout: float) -> bool:
    """Whether ``ip:port`` proves something is there.

    A refusal counts. A host that RSTs is a host: it received the packet, so the address is routed
    and something is listening on that segment even if not on that port. Only silence (a timeout or
    an unreachable) is evidence of absence, which is the same classification ``agent.scan`` phase 1
    makes and for the same reason.
    """
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
    except (asyncio.TimeoutError, TimeoutError):
        return False
    except ConnectionRefusedError:
        return True
    except OSError:
        return False
    try:
        writer.close()
        await writer.wait_closed()
    except OSError:
        pass
    return True


def _sample_addresses(net: ipaddress.IPv4Network, octets: Iterable[int]) -> list[str]:
    """The addresses to try inside one /24, as ``x.y.z.<octet>``."""
    base = int(net.network_address)
    return [str(ipaddress.IPv4Address(base + octet)) for octet in octets]


class _Probe:
    """One reachability probe: shared budget, shared concurrency limit, shared result set."""

    def __init__(self, *, concurrency: int, budget_seconds: float, timeout: float) -> None:
        self._concurrency = max(1, concurrency)
        self._semaphore = asyncio.Semaphore(self._concurrency)
        self._budget = budget_seconds
        self._timeout = timeout
        self._started = time.monotonic()
        self.truncated = False

    @property
    def _spent(self) -> bool:
        if time.monotonic() - self._started < self._budget:
            return False
        self.truncated = True
        return True

    async def _bounded(self, ip: str, port: int) -> bool:
        async with self._semaphore:
            return await _answers(ip, port, self._timeout)

    async def _alive(
        self,
        net: ipaddress.IPv4Network,
        octets: tuple[int, ...],
        ports: tuple[int, ...],
    ) -> bool:
        """Whether anything in ``net`` answers on any sampled address/port.

        Every probe for one /24 is fired at once rather than sequentially with an early exit. The
        sequential version is cheaper on a LIVE /24 and much slower on a dead one, and dead /24s
        outnumber live ones by orders of magnitude here, so the concurrent shape is the one that
        decides the runtime.
        """
        results = await asyncio.gather(
            *(
                self._bounded(ip, port)
                for ip in _sample_addresses(net, octets)
                for port in ports
            )
        )
        return any(results)

    async def live_subnets(
        self,
        nets: Iterable[ipaddress.IPv4Network],
        *,
        octets: tuple[int, ...],
        ports: tuple[int, ...],
    ) -> list[ipaddress.IPv4Network]:
        """The members of ``nets`` that answered, stopping early once the budget is spent.

        Whole BATCHES of subnets are in flight at once, and the batch is sized so the number of
        connects outstanding is about ``concurrency``. Awaiting one subnet at a time instead looks
        concurrent, because each subnet fires its own probes together, but it caps the real
        parallelism at the handful of probes ONE subnet makes: measured at 2.8 subnets a second,
        which is 8 hours for private space and about 2% of it inside the default budget. The
        semaphore is there to bound the connects; it can only do that if enough are asked for.
        """
        per_subnet = max(1, len(octets) * len(ports))
        batch_size = max(1, self._concurrency // per_subnet)
        batch: list[ipaddress.IPv4Network] = []
        alive: list[ipaddress.IPv4Network] = []

        async def drain() -> None:
            answered = await asyncio.gather(*(self._alive(n, octets, ports) for n in batch))
            alive.extend(net for net, hit in zip(batch, answered) if hit)
            batch.clear()

        # Consumed as an iterable rather than materialized: the caller passes a generator over every
        # /24 in private space, and holding all 86,272 of them just to slice it would be a list
        # nothing reads twice.
        for net in nets:
            batch.append(net)
            if len(batch) < batch_size:
                continue
            if self._spent:
                return alive
            await drain()
        if batch and not self._spent:
            await drain()
        return alive


def _candidate_subnets(
    spaces: Iterable[ipaddress.IPv4Network],
) -> Iterator[ipaddress.IPv4Network]:
    """Every /24 inside ``spaces``, in order.

    A generator rather than a list: private space is 86,272 of them, the probe consumes them in one
    pass, and nothing reads the sequence twice.
    """
    for space in spaces:
        yield from space.subnets(new_prefix=24) if space.prefixlen < 24 else iter((space,))


async def probe_private_space(
    *,
    spaces: Iterable[str] = PRIVATE_SPACE,
    concurrency: int = DEFAULT_CONCURRENCY,
    budget_seconds: float = DEFAULT_BUDGET_SECONDS,
    timeout: float = PROBE_TIMEOUT,
    sparse_octets: tuple[int, ...] = SPARSE_OCTETS,
    dense_octets: tuple[int, ...] = DENSE_OCTETS,
) -> list[str]:
    """The /24s of private space that answered, as CIDRs, collapsed.

    Two stages, for the reason in the module docstring: stage 1 samples every /24 thinly, stage 2
    re-samples densely inside only the /16s stage 1 found something in. Stage 2 is what finds a
    VLAN whose only live host sits at .137, and it is affordable because it runs over a few /16s
    rather than over all 273 of them.

    Never raises. A probe is an enrichment of what the interfaces already say, so a failure has to
    narrow the result rather than stop the agent from enrolling.
    """
    networks = [ipaddress.ip_network(s) for s in spaces]
    probe = _Probe(concurrency=concurrency, budget_seconds=budget_seconds, timeout=timeout)

    sparse_hits = await probe.live_subnets(
        _candidate_subnets(networks), octets=sparse_octets, ports=SPARSE_PORTS
    )
    # The /16s worth a second, closer look. A /16 is the unit because it is how estates are handed
    # out and how the existing supernet16 scope already thinks: finding one live /24 in 10.20.x is
    # strong evidence the rest of 10.20 is the customer's too.
    populated = {net.supernet(new_prefix=16) for net in sparse_hits}
    dense_hits = await probe.live_subnets(
        _candidate_subnets(sorted(populated)), octets=dense_octets, ports=PROBE_PORTS
    )

    alive = sorted(set(sparse_hits) | set(dense_hits))
    if probe.truncated:
        logger.warning(
            "Reachability probe budget of %.0fs is spent; advertising the %d network(s) found so "
            "far. Raise ARES_REACH_BUDGET_SECONDS, or set ARES_NETWORKS to skip discovery.",
            budget_seconds,
            len(alive),
        )
    return [str(n) for n in ipaddress.collapse_addresses(alive)]


async def discover(
    *,
    attached: list[str],
    probe: bool = True,
    concurrency: int = DEFAULT_CONCURRENCY,
    budget_seconds: float = DEFAULT_BUDGET_SECONDS,
    timeout: float = PROBE_TIMEOUT,
) -> list[str]:
    """Everything this agent can reach, from all three sources, collapsed into scan targets.

    ``attached`` comes in already widened by whichever scope the operator chose, so the existing
    behaviour is preserved exactly and the other two sources only ever ADD. That ordering is the
    point: an agent that used to advertise ``172.23.0.0/16`` still advertises it, and now also
    advertises the 10.x networks it can demonstrably reach.
    """
    found = list(attached)
    found += kernel_reachable()
    if probe:
        try:
            found += await probe_private_space(
                concurrency=concurrency, budget_seconds=budget_seconds, timeout=timeout
            )
        except Exception:  # noqa: BLE001 - discovery is best-effort; never block enrollment on it
            logger.warning(
                "Reachability probe failed; using interfaces and routes only.", exc_info=True
            )
    nets: list[ipaddress.IPv4Network] = []
    for cidr in found:
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        if isinstance(net, ipaddress.IPv4Network):
            nets.append(net)
    return [str(n) for n in ipaddress.collapse_addresses(nets)]
