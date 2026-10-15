"""Reachability discovery: find every private network the agent can reach, not just its own.

The parsers are pure and tested against real command output. The probe is tested against a fake
connector rather than a socket, so the two-stage shape (thin sweep, then a dense pass inside the
/16s that showed life) is asserted directly instead of inferred from timing.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
from collections.abc import Callable

import pytest

from agent import reachability


# --- private-space membership -------------------------------------------------------------------


@pytest.mark.parametrize(
    "cidr",
    ["10.0.0.0/8", "10.20.5.0/24", "172.16.0.0/12", "172.23.0.0/16", "192.168.1.0/24",
     "100.64.0.0/10", "100.70.3.0/24"],
)
def test_private_space_includes_rfc1918_and_shared_address_space(cidr: str) -> None:
    assert reachability.is_private_v4(ipaddress.ip_network(cidr))


@pytest.mark.parametrize(
    "cidr",
    [
        "8.8.8.0/24",  # public
        "127.0.0.0/8",  # loopback: is_private says yes, and it is not a customer network
        "169.254.0.0/16",  # link-local, same reason
        "0.0.0.0/8",  # unspecified, same reason
        "172.32.0.0/16",  # just outside 172.16/12, the classic off-by-one in a hand-written list
    ],
)
def test_private_space_excludes_what_is_not_a_customer_network(cidr: str) -> None:
    assert not reachability.is_private_v4(ipaddress.ip_network(cidr))


# --- routing table ------------------------------------------------------------------------------

_IP_ROUTE = """default via 172.23.0.1 dev eth0
10.20.0.0/16 via 172.23.0.1 dev eth0
10.30.4.0/24 via 172.23.0.1 dev eth0
172.23.0.0/16 dev eth0 proto kernel scope link src 172.23.104.119
192.0.2.0/24 via 172.23.0.1 dev eth0
"""


def test_routes_report_private_destinations_reached_through_a_gateway() -> None:
    # The customer case exactly: the agent is attached to 172.23 and holds routes to 10.20 and
    # 10.30 through the corporate router. Those are reachable and were previously invisible.
    assert reachability.routes_from_ip_route(_IP_ROUTE) == [
        "10.20.0.0/16",
        "10.30.4.0/24",
        "172.23.0.0/16",
    ]


def test_routes_skip_the_default_route_and_public_destinations() -> None:
    # "default" is not a destination anyone can enumerate, and 192.0.2.0/24 is public: neither
    # belongs in a list of networks to sweep.
    parsed = reachability.routes_from_ip_route(_IP_ROUTE)
    assert "0.0.0.0/0" not in parsed
    assert "192.0.2.0/24" not in parsed


def test_routes_from_netstat_pads_a_partial_bsd_destination() -> None:
    # BSD writes 10.20.0.0/16 as "10.20", which a naive parser reads as the address 10.20.0.0/32
    # and so scans one host instead of a /16.
    output = """Routing tables

Internet:
Destination        Gateway            Flags
default            192.168.1.1        UGSc
10.20              192.168.1.1        UGSc
192.168.1          link#4             UCS
"""
    assert reachability.routes_from_netstat(output) == ["10.20.0.0/16", "192.168.1.0/24"]


def test_neighbour_table_reports_the_slash24_of_each_on_link_address() -> None:
    # Anything the machine has exchanged a frame with is on-link whatever the routing table says.
    output = """10.20.1.4 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE
10.20.1.9 dev eth0 lladdr aa:bb:cc:dd:ee:00 STALE
8.8.8.8 dev eth0 lladdr aa:bb:cc:dd:ee:11 REACHABLE
fe80::1 dev eth0 lladdr aa:bb:cc:dd:ee:22 router REACHABLE
"""
    assert reachability.neighbours_from_ip_neigh(output) == ["10.20.1.0/24"]


def test_parsers_survive_empty_or_unreadable_output() -> None:
    # The collectors return "" when the command is missing (a slim image with no iproute2), so
    # every parser has to read that as "nothing found" rather than raise on the agent's startup.
    assert reachability.routes_from_ip_route("") == []
    assert reachability.routes_from_netstat("") == []
    assert reachability.neighbours_from_ip_neigh("not a routing table at all") == []


# --- the active probe ---------------------------------------------------------------------------


Rule = Callable[[str, int], "reachability.Answer | None"]


@pytest.fixture
def _fake_network(monkeypatch: pytest.MonkeyPatch):
    """Answer for a chosen set of addresses; record everything that was probed.

    A ``live`` address accepts on every port and every other address is silent, unless ``rule``
    says otherwise for an ``(ip, port)``: that is how a box answering for a whole range is built.
    """

    def install(live: set[str], *, rule: Rule | None = None) -> list[str]:
        probed: list[str] = []

        async def _answers(ip: str, port: int, timeout: float) -> reachability.Answer:
            probed.append(ip)
            if rule is not None and (said := rule(ip, port)) is not None:
                return said
            return reachability.Answer.ACCEPTED if ip in live else reachability.Answer.SILENT

        monkeypatch.setattr(reachability, "_answers", _answers)
        return probed

    return install


async def test_probe_reports_only_the_subnets_that_answered(_fake_network) -> None:
    # One host on a gateway address in 10.20.5.x. Nothing else in 86,272 candidate /24s answers,
    # so exactly one network comes back rather than the whole of private space.
    _fake_network({"10.20.5.1"})
    found = await reachability.probe_private_space(spaces=["10.20.0.0/16"])
    assert found == ["10.20.5.0/24"]


async def test_probe_finds_a_sparse_subnet_inside_a_populated_range(_fake_network) -> None:
    # The reason for stage 2. 10.20.7.137 is on none of the sampled addresses, but 10.20.5.1 puts
    # the whole /16 in play, and the dense pass then samples .150 in every one of its /24s.
    _fake_network({"10.20.5.1", "10.20.7.150"})
    found = await reachability.probe_private_space(spaces=["10.20.0.0/16"])
    assert found == ["10.20.5.0/24", "10.20.7.0/24"]


async def test_probe_does_not_pay_for_a_dense_pass_over_dead_space(_fake_network) -> None:
    # Stage 2 must run only inside /16s stage 1 found something in, or the whole two-stage shape
    # buys nothing: a dense pass over all of private space is the cost this design exists to avoid.
    probed = _fake_network(set())
    assert await reachability.probe_private_space(spaces=["10.20.0.0/16"]) == []
    sampled_octets = {ip.rsplit(".", 1)[1] for ip in probed}
    assert sampled_octets == {"1", "254"}


async def test_probe_stops_when_its_budget_is_spent(_fake_network, monkeypatch) -> None:
    # A slow network must yield a partial map rather than run until something kills the container.
    #
    # Asserts on what was NOT probed rather than on what was found. The budget is checked between
    # batches, so whichever batch was in flight when it ran out still finishes: an assertion that
    # nothing at all came back would be pinning the old one-subnet-at-a-time loop, whose real
    # concurrency was six probes and which took eight hours over private space.
    probed = _fake_network({"10.20.5.1"})
    clock = iter([0.0, 0.0, 1_000.0])
    monkeypatch.setattr(reachability.time, "monotonic", lambda: next(clock, 1_000.0))

    await reachability.probe_private_space(spaces=["10.20.0.0/16"], budget_seconds=1.0)

    # a /16 holds 256 /24s and the batch is far smaller than that, so a probe that honoured the
    # budget cannot have touched the end of the range.
    assert "10.20.255.1" not in probed
    assert len(probed) < 256 * len(reachability.SPARSE_OCTETS) * len(reachability.SPARSE_PORTS)


async def test_probe_treats_a_refusal_as_proof_the_network_is_there(monkeypatch) -> None:
    # A host that RSTs is a host: the packet arrived, so the address is routed. Only silence is
    # evidence of absence, and reading a refusal as "dead" would hide every firewalled segment.
    async def _open_connection(ip: str, port: int):
        raise ConnectionRefusedError

    monkeypatch.setattr(reachability.asyncio, "open_connection", _open_connection)
    assert await reachability._answers("10.20.5.1", 443, 0.1) is reachability.Answer.REFUSED


async def test_discover_adds_to_the_attached_subnets_and_never_replaces_them(
    monkeypatch: pytest.MonkeyPatch, _fake_network
) -> None:
    # The ordering that makes this safe to ship as a default: an agent that advertised
    # 172.23.0.0/16 still advertises it, and now also advertises what it can reach.
    _fake_network(set())
    monkeypatch.setattr(reachability, "kernel_reachable", lambda: ["10.20.0.0/16"])
    found = await reachability.discover(attached=["172.23.0.0/16"], probe=False)
    assert found == ["10.20.0.0/16", "172.23.0.0/16"]


async def test_discover_collapses_a_network_reported_by_two_sources(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The routing table and the interface both name the attached subnet, and a /24 inside an
    # advertised /16 is already covered: without collapsing, the agent enqueues a task per
    # duplicate and scans the same addresses two and three times over.
    monkeypatch.setattr(
        reachability, "kernel_reachable", lambda: ["172.23.0.0/16", "172.23.104.0/24"]
    )
    found = await reachability.discover(attached=["172.23.0.0/16"], probe=False)
    assert found == ["172.23.0.0/16"]


async def test_discover_survives_a_failing_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    # Discovery is an enrichment of what the interfaces already say. A probe that blows up must
    # narrow the result, never stop the agent from enrolling.
    async def _explode(**_kwargs: object) -> list[str]:
        raise OSError("no network")

    monkeypatch.setattr(reachability, "probe_private_space", _explode)
    monkeypatch.setattr(reachability, "kernel_reachable", list)
    assert await reachability.discover(attached=["172.23.0.0/16"]) == ["172.23.0.0/16"]


async def test_the_probe_keeps_many_subnets_in_flight_at_once(monkeypatch) -> None:
    """The regression test for the reason this probe is usable at all.

    The first version awaited one /24 at a time. Each fired its own handful of probes together, so
    it LOOKED concurrent and the semaphore said 1024, but only six connects were ever outstanding:
    measured at 2.8 subnets a second, which is eight hours over private space and about 2% of it
    inside the default budget. The feature would have swept 10.0.0.0/8 as far as 10.6.x and then
    logged a truncation, which is the exact miss it exists to fix.

    Asserts on peak concurrency rather than on elapsed time, so it fails for the real reason on a
    slow machine instead of flaking.
    """
    in_flight = 0
    peak = 0

    async def _answers(ip: str, port: int, timeout: float) -> reachability.Answer:
        nonlocal in_flight, peak
        in_flight += 1
        peak = max(peak, in_flight)
        await asyncio.sleep(0)  # yield, so the rest of the batch gets to start
        in_flight -= 1
        return reachability.Answer.SILENT

    monkeypatch.setattr(reachability, "_answers", _answers)
    await reachability.probe_private_space(spaces=["10.20.0.0/16"], concurrency=1024)

    per_subnet = len(reachability.SPARSE_OCTETS) * len(reachability.SPARSE_PORTS)
    assert peak > per_subnet * 10, f"only {peak} probes in flight; the batch is not being used"


# --- a box answering for every address (ARES-1878) -----------------------------------------------

FakeNetwork = Callable[..., list[str]]


def _proxy(*ports: int) -> Rule:
    """A transparent proxy in front of 10.20.0.0/16: it completes the handshake on ``ports`` at
    every address, whether or not a machine is there, and passes everything else through to
    addresses that hold nothing."""

    def rule(ip: str, port: int) -> reachability.Answer | None:
        if ip.startswith("10.20.") and port in ports:
            return reachability.Answer.ACCEPTED
        return None

    return rule


def _behind_proxy(ip: str, port: int, answer: reachability.Answer) -> Rule:
    """The port-80 proxy, plus one real machine behind it answering ``port`` with ``answer``."""
    proxy = _proxy(80)

    def rule(address: str, probed: int) -> reachability.Answer | None:
        if (address, probed) == (ip, port):
            return answer
        return proxy(address, probed)

    return rule


async def test_a_range_a_proxy_answers_for_is_not_advertised(
    _fake_network: FakeNetwork, caplog: pytest.LogCaptureFixture
) -> None:
    """The field case: three agents scoped to one /16 each advertised most of private space."""
    # given a proxy taking port 80 at every address of 10.20.0.0/16 and nothing behind it
    _fake_network(set(), rule=_proxy(80))

    # when the agent probes the range
    with caplog.at_level(logging.WARNING, logger="ares.agent.reachability"):
        found = await reachability.probe_private_space(spaces=["10.20.0.0/16"])

    # then none of it is advertised, and the warning says how much was skipped and on which port
    assert found == []
    assert "ignored 256 network(s)" in caplog.text
    assert "port(s) 80 " in caplog.text


async def test_a_host_behind_the_proxy_still_puts_its_network_on_the_map(
    _fake_network: FakeNetwork,
) -> None:
    # given a gateway at 10.20.5.1 with SSH open, which the proxy does not fake
    _fake_network(set(), rule=_behind_proxy("10.20.5.1", 22, reachability.Answer.ACCEPTED))

    # when the agent probes the range
    found = await reachability.probe_private_space(spaces=["10.20.0.0/16"])

    # then that /24 is advertised and every other one stays hidden behind the proxy
    assert found == ["10.20.5.0/24"]


async def test_a_reset_behind_the_proxy_still_counts(_fake_network: FakeNetwork) -> None:
    # given a machine at 10.20.5.254 that resets 443: a proxy completes handshakes, it never
    # refuses one, so the reset can only come from a real stack
    _fake_network(set(), rule=_behind_proxy("10.20.5.254", 443, reachability.Answer.REFUSED))

    # when the agent probes the range
    found = await reachability.probe_private_space(spaces=["10.20.0.0/16"])

    # then the reset alone is enough for its /24
    assert found == ["10.20.5.0/24"]


async def test_a_real_host_that_only_accepts_is_not_mistaken_for_the_box(
    _fake_network: FakeNetwork,
) -> None:
    # given an ordinary network: .1 accepts and nothing else in its /24 is there
    _fake_network({"10.20.5.1"})

    # when the agent probes, the addresses picked at random stay silent
    found = await reachability.probe_private_space(spaces=["10.20.0.0/16"])

    # then the accept stands as evidence
    assert found == ["10.20.5.0/24"]


def test_canaries_never_land_on_an_address_the_probe_already_sampled() -> None:
    net = ipaddress.ip_network("10.20.5.0/24")
    for sampled in (reachability.SPARSE_OCTETS, reachability.DENSE_OCTETS):
        # when canaries are drawn after either stage's sample
        canaries = reachability._canary_addresses(net, avoid=sampled)

        # then they are distinct host addresses of the same /24, none of them resampled
        octets = [int(ip.rsplit(".", 1)[1]) for ip in canaries]
        assert len(set(octets)) == reachability.CANARIES
        assert all(o in reachability._HOST_OCTETS and o not in sampled for o in octets)
        assert all(ip.startswith("10.20.5.") for ip in canaries)
