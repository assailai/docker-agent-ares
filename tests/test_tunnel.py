"""Data-plane tunnel client: URL derivation, frame codec, destination authorization (IP
literals against the registered networks, hostnames resolved here and checked either way),
and OPEN-frame resilience (a bad or out-of-scope target is refused, never a crash)."""

from __future__ import annotations

import asyncio
import json
import socket
import ssl
import types

import pytest
from websockets.exceptions import InvalidStatus

from agent.hostpins import HostPins
from agent.tunnel import (
    _DATA,
    _HOSTS_REPORTED_MAX,
    _OPEN_ERR,
    _PROBE_TIMEOUT,
    HostApproval,
    RefusalLog,
    Refused,
    globally_routable,
    host_approval,
    TunnelClient,
    TunnelManager,
    _decode,
    _encode,
    explain_probe_failure,
    normalize_host,
    probe,
    summarize_addresses,
    tunnel_url,
)


class _RecordingWS:
    """Stands in for a live WebSocket, capturing the frames the client sends."""

    def __init__(self) -> None:
        self.sent: list[bytes] = []

    async def send(self, frame: bytes) -> None:
        self.sent.append(frame)


def _client(
    networks: list[str] | None = None,
    allowed_hosts: set[str] | None = None,
    scoped_hosts: set[str] | None = None,
) -> TunnelClient:
    return TunnelClient(
        "ws://x/api/v1/agent/tunnel",
        "tok",
        networks if networks is not None else ["10.0.0.0/24", "192.168.1.0/24"],
        allowed_hosts if allowed_hosts is not None else set(),
        scoped_hosts=scoped_hosts if scoped_hosts is not None else set(),
        ssl_context=None,
    )


def _stub_resolver(client: TunnelClient, mapping: dict[str, list[str]]) -> None:
    """Resolve names from ``mapping`` instead of touching real DNS; unknown names fail."""

    async def resolve(host: str, port: int) -> list[str]:
        if host not in mapping:
            raise Refused(f"{host} did not resolve on this agent")
        return mapping[host]

    client._resolve = resolve  # type: ignore[method-assign]


def test_tunnel_url_maps_scheme_and_path() -> None:
    assert tunnel_url("https://ares.assailai.com") == "wss://ares.assailai.com/api/v1/agent/tunnel"
    assert (
        tunnel_url("http://host.docker.internal:8000/")
        == "ws://host.docker.internal:8000/api/v1/agent/tunnel"
    )


def test_frame_round_trips() -> None:
    assert _decode(_encode(_DATA, 7, b"hello")) == (_DATA, 7, b"hello")


def test_normalize_host_is_case_and_root_dot_insensitive() -> None:
    assert normalize_host("Bank.Internal.") == "bank.internal"
    assert normalize_host("  bank.internal ") == "bank.internal"


# ── IP literals: unchanged behaviour ──────────────────────────────────────────
def test_ip_inside_registered_networks_is_dialed_as_is() -> None:
    client = _client()
    assert asyncio.run(client._dial_address("10.0.0.5", 80)) == "10.0.0.5"
    assert asyncio.run(client._dial_address("192.168.1.200", 443)) == "192.168.1.200"


def test_ip_outside_registered_networks_is_refused() -> None:
    client = _client()
    with pytest.raises(Refused):
        asyncio.run(client._dial_address("8.8.8.8", 53))


# ── hostnames: resolved here, then authorized ─────────────────────────────────
def test_name_resolving_into_registered_networks_is_allowed() -> None:
    client = _client()
    _stub_resolver(client, {"bank.internal": ["10.0.0.7"]})
    assert asyncio.run(client._dial_address("bank.internal", 8000)) == "10.0.0.7"


def test_name_resolving_outside_networks_is_refused_without_a_pushed_host() -> None:
    client = _client()
    _stub_resolver(client, {"staging.acme.com": ["203.0.113.10"]})
    with pytest.raises(Refused, match="not an approved target"):
        asyncio.run(client._dial_address("staging.acme.com", 443))


def test_pushed_host_allows_a_name_outside_the_networks() -> None:
    client = _client(allowed_hosts={"staging.acme.com"})
    _stub_resolver(client, {"staging.acme.com": ["203.0.113.10"]})
    assert asyncio.run(client._dial_address("staging.acme.com", 443)) == "203.0.113.10"


def test_pushed_host_match_ignores_case_and_root_dot() -> None:
    client = _client(allowed_hosts={"staging.acme.com"})
    _stub_resolver(client, {"Staging.Acme.com.": ["203.0.113.10"]})
    assert asyncio.run(client._dial_address("Staging.Acme.com.", 443)) == "203.0.113.10"


def test_a_name_is_refused_once_its_host_leaves_the_pushed_set() -> None:
    # the set is shared with the manager and mutated in place, so a hunt ending closes the door
    # on the live connection without a reconnect.
    hosts = {"staging.acme.com"}
    client = _client(allowed_hosts=hosts)
    _stub_resolver(client, {"staging.acme.com": ["203.0.113.10"]})
    assert asyncio.run(client._dial_address("staging.acme.com", 443)) == "203.0.113.10"
    hosts.clear()
    with pytest.raises(Refused):
        asyncio.run(client._dial_address("staging.acme.com", 443))


def test_a_name_with_any_address_outside_the_networks_needs_the_pushed_set() -> None:
    # a split answer must not sneak past on the strength of one in-network address.
    client = _client()
    _stub_resolver(client, {"mixed.internal": ["10.0.0.7", "8.8.8.8"]})
    with pytest.raises(Refused):
        asyncio.run(client._dial_address("mixed.internal", 80))


def test_unresolvable_name_is_refused() -> None:
    client = _client()
    _stub_resolver(client, {})
    with pytest.raises(Refused, match="did not resolve"):
        asyncio.run(client._dial_address("nowhere.internal", 80))


def test_resolve_deduplicates_and_preserves_order() -> None:
    client = _client()

    async def fake_getaddrinfo(host: str, port: int, **kwargs: object) -> list[tuple]:
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.7", port)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.7", port)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.8", port)),
        ]

    async def run() -> list[str]:
        asyncio.get_running_loop().getaddrinfo = fake_getaddrinfo  # type: ignore[method-assign]
        return await client._resolve("bank.internal", 8000)

    assert asyncio.run(run()) == ["10.0.0.7", "10.0.0.8"]


def test_unparseable_address_is_never_treated_as_inside_the_networks() -> None:
    client = _client(networks=["10.0.0.0/8", "fe80::/10"])
    assert client._in_allowed_networks("not-an-address") is False
    # a scope id is legal and still compared on the address itself.
    assert client._in_allowed_networks("fe80::1%eth0") is True


# ── OPEN-frame handling ───────────────────────────────────────────────────────
def _client_with_ws(allowed_hosts: set[str] | None = None) -> tuple[TunnelClient, _RecordingWS]:
    client = _client(["10.0.0.0/24"], allowed_hosts)
    ws = _RecordingWS()
    client._ws = ws
    return client, ws


def test_malformed_open_frame_is_refused_not_fatal() -> None:
    # a garbled OPEN payload answers OPEN_ERR (so ares fails that stream fast) and never raises.
    client, ws = _client_with_ws()
    asyncio.run(client._open(5, b"not json at all"))
    assert _decode(ws.sent[0])[:2] == (_OPEN_ERR, 5)


def test_open_outside_allowlist_is_refused() -> None:
    # a target the agent was never registered for is refused at OPEN.
    client, ws = _client_with_ws()
    asyncio.run(client._open(9, json.dumps({"host": "8.8.8.8", "port": 53}).encode()))
    assert _decode(ws.sent[0])[:2] == (_OPEN_ERR, 9)


def test_open_with_an_unauthorized_name_is_refused() -> None:
    client, ws = _client_with_ws()
    _stub_resolver(client, {"evil.example.com": ["203.0.113.10"]})
    asyncio.run(client._open(11, json.dumps({"host": "evil.example.com", "port": 80}).encode()))
    assert _decode(ws.sent[0])[:2] == (_OPEN_ERR, 11)


def test_open_dials_the_resolved_address_not_the_name(monkeypatch: pytest.MonkeyPatch) -> None:
    # the check and the connect must land on the same destination, so the dial uses the address
    # we authorized rather than going back through the resolver.
    client, ws = _client_with_ws({"bank.internal"})
    _stub_resolver(client, {"bank.internal": ["203.0.113.10"]})
    dialed: list[tuple[str, int]] = []

    async def fake_open_connection(host: str, port: int):
        dialed.append((host, port))
        raise OSError("no listener in the test")

    monkeypatch.setattr(asyncio, "open_connection", fake_open_connection)
    asyncio.run(client._open(13, json.dumps({"host": "bank.internal", "port": 8000}).encode()))
    assert dialed == [("203.0.113.10", 8000)]
    assert _decode(ws.sent[0])[:2] == (_OPEN_ERR, 13)  # the dial failed, so the stream fails


# ── manager: the pushed set ───────────────────────────────────────────────────
def test_manager_sync_replaces_the_pushed_host_set_in_place() -> None:
    manager = TunnelManager("ws://x", "tok", ["10.0.0.0/24"], ssl_context=None)
    shared = manager._allowed_hosts
    manager.sync(False, ["Bank.Internal.", "  ", "staging.acme.com"])
    assert shared == {"bank.internal", "staging.acme.com"}
    manager.sync(False, [])
    assert shared == set()
    assert shared is manager._allowed_hosts  # the live client holds this same object


# ── refusal logging: readable at hundreds-per-run volumes ─────────────────────
def test_summarize_addresses_names_a_few_then_counts_the_rest() -> None:
    assert summarize_addresses(["1.1.1.1", "2.2.2.2"]) == "1.1.1.1, 2.2.2.2"
    many = [f"10.0.0.{n}" for n in range(1, 9)]
    assert summarize_addresses(many) == "10.0.0.1, 10.0.0.2, 10.0.0.3, +5 more"


def test_a_refused_host_is_explained_once_then_only_counted(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """One assessment refuses the same telemetry host hundreds of times; a per-dial WARNING would
    bury the refusal an operator actually needs to see."""
    log = RefusalLog()
    with caplog.at_level("INFO", logger="ares.agent.tunnel"):
        for _ in range(50):
            log.record("autofill.example.com", "autofill.example.com resolves outside ...")
        log.record("other.example.com", "other.example.com resolves outside ...")

        warnings = [r for r in caplog.records if r.levelname == "WARNING"]
        assert len(warnings) == 2  # one per host, not one per dial
        assert not [r for r in caplog.records if r.levelname == "INFO"]  # rollup not due yet

        caplog.clear()
        log.flush()
        rollup = [r.getMessage() for r in caplog.records if r.levelname == "INFO"]

    assert len(rollup) == 1
    assert "49 further tunnel dial(s) to 1 host(s)" in rollup[0]
    assert "autofill.example.com x49" in rollup[0]


def test_flush_is_quiet_when_nothing_was_suppressed(caplog: pytest.LogCaptureFixture) -> None:
    log = RefusalLog()
    with caplog.at_level("INFO", logger="ares.agent.tunnel"):
        log.record("one.example.com", "one.example.com resolves outside ...")
        caplog.clear()
        log.flush()
        log.flush()
    assert caplog.records == []  # no empty rollups, and no re-explaining a reported host


def test_open_records_the_refusal_once_per_host(caplog: pytest.LogCaptureFixture) -> None:
    """The OPEN path must route refusals through the collapsing log, not straight to a WARNING."""
    client = _client()
    client._ws = _RecordingWS()  # type: ignore[assignment]
    _stub_resolver(client, {"evil.example.com": ["8.8.8.8"]})
    frame = json.dumps({"host": "evil.example.com", "port": 80}).encode()
    with caplog.at_level("INFO", logger="ares.agent.tunnel"):
        for stream_id in range(5):
            asyncio.run(client._open(stream_id, frame))

    warnings = [r for r in caplog.records if r.levelname == "WARNING"]
    assert len(warnings) == 1
    assert "not an approved target" in warnings[0].getMessage()


def test_full_refusal_lines_are_capped_across_distinct_hosts(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The page under test decides what the browser dials, so distinct refused hosts are not ours to
    bound: one referencing a thousand third parties must not produce a thousand WARNING lines."""
    log = RefusalLog()
    with caplog.at_level("INFO", logger="ares.agent.tunnel"):
        for n in range(_HOSTS_REPORTED_MAX * 2):
            log.record(f"host{n}.example.com", f"host{n}.example.com resolves outside ...")

    warnings = [r for r in caplog.records if r.levelname == "WARNING"]
    assert len(warnings) == _HOSTS_REPORTED_MAX  # the rest are counted, not printed

    caplog.clear()
    with caplog.at_level("INFO", logger="ares.agent.tunnel"):
        log.flush()
    rollup = [r.getMessage() for r in caplog.records if r.levelname == "INFO"]
    assert len(rollup) == 1
    assert f"to {_HOSTS_REPORTED_MAX} host(s)" in rollup[0]  # the ones over budget still accounted


# --- startup preflight: rehearse the data plane before a hunt depends on it -------------------


def _http_response(status: int):
    """A websockets HTTP response object, as InvalidStatus carries when an upgrade is refused."""
    return types.SimpleNamespace(status_code=status)


def test_a_refused_upgrade_is_named_as_a_refusal_not_a_network_block() -> None:
    # An HTTP status where a 101 belongs is the signature that matters: something spoke HTTP back,
    # so we reached a server and it declined. That is a very different fix from "port blocked".
    explanation = explain_probe_failure(InvalidStatus(_http_response(502)))

    assert "HTTP 502" in explanation
    assert "101" in explanation
    assert "WebSocket upgrades allowed" in explanation


def test_a_rejected_upgrade_points_at_a_stripped_header_when_the_control_plane_works() -> None:
    # 401 on the upgrade while HTTPS succeeds is much more often a proxy dropping the
    # Authorization header than a genuinely bad token, and those have opposite fixes.
    explanation = explain_probe_failure(InvalidStatus(_http_response(401)))

    assert "Authorization" in explanation


def test_a_timed_out_upgrade_is_named_as_a_silent_drop() -> None:
    assert "silently dropping" in explain_probe_failure(TimeoutError())


def test_an_unremarkable_failure_gets_no_invented_explanation() -> None:
    # The raw error is better than a confident guess, so callers append this unconditionally.
    assert explain_probe_failure(OSError("connection refused")) == ""


async def test_the_probe_opens_and_closes_without_sending_anything(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The upgrade completing is the whole result: a probe that sent frames could be mistaken by
    ares for a live tunnel with a stream on it."""
    opened: dict[str, object] = {}

    class _Connection:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            opened["closed"] = True

        async def send(self, _frame):  # pragma: no cover - must never be called
            raise AssertionError("the probe must not send frames")

    def _connect(url, **kwargs):
        opened.update({"url": url, **kwargs})
        return _Connection()

    monkeypatch.setattr("agent.tunnel.websockets.connect", _connect)
    context = ssl.create_default_context()

    await probe("wss://ares.example.com/api/v1/agent/tunnel", "tok", ssl_context=context)

    assert opened["closed"] is True
    assert opened["ssl"] is context  # the shared trust, so the probe proves the real thing
    assert opened["additional_headers"] == {"Authorization": "Bearer tok"}
    assert opened["open_timeout"] == _PROBE_TIMEOUT  # bounded: a blackhole costs one slow start


async def test_the_probe_sends_no_ssl_context_for_a_plaintext_url(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: dict[str, object] = {}

    class _Connection:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return None

    monkeypatch.setattr(
        "agent.tunnel.websockets.connect",
        lambda url, **kwargs: (seen.update(kwargs), _Connection())[1],
    )

    url = "ws://localhost:8080/api/v1/agent/tunnel"
    await probe(url, "tok", ssl_context=ssl.create_default_context())

    assert seen["ssl"] is None


# --- host approval: wildcard, suffix, exact -------------------------------------------------


@pytest.mark.parametrize(
    ("host", "allowed", "expected"),
    [
        # exact, as before
        ("staging.acme.com", {"staging.acme.com"}, HostApproval.EXACT),
        ("other.acme.com", {"staging.acme.com"}, HostApproval.NONE),
        # suffix forms. This is the hole exact-match left: ares ships okta.com / auth0.com /
        # pingone.com as built-in identity providers, but every real tenant is <name>.okta.com,
        # so none of those entries ever matched anything at all.
        ("acme.okta.com", {".okta.com"}, HostApproval.SUFFIX),
        ("acme.okta.com", {"*.okta.com"}, HostApproval.SUFFIX),
        ("okta.com", {".okta.com"}, HostApproval.SUFFIX),
        ("deep.sub.okta.com", {"*.okta.com"}, HostApproval.SUFFIX),
        # a suffix entry must not match a host that merely ENDS WITH the text
        ("notokta.com", {".okta.com"}, HostApproval.NONE),
        ("okta.com.evil.test", {".okta.com"}, HostApproval.NONE),
        # the wildcard opens any name
        ("anything.at.all.example", {"*"}, HostApproval.WILDCARD),
        ("agtacc.allstate.com", {"*"}, HostApproval.WILDCARD),
        # case and the root dot are irrelevant on both sides
        ("ACME.Okta.Com.", {"*.OKTA.com"}, HostApproval.SUFFIX),
        # empties are never a destination
        ("", {"*"}, HostApproval.NONE),
        ("host.example.com", {"", "   "}, HostApproval.NONE),
        # Several entries can match at once, and the NARROWEST decides, whatever order the set
        # iterates in. ares pushes "*" ALONGSIDE the run's real target while an interactive login
        # is parked, so this is the common case rather than a corner: grading it WILDCARD would
        # apply the public-address rule to the hunt's own internal target and refuse it.
        ("acme.okta.com", {"*", "acme.okta.com"}, HostApproval.EXACT),
        ("acme.okta.com", {"*", ".okta.com"}, HostApproval.SUFFIX),
        ("acme.okta.com", {"*", ".okta.com", "acme.okta.com"}, HostApproval.EXACT),
    ],
)
def test_host_approval_reports_the_narrowest_match(
    host: str, allowed: set[str], expected: HostApproval
) -> None:
    assert host_approval(host, allowed) is expected


def test_wildcard_does_not_widen_ip_literals() -> None:
    """The wildcard opens NAMES, and an IP literal is not one: it stays bounded by the registered
    networks. What a wildcard-approved NAME may resolve to is a separate question, answered by the
    address-class tests below - this one deliberately only covers the literal."""
    client = _client(allowed_hosts={"*"})
    with pytest.raises(Refused, match="outside this agent's registered networks"):
        asyncio.run(client._dial_address("203.0.113.10", 443))


def test_wildcard_lets_an_unenumerated_login_host_through() -> None:
    client = _client(allowed_hosts={"*"})
    _stub_resolver(client, {"agtacc.allstate.com": ["167.127.118.229"]})
    assert asyncio.run(client._dial_address("agtacc.allstate.com", 443)) == "167.127.118.229"


# --- address classes: what a pattern-approved name is allowed to resolve to --------------------
#
# A name approved by "*" or a domain suffix matches hosts nobody enumerated, so the name proves
# nothing about intent and the ADDRESS has to earn the dial. Without this the agent would relay TCP
# to cloud metadata, to services on loopback, and into private segments it was never registered
# for, on nothing more than an approved login domain.

_SPECIAL_USE = [
    pytest.param("169.254.169.254", id="cloud-metadata-over-link-local"),
    pytest.param("127.0.0.1", id="ipv4-loopback"),
    pytest.param("192.168.7.9", id="rfc1918-outside-registered-networks"),
    pytest.param("10.9.9.9", id="rfc1918-in-another-private-block"),
    pytest.param("100.64.0.1", id="rfc6598-carrier-grade-nat"),
    pytest.param("0.0.0.0", id="unspecified"),
    pytest.param("224.0.0.1", id="ipv4-multicast-which-is-global-calls-global"),
    pytest.param("239.255.255.250", id="ipv4-scoped-multicast"),
    pytest.param("203.0.113.5", id="test-net-3"),
    pytest.param("198.18.0.1", id="benchmarking-range"),
    pytest.param("::1", id="ipv6-loopback"),
    pytest.param("fe80::1", id="ipv6-link-local"),
    pytest.param("fc00::1", id="ipv6-unique-local"),
    pytest.param("ff02::1", id="ipv6-multicast-which-is-global-also-calls-global"),
    pytest.param("::", id="ipv6-unspecified"),
    pytest.param("::ffff:169.254.169.254", id="metadata-as-ipv4-mapped-ipv6"),
    pytest.param("::ffff:127.0.0.1", id="loopback-as-ipv4-mapped-ipv6"),
]


@pytest.mark.parametrize("address", _SPECIAL_USE)
def test_a_wildcard_name_cannot_reach_special_use_space(address: str) -> None:
    """Pinned as a table because this is a policy about the special-use registries, and those move
    between Python releases: production runs 3.12 while a dev venv may be newer."""
    client = _client(networks=["10.0.0.0/24"], allowed_hosts={"*"})
    _stub_resolver(client, {"login-resource.example.test": [address]})
    with pytest.raises(Refused, match="not public address space"):
        asyncio.run(client._dial_address("login-resource.example.test", 443))


@pytest.mark.parametrize("address", _SPECIAL_USE)
def test_a_suffix_name_cannot_reach_special_use_space(address: str) -> None:
    """A suffix is as unenumerable as "*" and gets the same rule. This matters MORE than the
    wildcard: ares ships okta.com / auth0.com / pingone.com as built-in identity-provider suffixes,
    so a suffix entry is not confined to the interactive-login window the wildcard lives in."""
    client = _client(networks=["10.0.0.0/24"], allowed_hosts={".okta.com"})
    _stub_resolver(client, {"tenant.okta.com": [address]})
    with pytest.raises(Refused, match="not public address space"):
        asyncio.run(client._dial_address("tenant.okta.com", 443))


def test_a_pattern_named_public_address_is_still_reachable() -> None:
    """The whole reason "*" exists: a federated login bounces through hosts nobody can list. The
    fix must not break that."""
    client = _client(networks=["10.0.0.0/24"], allowed_hosts={"*"})
    _stub_resolver(client, {"cdn.example.test": ["93.184.216.34"]})
    assert asyncio.run(client._dial_address("cdn.example.test", 443)) == "93.184.216.34"


@pytest.mark.parametrize(
    "answers",
    [
        ["93.184.216.34", "169.254.169.254"],
        ["169.254.169.254", "93.184.216.34"],
    ],
)
def test_one_bad_answer_refuses_the_whole_name(answers: list[str]) -> None:
    """EVERY answer has to pass, not just the one that would be dialled. Whoever controls the DNS
    reply controls its order, so checking a mixed reply and then taking the first record would be
    the same as not checking at all - hence both orderings."""
    client = _client(networks=["10.0.0.0/24"], allowed_hosts={"*"})
    _stub_resolver(client, {"mixed.example.test": answers})
    with pytest.raises(Refused, match="not public address space"):
        asyncio.run(client._dial_address("mixed.example.test", 443))


def test_an_exact_runtime_target_may_be_a_private_host() -> None:
    """An exact name is a destination ares was TOLD to assess, and internal targets under
    split-horizon DNS answer with private addresses. Grading exact with the patterns would refuse
    the hunt's own target."""
    client = _client(networks=["10.0.0.0/24"], allowed_hosts={"intranet.acme.local"})
    _stub_resolver(client, {"intranet.acme.local": ["10.5.0.7"]})
    assert asyncio.run(client._dial_address("intranet.acme.local", 443)) == "10.5.0.7"


def test_the_login_wildcard_does_not_downgrade_the_hunts_own_target() -> None:
    """The regression the narrowest-match rule exists for: "*" is pushed alongside the real target
    during an interactive login, and a first-match implementation refuses that target."""
    client = _client(networks=["10.0.0.0/24"], allowed_hosts={"*", "intranet.acme.local"})
    _stub_resolver(client, {"intranet.acme.local": ["10.5.0.7"]})
    assert asyncio.run(client._dial_address("intranet.acme.local", 443)) == "10.5.0.7"


def test_an_operator_scoped_host_reaches_any_address_class() -> None:
    """A standing decision by a person who typed one exact destination. That is the point of scope:
    an operator can add a host this agent's own detection never reached."""
    client = _client(networks=["10.0.0.0/24"], scoped_hosts={"pinned.example.test"})
    _stub_resolver(client, {"pinned.example.test": ["169.254.169.254"]})
    assert asyncio.run(client._dial_address("pinned.example.test", 443)) == "169.254.169.254"


def test_a_name_inside_the_registered_networks_needs_no_approval_at_all() -> None:
    client = _client(networks=["10.0.0.0/24"])
    _stub_resolver(client, {"db.acme.local": ["10.0.0.15"]})
    assert asyncio.run(client._dial_address("db.acme.local", 443)) == "10.0.0.15"


def test_an_unparseable_answer_is_never_globally_routable() -> None:
    """Fail closed: an address we cannot classify is not one we can vouch for."""
    assert globally_routable("not-an-address") is False
    assert globally_routable("") is False


def test_the_checked_address_is_the_one_dialled() -> None:
    """The existing anti-rebinding property, asserted so the restructure above cannot lose it: the
    concrete address that passed the check is returned, never the name for a second lookup."""
    client = _client(networks=["10.0.0.0/24"], allowed_hosts={"*"})
    _stub_resolver(client, {"many.example.test": ["93.184.216.34", "93.184.216.35"]})
    assert asyncio.run(client._dial_address("many.example.test", 443)) == "93.184.216.34"


# --- static pins ----------------------------------------------------------------------------


def test_a_pin_short_circuits_dns_entirely(tmp_path) -> None:
    """The point of a pin: a name the resolver will not answer still reaches its destination."""
    path = tmp_path / "hosts"
    path.write_text("167.127.118.229 agtacc.allstate.com\n")
    client = TunnelClient(
        "ws://x/api/v1/agent/tunnel",
        "tok",
        ["10.0.0.0/24"],
        {"agtacc.allstate.com"},
        ssl_context=None,
        pins=HostPins(path=path),
    )

    async def go() -> str:
        async def never_answers(*args, **kwargs):  # pragma: no cover - must not be reached
            raise AssertionError("DNS was consulted despite a pin")

        asyncio.get_running_loop().getaddrinfo = never_answers  # type: ignore[method-assign]
        return await client._dial_address("agtacc.allstate.com", 443)

    assert asyncio.run(go()) == "167.127.118.229"


def test_a_pin_supplies_an_address_never_authorization(tmp_path) -> None:
    """A pinned address still has to pass the ordinary check, so pinning cannot widen the agent."""
    path = tmp_path / "hosts"
    path.write_text("203.0.113.10 rogue.example.com\n")
    client = TunnelClient(
        "ws://x/api/v1/agent/tunnel",
        "tok",
        ["10.0.0.0/24"],
        set(),  # ares approved nothing
        ssl_context=None,
        pins=HostPins(path=path),
    )
    with pytest.raises(Refused, match="not an approved target"):
        asyncio.run(client._dial_address("rogue.example.com", 443))


def test_a_resolver_timeout_says_what_happened() -> None:
    """str(TimeoutError()) is empty, so the old message stopped dead at the colon."""
    client = _client()

    async def hang(host, port, **kwargs):
        await asyncio.sleep(3600)

    async def go() -> None:
        loop = asyncio.get_running_loop()
        loop.getaddrinfo = hang  # type: ignore[method-assign]
        with pytest.raises(Refused) as excinfo:
            await client._resolve("slow.example.com", 443)
        message = str(excinfo.value)
        assert message.rstrip().endswith(")"), message
        assert "did not resolve" in message
        assert "the resolver did not answer" in message

    # a real 15s wait would make the suite unusable; shrink the budget for this one assertion.
    import agent.tunnel as tunnel_mod

    original = tunnel_mod._RESOLVE_TIMEOUT
    tunnel_mod._RESOLVE_TIMEOUT = 0.05
    try:
        asyncio.run(go())
    finally:
        tunnel_mod._RESOLVE_TIMEOUT = original


# --- addresses an operator put in the agent's scope by hand -------------------------------------


def test_a_scoped_address_is_dialable_outside_the_registered_networks() -> None:
    """The reason this exists at all.

    The two halves are decided in different places: the agent bounds an IP literal by the networks
    IT detected, while the scope is what ares was told. An operator can legitimately add an address
    the agent's own detection never reached, and without this clause the scan finds that host and
    the tunnel then refuses to dial it, which reads as a machine that exists and cannot be
    assessed.
    """
    client = _client(networks=["10.0.0.0/24"], scoped_hosts={"10.20.1.50"})

    async def go() -> str:
        return await client._dial_address("10.20.1.50", 443)

    assert asyncio.run(go()) == "10.20.1.50"


def test_a_scoped_address_grants_that_address_and_nothing_beside_it() -> None:
    """Exact match only. The scope is a statement about one machine, so it must never widen into
    the machine's neighbours the way a network entry would."""
    client = _client(networks=["10.0.0.0/24"], scoped_hosts={"10.20.1.50"})

    async def go() -> str:
        return await client._dial_address("10.20.1.51", 443)

    with pytest.raises(Refused):
        asyncio.run(go())


def test_a_scoped_name_never_matches_by_suffix() -> None:
    """host_approved beside this one understands wildcards and domain suffixes, because a
    federated login visits hosts nobody can enumerate. A hand-added host is not that, so
    "payroll.corp.local" must not carry "evil.payroll.corp.local" with it."""
    client = _client(networks=["10.0.0.0/24"], scoped_hosts={"payroll.corp.local"})
    _stub_resolver(client, {"evil.payroll.corp.local": ["203.0.113.9"]})

    async def go() -> str:
        return await client._dial_address("evil.payroll.corp.local", 443)

    with pytest.raises(Refused):
        asyncio.run(go())


def test_scoped_hosts_reach_a_live_tunnel_without_a_reconnect() -> None:
    """The manager mutates the shared set in place, exactly as it does for the per-hunt allowlist,
    so an address added in the dashboard is dialable on the next beat rather than at the next
    reconnect."""
    manager = TunnelManager(
        "ws://x/api/v1/agent/tunnel", "tok", ["10.0.0.0/24"], ssl_context=None
    )
    shared = manager._scoped_hosts

    manager.sync(False, (), ("10.20.1.50",))

    assert shared is manager._scoped_hosts  # same object: a live client sees the update
    assert manager._scoped_hosts == {"10.20.1.50"}


def test_set_networks_widens_what_an_ip_literal_is_bounded_by() -> None:
    """Reachability discovery keeps running after enrollment, so what the agent believes it can
    reach has to be updatable. Reporting a new network to ares without this leaves the scan finding
    hosts the tunnel refuses."""
    manager = TunnelManager(
        "ws://x/api/v1/agent/tunnel", "tok", ["172.23.0.0/16"], ssl_context=None
    )

    manager.set_networks(["172.23.0.0/16", "10.20.0.0/16"])

    assert manager._allowed_networks == ["172.23.0.0/16", "10.20.0.0/16"]
