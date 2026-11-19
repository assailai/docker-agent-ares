"""The dial guard (ARES-2308, finding find_011CgpEPZGs44VxrUaizRKvD).

ares approves a tunnel destination by NAME and the agent resolves it at dial time, on the
customer's DNS. A name whose answer moves after approval (a rebinding answer, or split-horizon)
used to be dialled wherever it then pointed whenever the name had been approved exactly, which is
how every interactive-login host and every operator-scoped host is approved. These tests pin the
fix: every address a name yields is judged at dial time, loopback / link-local / cloud metadata /
unspecified / multicast / broadcast never reach a socket, private space still does, and the socket
goes to the literal that was judged, from one resolution per dial.

Resolution is faked at ``loop.getaddrinfo`` (not by stubbing ``TunnelClient._resolve``), so the real
lookup -> vet -> authorize -> connect path runs end to end.
"""

from __future__ import annotations

import asyncio
import json
import socket
from pathlib import Path

import pytest

from agent import dial_guard
from agent.dial_guard import Forbidden, Refused, canonical_address, forbidden_class, vet
from agent.hostpins import HostPins
from agent.tunnel import _OPEN_ERR, _OPEN_OK, TunnelClient, _decode

# the phrase every guard refusal carries, whichever rule of the guard fired
NEVER_DIALS = "never dials"
# a path that never exists, so a developer's own /host-hosts can never leak into a test
_NO_HOSTS_FILE = Path("/nonexistent/ares-test/host-hosts")


# ── helpers ───────────────────────────────────────────────────────────────────────────────────


class _RecordingWS:
    def __init__(self) -> None:
        self.sent: list[bytes] = []

    async def send(self, frame: bytes) -> None:
        self.sent.append(frame)

    def reply(self, stream_id: int) -> tuple[int, str]:
        """The OPEN_OK / OPEN_ERR sent for ``stream_id``, with its reason. Exactly one is allowed."""
        found = [
            (opcode, payload.decode("utf-8"))
            for opcode, sid, payload in map(_decode, self.sent)
            if sid == stream_id and opcode in (_OPEN_OK, _OPEN_ERR)
        ]
        assert len(found) == 1, found
        return found[0]


class _FakeReader:
    """A target that hangs up at once, so the relay task ends instead of outliving the test."""

    async def read(self, _n: int) -> bytes:
        return b""


class _FakeWriter:
    def write(self, _data: bytes) -> None:
        return None

    async def drain(self) -> None:
        return None

    def close(self) -> None:
        return None


def _info(address: str, port: int) -> tuple:
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    sockaddr = (address, port, 0, 0) if family == socket.AF_INET6 else (address, port)
    return (family, socket.SOCK_STREAM, 6, "", sockaddr)


class _Resolver:
    """A fake ``loop.getaddrinfo`` that answers from a script and counts every lookup.

    ``answers`` maps a name to the list of answers it gives on successive lookups; the last answer
    repeats. That is exactly the shape of a rebinding name: one answer while ares looks, another
    when the agent dials.
    """

    def __init__(self, answers: dict[str, list[list[str]]]) -> None:
        self._answers = answers
        self.calls: list[str] = []

    async def __call__(self, host: str, port: int, **_kwargs: object) -> list[tuple]:
        self.calls.append(host)
        script = self._answers.get(host)
        if not script:
            raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")
        answer = script[min(len(self.calls_for(host)) - 1, len(script) - 1)]
        return [_info(address, port) for address in answer]

    def calls_for(self, host: str) -> list[str]:
        return [call for call in self.calls if call == host]


def _install(monkeypatch: pytest.MonkeyPatch, resolver: _Resolver) -> None:
    monkeypatch.setattr(asyncio.get_running_loop(), "getaddrinfo", resolver)


def _record_dials(monkeypatch: pytest.MonkeyPatch, *, succeed: bool = False) -> list[str]:
    """Replace the socket connect and return the list of hosts it was handed, in order.

    Fails every connect unless ``succeed``, so a test sees every address the agent tries.
    """
    dialled: list[str] = []

    async def fake_open_connection(host: str, port: int, **_kwargs: object):
        dialled.append(host)
        if succeed:
            return _FakeReader(), _FakeWriter()
        raise OSError("no listener in the test")

    monkeypatch.setattr(asyncio, "open_connection", fake_open_connection)
    return dialled


def _client(
    *,
    networks: list[str] | None = None,
    allowed_hosts: set[str] | None = None,
    scoped_hosts: set[str] | None = None,
    pins: HostPins | None = None,
) -> tuple[TunnelClient, _RecordingWS]:
    client = TunnelClient(
        "ws://x/api/v1/agent/tunnel",
        "tok",
        networks if networks is not None else ["10.0.0.0/24"],
        allowed_hosts if allowed_hosts is not None else set(),
        scoped_hosts=scoped_hosts if scoped_hosts is not None else set(),
        ssl_context=None,
        pins=pins if pins is not None else HostPins(path=_NO_HOSTS_FILE),
    )
    ws = _RecordingWS()
    client._ws = ws  # type: ignore[assignment]
    return client, ws


def _open_frame(host: str, port: int = 80) -> bytes:
    return json.dumps({"host": host, "port": port}).encode()


# ── the classifier ────────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("address", "expected"),
    [
        pytest.param("127.0.0.1", Forbidden.LOOPBACK, id="loopback"),
        pytest.param("127.255.255.254", Forbidden.LOOPBACK, id="loopback-whole-8"),
        pytest.param("::1", Forbidden.LOOPBACK, id="v6-loopback"),
        pytest.param("::ffff:127.0.0.1", Forbidden.LOOPBACK, id="mapped-loopback"),
        pytest.param("169.254.169.254", Forbidden.CLOUD_METADATA, id="imds"),
        pytest.param("::ffff:169.254.169.254", Forbidden.CLOUD_METADATA, id="mapped-imds"),
        pytest.param("169.254.170.2", Forbidden.CLOUD_METADATA, id="ecs-task-credentials"),
        pytest.param("fd00:ec2::254", Forbidden.CLOUD_METADATA, id="aws-imds-v6-in-ula"),
        pytest.param("fd00:ec2::254%eth0", Forbidden.CLOUD_METADATA, id="aws-imds-v6-zone"),
        pytest.param("100.100.100.200", Forbidden.CLOUD_METADATA, id="alibaba-in-cgnat"),
        pytest.param("168.63.129.16", Forbidden.CLOUD_METADATA, id="azure-wireserver"),
        pytest.param("169.254.1.1", Forbidden.LINK_LOCAL, id="link-local"),
        pytest.param("fe80::1", Forbidden.LINK_LOCAL, id="v6-link-local"),
        pytest.param("fe80::1%eth0", Forbidden.LINK_LOCAL, id="v6-link-local-zone"),
        pytest.param("0.0.0.0", Forbidden.UNSPECIFIED, id="unspecified"),
        pytest.param("0.1.2.3", Forbidden.UNSPECIFIED, id="this-network"),
        pytest.param("::", Forbidden.UNSPECIFIED, id="v6-unspecified"),
        pytest.param("224.0.0.1", Forbidden.MULTICAST, id="multicast"),
        pytest.param("239.255.255.250", Forbidden.MULTICAST, id="multicast-scoped"),
        pytest.param("ff02::1", Forbidden.MULTICAST, id="v6-multicast"),
        pytest.param("255.255.255.255", Forbidden.BROADCAST, id="broadcast"),
        # an IPv4 address carried inside IPv6 by another mechanism is judged as that IPv4 address
        pytest.param("64:ff9b::a9fe:a9fe", Forbidden.CLOUD_METADATA, id="nat64-imds"),
        pytest.param("64:ff9b::7f00:1", Forbidden.LOOPBACK, id="nat64-loopback"),
        pytest.param("2002:7f00:1::1", Forbidden.LOOPBACK, id="6to4-loopback"),
        pytest.param("::127.0.0.1", Forbidden.LOOPBACK, id="v4-compatible-loopback"),
        # fail closed: a name where an address belongs is refused, never resolved
        pytest.param("metadata.google.internal", Forbidden.UNPARSEABLE, id="a-name"),
        pytest.param("", Forbidden.UNPARSEABLE, id="empty"),
    ],
)
def test_forbidden_addresses_are_classified(address: str, expected: Forbidden) -> None:
    assert forbidden_class(address) is expected


@pytest.mark.parametrize(
    "address",
    [
        # the customer's internal network is the whole point of the agent
        pytest.param("10.0.0.5", id="rfc1918-10"),
        pytest.param("172.16.4.2", id="rfc1918-172"),
        pytest.param("192.168.1.10", id="rfc1918-192"),
        pytest.param("100.64.0.1", id="cgnat"),
        pytest.param("fd12:3456:789a::1", id="ula"),
        pytest.param("::ffff:10.0.0.5", id="mapped-private"),
        pytest.param("64:ff9b::a00:5", id="nat64-private"),
        # and public space, for a login host or a public target
        pytest.param("93.184.216.34", id="public-v4"),
        pytest.param("2606:4700::1111", id="public-v6"),
    ],
)
def test_private_and_public_addresses_are_allowed(address: str) -> None:
    assert forbidden_class(address) is None


def test_a_mapped_address_is_dialled_in_its_ipv4_form() -> None:
    assert str(canonical_address("::ffff:10.0.0.5")) == "10.0.0.5"


# ── vet: one answer in, the dialable part out ─────────────────────────────────────────────────


def test_vet_drops_forbidden_records_and_keeps_the_rest_in_order() -> None:
    vetted = vet(
        "mixed.example.test",
        ["169.254.169.254", "10.0.0.9", "::ffff:127.0.0.1", "93.184.216.34", "::ffff:10.0.0.9"],
    )
    # canonical and deduplicated: the mapped spelling of 10.0.0.9 is the same destination
    assert vetted.addresses == ("10.0.0.9", "93.184.216.34")
    assert vetted.dropped == (
        ("169.254.169.254", Forbidden.CLOUD_METADATA),
        ("::ffff:127.0.0.1", Forbidden.LOOPBACK),
    )
    note = vetted.drop_note("mixed.example.test")
    assert "169.254.169.254 (cloud metadata)" in note and "10.0.0.9" in note


def test_vet_refuses_when_nothing_dialable_remains() -> None:
    with pytest.raises(Refused, match=NEVER_DIALS) as excinfo:
        vet("rebound.example.test", ["169.254.169.254", "fe80::1"])
    assert "169.254.169.254 (cloud metadata)" in str(excinfo.value)
    assert "fe80::1 (link-local)" in str(excinfo.value)


def test_vet_of_an_empty_answer_says_so() -> None:
    with pytest.raises(Refused, match="resolved to no address"):
        vet("empty.example.test", [])


# ── lookup and connect ────────────────────────────────────────────────────────────────────────


async def test_lookup_resolves_once(monkeypatch: pytest.MonkeyPatch) -> None:
    resolver = _Resolver({"bank.internal": [["10.0.0.7", "10.0.0.7", "10.0.0.8"]]})
    _install(monkeypatch, resolver)
    assert await dial_guard.lookup("bank.internal", 443, timeout=1.0) == ["10.0.0.7", "10.0.0.8"]
    assert resolver.calls == ["bank.internal"]


async def test_open_vetted_never_resolves_a_name(monkeypatch: pytest.MonkeyPatch) -> None:
    resolver = _Resolver({"sso.attacker.example": [["127.0.0.1"]]})
    _install(monkeypatch, resolver)
    dialled = _record_dials(monkeypatch)
    with pytest.raises(Refused, match="not an IP address"):
        await dial_guard.open_vetted("sso.attacker.example", 80, timeout=1.0)
    assert resolver.calls == [] and dialled == []


@pytest.mark.parametrize("address", ["127.0.0.1", "169.254.169.254", "::ffff:127.0.0.1"])
async def test_open_vetted_refuses_a_forbidden_literal_at_the_socket(
    monkeypatch: pytest.MonkeyPatch, address: str
) -> None:
    dialled = _record_dials(monkeypatch)
    with pytest.raises(Refused, match=NEVER_DIALS):
        await dial_guard.open_vetted(address, 80, timeout=1.0)
    assert dialled == []


async def test_open_vetted_dials_the_canonical_literal(monkeypatch: pytest.MonkeyPatch) -> None:
    dialled = _record_dials(monkeypatch, succeed=True)
    await dial_guard.open_vetted("::ffff:10.0.0.5", 80, timeout=1.0)
    assert dialled == ["10.0.0.5"]


# ── the tunnel: a pushed name can never be dialled onto a forbidden address ──────────────────────

_FORBIDDEN_ANSWERS = [
    pytest.param("127.0.0.1", id="loopback"),
    pytest.param("169.254.169.254", id="cloud-metadata"),
    pytest.param("::ffff:127.0.0.1", id="mapped-loopback"),
    pytest.param("fe80::1", id="v6-link-local"),
    pytest.param("fd00:ec2::254", id="aws-imds-v6"),
    pytest.param("0.0.0.0", id="unspecified"),
]

# every way a name can be authorized. Before the fix the first four dialled wherever the name
# pointed; only the pattern was held to public space.
_APPROVALS = [
    pytest.param({"allowed_hosts": {"sso.attacker.example"}}, id="exact-login-host-older-agent"),
    pytest.param(
        {"allowed_hosts": {"*", "sso.attacker.example"}}, id="exact-plus-wildcard-login-window"
    ),
    pytest.param({"scoped_hosts": {"sso.attacker.example"}}, id="operator-scope"),
    pytest.param(
        # host-all puts 127.0.0.1/32 in the registered networks; nothing may put a NAME there
        {"networks": ["127.0.0.0/8", "169.254.0.0/16", "fe80::/10", "fd00::/8", "0.0.0.0/8"]},
        id="inside-registered-networks",
    ),
    pytest.param({"allowed_hosts": {"*"}}, id="wildcard"),
]


@pytest.mark.parametrize("approval", _APPROVALS)
@pytest.mark.parametrize("answer", _FORBIDDEN_ANSWERS)
async def test_a_pushed_name_resolving_to_a_forbidden_address_is_refused(
    monkeypatch: pytest.MonkeyPatch, approval: dict, answer: str
) -> None:
    client, ws = _client(**approval)
    _install(monkeypatch, _Resolver({"sso.attacker.example": [[answer]]}))
    dialled = _record_dials(monkeypatch, succeed=True)

    await client._open(7, _open_frame("sso.attacker.example"))

    assert dialled == []
    opcode, reason = ws.reply(7)
    assert opcode == _OPEN_ERR
    assert NEVER_DIALS in reason


@pytest.mark.parametrize("answer", ["10.20.1.5", "192.168.40.2", "93.184.216.34"])
async def test_a_pushed_name_connects_to_exactly_the_address_it_resolved_to(
    monkeypatch: pytest.MonkeyPatch, answer: str
) -> None:
    """Private space stays reachable (the agent's purpose), and the socket goes to the literal."""
    client, ws = _client(allowed_hosts={"intranet.acme.local"})
    resolver = _Resolver({"intranet.acme.local": [[answer]]})
    _install(monkeypatch, resolver)
    dialled = _record_dials(monkeypatch, succeed=True)

    await client._open(8, _open_frame("intranet.acme.local", 443))

    assert dialled == [answer]
    assert ws.reply(8)[0] == _OPEN_OK
    assert resolver.calls == ["intranet.acme.local"]


async def test_a_mixed_answer_dials_only_the_vetted_records(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    client, ws = _client(allowed_hosts={"intranet.acme.local"})
    answer = ["169.254.169.254", "10.20.1.5", "127.0.0.1", "93.184.216.34", "fe80::1"]
    _install(monkeypatch, _Resolver({"intranet.acme.local": [answer]}))
    dialled = _record_dials(monkeypatch)  # every connect fails, so every kept record is tried

    with caplog.at_level("WARNING", logger="ares.agent.tunnel"):
        await client._open(9, _open_frame("intranet.acme.local", 443))

    assert dialled == ["10.20.1.5", "93.184.216.34"]
    assert ws.reply(9)[0] == _OPEN_ERR  # both dials failed in the test
    assert any("169.254.169.254 (cloud metadata)" in r.getMessage() for r in caplog.records)


async def test_a_wildcard_mixed_answer_dials_only_the_public_record(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The "*" login window: a forbidden record is dropped, not dialled, and the public one opens."""
    client, ws = _client(allowed_hosts={"*"})
    _install(monkeypatch, _Resolver({"cdn.example.test": [["169.254.169.254", "93.184.216.34"]]}))
    dialled = _record_dials(monkeypatch, succeed=True)

    await client._open(10, _open_frame("cdn.example.test", 443))

    assert dialled == ["93.184.216.34"]
    assert ws.reply(10)[0] == _OPEN_OK


async def test_a_rebinding_name_cannot_steer_the_socket(monkeypatch: pytest.MonkeyPatch) -> None:
    """The exploit: the name answers a public address first and loopback on every lookup after.

    One OPEN resolves exactly once and dials the literal it judged, so the second answer can never
    reach the socket of that dial; and a later OPEN that does see the rebound answer is refused.
    The fake connect performs a lookup of its own whenever it is handed a NAME, so a by-name dial
    would show up as an extra lookup here.
    """
    client, ws = _client(allowed_hosts={"*", "sso.attacker.example"})
    resolver = _Resolver({"sso.attacker.example": [["93.184.216.34"], ["127.0.0.1"]]})
    _install(monkeypatch, resolver)
    dialled: list[str] = []

    async def connect_like_asyncio(host: str, port: int, **_kwargs: object):
        if canonical_address(host) is None:  # a name: resolve it, as asyncio would
            infos = await asyncio.get_running_loop().getaddrinfo(host, port)
            host = infos[0][4][0]
        dialled.append(host)
        return _FakeReader(), _FakeWriter()

    monkeypatch.setattr(asyncio, "open_connection", connect_like_asyncio)

    await client._open(11, _open_frame("sso.attacker.example"))
    assert resolver.calls == ["sso.attacker.example"]  # one lookup for the whole dial
    assert dialled == ["93.184.216.34"]
    assert ws.reply(11)[0] == _OPEN_OK

    await client._open(12, _open_frame("sso.attacker.example"))  # DNS has now moved to loopback
    assert dialled == ["93.184.216.34"]  # nothing new reached a socket
    opcode, reason = ws.reply(12)
    assert opcode == _OPEN_ERR
    assert "127.0.0.1 (loopback)" in reason


async def test_a_pin_to_the_hosts_own_loopback_is_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    """Debian-family /etc/hosts maps the machine's own hostname to 127.0.1.1, and the agent reads
    the host's file. A pushed name equal to that hostname must not land on this host's loopback."""
    hosts = tmp_path / "hosts"
    hosts.write_text("127.0.1.1 agent-box.corp.local agent-box\n")
    client, ws = _client(allowed_hosts={"agent-box"}, pins=HostPins(path=hosts))
    dialled = _record_dials(monkeypatch, succeed=True)

    await client._open(13, _open_frame("agent-box"))

    assert dialled == []
    assert ws.reply(13)[0] == _OPEN_ERR


# ── IP literals ─────────────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "literal", ["169.254.169.254", "127.0.0.1", "::ffff:169.254.169.254", "fd00:ec2::254"]
)
async def test_a_forbidden_literal_in_the_pushed_scope_is_refused(
    monkeypatch: pytest.MonkeyPatch, literal: str
) -> None:
    """Scope is what ares pushed, so it cannot put a forbidden address in reach either."""
    client, ws = _client(scoped_hosts={literal})
    dialled = _record_dials(monkeypatch, succeed=True)

    await client._open(14, _open_frame(literal))

    assert dialled == []
    assert NEVER_DIALS in ws.reply(14)[1]


async def test_link_local_stays_refused_even_inside_the_registered_networks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, ws = _client(networks=["169.254.0.0/16"])
    dialled = _record_dials(monkeypatch, succeed=True)

    await client._open(15, _open_frame("169.254.169.254"))

    assert dialled == []
    assert ws.reply(15)[0] == _OPEN_ERR


# ── real sockets: the guard holds against an actual loopback listener ────────────────────────────


async def test_real_loopback_listener_is_reached_only_by_a_registered_literal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """End to end on real sockets, no connect fake.

    A listener on 127.0.0.1 stands in for a service bound to the agent host's localhost. A pushed
    NAME resolving there is refused and the listener never sees a connection, even though the
    registered networks contain 127.0.0.1/32 (``ARES_SCAN_SCOPE=host-all``). The same address as a
    literal inside those networks is the one deliberate exception, and it does connect.
    """
    # pinned explicitly: another test module may have left a fake in its place
    monkeypatch.setattr(asyncio, "open_connection", asyncio.streams.open_connection)
    accepted: list[int] = []

    async def on_connect(_reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        accepted.append(1)
        writer.close()

    server = await asyncio.start_server(on_connect, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        client, ws = _client(
            networks=["127.0.0.1/32", "10.0.0.0/24"],
            allowed_hosts={"*", "sso.attacker.example"},
        )
        _install(monkeypatch, _Resolver({"sso.attacker.example": [["127.0.0.1"]]}))

        await client._open(20, _open_frame("sso.attacker.example", port))
        await asyncio.sleep(0.05)
        assert ws.reply(20)[0] == _OPEN_ERR
        assert accepted == []

        await client._open(21, _open_frame("127.0.0.1", port))
        await asyncio.sleep(0.05)
        assert ws.reply(21)[0] == _OPEN_OK
        assert accepted == [1]
    finally:
        # the listener hangs up straight away, so the relay task sees EOF and ends on its own
        server.close()
        await server.wait_closed()
