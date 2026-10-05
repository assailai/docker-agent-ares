"""Identity evidence: what a live host says about itself, and what we refuse to invent.

The TLS tests drive a real local listener with a real certificate (via ``trustme``), because the
one thing this module must get right is reading a certificate the peer did NOT prove: under
``CERT_NONE`` CPython's ``getpeercert()`` returns an empty dict, and only ``binary_form=True``
returns anything at all. A mock would happily hide that.
"""

from __future__ import annotations

import asyncio
import base64
import ssl
import struct

import pytest
import trustme

from agent import identify
from agent.identify import HostEvidence, IdentityProbe, ServiceEvidence
from agent.kubeinfo import KubernetesEvidence


# --- TLS certificate collection -----------------------------------------------------------------


@pytest.fixture(scope="module")
def ca() -> trustme.CA:
    return trustme.CA()


async def _tls_server(ca: trustme.CA, name: str = "esxi-01.acme.internal"):
    """A TLS listener presenting a cert for ``name``, signed by a CA nothing here trusts."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ca.issue_cert(name).configure_cert(ctx)
    server = await asyncio.start_server(lambda r, w: w.close(), "127.0.0.1", 0, ssl=ctx)
    return server, server.sockets[0].getsockname()[1]


async def test_tls_certificate_reads_an_untrusted_peer(ca: trustme.CA) -> None:
    # the whole design rests on this: the cert is readable even though we do not trust its issuer,
    # which is the normal case for an internal estate full of self-signed devices.
    server, port = await _tls_server(ca)
    try:
        der_b64 = await identify.tls_certificate("127.0.0.1", port, timeout=5.0)
    finally:
        server.close()
        await server.wait_closed()

    assert der_b64 is not None
    der = base64.b64decode(der_b64)
    assert der[:1] == b"\x30"  # a DER SEQUENCE, i.e. a real certificate rather than noise


async def test_tls_certificate_returns_none_on_a_plaintext_port() -> None:
    # a "TLS" port that is not actually TLS must be a missing signal, never an exception.
    server = await asyncio.start_server(lambda r, w: w.close(), "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        assert await identify.tls_certificate("127.0.0.1", port, timeout=1.0) is None
    finally:
        server.close()
        await server.wait_closed()


async def test_tls_certificate_returns_none_when_nothing_listens() -> None:
    assert await identify.tls_certificate("127.0.0.1", 1, timeout=0.5) is None


async def test_oversized_certificate_is_dropped(
    ca: trustme.CA, monkeypatch: pytest.MonkeyPatch
) -> None:
    # a device serving something enormous costs bytes on a report carrying hundreds of hosts, so
    # it is dropped rather than shipped.
    monkeypatch.setattr(identify, "MAX_CERT_BYTES", 8)
    server, port = await _tls_server(ca)
    try:
        assert await identify.tls_certificate("127.0.0.1", port, timeout=5.0) is None
    finally:
        server.close()
        await server.wait_closed()


# --- reverse DNS --------------------------------------------------------------------------------


async def test_reverse_dns_resolves_loopback() -> None:
    # loopback is the one PTR every machine answers. Note the value: "localhost" is exactly the
    # junk ares must reject, which is why the agent reports it verbatim rather than judging it.
    assert await identify.reverse_dns("127.0.0.1", timeout=5.0) == "localhost"


async def test_reverse_dns_returns_none_without_a_ptr() -> None:
    # an address with no PTR is a missing name, not an error: NI_NAMEREQD is what stops the
    # resolver handing back the address itself dressed up as a name.
    assert await identify.reverse_dns("192.0.2.123", timeout=2.0) is None


async def test_reverse_dns_times_out_quietly(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _hang(*_a, **_k):
        await asyncio.sleep(10)

    loop = asyncio.get_running_loop()
    monkeypatch.setattr(type(loop), "getnameinfo", lambda *a, **k: _hang(), raising=False)
    assert await identify.reverse_dns("10.0.0.1", timeout=0.05) is None


# --- HTTP probe ---------------------------------------------------------------------------------


def test_parse_http_extracts_title_server_and_redirect() -> None:
    raw = (
        b"HTTP/1.1 302 Found\r\n"
        b"Server: nginx/1.24.0\r\n"
        b"Location: https://vcenter.acme.internal/ui\r\n"
        b"WWW-Authenticate: Basic realm=\"ESXi\"\r\n\r\n"
        b"<html><head><title>  VMware  ESXi  </title></head></html>"
    )
    ev = identify._parse_http(443, raw)
    assert ev is not None
    assert ev.http_status == 302
    assert ev.http_server == "nginx/1.24.0"
    assert ev.http_location == "https://vcenter.acme.internal/ui"
    assert ev.http_auth_realm == 'Basic realm="ESXi"'
    assert ev.http_title == "VMware ESXi"  # whitespace collapsed


def test_parse_http_without_a_title() -> None:
    ev = identify._parse_http(80, b"HTTP/1.0 200 OK\r\nServer: gunicorn\r\n\r\n{}")
    assert ev is not None
    assert ev.http_title is None
    assert ev.http_server == "gunicorn"


def test_parse_http_rejects_a_non_http_banner() -> None:
    # SSH answers on connect with its own banner; that is not an HTTP response and must not be
    # parsed as one.
    assert identify._parse_http(22, b"SSH-2.0-OpenSSH_9.6\r\n") is None


async def test_http_probe_against_a_real_listener() -> None:
    async def _handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await reader.read(1024)
        writer.write(
            b"HTTP/1.1 200 OK\r\nServer: Apache/2.4\r\n\r\n<title>Printer Admin</title>"
        )
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(_handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        ev = await identify.http_probe("127.0.0.1", port, timeout=5.0)
    finally:
        server.close()
        await server.wait_closed()

    assert ev is not None
    assert ev.http_title == "Printer Admin"
    assert ev.http_server == "Apache/2.4"
    assert ev.port == port


async def test_http_probe_returns_none_when_nothing_listens() -> None:
    assert await identify.http_probe("127.0.0.1", 1, timeout=0.5) is None


# --- NetBIOS ------------------------------------------------------------------------------------


def test_nbstat_query_is_a_wildcard_node_status() -> None:
    q = identify.build_nbstat_query()
    assert len(q) == 50
    assert q[4:6] == struct.pack(">H", 1)  # exactly one question
    assert q[-4:] == struct.pack(">HH", 0x0021, 0x0001)  # NBSTAT, IN


def _nbstat_reply(names: list[tuple[str, int, bool]]) -> bytes:
    """A synthetic NBSTAT reply carrying ``(name, suffix, is_group)`` entries."""
    body = bytearray(12 + 1 + 32 + 1 + 4)  # header + echoed question
    body += bytearray(1 + 32 + 1 + 4 + 4 + 2)  # answer name + type + class + ttl + rdlength
    body.append(len(names))
    for name, suffix, is_group in names:
        body += name.ljust(15).encode("latin-1")[:15]
        body.append(suffix)
        body += struct.pack(">H", 0x8000 if is_group else 0x0400)
    return bytes(body)


def test_parse_nbstat_reply_picks_the_unique_workstation_name() -> None:
    data = _nbstat_reply([("ACME", 0x00, True), ("FILESRV01", 0x00, False)])
    assert identify.parse_nbstat_reply(data) == "FILESRV01"


def test_parse_nbstat_reply_skips_group_and_service_entries() -> None:
    # a workgroup name (group) and a messenger entry (suffix 0x03) are not the machine's name.
    data = _nbstat_reply([("WORKGROUP", 0x00, True), ("SOMEONE", 0x03, False)])
    assert identify.parse_nbstat_reply(data) is None


def test_parse_nbstat_reply_survives_a_truncated_packet() -> None:
    assert identify.parse_nbstat_reply(b"\x00" * 20) is None


async def test_netbios_name_returns_none_when_nothing_answers() -> None:
    # 203.0.113.0/24 is TEST-NET-3: nothing there will ever reply.
    assert await identify.netbios_name("203.0.113.7", timeout=0.2) is None


# --- the probe as a whole -------------------------------------------------------------------


async def test_probe_gathers_every_enabled_source(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _ptr(ip, *, timeout):
        return "db-01.corp.local"

    async def _cert(ip, port, *, timeout):
        return "Y2VydA==" if port == 443 else None

    async def _http(ip, port, *, timeout):
        return ServiceEvidence(port=port, http_title="Grafana", http_server="nginx")

    async def _nb(ip, *, timeout):
        return "DB01"

    monkeypatch.setattr(identify, "reverse_dns", _ptr)
    monkeypatch.setattr(identify, "tls_certificate", _cert)
    monkeypatch.setattr(identify, "http_probe", _http)
    monkeypatch.setattr(identify, "netbios_name", _nb)

    probe = IdentityProbe(hosts_file_lookup=lambda ip: "db-01")
    ev = await probe.run("10.0.0.9", {443: "https", 80: "http", 5432: "postgres"})

    assert ev.ip == "10.0.0.9"
    assert ev.ptr_name == "db-01.corp.local"
    assert ev.hosts_file_name == "db-01"
    assert ev.netbios_name == "DB01"
    # the cert and the HTTP result for the same port land on ONE service entry, not two.
    by_port = {s.port: s for s in ev.services}
    assert by_port[443].tls_cert_der == "Y2VydA=="
    assert by_port[443].http_title == "Grafana"
    assert 5432 not in by_port  # a database port is neither a TLS nor an HTTP probe target


async def test_probe_respects_per_source_toggles(monkeypatch: pytest.MonkeyPatch) -> None:
    called: list[str] = []

    async def _ptr(ip, *, timeout):
        called.append("ptr")
        return "nope"

    async def _cert(ip, port, *, timeout):
        called.append("tls")
        return "x"

    async def _http(ip, port, *, timeout):
        called.append("http")
        return ServiceEvidence(port=port, http_title="x")

    async def _nb(ip, *, timeout):
        called.append("netbios")
        return "x"

    monkeypatch.setattr(identify, "reverse_dns", _ptr)
    monkeypatch.setattr(identify, "tls_certificate", _cert)
    monkeypatch.setattr(identify, "http_probe", _http)
    monkeypatch.setattr(identify, "netbios_name", _nb)

    probe = IdentityProbe(reverse_dns=False, tls=False, http=True, netbios=False)
    await probe.run("10.0.0.9", {443: "https"})
    assert called == ["http"]


async def test_probe_caps_how_many_ports_it_touches(monkeypatch: pytest.MonkeyPatch) -> None:
    # a host listening on everything must not cost one handshake per port.
    probed: list[int] = []

    async def _cert(ip, port, *, timeout):
        probed.append(port)
        return None

    async def _nothing(*_a, **_k):
        return None

    monkeypatch.setattr(identify, "tls_certificate", _cert)
    monkeypatch.setattr(identify, "reverse_dns", _nothing)
    monkeypatch.setattr(identify, "netbios_name", _nothing)
    monkeypatch.setattr(identify, "http_probe", _nothing)

    probe = IdentityProbe()
    await probe.run("10.0.0.9", dict.fromkeys(identify.TLS_PORTS, "https"))
    assert len(probed) == identify.MAX_TLS_PROBES


async def test_a_domain_controller_gets_its_ldaps_certificate_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """636 must survive the cap on a host that also serves web ports.

    A domain controller's LDAPS certificate is issued to the machine by the domain, so it is one of
    the few that reliably carries a real FQDN. It sits above the web-adjacent ports in the list for
    that reason, and this pins the consequence rather than the list order itself.
    """
    probed: list[int] = []

    async def _cert(ip, port, *, timeout):
        probed.append(port)
        return None

    async def _nothing(*_a, **_k):
        return None

    monkeypatch.setattr(identify, "tls_certificate", _cert)
    monkeypatch.setattr(identify, "reverse_dns", _nothing)
    monkeypatch.setattr(identify, "netbios_name", _nothing)
    monkeypatch.setattr(identify, "http_probe", _nothing)

    await IdentityProbe().run(
        "10.0.0.9", dict.fromkeys([443, 636, 902, 8006, 5480, 993, 995], "https")
    )
    assert 636 in probed


async def test_a_container_on_an_arbitrary_port_is_still_probed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """8090 is in no curated list, which is the normal shape of a published container.

    A fixed port list can only describe software running where its authors put it, so leftover
    budget goes to ports the sweep could not identify.
    """
    tls_probed: list[int] = []
    http_probed: list[int] = []

    async def _cert(ip, port, *, timeout):
        tls_probed.append(port)
        return None

    async def _http(ip, port, *, timeout):
        http_probed.append(port)
        return None

    async def _nothing(*_a, **_k):
        return None

    monkeypatch.setattr(identify, "tls_certificate", _cert)
    monkeypatch.setattr(identify, "http_probe", _http)
    monkeypatch.setattr(identify, "reverse_dns", _nothing)
    monkeypatch.setattr(identify, "netbios_name", _nothing)

    await IdentityProbe().run("10.0.0.9", {8090: "unknown", 22: "ssh"})

    assert tls_probed == [8090]
    assert http_probed == [8090]


async def test_ports_the_sweep_identified_as_something_else_are_left_alone(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # a database and a printer's raw port will never yield a name, and sending them
    # application-layer bytes is traffic aimed at things with no reason to receive it.
    probed: list[int] = []

    async def _record(ip, port, *, timeout):
        probed.append(port)
        return None

    async def _nothing(*_a, **_k):
        return None

    monkeypatch.setattr(identify, "tls_certificate", _record)
    monkeypatch.setattr(identify, "http_probe", _record)
    monkeypatch.setattr(identify, "reverse_dns", _nothing)
    monkeypatch.setattr(identify, "netbios_name", _nothing)

    await IdentityProbe().run(
        "10.0.0.9", {5432: "postgres", 3306: "mysql", 9100: "unknown-printer", 22: "ssh"}
    )

    assert probed == []


async def test_a_raw_print_port_is_never_probed(monkeypatch: pytest.MonkeyPatch) -> None:
    """9100 prints whatever you send it.

    The sweep does not reach it today, but it is unlabelled, so the day someone widens the port
    list a stray GET becomes a page of garbage on every printer in the estate. Pinned here rather
    than left to a comment.
    """
    probed: list[int] = []

    async def _record(ip, port, *, timeout):
        probed.append(port)
        return None

    async def _nothing(*_a, **_k):
        return None

    monkeypatch.setattr(identify, "tls_certificate", _record)
    monkeypatch.setattr(identify, "http_probe", _record)
    monkeypatch.setattr(identify, "reverse_dns", _nothing)
    monkeypatch.setattr(identify, "netbios_name", _nothing)

    await IdentityProbe().run("10.0.0.9", {9100: "unknown", 515: "printer"})
    assert probed == []


async def test_a_plaintext_web_port_is_not_given_a_tls_handshake(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # port 80 will never complete a handshake, so spending a fallback probe on one is pure waste.
    tls_probed: list[int] = []

    async def _cert(ip, port, *, timeout):
        tls_probed.append(port)
        return None

    async def _nothing(*_a, **_k):
        return None

    monkeypatch.setattr(identify, "tls_certificate", _cert)
    monkeypatch.setattr(identify, "http_probe", _nothing)
    monkeypatch.setattr(identify, "reverse_dns", _nothing)
    monkeypatch.setattr(identify, "netbios_name", _nothing)

    await IdentityProbe().run("10.0.0.9", {80: "http"})
    assert tls_probed == []


async def test_ports_that_need_a_protocol_preamble_are_not_probed() -> None:
    """RDP and the database ports are deliberately absent from the TLS list.

    None of them speak TLS on connect: RDP wants an X.224 connection request first, and postgres,
    MySQL and MSSQL negotiate through their own protocols. Listing them would send a ClientHello
    that can only ever fail, so their absence is a decision and not an oversight.
    """
    for port in (3389, 5432, 3306, 1433):
        assert port not in identify.TLS_PORTS


async def test_probe_survives_a_source_that_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    # one exploding probe must not cost the evidence its siblings collected.
    async def _boom(*_a, **_k):
        raise RuntimeError("resolver exploded")

    async def _nb(ip, *, timeout):
        return "WS01"

    monkeypatch.setattr(identify, "reverse_dns", _boom)
    monkeypatch.setattr(identify, "tls_certificate", _boom)
    monkeypatch.setattr(identify, "http_probe", _boom)
    monkeypatch.setattr(identify, "netbios_name", _nb)

    ev = await IdentityProbe().run("10.0.0.9", {443: "https"})
    assert ev.ptr_name is None
    assert ev.netbios_name == "WS01"


async def test_probe_survives_a_broken_hosts_file_lookup() -> None:
    def _boom(_ip):
        raise ValueError("bad pin table")

    ev = await IdentityProbe(
        reverse_dns=False, tls=False, http=False, netbios=False, hosts_file_lookup=_boom
    ).run("10.0.0.9", {})
    assert ev.hosts_file_name is None
    assert ev.is_empty()


# --- the wire payload ---------------------------------------------------------------------------


def test_payload_omits_everything_we_did_not_learn() -> None:
    # a host we know one thing about must not ship a dict full of nulls: this rides a report
    # carrying hundreds of hosts.
    ev = HostEvidence(ip="10.0.0.1", ptr_name="a.b")
    assert ev.as_payload() == {"ip": "10.0.0.1", "ptr_name": "a.b"}


def test_payload_includes_services_when_present() -> None:
    ev = HostEvidence(
        ip="10.0.0.1", services=[ServiceEvidence(port=443, http_title="vCenter")]
    )
    assert ev.as_payload() == {
        "ip": "10.0.0.1",
        "services": [{"port": 443, "http_title": "vCenter"}],
    }


def test_empty_evidence_is_recognised() -> None:
    assert HostEvidence(ip="10.0.0.1").is_empty()
    assert ServiceEvidence(port=80).is_empty()
    assert not HostEvidence(ip="10.0.0.1", netbios_name="X").is_empty()


# --- the cluster inventory, read beside the sweep -----------------------------------------------


_QUIET = {"reverse_dns": False, "tls": False, "http": False, "netbios": False}


async def test_a_cluster_inventory_names_the_host() -> None:
    inventory: asyncio.Future = asyncio.get_running_loop().create_future()
    inventory.set_result({"10.42.0.5": KubernetesEvidence(service="checkout", namespace="pay")})
    probe = IdentityProbe(**_QUIET, kubernetes_inventory=inventory)
    named = await probe.run("10.42.0.5", {80: "http"})
    unnamed = await probe.run("10.42.0.6", {80: "http"})
    assert named.kubernetes is not None and named.kubernetes.service == "checkout"
    assert unnamed.kubernetes is None


async def test_naming_waits_for_a_cluster_read_still_in_flight() -> None:
    inventory: asyncio.Future = asyncio.get_running_loop().create_future()
    probe = IdentityProbe(**_QUIET, kubernetes_inventory=inventory)
    pending = asyncio.ensure_future(probe.run("10.42.0.5", {80: "http"}))
    await asyncio.sleep(0)
    assert not pending.done()
    inventory.set_result({"10.42.0.5": KubernetesEvidence(service="checkout")})
    assert (await pending).kubernetes is not None


async def test_one_cancelled_probe_does_not_cancel_the_read_the_others_wait_on() -> None:
    inventory: asyncio.Future = asyncio.get_running_loop().create_future()
    probe = IdentityProbe(**_QUIET, kubernetes_inventory=inventory)
    first = asyncio.ensure_future(probe.run("10.42.0.5", {80: "http"}))
    second = asyncio.ensure_future(probe.run("10.42.0.5", {80: "http"}))
    await asyncio.sleep(0)
    first.cancel()
    await asyncio.sleep(0)
    assert not inventory.cancelled()
    inventory.set_result({"10.42.0.5": KubernetesEvidence(service="checkout")})
    assert (await second).kubernetes is not None


async def test_a_failed_cluster_read_costs_only_that_source(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _ptr(ip, *, timeout):
        return "web-01.corp.local"

    monkeypatch.setattr(identify, "reverse_dns", _ptr)
    inventory: asyncio.Future = asyncio.get_running_loop().create_future()
    inventory.set_exception(RuntimeError("cluster unreachable"))
    probe = IdentityProbe(**{**_QUIET, "reverse_dns": True}, kubernetes_inventory=inventory)
    evidence = await probe.run("10.42.0.5", {80: "http"})
    assert evidence.kubernetes is None
    assert evidence.ptr_name == "web-01.corp.local"
