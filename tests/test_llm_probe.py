"""Local BYOM model dialling (ARES-2424): pushed model endpoints are re-vetted
against the agent's registered networks and widen nothing beyond the exact
host and port ares pushed for a live hunt."""

from __future__ import annotations

import asyncio

import pytest

from agent.control_plane import CAPABILITIES
from agent.dial_guard import Refused
from agent.tunnel import TunnelClient, TunnelManager, parse_llm_host


def _client(
    networks: list[str] | None = None,
    llm_hosts: set[tuple[str, int]] | None = None,
) -> TunnelClient:
    return TunnelClient(
        "ws://x/api/v1/agent/tunnel",
        "tok",
        networks if networks is not None else ["10.0.0.0/24"],
        set(),
        scoped_hosts=set(),
        llm_hosts=llm_hosts if llm_hosts is not None else set(),
        ssl_context=None,
    )


def _stub_resolver(client: TunnelClient, mapping: dict[str, list[str]]) -> None:
    async def resolve(host: str, port: int) -> list[str]:
        if host not in mapping:
            raise Refused(f"{host} did not resolve on this agent")
        return mapping[host]

    client._resolve = resolve  # type: ignore[method-assign]


def test_llm_probe_capability_is_reported() -> None:
    assert "llm_probe" in CAPABILITIES


def test_parse_llm_host() -> None:
    assert parse_llm_host("10.0.0.8:8000") == ("10.0.0.8", 8000)
    assert parse_llm_host("Models.Internal.:11434") == ("models.internal", 11434)
    assert parse_llm_host("no-port") is None
    assert parse_llm_host("host:notaport") is None
    assert parse_llm_host("host:99999") is None


def test_model_ip_inside_registered_networks_dials() -> None:
    client = _client(llm_hosts={("10.0.0.8", 8000)})
    assert asyncio.run(client._approved_addresses("10.0.0.8", 8000)) == ["10.0.0.8"]


def test_model_ip_outside_registered_networks_is_refused() -> None:
    client = _client(llm_hosts={("172.16.0.9", 8000)})
    with pytest.raises(Refused, match="registered networks"):
        asyncio.run(client._approved_addresses("172.16.0.9", 8000))


def test_model_push_does_not_widen_to_other_ports_or_hosts() -> None:
    client = _client(llm_hosts={("10.0.0.8", 8000)})
    # Same host, wrong port: not the pushed endpoint, and 10.0.0.8 is inside the
    # registered networks only on the ordinary target rule, which needs an
    # operator scope entry this client does not have on another port either.
    # The llm path itself must not authorize it.
    assert not client._is_llm_destination("10.0.0.8", 9000)
    assert not client._is_llm_destination("10.0.0.9", 8000)


def test_model_metadata_address_is_refused_however_pushed() -> None:
    client = _client(
        networks=["169.254.0.0/16", "10.0.0.0/24"], llm_hosts={("169.254.169.254", 80)}
    )
    with pytest.raises(Refused):
        asyncio.run(client._approved_addresses("169.254.169.254", 80))


def test_model_hostname_resolving_outside_networks_is_refused() -> None:
    client = _client(llm_hosts={("models.internal", 8000)})
    _stub_resolver(client, {"models.internal": ["192.168.9.9"]})
    with pytest.raises(Refused, match="registered networks"):
        asyncio.run(client._approved_addresses("models.internal", 8000))


def test_model_hostname_resolving_inside_networks_dials() -> None:
    client = _client(llm_hosts={("models.internal", 8000)})
    _stub_resolver(client, {"models.internal": ["10.0.0.8"]})
    assert asyncio.run(client._approved_addresses("models.internal", 8000)) == ["10.0.0.8"]


def test_model_hostname_rebinding_to_metadata_is_dropped_then_refused() -> None:
    client = _client(llm_hosts={("models.internal", 8000)})
    _stub_resolver(client, {"models.internal": ["169.254.169.254"]})
    with pytest.raises(Refused):
        asyncio.run(client._approved_addresses("models.internal", 8000))


def test_manager_holds_llm_hosts_and_idle_grace() -> None:
    async def go() -> None:
        manager = TunnelManager(
            "ws://x", "tok", ["10.0.0.0/24"], ssl_context=None, idle_seconds=0.05
        )
        manager.sync(True, [], [], ["10.0.0.8:8000", "junk"])
        assert manager._llm_hosts == {("10.0.0.8", 8000)}
        assert manager._task is not None
        manager.sync(False, [], [], [])
        assert manager._llm_hosts == set()
        # Idle grace: the tunnel is still up immediately after the last hunt.
        assert manager._task is not None and not manager._task.done()
        await asyncio.sleep(0.15)
        assert manager._task is None
        manager.stop()

    asyncio.run(go())
