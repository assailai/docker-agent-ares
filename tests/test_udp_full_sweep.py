"""The exhaustive UDP sweep is the ARES-2249 "replicate" parity with the retiring SERVICE
port-inventory lane: gated on its udp_operations token, it records only the ports that REPLY (open)
and leaves silence indeterminate (never closed)."""

from __future__ import annotations

import pytest

from agent import assessment_discover, main

_FULL_SWEEP = "udp_full_sweep"


def _scope(*, udp_operations: list[str], tcp_ports: str = "22,23", cidr: str = "10.0.0.0/30"):
    job = {
        "tenant_id": "11111111-1111-1111-1111-111111111111",
        "assessment_id": "22222222-2222-2222-2222-222222222222",
        "snapshot_id": "33333333-3333-3333-3333-333333333333",
        "scope_revision_sha256": "c" * 64,
        "agent_id": "44444444-4444-4444-4444-444444444444",
        "job_id": "55555555-5555-5555-5555-555555555555",
        "nonce": "n0nce",
        "target_cidrs": [cidr],
        "tcp_ports": tcp_ports,
        "udp_operations": udp_operations,
    }
    return assessment_discover.derive_scope(job)


async def test_full_sweep_is_gated_on_its_token() -> None:
    # Without the token the sweep does nothing, even though UDP ports are in scope: it never runs
    # unless the signed job asked for it (and only an NA-lane-live org enqueues it).
    scope = _scope(udp_operations=["snmp_default_community"])
    assert await main._udp_full_sweep_discover(scope) == []


async def test_full_sweep_records_only_replying_ports(monkeypatch: pytest.MonkeyPatch) -> None:
    scope = _scope(udp_operations=[_FULL_SWEEP])

    async def fake_open(ip: str, port: int, *, timeout: float) -> bool:
        return port == 23  # only 23 "replies"; 22 stays silent (indeterminate)

    monkeypatch.setattr(main, "_udp_port_open", fake_open)
    observations = await main._udp_full_sweep_discover(scope)

    # a /30 has two usable hosts; each reports 23 open, neither reports 22 (silence != closed)
    assert {(o["address"], o["port"]) for o in observations} == {
        ("10.0.0.1", 23),
        ("10.0.0.2", 23),
    }
    for o in observations:
        assert o["transport"] == "udp"
        assert o["outcome"] == "open"
        assert o["protocol_id"] is None


async def test_full_sweep_silence_yields_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    scope = _scope(udp_operations=[_FULL_SWEEP])

    async def never_open(ip: str, port: int, *, timeout: float) -> bool:
        return False

    monkeypatch.setattr(main, "_udp_port_open", never_open)
    assert await main._udp_full_sweep_discover(scope) == []
