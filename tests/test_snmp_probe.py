"""The SNMP UDP sweep in the discover handler (PR-08 sub-slice 2).

The transport is monkeypatched here, so these pin the handler logic, not a real socket: that the
sweep runs only when the signed job asked for it, that a responder becomes exactly one honest
udp/161/snmp observation and a non-responder stays silent (never reported closed), and that the
per-host probe tries each default community in order and accepts only a non-error response.
"""

from __future__ import annotations

import ipaddress

import pytest

from agent import assessment_discover, main, snmp


def _scope(*, udp_operations: tuple[str, ...], cidr: str = "10.0.0.0/29") -> assessment_discover.DiscoverScope:
    return assessment_discover.DiscoverScope(
        networks=(ipaddress.ip_network(cidr),),
        excludes=(),
        ports=(161,),
        udp_operations=udp_operations,
    )


def _accepted(community: str = "public", sys_descr: str | None = "lab snmpd") -> snmp.SnmpGetResponse:
    return snmp.SnmpGetResponse(
        community=community, request_id=1, error_status=0, sys_descr=sys_descr
    )


async def test_the_sweep_runs_only_when_the_job_asked_for_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _probe(_ip: str, *, timeout: float) -> snmp.SnmpGetResponse | None:
        raise AssertionError("must not probe when the op was not requested")

    monkeypatch.setattr(main, "_probe_snmp", _probe)
    assert await main._snmp_discover(_scope(udp_operations=())) == []


async def test_a_responder_becomes_one_udp_snmp_observation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _probe(ip: str, *, timeout: float) -> snmp.SnmpGetResponse | None:
        return _accepted() if ip == "10.0.0.5" else None

    monkeypatch.setattr(main, "_probe_snmp", _probe)
    observations = await main._snmp_discover(
        _scope(udp_operations=(snmp.SNMP_DEFAULT_COMMUNITY_OP,))
    )
    assert len(observations) == 1
    only = observations[0]
    assert only["address"] == "10.0.0.5"
    assert only["transport"] == "udp"
    assert only["port"] == 161
    assert only["outcome"] == "open"
    assert only["protocol_id"] == "snmp"
    assert only["banner_sha256"] is not None  # the sysDescr commits the evidence


async def test_non_responders_stay_silent_not_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _probe(_ip: str, *, timeout: float) -> snmp.SnmpGetResponse | None:
        return None

    monkeypatch.setattr(main, "_probe_snmp", _probe)
    # Nothing answered: the result is empty, never a list of "closed" rows. A UDP no-response stays
    # indeterminate, which the absence of an observation expresses honestly.
    assert await main._snmp_discover(_scope(udp_operations=(snmp.SNMP_DEFAULT_COMMUNITY_OP,))) == []


async def test_a_responder_with_no_description_still_observes_without_a_banner(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _probe(ip: str, *, timeout: float) -> snmp.SnmpGetResponse | None:
        return _accepted(sys_descr=None) if ip == "10.0.0.2" else None

    monkeypatch.setattr(main, "_probe_snmp", _probe)
    observations = await main._snmp_discover(
        _scope(udp_operations=(snmp.SNMP_DEFAULT_COMMUNITY_OP,))
    )
    assert len(observations) == 1
    assert observations[0]["protocol_id"] == "snmp"
    assert observations[0]["banner_sha256"] is None


# ── the per-host probe: community order and acceptance ────────────────────────


async def test_probe_tries_each_community_and_returns_the_first_accepted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attempts: list[int] = []

    async def _round_trip(
        _ip: str, _payload: bytes, *, request_id: int, timeout: float
    ) -> snmp.SnmpGetResponse | None:
        attempts.append(request_id)
        # Reject the first community, accept the second.
        return _accepted(community="private") if len(attempts) == 2 else None

    monkeypatch.setattr(main, "_snmp_round_trip", _round_trip)
    response = await main._probe_snmp("10.0.0.5", timeout=1.0)
    assert response is not None
    assert response.community == "private"
    assert len(attempts) == len(snmp.DEFAULT_COMMUNITIES) == 2


async def test_an_error_status_response_is_not_accepted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _round_trip(
        _ip: str, _payload: bytes, *, request_id: int, timeout: float
    ) -> snmp.SnmpGetResponse | None:
        return snmp.SnmpGetResponse(
            community="public", request_id=request_id, error_status=5, sys_descr=None
        )

    monkeypatch.setattr(main, "_snmp_round_trip", _round_trip)
    # Both communities answered with an error status: nothing is accepted.
    assert await main._probe_snmp("10.0.0.5", timeout=1.0) is None
