"""The discover handler: verify a signed job, re-derive scope, probe, sign and submit a result.

Proves the agent's half of the §29.8 round trip end to end (minus the real socket, which is mocked):
a job signed by the control plane's key is verified, the scope is re-derived from it, the scanner's
OPEN hits inside that scope become signed service observations, and the sealed result verifies under
the agent's OWN registered public key (which is what the control plane admits it by). An
out-of-scope hit is dropped even though the scanner returned it.
"""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from agent import assessment, assessment_discover, main
from agent.state import AgentState

_JOB_DOMAIN = "ares.network-assessment.signed-task.discover:v1"
_JOB_SCHEMA = "ares.network-assessment.signed-task.discover.v1"


def _signed_job(cp_seed: str) -> dict:
    payload = {
        "tenant_id": "11111111-1111-1111-1111-111111111111",
        "assessment_id": "22222222-2222-2222-2222-222222222222",
        "snapshot_id": "33333333-3333-3333-3333-333333333333",
        "scope_revision_sha256": "c" * 64,
        "agent_id": "44444444-4444-4444-4444-444444444444",
        "job_id": "55555555-5555-5555-5555-555555555555",
        "nonce": "n0nce",
        "target_cidrs": ["10.0.0.0/24"],
        "tcp_ports": "22,23",
    }
    # Sign it exactly as the control plane does (seal_result is the generic sealer).
    return assessment.seal_result(
        payload, schema=_JOB_SCHEMA, seed_b64=cp_seed, domain=_JOB_DOMAIN, signer_key_id="cp-key-1"
    )


_BANNERS = {23: b"\xff\xfd\x18\xff\xfd\x20", 22: b"SSH-2.0-OpenSSH_9.6\r\n"}


@pytest.fixture
def _mocks(monkeypatch: pytest.MonkeyPatch) -> dict[str, AsyncMock]:
    mocks = {
        "task_started": AsyncMock(),
        "task_failed": AsyncMock(),
        "submit": AsyncMock(),
        "scan_cidr": AsyncMock(
            return_value=[
                {"ip": "10.0.0.9", "port": 23},
                {"ip": "10.0.0.10", "port": 22},
                {"ip": "10.9.9.9", "port": 80},  # outside the job's target CIDR: must be dropped
            ]
        ),
    }
    monkeypatch.setattr(main.control_plane, "task_started", mocks["task_started"])
    monkeypatch.setattr(main.control_plane, "task_failed", mocks["task_failed"])
    monkeypatch.setattr(main.control_plane, "submit_assessment_result", mocks["submit"])
    monkeypatch.setattr(main.scan, "scan_cidr", mocks["scan_cidr"])

    async def _banner(_ip: str, port: int, *, timeout: float) -> bytes:
        return _BANNERS.get(port, b"")

    monkeypatch.setattr(main, "_read_banner", _banner)
    return mocks


async def test_valid_job_is_verified_probed_and_a_signed_result_submitted(
    _mocks: dict[str, AsyncMock],
) -> None:
    cp_seed = assessment.generate_signing_seed()
    cp_public = assessment.public_key_b64_from_seed(cp_seed)
    agent_seed = assessment.generate_signing_seed()
    agent_public = assessment.public_key_b64_from_seed(agent_seed)
    state = AgentState(
        agent_id="a",
        agent_token="t",
        signing_key_seed=agent_seed,
        cp_assessment_public_keys=[cp_public],
    )
    task = {
        "id": "task-1",
        "task_type": "network_assessment_discover_v1",
        "tool_config": {"envelope": _signed_job(cp_seed)},
    }

    await main._run_task("token", task, state=state)

    _mocks["task_started"].assert_awaited_once()
    _mocks["task_failed"].assert_not_awaited()
    _mocks["submit"].assert_awaited_once()

    sealed = _mocks["submit"].await_args.args[3]
    result = assessment.open_signed_job(
        sealed,
        public_keys=[agent_public],  # the control plane admits the result by the AGENT's key
        domain=assessment_discover.RESULT_DOMAIN,
        expected_schema=assessment_discover.RESULT_SCHEMA,
    )
    assert result is not None
    # bound back to the exact job
    assert result["snapshot_id"] == "33333333-3333-3333-3333-333333333333"
    assert result["job_id"] == "55555555-5555-5555-5555-555555555555"
    # two in-scope OPEN services; the 10.9.9.9 hit was dropped by scope.in_scope
    by_port = {s["port"]: s for s in result["services"]}
    assert sorted(by_port) == [22, 23]
    assert all(s["outcome"] == "open" for s in result["services"])
    # the protocol is identified from the banner the service emitted, never from the port
    assert by_port[23]["protocol_id"] == "telnet"
    assert by_port[22]["protocol_id"] == "ssh"
    assert by_port[23]["banner_sha256"] is not None  # the banner's hash commits to the evidence


async def test_wrong_cp_key_refuses_before_any_probe(_mocks: dict[str, AsyncMock]) -> None:
    job = _signed_job(assessment.generate_signing_seed())  # signed by a key the agent won't know
    other_cp_public = assessment.public_key_b64_from_seed(assessment.generate_signing_seed())
    state = AgentState(
        agent_id="a",
        agent_token="t",
        signing_key_seed=assessment.generate_signing_seed(),
        cp_assessment_public_keys=[other_cp_public],
    )
    task = {
        "id": "task-2",
        "task_type": "network_assessment_discover_v1",
        "tool_config": {"envelope": job},
    }

    await main._run_task("token", task, state=state)

    _mocks["scan_cidr"].assert_not_called()
    _mocks["task_started"].assert_not_awaited()
    _mocks["submit"].assert_not_awaited()
    _mocks["task_failed"].assert_awaited_once()
