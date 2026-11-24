"""The collect handler: verify a signed collect job, read the device config, sign control facts.

Proves the agent half of the credentialed round trip (the SSH read mocked with a real cEOS config
fixture): a job signed by the control plane is verified, the credential is resolved from the LOCAL
vault, the Arista parser normalises the running-config, and the sealed CollectResultV1 carries the
net.management.telnet facts the control plane's evaluator confirms. A job whose credential the vault
does not hold yields honest UNAVAILABLE coverage, not a guess or a crash.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from agent import assessment, assessment_collect, main
from agent.credential_vault import write_vault
from agent.state import AgentState

_FIX = Path(__file__).with_name("fixtures")


def _job_payload(
    cp_seed: str, *, credential_ref: str = "cred-1", control_ids: list[str] | None = None
) -> dict:
    return {
        "tenant_id": "11111111-1111-1111-1111-111111111111",
        "environment": "production",
        "assessment_id": "22222222-2222-2222-2222-222222222222",
        "snapshot_id": "33333333-3333-3333-3333-333333333333",
        "scope_revision_sha256": "c" * 64,
        "agent_id": "44444444-4444-4444-4444-444444444444",
        "agent_epoch": 1,
        "job_id": "55555555-5555-5555-5555-555555555555",
        "nonce": "n",
        "target_address": "10.0.0.11",
        "credential_ref": credential_ref,
        "control_ids": control_ids if control_ids is not None else ["net.management.telnet"],
    }


def _signed_job(cp_seed: str, **over) -> dict:
    return assessment.seal_result(
        _job_payload(cp_seed, **over),
        schema=assessment_collect.JOB_SCHEMA,
        seed_b64=cp_seed,
        domain=assessment_collect.JOB_DOMAIN,
        signer_key_id="cp-1",
    )


@pytest.fixture
def _env(tmp_path, monkeypatch):
    cp_seed = assessment.generate_signing_seed()
    agent_seed = assessment.generate_signing_seed()
    monkeypatch.setattr(main.settings, "data_dir", tmp_path)
    write_vault(
        tmp_path / "credentials.json",
        {"cred-1": {"kind": "ssh_password", "username": "ops", "secret": "s3cr3t"}},
    )
    mocks = {
        "task_started": AsyncMock(),
        "task_failed": AsyncMock(),
        "submit": AsyncMock(),
        "collect": AsyncMock(return_value=(_FIX / "ceos_running_config_planted.txt").read_text()),
        "collect_lldp": AsyncMock(
            return_value=(_FIX / "ceos_lldp_neighbors_detail.txt").read_text()
        ),
        "collect_sshd": AsyncMock(
            return_value=(_FIX / "sshd_effective_planted.txt").read_text()
        ),
    }
    monkeypatch.setattr(main.control_plane, "task_started", mocks["task_started"])
    monkeypatch.setattr(main.control_plane, "task_failed", mocks["task_failed"])
    monkeypatch.setattr(main.control_plane, "submit_assessment_result", mocks["submit"])
    monkeypatch.setattr(main.ssh_collect, "collect_running_config", mocks["collect"])
    monkeypatch.setattr(main.ssh_collect, "collect_lldp_output", mocks["collect_lldp"])
    monkeypatch.setattr(main.ssh_collect, "collect_sshd_effective_config", mocks["collect_sshd"])
    state = AgentState(
        agent_id="a",
        agent_token="t",
        signing_key_seed=agent_seed,
        cp_assessment_public_keys=[assessment.public_key_b64_from_seed(cp_seed)],
    )
    return {"cp_seed": cp_seed, "agent_public": assessment.public_key_b64_from_seed(agent_seed),
            "state": state, "mocks": mocks}


def test_signed_budget_tighter_than_ceiling_is_honored() -> None:
    timeout_s, max_bytes = main._effective_collect_budget(
        {"budget": {"per_command_timeout_ms": 5000, "max_received_bytes": 1000}}
    )
    assert timeout_s == 5.0 and max_bytes == 1000


def test_signed_budget_looser_than_ceiling_is_clamped() -> None:
    # a forged-large budget can only ever tighten, never loosen, the agent's own bound.
    timeout_s, max_bytes = main._effective_collect_budget(
        {"budget": {"per_command_timeout_ms": 10_000_000, "max_received_bytes": 10**9}}
    )
    assert timeout_s == main._COLLECT_TIMEOUT_S and max_bytes == main._COLLECT_MAX_BYTES


def test_missing_or_malformed_budget_falls_back_to_ceilings() -> None:
    for job in ({}, {"budget": None}, {"budget": {"per_command_timeout_ms": "x"}}):
        timeout_s, max_bytes = main._effective_collect_budget(job)
        assert timeout_s == main._COLLECT_TIMEOUT_S and max_bytes == main._COLLECT_MAX_BYTES


async def test_collect_reads_config_and_signs_control_facts(_env) -> None:
    task = {
        "id": "task-c",
        "task_type": "network_assessment_collect_v1",
        "tool_config": {"envelope": _signed_job(_env["cp_seed"])},
    }
    await main._run_task("tok", task, state=_env["state"])

    _env["mocks"]["task_started"].assert_awaited_once()
    _env["mocks"]["task_failed"].assert_not_awaited()
    _env["mocks"]["submit"].assert_awaited_once()
    _env["mocks"]["collect"].assert_awaited_once()

    sealed = _env["mocks"]["submit"].await_args.args[3]
    result = assessment.open_signed_job(
        sealed,
        public_keys=[_env["agent_public"]],
        domain=assessment_collect.RESULT_DOMAIN,
        expected_schema=assessment_collect.RESULT_SCHEMA,
    )
    assert result is not None
    assert result["snapshot_id"] == "33333333-3333-3333-3333-333333333333"
    control = result["controls"][0]
    assert control["control_id"] == "net.management.telnet"
    assert control["facts"]["management_protocols"]["value"] == ["ssh", "telnet"]
    assert control["facts"]["applicable"]["status"] == "OBSERVED"
    assert control["facts"]["collection_complete"]["value"] is True

    # the device's LLDP neighbours ride the result as topology evidence. The agent reports them
    # faithfully (data-plane and management alike); the control plane classifies out the mgmt ones.
    _env["mocks"]["collect_lldp"].assert_awaited_once()
    addresses = {n["neighbour_address"] for n in result["neighbours"]}
    assert "172.20.20.4" in addresses and "172.20.20.6" in addresses
    assert all(
        set(n) == {"local_interface", "neighbour_id", "neighbour_interface", "neighbour_address"}
        for n in result["neighbours"]
    )


async def test_host_controls_are_read_from_sshd_effective_config(_env) -> None:
    # A server.ssh.* job routes to the host tier: sshd -T, not show running-config, and no LLDP.
    task = {
        "id": "task-host",
        "task_type": "network_assessment_collect_v1",
        "tool_config": {
            "envelope": _signed_job(
                _env["cp_seed"],
                control_ids=["server.ssh.password", "server.ssh.root_login", "server.ssh.max_auth_tries"],
            )
        },
    }
    await main._run_task("tok", task, state=_env["state"])

    _env["mocks"]["collect_sshd"].assert_awaited_once()
    _env["mocks"]["collect"].assert_not_called()  # the running-config path is never opened
    _env["mocks"]["collect_lldp"].assert_not_called()  # LLDP is a device grammar, not a host one
    _env["mocks"]["submit"].assert_awaited_once()

    result = assessment.open_signed_job(
        _env["mocks"]["submit"].await_args.args[3],
        public_keys=[_env["agent_public"]],
        domain=assessment_collect.RESULT_DOMAIN,
        expected_schema=assessment_collect.RESULT_SCHEMA,
    )
    by_id = {c["control_id"]: c for c in result["controls"]}
    assert by_id["server.ssh.password"]["facts"]["ssh_password_authentication"]["value"] is True
    assert by_id["server.ssh.root_login"]["facts"]["ssh_root_login_permitted"]["value"] is True
    assert by_id["server.ssh.max_auth_tries"]["facts"]["ssh_max_auth_tries"]["value"] == 6
    assert result["neighbours"] == []


async def test_missing_credential_yields_unavailable_coverage(_env) -> None:
    task = {
        "id": "task-c2",
        "task_type": "network_assessment_collect_v1",
        "tool_config": {"envelope": _signed_job(_env["cp_seed"], credential_ref="no-such-ref")},
    }
    await main._run_task("tok", task, state=_env["state"])

    _env["mocks"]["collect"].assert_not_called()  # no credential -> never opens a session
    _env["mocks"]["submit"].assert_awaited_once()
    result = assessment.open_signed_job(
        _env["mocks"]["submit"].await_args.args[3],
        public_keys=[_env["agent_public"]],
        domain=assessment_collect.RESULT_DOMAIN,
        expected_schema=assessment_collect.RESULT_SCHEMA,
    )
    assert result["controls"] == []
    assert result["coverage"][0]["state"] == "unavailable"


async def test_unverifiable_collect_job_refuses_before_any_session(_env) -> None:
    other_cp = assessment.public_key_b64_from_seed(assessment.generate_signing_seed())
    state = AgentState(
        agent_id="a", agent_token="t",
        signing_key_seed=assessment.generate_signing_seed(),
        cp_assessment_public_keys=[other_cp],  # not the key the job was signed with
    )
    task = {
        "id": "task-c3",
        "task_type": "network_assessment_collect_v1",
        "tool_config": {"envelope": _signed_job(_env["cp_seed"])},
    }
    await main._run_task("tok", task, state=state)

    _env["mocks"]["collect"].assert_not_called()
    _env["mocks"]["task_started"].assert_not_awaited()
    _env["mocks"]["task_failed"].assert_awaited_once()
