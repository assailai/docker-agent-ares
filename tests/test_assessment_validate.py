"""The agent verifies a control-plane-signed validation plan, probes within budget, and seals a result.

The plan here is signed with the EXACT scheme the control plane uses for Controlled Validation
(``ares.domain.assessment.validation.crypto``): Ed25519 over ``<DOMAIN>\\x00<canonical-json>`` where
the canonical JSON is the plan's fields with ``plan_signature`` removed, sorted-key compact UTF-8. So
these prove the agent's verification and sealing are byte-compatible with the control plane; the
cross-repo golden fixture is the standing guard against drift. The probe tests open a real loopback
socket (the module's whole point is bounded, read-only, ACTIVE probing) but never leave 127.0.0.1.
"""

from __future__ import annotations

import asyncio
import base64
import json
import socket

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent import assessment_validate

_DIGEST = "sha256:" + "a" * 64


def _public_b64(key: Ed25519PrivateKey) -> str:
    raw = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    return base64.b64encode(raw).decode()


def _canonical(payload: dict) -> bytes:
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _endpoint(
    address: str = "10.10.0.5", port: int = 443, protocol: str = "tcp"
) -> dict:
    return {"address": address, "port": port, "protocol": protocol, "server_name": ""}


def _budget() -> dict:
    return {
        "max_requests": 1,
        "max_bytes_sent": 2048,
        "max_bytes_received": 8192,
        "max_evidence_bytes": 4096,
        "timeout_seconds": 5.0,
        "max_concurrency": 1,
    }


def _unsigned_plan(
    endpoint: dict | None = None, *, safety: str = "PASSIVE", op: str = "SAFE_HANDSHAKE"
) -> dict:
    step = {
        "step_id": "step-1",
        "validator_id": "net.reachability.v1",
        "validator_version": "1.0.0",
        "validator_package_digest": _DIGEST,
        "operation_id": "op-1",
        "safety_class": safety,
        "operation_class": op,
        "endpoint": endpoint or _endpoint(),
        "budget": _budget(),
        "preconditions": [],
        "stop_conditions": [],
        "expected_evidence_kinds": ["validation_transcript"],
    }
    return {
        "schema_version": "ares.controlled-validation-plan.v1",
        "tenant_id": "t1",
        "environment_id": "production",
        "assessment_id": "asmt-1",
        "snapshot_id": "00000000-0000-0000-0000-000000000001",
        "finding_id": "f1",
        "finding_family": "network.service.reachable",
        "required_evidence_kind": "validation_transcript",
        "asset_id": "asset-1",
        "scope_revision_id": "rev-1",
        "scope_revision_digest": _DIGEST,
        "customer_authorization_id": "auth-1",
        "customer_authorization_digest": _DIGEST,
        "execution_profile_digest": _DIGEST,
        "agent_id": "ag-1",
        "agent_epoch": 1,
        "plan_id": "plan-1",
        "validation_id": "val-1",
        "approval_id": "appr-1",
        "lease_token_digest": _DIGEST,
        "result_key_id": "result-key-1",
        "steps": [step],
        "created_at": "2026-01-01T00:00:00+00:00",
        "expires_at": "2099-01-01T00:00:00+00:00",
        "plan_key_id": "cp-key-1",
        "plan_signature_algorithm": "Ed25519",
        "pilot_id": "",
    }


def _sign_plan(plan: dict, key: Ed25519PrivateKey) -> dict:
    payload = _canonical({k: v for k, v in plan.items() if k != "plan_signature"})
    message = assessment_validate.PLAN_DOMAIN.encode("ascii") + b"\x00" + payload
    signed = dict(plan)
    signed["plan_signature"] = base64.b64encode(key.sign(message)).decode()
    return signed


# ---- plan verification -------------------------------------------------------------------------


def test_a_valid_plan_verifies() -> None:
    key = Ed25519PrivateKey.generate()
    plan = _sign_plan(_unsigned_plan(), key)
    assert (
        assessment_validate.verify_plan(plan, cp_public_keys=[_public_b64(key)]) is True
    )


def test_a_tampered_plan_is_refused() -> None:
    key = Ed25519PrivateKey.generate()
    plan = _sign_plan(_unsigned_plan(), key)
    plan["steps"][0]["endpoint"]["address"] = (
        "10.10.0.6"  # move the target after signing
    )
    assert (
        assessment_validate.verify_plan(plan, cp_public_keys=[_public_b64(key)])
        is False
    )


def test_a_wrong_key_is_refused() -> None:
    key = Ed25519PrivateKey.generate()
    other = Ed25519PrivateKey.generate()
    plan = _sign_plan(_unsigned_plan(), key)
    assert (
        assessment_validate.verify_plan(plan, cp_public_keys=[_public_b64(other)])
        is False
    )


def test_an_empty_key_list_fails_closed() -> None:
    key = Ed25519PrivateKey.generate()
    plan = _sign_plan(_unsigned_plan(), key)
    assert assessment_validate.verify_plan(plan, cp_public_keys=[]) is False


@pytest.mark.parametrize(
    "mutate",
    [
        lambda p: p.pop("plan_signature"),
        lambda p: p.update(plan_signature_algorithm="RSA"),
        lambda p: p.update(schema_version="ares.controlled-validation-plan.v2"),
        lambda p: p.update(steps=[]),
        lambda p: p.update(steps=[p["steps"][0], p["steps"][0]]),
    ],
)
def test_malformed_plans_fail_closed(mutate) -> None:
    key = Ed25519PrivateKey.generate()
    plan = _sign_plan(_unsigned_plan(), key)
    mutate(plan)
    assert (
        assessment_validate.verify_plan(plan, cp_public_keys=[_public_b64(key)])
        is False
    )


def test_a_non_dict_plan_is_refused() -> None:
    assert assessment_validate.verify_plan(None, cp_public_keys=["x"]) is False


# ---- step gating + budget ----------------------------------------------------------------------


def test_a_safe_step_is_runnable() -> None:
    assert assessment_validate.step_is_runnable(_unsigned_plan()["steps"][0]) is True


@pytest.mark.parametrize(
    "safety,op",
    [
        ("CONSEQUENTIAL", "SAFE_HANDSHAKE"),
        ("PASSIVE", "TRANSACTIONAL"),
        ("REVERSIBLE", "MUTATING"),
    ],
)
def test_an_unsafe_step_is_not_runnable(safety, op) -> None:
    step = _unsigned_plan(safety=safety, op=op)["steps"][0]
    assert assessment_validate.step_is_runnable(step) is False


def test_the_effective_budget_is_the_per_counter_minimum() -> None:
    signed = {
        "max_requests": 50,
        "max_bytes_sent": 1_000_000,
        "max_bytes_received": 1_000_000,
        "timeout_seconds": 600.0,
    }
    eff = assessment_validate.effective_budget(signed)
    assert eff["max_requests"] == assessment_validate._LOCAL_MAX_REQUESTS
    assert eff["max_bytes_sent"] == assessment_validate._LOCAL_MAX_BYTES_SENT
    assert eff["max_bytes_received"] == assessment_validate._LOCAL_MAX_BYTES_RECEIVED
    assert eff["timeout_seconds"] == assessment_validate._LOCAL_TIMEOUT_SECONDS


def test_a_tighter_signed_budget_is_honored_tighter() -> None:
    signed = {
        "max_requests": 1,
        "max_bytes_sent": 100,
        "max_bytes_received": 200,
        "timeout_seconds": 2.0,
    }
    eff = assessment_validate.effective_budget(signed)
    assert eff == {
        "max_requests": 1,
        "max_bytes_sent": 100,
        "max_bytes_received": 200,
        "timeout_seconds": 2.0,
    }


# ---- bounded probe (loopback only) -------------------------------------------------------------


async def test_a_reachable_endpoint_is_confirmed() -> None:
    async def handle(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        writer.write(b"HELLO\r\n")
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        obs = await assessment_validate.probe_endpoint(
            _endpoint(address="127.0.0.1", port=port, protocol="tcp"), _budget()
        )
    finally:
        server.close()
        await server.wait_closed()
    assert obs["outcome"] == "CONFIRMED"
    assert obs["received_bytes"] >= 0
    assert obs["requests"] == 1


async def test_a_refused_endpoint_is_not_confirmed() -> None:
    # Bind then immediately close to hand back a port nothing is listening on.
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    obs = await assessment_validate.probe_endpoint(
        _endpoint(address="127.0.0.1", port=port, protocol="tcp"), _budget()
    )
    assert obs["outcome"] == "NOT_CONFIRMED"
    assert obs["terminal_reason"] == "REFUSED"


async def test_an_http_probe_sends_one_bounded_head() -> None:
    seen: list[bytes] = []

    async def handle(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        seen.append(await reader.read(256))
        writer.write(b"HTTP/1.0 200 OK\r\nServer: test\r\n\r\n")
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        obs = await assessment_validate.probe_endpoint(
            _endpoint(address="127.0.0.1", port=port, protocol="http"), _budget()
        )
    finally:
        server.close()
        await server.wait_closed()
    assert obs["outcome"] == "CONFIRMED"
    assert obs["sent_bytes"] > 0
    assert seen and seen[0].startswith(b"HEAD / HTTP/1.0")
    assert "200" in obs["protocol_metadata"].get("http_status_line", "")


# ---- build + sign a result ---------------------------------------------------------------------


def test_the_result_copies_every_plan_binding_field_and_signs_verifiably() -> None:
    cp = Ed25519PrivateKey.generate()
    agent_key = Ed25519PrivateKey.generate()
    seed_b64 = base64.b64encode(agent_key.private_bytes_raw()).decode()
    plan = _sign_plan(_unsigned_plan(), cp)

    observation = assessment_validate._observation(
        outcome="CONFIRMED",
        summary="reachable",
        sent_bytes=0,
        received_bytes=7,
        requests=1,
    )
    entry, _payload, _descriptor = assessment_validate.build_evidence(
        plan, observation, captured_at="2026-01-02T00:00:00+00:00"
    )
    result = assessment_validate.build_validation_result(
        plan,
        observation=observation,
        evidence_entry=entry,
        started_at="2026-01-02T00:00:00+00:00",
        completed_at="2026-01-02T00:00:01+00:00",
        budget_used={"requests": 1, "bytes_sent": 0, "bytes_received": 7},
    )

    # Every context + validator + endpoint + budget field is bound back to the plan.
    step = plan["steps"][0]
    for field in ("tenant_id", "snapshot_id", "finding_id", "asset_id", "agent_epoch"):
        assert result[field] == plan[field]
    for field in ("validation_id", "plan_id", "approval_id", "result_key_id"):
        assert result[field] == plan[field]
    for field in ("validator_id", "operation_id", "endpoint", "budget"):
        assert result[field] == step[field]
    assert result["evidence_manifest"] == [entry]

    sealed = assessment_validate.sign_validation_result(result, seed_b64=seed_b64)
    assert sealed["result_signature_algorithm"] == "Ed25519"

    # The signature verifies over the canonical projection under RESULT_DOMAIN, byte-for-byte what the
    # control plane's _verify_result_signature checks.
    payload = _canonical({k: v for k, v in sealed.items() if k != "result_signature"})
    message = assessment_validate.RESULT_DOMAIN.encode("ascii") + b"\x00" + payload
    agent_key.public_key().verify(base64.b64decode(sealed["result_signature"]), message)


def test_an_expired_plan_is_detected() -> None:
    plan = _unsigned_plan()
    plan["expires_at"] = "2000-01-01T00:00:00+00:00"
    assert assessment_validate.plan_is_expired(plan) is True
    assert assessment_validate.plan_is_expired(_unsigned_plan()) is False
