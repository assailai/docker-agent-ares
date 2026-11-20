"""The agent re-derives scope from a verified job and seals a control-plane-shaped discover result.

These are pure: no socket is opened and no clock is read. They prove the agent emits exactly the
``DiscoverResultV1`` shape the control plane admits, signs it with the key it registered, and refuses
to probe outside the frozen scope. The seal -> open round trip here uses the agent's OWN verifier
(``assessment.open_signed_job``), which is byte-identical to the control plane's ``wire.open_sealed``;
the cross-repo golden fixture (ARES-2214) guards that the two stay compatible.
"""

from __future__ import annotations

import base64

import pytest

from agent import assessment, assessment_discover

# The exact field set of ares.domain.assessment.results.DiscoverResultV1. The control plane forbids
# extras, so the agent's payload must carry these and only these keys.
_RESULT_FIELDS = {
    "tenant_id",
    "assessment_id",
    "snapshot_id",
    "scope_revision_sha256",
    "agent_id",
    "job_id",
    "nonce",
    "completed_at",
    "services",
    "coverage",
    "partial",
}


def _job(**overrides) -> dict:
    job = {
        "tenant_id": "11111111-1111-1111-1111-111111111111",
        "assessment_id": "22222222-2222-2222-2222-222222222222",
        "snapshot_id": "33333333-3333-3333-3333-333333333333",
        "scope_revision_sha256": "c" * 64,
        "agent_id": "44444444-4444-4444-4444-444444444444",
        "job_id": "55555555-5555-5555-5555-555555555555",
        "nonce": "n0nce",
        "target_cidrs": ["10.0.0.0/24"],
        "tcp_ports": "22,23,443",
    }
    job.update(overrides)
    return job


def test_port_spec_matches_the_control_plane_parser() -> None:
    assert assessment_discover.parse_port_spec("1-5,443") == [1, 2, 3, 4, 5, 443]
    with pytest.raises(ValueError):
        assessment_discover.parse_port_spec("0-10")
    with pytest.raises(ValueError):
        assessment_discover.parse_port_spec(" , ")


def test_derive_scope_parses_targets_and_ports() -> None:
    scope = assessment_discover.derive_scope(_job())
    assert scope.ports == (22, 23, 443)
    assert scope.in_scope("10.0.0.9") is True
    assert scope.in_scope("10.0.1.9") is False  # outside the target network
    assert scope.in_scope("not-an-ip") is False  # fails closed


def test_derive_scope_honours_excludes() -> None:
    scope = assessment_discover.derive_scope(_job(exclude_cidrs=["10.0.0.0/28"]))
    assert scope.in_scope("10.0.0.5") is False  # inside the exclude
    assert scope.in_scope("10.0.0.200") is True  # in target, outside the exclude


def test_derive_scope_refuses_a_job_missing_binding() -> None:
    job = _job()
    del job["snapshot_id"]
    with pytest.raises(ValueError, match="snapshot_id"):
        assessment_discover.derive_scope(job)


def test_service_observation_rejects_a_bad_outcome() -> None:
    with pytest.raises(ValueError, match="outcome"):
        assessment_discover.service_observation(
            address="10.0.0.9", port=23, transport="tcp", outcome="up"
        )


def test_build_result_carries_the_job_binding_and_exact_shape() -> None:
    job = _job()
    services = [
        assessment_discover.service_observation(
            address="10.0.0.9", port=23, transport="tcp", outcome="open", protocol_id="telnet"
        )
    ]
    coverage = [assessment_discover.coverage_entry(scope="10.0.0.0/24:22-443", state="assessed")]
    result = assessment_discover.build_discover_result(
        job, services=services, coverage=coverage, completed_at="2026-11-18T13:00:00Z"
    )
    assert set(result) == _RESULT_FIELDS
    assert result["snapshot_id"] == job["snapshot_id"]
    assert result["nonce"] == job["nonce"]
    assert result["services"][0]["outcome"] == "open"
    assert set(result["services"][0]) == {
        "address",
        "port",
        "transport",
        "outcome",
        "protocol_id",
        "banner_sha256",
    }


def test_sealed_result_verifies_under_the_registered_public_key() -> None:
    seed = assessment.generate_signing_seed()
    public = assessment.public_key_b64_from_seed(seed)
    result = assessment_discover.build_discover_result(
        _job(),
        services=[
            assessment_discover.service_observation(
                address="10.0.0.9", port=23, transport="tcp", outcome="open"
            )
        ],
        coverage=[],
        completed_at="2026-11-18T13:00:00Z",
    )
    envelope = assessment.seal_result(
        result,
        schema=assessment_discover.RESULT_SCHEMA,
        seed_b64=seed,
        domain=assessment_discover.RESULT_DOMAIN,
        signer_key_id="agent-key-1",
    )
    opened = assessment.open_signed_job(
        envelope,
        public_keys=[public],
        domain=assessment_discover.RESULT_DOMAIN,
        expected_schema=assessment_discover.RESULT_SCHEMA,
    )
    assert opened == result


def test_sealed_result_is_refused_under_a_different_key() -> None:
    seed = assessment.generate_signing_seed()
    other_public = assessment.public_key_b64_from_seed(assessment.generate_signing_seed())
    envelope = assessment.seal_result(
        assessment_discover.build_discover_result(
            _job(), services=[], coverage=[], completed_at="2026-11-18T13:00:00Z"
        ),
        schema=assessment_discover.RESULT_SCHEMA,
        seed_b64=seed,
        domain=assessment_discover.RESULT_DOMAIN,
        signer_key_id="agent-key-1",
    )
    assert (
        assessment.open_signed_job(
            envelope,
            public_keys=[other_public],
            domain=assessment_discover.RESULT_DOMAIN,
            expected_schema=assessment_discover.RESULT_SCHEMA,
        )
        is None
    )


def test_sealed_result_payload_bytes_are_canonical() -> None:
    # The sealed payload must be the control plane's canonical JSON (sorted keys, compact), so a
    # re-verification over the stored bytes on the control plane reads them unchanged.
    envelope = assessment.seal_result(
        {"b": 1, "a": 2},
        schema=assessment_discover.RESULT_SCHEMA,
        seed_b64=assessment.generate_signing_seed(),
        domain=assessment_discover.RESULT_DOMAIN,
        signer_key_id="k",
    )
    assert base64.b64decode(envelope["payload"]) == b'{"a":2,"b":1}'


def test_derive_scope_parses_udp_operations() -> None:
    scope = assessment_discover.derive_scope(_job(udp_operations=["snmp_default_community"]))
    assert scope.udp_operations == ("snmp_default_community",)


def test_derive_scope_without_udp_operations_is_empty() -> None:
    assert assessment_discover.derive_scope(_job()).udp_operations == ()


def test_derive_scope_drops_non_string_udp_operations() -> None:
    # The job is verified before this runs, but the parser still keeps only well-formed string ops
    # and an unknown op is simply carried for the handler to ignore (forward-compatible).
    scope = assessment_discover.derive_scope(
        _job(udp_operations=["snmp_default_community", "", 7, None])
    )
    assert scope.udp_operations == ("snmp_default_community",)
