"""The agent-side raw-evidence artifact descriptor: shape, hashing, and the seal round trip.

Pins the descriptor to exactly the keys the control plane's AssessmentArtifactDescriptorV1 allows
(extra="forbid"), proves the hash and size are derived from the bytes, and that a sealed descriptor
verifies under the artifact domain and is rejected under a wrong key or domain. The control plane
re-derives the hash and size from the uploaded bytes, so this is the agent half of that contract.
"""

from __future__ import annotations

import hashlib
from uuid import uuid4

from agent import assessment
from agent.assessment_artifact import (
    ARTIFACT_DOMAIN,
    ARTIFACT_SCHEMA,
    KIND_PACKET_CAPTURE,
    build_artifact_descriptor,
    content_sha256,
)

# The exact field set AssessmentArtifactDescriptorV1 allows (extra="forbid"). A drift on either side
# fails ingestion; pinned here as the agent half of the cross-repo contract (ARES-2214).
_DESCRIPTOR_KEYS = {
    "tenant_id",
    "assessment_id",
    "snapshot_id",
    "agent_id",
    "job_id",
    "nonce",
    "kind",
    "content_sha256",
    "byte_size",
    "captured_at",
}

_BODY = b"\xd4\xc3\xb2\xa1pcap-of-one-job" + b"X" * 100


def _job() -> dict:
    return {
        "tenant_id": str(uuid4()),
        "assessment_id": str(uuid4()),
        "snapshot_id": str(uuid4()),
        "agent_id": str(uuid4()),
        "job_id": str(uuid4()),
        "nonce": "n-123",
    }


def test_descriptor_has_exactly_the_control_plane_keys() -> None:
    d = build_artifact_descriptor(
        _job(), kind=KIND_PACKET_CAPTURE, body=_BODY, captured_at="2026-11-23T13:00:00+00:00"
    )
    assert set(d) == _DESCRIPTOR_KEYS
    assert d["kind"] == "packet_capture"
    assert d["content_sha256"] == hashlib.sha256(_BODY).hexdigest()
    assert d["byte_size"] == len(_BODY)
    assert content_sha256(_BODY) == d["content_sha256"]


def test_sealed_descriptor_round_trips_under_the_artifact_domain() -> None:
    seed = assessment.generate_signing_seed()
    public = assessment.public_key_b64_from_seed(seed)
    descriptor = build_artifact_descriptor(
        _job(), kind=KIND_PACKET_CAPTURE, body=_BODY, captured_at="2026-11-23T13:00:00+00:00"
    )
    envelope = assessment.seal_result(
        descriptor,
        schema=ARTIFACT_SCHEMA,
        seed_b64=seed,
        domain=ARTIFACT_DOMAIN,
        signer_key_id=public,
    )
    opened = assessment.open_signed_job(
        envelope, public_keys=[public], domain=ARTIFACT_DOMAIN, expected_schema=ARTIFACT_SCHEMA
    )
    assert opened == descriptor


def test_a_wrong_key_or_domain_is_rejected() -> None:
    seed = assessment.generate_signing_seed()
    public = assessment.public_key_b64_from_seed(seed)
    other = assessment.public_key_b64_from_seed(assessment.generate_signing_seed())
    descriptor = build_artifact_descriptor(
        _job(), kind=KIND_PACKET_CAPTURE, body=_BODY, captured_at="2026-11-23T13:00:00+00:00"
    )
    envelope = assessment.seal_result(
        descriptor, schema=ARTIFACT_SCHEMA, seed_b64=seed, domain=ARTIFACT_DOMAIN, signer_key_id=public
    )
    assert (
        assessment.open_signed_job(
            envelope, public_keys=[other], domain=ARTIFACT_DOMAIN, expected_schema=ARTIFACT_SCHEMA
        )
        is None
    )
    assert (
        assessment.open_signed_job(
            envelope,
            public_keys=[public],
            domain="ares.network-assessment.result.discover:v1",
            expected_schema=ARTIFACT_SCHEMA,
        )
        is None
    )
