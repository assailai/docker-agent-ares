"""The agent verifies a control-plane-signed job before acting on it.

The envelope here is built with the EXACT scheme the control plane uses (sorted compact JSON bytes,
Ed25519 over ``<domain>\\x00<payload>``), so this proves the agent's verification is byte-compatible
with ``ares/domain/assessment`` on the control plane. The cross-repo golden-fixture round-trip
(ARES-2214) is the standing guard against drift.
"""

from __future__ import annotations

import base64
import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent import assessment

DOMAIN = "ares.network-assessment.signed-task.discover:v1"
SCHEMA = "ares.network-assessment.signed-task.discover.v1"


def _public_b64(key: Ed25519PrivateKey) -> str:
    raw = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    return base64.b64encode(raw).decode()


def _seal(payload: dict, key: Ed25519PrivateKey, *, domain: str = DOMAIN, schema: str = SCHEMA):
    # Byte-for-byte the control plane's wire.seal: sorted compact JSON, signed domain-separated.
    payload_bytes = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    message = domain.encode("ascii") + b"\x00" + payload_bytes
    signature = base64.b64encode(key.sign(message)).decode()
    return {
        "schema_version": schema,
        "payload": base64.b64encode(payload_bytes).decode(),
        "signature": signature,
        "signer_key_id": "cp-key-1",
    }


def test_valid_job_opens() -> None:
    key = Ed25519PrivateKey.generate()
    payload = {"assessment_id": "a1", "target_cidrs": ["10.0.0.0/24"], "tcp_ports": "1-1023"}
    envelope = _seal(payload, key)
    out = assessment.open_signed_job(
        envelope, public_keys=[_public_b64(key)], domain=DOMAIN, expected_schema=SCHEMA
    )
    assert out == payload


def test_tampered_payload_is_refused() -> None:
    key = Ed25519PrivateKey.generate()
    envelope = _seal({"target_cidrs": ["10.0.0.0/24"]}, key)
    forged = base64.b64encode(json.dumps({"target_cidrs": ["0.0.0.0/0"]}).encode()).decode()
    envelope["payload"] = forged
    assert (
        assessment.open_signed_job(
            envelope, public_keys=[_public_b64(key)], domain=DOMAIN, expected_schema=SCHEMA
        )
        is None
    )


def test_wrong_key_is_refused() -> None:
    key = Ed25519PrivateKey.generate()
    other = Ed25519PrivateKey.generate()
    envelope = _seal({"x": 1}, key)
    assert (
        assessment.open_signed_job(
            envelope, public_keys=[_public_b64(other)], domain=DOMAIN, expected_schema=SCHEMA
        )
        is None
    )


def test_wrong_schema_is_refused() -> None:
    key = Ed25519PrivateKey.generate()
    envelope = _seal({"x": 1}, key)
    assert (
        assessment.open_signed_job(
            envelope,
            public_keys=[_public_b64(key)],
            domain=DOMAIN,
            expected_schema="ares.network-assessment.signed-task.discover.v2",
        )
        is None
    )


def test_empty_key_list_fails_closed() -> None:
    key = Ed25519PrivateKey.generate()
    envelope = _seal({"x": 1}, key)
    assert (
        assessment.open_signed_job(
            envelope, public_keys=[], domain=DOMAIN, expected_schema=SCHEMA
        )
        is None
    )


@pytest.mark.parametrize("bad", [None, "not-a-dict", {}, {"schema_version": SCHEMA}])
def test_malformed_envelope_is_refused(bad: object) -> None:
    key = Ed25519PrivateKey.generate()
    assert (
        assessment.open_signed_job(
            bad, public_keys=[_public_b64(key)], domain=DOMAIN, expected_schema=SCHEMA
        )
        is None
    )


def test_generated_keypair_signs_a_result_that_verifies() -> None:
    # The agent generates a keypair once, registers the public half, and signs its results with the
    # private half. A signature by the seed must verify under the derived public key.
    seed = assessment.generate_signing_seed()
    public = assessment.public_key_b64_from_seed(seed)
    private = Ed25519PrivateKey.from_private_bytes(base64.b64decode(seed))
    message = DOMAIN.encode("ascii") + b"\x00" + b"result-bytes"
    signature = base64.b64encode(private.sign(message)).decode()
    assert assessment.verify_signature(
        signature=signature, domain=DOMAIN, payload=b"result-bytes", public_keys=[public]
    )


def test_public_key_is_stable_for_a_seed() -> None:
    seed = assessment.generate_signing_seed()
    assert assessment.public_key_b64_from_seed(seed) == assessment.public_key_b64_from_seed(seed)
