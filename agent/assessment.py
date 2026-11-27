"""Verify a control-plane-signed Network Assessment job before the agent acts on it.

The control plane signs every assessment job; the agent must verify that signature BEFORE it reads
any target field, so a forged or tampered job never reaches the probes. This is byte-identical to
the control plane's scheme (``ares/domain/assessment/signing.py`` + ``wire.py``):

* the signature is Ed25519 over ``<domain>\\x00<exact payload bytes>``;
* ``payload`` in the envelope is the base64 of the EXACT JSON bytes the control plane signed;
* verification runs over those exact bytes, never a re-serialisation, so there is no canonical-JSON
  dependency and no way for a producer/verifier serialisation difference to matter.

A LIST of public keys is admitted so a control-plane key rotation accepts the outgoing and incoming
key at once. The cross-repo fixture round-trip (ARES-2214) is the standing proof the two stay
compatible; this file is deliberately tiny and dependency-light (only ``cryptography``) so the
agent image stays lean.
"""

from __future__ import annotations

import base64
import json
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

_PRINTABLE_ASCII_MIN = 0x21
_PRINTABLE_ASCII_MAX = 0x7E


def _domain_separated(domain: str, payload: bytes) -> bytes:
    if not domain or any(
        not (_PRINTABLE_ASCII_MIN <= ord(ch) <= _PRINTABLE_ASCII_MAX) for ch in domain
    ):
        raise ValueError("signature domain must be printable ASCII without whitespace")
    return domain.encode("ascii") + b"\x00" + payload


def verify_signature(*, signature: str, domain: str, payload: bytes, public_keys: list[str]) -> bool:
    """Whether ``signature`` (base64) is a valid Ed25519 signature over ``payload`` under ANY of
    ``public_keys`` (base64 raw 32-byte keys). Fails closed on any malformed input or an empty list.
    """
    try:
        raw_signature = base64.b64decode(signature, validate=True)
    except (ValueError, TypeError):
        return False
    message = _domain_separated(domain, payload)
    for encoded in public_keys:
        try:
            public = Ed25519PublicKey.from_public_bytes(base64.b64decode(encoded, validate=True))
            public.verify(raw_signature, message)
        except (InvalidSignature, ValueError, TypeError):
            continue
        return True
    return False


def open_signed_job(
    envelope: Any, *, public_keys: list[str], domain: str, expected_schema: str
) -> dict | None:
    """Return the decoded job as a dict if the envelope verifies and declares the expected schema,
    else ``None`` (fail closed). The caller still checks expiry and binding before acting.

    Order is deliberate: reject a wrong schema before spending a verify, verify the signature over
    the exact payload bytes, then decode. Nothing here re-serialises the payload.
    """
    if not isinstance(envelope, dict):
        return None
    if envelope.get("schema_version") != expected_schema:
        return None
    try:
        payload = base64.b64decode(envelope["payload"], validate=True)
    except (ValueError, TypeError, KeyError):
        return None
    if not verify_signature(
        signature=str(envelope.get("signature", "")),
        domain=domain,
        payload=payload,
        public_keys=public_keys,
    ):
        return None
    try:
        decoded = json.loads(payload)
    except (ValueError, TypeError):
        return None
    return decoded if isinstance(decoded, dict) else None


def generate_signing_seed() -> str:
    """A fresh base64 of a raw 32-byte Ed25519 PRIVATE seed. The agent generates this once at
    enrolment, persists it locally (never sends it), and registers only the matching public key."""
    return base64.b64encode(Ed25519PrivateKey.generate().private_bytes_raw()).decode()


def public_key_b64_from_seed(seed_b64: str) -> str:
    """The base64 of the raw 32-byte PUBLIC key matching a private seed produced by
    :func:`generate_signing_seed`. This is what the agent registers and signs results under."""
    private = Ed25519PrivateKey.from_private_bytes(base64.b64decode(seed_b64, validate=True))
    raw = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    return base64.b64encode(raw).decode()


def seal_result(
    payload: dict,
    *,
    schema: str,
    seed_b64: str,
    domain: str,
    signer_key_id: str,
) -> dict:
    """Seal a result payload into the control plane's ``SignedEnvelope`` wire shape, byte-for-byte.

    The agent signs its OWN results with the private seed it generated at enrolment (the seed never
    leaves the agent; only the matching public key was registered). The control plane verifies the
    signature against that registered public key before admitting the result. The payload bytes are
    the EXACT bytes the control plane's ``signing.canonical_json_bytes`` produces (sorted keys,
    compact separators, no NaN), so a round trip through ``wire.open_sealed`` reads them unchanged.
    """
    payload_bytes = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")
    private = Ed25519PrivateKey.from_private_bytes(base64.b64decode(seed_b64, validate=True))
    signature = base64.b64encode(private.sign(_domain_separated(domain, payload_bytes))).decode()
    return {
        "schema_version": schema,
        "payload": base64.b64encode(payload_bytes).decode(),
        "signature": signature,
        "signer_key_id": signer_key_id,
    }
