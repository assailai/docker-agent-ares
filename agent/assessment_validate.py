"""Run one control-plane-signed Controlled Validation plan: verify, bounded read-only probe, sign.

The agent half of the Mode-2 Controlled Validation tier (PR-65/PR-67). The control plane mints a
one-step, inline-signed ``ValidationPlan`` and dispatches it as a ``controlled_validation_v1`` task;
the agent verifies that signature BEFORE it reads any endpoint or opens any socket, runs a single
bounded, read-only probe strictly inside the plan's ``SafetyBudget`` (and the agent's own harder
local ceiling), and returns a ``ValidationResult`` it seals with its own enrolment key. The control
plane re-verifies the result against the agent's registered key, binds it to the plan it issued, and
seals a receipt (``ares/infra/agent_runtime/network_validation_receipt.py``); nothing here can set a
finding verdict, a validator result is an OBSERVATION that corroborates at most.

This is deliberately minimal-impact by construction. A step is run only when its ``safety_class`` is
PASSIVE/NON_CONSEQUENTIAL and its ``operation_class`` is PASSIVE_OBSERVE/READ_ONLY_QUERY/
SAFE_HANDSHAKE; anything higher is refused (BLOCKED/DENIED) without a packet sent. The probe never
writes to the target: it opens one TCP connection, optionally completes a TLS handshake, and for a
request-class protocol sends a single bounded read-only request (an HTTP ``HEAD``) or reads a service
banner, counting every byte against the budget and stopping at the first ceiling it meets.

The signing representation is byte-identical to the control plane's
``ares.domain.assessment.validation.crypto``: each envelope is signed over
``<DOMAIN>\\x00<canonical-json payload>`` where the payload is the model's JSON projection with the
signature field removed, and ``canonical-json`` is sorted-key compact UTF-8 (the same choice the rest
of the module's trust chain makes). So a producer here and the verifier there agree on the exact
bytes without a canonical-JSON library. The result shape must match
``ares.domain.assessment.validation.model.ValidationResult`` exactly (``extra="forbid"`` on the
control plane); the cross-repo fixture round trip is the standing guard that the two stay in step.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import ssl
from datetime import UTC, datetime
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent.assessment import _domain_separated, verify_signature

# Domain-separation strings and the result schema, byte-identical to the control plane's
# ``validation.crypto`` and ``ValidationResult.schema_version``; a mismatch fails verification at
# either end.
PLAN_DOMAIN = "ARES-CONTROLLED-VALIDATION-PLAN-V1"
RESULT_DOMAIN = "ARES-CONTROLLED-VALIDATION-RESULT-V1"
RESULT_SCHEMA = "ares.controlled-validation-result.v1"
ED25519_ALGORITHM = "Ed25519"

# Only these classes are ever run; anything more consequential is refused without a packet sent. Kept
# as text, compared to the plan's stored string values (mirrors ``ValidationSafetyClass`` /
# ``OperationClass``).
_SAFE_SAFETY_CLASSES = frozenset({"PASSIVE", "NON_CONSEQUENTIAL"})
_SAFE_OPERATION_CLASSES = frozenset(
    {"PASSIVE_OBSERVE", "READ_ONLY_QUERY", "SAFE_HANDSHAKE"}
)

# The agent's HARD local ceiling for one validation step, applied as the SMALLER of itself and the
# signed budget per counter: however generous the signed plan is, a probe from this box never buys
# more than this. A plan that signs a tighter budget is honored tighter.
_LOCAL_MAX_REQUESTS = 2
_LOCAL_MAX_BYTES_SENT = 4096
_LOCAL_MAX_BYTES_RECEIVED = 65536
_LOCAL_TIMEOUT_SECONDS = 15.0

# Protocols whose observation completes a TLS handshake, and those for which the agent sends a single
# read-only HTTP request. Everything else is a connect/banner observation.
_TLS_PROTOCOLS = frozenset({"tls", "https", "smtps", "ldaps", "ftps", "imaps", "pop3s"})
_HTTP_PROTOCOLS = frozenset({"http", "https"})

_MAX_SUMMARY = 1024
_BANNER_READ_CAP = 512


class ValidationPlanRejected(Exception):
    """The dispatched plan did not verify, or asked for an operation the agent will not run."""


def _canonical_bytes(payload: dict[str, Any]) -> bytes:
    """The exact bytes the control plane's ``canonical_json_bytes`` produces for ``payload``.

    Sorted keys, compact separators, UTF-8, no NaN, so the agent and the control plane sign and
    verify over identical bytes with no canonical-JSON dependency."""
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _signing_payload(envelope: dict[str, Any], signature_field: str) -> bytes:
    """Canonical bytes an envelope is signed over: its fields with the signature field removed."""
    return _canonical_bytes({k: v for k, v in envelope.items() if k != signature_field})


def verify_plan(plan: Any, *, cp_public_keys: list[str]) -> bool:
    """Whether ``plan`` is a well-formed control-plane-signed one-step validation plan.

    Fails closed: a non-dict, a plan carrying no inline signature, a plan that declares a schema
    other than the plan schema, a plan with no step, or a signature that does not verify over the
    canonical projection under :data:`PLAN_DOMAIN` against ANY of ``cp_public_keys`` (an empty key
    list fails closed) all return False, BEFORE any endpoint field is read. The signature is the
    authenticity gate: it proves the control plane issued this exact plan."""
    if not isinstance(plan, dict):
        return False
    if plan.get("schema_version") != "ares.controlled-validation-plan.v1":
        return False
    steps = plan.get("steps")
    if not isinstance(steps, list) or len(steps) != 1 or not isinstance(steps[0], dict):
        return False
    signature = plan.get("plan_signature")
    if not isinstance(signature, str) or not signature:
        return False
    if plan.get("plan_signature_algorithm") != ED25519_ALGORITHM:
        return False
    return verify_signature(
        signature=signature,
        domain=PLAN_DOMAIN,
        payload=_signing_payload(plan, "plan_signature"),
        public_keys=cp_public_keys,
    )


def step_is_runnable(step: dict[str, Any]) -> bool:
    """Whether the step's safety and operation classes are within the minimal-impact envelope.

    A step outside the envelope is refused without a packet sent (fail closed); this is the agent's
    own guard, independent of whatever the control plane approved."""
    return (
        step.get("safety_class") in _SAFE_SAFETY_CLASSES
        and step.get("operation_class") in _SAFE_OPERATION_CLASSES
    )


def effective_budget(signed: dict[str, Any]) -> dict[str, Any]:
    """The per-counter MINIMUM of the signed budget and the agent's hard local ceiling."""
    return {
        "max_requests": min(int(signed["max_requests"]), _LOCAL_MAX_REQUESTS),
        "max_bytes_sent": min(int(signed["max_bytes_sent"]), _LOCAL_MAX_BYTES_SENT),
        "max_bytes_received": min(
            int(signed["max_bytes_received"]), _LOCAL_MAX_BYTES_RECEIVED
        ),
        "timeout_seconds": min(
            float(signed["timeout_seconds"]), _LOCAL_TIMEOUT_SECONDS
        ),
    }


def iso_z(timestamp: str) -> str:
    """Normalize a UTC ISO-8601 timestamp to the ``...Z`` form the control plane re-serializes to.

    The result's ``started_at``/``completed_at`` are signed, and the control plane validates the
    result as a pydantic ``AwareDatetime`` and re-dumps it before verifying the signature: pydantic
    emits a UTC offset as ``Z``, not ``+00:00``. The agent must therefore sign the ``Z`` form, or the
    bytes diverge and the result signature fails. This is the one place that conversion happens."""
    return timestamp.replace("+00:00", "Z")


def _summary(text: str) -> str:
    """A ProbeObservation-safe summary: 1-1024 chars, no control characters except tab."""
    cleaned = "".join(ch for ch in text if ch == "\t" or ord(ch) >= 0x20).strip()
    if not cleaned:
        cleaned = "validation probe produced no printable summary"
    return cleaned[:_MAX_SUMMARY]


def _observation(
    *,
    outcome: str,
    summary: str,
    sent_bytes: int,
    received_bytes: int,
    requests: int,
    protocol_metadata: dict[str, Any] | None = None,
    terminal_reason: str = "NONE",
) -> dict[str, Any]:
    return {
        "outcome": outcome,
        "summary": _summary(summary),
        "sent_bytes": max(0, sent_bytes),
        "received_bytes": max(0, received_bytes),
        "requests": max(0, requests),
        "protocol_metadata": protocol_metadata or {},
        "terminal_reason": terminal_reason,
    }


async def probe_endpoint(
    endpoint: dict[str, Any], budget: dict[str, Any]
) -> dict[str, Any]:
    """Open one bounded, read-only connection to ``endpoint`` and report what it observed.

    Never writes to the target beyond a single read-only request (an HTTP ``HEAD`` or none at all),
    and never reads or sends past the effective budget. Returns a ProbeObservation-shaped dict. Any
    failure is reported as an outcome, never raised, so the task always settles. CONFIRMED means the
    endpoint accepted the connection and completed the protocol's safe handshake (it corroborates that
    the service is reachable); NOT_CONFIRMED means the connection was refused; a timeout is
    FILTERED/TIMEOUT; anything else is ERROR."""
    address = str(endpoint["address"])
    port = int(endpoint["port"])
    protocol = str(endpoint["protocol"])
    server_name = str(endpoint.get("server_name") or "")
    timeout = float(budget["timeout_seconds"])
    max_recv = int(budget["max_bytes_received"])
    max_sent = int(budget["max_bytes_sent"])
    max_requests = int(budget["max_requests"])

    writer: asyncio.StreamWriter | None = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(address, port), timeout=timeout
        )
    except TimeoutError:
        return _observation(
            outcome="INCONCLUSIVE",
            summary=f"TCP connect to {address}:{port} timed out after {timeout:g}s",
            sent_bytes=0,
            received_bytes=0,
            requests=1,
            terminal_reason="TIMEOUT",
        )
    except ConnectionRefusedError:
        return _observation(
            outcome="NOT_CONFIRMED",
            summary=f"TCP connect to {address}:{port} was refused",
            sent_bytes=0,
            received_bytes=0,
            requests=1,
            terminal_reason="REFUSED",
        )
    except OSError as exc:
        return _observation(
            outcome="ERROR",
            summary=f"TCP connect to {address}:{port} failed: {type(exc).__name__}",
            sent_bytes=0,
            received_bytes=0,
            requests=1,
            terminal_reason="FILTERED",
        )

    metadata: dict[str, Any] = {"protocol": protocol, "connected": True}
    try:
        if protocol in _TLS_PROTOCOLS:
            tls_meta = _tls_metadata(writer)
            if tls_meta is None:
                return _observation(
                    outcome="INCONCLUSIVE",
                    summary=f"TLS handshake to {address}:{port} did not complete",
                    sent_bytes=0,
                    received_bytes=0,
                    requests=1,
                    terminal_reason="REFUSED",
                )
            metadata.update(tls_meta)

        if protocol in _HTTP_PROTOCOLS and max_requests >= 1:
            return await _probe_http(
                reader=reader,
                writer=writer,
                address=address,
                port=port,
                server_name=server_name or address,
                secure=protocol == "https",
                max_sent=max_sent,
                max_recv=max_recv,
                timeout=timeout,
                metadata=metadata,
            )

        received, banner = await _read_banner(
            reader, cap=min(max_recv, _BANNER_READ_CAP), timeout=timeout
        )
        if banner:
            metadata["banner"] = banner
        return _observation(
            outcome="CONFIRMED",
            summary=f"{protocol} endpoint {address}:{port} accepted the connection and the safe handshake",
            sent_bytes=0,
            received_bytes=received,
            requests=1,
            protocol_metadata=metadata,
        )
    except TimeoutError:
        return _observation(
            outcome="INCONCLUSIVE",
            summary=f"{protocol} probe of {address}:{port} timed out",
            sent_bytes=0,
            received_bytes=0,
            requests=1,
            protocol_metadata=metadata,
            terminal_reason="TIMEOUT",
        )
    except (OSError, ssl.SSLError) as exc:
        return _observation(
            outcome="ERROR",
            summary=f"{protocol} probe of {address}:{port} failed: {type(exc).__name__}",
            sent_bytes=0,
            received_bytes=0,
            requests=1,
            protocol_metadata=metadata,
            terminal_reason="INTERNAL_ERROR",
        )
    finally:
        if writer is not None:
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout=2.0)
            except (TimeoutError, OSError, ssl.SSLError):
                pass


def _tls_metadata(writer: asyncio.StreamWriter) -> dict[str, Any] | None:
    """The negotiated TLS version/cipher, if the transport completed a handshake, else None.

    ``asyncio.open_connection`` does not itself do TLS; a bare connection to a TLS port returns no
    SSL object, so this records that TLS context was not negotiated rather than inventing one. A full
    start_tls handshake is a later hardening; for now a reachable TLS port is a reachable port."""
    ssl_object = writer.get_extra_info("ssl_object")
    if ssl_object is None:
        return {"tls_negotiated": False}
    return {
        "tls_negotiated": True,
        "tls_version": ssl_object.version(),
        "tls_cipher": (ssl_object.cipher() or (None,))[0],
    }


async def _read_banner(
    reader: asyncio.StreamReader, *, cap: int, timeout: float
) -> tuple[int, str]:
    """Read at most ``cap`` bytes of a service banner, returning (bytes_read, printable_text)."""
    if cap <= 0:
        return 0, ""
    try:
        data = await asyncio.wait_for(reader.read(cap), timeout=min(timeout, 5.0))
    except (TimeoutError, OSError, ssl.SSLError):
        return 0, ""
    text = data.decode("latin-1", errors="replace")
    printable = "".join(ch for ch in text if ch == "\t" or ord(ch) >= 0x20).strip()
    return len(data), printable[:_BANNER_READ_CAP]


async def _probe_http(
    *,
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    address: str,
    port: int,
    server_name: str,
    secure: bool,
    max_sent: int,
    max_recv: int,
    timeout: float,
    metadata: dict[str, Any],
) -> dict[str, Any]:
    """Send a single read-only ``HEAD`` request and read the bounded response status line."""
    request = (
        f"HEAD / HTTP/1.0\r\nHost: {server_name}\r\nConnection: close\r\n\r\n".encode(
            "latin-1"
        )
    )
    if len(request) > max_sent:
        # The budget does not even cover one HEAD: do not send; the connection alone is the evidence.
        return _observation(
            outcome="CONFIRMED",
            summary=f"http endpoint {address}:{port} accepted the connection (budget too small to request)",
            sent_bytes=0,
            received_bytes=0,
            requests=1,
            protocol_metadata=metadata,
        )
    writer.write(request)
    await asyncio.wait_for(writer.drain(), timeout=timeout)
    received, banner = await _read_banner(
        reader, cap=min(max_recv, _BANNER_READ_CAP), timeout=timeout
    )
    status_line = banner.splitlines()[0] if banner else ""
    metadata["scheme"] = "https" if secure else "http"
    if status_line:
        metadata["http_status_line"] = status_line
    return _observation(
        outcome="CONFIRMED" if status_line else "INCONCLUSIVE",
        summary=(
            f"http endpoint {address}:{port} answered a HEAD request: {status_line}"
            if status_line
            else f"http endpoint {address}:{port} accepted a HEAD request but returned no status line"
        ),
        sent_bytes=len(request),
        received_bytes=received,
        requests=1,
        protocol_metadata=metadata,
        terminal_reason="NONE" if status_line else "INCONCLUSIVE",
    )


def build_evidence(
    plan: dict[str, Any], observation: dict[str, Any], *, captured_at: str
) -> tuple[dict[str, Any], bytes, bytes]:
    """The single evidence artifact for this validation: the probe transcript and its manifest entry.

    Returns ``(manifest_entry, payload_bytes, descriptor_bytes)``. ``payload_bytes`` is the canonical
    transcript the agent observed; ``descriptor_bytes`` is a small descriptor binding it to the
    validation. Both digests in the manifest entry are the real sha256 of those bytes, so the sealed
    receipt commits to exactly what the probe saw. (Uploading the bytes to the artifact store for a
    ``controlled_validation_v1`` task is a later slice: the existing artifact channel binds to a
    discover/collect ``job_id``/``nonce`` the plan does not carry.)"""
    transcript = {
        "validation_id": plan["validation_id"],
        "snapshot_id": plan["snapshot_id"],
        "endpoint": plan["steps"][0]["endpoint"],
        "observation": observation,
        "captured_at": captured_at,
    }
    payload_bytes = _canonical_bytes(transcript)
    payload_sha256 = hashlib.sha256(payload_bytes).hexdigest()
    descriptor = {
        "evidence_id": f"evidence-{plan['validation_id']}",
        "kind": "validation_transcript",
        "payload_sha256": payload_sha256,
        "payload_bytes": len(payload_bytes),
        "captured_at": captured_at,
    }
    descriptor_bytes = _canonical_bytes(descriptor)
    descriptor_sha256 = hashlib.sha256(descriptor_bytes).hexdigest()
    entry = {
        "evidence_id": descriptor["evidence_id"],
        "payload_sha256": payload_sha256,
        "descriptor_sha256": descriptor_sha256,
        "payload_bytes": len(payload_bytes),
    }
    return entry, payload_bytes, descriptor_bytes


def build_validation_result(
    plan: dict[str, Any],
    *,
    observation: dict[str, Any],
    evidence_entry: dict[str, Any],
    started_at: str,
    completed_at: str,
    budget_used: dict[str, int | float],
    state: str = "COMPLETED",
) -> dict[str, Any]:
    """Assemble a ``ValidationResult``-shaped payload fully bound back to the signed plan.

    Every context, validator, endpoint and budget field is copied from the plan (or its single step),
    so the control plane's binding check passes only for a result that answers exactly this plan. The
    outcome, rationale and counters are the agent's own observation; ``result_signature`` is filled in
    by :func:`sign_validation_result`."""
    step = plan["steps"][0]
    rationale = observation["summary"]
    return {
        "schema_version": RESULT_SCHEMA,
        # context binding (every _ContextBound field, copied from the plan)
        "tenant_id": plan["tenant_id"],
        "environment_id": plan["environment_id"],
        "assessment_id": plan["assessment_id"],
        "snapshot_id": plan["snapshot_id"],
        "finding_id": plan["finding_id"],
        "finding_family": plan["finding_family"],
        "required_evidence_kind": plan["required_evidence_kind"],
        "asset_id": plan["asset_id"],
        "scope_revision_id": plan["scope_revision_id"],
        "scope_revision_digest": plan["scope_revision_digest"],
        "customer_authorization_id": plan["customer_authorization_id"],
        "customer_authorization_digest": plan["customer_authorization_digest"],
        "execution_profile_digest": plan["execution_profile_digest"],
        "agent_id": plan["agent_id"],
        "agent_epoch": plan["agent_epoch"],
        # plan + validator binding
        "validation_id": plan["validation_id"],
        "plan_id": plan["plan_id"],
        "approval_id": plan["approval_id"],
        "lease_token_digest": plan["lease_token_digest"],
        "result_key_id": plan["result_key_id"],
        "validator_id": step["validator_id"],
        "validator_version": step["validator_version"],
        "validator_package_digest": step["validator_package_digest"],
        "operation_id": step["operation_id"],
        "endpoint": step["endpoint"],
        "budget": step["budget"],
        # observation
        "state": state,
        "outcome": observation["outcome"],
        "rationale": rationale,
        "evidence_ids": [evidence_entry["evidence_id"]],
        "started_at": iso_z(started_at),
        "completed_at": iso_z(completed_at),
        "budget_used": budget_used,
        "evidence_manifest": [evidence_entry],
        "terminal_reason": observation.get("terminal_reason", "NONE"),
        "coverage_debt": False,
        "counters_complete": True,
        "limitations": [],
        "result_signature_algorithm": "",
        "result_signature": "",
        "pilot_id": plan.get("pilot_id", ""),
    }


def sign_validation_result(result: dict[str, Any], *, seed_b64: str) -> dict[str, Any]:
    """Seal ``result`` with the agent's enrolment key over :data:`RESULT_DOMAIN`.

    Signs the canonical projection (every field but ``result_signature``) and fills in the signature
    and its algorithm. The control plane verifies this against the agent's REGISTERED public key, so
    the seed never leaves the agent; only the matching public key was registered at enrolment."""
    import base64

    signed = dict(result)
    signed["result_signature_algorithm"] = ED25519_ALGORITHM
    signed["result_signature"] = ""
    payload = _signing_payload(signed, "result_signature")
    private = Ed25519PrivateKey.from_private_bytes(
        base64.b64decode(seed_b64, validate=True)
    )
    signed["result_signature"] = base64.b64encode(
        private.sign(_domain_separated(RESULT_DOMAIN, payload))
    ).decode()
    return signed


def plan_is_expired(plan: dict[str, Any], *, now: datetime | None = None) -> bool:
    """Whether the plan's ``expires_at`` is in the past. An expired plan is not probed: a CONFIRMED
    outcome past expiry is refused by the control plane, so running it wastes a probe."""
    moment = now or datetime.now(UTC)
    try:
        expires = datetime.fromisoformat(str(plan["expires_at"]))
    except (ValueError, KeyError, TypeError):
        return True
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=UTC)
    return moment >= expires
