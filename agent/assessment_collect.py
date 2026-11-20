"""Turn a verified COLLECT job + a device's config into a signed, control-plane-shaped result.

The agent half of the credentialed collection. ``main._run_task`` verifies the signed collect job
(agent-first), resolves ``credential_ref`` from the LOCAL vault, this module's caller reads the
running-config over SSH, and here the parsed fields become the normalized facts the executable-control
evaluator consumes, assembled into a ``CollectResultV1``-shaped payload that ``assessment.seal_result``
signs with the agent's own key.

Pure: no socket, no clock. The result shape must match
``ares.domain.assessment.results.CollectResultV1`` exactly (``extra="forbid"`` on the control plane),
so the constructors emit only the allowed keys. The cross-repo fixture round trip guards drift.
"""

from __future__ import annotations

# Envelope schemas + signature domains for the collect job the agent verifies and the result it
# signs. Mirror ares.domain.assessment.tasks.SCHEMA_COLLECT_V1 / results.SCHEMA_COLLECT_RESULT_V1 and
# the dispatch/result signature domains; a mismatch fails verification at either end.
JOB_SCHEMA = "ares.network-assessment.signed-task.collect.v1"
JOB_DOMAIN = "ares.network-assessment.signed-task.collect:v1"
RESULT_SCHEMA = "ares.network-assessment.result.collect.v1"
RESULT_DOMAIN = "ares.network-assessment.result.collect:v1"

_REQUIRED_JOB_FIELDS = (
    "tenant_id",
    "assessment_id",
    "snapshot_id",
    "scope_revision_sha256",
    "agent_id",
    "job_id",
    "nonce",
    "target_address",
    "credential_ref",
    "control_ids",
)

_COVERAGE_STATES = frozenset(
    {"assessed", "not_assessed", "unavailable", "unsupported", "prohibited", "skipped", "inconclusive"}
)


def require_fields(job: dict) -> list[str]:
    """The control_ids a verified collect job asks for, or raise ``ValueError`` if it is malformed.

    Called only after the signature verified, so a missing field is a contract violation, not
    attacker input."""
    missing = [field for field in _REQUIRED_JOB_FIELDS if field not in job]
    if missing:
        raise ValueError(f"verified collect job missing required field(s): {', '.join(missing)}")
    control_ids = job["control_ids"]
    if not isinstance(control_ids, list) or not all(isinstance(c, str) for c in control_ids):
        raise ValueError("collect job control_ids must be a list of strings")
    return list(control_ids)


def control_facts(control_id: str, fields: dict[str, object], *, collection_complete: bool) -> dict:
    """The ``{status, value}`` facts for one control: the three gates plus the collected fields.

    The agent asserts ``applicable`` and ``collection_complete`` from what it observed (the device
    answered and the config was read). ``policy_approved`` is OBSERVED/true for v1, standing for the
    assessment the customer launched; binding a real approved policy at the control plane is the
    hardening that replaces this. A field the parser could not read is simply absent, so the control
    evaluates NOT_ASSESSED rather than on a guessed value."""
    facts: dict[str, dict] = {
        "applicable": {"status": "OBSERVED", "value": True},
        "policy_approved": {"status": "OBSERVED", "value": True},
        "collection_complete": {
            "status": "OBSERVED" if collection_complete else "PARTIAL",
            "value": bool(collection_complete),
        },
    }
    for name, value in fields.items():
        facts[name] = {"status": "OBSERVED", "value": value}
    return {"control_id": control_id, "facts": facts, "evidence_sha256": None}


def coverage_entry(*, scope: str, state: str, reason_code: str | None = None) -> dict:
    """One coverage record for a control that could not be collected (no credential, unsupported)."""
    if state not in _COVERAGE_STATES:
        raise ValueError(f"unknown coverage state: {state!r}")
    return {"scope": scope, "state": state, "reason_code": reason_code}


def neighbour_entry(
    *,
    local_interface: str,
    neighbour_id: str,
    neighbour_interface: str | None = None,
    neighbour_address: str | None = None,
) -> dict:
    """One link-layer neighbour the device reported, shaped to match the control plane's
    ``CollectedNeighbour`` exactly (``extra="forbid"``). The control plane classifies a
    management-interface neighbour out and keys an edge on ``neighbour_address``, so the agent
    reports every neighbour faithfully, the local interface included."""
    return {
        "local_interface": str(local_interface),
        "neighbour_id": str(neighbour_id),
        "neighbour_interface": neighbour_interface,
        "neighbour_address": neighbour_address,
    }


def build_collect_result(
    job: dict,
    *,
    controls: list[dict],
    coverage: list[dict],
    completed_at: str,
    neighbours: list[dict] | None = None,
    partial: bool = False,
) -> dict:
    """Assemble a ``CollectResultV1``-shaped payload bound back to the verified job."""
    return {
        "tenant_id": job["tenant_id"],
        "assessment_id": job["assessment_id"],
        "snapshot_id": job["snapshot_id"],
        "scope_revision_sha256": job["scope_revision_sha256"],
        "agent_id": job["agent_id"],
        "job_id": job["job_id"],
        "nonce": job["nonce"],
        "completed_at": completed_at,
        "target_address": job["target_address"],
        "controls": list(controls),
        "coverage": list(coverage),
        "neighbours": list(neighbours or []),
        "partial": partial,
    }
