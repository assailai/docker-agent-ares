"""Describe and seal a raw-evidence artifact the agent uploads out of band.

The agent half of the Network Assessment artifact channel (ARES-2267). The signed JSON result carries
only a hash; this is how the bytes behind that hash (a packet capture of the job's own traffic, a
captured running-config, a banner) come home. The agent builds a descriptor binding the bytes to the
exact verified job, seals it with the enrolment signing seed, and uploads both via
``control_plane.submit_assessment_artifact``.

The descriptor shape must match ``ares.domain.assessment.results.AssessmentArtifactDescriptorV1``
exactly (``extra="forbid"`` on the control plane), so this emits only the allowed keys. The control
plane re-derives the hash and size from the uploaded bytes and refuses a mismatch, so these cannot
lie. The cross-repo fixture round trip (ARES-2214) is the standing guard that these two definitions
stay in step.
"""

from __future__ import annotations

import hashlib

# The envelope schema and signature domain an ARTIFACT descriptor is sealed under. These mirror
# ``results.SCHEMA_ARTIFACT_V1`` and ``results.SIGN_DOMAIN_ARTIFACT`` on the control plane; a mismatch
# makes every artifact fail schema/signature verification at ingestion, so they are pinned here.
ARTIFACT_SCHEMA = "ares.network-assessment.artifact.v1"
ARTIFACT_DOMAIN = "ares.network-assessment.artifact:v1"

# The artifact kinds, mirroring ``AssessmentArtifactKind`` on the control plane (compared as text).
KIND_PACKET_CAPTURE = "packet_capture"
KIND_RUNNING_CONFIG = "running_config"
KIND_SERVICE_BANNER = "service_banner"


def content_sha256(body: bytes) -> str:
    """The lowercase hex sha256 the control plane re-derives from the uploaded bytes."""
    return hashlib.sha256(body).hexdigest()


def build_artifact_descriptor(job: dict, *, kind: str, body: bytes, captured_at: str) -> dict:
    """Build the artifact descriptor binding ``body`` to the exact verified ``job``.

    ``job`` is the already-verified signed task payload (the agent-first gate ran before this), so its
    binding fields are trusted. ``captured_at`` is an ISO-8601 timestamp. The returned dict is the
    payload ``assessment.seal_result`` seals under :data:`ARTIFACT_SCHEMA` / :data:`ARTIFACT_DOMAIN`.
    """
    return {
        "tenant_id": job["tenant_id"],
        "assessment_id": job["assessment_id"],
        "snapshot_id": job["snapshot_id"],
        "agent_id": job["agent_id"],
        "job_id": job["job_id"],
        "nonce": job["nonce"],
        "kind": kind,
        "content_sha256": content_sha256(body),
        "byte_size": len(body),
        "captured_at": captured_at,
    }
