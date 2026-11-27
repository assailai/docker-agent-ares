"""Normalize a storage array's read-only management-API output into executable-control facts (the
credentialed storage-management cohort slice).

Read-only: authenticates to the array's management API with a bearer token from the agent's local
vault (``storage_mgmt`` credential kind) and does GETs only (no create / modify / delete), then parses
the returned security-posture document into the ``storage.*`` management fields. Like the device, host
and Kubernetes collectors it ABSTAINS rather than invents: an endpoint the token is not authorized
for, or an array not reachable, leaves the control UNAVAILABLE / the field out, so it stays
NOT_ASSESSED.

This targets a GENERIC array-management REST contract (the shape a lab simulator serves, and the shape
a per-vendor adapter -- NetApp ONTAP, Pure FlashArray, Dell PowerStore -- maps onto). The vendor
adapters are their own breadth cohorts; this slice proves the credentialed storage-management
transport and the six management-posture controls end to end against the generic contract. The two
documents it reads:

- ``GET /api/v1/security/posture`` -> the array's self-reported management-security posture (the
  ``authenticated_native_configuration`` evidence class the controls require): management transport
  encryption, admin MFA enforcement, data-access logging, snapshot deletion-protection, and whether a
  privileged account can bypass immutability.
- ``GET /api/v1/security/administrators`` -> the array's administrative accounts, sent as the RAW
  observed set for the baseline-comparison control (the control plane diffs it against the tenant
  baseline; the agent never judges which admins are "unapproved").

The parse functions are PURE (posture JSON in, typed value out); the networked GET is a separate
coroutine so the handler is testable by monkeypatching the fetch.
"""

from __future__ import annotations

import ssl

import httpx

# The storage-management controls this collector reads, grouped by the management-API document each one
# needs so the tier fetches a document only when a requested control uses it.
POSTURE_CONTROLS = frozenset(
    {
        "storage.mgmt.plaintext_protocol",
        "storage.auth.mfa_not_enforced",
        "storage.audit.data_access_logging_disabled",
        "storage.snapshot.unprotected",
        "storage.immutability.bypassable",
        "storage.volume.encryption",
        "storage.replication.untrusted",
        "storage.lifecycle.unsupported_firmware",
        "storage.multipath.inconsistent_access",
        "storage.recovery.unseparated_evidence",
    }
)
# A BASELINE-COMPARISON control: the agent sends the RAW observed administrator set and leaves the
# `policy_approved` gate for the control plane, which diffs the set against the tenant's approved
# baseline (the agent has none). Distinct from the factual-absolute posture controls above, whose
# field IS the finding; here the agent never judges which admins are "unapproved".
RBAC_CONTROLS = frozenset({"storage.rbac.unapproved_admins"})
SERVES = POSTURE_CONTROLS | RBAC_CONTROLS

# The array management API is served over TLS on the standard HTTPS port; the collect target is the
# array's management endpoint.
_API_PORT = 443
_POSTURE_PATH = "/api/v1/security/posture"
_ADMINS_PATH = "/api/v1/security/administrators"

# Bound the admin read so a huge account directory cannot make one collection unbounded
# (build-for-scale). A set larger than this still yields a lower-bound observed set, which only ever
# UNDER-reports a gt-0 unapproved-admins finding, never a false positive.
_MAX_ADMINS = 10_000


def serves(control_id: str) -> bool:
    """Whether this collector reads ``control_id`` from the array management API with the bearer
    token."""
    return control_id in SERVES


def _bool_at(posture: object, *path: str) -> bool | None:
    """The boolean at a fixed nested path in the posture document, or ``None`` to abstain when the path
    is absent or the value is not a boolean. Walks only the fixed, shallow paths this collector reads,
    so a hostile deeply-nested payload is never recursed."""
    node: object = posture
    for key in path:
        if not isinstance(node, dict):
            return None
        node = node.get(key)
    return node if isinstance(node, bool) else None


def _int_at(posture: object, *path: str) -> int | None:
    """The non-negative integer at a fixed nested path, or ``None`` to abstain when the path is absent
    or the value is not an int. ``bool`` is excluded explicitly (``True``/``False`` are ints in Python),
    so a mis-typed boolean never reads as a count."""
    node: object = posture
    for key in path:
        if not isinstance(node, dict):
            return None
        node = node.get(key)
    if isinstance(node, bool) or not isinstance(node, int) or node < 0:
        return None
    return node


def parse_management_encryption_enforced(posture: object) -> bool | None:
    """Whether the array enforces transport encryption for its management interface
    (``management_transport.tls_enforced``), or ``None`` to abstain. The field is the enforced sense,
    so a ``False`` reading is the finding (plaintext management permitted)."""
    return _bool_at(posture, "management_transport", "tls_enforced")


def parse_admin_mfa_enforced(posture: object) -> bool | None:
    """Whether the array enforces MFA for administrative logins (``authentication.mfa_enforced``), or
    ``None`` to abstain. ``False`` is the finding (management without enforced MFA)."""
    return _bool_at(posture, "authentication", "mfa_enforced")


def parse_data_access_logging_enabled(posture: object) -> bool | None:
    """Whether the array logs data-access events (``audit.data_access_logging_enabled``), or ``None``
    to abstain. ``False`` is the finding (data-access logging disabled)."""
    return _bool_at(posture, "audit", "data_access_logging_enabled")


def parse_snapshot_deletion_protection(posture: object) -> bool | None:
    """Whether snapshots carry deletion protection (``snapshots.deletion_protection_enabled``), or
    ``None`` to abstain. ``False`` is the finding (snapshots can be deleted)."""
    return _bool_at(posture, "snapshots", "deletion_protection_enabled")


def parse_immutability_bypass_possible(posture: object) -> bool | None:
    """Whether a privileged account can bypass object-lock / WORM immutability
    (``immutability.privileged_bypass_possible``), or ``None`` to abstain. Here ``True`` is the finding
    (immutability is bypassable), the opposite polarity to the other posture fields."""
    return _bool_at(posture, "immutability", "privileged_bypass_possible")


def management_encryption_field(posture: object) -> dict[str, object] | None:
    """The ``storage.mgmt.plaintext_protocol`` field dict, or ``None`` to abstain."""
    value = parse_management_encryption_enforced(posture)
    return None if value is None else {"management_encryption_enforced": value}


def admin_mfa_field(posture: object) -> dict[str, object] | None:
    """The ``storage.auth.mfa_not_enforced`` field dict, or ``None`` to abstain."""
    value = parse_admin_mfa_enforced(posture)
    return None if value is None else {"admin_mfa_enforced": value}


def data_access_logging_field(posture: object) -> dict[str, object] | None:
    """The ``storage.audit.data_access_logging_disabled`` field dict, or ``None`` to abstain."""
    value = parse_data_access_logging_enabled(posture)
    return None if value is None else {"data_access_logging_enabled": value}


def snapshot_protection_field(posture: object) -> dict[str, object] | None:
    """The ``storage.snapshot.unprotected`` field dict, or ``None`` to abstain."""
    value = parse_snapshot_deletion_protection(posture)
    return None if value is None else {"snapshot_deletion_protection_enabled": value}


def immutability_bypass_field(posture: object) -> dict[str, object] | None:
    """The ``storage.immutability.bypassable`` field dict, or ``None`` to abstain."""
    value = parse_immutability_bypass_possible(posture)
    return None if value is None else {"immutability_privileged_bypass_possible": value}


def parse_volume_encryption_enabled(posture: object) -> bool | None:
    """Whether the array enforces volume encryption at rest (``volumes.encryption_enabled``), or
    ``None`` to abstain. ``False`` is the finding (a volume unencrypted at rest)."""
    return _bool_at(posture, "volumes", "encryption_enabled")


def parse_untrusted_replication_targets(posture: object) -> int | None:
    """The count of replication targets the array reports as unencrypted or to an untrusted peer
    (``replication.unencrypted_or_untrusted_targets``), or ``None`` to abstain. ``gt 0`` is the
    finding. The array classifies its own targets; the collector reports the count, it does not
    define trust."""
    return _int_at(posture, "replication", "unencrypted_or_untrusted_targets")


def parse_end_of_life_components(posture: object) -> int | None:
    """The count of storage components (controller, shelf, drive, protocol firmware) the array reports
    as end-of-life (``lifecycle.end_of_life_components``), or ``None`` to abstain. ``gt 0`` is the
    finding."""
    return _int_at(posture, "lifecycle", "end_of_life_components")


def parse_multipath_inconsistencies(posture: object) -> int | None:
    """The count of multipath / zoning / host-access inconsistencies the array reports
    (``multipath.inconsistencies``), or ``None`` to abstain. ``gt 0`` is the finding."""
    return _int_at(posture, "multipath", "inconsistencies")


def parse_recovery_evidence_separated(posture: object) -> bool | None:
    """Whether recoverability evidence is kept separate from the configured-backup evidence
    (``recovery.evidence_separated``), or ``None`` to abstain. ``False`` is the finding (recovery
    evidence not independently separated)."""
    return _bool_at(posture, "recovery", "evidence_separated")


def volume_encryption_field(posture: object) -> dict[str, object] | None:
    """The ``storage.volume.encryption`` field dict, or ``None`` to abstain."""
    value = parse_volume_encryption_enabled(posture)
    return None if value is None else {"volume_encryption_enabled": value}


def replication_untrusted_field(posture: object) -> dict[str, object] | None:
    """The ``storage.replication.untrusted`` field dict, or ``None`` to abstain."""
    value = parse_untrusted_replication_targets(posture)
    return None if value is None else {"unencrypted_or_untrusted_replication_targets": value}


def lifecycle_firmware_field(posture: object) -> dict[str, object] | None:
    """The ``storage.lifecycle.unsupported_firmware`` field dict, or ``None`` to abstain."""
    value = parse_end_of_life_components(posture)
    return None if value is None else {"end_of_life_storage_components": value}


def multipath_inconsistency_field(posture: object) -> dict[str, object] | None:
    """The ``storage.multipath.inconsistent_access`` field dict, or ``None`` to abstain."""
    value = parse_multipath_inconsistencies(posture)
    return None if value is None else {"multipath_or_zoning_inconsistencies": value}


def recovery_evidence_field(posture: object) -> dict[str, object] | None:
    """The ``storage.recovery.unseparated_evidence`` field dict, or ``None`` to abstain."""
    value = parse_recovery_evidence_separated(posture)
    return None if value is None else {"recoverability_evidence_separated": value}


def parse_admin_members(admins_doc: object) -> list[str] | None:
    """The array's administrative accounts, as a sorted, de-duplicated list of stable identifiers
    (``admin:<name>``), or ``None`` to abstain when the document is not an administrators list. This is
    the RAW OBSERVED SET: the agent does NOT judge which are "unapproved" (it has no baseline); the
    control plane diffs this against the tenant's approved baseline. The read is bounded so a huge
    directory cannot make one collection unbounded."""
    if not isinstance(admins_doc, dict):
        return None
    admins = admins_doc.get("administrators")
    if not isinstance(admins, list):
        return None
    members: set[str] = set()
    for entry in admins:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name")
        if isinstance(name, str) and name:
            members.add(f"admin:{name}")
        if len(members) >= _MAX_ADMINS:
            break
    return sorted(members)


def admin_members_field(admins_doc: object) -> dict[str, object] | None:
    """The observed-set field the agent sends for ``storage.rbac.unapproved_admins``: the raw admin
    account identifiers, under the wire key the control plane's approved-policy normalizer reads
    (``observed_storage_admins``). Abstains (``None``) when the input is not an administrators list."""
    members = parse_admin_members(admins_doc)
    return None if members is None else {"observed_storage_admins": members}


def _verify_arg(verify: str | bool) -> ssl.SSLContext | str | bool:
    """Resolve the ``verify`` argument for httpx. ``False`` becomes an explicit no-verify SSL context
    because a storage array serves its own CA-signed (often self-signed) management certificate the
    agent has no store for; the connection is still TLS and the bearer token authenticates us to the
    array (the inverse trust from the ares control plane, where a bad certificate must fail)."""
    if verify is False:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    return verify


async def _get_json(
    target: str, token: str, path: str, *, timeout: float, verify: str | bool = False
) -> dict:
    """A read-only GET to one management-API path with the bearer token, returning the decoded JSON
    object (``{}`` when the body is not an object). GET only, no write. Raises on
    connect / auth / HTTP error, which the caller records as honest UNAVAILABLE."""
    url = f"https://{target}:{_API_PORT}{path}"
    async with httpx.AsyncClient(verify=_verify_arg(verify), timeout=timeout) as client:
        response = await client.get(
            url, headers={"Authorization": f"Bearer {token}", "Accept": "application/json"}
        )
        response.raise_for_status()
        body = response.json()
    return body if isinstance(body, dict) else {}


async def fetch_posture(
    target: str, token: str, *, timeout: float, verify: str | bool = False
) -> dict:
    """The array's management security-posture document, read read-only with the bearer token."""
    return await _get_json(target, token, _POSTURE_PATH, timeout=timeout, verify=verify)


async def fetch_administrators(
    target: str, token: str, *, timeout: float, verify: str | bool = False
) -> dict:
    """The array's administrative accounts document, read read-only with the bearer token."""
    return await _get_json(target, token, _ADMINS_PATH, timeout=timeout, verify=verify)
