"""The storage-management collector normalises an array's read-only management-API documents into the
``storage.*`` posture fields, and sends the RAW administrator set for the baseline-comparison control.
Every parser ABSTAINS (returns ``None``) when the document is not the shape it expects, so an
unreachable or unauthorized read leaves the control NOT_ASSESSED rather than inventing a posture."""

from __future__ import annotations

from agent.collectors import storage_mgmt


def _posture(
    *,
    tls: bool = True,
    mfa: bool = True,
    logging: bool = True,
    snapshot_protected: bool = True,
    immutability_bypass: bool = False,
    volume_encrypted: bool = True,
    untrusted_replication: int = 0,
    eol_components: int = 0,
    multipath_issues: int = 0,
    recovery_separated: bool = True,
) -> dict:
    """A full posture document. The defaults are the HARDENED array (no finding on any control); a
    test flips one field to the insecure value to assert that control's finding polarity."""
    return {
        "management_transport": {"tls_enforced": tls},
        "authentication": {"mfa_enforced": mfa},
        "audit": {"data_access_logging_enabled": logging},
        "snapshots": {"deletion_protection_enabled": snapshot_protected},
        "immutability": {"enabled": True, "privileged_bypass_possible": immutability_bypass},
        "volumes": {"encryption_enabled": volume_encrypted},
        "replication": {"unencrypted_or_untrusted_targets": untrusted_replication},
        "lifecycle": {"end_of_life_components": eol_components},
        "multipath": {"inconsistencies": multipath_issues},
        "recovery": {"evidence_separated": recovery_separated},
    }


# ── factual-absolute posture controls ─────────────────────────────────────────────────────────────
def test_management_encryption_reads_the_enforced_flag() -> None:
    assert storage_mgmt.parse_management_encryption_enforced(_posture(tls=True)) is True
    # tls_enforced False is the finding (plaintext management permitted).
    assert storage_mgmt.parse_management_encryption_enforced(_posture(tls=False)) is False


def test_admin_mfa_reads_the_enforced_flag() -> None:
    assert storage_mgmt.parse_admin_mfa_enforced(_posture(mfa=True)) is True
    assert storage_mgmt.parse_admin_mfa_enforced(_posture(mfa=False)) is False


def test_data_access_logging_reads_the_enabled_flag() -> None:
    assert storage_mgmt.parse_data_access_logging_enabled(_posture(logging=True)) is True
    assert storage_mgmt.parse_data_access_logging_enabled(_posture(logging=False)) is False


def test_snapshot_protection_reads_the_enabled_flag() -> None:
    assert storage_mgmt.parse_snapshot_deletion_protection(_posture(snapshot_protected=True)) is True
    assert storage_mgmt.parse_snapshot_deletion_protection(_posture(snapshot_protected=False)) is False


def test_immutability_bypass_has_the_opposite_polarity() -> None:
    # Here True is the finding (immutability bypassable), unlike the other posture fields.
    assert storage_mgmt.parse_immutability_bypass_possible(_posture(immutability_bypass=False)) is False
    assert storage_mgmt.parse_immutability_bypass_possible(_posture(immutability_bypass=True)) is True


def test_posture_parsers_abstain_on_missing_or_non_bool() -> None:
    # A missing section, a missing key, a non-bool value, and a non-dict document all abstain.
    assert storage_mgmt.parse_management_encryption_enforced({}) is None
    assert storage_mgmt.parse_admin_mfa_enforced({"authentication": {}}) is None
    assert storage_mgmt.parse_data_access_logging_enabled({"audit": {"data_access_logging_enabled": "yes"}}) is None
    assert storage_mgmt.parse_snapshot_deletion_protection("nope") is None
    assert storage_mgmt.parse_immutability_bypass_possible({"immutability": "nope"}) is None


def test_posture_field_dicts_and_abstain() -> None:
    p = _posture(tls=False, mfa=False, logging=False, snapshot_protected=False, immutability_bypass=True)
    assert storage_mgmt.management_encryption_field(p) == {"management_encryption_enforced": False}
    assert storage_mgmt.admin_mfa_field(p) == {"admin_mfa_enforced": False}
    assert storage_mgmt.data_access_logging_field(p) == {"data_access_logging_enabled": False}
    assert storage_mgmt.snapshot_protection_field(p) == {"snapshot_deletion_protection_enabled": False}
    assert storage_mgmt.immutability_bypass_field(p) == {"immutability_privileged_bypass_possible": True}
    assert storage_mgmt.management_encryption_field({}) is None
    assert storage_mgmt.admin_mfa_field({}) is None


# ── the five additional posture controls (same storage_mgmt kind) ─────────────────────────────────
def test_volume_encryption_reads_the_enabled_flag() -> None:
    assert storage_mgmt.parse_volume_encryption_enabled(_posture(volume_encrypted=True)) is True
    assert storage_mgmt.parse_volume_encryption_enabled(_posture(volume_encrypted=False)) is False


def test_recovery_evidence_reads_the_separated_flag() -> None:
    assert storage_mgmt.parse_recovery_evidence_separated(_posture(recovery_separated=True)) is True
    assert storage_mgmt.parse_recovery_evidence_separated(_posture(recovery_separated=False)) is False


def test_integer_count_fields_read_the_reported_count() -> None:
    p = _posture(untrusted_replication=2, eol_components=3, multipath_issues=1)
    assert storage_mgmt.parse_untrusted_replication_targets(p) == 2
    assert storage_mgmt.parse_end_of_life_components(p) == 3
    assert storage_mgmt.parse_multipath_inconsistencies(p) == 1
    clean = _posture()
    assert storage_mgmt.parse_untrusted_replication_targets(clean) == 0
    assert storage_mgmt.parse_end_of_life_components(clean) == 0
    assert storage_mgmt.parse_multipath_inconsistencies(clean) == 0


def test_integer_fields_reject_bool_and_negative_and_missing() -> None:
    # bool is an int subclass in Python; it must NOT read as a count.
    assert storage_mgmt.parse_untrusted_replication_targets({"replication": {"unencrypted_or_untrusted_targets": True}}) is None
    assert storage_mgmt.parse_end_of_life_components({"lifecycle": {"end_of_life_components": -1}}) is None
    assert storage_mgmt.parse_multipath_inconsistencies({"multipath": {}}) is None
    assert storage_mgmt.parse_untrusted_replication_targets("nope") is None


def test_additional_posture_field_dicts_and_abstain() -> None:
    p = _posture(
        volume_encrypted=False, untrusted_replication=1, eol_components=1,
        multipath_issues=1, recovery_separated=False,
    )
    assert storage_mgmt.volume_encryption_field(p) == {"volume_encryption_enabled": False}
    assert storage_mgmt.replication_untrusted_field(p) == {"unencrypted_or_untrusted_replication_targets": 1}
    assert storage_mgmt.lifecycle_firmware_field(p) == {"end_of_life_storage_components": 1}
    assert storage_mgmt.multipath_inconsistency_field(p) == {"multipath_or_zoning_inconsistencies": 1}
    assert storage_mgmt.recovery_evidence_field(p) == {"recoverability_evidence_separated": False}
    assert storage_mgmt.volume_encryption_field({}) is None
    assert storage_mgmt.lifecycle_firmware_field({}) is None


# ── baseline-comparison control (storage.rbac.unapproved_admins) ──────────────────────────────────
def _admins(*names: str) -> dict:
    return {"administrators": [{"name": n, "role": "storage_admin"} for n in names]}


def test_admin_members_lists_account_identifiers_sorted_and_deduped() -> None:
    doc = {
        "administrators": [
            {"name": "arrayadmin", "role": "storage_admin", "builtin": True},
            {"name": "rogue", "role": "storage_admin"},
            {"name": "arrayadmin", "role": "security_admin"},  # duplicate name
        ]
    }
    assert storage_mgmt.parse_admin_members(doc) == ["admin:arrayadmin", "admin:rogue"]


def test_admin_members_skips_malformed_entries() -> None:
    doc = {"administrators": [{"name": "ok"}, {"role": "no-name"}, "not-a-dict", {"name": ""}]}
    assert storage_mgmt.parse_admin_members(doc) == ["admin:ok"]


def test_admin_members_abstains_on_non_list() -> None:
    assert storage_mgmt.parse_admin_members({}) is None
    assert storage_mgmt.parse_admin_members({"administrators": "nope"}) is None
    assert storage_mgmt.parse_admin_members("nope") is None


def test_admin_members_field_uses_the_wire_key_and_abstains() -> None:
    assert storage_mgmt.admin_members_field(_admins("arrayadmin", "rogue")) == {
        "observed_storage_admins": ["admin:arrayadmin", "admin:rogue"]
    }
    assert storage_mgmt.admin_members_field({"administrators": "nope"}) is None


# ── serves() routing ──────────────────────────────────────────────────────────────────────────────
def test_serves_the_six_storage_mgmt_controls_only() -> None:
    for control in (
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
        "storage.rbac.unapproved_admins",
    ):
        assert storage_mgmt.serves(control) is True
    # The NFS config-read storage control belongs to the SSH host tier, not this management tier.
    assert storage_mgmt.serves("storage.nfs.wildcard_rw") is False
    assert storage_mgmt.serves("kubernetes.workload.privileged") is False


def test_the_baseline_control_is_the_only_rbac_member() -> None:
    assert storage_mgmt.RBAC_CONTROLS == frozenset({"storage.rbac.unapproved_admins"})
    assert "storage.rbac.unapproved_admins" not in storage_mgmt.POSTURE_CONTROLS
