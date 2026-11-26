"""The backup-repository collector reads each bucket's object-lock (immutability) and encryption
posture from an S3/object-lock store, and flags the repository when ANY bucket is mutable or
unencrypted. The networked read (fetch_bucket_posture) is exercised live against a real MinIO in the
accuracy lab; these tests pin the pure parsing."""

from __future__ import annotations

from agent.collectors import backup_collect

_ALL_PROTECTED = [
    {"bucket": "b1", "object_lock_enabled": True, "encryption_enabled": True},
    {"bucket": "b2", "object_lock_enabled": True, "encryption_enabled": True},
]
_ONE_MUTABLE = [
    {"bucket": "b1", "object_lock_enabled": True, "encryption_enabled": True},
    {"bucket": "b2", "object_lock_enabled": False, "encryption_enabled": False},
]


def test_all_protected_reads_immutable_and_encrypted() -> None:
    assert backup_collect.parse_repository_immutable(_ALL_PROTECTED) is True
    assert backup_collect.parse_backup_encrypted(_ALL_PROTECTED) is True


def test_any_mutable_or_unencrypted_bucket_is_a_finding() -> None:
    assert backup_collect.parse_repository_immutable(_ONE_MUTABLE) is False
    assert backup_collect.parse_backup_encrypted(_ONE_MUTABLE) is False


def test_abstains_on_no_buckets_or_bad_input() -> None:
    assert backup_collect.parse_repository_immutable([]) is None
    assert backup_collect.parse_backup_encrypted([]) is None
    assert backup_collect.parse_repository_immutable("nope") is None
    assert backup_collect.parse_backup_encrypted(None) is None


def test_serves_and_field_dicts() -> None:
    assert backup_collect.serves("backup.repository.immutable") is True
    assert backup_collect.serves("backup.data.unencrypted") is True
    assert backup_collect.serves("database.client.tls") is False
    assert backup_collect.repository_immutable_field(_ONE_MUTABLE) == {"immutability_enabled": False}
    assert backup_collect.backup_encrypted_field(_ALL_PROTECTED) == {
        "backup_encryption_enabled": True
    }
    assert backup_collect.repository_immutable_field([]) is None
