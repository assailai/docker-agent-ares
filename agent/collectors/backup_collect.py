"""Normalize a backup repository's object-storage posture into executable-control facts (the
repository slice of the backup cohort).

Read-only: opens an S3/object-lock client with an ``s3_login`` access key from the agent's local
vault, lists the repository buckets, and reads each bucket's object-lock (immutability) and encryption
(SSE) configuration. Like every collector it ABSTAINS rather than invents: a client that cannot
connect, or a repository with no buckets, leaves the control UNAVAILABLE.

Modern immutable backups (Veeam / Rubrik / Cohesity / restic / Kopia) write to an S3 object-lock
repository, so the repository-layer controls live at the object store: ``backup.repository.immutable``
(object-lock retention) and ``backup.data.unencrypted`` (bucket/server-side encryption). The
console-layer backup controls (admin MFA, clean-room recovery, admin-action logging, plane isolation,
coverage, restore-test evidence) need the backup PLATFORM's own management API, a separate transport,
and stay DESIGNED.
"""

from __future__ import annotations

import asyncio
import ssl

import urllib3
from minio import Minio

from agent.credential_vault import Credential

SERVES = frozenset({"backup.repository.immutable", "backup.data.unencrypted"})

_DEFAULT_PORT = 9000
# Bound the number of buckets read so a repository with thousands cannot make one collection unbounded
# (build-for-scale). A FALSE reading (a bucket without object-lock / encryption) is reached as soon as
# one is seen, so the bound only ever affects the all-good case, never a finding.
_MAX_BUCKETS = 1000


def serves(control_id: str) -> bool:
    """Whether this collector reads ``control_id`` from an object-storage backup repository."""
    return control_id in SERVES


def parse_repository_immutable(bucket_posture: object) -> bool | None:
    """Whether every backup bucket enforces object-lock retention (immutability), or ``None`` to
    abstain when the input is not a list of bucket postures or the repository has no buckets. ``True``
    when every bucket has object-lock enabled; ``False`` (a finding) when any bucket does not, because
    a single mutable repository bucket is where a ransomware actor deletes the backups."""
    if not isinstance(bucket_posture, list) or not bucket_posture:
        return None
    return all(
        isinstance(b, dict) and b.get("object_lock_enabled") is True for b in bucket_posture
    )


def parse_backup_encrypted(bucket_posture: object) -> bool | None:
    """Whether every backup bucket enforces server-side encryption, or ``None`` to abstain when the
    input is not a list of bucket postures or the repository has no buckets. ``True`` when every bucket
    has encryption configured; ``False`` (a finding) when any bucket does not."""
    if not isinstance(bucket_posture, list) or not bucket_posture:
        return None
    return all(isinstance(b, dict) and b.get("encryption_enabled") is True for b in bucket_posture)


def repository_immutable_field(bucket_posture: object) -> dict[str, object] | None:
    """The ``backup.repository.immutable`` field dict from a bucket-posture list, or ``None`` to
    abstain."""
    value = parse_repository_immutable(bucket_posture)
    return None if value is None else {"immutability_enabled": value}


def backup_encrypted_field(bucket_posture: object) -> dict[str, object] | None:
    """The ``backup.data.unencrypted`` field dict from a bucket-posture list, or ``None`` to
    abstain."""
    value = parse_backup_encrypted(bucket_posture)
    return None if value is None else {"backup_encryption_enabled": value}


def _unverified_http_client(timeout: float) -> urllib3.PoolManager:
    """An HTTPS pool manager that ENCRYPTS the S3 session but does not verify the endpoint certificate:
    an on-prem object store commonly serves its own self-signed certificate, which the agent has no
    store for. The session is still TLS, so the secret key never crosses the wire in the clear.
    Mirrors the other credentialed tiers (db/ldap/vsphere/kube), the inverse trust from the ares
    control plane where a bad certificate must fail."""
    return urllib3.PoolManager(
        cert_reqs=ssl.CERT_NONE,
        timeout=urllib3.Timeout(connect=timeout, read=timeout),
        retries=False,
    )


def _read_bucket_posture(host: str, port: int, credential: Credential, timeout: float) -> list[dict]:
    """Open ONE read-only S3 client, list the buckets, and read each bucket's object-lock + encryption
    configuration. Synchronous (minio is), so the caller runs it in a thread. Read-only: list +
    get-config calls only, never a put/delete."""
    client = Minio(
        f"{host}:{port}",
        access_key=credential.username,
        secret_key=credential.secret,
        secure=True,
        http_client=_unverified_http_client(timeout),
    )
    posture: list[dict] = []
    for bucket in client.list_buckets()[:_MAX_BUCKETS]:
        object_lock_enabled = False
        try:
            config = client.get_object_lock_config(bucket.name)
            # object-lock is enabled when a retention mode is configured on the bucket
            object_lock_enabled = getattr(config, "mode", None) is not None
        except Exception:  # noqa: BLE001 - "object lock not enabled" is an error we read as False
            object_lock_enabled = False
        encryption_enabled = False
        try:
            client.get_bucket_encryption(bucket.name)
            encryption_enabled = True
        except Exception:  # noqa: BLE001 - "no encryption configuration" is read as False
            encryption_enabled = False
        posture.append(
            {
                "bucket": bucket.name,
                "object_lock_enabled": object_lock_enabled,
                "encryption_enabled": encryption_enabled,
            }
        )
    return posture


async def fetch_bucket_posture(
    host: str, credential: Credential, *, timeout: float, port: int = _DEFAULT_PORT
) -> list[dict]:
    """The per-bucket object-lock + encryption posture of the backup repository, read over TLS. Runs
    the synchronous minio client in a thread so the event loop is not blocked. Raises on
    connect/auth/list failure, which the caller records as honest UNAVAILABLE."""
    return await asyncio.to_thread(_read_bucket_posture, host, port, credential, timeout)
