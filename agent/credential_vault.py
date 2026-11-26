"""The agent-local credential vault: secrets never leave the customer network (decision 11).

A credentialed COLLECT job carries only an OPAQUE ``credential_ref``; the control plane never holds
the password or key. This vault is where the agent resolves that reference to the actual credential,
on the box, so the secret is only ever read locally to open a read-only session to a device. The
store is a single JSON file written 0600 (the same protection the agent's bearer token gets in
``state.py``), and a reference the vault does not hold resolves to ``None`` so the collector reports
an honest UNAVAILABLE rather than guessing.

Deliberately small and read-mostly: the operator provisions the file (or a future control-plane flow
writes it through a local-only channel), and the agent only ever READS it. Nothing here sends a
secret anywhere, and the resolved credential is never logged.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

_FILE_MODE = 0o600


@dataclass(frozen=True, slots=True)
class Credential:
    """One resolved credential for a read-only collection. ``secret`` is a password, a private key, or
    a bearer token depending on ``kind``; it is held only in memory for the length of one collection
    and never logged or sent. ``username`` is the login for the SSH kinds and is unused (``""``) for a
    bearer-token kind, where the token alone authenticates."""

    # ssh_password | ssh_key | k8s_token | db_login | ldap_bind | vsphere_login | mysql_login |
    # s3_login (an object-storage access key: username=access key id, secret=secret access key; the
    # backup-repository posture tier reads an S3/object-lock backup repository with it)
    kind: str
    username: str
    secret: str

    def __repr__(self) -> str:  # never leak the secret through a repr in a log or traceback
        return f"Credential(kind={self.kind!r}, username={self.username!r}, secret=<redacted>)"


class CredentialVault:
    """Resolve an opaque ``credential_ref`` to a local :class:`Credential`, or ``None``.

    Backed by a 0600 JSON file mapping reference -> {kind, username, secret}. A malformed file, a
    missing file, or an unknown reference all resolve to ``None``: the collector then reports the
    control UNAVAILABLE rather than failing the whole task, exactly as a missing credential should
    read.
    """

    def __init__(self, path: Path) -> None:
        self._path = path

    def resolve(self, credential_ref: str) -> Credential | None:
        entry = self._entries().get(credential_ref)
        if not isinstance(entry, dict):
            return None
        kind, username, secret = entry.get("kind"), entry.get("username"), entry.get("secret")
        if kind not in (
            "ssh_password",
            "ssh_key",
            "k8s_token",
            "db_login",
            "ldap_bind",
            "vsphere_login",
            "mysql_login",
            "s3_login",
        ):
            return None
        # The SSH kinds need a login; a bearer token authenticates on its own, so its username is
        # optional and defaults to empty.
        if kind == "k8s_token":
            username = username if isinstance(username, str) else ""
        elif not isinstance(username, str):
            return None
        if not isinstance(secret, str) or not secret:
            return None
        return Credential(kind=kind, username=username, secret=secret)

    def has(self, credential_ref: str) -> bool:
        return self.resolve(credential_ref) is not None

    def _entries(self) -> dict:
        try:
            data = json.loads(self._path.read_text())
        except (OSError, ValueError):
            return {}
        return data if isinstance(data, dict) else {}


def write_vault(path: Path, entries: dict[str, dict]) -> None:
    """Write the vault file 0600 (owner read/write only), the same protection the bearer token gets.

    For provisioning/tests: the agent itself only ever reads the vault. Created private rather than
    written and then narrowed, so the secrets are never readable under the umask during the write."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    fd = os.open(path=tmp, flags=os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode=_FILE_MODE)
    with os.fdopen(fd, "w") as handle:
        os.fchmod(handle.fileno(), _FILE_MODE)
        handle.write(json.dumps(entries, indent=2))
    tmp.replace(path)
