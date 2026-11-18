"""The agent-local credential vault resolves an opaque reference to a local credential, or None.

Secrets never leave the agent: the vault only ever READS a 0600 file, an unknown reference resolves
to None (so the collector reports UNAVAILABLE, not a guess), and the credential never leaks through a
repr.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

from agent.credential_vault import CredentialVault, write_vault


def test_resolves_a_known_reference(tmp_path: Path) -> None:
    path = tmp_path / "vault.json"
    write_vault(path, {"cred-ref-1": {"kind": "ssh_password", "username": "ops", "secret": "s3cr3t"}})
    cred = CredentialVault(path).resolve("cred-ref-1")
    assert cred is not None
    assert cred.kind == "ssh_password" and cred.username == "ops" and cred.secret == "s3cr3t"


def test_unknown_reference_is_none(tmp_path: Path) -> None:
    path = tmp_path / "vault.json"
    write_vault(path, {"cred-ref-1": {"kind": "ssh_key", "username": "ops", "secret": "KEY"}})
    vault = CredentialVault(path)
    assert vault.resolve("nope") is None
    assert vault.has("cred-ref-1") is True
    assert vault.has("nope") is False


def test_missing_or_malformed_file_is_none(tmp_path: Path) -> None:
    assert CredentialVault(tmp_path / "absent.json").resolve("x") is None
    bad = tmp_path / "bad.json"
    bad.write_text("not json")
    assert CredentialVault(bad).resolve("x") is None


def test_malformed_entry_is_none(tmp_path: Path) -> None:
    path = tmp_path / "vault.json"
    write_vault(
        path,
        {
            "bad-kind": {"kind": "telnet", "username": "u", "secret": "s"},
            "no-secret": {"kind": "ssh_password", "username": "u", "secret": ""},
            "not-a-dict": "nope",
        },
    )
    vault = CredentialVault(path)
    assert vault.resolve("bad-kind") is None
    assert vault.resolve("no-secret") is None
    assert vault.resolve("not-a-dict") is None


def test_vault_file_is_0600(tmp_path: Path) -> None:
    path = tmp_path / "vault.json"
    write_vault(path, {"r": {"kind": "ssh_password", "username": "u", "secret": "s"}})
    mode = stat.S_IMODE(os.stat(path).st_mode)
    assert mode == 0o600, oct(mode)


def test_repr_never_leaks_the_secret(tmp_path: Path) -> None:
    path = tmp_path / "vault.json"
    write_vault(path, {"r": {"kind": "ssh_password", "username": "u", "secret": "TOPSECRET"}})
    cred = CredentialVault(path).resolve("r")
    assert "TOPSECRET" not in repr(cred)
    assert "redacted" in repr(cred)
