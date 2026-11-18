"""Read a device's running-config over SSH, read-only, with the credential resolved locally.

The one place the agent opens an SSH session for a credentialed collection. It runs a single
read-only command (``show running-config``) and returns its text, bounded; it never enters config
mode, never writes, and the credential it uses came from the agent's local vault, so no secret left
the box to get here. ``known_hosts`` is disabled because a lab/cEOS fabric has no host-key registry;
host-key pinning is a hardening tracked for production collection.

Separated from the handler so the handler's logic (verify, normalise, sign) is testable by
monkeypatching :func:`collect_running_config`, which is the only function here that touches the
network.
"""

from __future__ import annotations

import asyncio

import asyncssh

from agent.credential_vault import Credential

_DEFAULT_COMMAND = "show running-config"


async def collect_running_config(
    host: str,
    credential: Credential,
    *,
    port: int = 22,
    timeout: float = 20.0,
    max_bytes: int = 2_000_000,
    command: str = _DEFAULT_COMMAND,
) -> str:
    """The device's running-config text, truncated to ``max_bytes``. Raises on connect/auth/timeout.

    Read-only: one show command, no config-mode, no write. The credential (password or key) is used
    only to authenticate this session and is never logged."""
    options: dict[str, object] = {
        "username": credential.username,
        "known_hosts": None,
        "connect_timeout": timeout,
    }
    if credential.kind == "ssh_password":
        options["password"] = credential.secret
    else:
        options["client_keys"] = [asyncssh.import_private_key(credential.secret)]

    async with asyncssh.connect(host, port=port, **options) as conn:
        result = await asyncio.wait_for(conn.run(command, check=False), timeout=timeout)
        text = result.stdout if isinstance(result.stdout, str) else ""
        return text[:max_bytes]
