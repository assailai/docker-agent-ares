"""Normalize a vCenter/ESXi environment's read-only inventory into executable-control facts (the
credentialed virtualization tier).

Read-only: logs in to the management endpoint over TLS with a reader login from the agent's local
vault (``vsphere_login`` credential kind), reads a property off each host (the ESXi lockdown mode),
and parses it. Like every collector it ABSTAINS rather than invents: a login that fails or an
inventory it cannot read leaves the control UNAVAILABLE.

Only a property a read-only session exposes lives here. The controls that need SSO/MFA policy, admin
permission graphs, datastore encryption state, or drift reconciliation are NOT a single inventory
property and stay DESIGNED.

The parse is PURE (lockdown-mode strings in, a bool out); the networked SOAP login+read is a separate
coroutine so the handler is testable by monkeypatching it.
"""

from __future__ import annotations

import asyncio
import ssl

from pyVim.connect import Disconnect, SmartConnect
from pyVmomi import vim

from agent.credential_vault import Credential

SERVES = frozenset({"virtualization.host.lockdown_disabled"})

# The ESXi lockdown mode that means lockdown is OFF; "lockdownNormal" / "lockdownStrict" mean it is on.
_LOCKDOWN_DISABLED = "lockdownDisabled"
_DEFAULT_PORT = 443


def serves(control_id: str) -> bool:
    """Whether this collector reads ``control_id`` from the vSphere management endpoint."""
    return control_id in SERVES


def parse_host_lockdown_enabled(lockdown_modes: object) -> bool | None:
    """Whether host lockdown is enabled across the environment (EVERY host in a mode other than
    ``lockdownDisabled``), or ``None`` to abstain when there are no host readings. A single host with
    lockdown disabled makes the posture "not enabled" (a finding), because lockdown should be on
    everywhere; reporting enabled only when all hosts have it is the safe direction (never a false
    clean while one host is exposed)."""
    if not isinstance(lockdown_modes, list):
        return None
    modes = [mode for mode in lockdown_modes if isinstance(mode, str) and mode]
    if not modes:
        return None
    return all(mode != _LOCKDOWN_DISABLED for mode in modes)


def host_lockdown_field(lockdown_modes: object) -> dict[str, object] | None:
    """The ``virtualization.host.lockdown_disabled`` field dict from a list of host lockdown modes, or
    ``None`` to abstain."""
    enabled = parse_host_lockdown_enabled(lockdown_modes)
    return None if enabled is None else {"host_lockdown_mode_enabled": enabled}


def _tls_context() -> ssl.SSLContext:
    """A TLS context that ENCRYPTS the vCenter session but does not verify the certificate: a vCenter
    serves its own internal certificate, which the agent has no store for. The session is still TLS,
    so the reader password never crosses the wire in the clear. Mirrors the kube/db/ldap tiers."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def _query_host_lockdown_modes(
    host: str, port: int, credential: Credential, timeout: float
) -> list[str]:
    """Log in over TLS, read every host's lockdown mode, and return the modes. Synchronous (pyvmomi
    is), so the caller runs it in a thread. Read-only: a property read, no reconfigure."""
    service_instance = SmartConnect(
        host=host,
        port=port,
        user=credential.username,
        pwd=credential.secret,
        sslContext=_tls_context(),
        connectionPoolTimeout=int(timeout),
    )
    try:
        content = service_instance.RetrieveContent()
        view = content.viewManager.CreateContainerView(
            content.rootFolder, [vim.HostSystem], True
        )
        try:
            modes: list[str] = []
            for host_system in view.view:
                config = host_system.config
                if config is not None and config.lockdownMode is not None:
                    modes.append(str(config.lockdownMode))
            return modes
        finally:
            view.Destroy()
    finally:
        Disconnect(service_instance)


async def fetch_host_lockdown_modes(
    host: str, credential: Credential, *, timeout: float, port: int = _DEFAULT_PORT
) -> list[str]:
    """Every host's ESXi lockdown mode, read over TLS. Runs the synchronous pyvmomi login+read in a
    thread so the event loop is not blocked. Raises on login/read failure, which the caller records as
    honest UNAVAILABLE."""
    return await asyncio.to_thread(_query_host_lockdown_modes, host, port, credential, timeout)
