"""Normalize an Active Directory domain's read-only LDAP into executable-control facts (the
credentialed identity tier).

Read-only: binds to a domain controller over LDAPS with a reader login from the agent's local vault
(``ldap_bind`` credential kind), runs a single scoped search, and parses the result. Like every
collector it ABSTAINS rather than invents: a bind that fails or a search the reader cannot run leaves
the control UNAVAILABLE.

Only controls a normal directory read can answer FP-free live here. ``identity.delegation.unconstrained``
counts principals flagged for unconstrained Kerberos delegation (a well-known critical AD finding),
EXCLUDING domain controllers, which hold that flag by design. The AD controls that need policy /
registry state (LDAP signing / channel binding), AD CS template ACLs, trust SID-filtering, or GPO
contents are NOT here: they are not a single directory attribute, so a collector for them would have
to guess.

The parse is PURE (userAccountControl values in, a count out); the networked bind+search is a separate
coroutine so the handler is testable by monkeypatching it.
"""

from __future__ import annotations

import asyncio
import ssl

import ldap3

from agent.credential_vault import Credential

SERVES = frozenset({"identity.delegation.unconstrained"})

# userAccountControl bit flags (Microsoft AD): a principal TRUSTED_FOR_DELEGATION (unconstrained) is
# the finding; a SERVER_TRUST_ACCOUNT (a domain controller) holds that flag legitimately and is
# excluded so a healthy domain's DCs are not a false positive.
_TRUSTED_FOR_DELEGATION = 0x80000  # 524288
_SERVER_TRUST_ACCOUNT = 0x2000  # 8192 (a domain controller)

_LDAPS_PORT = 636
# The server-side filter narrows the search to the (usually few) accounts with the delegation bit, so
# a huge directory does not stream every account; the DC exclusion is applied in the pure parser.
_DELEGATION_FILTER = f"(userAccountControl:1.2.840.113556.1.4.803:={_TRUSTED_FOR_DELEGATION})"
_MAX_PRINCIPALS = 5000


def serves(control_id: str) -> bool:
    """Whether this collector reads ``control_id`` from LDAP."""
    return control_id in SERVES


def parse_unconstrained_delegation_principals(uac_values: object) -> int | None:
    """The number of principals configured for UNCONSTRAINED Kerberos delegation, or ``None`` to
    abstain when the input is not a list of userAccountControl values. A principal counts when its
    userAccountControl has the TRUSTED_FOR_DELEGATION bit and is NOT a domain controller
    (SERVER_TRUST_ACCOUNT): a DC holds unconstrained delegation by design, so excluding it is what
    keeps a healthy domain from false-positiving."""
    if not isinstance(uac_values, list):
        return None
    count = 0
    for value in uac_values:
        if not isinstance(value, int):
            continue
        if (value & _TRUSTED_FOR_DELEGATION) and not (value & _SERVER_TRUST_ACCOUNT):
            count += 1
    return count


def unconstrained_delegation_field(uac_values: object) -> dict[str, object] | None:
    """The ``identity.delegation.unconstrained`` field dict from a list of userAccountControl values,
    or ``None`` to abstain."""
    count = parse_unconstrained_delegation_principals(uac_values)
    return None if count is None else {"unconstrained_delegation_principals": count}


def _tls() -> ldap3.Tls:
    """A TLS config that ENCRYPTS the LDAPS session but does not verify the DC certificate: a domain
    controller serves its own CA-signed (often internal) certificate, which the agent has no store
    for. The session is still TLS, so the bind password never crosses the wire in the clear. The
    inverse of the ares control plane, where a bad certificate must fail; mirrors the kube/db tiers."""
    return ldap3.Tls(validate=ssl.CERT_NONE)


def _query_delegation_uac(host: str, port: int, credential: Credential, timeout: float) -> list[int]:
    """Bind to the DC over LDAPS, search for the delegation-flagged principals, and return their
    userAccountControl values. Synchronous (ldap3 is), so the caller runs it in a thread. Read-only:
    one bind, one scoped search, then unbind."""
    server = ldap3.Server(
        host,
        port=port,
        use_ssl=True,
        tls=_tls(),
        get_info=ldap3.DSA,
        connect_timeout=timeout,
    )
    connection = ldap3.Connection(
        server,
        user=credential.username,
        password=credential.secret,
        auto_bind=True,
        receive_timeout=timeout,
    )
    try:
        base = ""
        if server.info and server.info.other:
            contexts = server.info.other.get("defaultNamingContext") or server.info.naming_contexts
            if contexts:
                base = str(contexts[0])
        if not base:
            raise ldap3.core.exceptions.LDAPException("no defaultNamingContext on the directory")
        connection.search(
            base,
            _DELEGATION_FILTER,
            attributes=["userAccountControl"],
            size_limit=_MAX_PRINCIPALS,
        )
        # ldap3 returns userAccountControl as a STRING when the server's schema is not loaded (the
        # common case with get_info=DSA), so coerce to int here; a value that is not an integer is
        # skipped. This normalization is why the pure parser can require ints.
        values: list[int] = []
        for entry in connection.entries:
            uac = entry.userAccountControl.value
            try:
                values.append(int(uac))
            except (TypeError, ValueError):
                continue
        return values
    finally:
        connection.unbind()


async def fetch_delegation_uac(
    host: str, credential: Credential, *, timeout: float, port: int = _LDAPS_PORT
) -> list[int]:
    """The userAccountControl values of the delegation-flagged principals, read over LDAPS. Runs the
    synchronous ldap3 bind+search in a thread so the event loop is not blocked. Raises on
    bind/search failure, which the caller records as honest UNAVAILABLE."""
    return await asyncio.to_thread(_query_delegation_uac, host, port, credential, timeout)
