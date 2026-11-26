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
from datetime import UTC, datetime, timedelta

import ldap3

from agent.credential_vault import Credential

DELEGATION_CONTROLS = frozenset({"identity.delegation.unconstrained"})
KRBTGT_CONTROLS = frozenset({"identity.krbtgt.rotation_stale"})
STALE_CONTROLS = frozenset({"identity.stale.privileged_principals"})
SERVES = DELEGATION_CONTROLS | KRBTGT_CONTROLS | STALE_CONTROLS

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
    # ldap3's connect_timeout / receive_timeout require an int; the collect path passes a float
    # budget (e.g. 20.0) and ldap3 then raises "required argument is not an integer" on the socket,
    # so every search fails UNAVAILABLE. Coerce to a whole number of seconds, at least 1.
    timeout = max(1, int(timeout))
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


# ── krbtgt password age ───────────────────────────────────────────────────────────────────────────
# The krbtgt account signs every Kerberos ticket, so a password not rotated in a long time means a
# stolen key (a golden-ticket secret) stays valid indefinitely. pwdLastSet is a Windows FILETIME:
# 100-nanosecond intervals since 1601-01-01 UTC. ldap3 may present it as that raw number (a string
# under get_info=DSA) or, schema-aware, as a datetime; the parser handles both.
_KRBTGT_FILTER = "(sAMAccountName=krbtgt)"
_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=UTC)


def parse_krbtgt_age_days(pwdlastset: object, now: datetime) -> int | None:
    """The age in whole days of the krbtgt password from its pwdLastSet, or ``None`` to abstain when
    the value is unset (``0`` means "must change at next logon", never a real age) or unreadable.
    ``now`` is injected so the computation is deterministic and testable."""
    if isinstance(pwdlastset, datetime):
        set_at = pwdlastset if pwdlastset.tzinfo else pwdlastset.replace(tzinfo=UTC)
    else:
        try:
            filetime = int(pwdlastset)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            return None
        if filetime <= 0:
            return None
        set_at = _FILETIME_EPOCH + timedelta(microseconds=filetime // 10)
    age = (now - set_at).days
    return age if age >= 0 else None


def krbtgt_age_field(pwdlastset: object, now: datetime) -> dict[str, object] | None:
    """The ``identity.krbtgt.rotation_stale`` field dict from a pwdLastSet value, or ``None`` to
    abstain."""
    age = parse_krbtgt_age_days(pwdlastset, now)
    return None if age is None else {"krbtgt_password_age_days": age}


def _query_krbtgt_pwdlastset(
    host: str, port: int, credential: Credential, timeout: float
) -> object:
    """Bind to the DC over LDAPS, read the krbtgt account's pwdLastSet, and return it as ldap3 presents
    it, or ``None`` when the account/attribute is absent. Synchronous (ldap3 is)."""
    # ldap3 needs an int timeout (see _query_delegation_uac); the collect budget is a float.
    timeout = max(1, int(timeout))
    server = ldap3.Server(
        host, port=port, use_ssl=True, tls=_tls(), get_info=ldap3.DSA, connect_timeout=timeout
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
        connection.search(base, _KRBTGT_FILTER, attributes=["pwdLastSet"])
        for entry in connection.entries:
            return entry.pwdLastSet.value
        return None
    finally:
        connection.unbind()


async def fetch_krbtgt_pwdlastset(
    host: str, credential: Credential, *, timeout: float, port: int = _LDAPS_PORT
) -> object:
    """The krbtgt account's pwdLastSet, read over LDAPS. Runs the synchronous ldap3 bind in a thread.
    Raises on bind/search failure, which the caller records as honest UNAVAILABLE."""
    return await asyncio.to_thread(_query_krbtgt_pwdlastset, host, port, credential, timeout)


# ── inactive privileged principals ────────────────────────────────────────────────────────────────
# A privileged credential nobody uses is a standing attack surface: it is unlikely to be monitored and
# its compromise is quiet. Privileged principals are identified by adminCount=1, which AD stamps on
# members of the protected admin groups (Domain/Enterprise/Schema Admins, Administrators) and their
# service/computer accounts. INACTIVE = lastLogonTimestamp present AND older than a documented fixed
# threshold (90 days, a standard benchmark, like the EOL floor); the agent applies it, so the field is
# already a count. A never-logged-in account (lastLogonTimestamp unset) is NOT counted: absence does
# not prove inactivity (it may be newly provisioned), so this never false-positives a fresh account.
_STALE_FILTER = "(adminCount=1)"
_STALE_THRESHOLD_DAYS = 90


def _filetime_to_datetime(value: object) -> datetime | None:
    """A Windows lastLogon/pwdLastSet value (a FILETIME integer, or a datetime ldap3 may present
    schema-aware) as a timezone-aware datetime, or ``None`` when unset (``0``) or unreadable."""
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    try:
        filetime = int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None
    if filetime <= 0:
        return None
    return _FILETIME_EPOCH + timedelta(microseconds=filetime // 10)


def parse_inactive_privileged(lastlogon_values: object, now: datetime) -> int | None:
    """The number of privileged principals whose last logon is older than the inactivity threshold, or
    ``None`` to abstain when the input is not a list. Only a principal with a PRESENT lastLogonTimestamp
    older than the threshold counts; a never-logged-in account (unset/0) is excluded (absence is not
    proof of inactivity). ``now`` is injected so the computation is deterministic and testable. An
    adminCount=1 straggler (membership cleared but the flag not reset) is a documented limitation."""
    if not isinstance(lastlogon_values, list):
        return None
    cutoff = now - timedelta(days=_STALE_THRESHOLD_DAYS)
    count = 0
    for value in lastlogon_values:
        last = _filetime_to_datetime(value)
        if last is not None and last < cutoff:
            count += 1
    return count


def inactive_privileged_field(lastlogon_values: object, now: datetime) -> dict[str, object] | None:
    """The ``identity.stale.privileged_principals`` field dict from a list of lastLogonTimestamp
    values, or ``None`` to abstain."""
    count = parse_inactive_privileged(lastlogon_values, now)
    return None if count is None else {"inactive_privileged_principals": count}


def _query_privileged_lastlogon(
    host: str, port: int, credential: Credential, timeout: float
) -> list[object]:
    """Bind to the DC over LDAPS, search for the privileged principals (adminCount=1), and return their
    lastLogonTimestamp values (``None`` for an account that has none). Synchronous (ldap3 is)."""
    timeout = max(1, int(timeout))  # ldap3 needs an int timeout (see _query_delegation_uac)
    server = ldap3.Server(
        host, port=port, use_ssl=True, tls=_tls(), get_info=ldap3.DSA, connect_timeout=timeout
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
            _STALE_FILTER,
            attributes=["lastLogonTimestamp"],
            size_limit=_MAX_PRINCIPALS,
        )
        values: list[object] = []
        for entry in connection.entries:
            attrs = entry.entry_attributes_as_dict
            found = attrs.get("lastLogonTimestamp")
            values.append(found[0] if found else None)
        return values
    finally:
        connection.unbind()


async def fetch_privileged_lastlogon(
    host: str, credential: Credential, *, timeout: float, port: int = _LDAPS_PORT
) -> list[object]:
    """The lastLogonTimestamp values of the privileged principals, read over LDAPS. Runs the
    synchronous ldap3 bind+search in a thread. Raises on bind/search failure (honest UNAVAILABLE)."""
    return await asyncio.to_thread(_query_privileged_lastlogon, host, port, credential, timeout)
