"""The identity (LDAP) collector counts principals configured for unconstrained Kerberos delegation
from their userAccountControl values, excluding domain controllers (which hold that flag by design),
and abstains when the input is not a list. The networked bind+search (fetch_delegation_uac) is
exercised live against a Samba AD domain controller in the accuracy lab; these tests pin the pure
bit-parsing."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from agent.collectors import ldap_query
from agent.credential_vault import Credential

# userAccountControl bit flags.
_NORMAL = 0x200  # NORMAL_ACCOUNT
_DELEGATION = 0x80000  # TRUSTED_FOR_DELEGATION (unconstrained)
_DC = 0x2000  # SERVER_TRUST_ACCOUNT (a domain controller)


def test_counts_non_dc_unconstrained_delegation() -> None:
    values = [_NORMAL | _DELEGATION, _NORMAL | _DELEGATION, _NORMAL]
    assert ldap_query.parse_unconstrained_delegation_principals(values) == 2


def test_domain_controllers_are_excluded() -> None:
    # A DC holds TRUSTED_FOR_DELEGATION by design: not a finding.
    values = [_DC | _DELEGATION, _DC | _DELEGATION]
    assert ldap_query.parse_unconstrained_delegation_principals(values) == 0


def test_a_healthy_domain_reads_zero() -> None:
    assert ldap_query.parse_unconstrained_delegation_principals([_NORMAL, _NORMAL]) == 0
    assert ldap_query.parse_unconstrained_delegation_principals([]) == 0


def test_mixed_domain_counts_only_non_dc_delegation() -> None:
    values = [_NORMAL | _DELEGATION, _DC | _DELEGATION, _NORMAL]
    assert ldap_query.parse_unconstrained_delegation_principals(values) == 1


def test_not_a_list_abstains() -> None:
    assert ldap_query.parse_unconstrained_delegation_principals(0x80000) is None
    assert ldap_query.parse_unconstrained_delegation_principals(None) is None


def test_non_int_entries_are_ignored() -> None:
    assert ldap_query.parse_unconstrained_delegation_principals([_NORMAL | _DELEGATION, "x", None]) == 1


def test_serves_and_field_dict() -> None:
    assert ldap_query.serves("identity.delegation.unconstrained") is True
    assert ldap_query.serves("identity.krbtgt.rotation_stale") is True
    assert ldap_query.serves("server.ssh.password") is False
    assert ldap_query.unconstrained_delegation_field([_NORMAL | _DELEGATION]) == {
        "unconstrained_delegation_principals": 1
    }
    assert ldap_query.unconstrained_delegation_field("nope") is None


# ── krbtgt password age ───────────────────────────────────────────────────────────────────────────
_EPOCH = datetime(1601, 1, 1, tzinfo=UTC)
_NOW = datetime(2026, 1, 1, tzinfo=UTC)


def _to_filetime(dt: datetime) -> int:
    return int((dt - _EPOCH).total_seconds() * 10_000_000)


def test_krbtgt_age_from_filetime_string() -> None:
    # ldap3 commonly returns pwdLastSet as a FILETIME string; a 200-day-old password reads 200.
    old = str(_to_filetime(_NOW - timedelta(days=200)))
    assert ldap_query.parse_krbtgt_age_days(old, _NOW) == 200


def test_krbtgt_age_from_datetime() -> None:
    # Schema-aware ldap3 may return a datetime; a 100-day-old password reads 100.
    assert ldap_query.parse_krbtgt_age_days(_NOW - timedelta(days=100), _NOW) == 100


def test_freshly_rotated_krbtgt_reads_low_age() -> None:
    assert ldap_query.parse_krbtgt_age_days(_to_filetime(_NOW - timedelta(days=3)), _NOW) == 3


def test_krbtgt_unset_or_unreadable_abstains() -> None:
    # pwdLastSet 0 means "must change at next logon", never a real age: abstain.
    assert ldap_query.parse_krbtgt_age_days(0, _NOW) is None
    assert ldap_query.parse_krbtgt_age_days("not-a-number", _NOW) is None
    assert ldap_query.parse_krbtgt_age_days(None, _NOW) is None


def test_krbtgt_age_field() -> None:
    old = _to_filetime(_NOW - timedelta(days=365))
    assert ldap_query.krbtgt_age_field(old, _NOW) == {"krbtgt_password_age_days": 365}
    assert ldap_query.krbtgt_age_field(0, _NOW) is None


def test_float_timeout_is_coerced_to_int_for_ldap3(monkeypatch) -> None:
    """ldap3's connect_timeout / receive_timeout require an int. The collect path passes a float
    budget (e.g. 20.0), which made every bind fail with "required argument is not an integer" and the
    identity tier report UNAVAILABLE. The query must coerce the timeout to a whole number of seconds.
    Regression for the live end-to-end run that surfaced it."""
    from agent.collectors import ldap_query

    seen: dict[str, object] = {}

    class _Server:
        def __init__(self, *a, **k):
            seen["server_connect_timeout"] = k.get("connect_timeout")
            self.info = None

    class _Conn:
        def __init__(self, *a, **k):
            seen["conn_receive_timeout"] = k.get("receive_timeout")

        def search(self, *a, **k):
            return None

        entries: list = []

        def unbind(self):
            return None

    monkeypatch.setattr(ldap_query.ldap3, "Server", _Server)
    monkeypatch.setattr(ldap_query.ldap3, "Connection", _Conn)
    # a float timeout (what the collect budget passes) must reach ldap3 as an int
    try:
        ldap_query._query_delegation_uac("dc", 636, _cred(), 20.0)
    except Exception:
        pass  # the stubbed directory has no naming context; we only assert the timeout type
    assert isinstance(seen["server_connect_timeout"], int)
    assert isinstance(seen["conn_receive_timeout"], int)


def _cred() -> Credential:
    return Credential(kind="ldap_bind", username="Administrator@LAB.LOCAL", secret="pw")
