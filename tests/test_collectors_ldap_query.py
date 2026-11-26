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


# ── inactive privileged principals (identity.stale.privileged_principals) ──────────────────────────
from datetime import UTC, datetime, timedelta  # noqa: E402

_NOW = datetime(2026, 11, 26, tzinfo=UTC)


def test_counts_only_privileged_principals_inactive_beyond_the_threshold() -> None:
    values = [
        _NOW - timedelta(days=200),  # stale -> counts
        _NOW - timedelta(days=30),  # recently active -> does not count
        None,  # never logged in -> NOT counted (absence is not inactivity)
        _NOW - timedelta(days=91),  # just past the 90-day threshold -> counts
    ]
    assert ldap_query.parse_inactive_privileged(values, _NOW) == 2


def test_never_logged_in_privileged_account_is_not_a_false_positive() -> None:
    assert ldap_query.parse_inactive_privileged([None, 0], _NOW) == 0


def test_inactive_privileged_accepts_filetime_integers() -> None:
    # a FILETIME for 2020-01-01 (well past the threshold) counts; 0 (unset) does not.
    old_ft = int((datetime(2020, 1, 1, tzinfo=UTC) - datetime(1601, 1, 1, tzinfo=UTC)).total_seconds() * 10_000_000)
    assert ldap_query.parse_inactive_privileged([old_ft, 0], _NOW) == 1


def test_inactive_privileged_abstains_on_non_list() -> None:
    assert ldap_query.parse_inactive_privileged("nope", _NOW) is None
    assert ldap_query.parse_inactive_privileged(None, _NOW) is None


def test_inactive_privileged_field_and_serves() -> None:
    assert ldap_query.serves("identity.stale.privileged_principals") is True
    assert ldap_query.inactive_privileged_field([_NOW - timedelta(days=120)], _NOW) == {
        "inactive_privileged_principals": 1
    }
    assert ldap_query.inactive_privileged_field("nope", _NOW) is None


# ── domain replication rights (identity.replication.unapproved) ────────────────────────────────────
import struct as _struct  # noqa: E402
import uuid as _uuid  # noqa: E402

_REPL_GUID = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
_OTHER_GUID = "00000000-0000-0000-0000-000000000000"


def _ace(guid_str: str, sid_subs: list[int]) -> bytes:
    guid = _uuid.UUID(guid_str).bytes_le
    sid = bytes([1, len(sid_subs)]) + (5).to_bytes(6, "big") + b"".join(
        s.to_bytes(4, "little") for s in sid_subs
    )
    body = _struct.pack("<I", 0x100) + _struct.pack("<I", 0x1) + guid + sid  # mask, flags(OBJ), guid, sid
    return bytes([0x05, 0x00]) + _struct.pack("<H", 4 + len(body)) + body


def _make_sd(aces: list[bytes]) -> bytes:
    acl_body = b"".join(aces)
    acl = (
        bytes([4, 0])
        + _struct.pack("<H", 8 + len(acl_body))
        + _struct.pack("<H", len(aces))
        + _struct.pack("<H", 0)
        + acl_body
    )
    header = bytes([1, 0]) + _struct.pack("<H", 0x8004) + _struct.pack("<I", 0) * 3 + _struct.pack("<I", 20)
    return header + acl


def test_replication_trustees_detects_the_replication_right() -> None:
    sd = _make_sd([_ace(_REPL_GUID, [21, 100, 200, 300, 1105])])
    assert ldap_query.parse_replication_trustees(sd) == ["S-1-5-21-100-200-300-1105"]


def test_non_replication_ace_is_ignored() -> None:
    sd = _make_sd([_ace(_OTHER_GUID, [32, 544])])
    assert ldap_query.parse_replication_trustees(sd) == []


def test_replication_collects_only_the_replication_aces_and_dedups() -> None:
    sd = _make_sd([_ace(_OTHER_GUID, [1]), _ace(_REPL_GUID, [5, 9]), _ace(_REPL_GUID, [5, 9])])
    assert ldap_query.parse_replication_trustees(sd) == ["S-1-5-5-9"]


def test_replication_abstains_on_garbage() -> None:
    assert ldap_query.parse_replication_trustees(b"too short") is None
    assert ldap_query.parse_replication_trustees("not bytes") is None
    assert ldap_query.parse_replication_trustees(None) is None


def test_replication_field_served_and_baseline() -> None:
    assert ldap_query.serves("identity.replication.unapproved") is True
    assert "identity.replication.unapproved" in ldap_query.BASELINE_CONTROLS
    sd = _make_sd([_ace(_REPL_GUID, [21, 1, 2, 3, 512])])
    assert ldap_query.replication_trustees_field(sd) == {
        "observed_replication_principals": ["S-1-5-21-1-2-3-512"]
    }
    assert ldap_query.replication_trustees_field(b"x") is None
