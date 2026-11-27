"""The database-query collector counts dangerous PostgreSQL extensions from the installed-extension
list, where "dangerous" is a fixed set (untrusted procedural languages, dblink / foreign-data /
adminpack) whose presence confers code execution or server access, and abstains when the input is not
a list. The networked query (fetch_extension_names) is exercised live against a real postgres in the
accuracy lab; these tests pin the pure parsing."""

from __future__ import annotations

from agent.collectors import db_query


def test_counts_dangerous_extensions() -> None:
    assert db_query.parse_dangerous_extensions(["dblink", "plpgsql"]) == 1
    assert db_query.parse_dangerous_extensions(["plpython3u", "dblink", "postgres_fdw"]) == 3


def test_a_stock_database_with_only_trusted_extensions_reads_zero() -> None:
    assert db_query.parse_dangerous_extensions(["plpgsql", "pgcrypto", "uuid-ossp"]) == 0
    assert db_query.parse_dangerous_extensions([]) == 0


def test_extension_match_is_case_insensitive() -> None:
    assert db_query.parse_dangerous_extensions(["DBLINK", "PLPython3U"]) == 2


def test_not_a_list_abstains() -> None:
    assert db_query.parse_dangerous_extensions("dblink") is None
    assert db_query.parse_dangerous_extensions(None) is None
    assert db_query.parse_dangerous_extensions({"extname": "dblink"}) is None


def test_non_string_entries_are_ignored() -> None:
    assert db_query.parse_dangerous_extensions(["dblink", 123, None]) == 1


def test_serves_and_field_dict() -> None:
    assert db_query.serves("database.extension.dangerous_enabled") is True
    assert db_query.serves("database.client.tls") is False  # config-read tier, not this one
    assert db_query.serves("server.ssh.password") is False
    assert db_query.dangerous_extensions_field(["dblink", "plpgsql"]) == {
        "dangerous_extensions_enabled": 1
    }
    assert db_query.dangerous_extensions_field("nope") is None


def test_engine_eol_count_flags_below_the_supported_floor() -> None:
    from agent.collectors import db_query as dq
    assert dq.parse_engine_eol_count(120022) == 1   # PostgreSQL 12 -> EOL
    assert dq.parse_engine_eol_count(130010) == 1   # 13 -> EOL
    assert dq.parse_engine_eol_count(140008) == 0   # 14 -> supported
    assert dq.parse_engine_eol_count(170004) == 0   # 17 -> supported
    assert dq.parse_engine_eol_count("120022") == 1  # string form coerced
    assert dq.parse_engine_eol_count(0) is None
    assert dq.parse_engine_eol_count("nope") is None
    assert dq.serves("database.lifecycle.unsupported_engine") is True
    assert dq.engine_eol_field(120022) == {"end_of_life_engine_or_extensions": 1}
    assert dq.engine_eol_field(170004) == {"end_of_life_engine_or_extensions": 0}


# ── security settings drift (database.config.baseline_drift, a baseline-comparison control) ────────
def test_security_settings_field_encodes_name_value_pairs() -> None:
    settings = {"ssl": "off", "log_connections": "on", "password_encryption": "md5"}
    assert db_query.security_settings_field(settings) == {
        "observed_db_settings": ["log_connections=on", "password_encryption=md5", "ssl=off"]
    }


def test_security_settings_field_abstains_on_non_dict() -> None:
    assert db_query.security_settings_field(None) is None
    assert db_query.security_settings_field("nope") is None


def test_baseline_drift_served_and_baseline() -> None:
    assert db_query.serves("database.config.baseline_drift") is True
    assert "database.config.baseline_drift" in db_query.BASELINE_CONTROLS
    # a factual-absolute db control is NOT a baseline control.
    assert "database.extension.dangerous_enabled" not in db_query.BASELINE_CONTROLS


def test_monitored_settings_query_names_only_the_fixed_set() -> None:
    # the query is built from the fixed reference, so no injection surface and a stable scope.
    for name in db_query._MONITORED_SECURITY_SETTINGS:
        assert f"'{name}'" in db_query._SECURITY_SETTINGS_QUERY
