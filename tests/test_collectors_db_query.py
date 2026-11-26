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
