"""The MySQL collector counts anonymous accounts (an empty user name, which permits login with no
identity) from the account list, and abstains when the input is not a list. The networked query
(fetch_usernames) is exercised live against a real MariaDB in the accuracy lab; these tests pin the
pure parsing."""

from __future__ import annotations

from agent.collectors import mysql_query


def test_counts_anonymous_accounts() -> None:
    # An empty user name is an anonymous account; named accounts (incl. system ones) are not.
    users = ["", "root", "ares_ro", "mariadb.sys"]
    assert mysql_query.parse_anonymous_accounts(users) == 1


def test_multiple_anonymous_accounts() -> None:
    assert mysql_query.parse_anonymous_accounts(["", ""]) == 2


def test_no_anonymous_accounts_reads_zero() -> None:
    assert mysql_query.parse_anonymous_accounts(["root", "app", "mariadb.sys"]) == 0
    assert mysql_query.parse_anonymous_accounts([]) == 0


def test_not_a_list_abstains() -> None:
    assert mysql_query.parse_anonymous_accounts("") is None
    assert mysql_query.parse_anonymous_accounts(None) is None


def test_non_string_entries_are_ignored() -> None:
    assert mysql_query.parse_anonymous_accounts(["", 123, None]) == 1


def test_serves_and_field_dict() -> None:
    assert mysql_query.serves("database.auth.default_accounts") is True
    assert mysql_query.serves("database.extension.dangerous_enabled") is False  # postgres tier
    assert mysql_query.serves("server.ssh.password") is False
    assert mysql_query.default_accounts_field(["", "root"]) == {"default_or_anonymous_accounts": 1}
    assert mysql_query.default_accounts_field("nope") is None
