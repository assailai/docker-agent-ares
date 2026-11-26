"""The database host collector normalizes a PostgreSQL server's on-disk config (``postgresql.conf``,
``pg_hba.conf``) into the host-readable ``database.*`` facts: DDL auditing, listener restriction, and
whether clients must use TLS, abstaining whenever the file does not carry the setting."""

from __future__ import annotations

from pathlib import Path

from agent.collectors import database_host

_FIX = Path(__file__).with_name("fixtures")


# ── postgresql.conf (audit logging) ───────────────────────────────────────────────────────────────
def test_ddl_logging_reads_auditing_on() -> None:
    conf = (_FIX / "postgresql_conf_audit_on.txt").read_text()
    assert database_host.parse_db_audit_logging_enabled(conf) is True


def test_log_statement_none_reads_auditing_off() -> None:
    conf = (_FIX / "postgresql_conf_audit_off.txt").read_text()
    assert database_host.parse_db_audit_logging_enabled(conf) is False


def test_pgaudit_preload_reads_auditing_on() -> None:
    conf = "shared_preload_libraries = 'pg_stat_statements,pgaudit'\nmax_connections = 100\n"
    assert database_host.parse_db_audit_logging_enabled(conf) is True


def test_audit_abstains_when_unset_or_not_a_pg_conf() -> None:
    # A real postgresql.conf that does not set log_statement abstains (the effective value may come
    # from ALTER SYSTEM / a default this file read cannot see), and unrelated text abstains too.
    assert database_host.parse_db_audit_logging_enabled("listen_addresses = 'localhost'\n") is None
    assert database_host.parse_db_audit_logging_enabled("hello world\n") is None


# ── pg_hba.conf (listener restriction + client TLS) ───────────────────────────────────────────────
def test_open_pg_hba_is_unrestricted_and_plaintext_capable() -> None:
    hba = (_FIX / "pg_hba_open.txt").read_text()
    # An all-addresses `host` entry: listener is not restricted, and TLS is not required.
    assert database_host.parse_db_listener_unrestricted(hba) is False
    assert database_host.parse_db_client_tls_required(hba) is False


def test_restricted_hostssl_pg_hba_passes_both() -> None:
    hba = (_FIX / "pg_hba_restricted.txt").read_text()
    # Specific networks over hostssl only: restricted, and TLS required.
    assert database_host.parse_db_listener_unrestricted(hba) is True
    assert database_host.parse_db_client_tls_required(hba) is True


def test_old_netmask_all_addresses_form_is_open() -> None:
    assert (
        database_host.parse_db_listener_unrestricted("host all all 0.0.0.0 0.0.0.0 md5\n") is False
    )


def test_stock_postgres_all_keyword_address_is_open() -> None:
    # The stock PostgreSQL image ships `host all all all scram-sha-256`: the fourth token is the
    # `all` ADDRESS keyword (every host), the most common open-postgres config. It must read
    # not-restricted, and `host` permits plaintext so TLS is not required.
    line = "host all all all scram-sha-256\n"
    assert database_host.parse_db_listener_unrestricted(line) is False
    assert database_host.parse_db_client_tls_required(line) is False


def test_hostnossl_entry_means_tls_not_required() -> None:
    assert database_host.parse_db_client_tls_required("hostnossl all all 10.0.0.0/24 md5\n") is False


def test_socket_only_pg_hba_abstains() -> None:
    # Only `local` (unix-socket) entries: no TCP listener to judge, so abstain on both.
    socket_only = "local all all peer\n"
    assert database_host.parse_db_listener_unrestricted(socket_only) is None
    assert database_host.parse_db_client_tls_required(socket_only) is None
    assert database_host.parse_db_listener_unrestricted("not a pg_hba file\n") is None


# ── my.cnf (MySQL / MariaDB) ──────────────────────────────────────────────────────────────────────
def test_mysql_require_secure_transport_on_is_tls_required() -> None:
    assert (
        database_host.parse_mysql_client_tls_required("[mysqld]\nrequire_secure_transport = ON\n")
        is True
    )
    assert (
        database_host.parse_mysql_client_tls_required("[mysqld]\nrequire_secure_transport = OFF\n")
        is False
    )


def test_mysql_bind_all_interfaces_is_unrestricted() -> None:
    assert database_host.parse_mysql_listener_unrestricted("[mysqld]\nbind-address = 0.0.0.0\n") is False
    assert database_host.parse_mysql_listener_unrestricted("[mysqld]\nbind-address = 127.0.0.1\n") is True
    # skip-networking disables TCP entirely: the listener is not network-reachable (restricted).
    assert database_host.parse_mysql_listener_unrestricted("[mysqld]\nskip-networking\n") is True


def test_mysql_abstains_outside_mysqld_section_or_when_absent() -> None:
    # A bind-address in [client] is a tool default, not the server posture: abstain.
    assert database_host.parse_mysql_listener_unrestricted("[client]\nbind-address = 0.0.0.0\n") is None
    assert database_host.parse_mysql_listener_unrestricted("[mysqld]\nmax_connections = 100\n") is None
    assert database_host.parse_mysql_client_tls_required("not a my.cnf\n") is None


def test_routing_and_collection() -> None:
    assert database_host.serves("database.audit.logging_disabled") is True
    assert database_host.serves("database.listener.unrestricted") is True
    assert database_host.serves("database.client.tls") is True
    assert database_host.serves("server.ssh.password") is False
    assert database_host.source_for("database.audit.logging_disabled") == database_host.SOURCE_PG_CONF
    # The shared controls read from BOTH engines' sources; whichever engine's config is present wins.
    assert database_host.sources_for_control("database.client.tls") == {
        database_host.SOURCE_PG_HBA,
        database_host.SOURCE_MY_CNF,
    }
    assert database_host.sources_for_control("database.audit.logging_disabled") == {
        database_host.SOURCE_PG_CONF
    }
    # Postgres host (only pg_hba present): answered by the pg parser.
    pg_only = {database_host.SOURCE_PG_HBA: "host all all 0.0.0.0/0 md5\n"}
    assert database_host.collect_control_fields(pg_only, "database.client.tls") == {
        "client_tls_required": False
    }
    # MySQL host (only my.cnf present): the pg parser abstains, the mysql parser answers.
    mysql_only = {database_host.SOURCE_MY_CNF: "[mysqld]\nrequire_secure_transport = ON\n"}
    assert database_host.collect_control_fields(mysql_only, "database.client.tls") == {
        "client_tls_required": True
    }
    assert database_host.collect_control_fields(pg_only, "net.management.telnet") is None


def test_mysql_at_rest_encryption_off_is_a_finding() -> None:
    from agent.collectors import database_host as dh
    assert dh.parse_mysql_encryption_at_rest("[mysqld]\ninnodb_encrypt_tables = OFF") is False
    assert dh.parse_mysql_encryption_at_rest("[mysqld]\ninnodb_encrypt_tables = ON") is True
    assert dh.parse_mysql_encryption_at_rest("[mysqld]\ninnodb_encrypt_tables = FORCE") is True
    # absent -> abstain (effective value may be SET PERSISTed)
    assert dh.parse_mysql_encryption_at_rest("[mysqld]\nbind-address = 0.0.0.0") is None
    assert dh.serves("database.encryption.at_rest_disabled") is True
    assert dh.collect_control_fields({"my_cnf": "[mysqld]\ninnodb_encrypt_tables = OFF"},
                                     "database.encryption.at_rest_disabled") == {"encryption_at_rest_enabled": False}
