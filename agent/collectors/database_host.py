"""Normalize a PostgreSQL server's on-disk configuration into executable-control facts (the
host-readable slice of the database cohort).

Read-only: reads ``postgresql.conf`` and ``pg_hba.conf`` over the same SSH transport the other host
collectors use, and parses them into the ``database.*`` fields a host's own config proves. Like every
host collector it ABSTAINS rather than invents: a setting the file does not carry is left out (the
EFFECTIVE value may come from ``ALTER SYSTEM`` / ``postgresql.auto.conf`` or a default, which a file
read cannot see), so the control stays NOT_ASSESSED rather than a false posture claim.

Only PostgreSQL, and only what its config files prove, lives here. The controls that need a
privileged SQL session (default/anonymous accounts, PUBLIC privileged grants, dangerous extensions,
at-rest encryption, replication-channel trust, read-path breadth) stay DESIGNED: a native database
login is a new transport and a new credential kind, deliberately out of scope for the read-only
host-config tier. MySQL/MariaDB (a different config grammar) is a future sibling of this module.
"""

from __future__ import annotations

# The evidence sources this collector reads, and the ssh_collect readers that produce them. PostgreSQL
# and MySQL/MariaDB are different engines with different config grammars, so each has its own source;
# a host runs at most one, and the other source simply reads empty (the engine's files are absent), so
# the engine-specific parser for the missing engine abstains and the present one answers.
SOURCE_PG_CONF = "pg_conf"
SOURCE_PG_HBA = "pg_hba"
SOURCE_MY_CNF = "my_cnf"

SOURCE_READERS = {
    SOURCE_PG_CONF: "collect_postgres_conf",
    SOURCE_PG_HBA: "collect_postgres_hba",
    SOURCE_MY_CNF: "collect_mysql_conf",
}

# A directive that marks the text as a genuine postgresql.conf, so unrelated bytes abstain rather than
# read a setting out of them.
_PG_CONF_MARKERS = (
    "listen_addresses",
    "max_connections",
    "shared_buffers",
    "shared_preload_libraries",
    "log_statement",
    "data_directory",
    "wal_level",
    "port",
)
# log_statement values that include DDL in the audit log. 'none' is the only setting that omits it.
_PG_LOG_STATEMENT_WITH_DDL = frozenset({"ddl", "mod", "all"})


def _pg_conf_values(pg_conf: str) -> dict[str, str]:
    """``postgresql.conf`` as a ``{key: value}`` map, keys lower-cased, quotes and inline comments
    stripped. Returns an empty map when the text is not a postgresql.conf (no recognized directive),
    which makes every field abstain."""
    values: dict[str, str] = {}
    for raw in pg_conf.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        key, sep, rest = line.partition("=")
        if not sep:
            continue
        key = key.strip().lower()
        # Strip an inline comment, then surrounding quotes. postgresql.conf values are simple scalars,
        # so a '#' after the value is a comment; a '#' inside a quoted value does not occur here.
        value = rest.split("#", 1)[0].strip().strip("'\"")
        if key:
            values[key] = value
    if not any(marker in values for marker in _PG_CONF_MARKERS):
        return {}
    return values


def parse_db_audit_logging_enabled(pg_conf: str) -> bool | None:
    """Whether privilege/DDL auditing is on (``log_statement`` logs DDL, or pgAudit is preloaded), or
    ``None`` to abstain when neither is set in the file. ``log_statement = none`` reads ``False`` (DDL
    not audited); ``ddl``/``mod``/``all`` or a ``pgaudit`` in ``shared_preload_libraries`` reads
    ``True``. Absent abstains rather than assuming the default, because the effective value can come
    from ``ALTER SYSTEM`` this file read cannot see."""
    values = _pg_conf_values(pg_conf)
    if "pgaudit" in values.get("shared_preload_libraries", "").lower():
        return True
    log_statement = values.get("log_statement")
    if log_statement is None:
        return None
    return log_statement.lower() in _PG_LOG_STATEMENT_WITH_DDL


# ── pg_hba.conf (the client authentication rules) ─────────────────────────────────────────────────
# A pg_hba line is `TYPE DATABASE USER ADDRESS METHOD`. These are the TCP connection types (``local``
# is a unix socket, not network-reachable, so it is not a listener/TLS concern).
_PG_HBA_TCP_TYPES = frozenset({"host", "hostssl", "hostnossl", "hostgssenc", "hostnogssenc"})
_PG_HBA_ALL_TYPES = _PG_HBA_TCP_TYPES | {"local"}
# TCP types that permit an UNENCRYPTED connection: `host` allows SSL or plaintext, `hostnossl` forbids
# SSL. An entry of either means a client can reach the server without TLS, so TLS is not required.
_PG_HBA_PLAINTEXT_TYPES = frozenset({"host", "hostnossl"})
# ADDRESS values that open an entry to every host (the all-addresses CIDRs).
_PG_HBA_OPEN_CIDRS = frozenset({"0.0.0.0/0", "::/0"})


def _pg_hba_rows(pg_hba: str) -> list[list[str]]:
    """``pg_hba.conf`` as a list of token-lists, keeping only lines whose first token is a known
    connection type. Returns an empty list when no such line is present, which marks the text as not a
    pg_hba.conf and makes every field abstain."""
    rows = [
        tokens
        for line in pg_hba.splitlines()
        if (stripped := line.strip())
        and not stripped.startswith("#")
        and (tokens := stripped.split())[0].lower() in _PG_HBA_ALL_TYPES
    ]
    return rows


def _row_opens_to_all(row: list[str]) -> bool:
    """Whether a TCP pg_hba row admits every host: the ``all`` ADDRESS keyword (what the stock
    PostgreSQL image ships as ``host all all all ...``), the all-addresses CIDRs ``0.0.0.0/0`` /
    ``::/0``, or the old netmask form ``0.0.0.0 0.0.0.0``. The ADDRESS is the fourth token
    (``TYPE DATABASE USER ADDRESS ...``), so matching ``all`` here is the address, not the
    database/user ``all`` in tokens 2 and 3."""
    address = row[3].lower() if len(row) > 3 else ""
    netmask = row[4] if len(row) > 4 else ""
    return (
        address == "all"
        or address in _PG_HBA_OPEN_CIDRS
        or (address == "0.0.0.0" and netmask == "0.0.0.0")
    )


def parse_db_listener_unrestricted(pg_hba: str) -> bool | None:
    """Whether the listener is restricted to intended clients, or ``None`` to abstain when pg_hba has
    no TCP entries (socket-only, nothing to judge). ``True`` (restricted) when every TCP entry names a
    specific host/network; ``False`` when any TCP entry admits every host (``0.0.0.0/0`` / ``::/0``).
    The field is the restricted sense, so an all-hosts entry reads ``False`` and becomes a finding."""
    tcp_rows = [row for row in _pg_hba_rows(pg_hba) if row[0].lower() in _PG_HBA_TCP_TYPES]
    if not tcp_rows:
        return None
    return not any(_row_opens_to_all(row) for row in tcp_rows)


def parse_db_client_tls_required(pg_hba: str) -> bool | None:
    """Whether clients must use TLS, or ``None`` to abstain when pg_hba has no TCP entries. ``True``
    when every TCP entry requires an encrypted connection (``hostssl`` / ``hostgssenc``); ``False``
    when any entry permits plaintext (``host`` / ``hostnossl``). The field is the required sense, so a
    plaintext-capable entry reads ``False`` and becomes a finding."""
    tcp_rows = [row for row in _pg_hba_rows(pg_hba) if row[0].lower() in _PG_HBA_TCP_TYPES]
    if not tcp_rows:
        return None
    return not any(row[0].lower() in _PG_HBA_PLAINTEXT_TYPES for row in tcp_rows)


# ── my.cnf (MySQL / MariaDB server config) ────────────────────────────────────────────────────────
# INI-style with a [mysqld] section. These controls read that section only ([client]/[mysql] are tool
# defaults, not the server posture). A host with no my.cnf reads empty and every MySQL parser abstains,
# so a PostgreSQL host is answered by the pg parsers instead (and vice versa).
_MYSQL_MARKER_SECTION = "[mysqld]"
_MYSQL_TRUEY = frozenset({"on", "1", "true", "yes"})
_MYSQL_ALL_INTERFACES = frozenset({"0.0.0.0", "::", "*"})


def _mysqld_values(my_cnf: str) -> dict[str, str]:
    """The ``[mysqld]`` section of my.cnf as a ``{key: value}`` map, keys lower-cased with ``-``
    normalized to ``_`` (my.cnf treats them alike), inline comments stripped, a bare flag mapping to
    the empty string. Returns an empty map when the text has no ``[mysqld]`` section, which makes every
    field abstain."""
    values: dict[str, str] = {}
    in_mysqld = False
    seen_mysqld = False
    for raw in my_cnf.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";", "!")):
            continue
        if line.startswith("[") and line.endswith("]"):
            in_mysqld = line.lower() == _MYSQL_MARKER_SECTION
            seen_mysqld = seen_mysqld or in_mysqld
            continue
        if not in_mysqld:
            continue
        key, sep, rest = line.partition("=")
        key = key.strip().lower().replace("-", "_")
        value = rest.split("#", 1)[0].strip().strip("'\"") if sep else ""
        if key:
            values[key] = value
    return values if seen_mysqld else {}


def parse_mysql_client_tls_required(my_cnf: str) -> bool | None:
    """Whether MySQL requires clients to use TLS (``require_secure_transport = ON``), or ``None`` to
    abstain when the directive is not in ``[mysqld]`` (the effective value may be SET PERSISTed, which
    this file read cannot see). The field is the required sense, so OFF reads ``False`` (a finding)."""
    value = _mysqld_values(my_cnf).get("require_secure_transport")
    return None if value is None else value.lower() in _MYSQL_TRUEY


def parse_mysql_listener_unrestricted(my_cnf: str) -> bool | None:
    """Whether the MySQL listener is restricted to intended clients, or ``None`` to abstain when
    neither ``bind-address`` nor ``skip-networking`` is set. ``skip_networking`` on (TCP disabled), or
    a ``bind-address`` that is not an all-interfaces address, reads ``True`` (restricted); an
    all-interfaces bind (``0.0.0.0`` / ``::`` / ``*``) reads ``False`` (open, a finding)."""
    values = _mysqld_values(my_cnf)
    skip = values.get("skip_networking")
    if skip is not None and skip.lower() in _MYSQL_TRUEY | {""}:
        return True
    bind = values.get("bind_address")
    if bind is None:
        return None
    return bind.lower() not in _MYSQL_ALL_INTERFACES


# One entry per (control_id, field): the ordered evidence sources it can be read from. A control that
# more than one engine expresses (listener, client TLS) lists each engine's (source, extractor); the
# first source that yields a value wins, and the others abstain because their engine's files are absent
# on this host. Audit logging is PostgreSQL-only here (MySQL's general_log is not a DDL audit).
_FIELD_EXTRACTORS: dict[tuple[str, str], list[tuple[str, object]]] = {
    ("database.audit.logging_disabled", "privilege_and_ddl_auditing_enabled"): [
        (SOURCE_PG_CONF, parse_db_audit_logging_enabled),
    ],
    ("database.listener.unrestricted", "listener_restricted_to_intended_clients"): [
        (SOURCE_PG_HBA, parse_db_listener_unrestricted),
        (SOURCE_MY_CNF, parse_mysql_listener_unrestricted),
    ],
    ("database.client.tls", "client_tls_required"): [
        (SOURCE_PG_HBA, parse_db_client_tls_required),
        (SOURCE_MY_CNF, parse_mysql_client_tls_required),
    ],
}


def _fields_for(control_id: str) -> list[tuple[str, list[tuple[str, object]]]]:
    """The ``(field, [(source, extractor), ...])`` entries this parser has for ``control_id``."""
    return [
        (field, source_extractors)
        for (ctrl, field), source_extractors in _FIELD_EXTRACTORS.items()
        if ctrl == control_id
    ]


def serves(control_id: str) -> bool:
    """Whether this collector reads the evidence for ``control_id``."""
    return bool(_fields_for(control_id))


def source_for(control_id: str) -> str | None:
    """The primary evidence source ``control_id`` is read from (the first of its candidate sources), or
    ``None`` if not served. Prefer :func:`sources_for_control` when a control reads more than one."""
    fields = _fields_for(control_id)
    return fields[0][1][0][0] if fields else None


def sources_for_control(control_id: str) -> set[str]:
    """Every evidence source ``control_id`` may be read from across its fields and engines, so the host
    tier reads each one the control needs (a control the stock engine expresses two ways reads both)."""
    return {source for _, source_extractors in _fields_for(control_id) for source, _ in source_extractors}


def collect_control_fields(sources: dict[str, str], control_id: str) -> dict[str, object] | None:
    """The typed field values this parser can read for ``control_id`` from the collected evidence, or
    ``None`` if it does not serve that control. For each field, the candidate sources are tried in
    order and the FIRST that yields a non-abstaining value wins (the other engine's files are absent on
    this host, so its parser abstains); a field all of whose sources abstain is left out."""
    supported = _fields_for(control_id)
    if not supported:
        return None
    fields: dict[str, object] = {}
    for field, source_extractors in supported:
        for source, extractor in source_extractors:
            value = extractor(sources.get(source, ""))
            if value is not None:
                fields[field] = value
                break
    return fields
