"""Normalize a PostgreSQL instance's read-only catalog into executable-control facts (the credentialed
database-query tier).

A step beyond the config-read database tier (:mod:`database_host`): some database controls need a
privileged read-only SQL session, not a file. This tier opens ONE read-only connection with a reader
login from the agent's local vault (``db_login`` credential kind) over TLS, runs a single FIXED
catalog query (no arbitrary SQL, no customer-record sampling), and parses the result. Like every
collector it ABSTAINS rather than invents: a connection that fails, or a query the reader cannot run,
leaves the control UNAVAILABLE rather than guessing.

PostgreSQL only, via pg8000 (pure-Python, so the Alpine image needs no build toolchain). The query is
synchronous; it runs in a thread so the agent event loop is not blocked.
"""

from __future__ import annotations

import asyncio
import ssl

import pg8000.native

from agent.credential_vault import Credential

SERVES = frozenset({"database.extension.dangerous_enabled"})

# Extensions whose mere presence confers code execution, server-file access, or arbitrary outbound
# connections from inside the database: the untrusted procedural languages and the foreign-data /
# dblink / adminpack family. Their presence IS the finding this control asks for; a trusted extension
# (plpgsql, pgcrypto, uuid-ossp, ...) is not counted, so a stock database does not false-positive.
_DANGEROUS_EXTENSIONS = frozenset(
    {
        "plpythonu",
        "plpython2u",
        "plpython3u",
        "plperlu",
        "pltclu",
        "plr",
        "dblink",
        "postgres_fdw",
        "file_fdw",
        "adminpack",
    }
)

_DEFAULT_PORT = 5432
_DEFAULT_DATABASE = "postgres"
# A single fixed read-only catalog query: the installed-extension list. No arbitrary SQL ever.
_EXTENSIONS_QUERY = "SELECT extname FROM pg_extension"


def serves(control_id: str) -> bool:
    """Whether this collector reads ``control_id`` from a database SQL session."""
    return control_id in SERVES


def parse_dangerous_extensions(extension_names: object) -> int | None:
    """The number of installed extensions in the dangerous set, or ``None`` to abstain when the input
    is not a list of names."""
    if not isinstance(extension_names, list):
        return None
    return sum(
        1
        for name in extension_names
        if isinstance(name, str) and name.lower() in _DANGEROUS_EXTENSIONS
    )


def dangerous_extensions_field(extension_names: object) -> dict[str, object] | None:
    """The ``database.extension.dangerous_enabled`` field dict from an extension-name list, or ``None``
    to abstain."""
    count = parse_dangerous_extensions(extension_names)
    return None if count is None else {"dangerous_extensions_enabled": count}


def _tls_context() -> ssl.SSLContext:
    """A TLS context that ENCRYPTS the database session but does not verify the server certificate: a
    database commonly serves its own self-signed certificate, which the agent has no store for. The
    session is still TLS, so the reader password never crosses the wire in the clear. This is the
    inverse of the ares control plane, where a bad certificate must fail; it mirrors the kube tier."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def _query_extension_names(
    host: str, port: int, credential: Credential, database: str, timeout: float
) -> list[str]:
    """Open ONE read-only TLS connection, run the fixed extension query, and return the names.
    Synchronous (pg8000 is), so the caller runs it in a thread."""
    connection = pg8000.native.Connection(
        user=credential.username,
        password=credential.secret,
        host=host,
        port=port,
        database=database,
        ssl_context=_tls_context(),
        timeout=timeout,
    )
    try:
        rows = connection.run(_EXTENSIONS_QUERY)
        return [row[0] for row in rows if row and isinstance(row[0], str)]
    finally:
        connection.close()


async def fetch_extension_names(
    host: str,
    credential: Credential,
    *,
    timeout: float,
    port: int = _DEFAULT_PORT,
    database: str = _DEFAULT_DATABASE,
) -> list[str]:
    """The installed-extension names from the target database, read over TLS. Runs the synchronous
    pg8000 query in a thread so the event loop is not blocked. Raises on connect/auth/query failure,
    which the caller records as honest UNAVAILABLE."""
    return await asyncio.to_thread(
        _query_extension_names, host, port, credential, database, timeout
    )
