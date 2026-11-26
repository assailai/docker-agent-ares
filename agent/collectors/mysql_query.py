"""Normalize a MySQL/MariaDB instance's account list into executable-control facts (the MySQL half of
the credentialed database-query tier).

Read-only: opens ONE connection with a reader login from the agent's local vault (``mysql_login``
credential kind) over TLS, runs a single FIXED catalog query (the account list), and parses it. Like
every collector it ABSTAINS rather than invents: a connection that fails, or a query the reader cannot
run, leaves the control UNAVAILABLE.

PostgreSQL's equivalent controls live in :mod:`db_query`; this is MySQL/MariaDB, via PyMySQL (the
pure-Python driver). Only the unambiguous finding lives here: an ANONYMOUS account (empty user name),
which permits login with no identity. A "default well-known account" check is deliberately not here,
because distinguishing a legitimate renamed-admin from a default is not false-positive-free.
"""

from __future__ import annotations

import asyncio
import ssl

import pymysql

from agent.credential_vault import Credential

SERVES = frozenset({"database.auth.default_accounts"})

_DEFAULT_PORT = 3306
# A single fixed read-only catalog query: the account list. No arbitrary SQL ever.
_USERS_QUERY = "SELECT User FROM mysql.user"


def serves(control_id: str) -> bool:
    """Whether this collector reads ``control_id`` from a MySQL/MariaDB session."""
    return control_id in SERVES


def parse_anonymous_accounts(usernames: object) -> int | None:
    """The number of ANONYMOUS accounts (an empty user name, which permits login with no identity), or
    ``None`` to abstain when the input is not a list of user names. A named system account
    (``mariadb.sys``, ``mysql.session``) is not anonymous and is not counted."""
    if not isinstance(usernames, list):
        return None
    return sum(1 for name in usernames if isinstance(name, str) and name == "")


def default_accounts_field(usernames: object) -> dict[str, object] | None:
    """The ``database.auth.default_accounts`` field dict from a list of user names, or ``None`` to
    abstain."""
    count = parse_anonymous_accounts(usernames)
    return None if count is None else {"default_or_anonymous_accounts": count}


def _tls_context() -> ssl.SSLContext:
    """A TLS context that ENCRYPTS the database session but does not verify the server certificate: a
    database commonly serves its own self-signed certificate, which the agent has no store for. The
    session is still TLS, so the reader password never crosses the wire in the clear. Mirrors the other
    tiers."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def _query_usernames(host: str, port: int, credential: Credential, timeout: float) -> list[str]:
    """Open ONE read-only TLS connection, run the fixed account query, and return the user names.
    Synchronous (PyMySQL is), so the caller runs it in a thread."""
    connection = pymysql.connect(
        host=host,
        port=port,
        user=credential.username,
        password=credential.secret,
        ssl=_tls_context(),
        connect_timeout=int(timeout),
        read_timeout=int(timeout),
    )
    try:
        with connection.cursor() as cursor:
            cursor.execute(_USERS_QUERY)
            return [row[0] for row in cursor.fetchall() if isinstance(row[0], str)]
    finally:
        connection.close()


async def fetch_usernames(
    host: str, credential: Credential, *, timeout: float, port: int = _DEFAULT_PORT
) -> list[str]:
    """The account user names from the target database, read over TLS. Runs the synchronous PyMySQL
    query in a thread so the event loop is not blocked. Raises on connect/auth/query failure, which the
    caller records as honest UNAVAILABLE."""
    return await asyncio.to_thread(_query_usernames, host, port, credential, timeout)
