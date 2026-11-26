"""Read a device's running-config over SSH, read-only, with the credential resolved locally.

The one place the agent opens an SSH session for a credentialed collection. It runs a single
read-only command (``show running-config``) and returns its text, bounded; it never enters config
mode, never writes, and the credential it uses came from the agent's local vault, so no secret left
the box to get here. ``known_hosts`` is disabled because a lab/cEOS fabric has no host-key registry;
host-key pinning is a hardening tracked for production collection.

Separated from the handler so the handler's logic (verify, normalise, sign) is testable by
monkeypatching :func:`collect_running_config`, which is the only function here that touches the
network.
"""

from __future__ import annotations

import asyncio

import asyncssh

from agent.credential_vault import Credential

_DEFAULT_COMMAND = "show running-config"
_LLDP_COMMAND = "show lldp neighbors detail"
# OpenSSH's own dump of its EFFECTIVE configuration (defaults, Include and Match already resolved).
# Read-only like every other command here: it prints config, it changes none. The host tier of the
# credentialed collector reads this instead of a network device's running-config.
_SSHD_EFFECTIVE_COMMAND = "sshd -T"
# The kernel's RUNNING network-stack settings. Read-only (``-a`` lists, it does not set).
_SYSCTL_COMMAND = "sysctl -a"
# The account database (name:passwd:uid:gid:gecos:home:shell). Read-only enumeration; getent reads
# the resolved database (files + any directory source) without the shadow hashes.
_PASSWD_COMMAND = "getent passwd"
# The account database plus the group database, separated by a marker, for the local-administrator
# observed set (uid-0 accounts + admin-group members). Read-only enumeration, no root and no shadow.
_LOCALADMIN_COMMAND = "getent passwd; echo '===GROUPS==='; getent group"
# The dnf package-manager configuration (rpm/dnf hosts). Read-only file read; a non-dnf host has no
# such file and the read simply fails, recorded as honest UNAVAILABLE coverage.
_PKG_CONFIG_COMMAND = "cat /etc/dnf/dnf.conf"
# The running host firewall posture (firewalld). Read-only queries; a host without firewalld prints a
# shell error, which the parser reads as abstain (its absence is not a weakness on an SG-fronted host).
_FIREWALL_STATE_COMMAND = "firewall-cmd --state 2>&1; echo '===LISTALL==='; firewall-cmd --list-all 2>&1"
# The dnf-automatic updater configuration (rpm/dnf hosts). Read-only file read; an absent file abstains.
_PKG_AUTO_COMMAND = "cat /etc/dnf/automatic.conf"
# The host's auditd service state (the Linux security audit log). Read-only systemctl queries; a host
# with no auditd unit prints a "No such file"/"not-found" line, which the parser abstains on (we
# cannot assert "security logging disabled" on a host that ships logs through journald/rsyslog to a
# SIEM instead). The ``is-enabled`` read confirms the unit exists; ``is-active`` reads whether it runs.
_AUDITD_STATE_COMMAND = (
    "systemctl is-enabled auditd 2>&1; echo '===ACTIVE==='; systemctl is-active auditd 2>&1"
)
# The NFS server's export table (``/etc/exports`` plus any drop-ins). Read-only file read; a host that
# is not an NFS server has no such file and the read yields empty output, which the parser abstains on
# (no exports is not a weakness we can assert) rather than reading as a host with no wildcard export.
_NFS_EXPORTS_COMMAND = "cat /etc/exports 2>/dev/null; cat /etc/exports.d/*.exports 2>/dev/null"
# PostgreSQL's on-disk config, from the common Debian/RHEL locations (only one exists on a given host;
# the rest glob to nothing). Read-only file reads; a host with no PostgreSQL yields empty output, which
# the parser abstains on rather than reading as a database with a missing setting.
_POSTGRES_CONF_COMMAND = (
    "cat /etc/postgresql/*/main/postgresql.conf /var/lib/pgsql/data/postgresql.conf "
    "/var/lib/postgresql/data/postgresql.conf 2>/dev/null"
)
_POSTGRES_HBA_COMMAND = (
    "cat /etc/postgresql/*/main/pg_hba.conf /var/lib/pgsql/data/pg_hba.conf "
    "/var/lib/postgresql/data/pg_hba.conf 2>/dev/null"
)
# Postfix's main.cf. Read-only file read; a host with no Postfix yields empty output, which the parser
# abstains on rather than reading as a mail server with a missing directive.
_POSTFIX_MAIN_CF_COMMAND = "cat /etc/postfix/main.cf 2>/dev/null"
# The Postfix server version (just the value, e.g. "3.7.11"), for the mail-lifecycle control.
_POSTFIX_VERSION_COMMAND = "postconf -h mail_version 2>/dev/null"
# MySQL / MariaDB server config, from the common Debian/RHEL locations and their conf.d drop-ins (only
# the ones that exist are read; the rest glob to nothing). Read-only file reads; a host with no MySQL
# yields empty output, which the parser abstains on rather than reading as a database with a missing
# directive.
_MYSQL_CONF_COMMAND = (
    "cat /etc/mysql/my.cnf /etc/my.cnf /etc/mysql/mysql.conf.d/*.cnf "
    "/etc/mysql/mariadb.conf.d/*.cnf 2>/dev/null"
)
# The web server (nginx) effective config: the main file plus the enabled site/snippet includes
# (only the locations that exist on a given host glob to anything). Read-only file reads; a host with
# no nginx yields empty output, which the parser abstains on rather than reading as a web host with a
# missing directive.
_NGINX_CONF_COMMAND = (
    "cat /etc/nginx/nginx.conf /etc/nginx/conf.d/*.conf /etc/nginx/sites-enabled/* 2>/dev/null"
)


async def _run_show(
    host: str,
    credential: Credential,
    command: str,
    *,
    port: int,
    timeout: float,
    max_bytes: int,
) -> str:
    """Open one read-only SSH session and return one show command's output, truncated. Raises on
    connect/auth/timeout. The single networked primitive both reads share, so each read is one
    bounded show command, no config-mode and no write, and the credential is never logged."""
    options: dict[str, object] = {
        "username": credential.username,
        "known_hosts": None,
        "connect_timeout": timeout,
    }
    if credential.kind == "ssh_password":
        options["password"] = credential.secret
    else:
        options["client_keys"] = [asyncssh.import_private_key(credential.secret)]

    async with asyncssh.connect(host, port=port, **options) as conn:
        result = await asyncio.wait_for(conn.run(command, check=False), timeout=timeout)
        text = result.stdout if isinstance(result.stdout, str) else ""
        return text[:max_bytes]


async def collect_running_config(
    host: str,
    credential: Credential,
    *,
    port: int = 22,
    timeout: float = 20.0,
    max_bytes: int = 2_000_000,
    command: str = _DEFAULT_COMMAND,
) -> str:
    """The device's running-config text, truncated to ``max_bytes``. Raises on connect/auth/timeout.

    Read-only: one show command, no config-mode, no write. The credential (password or key) is used
    only to authenticate this session and is never logged."""
    return await _run_show(
        host, credential, command, port=port, timeout=timeout, max_bytes=max_bytes
    )


async def collect_lldp_output(
    host: str,
    credential: Credential,
    *,
    port: int = 22,
    timeout: float = 20.0,
    max_bytes: int = 500_000,
) -> str:
    """The device's LLDP neighbour table (``show lldp neighbors detail``), truncated. Same read-only
    single-show-command path as the running-config read; the agent parses it into neighbours. Only
    called for a grammar that exposes LLDP (Arista), so an FRR device is never asked."""
    return await _run_show(
        host, credential, _LLDP_COMMAND, port=port, timeout=timeout, max_bytes=max_bytes
    )


async def collect_sshd_effective_config(
    host: str,
    credential: Credential,
    *,
    port: int = 22,
    timeout: float = 20.0,
    max_bytes: int = 500_000,
) -> str:
    """The Linux host's EFFECTIVE SSH daemon configuration (``sshd -T``), truncated. Same read-only
    single-command path as the device reads: it dumps config and changes nothing. Used for the host
    tier (``server.ssh.*`` controls); a network device has no ``sshd`` and the read simply fails,
    which the caller records as honest UNAVAILABLE coverage rather than a guessed fact."""
    return await _run_show(
        host, credential, _SSHD_EFFECTIVE_COMMAND, port=port, timeout=timeout, max_bytes=max_bytes
    )


async def collect_sysctl_config(
    host: str,
    credential: Credential,
    *,
    port: int = 22,
    timeout: float = 20.0,
    max_bytes: int = 500_000,
) -> str:
    """The Linux host's RUNNING kernel settings (``sysctl -a``), truncated. Read-only (``-a`` lists,
    it does not set). Used for the host tier (``server.sysctl.*`` controls); a network device has no
    ``sysctl`` and the read simply fails, recorded as honest UNAVAILABLE coverage."""
    return await _run_show(
        host, credential, _SYSCTL_COMMAND, port=port, timeout=timeout, max_bytes=max_bytes
    )


async def collect_passwd_database(
    host: str,
    credential: Credential,
    *,
    port: int = 22,
    timeout: float = 20.0,
    max_bytes: int = 500_000,
) -> str:
    """The Linux host's account database (``getent passwd``), truncated. Read-only enumeration; it
    returns no password hashes (those live in shadow). Used for the host tier (``server.account.*``
    controls); a network device has no ``getent`` and the read simply fails, recorded as honest
    UNAVAILABLE coverage."""
    return await _run_show(
        host, credential, _PASSWD_COMMAND, port=port, timeout=timeout, max_bytes=max_bytes
    )


async def collect_localadmin_sources(
    host: str,
    credential: Credential,
    *,
    port: int = 22,
    timeout: float = 20.0,
    max_bytes: int = 500_000,
) -> str:
    """The Linux host's account + group databases (``getent passwd`` then ``getent group``, split by a
    marker), truncated. Read-only enumeration, no root and no password hashes. Used for the host tier's
    baseline-comparison control ``server.localadmin.unapproved`` (the observed local-administrator set);
    a network device has no ``getent`` and the read simply fails, recorded as honest UNAVAILABLE."""
    return await _run_show(
        host, credential, _LOCALADMIN_COMMAND, port=port, timeout=timeout, max_bytes=max_bytes
    )


async def collect_pkg_config(
    host: str,
    credential: Credential,
    *,
    port: int = 22,
    timeout: float = 20.0,
    max_bytes: int = 500_000,
) -> str:
    """The Linux host's dnf package-manager configuration (``/etc/dnf/dnf.conf``), truncated. Read-only
    file read: it prints config and changes nothing. Used for the host tier (``server.pkg.*``
    controls); a non-dnf host (Debian/Ubuntu, a network device) has no such file and the read simply
    fails, which the caller records as honest UNAVAILABLE coverage rather than a guessed fact."""
    return await _run_show(
        host, credential, _PKG_CONFIG_COMMAND, port=port, timeout=timeout, max_bytes=max_bytes
    )


async def collect_firewall_state(
    host: str,
    credential: Credential,
    *,
    port: int = 22,
    timeout: float = 20.0,
    max_bytes: int = 500_000,
) -> str:
    """The Linux host's running firewalld posture (``firewall-cmd --state`` + ``--list-all``),
    truncated. Read-only queries: they report state and change nothing. Used for the host tier
    (``server.firewall.*``); a host without firewalld prints a shell error, which the parser abstains
    on (absence is not a weakness on an SG-fronted host) rather than reading as a disabled firewall."""
    return await _run_show(
        host, credential, _FIREWALL_STATE_COMMAND, port=port, timeout=timeout, max_bytes=max_bytes
    )


async def collect_pkg_auto_config(
    host: str,
    credential: Credential,
    *,
    port: int = 22,
    timeout: float = 20.0,
    max_bytes: int = 500_000,
) -> str:
    """The Linux host's dnf-automatic updater configuration (``/etc/dnf/automatic.conf``), truncated.
    Read-only file read. Used for the host tier (``server.pkg.auto_updates``); an absent file (the
    updater is not installed) fails the read, which the parser abstains on rather than reading as
    unpatched."""
    return await _run_show(
        host, credential, _PKG_AUTO_COMMAND, port=port, timeout=timeout, max_bytes=max_bytes
    )


async def collect_auditd_state(
    host: str,
    credential: Credential,
    *,
    port: int = 22,
    timeout: float = 20.0,
    max_bytes: int = 500_000,
) -> str:
    """The Linux host's auditd service state (``systemctl is-enabled``/``is-active auditd``),
    truncated. Read-only queries: they report state and change nothing. Used for the host tier
    (``server.audit.security_logging_disabled``); a host with no auditd unit prints a "No such
    file"/"not-found" line, which the parser abstains on rather than reading as a host with security
    logging disabled (it may ship its logs through journald/rsyslog to a SIEM instead)."""
    return await _run_show(
        host, credential, _AUDITD_STATE_COMMAND, port=port, timeout=timeout, max_bytes=max_bytes
    )


async def collect_nfs_exports(
    host: str,
    credential: Credential,
    *,
    port: int = 22,
    timeout: float = 20.0,
    max_bytes: int = 500_000,
) -> str:
    """The host's NFS export table (``/etc/exports`` plus ``/etc/exports.d/*.exports``), truncated.
    Read-only file read: it prints the exports and changes nothing. Used for the host tier
    (``storage.nfs.*``); a host that is not an NFS server has no such file and the read yields empty
    output, which the parser abstains on rather than reading as a host with no wildcard export."""
    return await _run_show(
        host, credential, _NFS_EXPORTS_COMMAND, port=port, timeout=timeout, max_bytes=max_bytes
    )


async def collect_postgres_conf(
    host: str,
    credential: Credential,
    *,
    port: int = 22,
    timeout: float = 20.0,
    max_bytes: int = 500_000,
) -> str:
    """PostgreSQL's ``postgresql.conf`` from the common Debian/RHEL locations, truncated. Read-only
    file read: it prints config and changes nothing. Used for the host tier (``database.*``); a host
    with no PostgreSQL yields empty output, which the parser abstains on rather than reading as a
    database with a missing setting."""
    return await _run_show(
        host, credential, _POSTGRES_CONF_COMMAND, port=port, timeout=timeout, max_bytes=max_bytes
    )


async def collect_postgres_hba(
    host: str,
    credential: Credential,
    *,
    port: int = 22,
    timeout: float = 20.0,
    max_bytes: int = 500_000,
) -> str:
    """PostgreSQL's ``pg_hba.conf`` (the client authentication rules) from the common Debian/RHEL
    locations, truncated. Read-only file read. Used for the host tier (``database.listener.*`` /
    ``database.client.tls``); a host with no PostgreSQL yields empty output, which the parser abstains
    on rather than reading as a database with no restriction."""
    return await _run_show(
        host, credential, _POSTGRES_HBA_COMMAND, port=port, timeout=timeout, max_bytes=max_bytes
    )


async def collect_postfix_main_cf(
    host: str,
    credential: Credential,
    *,
    port: int = 22,
    timeout: float = 20.0,
    max_bytes: int = 500_000,
) -> str:
    """Postfix's ``/etc/postfix/main.cf``, truncated. Read-only file read: it prints config and
    changes nothing. Used for the host tier (``mail.auth.legacy`` / ``mail.tls.inbound_not_enforced``);
    a host with no Postfix yields empty output, which the parser abstains on rather than reading as a
    mail server with a missing directive."""
    return await _run_show(
        host, credential, _POSTFIX_MAIN_CF_COMMAND, port=port, timeout=timeout, max_bytes=max_bytes
    )


async def collect_postfix_version(
    host: str,
    credential: Credential,
    *,
    port: int = 22,
    timeout: float = 20.0,
    max_bytes: int = 500_000,
) -> str:
    """The Postfix server version (``postconf -h mail_version``, e.g. ``3.7.11``), for the host tier
    (``mail.lifecycle.unsupported_gateway``). Read-only; a host with no Postfix yields empty output,
    which the parser abstains on rather than reading as an up-to-date mail server."""
    return await _run_show(
        host, credential, _POSTFIX_VERSION_COMMAND, port=port, timeout=timeout, max_bytes=max_bytes
    )


async def collect_mysql_conf(
    host: str,
    credential: Credential,
    *,
    port: int = 22,
    timeout: float = 20.0,
    max_bytes: int = 500_000,
) -> str:
    """MySQL / MariaDB server config from the common Debian/RHEL locations and conf.d drop-ins,
    truncated. Read-only file reads: they print config and change nothing. Used for the host tier
    (``database.listener.unrestricted`` / ``database.client.tls`` on MySQL); a host with no MySQL
    yields empty output, which the parser abstains on rather than reading as a database with a missing
    directive."""
    return await _run_show(
        host, credential, _MYSQL_CONF_COMMAND, port=port, timeout=timeout, max_bytes=max_bytes
    )


async def collect_nginx_conf(
    host: str,
    credential: Credential,
    *,
    port: int = 22,
    timeout: float = 20.0,
    max_bytes: int = 500_000,
) -> str:
    """The web server's effective nginx configuration, truncated. Read-only file reads: they print
    config and change nothing. Used for the host tier (``web.tls.client_facing_not_enforced`` /
    ``web.admin.public``); a host with no nginx yields empty output, which the parser abstains on
    rather than reading as a web host with a missing directive."""
    return await _run_show(
        host, credential, _NGINX_CONF_COMMAND, port=port, timeout=timeout, max_bytes=max_bytes
    )
