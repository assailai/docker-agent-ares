"""Normalize a Linux NFS server's export table into executable-control facts (the host-readable slice
of the storage cohort).

Read-only: reads ``/etc/exports`` (and ``/etc/exports.d/*.exports``) over the same SSH transport the
server-hardening tier uses, and parses it into the ``storage.nfs.*`` fields. Like every host
collector it ABSTAINS rather than invents: a host with no export entries at all (not an NFS server,
or exports declared somewhere this read cannot see) leaves the field out, so the control stays
NOT_ASSESSED rather than a false clean.

Only what a host's own export table proves lives here. The array-level storage controls (volume
encryption, snapshot protection, management-plane TLS, admin RBAC/MFA, replication trust, firmware
lifecycle, ...) need a storage-array management API, not a host file, so they stay DESIGNED with no
collector until that transport exists.
"""

from __future__ import annotations

# The evidence source this collector reads, and the ssh_collect reader that produces it. The host
# tier merges SOURCE_READERS across every host collector; the key is globally unique.
SOURCE_NFS_EXPORTS = "nfs_exports"

SOURCE_READERS = {SOURCE_NFS_EXPORTS: "collect_nfs_exports"}

# A client spec that opens an export to EVERY host. `*` is NFS's match-all; the two all-addresses
# CIDRs are the same thing written as a network. A partial wildcard like `*.corp.example` is NOT here:
# it restricts to a domain, so flagging it would be a false positive.
_WILDCARD_CLIENTS = frozenset({"*", "0.0.0.0/0", "::/0"})


def _export_lines(nfs_exports: str) -> list[str]:
    """The export table's data lines (comments and blanks dropped). An exports line names an absolute
    path first, so only lines whose first token starts with ``/`` are kept; everything else (a shell
    error, an unrelated file) is skipped, and an empty result makes the control abstain."""
    lines: list[str] = []
    for raw in nfs_exports.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.split(None, 1)[0].startswith("/"):
            lines.append(line)
    return lines


def _client_specs(export_line: str) -> list[tuple[str, str]]:
    """The ``(client, options)`` pairs on one export line. An entry is ``client(opt,opt)`` (NFS allows
    no space between the client and its parenthesised options); a bare ``client`` with no options, and
    a bare ``(opts)`` with no client (the match-all shorthand), are both handled."""
    specs: list[tuple[str, str]] = []
    for token in export_line.split()[1:]:  # token[0] is the exported path
        client, sep, rest = token.partition("(")
        options = rest[:-1] if sep and rest.endswith(")") else ""
        # A bare "(opts)" with no client is the match-all shorthand: the client is "*".
        specs.append((client or "*", options.lower()))
    return specs


def _is_read_write(options: str) -> bool:
    """Whether an export's options grant write access. NFS defaults to ``ro`` when neither is given,
    so write access requires an explicit ``rw`` token and no ``ro`` overriding it to its right is
    possible (``rw`` and ``ro`` are mutually exclusive; the last wins, and ``rw`` listed means rw)."""
    opts = [o.strip() for o in options.split(",")]
    return "rw" in opts


def parse_nfs_wildcard_rw_export(nfs_exports: str) -> bool | None:
    """Whether any export is readable AND writable by every host (a ``*`` / all-addresses client with
    ``rw``), or ``None`` to abstain when the table has no export entries at all (not an NFS server, or
    exports this read cannot see). With at least one export present the answer is definite: ``True``
    when a wildcard read-write export exists, ``False`` when every export is host-restricted or
    read-only."""
    lines = _export_lines(nfs_exports)
    if not lines:
        return None
    for line in lines:
        for client, options in _client_specs(line):
            if client in _WILDCARD_CLIENTS and _is_read_write(options):
                return True
    return False


# One entry per (control_id, field): the evidence source it reads and the extractor. Mirrors the
# linux_host registry so the host tier routes every host family the same way.
_FIELD_EXTRACTORS = {
    ("storage.nfs.wildcard_rw", "wildcard_read_write_export"): (
        SOURCE_NFS_EXPORTS,
        parse_nfs_wildcard_rw_export,
    ),
}


def _extractors_for(control_id: str) -> list[tuple[str, str, object]]:
    """The ``(field, source, extractor)`` entries this parser has for ``control_id`` (empty if it
    serves no such control)."""
    return [
        (field, source, extractor)
        for (ctrl, field), (source, extractor) in _FIELD_EXTRACTORS.items()
        if ctrl == control_id
    ]


def serves(control_id: str) -> bool:
    """Whether this collector reads the evidence for ``control_id``."""
    return bool(_extractors_for(control_id))


def source_for(control_id: str) -> str | None:
    """The single evidence source ``control_id`` is read from, or ``None`` if not served."""
    extractors = _extractors_for(control_id)
    return extractors[0][1] if extractors else None


def collect_control_fields(sources: dict[str, str], control_id: str) -> dict[str, object] | None:
    """The typed field values this parser can read for ``control_id`` from the collected evidence, or
    ``None`` if it does not serve that control. A field whose extractor abstains is left out, so a
    partially-readable source still yields the fields it could read and the rest stay NOT_ASSESSED."""
    supported = _extractors_for(control_id)
    if not supported:
        return None
    fields: dict[str, object] = {}
    for field, source, extractor in supported:
        value = extractor(sources.get(source, ""))
        if value is not None:
            fields[field] = value
    return fields
