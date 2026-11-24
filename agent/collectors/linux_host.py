"""Normalize a Linux host's read-only configuration dumps into executable-control facts.

Read-only: the collector runs a small set of config-dumping commands (``sshd -T`` for the effective
SSH daemon config, ``sysctl -a`` for the running kernel network-stack settings) and this parser turns
each one's text into the typed fields the control plane's executable-control evaluator consumes.
Reading the EFFECTIVE / RUNNING state, not a file on disk, is deliberate: a directive the admin never
wrote still has a compiled-in default, and a file-level read would miss it and mis-score a host, so
the honest source is what the daemon and kernel report they are actually enforcing.

Like the device parsers, it ABSTAINS rather than invents a value: a setting absent from its dump
leaves its field out of the returned dict, so that control stays NOT_ASSESSED rather than becoming a
false posture claim, and a dump that does not look like the expected output yields no fields so the
control is recorded UNSUPPORTED. These dumps are standard tool output (OpenSSH's own ``-T`` format,
``sysctl``'s ``key = value``), stable across versions, so a fixture captured from a real host is
faithful to what a live host emits (unlike a hand-written device running-config, which the device OS
would rewrite).

A host control is routed to exactly one evidence source by :func:`source_for`; the agent collects
each needed source once and hands the parser the ``{source: output}`` map. This is the host tier of
the credentialed collector; a network device is still read with the vendor running-config parsers. A
new host control is a new field extractor here (naming its source) plus its evaluator entry on the
control plane.
"""

from __future__ import annotations

# The evidence sources a host control can be read from. Each maps to one read-only command the agent
# runs (the command itself lives with the SSH transport, so this module stays pure and testable).
SOURCE_SSHD = "sshd"
SOURCE_SYSCTL = "sysctl"


# ── sshd -T (effective SSH daemon configuration) ──────────────────────────────────────────────────
# A handful of directives every real ``sshd -T`` dump carries. If none appear, the text is not an
# effective-config dump (an error line, an empty read, a truncated capture), so the parser abstains
# on the whole control rather than reading a field out of unrelated bytes.
_SSHD_MARKERS = ("passwordauthentication", "permitrootlogin", "maxauthtries")


def _directives(sshd_effective: str) -> dict[str, str]:
    """The ``sshd -T`` dump as a ``{directive: value}`` map, directive lower-cased and value the rest
    of the line. ``sshd -T`` prints one effective value per directive, so this is a straight parse; a
    blank or malformed line is skipped. Returns an empty map when the text is not an effective-config
    dump, which makes every field abstain."""
    directives: dict[str, str] = {}
    for raw in sshd_effective.splitlines():
        line = raw.strip()
        if not line:
            continue
        parts = line.split(None, 1)
        if len(parts) != 2:
            continue
        directives[parts[0].lower()] = parts[1].strip()
    if not any(marker in directives for marker in _SSHD_MARKERS):
        return {}
    return directives


def parse_password_authentication(sshd_effective: str) -> bool | None:
    """Whether password authentication is enabled (``passwordauthentication yes``), or ``None`` to
    abstain when the directive is absent. A weakness only against a key-only approved baseline, which
    the control's applicability binds; this parser reports the configured state, nothing more."""
    directives = _directives(sshd_effective)
    value = directives.get("passwordauthentication")
    return None if value is None else value.lower() == "yes"


def parse_root_login_permitted(sshd_effective: str) -> bool | None:
    """Whether direct root login with a password is permitted (``permitrootlogin yes``), or ``None``
    to abstain. Only a bare ``yes`` counts: ``prohibit-password`` / ``without-password`` /
    ``forced-commands-only`` are hardened states that still allow key or constrained root access, so
    flagging them would be a false positive on a deliberately hardened host."""
    directives = _directives(sshd_effective)
    value = directives.get("permitrootlogin")
    return None if value is None else value.lower() == "yes"


def parse_permit_empty_passwords(sshd_effective: str) -> bool | None:
    """Whether empty passwords are accepted (``permitemptypasswords yes``), or ``None`` to abstain.
    An unambiguous weakness: a host that authenticates an account with no password at all."""
    directives = _directives(sshd_effective)
    value = directives.get("permitemptypasswords")
    return None if value is None else value.lower() == "yes"


def parse_x11_forwarding_enabled(sshd_effective: str) -> bool | None:
    """Whether X11 forwarding is enabled (``x11forwarding yes``), or ``None`` to abstain. Enabled
    X11 forwarding widens the attack surface of an authenticated session and is off in a hardened
    baseline."""
    directives = _directives(sshd_effective)
    value = directives.get("x11forwarding")
    return None if value is None else value.lower() == "yes"


def parse_max_auth_tries(sshd_effective: str) -> int | None:
    """The configured ``MaxAuthTries`` as an integer, or ``None`` to abstain when the directive is
    absent or non-numeric. The control's predicate flags a value above the hardened ceiling; this
    parser only reads the number, it does not judge it."""
    directives = _directives(sshd_effective)
    value = directives.get("maxauthtries")
    if value is None or not value.isdigit():
        return None
    return int(value)


# ── sysctl -a (running kernel network-stack settings) ─────────────────────────────────────────────
# A handful of keys every real ``sysctl -a`` dump carries. If none appear, the text is not a sysctl
# dump, so the parser abstains rather than read a field out of unrelated bytes.
_SYSCTL_MARKERS = ("kernel.ostype", "net.ipv4.ip_forward")


def _sysctl_values(sysctl_output: str) -> dict[str, str]:
    """The ``sysctl -a`` dump as a ``{key: value}`` map. Lines are ``key = value`` (Linux); the key is
    lower-cased and whitespace trimmed. A blank or malformed line is skipped. Returns an empty map
    when the text is not a sysctl dump, which makes every field abstain."""
    values: dict[str, str] = {}
    for raw in sysctl_output.splitlines():
        line = raw.strip()
        if not line or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip().lower()
        if key:
            values[key] = value.strip()
    if not any(marker in values for marker in _SYSCTL_MARKERS):
        return {}
    return values


def _sysctl_flag_enabled(sysctl_output: str, key: str) -> bool | None:
    """Whether a boolean-style sysctl (``0``/``1``) is enabled, or ``None`` to abstain when the key is
    absent or non-numeric. A positive integer reads as enabled."""
    values = _sysctl_values(sysctl_output)
    value = values.get(key)
    if value is None or not value.lstrip("-").isdigit():
        return None
    return int(value) != 0


def parse_ip_forwarding_enabled(sysctl_output: str) -> bool | None:
    """Whether IPv4 forwarding is on (``net.ipv4.ip_forward = 1``), or ``None`` to abstain. On a host
    that is not an approved router/gateway this enables packet pivoting; the control's applicability
    binds the approved-baseline question, this parser reports only the running state."""
    return _sysctl_flag_enabled(sysctl_output, "net.ipv4.ip_forward")


def parse_source_route_accepted(sysctl_output: str) -> bool | None:
    """Whether source-routed packets are accepted (``net.ipv4.conf.all.accept_source_route = 1``), or
    ``None`` to abstain. Accepting source routing lets a sender dictate a packet's path and is off in
    a hardened baseline."""
    return _sysctl_flag_enabled(sysctl_output, "net.ipv4.conf.all.accept_source_route")


def parse_icmp_redirects_accepted(sysctl_output: str) -> bool | None:
    """Whether ICMP redirects are accepted (``net.ipv4.conf.all.accept_redirects = 1``), or ``None``
    to abstain. Accepting redirects lets an on-path host rewrite the routing table and is off in a
    hardened baseline."""
    return _sysctl_flag_enabled(sysctl_output, "net.ipv4.conf.all.accept_redirects")


# One entry per (control_id, field): the evidence source it reads and the extractor. A control whose
# extractor abstains (returns None) is omitted from the collected fields, so the control plane
# evaluates it NOT_ASSESSED rather than on a guess.
_FIELD_EXTRACTORS = {
    ("server.ssh.password", "ssh_password_authentication"): (
        SOURCE_SSHD,
        parse_password_authentication,
    ),
    ("server.ssh.root_login", "ssh_root_login_permitted"): (SOURCE_SSHD, parse_root_login_permitted),
    ("server.ssh.empty_passwords", "ssh_permit_empty_passwords"): (
        SOURCE_SSHD,
        parse_permit_empty_passwords,
    ),
    ("server.ssh.x11_forwarding", "ssh_x11_forwarding_enabled"): (
        SOURCE_SSHD,
        parse_x11_forwarding_enabled,
    ),
    ("server.ssh.max_auth_tries", "ssh_max_auth_tries"): (SOURCE_SSHD, parse_max_auth_tries),
    ("server.sysctl.ip_forwarding", "sysctl_ip_forwarding_enabled"): (
        SOURCE_SYSCTL,
        parse_ip_forwarding_enabled,
    ),
    ("server.sysctl.source_route", "sysctl_source_route_accepted"): (
        SOURCE_SYSCTL,
        parse_source_route_accepted,
    ),
    ("server.sysctl.icmp_redirects", "sysctl_icmp_redirects_accepted"): (
        SOURCE_SYSCTL,
        parse_icmp_redirects_accepted,
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
    """Whether this host collector reads the evidence for ``control_id``, so the dispatcher routes it
    to a host command rather than the device running-config."""
    return bool(_extractors_for(control_id))


def source_for(control_id: str) -> str | None:
    """The single evidence source (``sshd`` / ``sysctl``) ``control_id`` is read from, or ``None`` if
    this collector does not serve it. Every host control reads from exactly one source."""
    extractors = _extractors_for(control_id)
    return extractors[0][1] if extractors else None


def sources_for(control_ids: list[str]) -> set[str]:
    """The distinct evidence sources needed to collect the host controls among ``control_ids``, so the
    agent runs each host command at most once."""
    return {src for cid in control_ids if (src := source_for(cid)) is not None}


def collect_control_fields(sources: dict[str, str], control_id: str) -> dict[str, object] | None:
    """The typed field values this parser can read for ``control_id`` from the collected evidence, or
    ``None`` if the parser does not support that control. ``sources`` maps an evidence-source key to
    its dump text. A field whose extractor abstains is left out, so a partially-readable dump still
    yields the fields it could read and the rest stay NOT_ASSESSED. An empty-but-supported result
    (every field abstained) returns an empty dict, which the collector still records as a (gated,
    field-less) control that evaluates NOT_ASSESSED."""
    supported = _extractors_for(control_id)
    if not supported:
        return None
    fields: dict[str, object] = {}
    for field, source, extractor in supported:
        text = sources.get(source, "")
        value = extractor(text)
        if value is not None:
            fields[field] = value
    return fields
