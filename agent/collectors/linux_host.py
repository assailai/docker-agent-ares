"""Normalize a Linux host's effective SSH daemon configuration into executable-control facts.

Read-only: the collector runs ``sshd -T`` (the daemon's own dump of its EFFECTIVE configuration,
with every default, ``Include`` and ``Match`` already resolved) and this parser turns that text into
the typed fields the control plane's executable-control evaluator consumes. Reading the EFFECTIVE
config, not ``/etc/ssh/sshd_config`` on disk, is deliberate: a directive the admin never wrote still
has a compiled-in default, and a file-level read would miss it and mis-score a host, so the honest
source is what the daemon reports it is actually enforcing.

Like the device parsers, it ABSTAINS rather than invents a value: a directive absent from the dump
leaves its field out of the returned dict, so that control stays NOT_ASSESSED rather than becoming a
false posture claim, and a dump that does not look like ``sshd -T`` output at all yields no fields so
the control is recorded UNSUPPORTED. ``sshd -T`` emits one ``<directive> <value>`` line per line with
the directive name lower-cased, which is stable across OpenSSH versions, so a fixture captured from a
real host is faithful to what a live host emits (unlike a hand-written device running-config, which
the device OS would rewrite).

This is the host tier of the credentialed collector; a network device is still read with the vendor
running-config parsers. A new host control is a new field extractor here plus its evaluator entry on
the control plane.
"""

from __future__ import annotations

# The control-id prefix this collector serves. The agent partitions a collect job's requested
# controls by evidence source: a control under this prefix is read from the host's ``sshd -T`` dump,
# everything else from the device running-config. Keeping the split here (not in the task wiring)
# means a new host control needs no change to the dispatcher.
HOST_CONTROL_PREFIX = "server.ssh."

# A handful of directives every real ``sshd -T`` dump carries. If none of these appear, the text is
# not an effective-config dump (an error line, an empty read, a truncated capture), so the parser
# abstains on the whole control rather than reading a field out of unrelated bytes.
_SSHD_MARKERS = ("passwordauthentication", "permitrootlogin", "maxauthtries")


def _directives(sshd_effective: str) -> dict[str, str]:
    """The ``sshd -T`` dump as a ``{directive: value}`` map, directive lower-cased and value the rest
    of the line. Later lines win (``sshd -T`` prints one effective value per directive, so this is a
    straight parse); a blank or malformed line is skipped. Returns an empty map when the text is not
    an effective-config dump, which makes every field abstain."""
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


# One extractor per (control_id, field). A control whose extractor abstains (returns None) is omitted
# from the collected fields, so the control plane evaluates it NOT_ASSESSED rather than on a guess.
_FIELD_EXTRACTORS = {
    ("server.ssh.password", "ssh_password_authentication"): parse_password_authentication,
    ("server.ssh.root_login", "ssh_root_login_permitted"): parse_root_login_permitted,
    ("server.ssh.empty_passwords", "ssh_permit_empty_passwords"): parse_permit_empty_passwords,
    ("server.ssh.x11_forwarding", "ssh_x11_forwarding_enabled"): parse_x11_forwarding_enabled,
    ("server.ssh.max_auth_tries", "ssh_max_auth_tries"): parse_max_auth_tries,
}


def serves(control_id: str) -> bool:
    """Whether this host collector reads the evidence for ``control_id`` (a ``server.ssh.*`` control),
    so the dispatcher routes it to ``sshd -T`` rather than the device running-config."""
    return control_id.startswith(HOST_CONTROL_PREFIX)


def collect_control_fields(sshd_effective: str, control_id: str) -> dict[str, object] | None:
    """The typed field values this parser can read for ``control_id`` from an ``sshd -T`` dump, or
    ``None`` if the parser does not support that control. A field whose extractor abstains is left
    out, so a partially-readable dump still yields the fields it could read and the rest stay
    NOT_ASSESSED. An empty-but-supported result (every field abstained) returns an empty dict, which
    the collector still records as a (gated, field-less) control that evaluates NOT_ASSESSED."""
    supported = [
        (field, extractor)
        for (ctrl, field), extractor in _FIELD_EXTRACTORS.items()
        if ctrl == control_id
    ]
    if not supported:
        return None
    fields: dict[str, object] = {}
    for field, extractor in supported:
        value = extractor(sshd_effective)
        if value is not None:
            fields[field] = value
    return fields
