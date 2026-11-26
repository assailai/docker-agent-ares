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
SOURCE_PASSWD = "passwd"
SOURCE_PKG = "pkg"
SOURCE_FIREWALL = "firewall"
SOURCE_PKG_AUTO = "pkg_auto"
SOURCE_AUDIT = "audit"

# Each evidence source -> the ssh_collect reader function (named, not imported, so a test that
# monkeypatches ssh_collect still reaches it: it is resolved off the module at call time). The host
# tier merges this map across every host collector, so adding a source is one entry here plus its
# reader. Source keys are globally unique across the host collectors, so the merge never clobbers.
SOURCE_READERS = {
    SOURCE_SSHD: "collect_sshd_effective_config",
    SOURCE_SYSCTL: "collect_sysctl_config",
    SOURCE_PASSWD: "collect_passwd_database",
    SOURCE_PKG: "collect_pkg_config",
    SOURCE_FIREWALL: "collect_firewall_state",
    SOURCE_PKG_AUTO: "collect_pkg_auto_config",
    SOURCE_AUDIT: "collect_auditd_state",
}


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


# Substrings that mark a legacy/deprecated SSH algorithm in the comma-separated effective lists. These
# are the primitives a hardened baseline drops: SHA1 and MD5 MACs, CBC/arcfour/3DES/DES ciphers, and
# SHA1 / group1 key exchanges. Matching a substring keeps the check robust to the many vendor-suffixed
# spellings (`hmac-sha1`, `hmac-sha1-etm@openssh.com`, ...).
_WEAK_MAC_MARKERS = ("sha1", "md5", "-96", "ripemd")
_WEAK_CIPHER_MARKERS = ("cbc", "arcfour", "3des", "blowfish", "cast128", "rc4")
_WEAK_KEX_MARKERS = ("sha1", "group1-", "gss-group1")


def _list_has_weak(sshd_effective: str, directive: str, markers: tuple[str, ...]) -> bool | None:
    """Whether the comma-separated algorithm list for ``directive`` contains any token matching a weak
    marker, or ``None`` to abstain when the directive is absent. The effective list is what the daemon
    offers, so a weak entry means the daemon will negotiate it."""
    value = _directives(sshd_effective).get(directive)
    if value is None:
        return None
    tokens = [t.strip().lower() for t in value.split(",") if t.strip()]
    return any(marker in token for token in tokens for marker in markers)


def parse_weak_macs_offered(sshd_effective: str) -> bool | None:
    """Whether the SSH MAC list offers a SHA1/MD5/64-bit MAC a hardened baseline drops, or abstain."""
    return _list_has_weak(sshd_effective, "macs", _WEAK_MAC_MARKERS)


def parse_weak_ciphers_offered(sshd_effective: str) -> bool | None:
    """Whether the SSH cipher list offers a CBC/arcfour/3DES cipher a hardened baseline drops, or
    abstain."""
    return _list_has_weak(sshd_effective, "ciphers", _WEAK_CIPHER_MARKERS)


def parse_weak_kex_offered(sshd_effective: str) -> bool | None:
    """Whether the SSH key-exchange list offers a SHA1/group1 exchange a hardened baseline drops, or
    abstain."""
    return _list_has_weak(sshd_effective, "kexalgorithms", _WEAK_KEX_MARKERS)


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


def _sysctl_int(sysctl_output: str, key: str) -> int | None:
    """The integer value of a numeric sysctl, or ``None`` to abstain when the key is absent or
    non-numeric. Shared by the boolean flags and the threshold reads below."""
    value = _sysctl_values(sysctl_output).get(key)
    if value is None or not value.lstrip("-").isdigit():
        return None
    return int(value)


def _sysctl_flag_enabled(sysctl_output: str, key: str) -> bool | None:
    """Whether a boolean-style sysctl (``0``/``1``) is enabled, or ``None`` to abstain when the key is
    absent or non-numeric. A positive integer reads as enabled."""
    value = _sysctl_int(sysctl_output, key)
    return None if value is None else value != 0


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


def parse_icmp_redirects_v6_accepted(sysctl_output: str) -> bool | None:
    """Whether IPv6 ICMP redirects are accepted (``net.ipv6.conf.all.accept_redirects = 1``), or
    ``None`` to abstain. The IPv6 twin of :func:`parse_icmp_redirects_accepted`: accepting a redirect
    lets an on-path host rewrite the routing table over IPv6, and a hardened baseline turns it off on
    both stacks. Unambiguous (no host should accept redirects), so this is not applicability-bound."""
    return _sysctl_flag_enabled(sysctl_output, "net.ipv6.conf.all.accept_redirects")


def parse_send_redirects_enabled(sysctl_output: str) -> bool | None:
    """Whether the host SENDS ICMP redirects (``net.ipv4.conf.all.send_redirects = 1``), or ``None``
    to abstain. A host that is not an approved router should not emit redirects (they leak topology
    and can be abused); the control's applicability binds the approved-router question exactly as it
    does for IPv4 forwarding, and this parser reports only the running state."""
    return _sysctl_flag_enabled(sysctl_output, "net.ipv4.conf.all.send_redirects")


def parse_syncookies_disabled(sysctl_output: str) -> bool | None:
    """Whether TCP SYN cookies are turned off (``net.ipv4.tcp_syncookies = 0``), or ``None`` to
    abstain. SYN cookies defend the listen backlog against a SYN flood; disabling them has no
    legitimate server use, so a zero reads as an unambiguous weakness (the secure default is enabled,
    hence the inverted sense: the weakness is the OFF state)."""
    value = _sysctl_int(sysctl_output, "net.ipv4.tcp_syncookies")
    return None if value is None else value == 0


def parse_aslr_disabled(sysctl_output: str) -> bool | None:
    """Whether address-space layout randomization is weakened (``kernel.randomize_va_space < 2``), or
    ``None`` to abstain. Full ASLR is ``2``; ``1`` randomizes less and ``0`` disables it, both of which
    make memory-corruption exploitation materially easier. The secure default is ``2``, so the
    weakness is any value below it."""
    value = _sysctl_int(sysctl_output, "kernel.randomize_va_space")
    return None if value is None else value < 2


# ── getent passwd (the account database) ──────────────────────────────────────────────────────────
# A standard passwd line is seven colon-separated fields: name:passwd:uid:gid:gecos:home:shell. A real
# account database always carries the superuser as `root:...:0:...`; its absence means the text is not
# a passwd dump, so the parser abstains rather than read accounts out of unrelated bytes.
def _passwd_rows(passwd_output: str) -> list[list[str]]:
    """The passwd dump as a list of field-lists, keeping only well-formed 7+-field lines whose uid is
    numeric. Returns an empty list when no ``root`` superuser (uid 0) line is present, which marks the
    text as not a passwd dump and makes every field abstain."""
    rows = [
        parts
        for line in passwd_output.splitlines()
        if len(parts := line.split(":")) >= 7 and parts[2].isdigit()
    ]
    if not any(r[0] == "root" and r[2] == "0" for r in rows):
        return []
    return rows


def parse_extra_root_account(passwd_output: str) -> bool | None:
    """Whether any account OTHER than ``root`` has uid 0 (a root-equivalent backdoor), or ``None`` to
    abstain. Unambiguous and effective: a uid-0 account is superuser regardless of PAM or sudo policy,
    so this has none of the file-vs-effective gap a config-file read would."""
    rows = _passwd_rows(passwd_output)
    if not rows:
        return None
    return any(r[2] == "0" and r[0] != "root" for r in rows)


def parse_duplicate_uid(passwd_output: str) -> bool | None:
    """Whether two accounts share one uid (so the system cannot attribute an action to one of them),
    or ``None`` to abstain. A CIS/NIST accountability weakness, read straight from the database."""
    rows = _passwd_rows(passwd_output)
    if not rows:
        return None
    uids = [r[2] for r in rows]
    return len(set(uids)) != len(uids)


# ── /etc/dnf/dnf.conf (the rpm/dnf package-manager configuration) ─────────────────────────────────
# dnf.conf is an INI file; the `[main]` section (or a recognizable dnf key) marks a genuine dnf
# config, so unrelated bytes abstain rather than read a field out of them. Only rpm/dnf hosts carry
# it; a Debian/Ubuntu host (apt) or a network device has no such file, so the read fails upstream and
# the control is recorded UNAVAILABLE, never silently passed.
_PKG_FALSEY = frozenset({"0", "false", "no", "off"})


def _dnf_conf_values(pkg_output: str) -> dict[str, str]:
    """``/etc/dnf/dnf.conf`` as a ``{key: value}`` map, keys lower-cased, section headers and comments
    skipped. Returns an empty map when the text is not a dnf config (no ``[main]`` header and no
    recognized dnf key), which makes every field abstain."""
    values: dict[str, str] = {}
    has_main = False
    for raw in pkg_output.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            has_main = has_main or line.lower() == "[main]"
            continue
        key, sep, value = line.partition("=")
        if not sep:
            continue
        key = key.strip().lower()
        if key:
            values[key] = value.strip()
    if not (has_main or any(k in values for k in ("gpgcheck", "installonly_limit"))):
        return {}
    return values


def parse_gpg_check_disabled(pkg_output: str) -> bool | None:
    """Whether dnf package-signature verification is turned off (``gpgcheck=0``/``False`` in
    ``dnf.conf``), or ``None`` to abstain when the directive is absent. gpgcheck off means packages
    install without verifying their signature, an unambiguous supply-chain weakness independent of the
    host's patch cadence. Absent means the dnf default (on), which the parser abstains on rather than
    asserting: the control stays NOT_ASSESSED, never a false pass."""
    value = _dnf_conf_values(pkg_output).get("gpgcheck")
    return None if value is None else value.strip().lower() in _PKG_FALSEY


# ── firewall-cmd --state / --list-all (the running host firewall posture) ──────────────────────────
# The weakness this reads is an AFFIRMATIVE one: firewalld is RUNNING and its default zone accepts
# everything (`target: ACCEPT`), a permissive host firewall. It deliberately does NOT read "firewalld
# is absent / not running" as a weakness: on a cloud host the inbound filter is the security group,
# not a host firewall, so "no host firewall" is unknowable here, not a finding. Absence therefore
# ABSTAINS (returns None -> NOT_ASSESSED), which is why this never false-positives on an SG-fronted
# host. Live FIRING validation needs a host that actually runs firewalld; the abstain path is
# validated against the real (firewalld-absent) lab capture.
def parse_firewall_permissive(firewall_output: str) -> bool | None:
    """Whether a RUNNING host firewall accepts all traffic by default (firewalld ``target: ACCEPT``),
    or ``None`` to abstain when firewalld is not running/installed (its absence is not a weakness we
    can assert on an SG-fronted host). Reads firewalld only; a host using nftables/ufw directly
    abstains here, a documented limitation."""
    lines = [line.strip() for line in firewall_output.splitlines()]
    # `firewall-cmd --state` prints exactly "running" or "not running"; a missing binary prints a
    # shell error. Only a bare "running" line means the daemon is up.
    if not any(line.lower() == "running" for line in lines):
        return None
    for line in lines:
        low = line.lower()
        if low.startswith("target:"):
            return low.split(":", 1)[1].strip() == "accept"
    return None


# ── /etc/dnf/automatic.conf (the dnf-automatic updater configuration) ──────────────────────────────
# Reads an AFFIRMATIVE weakness: dnf-automatic is CONFIGURED and set not to apply updates
# (`apply_updates = no`). It does NOT read "dnf-automatic is absent" as a weakness: a host may patch
# through another mechanism (AWS SSM Patch Manager, a config-management tool), so absence is
# unknowable here and ABSTAINS (None -> NOT_ASSESSED), never a false "unpatched". rpm/dnf hosts only.
def _automatic_conf_values(pkg_auto_output: str) -> dict[str, str]:
    """``/etc/dnf/automatic.conf`` as a ``{key: value}`` map; empty when the text is not an
    automatic.conf (no recognized key), which makes the control abstain."""
    values: dict[str, str] = {}
    for raw in pkg_auto_output.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";", "[")):
            continue
        key, sep, value = line.partition("=")
        if not sep:
            continue
        key = key.strip().lower()
        if key:
            values[key] = value.strip()
    if not any(k in values for k in ("apply_updates", "upgrade_type", "download_updates")):
        return {}
    return values


def parse_auto_updates_disabled(pkg_auto_output: str) -> bool | None:
    """Whether dnf-automatic is present but configured NOT to apply updates (``apply_updates = no``),
    or ``None`` to abstain when the directive/file is absent. The weakness is the affirmative
    configured-off state, so a host with no dnf-automatic abstains rather than reading as unpatched."""
    value = _automatic_conf_values(pkg_auto_output).get("apply_updates")
    return None if value is None else value.strip().lower() in _PKG_FALSEY


# ── systemctl is-enabled/is-active auditd (the Linux security audit log) ───────────────────────────
# Reads whether the host's security audit log (auditd) is running. The two queries are joined by a
# `===ACTIVE===` separator: the first (`is-enabled`) tells us the unit EXISTS and the second
# (`is-active`) whether it is running now. The weakness is a host that HAS auditd installed but is not
# running it (security logging effectively off). A host with no auditd unit at all ABSTAINS (returns
# None -> NOT_ASSESSED): it may ship logs through journald/rsyslog to a SIEM, so "no auditd" is
# unknowable here, not a finding. That abstain is why this never false-positives on such a host.
_AUDIT_SEPARATOR = "===ACTIVE==="
# `systemctl is-enabled` tokens that mean the unit is present (whether or not it starts at boot). Any
# of these proves auditd EXISTS, so a non-running one is a real "logging off", not an absent host.
_AUDIT_KNOWN_UNIT_TOKENS = frozenset(
    {
        "enabled",
        "enabled-runtime",
        "disabled",
        "static",
        "masked",
        "masked-runtime",
        "alias",
        "indirect",
        "generated",
        "linked",
        "linked-runtime",
        "transient",
    }
)
# Substrings `systemctl` prints when the unit does not exist, so the parser abstains instead of
# reading "no such unit" as a stopped daemon.
_AUDIT_ABSENT_MARKERS = (
    "no such file",
    "not-found",
    "could not be found",
    "failed to get unit file state",
    "command not found",
)


def parse_security_logging_enabled(audit_output: str) -> bool | None:
    """Whether the host's security audit log (auditd) is running, or ``None`` to abstain when auditd
    is not installed. Reads the joined ``is-enabled`` / ``is-active`` output: it abstains when the
    unit does not exist (absent markers, or no recognized ``is-enabled`` state), and otherwise returns
    whether the daemon is currently ``active``. So an installed-but-stopped auditd reads ``False``
    (security logging disabled -> a finding) and a running one ``True``; a host that ships logs some
    other way never reaches a verdict here."""
    enabled_part, _, active_part = audit_output.partition(_AUDIT_SEPARATOR)
    enabled_low = enabled_part.lower()
    if any(marker in enabled_low for marker in _AUDIT_ABSENT_MARKERS):
        return None
    if not any(token in _AUDIT_KNOWN_UNIT_TOKENS for token in enabled_low.split()):
        return None
    # Exact token match, so "inactive" (which contains "active") does not read as running.
    return "active" in active_part.lower().split()


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
    ("server.ssh.weak_macs", "ssh_weak_macs_offered"): (SOURCE_SSHD, parse_weak_macs_offered),
    ("server.ssh.weak_ciphers", "ssh_weak_ciphers_offered"): (
        SOURCE_SSHD,
        parse_weak_ciphers_offered,
    ),
    ("server.ssh.weak_kex", "ssh_weak_kex_offered"): (SOURCE_SSHD, parse_weak_kex_offered),
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
    ("server.sysctl.icmp_redirects_v6", "sysctl_icmp_redirects_v6_accepted"): (
        SOURCE_SYSCTL,
        parse_icmp_redirects_v6_accepted,
    ),
    ("server.sysctl.send_redirects", "sysctl_send_redirects_enabled"): (
        SOURCE_SYSCTL,
        parse_send_redirects_enabled,
    ),
    ("server.sysctl.syncookies", "sysctl_syncookies_disabled"): (
        SOURCE_SYSCTL,
        parse_syncookies_disabled,
    ),
    ("server.sysctl.aslr", "sysctl_aslr_disabled"): (
        SOURCE_SYSCTL,
        parse_aslr_disabled,
    ),
    ("server.account.extra_root", "account_extra_root_present"): (
        SOURCE_PASSWD,
        parse_extra_root_account,
    ),
    ("server.account.duplicate_uid", "account_duplicate_uid_present"): (
        SOURCE_PASSWD,
        parse_duplicate_uid,
    ),
    ("server.pkg.gpg_check", "pkg_gpg_check_disabled"): (
        SOURCE_PKG,
        parse_gpg_check_disabled,
    ),
    ("server.firewall.permissive", "firewall_permissive_default"): (
        SOURCE_FIREWALL,
        parse_firewall_permissive,
    ),
    ("server.pkg.auto_updates", "pkg_auto_updates_disabled"): (
        SOURCE_PKG_AUTO,
        parse_auto_updates_disabled,
    ),
    ("server.audit.security_logging_disabled", "security_audit_logging_enabled"): (
        SOURCE_AUDIT,
        parse_security_logging_enabled,
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
