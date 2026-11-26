"""Normalize a Postfix mail server's ``main.cf`` into executable-control facts (the host-readable
slice of the mail cohort).

Read-only: reads ``/etc/postfix/main.cf`` over the same SSH transport the other host collectors use,
and parses it into the ``mail.*`` fields a Postfix server's own config proves. Like every host
collector it ABSTAINS rather than invents: a directive the file does not set is left out (it may be
configured on the submission service in ``master.cf`` this read does not cover, or left at a compiled
default), so the control stays NOT_ASSESSED rather than a false posture claim.

Only Postfix, and only what ``main.cf`` proves, lives here. ``mail.relay.config`` (open-relay) is NOT
here: detecting an open relay from the restriction lists alone is false-positive-prone, and the honest
test is an active relay probe (Controlled Validation), not a config read. The SPF/DMARC/MTA-STS/DKIM
posture controls are DNS and tenant-policy facts, not host config, and the mailbox-audit/forwarding/
antiphish controls are cloud-mail-tenant APIs. All of those stay DESIGNED.
"""

from __future__ import annotations

# The evidence source this collector reads, and the ssh_collect reader that produces it.
SOURCE_POSTFIX = "postfix_maincf"

SOURCE_READERS = {SOURCE_POSTFIX: "collect_postfix_main_cf"}

# Directives that mark the text as a genuine Postfix main.cf, so unrelated bytes abstain.
_POSTFIX_MARKERS = (
    "myhostname",
    "mydestination",
    "inet_interfaces",
    "mynetworks",
    "relayhost",
    "smtpd_tls_security_level",
    "smtpd_sasl_auth_enable",
)


def _postfix_values(postfix_main_cf: str) -> dict[str, str]:
    """``main.cf`` as a ``{key: value}`` map, keys lower-cased, comments dropped and continuation
    lines (a line beginning with whitespace continues the previous value) folded in. Returns an empty
    map when the text is not a Postfix main.cf (no recognized directive), which makes every field
    abstain."""
    values: dict[str, str] = {}
    current_key: str | None = None
    for raw in postfix_main_cf.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        # A leading-whitespace line continues the previous directive's value (Postfix syntax).
        if raw[0].isspace() and current_key is not None:
            values[current_key] = f"{values[current_key]} {raw.strip()}".strip()
            continue
        key, sep, rest = raw.partition("=")
        if not sep:
            continue
        current_key = key.strip().lower()
        values[current_key] = rest.strip()
    if not any(marker in values for marker in _POSTFIX_MARKERS):
        return {}
    return values


def parse_mail_legacy_auth_enabled(postfix_main_cf: str) -> bool | None:
    """Whether SMTP AUTH is offered without requiring TLS (legacy plaintext auth), or ``None`` to
    abstain when ``smtpd_sasl_auth_enable`` is not set in ``main.cf`` (AUTH may be enabled only on the
    submission service in ``master.cf``, which this read does not cover). ``True`` when AUTH is enabled
    (``smtpd_sasl_auth_enable = yes``) and not restricted to TLS (``smtpd_tls_auth_only`` is not
    ``yes``); ``False`` when AUTH is explicitly disabled or restricted to TLS."""
    values = _postfix_values(postfix_main_cf)
    sasl_enabled = values.get("smtpd_sasl_auth_enable")
    if sasl_enabled is None:
        return None
    if sasl_enabled.lower() != "yes":
        return False
    return values.get("smtpd_tls_auth_only", "no").lower() != "yes"


def parse_mail_inbound_tls_enforced(postfix_main_cf: str) -> bool | None:
    """Whether inbound TLS is enforced (``smtpd_tls_security_level = encrypt``), or ``None`` to abstain
    when the directive is not set (the level may be configured on the submission service in
    ``master.cf``, or left at a compiled default this file read cannot see). ``True`` only for
    ``encrypt``; ``none``/``may`` read ``False`` (opportunistic or no TLS, not enforced)."""
    level = _postfix_values(postfix_main_cf).get("smtpd_tls_security_level")
    if level is None:
        return None
    return level.lower() == "encrypt"


# One entry per (control_id, field): the evidence source it reads and the extractor.
_FIELD_EXTRACTORS = {
    ("mail.auth.legacy", "legacy_smtp_auth_enabled"): (
        SOURCE_POSTFIX,
        parse_mail_legacy_auth_enabled,
    ),
    ("mail.tls.inbound_not_enforced", "inbound_tls_enforced"): (
        SOURCE_POSTFIX,
        parse_mail_inbound_tls_enforced,
    ),
}


def _extractors_for(control_id: str) -> list[tuple[str, str, object]]:
    """The ``(field, source, extractor)`` entries this parser has for ``control_id``."""
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
    ``None`` if it does not serve that control. A field whose extractor abstains is left out."""
    supported = _extractors_for(control_id)
    if not supported:
        return None
    fields: dict[str, object] = {}
    for field, source, extractor in supported:
        value = extractor(sources.get(source, ""))
        if value is not None:
            fields[field] = value
    return fields
