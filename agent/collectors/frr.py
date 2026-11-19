"""Normalize an FRRouting (vtysh) running-config into executable-control facts.

Read-only: the collector runs `vtysh -c 'show running-config'` and this parser turns the Cisco-IOS-
style text into the typed fields the control plane's executable-control evaluator consumes. FRR is
the Cisco-syntax device in the cohort, carrying controls real Arista EOS cannot express: a
recoverable enable secret and a management line with no source access-class.

Vendor-specific on purpose: FRR's vtysh grammar differs from Arista EOS, so it has its own parser,
and the executable control is the single cross-vendor contract they both normalise into. This parser
was written against a real FRR 10.2 `show running-config`, not an assumed grammar.
"""

from __future__ import annotations

import re

# An enable secret and its storage encoding. FRR renders a cleartext secret verbatim with no type
# digit, an encrypted one as `enable password <N> <hash>`. Cleartext (no type) and type 0/7 are
# recoverable from the config; FRR's `service password-encryption` type 8 and types 5/9 are one-way.
_ENABLE_SECRET = re.compile(r"^enable (?:password|secret)(?: (\d+))? \S")
_REVERSIBLE_SECRET_TYPES = frozenset({"0", "7"})

# A vty source restriction: `access-class <acl>` bound under a management line. FRR omits an empty
# `line vty`, so an unrestricted management plane is the ABSENCE of any access-class binding, not the
# presence of an unrestricted block.
_ACCESS_CLASS = re.compile(r"^access-class \S+")


def parse_reversible_enable_secret(running_config: str) -> bool:
    """True when an enable secret is stored in a recoverable form (cleartext, or type 0/7).

    FRR renders a cleartext secret with no type digit, which is the most recoverable; an encrypted
    one carries its type. The running-config is complete evidence, so a device with no enable secret,
    or one stored one-way (type 5/8/9), is a definite False.
    """
    for line in running_config.splitlines():
        match = _ENABLE_SECRET.match(line.strip())
        if match and (match.group(1) is None or match.group(1) in _REVERSIBLE_SECRET_TYPES):
            return True
    return False


def parse_unrestricted_management_source(running_config: str) -> bool:
    """True when no management line binds a source access-class, leaving it reachable from anywhere.

    FRR omits an empty `line vty`, so the fault is the ABSENCE of an `access-class` binding rather
    than the presence of an unrestricted block. The running-config is complete evidence: a device
    that binds an access-class anywhere is a definite False.
    """
    return not any(_ACCESS_CLASS.match(line.strip()) for line in running_config.splitlines())


# Which control fields this parser can extract, and how. Each returns the field's typed value.
_FIELD_EXTRACTORS = {
    ("net.management.weak_enable_secret", "reversible_enable_secret"): (
        parse_reversible_enable_secret
    ),
    ("net.management.unrestricted_source", "unrestricted_management_source"): (
        parse_unrestricted_management_source
    ),
}


def collect_control_fields(running_config: str, control_id: str) -> dict[str, object] | None:
    """The typed field values this parser can read for ``control_id`` from an FRR config, or ``None``
    if the parser does not support that control (the collector then records it UNSUPPORTED)."""
    fields: dict[str, object] = {}
    for (ctrl, field), extractor in _FIELD_EXTRACTORS.items():
        if ctrl == control_id:
            fields[field] = extractor(running_config)
    return fields or None
