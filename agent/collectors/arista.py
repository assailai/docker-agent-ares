"""Normalize an Arista EOS running-config into executable-control facts.

Read-only: the collector runs ``show running-config`` and this parser turns the text into the typed
fields the control plane's executable-control evaluator consumes. It ABSTAINS rather than invents a
value when the config does not clearly show a setting, so a control whose evidence is not in the
config stays NOT_ASSESSED rather than becoming a false posture claim.

Vendor-specific on purpose (Arista EOS): the config grammar differs per vendor, so each vendor has
its own parser, and the executable control is the single cross-vendor contract they all normalise
into. This is the EOS one; it covers the controls the §29.8 lane needs, and a new control is a new
field extractor here plus its evaluator entry (already present) on the control plane.
"""

from __future__ import annotations

import re

# EOS enables SSH management by default and leaves Telnet off until explicitly configured, so a
# `management telnet` block that is not shut down is a configured Telnet management transport.
_MGMT_SERVICE = re.compile(r"^management (ssh|telnet)$")
_TRANSPORT_INPUT = re.compile(r"^transport input (.+)$")
_MANAGEMENT_PROTOCOL_WORDS = frozenset({"ssh", "telnet"})


def _indented(line: str) -> bool:
    return line.startswith((" ", "\t"))


def parse_management_protocols(running_config: str) -> list[str]:
    """The management transports the EOS config leaves reachable (sorted, de-duplicated).

    Reads two independent signals and unions them: a global ``management ssh`` / ``management
    telnet`` block that is not ``shutdown``, and ``transport input ...`` on a management line. A
    protocol named by either is enabled.
    """
    protocols: set[str] = set()
    lines = running_config.splitlines()
    index = 0
    while index < len(lines):
        stripped = lines[index].strip()
        service = _MGMT_SERVICE.match(stripped)
        if service:
            protocol = service.group(1)
            shut = False
            index += 1
            while index < len(lines) and _indented(lines[index]):
                if lines[index].strip() == "shutdown":
                    shut = True
                index += 1
            if not shut:
                protocols.add(protocol)
            continue
        transport = _TRANSPORT_INPUT.match(stripped)
        if transport:
            for word in transport.group(1).split():
                if word in _MANAGEMENT_PROTOCOL_WORDS:
                    protocols.add(word)
        index += 1
    return sorted(protocols)


# Which control fields this parser can extract, and how. Each returns the field's typed value, or
# raises to signal the config did not show it (the collector then abstains for that field).
_FIELD_EXTRACTORS = {
    ("net.management.telnet", "management_protocols"): parse_management_protocols,
}


def collect_control_fields(running_config: str, control_id: str) -> dict[str, object] | None:
    """The typed field values this parser can read for ``control_id`` from an EOS config, or ``None``
    if the parser does not support that control (the collector then records it UNSUPPORTED)."""
    fields: dict[str, object] = {}
    for (ctrl, field), extractor in _FIELD_EXTRACTORS.items():
        if ctrl == control_id:
            fields[field] = extractor(running_config)
    return fields or None
