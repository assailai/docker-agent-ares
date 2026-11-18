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

# An interface block header, and a `switchport mode dynamic ...` line inside it. EOS leaves an access
# port with DTP enabled when the mode is `dynamic auto`/`dynamic desirable`, so a switched port left
# in a dynamic mode is negotiating trunking rather than being pinned to access.
_INTERFACE = re.compile(r"^interface (\S+)$")
_DYNAMIC_MODE = re.compile(r"^switchport mode dynamic (auto|desirable)$")

# An SNMP community declaration: `snmp-server community <name> [view <v>] [ro|rw] [<acl>]`. The
# community string is the first token after the keyword. The well-known factory defaults below are
# guessable from off the device, so a community that matches one is a default-credential weakness
# regardless of its read/write scope.
_SNMP_COMMUNITY = re.compile(r"^snmp-server community (\S+)")
_DEFAULT_SNMP_COMMUNITIES = frozenset({"public", "private"})

# A privileged enable secret and its storage encoding type: `enable (password|secret) <type> <hash>`.
# EOS/IOS type 0 is cleartext and type 7 is the reversible Vigenere cipher, both recoverable from the
# config; type 5 (MD5) and 8/9 (scrypt/pbkdf2) are one-way. A reversible secret in the config is a
# credential anyone who can read the config can recover.
_ENABLE_SECRET = re.compile(r"^enable (?:password|secret) (\d+) \S")
_REVERSIBLE_SECRET_TYPES = frozenset({"0", "7"})


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


def parse_dynamic_trunk_negotiation(running_config: str) -> bool:
    """True when any switched interface is left negotiating a trunk (DTP on a `dynamic` mode).

    Device-level for v1: the control is "dynamic trunk negotiation on an approved access-role port",
    and this returns whether ANY Ethernet interface is in `switchport mode dynamic auto|desirable`.
    Binding the verdict to the port's approved role (so an uplink that is meant to trunk is excluded)
    is the hardening the control's own limitation note names; here the role is not yet modelled, so a
    True means at least one switched port is negotiating, which an access-role port must not.
    """
    lines = running_config.splitlines()
    index = 0
    while index < len(lines):
        header = _INTERFACE.match(lines[index].strip())
        if header and header.group(1).lower().startswith("ethernet"):
            index += 1
            while index < len(lines) and _indented(lines[index]):
                if _DYNAMIC_MODE.match(lines[index].strip()):
                    return True
                index += 1
            continue
        index += 1
    return False


def parse_default_snmp_community_present(running_config: str) -> bool:
    """True when the EOS config configures a well-known default SNMP community (public/private).

    The running-config is complete evidence for this, so a device with no matching community line is
    a definite False (not an abstention): either no SNMP community is configured, or only
    non-default names are. The name is matched case-insensitively, since `Public` is just as
    guessable as `public`, even though SNMP treats the two as distinct strings.
    """
    for line in running_config.splitlines():
        match = _SNMP_COMMUNITY.match(line.strip())
        if match and match.group(1).lower() in _DEFAULT_SNMP_COMMUNITIES:
            return True
    return False


def parse_reversible_enable_secret(running_config: str) -> bool:
    """True when the privileged enable secret is stored with a reversible encoding (type 0 or 7).

    The running-config is complete evidence, so a device with no enable secret, or one stored with a
    one-way encoding (type 5/8/9), is a definite False rather than an abstention. A reversible secret
    is recoverable by anyone who can read the config, so its encoding type alone decides this.
    """
    for line in running_config.splitlines():
        match = _ENABLE_SECRET.match(line.strip())
        if match and match.group(1) in _REVERSIBLE_SECRET_TYPES:
            return True
    return False


# Which control fields this parser can extract, and how. Each returns the field's typed value, or
# raises to signal the config did not show it (the collector then abstains for that field).
_FIELD_EXTRACTORS = {
    ("net.management.telnet", "management_protocols"): parse_management_protocols,
    ("net.port.dynamic_trunk", "dynamic_trunk_negotiation"): parse_dynamic_trunk_negotiation,
    ("net.snmp.default_community", "default_snmp_community_present"): (
        parse_default_snmp_community_present
    ),
    ("net.management.weak_enable_secret", "reversible_enable_secret"): (
        parse_reversible_enable_secret
    ),
}


def collect_control_fields(running_config: str, control_id: str) -> dict[str, object] | None:
    """The typed field values this parser can read for ``control_id`` from an EOS config, or ``None``
    if the parser does not support that control (the collector then records it UNSUPPORTED)."""
    fields: dict[str, object] = {}
    for (ctrl, field), extractor in _FIELD_EXTRACTORS.items():
        if ctrl == control_id:
            fields[field] = extractor(running_config)
    return fields or None
