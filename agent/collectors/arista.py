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
from collections.abc import Iterator

# EOS enables SSH management by default and leaves Telnet off until explicitly configured, so a
# `management telnet` block that is not shut down is a configured Telnet management transport.
_MGMT_SERVICE = re.compile(r"^management (ssh|telnet)$")
_TRANSPORT_INPUT = re.compile(r"^transport input (.+)$")
_MANAGEMENT_PROTOCOL_WORDS = frozenset({"ssh", "telnet"})

# An interface block header, used to walk each Ethernet interface's config block.
_INTERFACE = re.compile(r"^interface (\S+)$")

# An SNMP community declaration: `snmp-server community <name> [view <v>] [ro|rw] [<acl>]`. The
# community string is the first token after the keyword. The well-known factory defaults below are
# guessable from off the device, so a community that matches one is a default-credential weakness
# regardless of its read/write scope.
_SNMP_COMMUNITY = re.compile(r"^snmp-server community (\S+)")
_DEFAULT_SNMP_COMMUNITIES = frozenset({"public", "private"})



# BPDU guard protects an edge/access port from a rogue switch asserting a spanning-tree root. EOS
# applies it per-port with `spanning-tree bpduguard enable`, or fleet-wide to edge ports with a
# global `spanning-tree ... bpduguard default`. An access-mode port covered by neither is left
# unprotected against an L2 topology attack from the user edge.
_BPDUGUARD_DEFAULT = re.compile(r"^spanning-tree .*bpduguard default$")
_BPDUGUARD_ENABLE = re.compile(r"^spanning-tree bpduguard enable$")

# EOS does not render the default `switchport mode access`, so an access-mode port is identified
# by the ABSENCE of a routed (`no switchport`) or non-access mode (trunk / dynamic / dot1q-tunnel)
# marker in its block, not by a positive access line.
_NO_SWITCHPORT = re.compile(r"^no switchport$")
_SWITCHPORT_NONACCESS = re.compile(r"^switchport mode (?!access\b)")

# EOS secures an access port's MAC table with `switchport port-security` (optionally with a
# `maximum`, a violation action, or sticky learning). An access-mode port with no port-security
# line learns any MAC, so the user edge is open to MAC flooding and rogue hosts.
_PORT_SECURITY = re.compile(r"^switchport port-security")

# Remote syslog and NTP: a `logging host` / `logging vrf ... host` line ships logs off-box, and
# an `ntp server` line gives the device a time source. The absence of either is a posture gap:
# logs that never leave the device are lost on compromise or reboot, and an unsynchronized clock
# undermines log correlation and certificate checks.
_LOGGING_HOST = re.compile(r"^logging (?:vrf \S+ )?host \S")
_NTP_SERVER = re.compile(r"^ntp server ")
# A login banner: EOS renders a configured one as a `banner login` header line (its text
# follows, ending at an `EOF` terminator). Its absence is a posture/compliance gap.
_LOGIN_BANNER = re.compile(r"^banner login$")


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


def parse_snmp_write_community_present(running_config: str) -> bool:
    """True when any SNMPv1/v2c community grants read-write (rw) access.

    EOS renders `snmp-server community <name> [view <v>] [ro|rw] [<acl>]`; the access mode is a
    standalone token after the community name. A community with `rw` can change the device over SNMP,
    independent of how guessable its name is. The running-config is complete evidence, so a device
    with only read-only communities, or none, is a definite False.
    """
    for line in running_config.splitlines():
        stripped = line.strip()
        if stripped.startswith("snmp-server community ") and "rw" in stripped.split()[3:]:
            return True
    return False


def parse_remote_syslog_absent(running_config: str) -> bool:
    """True when no remote syslog host is configured, so logs never leave the device.

    The running-config is complete evidence: a device that binds any `logging host` (optionally in a
    vrf) is a definite False.
    """
    return not any(_LOGGING_HOST.match(line.strip()) for line in running_config.splitlines())


def parse_ntp_unconfigured(running_config: str) -> bool:
    """True when no NTP time source is configured, so the device clock is unsynchronized.

    The running-config is complete evidence: a device that configures any `ntp server` is a definite
    False.
    """
    return not any(_NTP_SERVER.match(line.strip()) for line in running_config.splitlines())


def parse_unencrypted_api_enabled(running_config: str) -> bool:
    """True when an enabled HTTP management API binds plaintext `protocol http`.

    EOS's `management api http-commands` defaults to HTTPS (no protocol line); a `protocol http`
    inside a block that is not shutdown serves eAPI over plaintext. The running-config is complete
    evidence, so a device with no management-api block, a shut one, or one on https only, is a
    definite False.
    """
    lines = running_config.splitlines()
    index = 0
    while index < len(lines):
        if lines[index].strip() == "management api http-commands":
            shut = False
            http = False
            index += 1
            while index < len(lines) and _indented(lines[index]):
                stripped = lines[index].strip()
                if stripped == "shutdown":
                    shut = True
                elif stripped == "protocol http" or stripped.startswith("protocol http "):
                    http = True
                index += 1
            if not shut and http:
                return True
            continue
        index += 1
    return False


def parse_login_banner_absent(running_config: str) -> bool:
    """True when no login banner is configured.

    EOS renders a configured banner as a `banner login` header line. The running-config is complete
    evidence, so a device with a `banner login` line is a definite False.
    """
    return not any(_LOGIN_BANNER.match(line.strip()) for line in running_config.splitlines())


def _ethernet_blocks(running_config: str) -> Iterator[list[str]]:
    """Yield the stripped body lines of each `interface EthernetN` block."""
    lines = running_config.splitlines()
    index = 0
    while index < len(lines):
        header = _INTERFACE.match(lines[index].strip())
        if header and header.group(1).lower().startswith("ethernet"):
            index += 1
            block: list[str] = []
            while index < len(lines) and _indented(lines[index]):
                block.append(lines[index].strip())
                index += 1
            yield block
            continue
        index += 1


def _is_access_port(block: list[str]) -> bool:
    """True when an Ethernet block is a switched access port.

    EOS omits the default `switchport mode access`, so a port is access unless it is routed
    (`no switchport`) or set to a non-access switchport mode (trunk / dynamic / dot1q-tunnel).
    """
    return not any(_NO_SWITCHPORT.match(line) or _SWITCHPORT_NONACCESS.match(line) for line in block)


def parse_access_port_without_bpduguard(running_config: str) -> bool:
    """True when a switched access port is covered by no BPDU guard.

    A global `spanning-tree ... bpduguard default` protects every edge port, so its presence makes
    this a definite False. Otherwise each access-mode Ethernet port must carry its own
    `spanning-tree bpduguard enable`; one that does not is unprotected. Access mode is EOS's default
    and is not rendered, so an access port is any switched Ethernet port (see `_is_access_port`). A
    device whose Ethernet ports are all routed or trunks has nothing to flag and is a definite False.
    """
    lines = running_config.splitlines()
    if any(_BPDUGUARD_DEFAULT.match(line.strip()) for line in lines):
        return False
    for block in _ethernet_blocks(running_config):
        if _is_access_port(block) and not any(_BPDUGUARD_ENABLE.match(line) for line in block):
            return True
    return False


def parse_access_port_without_port_security(running_config: str) -> bool:
    """True when a switched access port enables no MAC port security.

    Each access-mode Ethernet port must carry a `switchport port-security` line; one that does not
    learns any MAC on the user edge. Access mode is EOS's default and is not rendered, so an access
    port is any switched Ethernet port (see `_is_access_port`). A device whose Ethernet ports are all
    routed or trunks has nothing to flag and is a definite False.
    """
    for block in _ethernet_blocks(running_config):
        if _is_access_port(block) and not any(_PORT_SECURITY.match(line) for line in block):
            return True
    return False

# Which control fields this parser can extract, and how. Each returns the field's typed value, or
# raises to signal the config did not show it (the collector then abstains for that field).
_FIELD_EXTRACTORS = {
    ("net.management.telnet", "management_protocols"): parse_management_protocols,
    ("net.snmp.default_community", "default_snmp_community_present"): (
        parse_default_snmp_community_present
    ),
    ("net.snmp.write_community", "snmp_write_community_present"): (
        parse_snmp_write_community_present
    ),
    ("net.logging.no_remote_syslog", "remote_syslog_absent"): parse_remote_syslog_absent,
    ("net.ntp.no_ntp", "ntp_unconfigured"): parse_ntp_unconfigured,
    ("net.management.http_api_unencrypted", "unencrypted_api_enabled"): (
        parse_unencrypted_api_enabled
    ),
    ("net.management.no_login_banner", "login_banner_absent"): parse_login_banner_absent,
    ("net.l2.bpduguard_missing", "access_port_without_bpduguard"): (
        parse_access_port_without_bpduguard
    ),
    ("net.l2.port_security_missing", "access_port_without_port_security"): (
        parse_access_port_without_port_security
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


# --- LLDP neighbours (a second show command: `show lldp neighbors detail`) ------------------------
# Not a control field: topology evidence the control plane turns into adjacency edges. EOS prints one
# block per local interface, then one or more neighbours, each advertising a System Name, the peer's
# Port ID and (usually) a Management Address. The control plane keys an edge on that management
# address and excludes management-interface neighbours, so this parser reports every neighbour
# faithfully, the local interface included, and leaves the classification to the control plane.
_LLDP_INTERFACE = re.compile(r"^Interface (\S+) detected \d+ LLDP neighbor")
_LLDP_NEIGHBOR = re.compile(r"^Neighbor\b")
_LLDP_SYSTEM_NAME = re.compile(r'^System Name:\s*"?([^"]*?)"?\s*$')
_LLDP_PORT_ID = re.compile(r'^Port ID\s*:\s*"?([^"]*?)"?\s*$')
_LLDP_MGMT_ADDRESS = re.compile(r"^Management Address\s+:\s*(\S+)")


def parse_lldp_neighbours(lldp_output: str) -> list[dict[str, object]]:
    """The device's LLDP neighbours, one dict per neighbour: the local interface it was seen on and
    the peer's ``neighbour_id`` (system name), ``neighbour_interface`` (port id) and
    ``neighbour_address`` (management address, None when the peer advertised none).

    Parses ``show lldp neighbors detail``. A neighbour with no system name is skipped rather than
    reported as a nameless ghost. Management-vs-data-plane classification is the control plane's, so
    every interface's neighbours are reported here, the management interface included."""
    neighbours: list[dict[str, object]] = []
    local_interface: str | None = None
    current: dict[str, object] | None = None

    def flush() -> None:
        nonlocal current
        if current is not None and current.get("neighbour_id"):
            neighbours.append(current)
        current = None

    for raw in lldp_output.splitlines():
        line = raw.strip()
        if line.startswith("- "):  # a TLV marker line; drop the bullet so the key matches
            line = line[2:].strip()
        interface = _LLDP_INTERFACE.match(line)
        if interface:
            flush()
            local_interface = interface.group(1)
            continue
        if _LLDP_NEIGHBOR.match(line):
            flush()
            current = (
                {
                    "local_interface": local_interface,
                    "neighbour_id": "",
                    "neighbour_interface": None,
                    "neighbour_address": None,
                }
                if local_interface is not None
                else None
            )
            continue
        if current is None:
            continue
        name = _LLDP_SYSTEM_NAME.match(line)
        if name:
            current["neighbour_id"] = name.group(1)
            continue
        port = _LLDP_PORT_ID.match(line)
        if port and current["neighbour_interface"] is None:
            current["neighbour_interface"] = port.group(1)
            continue
        address = _LLDP_MGMT_ADDRESS.match(line)
        if address:
            current["neighbour_address"] = address.group(1)
    flush()
    return neighbours
