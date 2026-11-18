"""The Arista EOS parser normalizes a running-config into executable-control fields."""

from __future__ import annotations

from pathlib import Path

from agent.collectors import arista

_FIX = Path(__file__).with_name("fixtures")


def test_planted_config_shows_telnet_management() -> None:
    cfg = (_FIX / "ceos_running_config_planted.txt").read_text()
    assert arista.parse_management_protocols(cfg) == ["ssh", "telnet"]


def test_clean_config_has_no_telnet() -> None:
    cfg = (_FIX / "ceos_running_config_clean.txt").read_text()
    assert arista.parse_management_protocols(cfg) == ["ssh"]


def test_shutdown_management_telnet_is_not_enabled() -> None:
    cfg = "management telnet\n   shutdown\nmanagement ssh\n   no shutdown\n"
    assert arista.parse_management_protocols(cfg) == ["ssh"]


def test_transport_input_alone_is_enough() -> None:
    cfg = "line vty 0 4\n   transport input telnet\n"
    assert arista.parse_management_protocols(cfg) == ["telnet"]


def test_transport_input_none_adds_nothing() -> None:
    cfg = "line vty 0 4\n   transport input none\n"
    assert arista.parse_management_protocols(cfg) == []


def test_planted_config_has_a_dynamic_trunk_port() -> None:
    # Ethernet1 is left `switchport mode dynamic auto` (DTP on an access-intended port).
    cfg = (_FIX / "ceos_running_config_planted.txt").read_text()
    assert arista.parse_dynamic_trunk_negotiation(cfg) is True


def test_clean_config_has_no_dynamic_trunk_port() -> None:
    # Ethernet1 is pinned `switchport mode access` with `switchport nonegotiate`.
    cfg = (_FIX / "ceos_running_config_clean.txt").read_text()
    assert arista.parse_dynamic_trunk_negotiation(cfg) is False


def test_trunk_uplink_is_not_dynamic_negotiation() -> None:
    # A port explicitly pinned to trunk is not NEGOTIATING a trunk; only `dynamic` modes do.
    cfg = "interface Ethernet2\n   switchport mode trunk\n"
    assert arista.parse_dynamic_trunk_negotiation(cfg) is False


def test_planted_config_has_a_default_snmp_community() -> None:
    # core-switch is left with `snmp-server community public ro` (a factory-default community).
    cfg = (_FIX / "ceos_running_config_planted.txt").read_text()
    assert arista.parse_default_snmp_community_present(cfg) is True


def test_clean_config_uses_a_non_default_snmp_community() -> None:
    # edge-router configures a custom community, so no default is present.
    cfg = (_FIX / "ceos_running_config_clean.txt").read_text()
    assert arista.parse_default_snmp_community_present(cfg) is False


def test_no_snmp_community_configured_is_a_definite_false() -> None:
    # The running-config is complete evidence: no community line means no default community, not an
    # abstention.
    assert arista.parse_default_snmp_community_present("hostname x\n") is False


def test_default_snmp_community_is_matched_case_insensitively() -> None:
    # `Private` is as guessable as `private`, even though SNMP treats them as distinct strings.
    assert arista.parse_default_snmp_community_present("snmp-server community Private rw\n") is True


def test_snmp_community_with_view_and_acl_still_reads_the_name() -> None:
    cfg = "snmp-server community public view everything ro MGMT-ACL\n"
    assert arista.parse_default_snmp_community_present(cfg) is True


def test_collect_control_fields_for_telnet() -> None:
    cfg = (_FIX / "ceos_running_config_planted.txt").read_text()
    fields = arista.collect_control_fields(cfg, "net.management.telnet")
    assert fields == {"management_protocols": ["ssh", "telnet"]}


def test_collect_control_fields_for_dynamic_trunk() -> None:
    cfg = (_FIX / "ceos_running_config_planted.txt").read_text()
    fields = arista.collect_control_fields(cfg, "net.port.dynamic_trunk")
    assert fields == {"dynamic_trunk_negotiation": True}


def test_collect_control_fields_for_default_snmp_community() -> None:
    cfg = (_FIX / "ceos_running_config_planted.txt").read_text()
    fields = arista.collect_control_fields(cfg, "net.snmp.default_community")
    assert fields == {"default_snmp_community_present": True}


def test_collect_control_fields_for_unsupported_control_is_none() -> None:
    assert arista.collect_control_fields("hostname x\n", "server.ssh.password") is None
