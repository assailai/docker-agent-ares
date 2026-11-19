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


def test_planted_config_stores_a_reversible_enable_secret() -> None:
    # core-switch keeps `enable password 7 ...` (the reversible Vigenere encoding).
    cfg = (_FIX / "ceos_running_config_planted.txt").read_text()
    assert arista.parse_reversible_enable_secret(cfg) is True


def test_clean_config_uses_a_one_way_enable_secret() -> None:
    # edge-router stores `enable secret 5 ...` (MD5, not reversible).
    cfg = (_FIX / "ceos_running_config_clean.txt").read_text()
    assert arista.parse_reversible_enable_secret(cfg) is False


def test_cleartext_enable_secret_is_reversible() -> None:
    # type 0 is cleartext in the config, which is reversible by definition.
    assert arista.parse_reversible_enable_secret("enable secret 0 letmein\n") is True


def test_no_enable_secret_is_a_definite_false() -> None:
    assert arista.parse_reversible_enable_secret("hostname x\n") is False


def test_strong_enable_secret_without_a_type_digit_is_not_reversible() -> None:
    # `enable secret sha512 $6$...` names an algorithm, not a reversible type number.
    assert arista.parse_reversible_enable_secret("enable secret sha512 $6$abc$def\n") is False


def test_planted_config_has_an_unrestricted_management_line() -> None:
    # the planted switches' vty binds no source access-class.
    cfg = (_FIX / "ceos_running_config_planted.txt").read_text()
    assert arista.parse_unrestricted_management_source(cfg) is True


def test_clean_config_restricts_the_management_source() -> None:
    # edge-router's vty binds `ip access-class MGMT-IN in`.
    cfg = (_FIX / "ceos_running_config_clean.txt").read_text()
    assert arista.parse_unrestricted_management_source(cfg) is False


def test_a_vty_without_an_access_class_is_unrestricted() -> None:
    cfg = "line vty 0 31\n   transport input ssh\n"
    assert arista.parse_unrestricted_management_source(cfg) is True


def test_no_vty_block_has_no_management_line_to_flag() -> None:
    assert arista.parse_unrestricted_management_source("hostname x\n") is False


def test_one_unrestricted_vty_among_restricted_ones_still_flags() -> None:
    cfg = (
        "line vty 0 4\n   ip access-class MGMT-IN in\n"
        "line vty 5 15\n   transport input ssh\n"
    )
    assert arista.parse_unrestricted_management_source(cfg) is True


def test_planted_config_has_an_unprotected_access_port() -> None:
    # Ethernet3 is `switchport mode access` with no `spanning-tree bpduguard enable` and no global
    # default, so the user edge is unprotected against a rogue switch asserting spanning-tree root.
    cfg = (_FIX / "ceos_running_config_planted.txt").read_text()
    assert arista.parse_access_port_without_bpduguard(cfg) is True


def test_clean_config_protects_its_access_port_with_bpduguard() -> None:
    # edge-router's access port carries `spanning-tree bpduguard enable`.
    cfg = (_FIX / "ceos_running_config_clean.txt").read_text()
    assert arista.parse_access_port_without_bpduguard(cfg) is False


def test_global_bpduguard_default_protects_every_access_port() -> None:
    # A fleet-wide edge-port default covers access ports without a per-port line.
    cfg = "spanning-tree edge-port bpduguard default\ninterface Ethernet5\n   switchport mode access\n"
    assert arista.parse_access_port_without_bpduguard(cfg) is False


def test_a_routed_or_trunk_only_device_has_no_access_port_to_flag() -> None:
    cfg = "interface Ethernet1\n   switchport mode trunk\ninterface Ethernet2\n   no switchport\n"
    assert arista.parse_access_port_without_bpduguard(cfg) is False


def test_per_port_bpduguard_enable_protects_that_access_port() -> None:
    cfg = "interface Ethernet7\n   switchport mode access\n   spanning-tree bpduguard enable\n"
    assert arista.parse_access_port_without_bpduguard(cfg) is False


def test_planted_config_has_an_access_port_without_port_security() -> None:
    # Ethernet3 is `switchport mode access` with no `switchport port-security` line.
    cfg = (_FIX / "ceos_running_config_planted.txt").read_text()
    assert arista.parse_access_port_without_port_security(cfg) is True


def test_clean_config_secures_its_access_port_mac_table() -> None:
    # edge-router's access port carries `switchport port-security`.
    cfg = (_FIX / "ceos_running_config_clean.txt").read_text()
    assert arista.parse_access_port_without_port_security(cfg) is False


def test_port_security_with_a_maximum_still_counts_as_secured() -> None:
    cfg = "interface Ethernet9\n   switchport mode access\n   switchport port-security maximum 2\n"
    assert arista.parse_access_port_without_port_security(cfg) is False


def test_a_routed_or_trunk_only_device_has_no_access_port_for_port_security() -> None:
    cfg = "interface Ethernet1\n   switchport mode trunk\ninterface Ethernet2\n   no switchport\n"
    assert arista.parse_access_port_without_port_security(cfg) is False


def test_planted_config_has_a_write_community() -> None:
    cfg = (_FIX / "ceos_running_config_planted.txt").read_text()
    assert arista.parse_snmp_write_community_present(cfg) is True


def test_clean_config_has_no_write_community() -> None:
    cfg = (_FIX / "ceos_running_config_clean.txt").read_text()
    assert arista.parse_snmp_write_community_present(cfg) is False


def test_read_only_community_is_not_a_write_community() -> None:
    assert arista.parse_snmp_write_community_present("snmp-server community public ro\n") is False


def test_a_community_named_with_rw_is_not_a_write_community() -> None:
    # the access mode is a standalone token; a name containing 'rw' must not false-positive.
    assert arista.parse_snmp_write_community_present("snmp-server community brworks ro\n") is False


def test_planted_config_has_no_remote_syslog() -> None:
    cfg = (_FIX / "ceos_running_config_planted.txt").read_text()
    assert arista.parse_remote_syslog_absent(cfg) is True


def test_clean_config_has_remote_syslog() -> None:
    cfg = (_FIX / "ceos_running_config_clean.txt").read_text()
    assert arista.parse_remote_syslog_absent(cfg) is False


def test_logging_host_in_a_vrf_counts_as_configured() -> None:
    assert arista.parse_remote_syslog_absent("logging vrf MGMT host 10.0.0.1\n") is False


def test_planted_config_has_no_ntp() -> None:
    cfg = (_FIX / "ceos_running_config_planted.txt").read_text()
    assert arista.parse_ntp_unconfigured(cfg) is True


def test_clean_config_has_ntp() -> None:
    cfg = (_FIX / "ceos_running_config_clean.txt").read_text()
    assert arista.parse_ntp_unconfigured(cfg) is False


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


def test_collect_control_fields_for_weak_enable_secret() -> None:
    cfg = (_FIX / "ceos_running_config_planted.txt").read_text()
    fields = arista.collect_control_fields(cfg, "net.management.weak_enable_secret")
    assert fields == {"reversible_enable_secret": True}


def test_collect_control_fields_for_unrestricted_management_source() -> None:
    cfg = (_FIX / "ceos_running_config_planted.txt").read_text()
    fields = arista.collect_control_fields(cfg, "net.management.unrestricted_source")
    assert fields == {"unrestricted_management_source": True}


def test_collect_control_fields_for_bpduguard_missing() -> None:
    cfg = (_FIX / "ceos_running_config_planted.txt").read_text()
    fields = arista.collect_control_fields(cfg, "net.l2.bpduguard_missing")
    assert fields == {"access_port_without_bpduguard": True}


def test_collect_control_fields_for_port_security_missing() -> None:
    cfg = (_FIX / "ceos_running_config_planted.txt").read_text()
    fields = arista.collect_control_fields(cfg, "net.l2.port_security_missing")
    assert fields == {"access_port_without_port_security": True}


def test_collect_control_fields_for_snmp_write_community() -> None:
    cfg = (_FIX / "ceos_running_config_planted.txt").read_text()
    fields = arista.collect_control_fields(cfg, "net.snmp.write_community")
    assert fields == {"snmp_write_community_present": True}


def test_collect_control_fields_for_remote_syslog() -> None:
    cfg = (_FIX / "ceos_running_config_planted.txt").read_text()
    assert arista.collect_control_fields(cfg, "net.logging.no_remote_syslog") == {
        "remote_syslog_absent": True
    }


def test_collect_control_fields_for_ntp() -> None:
    cfg = (_FIX / "ceos_running_config_planted.txt").read_text()
    assert arista.collect_control_fields(cfg, "net.ntp.no_ntp") == {"ntp_unconfigured": True}


def test_collect_control_fields_for_unsupported_control_is_none() -> None:
    assert arista.collect_control_fields("hostname x\n", "server.ssh.password") is None
