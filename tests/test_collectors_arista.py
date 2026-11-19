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


def test_planted_config_serves_eapi_over_http() -> None:
    cfg = (_FIX / "ceos_running_config_planted.txt").read_text()
    assert arista.parse_unencrypted_api_enabled(cfg) is True


def test_clean_config_has_no_unencrypted_api() -> None:
    cfg = (_FIX / "ceos_running_config_clean.txt").read_text()
    assert arista.parse_unencrypted_api_enabled(cfg) is False


def test_default_eapi_is_https_and_not_flagged() -> None:
    cfg = "management api http-commands\n   no shutdown\n"
    assert arista.parse_unencrypted_api_enabled(cfg) is False


def test_explicit_https_eapi_is_not_flagged() -> None:
    cfg = "management api http-commands\n   protocol https\n   no shutdown\n"
    assert arista.parse_unencrypted_api_enabled(cfg) is False


def test_shutdown_http_api_is_not_enabled() -> None:
    cfg = "management api http-commands\n   protocol http\n   shutdown\n"
    assert arista.parse_unencrypted_api_enabled(cfg) is False


def test_planted_config_has_no_login_banner() -> None:
    cfg = (_FIX / "ceos_running_config_planted.txt").read_text()
    assert arista.parse_login_banner_absent(cfg) is True


def test_clean_config_has_a_login_banner() -> None:
    cfg = (_FIX / "ceos_running_config_clean.txt").read_text()
    assert arista.parse_login_banner_absent(cfg) is False


def test_a_configured_banner_is_detected() -> None:
    assert arista.parse_login_banner_absent("banner login\nAuthorized only.\nEOF\n") is False


def test_collect_control_fields_for_telnet() -> None:
    cfg = (_FIX / "ceos_running_config_planted.txt").read_text()
    fields = arista.collect_control_fields(cfg, "net.management.telnet")
    assert fields == {"management_protocols": ["ssh", "telnet"]}


def test_collect_control_fields_for_default_snmp_community() -> None:
    cfg = (_FIX / "ceos_running_config_planted.txt").read_text()
    fields = arista.collect_control_fields(cfg, "net.snmp.default_community")
    assert fields == {"default_snmp_community_present": True}


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


def test_collect_control_fields_for_unencrypted_api() -> None:
    cfg = (_FIX / "ceos_running_config_planted.txt").read_text()
    assert arista.collect_control_fields(cfg, "net.management.http_api_unencrypted") == {
        "unencrypted_api_enabled": True
    }


def test_collect_control_fields_for_login_banner() -> None:
    cfg = (_FIX / "ceos_running_config_planted.txt").read_text()
    assert arista.collect_control_fields(cfg, "net.management.no_login_banner") == {
        "login_banner_absent": True
    }


def test_collect_control_fields_for_unsupported_control_is_none() -> None:
    assert arista.collect_control_fields("hostname x\n", "server.ssh.password") is None
