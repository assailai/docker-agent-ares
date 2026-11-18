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


def test_collect_control_fields_for_telnet() -> None:
    cfg = (_FIX / "ceos_running_config_planted.txt").read_text()
    fields = arista.collect_control_fields(cfg, "net.management.telnet")
    assert fields == {"management_protocols": ["ssh", "telnet"]}


def test_collect_control_fields_for_unsupported_control_is_none() -> None:
    assert arista.collect_control_fields("hostname x\n", "server.ssh.password") is None
