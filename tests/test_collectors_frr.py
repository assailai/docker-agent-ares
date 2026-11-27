"""The FRR (vtysh) parser normalizes a Cisco-IOS-style running-config into executable-control fields.

Fixtures are the real `vtysh show running-config` of the lab's FRR nodes, not an assumed grammar.
"""

from __future__ import annotations

from pathlib import Path

from agent.collectors import frr

_FIX = Path(__file__).with_name("fixtures")


def test_planted_frr_stores_a_cleartext_enable_secret() -> None:
    # frr-access keeps `enable password weak-lab-secret` in cleartext (no service password-encryption).
    cfg = (_FIX / "frr_running_config_planted.txt").read_text()
    assert frr.parse_reversible_enable_secret(cfg) is True


def test_clean_frr_has_no_enable_secret() -> None:
    cfg = (_FIX / "frr_running_config_clean.txt").read_text()
    assert frr.parse_reversible_enable_secret(cfg) is False


def test_frr_type8_enable_secret_is_one_way() -> None:
    # FRR's `service password-encryption` renders type 8, which is one-way, not recoverable.
    assert frr.parse_reversible_enable_secret("enable password 8 0HfJqaD6ZTZ9w\n") is False


def test_frr_type7_enable_secret_is_reversible() -> None:
    assert frr.parse_reversible_enable_secret("enable password 7 00071A150754\n") is True


def test_planted_frr_binds_no_vty_access_class() -> None:
    # frr-access binds no access-class anywhere, so the management plane is unrestricted.
    cfg = (_FIX / "frr_running_config_planted.txt").read_text()
    assert frr.parse_unrestricted_management_source(cfg) is True


def test_clean_frr_binds_a_vty_access_class() -> None:
    # frr-edge binds `access-class vty-mgmt` under line vty.
    cfg = (_FIX / "frr_running_config_clean.txt").read_text()
    assert frr.parse_unrestricted_management_source(cfg) is False


def test_collect_control_fields_for_reversible_enable() -> None:
    cfg = (_FIX / "frr_running_config_planted.txt").read_text()
    fields = frr.collect_control_fields(cfg, "net.management.weak_enable_secret")
    assert fields == {"reversible_enable_secret": True}


def test_collect_control_fields_for_unrestricted_source() -> None:
    cfg = (_FIX / "frr_running_config_planted.txt").read_text()
    fields = frr.collect_control_fields(cfg, "net.management.unrestricted_source")
    assert fields == {"unrestricted_management_source": True}


def test_collect_control_fields_for_unsupported_control_is_none() -> None:
    cfg = (_FIX / "frr_running_config_planted.txt").read_text()
    assert frr.collect_control_fields(cfg, "net.snmp.default_community") is None
