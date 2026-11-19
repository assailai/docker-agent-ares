"""The vendor dispatch routes a running-config to the parser whose grammar it matches."""

from __future__ import annotations

from pathlib import Path

from agent.collectors import vendor

_FIX = Path(__file__).with_name("fixtures")


def test_frr_config_routes_to_the_frr_parser() -> None:
    # reversible_enable is an FRR-expressed control; the FRR parser returns it.
    cfg = (_FIX / "frr_running_config_planted.txt").read_text()
    assert vendor.collect_control_fields(cfg, "net.management.weak_enable_secret") == {
        "reversible_enable_secret": True
    }


def test_eos_config_routes_to_the_arista_parser() -> None:
    cfg = (_FIX / "ceos_running_config_planted.txt").read_text()
    assert vendor.collect_control_fields(cfg, "net.management.telnet") == {
        "management_protocols": ["ssh", "telnet"]
    }


def test_frr_grammar_is_not_parsed_as_arista() -> None:
    # A telnet (Arista) control is UNSUPPORTED on an FRR config: the FRR parser does not claim it.
    cfg = (_FIX / "frr_running_config_planted.txt").read_text()
    assert vendor.collect_control_fields(cfg, "net.management.telnet") is None


def test_neighbours_route_by_grammar() -> None:
    lldp = (_FIX / "ceos_lldp_neighbors_detail.txt").read_text()
    eos = (_FIX / "ceos_running_config_planted.txt").read_text()
    frr_cfg = (_FIX / "frr_running_config_planted.txt").read_text()
    # Arista exposes LLDP and parses its neighbours; FRR has no LLDP daemon, so it reports none.
    assert vendor.has_lldp(eos) and not vendor.has_lldp(frr_cfg)
    assert len(vendor.collect_neighbours(eos, lldp)) >= 2
    assert vendor.collect_neighbours(frr_cfg, lldp) == []
