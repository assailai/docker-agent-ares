"""The pcap capture module: BPF filter construction, the opt-in flag, and fail-soft when disabled.

The actual capture needs CAP_NET_RAW and a live fabric (proven in the lab), so these pin the pure,
safe-to-unit-test parts: the filter built from a verified scope, the opt-in gate that keeps the
default agent unchanged, and that a disabled capture launches nothing.
"""

from __future__ import annotations

import pytest

from agent import pcap_capture


def test_bpf_for_a_single_host() -> None:
    assert pcap_capture.bpf_for_targets(["10.0.0.12"]) == "host 10.0.0.12"


def test_bpf_for_a_cidr() -> None:
    assert pcap_capture.bpf_for_targets(["10.0.0.0/24"]) == "net 10.0.0.0/24"


def test_bpf_joins_multiple_and_drops_invalid() -> None:
    out = pcap_capture.bpf_for_targets(["10.0.0.12", "not-an-ip", "192.168.1.0/30"])
    assert out == "host 10.0.0.12 or net 192.168.1.0/30"


def test_bpf_is_none_when_no_valid_target() -> None:
    assert pcap_capture.bpf_for_targets(["nope", ""]) is None


@pytest.mark.parametrize(
    ("value", "expected"),
    [("1", True), ("true", True), ("YES", True), ("on", True), ("0", False), ("", False), ("no", False)],
)
def test_is_enabled_reads_the_flag(monkeypatch, value, expected) -> None:
    monkeypatch.setenv("ARES_ASSESSMENT_PCAP", value)
    assert pcap_capture.is_enabled() is expected


def test_is_enabled_is_false_when_unset(monkeypatch) -> None:
    monkeypatch.delenv("ARES_ASSESSMENT_PCAP", raising=False)
    assert pcap_capture.is_enabled() is False


async def test_start_launches_nothing_when_disabled(monkeypatch) -> None:
    monkeypatch.delenv("ARES_ASSESSMENT_PCAP", raising=False)
    # even with a valid target, a disabled capture returns None without touching the system.
    assert await pcap_capture.start(["10.0.0.12"]) is None


async def test_start_is_none_when_the_scope_is_empty(monkeypatch) -> None:
    monkeypatch.setenv("ARES_ASSESSMENT_PCAP", "1")
    assert await pcap_capture.start(["not-an-ip"]) is None
