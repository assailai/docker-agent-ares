"""The virtualization collector reads whether ESXi host lockdown is enabled across the environment:
enabled only when every host is in a mode other than lockdownDisabled, so a single exposed host reads
as a finding, and no hosts abstains. The networked login+read (fetch_host_lockdown_modes) is exercised
live against a vcsim vCenter simulator in the accuracy lab; these tests pin the pure parsing."""

from __future__ import annotations

from agent.collectors import vsphere_collect


def test_all_hosts_disabled_reads_not_enabled() -> None:
    # The finding: lockdown off everywhere (vcsim's default state).
    modes = ["lockdownDisabled", "lockdownDisabled"]
    assert vsphere_collect.parse_host_lockdown_enabled(modes) is False


def test_all_hosts_locked_down_reads_enabled() -> None:
    assert vsphere_collect.parse_host_lockdown_enabled(["lockdownNormal", "lockdownStrict"]) is True


def test_a_single_exposed_host_makes_the_posture_not_enabled() -> None:
    # One host with lockdown disabled is a gap: the environment is not fully locked down.
    modes = ["lockdownNormal", "lockdownDisabled", "lockdownStrict"]
    assert vsphere_collect.parse_host_lockdown_enabled(modes) is False


def test_no_hosts_abstains() -> None:
    assert vsphere_collect.parse_host_lockdown_enabled([]) is None
    assert vsphere_collect.parse_host_lockdown_enabled(["", None]) is None
    assert vsphere_collect.parse_host_lockdown_enabled("lockdownDisabled") is None


def test_serves_and_field_dict() -> None:
    assert vsphere_collect.serves("virtualization.host.lockdown_disabled") is True
    assert vsphere_collect.serves("virtualization.mgmt.tls") is False  # a probe control, not this tier
    assert vsphere_collect.serves("server.ssh.password") is False
    assert vsphere_collect.host_lockdown_field(["lockdownDisabled"]) == {
        "host_lockdown_mode_enabled": False
    }
    assert vsphere_collect.host_lockdown_field([]) is None


# ── promiscuous mode (virtualization.network.promiscuous_allowed) ──────────────────────────────────
def test_promiscuous_allowed_when_any_segment_allows_it() -> None:
    # effective readings (inheritance already resolved by the fetch): one True anywhere is the finding.
    assert vsphere_collect.parse_promiscuous_allowed([False, False, True]) is True


def test_promiscuous_rejected_everywhere_is_clean() -> None:
    assert vsphere_collect.parse_promiscuous_allowed([False, False, False]) is False


def test_promiscuous_abstains_without_readings() -> None:
    assert vsphere_collect.parse_promiscuous_allowed([]) is None
    assert vsphere_collect.parse_promiscuous_allowed("nope") is None
    assert vsphere_collect.parse_promiscuous_allowed(["off"]) is None  # no bools -> abstain


def test_promiscuous_field_and_serves() -> None:
    assert vsphere_collect.serves("virtualization.network.promiscuous_allowed") is True
    assert vsphere_collect.promiscuous_allowed_field([True]) == {"promiscuous_mode_allowed": True}
    assert vsphere_collect.promiscuous_allowed_field([False]) == {"promiscuous_mode_allowed": False}
    assert vsphere_collect.promiscuous_allowed_field([]) is None


def test_allow_promiscuous_reads_the_security_policy() -> None:
    class _Sec:
        allowPromiscuous = True

    class _Pol:
        security = _Sec()

    class _Spec:
        policy = _Pol()

    assert vsphere_collect._allow_promiscuous(_Spec()) is True
    assert vsphere_collect._allow_promiscuous(None) is None
