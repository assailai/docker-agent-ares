"""`_partition_host_tiers` routes the host controls between the SSH (Linux) and WinRM (Windows) tiers by
credential kind. The one control both tiers serve, `server.localadmin.unapproved`, must go to exactly
one of them so it never gets double coverage; a Windows-only control always goes to the Windows tier
(which then reports UNAVAILABLE for a non-winrm credential)."""

from __future__ import annotations

from agent.main import _partition_host_tiers

_LINUX_ONLY = "server.ssh.password"  # SSH tier only
_WINDOWS_ONLY = "server.remote.rdp_nla_disabled"  # WinRM tier only
_BOTH = "server.localadmin.unapproved"  # served by both tiers; routed by credential kind


def test_localadmin_goes_to_winrm_for_a_windows_job() -> None:
    host_ids, windows_ids = _partition_host_tiers([_BOTH, _WINDOWS_ONLY], is_winrm=True)
    assert host_ids == []
    assert windows_ids == [_BOTH, _WINDOWS_ONLY]


def test_localadmin_goes_to_ssh_for_a_non_windows_job() -> None:
    host_ids, windows_ids = _partition_host_tiers([_BOTH, _WINDOWS_ONLY], is_winrm=False)
    assert host_ids == [_BOTH]
    # the Windows-only control still routes to the WinRM tier, which will report it UNAVAILABLE
    assert windows_ids == [_WINDOWS_ONLY]


def test_a_linux_only_control_always_stays_on_the_ssh_tier() -> None:
    for is_winrm in (True, False):
        host_ids, windows_ids = _partition_host_tiers([_LINUX_ONLY], is_winrm=is_winrm)
        assert host_ids == [_LINUX_ONLY]
        assert windows_ids == []


def test_a_mixed_job_splits_by_kind_with_no_overlap() -> None:
    controls = [_LINUX_ONLY, _BOTH, _WINDOWS_ONLY]
    win_host, win_win = _partition_host_tiers(controls, is_winrm=True)
    assert win_host == [_LINUX_ONLY]
    assert win_win == [_BOTH, _WINDOWS_ONLY]
    ssh_host, ssh_win = _partition_host_tiers(controls, is_winrm=False)
    assert ssh_host == [_LINUX_ONLY, _BOTH]
    assert ssh_win == [_WINDOWS_ONLY]
    # the shared control lands in exactly one tier in either case (never both)
    assert set(win_host) & set(win_win) == set()
    assert set(ssh_host) & set(ssh_win) == set()
