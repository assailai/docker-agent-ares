"""The Linux-host parser normalizes read-only config dumps (``sshd -T``, ``sysctl -a``) into
executable-control fields, routing each control to its source and abstaining (never guessing) when a
setting is absent or the text is not the expected dump."""

from __future__ import annotations

from pathlib import Path

from agent.collectors import linux_host

_FIX = Path(__file__).with_name("fixtures")


def _sshd_planted() -> str:
    return (_FIX / "sshd_effective_planted.txt").read_text()


def _sshd_clean() -> str:
    return (_FIX / "sshd_effective_clean.txt").read_text()


def _sysctl_planted() -> str:
    return (_FIX / "sysctl_planted.txt").read_text()


def _sysctl_clean() -> str:
    return (_FIX / "sysctl_clean.txt").read_text()


# ── sshd -T ───────────────────────────────────────────────────────────────────────────────────────
def test_planted_dump_reads_every_weak_setting() -> None:
    cfg = _sshd_planted()
    assert linux_host.parse_password_authentication(cfg) is True
    assert linux_host.parse_root_login_permitted(cfg) is True
    assert linux_host.parse_permit_empty_passwords(cfg) is True
    assert linux_host.parse_x11_forwarding_enabled(cfg) is True
    assert linux_host.parse_max_auth_tries(cfg) == 6


def test_clean_dump_reads_every_hardened_setting() -> None:
    cfg = _sshd_clean()
    assert linux_host.parse_password_authentication(cfg) is False
    assert linux_host.parse_root_login_permitted(cfg) is False
    assert linux_host.parse_permit_empty_passwords(cfg) is False
    assert linux_host.parse_x11_forwarding_enabled(cfg) is False
    assert linux_host.parse_max_auth_tries(cfg) == 3


def test_prohibit_password_root_login_is_not_flagged() -> None:
    # A hardened host that still allows key-based root login must NOT read as "root login permitted".
    assert linux_host.parse_root_login_permitted("permitrootlogin prohibit-password\n") is False
    assert linux_host.parse_root_login_permitted("permitrootlogin without-password\n") is False
    assert linux_host.parse_root_login_permitted("permitrootlogin forced-commands-only\n") is False


def test_a_missing_sshd_directive_abstains() -> None:
    # Markers are present (a real dump) but these specific directives are not: abstain, do not guess.
    dump = "passwordauthentication yes\npermitrootlogin no\nmaxauthtries 4\n"
    assert linux_host.parse_x11_forwarding_enabled(dump) is None
    assert linux_host.parse_permit_empty_passwords(dump) is None


def test_non_numeric_max_auth_tries_abstains() -> None:
    assert linux_host.parse_max_auth_tries("maxauthtries none\npermitrootlogin no\n") is None


def test_text_that_is_not_an_sshd_dump_abstains_on_every_field() -> None:
    not_a_dump = "bash: sshd: command not found\n"
    assert linux_host.parse_password_authentication(not_a_dump) is None
    assert linux_host.parse_root_login_permitted(not_a_dump) is None
    assert linux_host.parse_max_auth_tries(not_a_dump) is None


def test_directive_names_are_case_insensitive() -> None:
    assert (
        linux_host.parse_password_authentication("PasswordAuthentication yes\nmaxauthtries 6\n")
        is True
    )


# ── sysctl -a ─────────────────────────────────────────────────────────────────────────────────────
def test_planted_sysctl_reads_every_weak_setting() -> None:
    cfg = _sysctl_planted()
    assert linux_host.parse_ip_forwarding_enabled(cfg) is True
    assert linux_host.parse_source_route_accepted(cfg) is True
    assert linux_host.parse_icmp_redirects_accepted(cfg) is True


def test_clean_sysctl_reads_every_hardened_setting() -> None:
    cfg = _sysctl_clean()
    assert linux_host.parse_ip_forwarding_enabled(cfg) is False
    assert linux_host.parse_source_route_accepted(cfg) is False
    assert linux_host.parse_icmp_redirects_accepted(cfg) is False


def test_a_missing_sysctl_key_abstains() -> None:
    # A real sysctl dump (ostype marker present) that omits a key abstains on that control.
    dump = "kernel.ostype = Linux\nnet.ipv4.ip_forward = 0\n"
    assert linux_host.parse_source_route_accepted(dump) is None
    assert linux_host.parse_icmp_redirects_accepted(dump) is None
    assert linux_host.parse_ip_forwarding_enabled(dump) is False


def test_text_that_is_not_a_sysctl_dump_abstains() -> None:
    assert linux_host.parse_ip_forwarding_enabled("sysctl: command not found\n") is None


# ── routing + collection ───────────────────────────────────────────────────────────────────────────
def test_source_routing_maps_each_control_to_one_source() -> None:
    assert linux_host.source_for("server.ssh.password") == linux_host.SOURCE_SSHD
    assert linux_host.source_for("server.sysctl.ip_forwarding") == linux_host.SOURCE_SYSCTL
    assert linux_host.source_for("net.management.telnet") is None


def test_sources_for_collects_each_needed_source_once() -> None:
    needed = linux_host.sources_for(
        ["server.ssh.password", "server.ssh.root_login", "server.sysctl.ip_forwarding"]
    )
    assert needed == {linux_host.SOURCE_SSHD, linux_host.SOURCE_SYSCTL}
    assert linux_host.sources_for(["net.management.telnet"]) == set()


def test_collect_control_fields_reads_from_the_right_source() -> None:
    sources = {
        linux_host.SOURCE_SSHD: _sshd_planted(),
        linux_host.SOURCE_SYSCTL: _sysctl_planted(),
    }
    assert linux_host.collect_control_fields(sources, "server.ssh.max_auth_tries") == {
        "ssh_max_auth_tries": 6
    }
    assert linux_host.collect_control_fields(sources, "server.sysctl.ip_forwarding") == {
        "sysctl_ip_forwarding_enabled": True
    }
    assert linux_host.collect_control_fields(sources, "server.sysctl.source_route") == {
        "sysctl_source_route_accepted": True
    }


def test_collect_control_fields_for_an_unsupported_control_returns_none() -> None:
    sources = {linux_host.SOURCE_SSHD: _sshd_planted()}
    assert linux_host.collect_control_fields(sources, "net.management.telnet") is None
    assert linux_host.collect_control_fields(sources, "server.ssh.unknown") is None


def test_collect_control_fields_abstains_field_by_field() -> None:
    # The dump is valid but omits the x11 directive: the control is still collected, with its field
    # left out, so it evaluates NOT_ASSESSED rather than on a guessed value.
    sources = {linux_host.SOURCE_SSHD: "passwordauthentication yes\npermitrootlogin no\nmaxauthtries 6\n"}
    assert linux_host.collect_control_fields(sources, "server.ssh.x11_forwarding") == {}


def test_collect_control_fields_abstains_when_its_source_is_absent() -> None:
    # A sysctl control asked for with only the sshd source present: no sysctl text, so it abstains.
    assert linux_host.collect_control_fields(
        {linux_host.SOURCE_SSHD: _sshd_planted()}, "server.sysctl.ip_forwarding"
    ) == {}


def test_serves_only_host_controls() -> None:
    assert linux_host.serves("server.ssh.password") is True
    assert linux_host.serves("server.sysctl.ip_forwarding") is True
    assert linux_host.serves("net.management.telnet") is False
    assert linux_host.serves("server.firewall.enabled") is False
