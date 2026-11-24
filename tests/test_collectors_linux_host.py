"""The Linux-host parser normalizes an ``sshd -T`` effective-config dump into executable-control
fields, and abstains (never guesses) when a directive is absent or the text is not a dump."""

from __future__ import annotations

from pathlib import Path

from agent.collectors import linux_host

_FIX = Path(__file__).with_name("fixtures")


def _planted() -> str:
    return (_FIX / "sshd_effective_planted.txt").read_text()


def _clean() -> str:
    return (_FIX / "sshd_effective_clean.txt").read_text()


def test_planted_dump_reads_every_weak_setting() -> None:
    cfg = _planted()
    assert linux_host.parse_password_authentication(cfg) is True
    assert linux_host.parse_root_login_permitted(cfg) is True
    assert linux_host.parse_permit_empty_passwords(cfg) is True
    assert linux_host.parse_x11_forwarding_enabled(cfg) is True
    assert linux_host.parse_max_auth_tries(cfg) == 6


def test_clean_dump_reads_every_hardened_setting() -> None:
    cfg = _clean()
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


def test_a_missing_directive_abstains() -> None:
    # Markers are present (a real dump) but these specific directives are not: abstain, do not guess.
    dump = "passwordauthentication yes\npermitrootlogin no\nmaxauthtries 4\n"
    assert linux_host.parse_x11_forwarding_enabled(dump) is None
    assert linux_host.parse_permit_empty_passwords(dump) is None


def test_non_numeric_max_auth_tries_abstains() -> None:
    assert linux_host.parse_max_auth_tries("maxauthtries none\npermitrootlogin no\n") is None


def test_text_that_is_not_a_dump_abstains_on_every_field() -> None:
    # No recognizable directive markers: not an sshd -T dump (an error line, an empty read). Every
    # field abstains rather than reading a value out of unrelated bytes.
    not_a_dump = "bash: sshd: command not found\n"
    assert linux_host.parse_password_authentication(not_a_dump) is None
    assert linux_host.parse_root_login_permitted(not_a_dump) is None
    assert linux_host.parse_max_auth_tries(not_a_dump) is None


def test_directive_names_are_case_insensitive() -> None:
    # sshd -T lower-cases directive names, but accept a capitalised capture defensively.
    assert linux_host.parse_password_authentication("PasswordAuthentication yes\nmaxauthtries 6\n") is True


def test_collect_control_fields_reads_the_planted_controls() -> None:
    cfg = _planted()
    assert linux_host.collect_control_fields(cfg, "server.ssh.password") == {
        "ssh_password_authentication": True
    }
    assert linux_host.collect_control_fields(cfg, "server.ssh.root_login") == {
        "ssh_root_login_permitted": True
    }
    assert linux_host.collect_control_fields(cfg, "server.ssh.max_auth_tries") == {
        "ssh_max_auth_tries": 6
    }


def test_collect_control_fields_for_an_unsupported_control_returns_none() -> None:
    # A control this host parser does not serve (a network control) is UNSUPPORTED, not a guess.
    assert linux_host.collect_control_fields(_planted(), "net.management.telnet") is None
    assert linux_host.collect_control_fields(_planted(), "server.ssh.unknown") is None


def test_collect_control_fields_abstains_field_by_field() -> None:
    # The dump is valid but omits the x11 directive: the control is still collected, with its field
    # left out, so it evaluates NOT_ASSESSED rather than on a guessed value.
    dump = "passwordauthentication yes\npermitrootlogin no\nmaxauthtries 6\n"
    assert linux_host.collect_control_fields(dump, "server.ssh.x11_forwarding") == {}


def test_serves_only_the_host_prefix() -> None:
    assert linux_host.serves("server.ssh.password") is True
    assert linux_host.serves("server.ssh.root_login") is True
    assert linux_host.serves("net.management.telnet") is False
    assert linux_host.serves("server.firewall.enabled") is False
