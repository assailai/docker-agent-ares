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


def test_weak_ssh_algorithms_are_flagged_and_modern_ones_pass() -> None:
    assert linux_host.parse_weak_macs_offered("macs hmac-sha1,hmac-sha2-256\nmaxauthtries 6\n") is True
    assert (
        linux_host.parse_weak_macs_offered(
            "macs hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com\npermitrootlogin no\n"
        )
        is False
    )
    assert linux_host.parse_weak_ciphers_offered("ciphers aes128-cbc,aes256-ctr\nmaxauthtries 6\n") is True
    assert (
        linux_host.parse_weak_ciphers_offered(
            "ciphers aes256-gcm@openssh.com,chacha20-poly1305@openssh.com\npermitrootlogin no\n"
        )
        is False
    )
    assert (
        linux_host.parse_weak_kex_offered(
            "kexalgorithms diffie-hellman-group14-sha1,curve25519-sha256\nmaxauthtries 6\n"
        )
        is True
    )
    assert (
        linux_host.parse_weak_kex_offered(
            "kexalgorithms curve25519-sha256,ecdh-sha2-nistp256\npermitrootlogin no\n"
        )
        is False
    )


def test_weak_algorithm_directive_absent_abstains() -> None:
    # A real dump (marker present) that omits the algorithm directive abstains rather than guessing.
    assert linux_host.parse_weak_macs_offered("permitrootlogin no\nmaxauthtries 6\n") is None
    assert linux_host.parse_weak_kex_offered("permitrootlogin no\nmaxauthtries 6\n") is None


# ── sysctl -a ─────────────────────────────────────────────────────────────────────────────────────
def test_planted_sysctl_reads_every_weak_setting() -> None:
    cfg = _sysctl_planted()
    assert linux_host.parse_ip_forwarding_enabled(cfg) is True
    assert linux_host.parse_source_route_accepted(cfg) is True
    assert linux_host.parse_icmp_redirects_accepted(cfg) is True
    assert linux_host.parse_icmp_redirects_v6_accepted(cfg) is True
    assert linux_host.parse_send_redirects_enabled(cfg) is True
    assert linux_host.parse_syncookies_disabled(cfg) is True
    assert linux_host.parse_aslr_disabled(cfg) is True


def test_clean_sysctl_reads_every_hardened_setting() -> None:
    cfg = _sysctl_clean()
    assert linux_host.parse_ip_forwarding_enabled(cfg) is False
    assert linux_host.parse_source_route_accepted(cfg) is False
    assert linux_host.parse_icmp_redirects_accepted(cfg) is False
    assert linux_host.parse_icmp_redirects_v6_accepted(cfg) is False
    assert linux_host.parse_send_redirects_enabled(cfg) is False
    assert linux_host.parse_syncookies_disabled(cfg) is False
    assert linux_host.parse_aslr_disabled(cfg) is False


def test_aslr_partially_randomized_still_reads_as_weak() -> None:
    # randomize_va_space 1 randomizes less than full (2); the weakness is any value below 2.
    weak = "kernel.ostype = Linux\nkernel.randomize_va_space = 1\n"
    full = "kernel.ostype = Linux\nkernel.randomize_va_space = 2\n"
    assert linux_host.parse_aslr_disabled(weak) is True
    assert linux_host.parse_aslr_disabled(full) is False


# ── /etc/dnf/dnf.conf ─────────────────────────────────────────────────────────────────────────────
def test_dnf_gpgcheck_off_is_flagged_and_on_passes() -> None:
    planted = (_FIX / "dnf_conf_planted.txt").read_text()
    clean = (_FIX / "dnf_conf_clean.txt").read_text()
    assert linux_host.parse_gpg_check_disabled(planted) is True
    assert linux_host.parse_gpg_check_disabled(clean) is False


def test_dnf_gpgcheck_absent_abstains() -> None:
    # A real dnf.conf (the [main] header marks it) that omits gpgcheck abstains rather than assume.
    assert linux_host.parse_gpg_check_disabled("[main]\ninstallonly_limit=3\n") is None


def test_text_that_is_not_a_dnf_conf_abstains() -> None:
    missing = "cat: /etc/dnf/dnf.conf: No such file or directory\n"
    assert linux_host.parse_gpg_check_disabled(missing) is None


def test_a_missing_sysctl_key_abstains() -> None:
    # A real sysctl dump (ostype marker present) that omits a key abstains on that control.
    dump = "kernel.ostype = Linux\nnet.ipv4.ip_forward = 0\n"
    assert linux_host.parse_source_route_accepted(dump) is None
    assert linux_host.parse_icmp_redirects_accepted(dump) is None
    assert linux_host.parse_ip_forwarding_enabled(dump) is False


def test_text_that_is_not_a_sysctl_dump_abstains() -> None:
    assert linux_host.parse_ip_forwarding_enabled("sysctl: command not found\n") is None


# ── getent passwd ───────────────────────────────────────────────────────────────────────────────
_PASSWD_PLANTED = (
    "root:x:0:0:root:/root:/bin/bash\n"
    "backdoor:x:0:0::/root:/bin/bash\n"  # a second uid-0 account: a root-equivalent backdoor
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    "alice:x:1000:1000::/home/alice:/bin/bash\n"
    "bob:x:1000:1001::/home/bob:/bin/bash\n"  # shares uid 1000 with alice
)
_PASSWD_CLEAN = (
    "root:x:0:0:root:/root:/bin/bash\n"
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    "alice:x:1000:1000::/home/alice:/bin/bash\n"
    "bob:x:1001:1001::/home/bob:/bin/bash\n"
)


def test_planted_passwd_flags_extra_root_and_duplicate_uid() -> None:
    assert linux_host.parse_extra_root_account(_PASSWD_PLANTED) is True
    assert linux_host.parse_duplicate_uid(_PASSWD_PLANTED) is True


def test_clean_passwd_has_one_root_and_unique_uids() -> None:
    assert linux_host.parse_extra_root_account(_PASSWD_CLEAN) is False
    assert linux_host.parse_duplicate_uid(_PASSWD_CLEAN) is False


def test_passwd_without_a_root_line_abstains() -> None:
    # Not a real passwd dump (no uid-0 root line): abstain rather than read accounts out of it.
    assert linux_host.parse_extra_root_account("getent: command not found\n") is None
    assert linux_host.parse_duplicate_uid("alice:x:1000:1000::/home/alice:/bin/bash\n") is None


# ── routing + collection ───────────────────────────────────────────────────────────────────────────
def test_source_routing_maps_each_control_to_one_source() -> None:
    assert linux_host.source_for("server.ssh.password") == linux_host.SOURCE_SSHD
    assert linux_host.source_for("server.sysctl.ip_forwarding") == linux_host.SOURCE_SYSCTL
    assert linux_host.source_for("server.sysctl.send_redirects") == linux_host.SOURCE_SYSCTL
    assert linux_host.source_for("server.account.extra_root") == linux_host.SOURCE_PASSWD
    assert linux_host.source_for("server.pkg.gpg_check") == linux_host.SOURCE_PKG
    assert linux_host.source_for("net.management.telnet") is None


def test_sources_for_collects_each_needed_source_once() -> None:
    needed = linux_host.sources_for(
        [
            "server.ssh.password",
            "server.sysctl.ip_forwarding",
            "server.account.extra_root",
            "server.pkg.gpg_check",
        ]
    )
    assert needed == {
        linux_host.SOURCE_SSHD,
        linux_host.SOURCE_SYSCTL,
        linux_host.SOURCE_PASSWD,
        linux_host.SOURCE_PKG,
    }
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
