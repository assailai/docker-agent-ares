"""The mail host collector normalizes a Postfix ``main.cf`` into the host-readable ``mail.*`` facts:
whether SMTP AUTH is offered without TLS (legacy auth) and whether inbound TLS is enforced, abstaining
whenever the directive is not set in main.cf (it may live on the submission service in master.cf)."""

from __future__ import annotations

from pathlib import Path

from agent.collectors import mail_host

_FIX = Path(__file__).with_name("fixtures")


def test_plaintext_sasl_auth_reads_legacy_enabled() -> None:
    # AUTH enabled and not restricted to TLS (smtpd_tls_auth_only = no): legacy plaintext auth.
    cfg = (_FIX / "postfix_legacy_auth.txt").read_text()
    assert mail_host.parse_mail_legacy_auth_enabled(cfg) is True


def test_tls_only_sasl_auth_passes() -> None:
    cfg = (_FIX / "postfix_hardened.txt").read_text()
    assert mail_host.parse_mail_legacy_auth_enabled(cfg) is False


def test_disabled_sasl_auth_is_not_legacy() -> None:
    assert (
        mail_host.parse_mail_legacy_auth_enabled(
            "myhostname = mail.x\nsmtpd_sasl_auth_enable = no\n"
        )
        is False
    )


def test_inbound_tls_enforced_only_for_encrypt() -> None:
    assert mail_host.parse_mail_inbound_tls_enforced((_FIX / "postfix_hardened.txt").read_text()) is True
    assert mail_host.parse_mail_inbound_tls_enforced((_FIX / "postfix_legacy_auth.txt").read_text()) is False


def test_continuation_lines_do_not_break_later_directives() -> None:
    # mynetworks spans two lines (a leading-whitespace continuation); the sasl directive after it must
    # still parse. This guards the continuation-folding in _postfix_values.
    cfg = (_FIX / "postfix_legacy_auth.txt").read_text()
    assert "10.0.0.0/24" in cfg  # the continuation line is present in the fixture
    assert mail_host.parse_mail_legacy_auth_enabled(cfg) is True


def test_abstains_when_directive_absent_or_not_postfix() -> None:
    # A real main.cf that does not set the directive abstains (it may be on the submission service in
    # master.cf), and unrelated text abstains too.
    assert mail_host.parse_mail_legacy_auth_enabled("myhostname = mail.x\n") is None
    assert mail_host.parse_mail_inbound_tls_enforced("myhostname = mail.x\n") is None
    assert mail_host.parse_mail_legacy_auth_enabled("hello world\n") is None


def test_routing_and_collection() -> None:
    assert mail_host.serves("mail.auth.legacy") is True
    assert mail_host.serves("mail.tls.inbound_not_enforced") is True
    assert mail_host.serves("server.ssh.password") is False
    assert mail_host.source_for("mail.auth.legacy") == mail_host.SOURCE_POSTFIX
    sources = {mail_host.SOURCE_POSTFIX: "myhostname = x\nsmtpd_tls_security_level = encrypt\n"}
    assert mail_host.collect_control_fields(sources, "mail.tls.inbound_not_enforced") == {
        "inbound_tls_enforced": True
    }
    assert mail_host.collect_control_fields(sources, "net.management.telnet") is None


# ── postfix lifecycle (mail.lifecycle.unsupported_gateway) ─────────────────────────────────────────
def test_mail_eol_counts_a_version_below_the_floor() -> None:
    assert mail_host.parse_mail_eol_count("3.5.0") == 1  # below 3.6 -> EOL
    assert mail_host.parse_mail_eol_count("2.11.0") == 1  # old major -> EOL


def test_mail_eol_supported_version_reads_zero() -> None:
    assert mail_host.parse_mail_eol_count("3.7.11") == 0  # the lab's version, still supported
    assert mail_host.parse_mail_eol_count("3.6.0") == 0  # exactly at the floor
    assert mail_host.parse_mail_eol_count("3.9.1") == 0


def test_mail_eol_abstains_on_unreadable_version() -> None:
    assert mail_host.parse_mail_eol_count("") is None
    assert mail_host.parse_mail_eol_count("not a version") is None


def test_mail_lifecycle_served_and_field() -> None:
    assert mail_host.serves("mail.lifecycle.unsupported_gateway") is True
    fields = mail_host.collect_control_fields(
        {"postfix_version": "3.5.9"}, "mail.lifecycle.unsupported_gateway"
    )
    assert fields == {"end_of_life_mail_components": 1}
