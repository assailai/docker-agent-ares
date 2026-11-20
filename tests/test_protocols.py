"""Passive protocol identification: identify from the service's bytes, never from the port."""

from __future__ import annotations

import pytest

from agent.protocols import (
    FTP_FEAT_COMMAND,
    SMTP_EHLO_COMMAND,
    ftp_feat_features,
    ftp_supports_auth_tls,
    identify_protocol,
    smtp_ehlo_capabilities,
    smtp_supports_starttls,
)


@pytest.mark.parametrize(
    "banner,expected",
    [
        (b"\xff\xfd\x18\xff\xfd\x20", "telnet"),  # IAC DO ... negotiation
        (b"SSH-2.0-OpenSSH_9.6\r\n", "ssh"),
        (b"220 mail.example.com ESMTP Postfix\r\n", "smtp"),
        (b"220 FileZilla Server 1.2 FTP ready\r\n", "ftp"),
        (b"220-smtp greeting continues\r\n", "smtp"),  # multiline 220- form
        (b"@RSYNCD: 31.0\n", "rsync"),
        (b"", None),  # nothing read: abstain (an OPEN-but-silent port, e.g. a quiet TCP/119)
        (b"HTTP/1.1 200 OK\r\n", None),  # not a passive management protocol here
        (b"220 just a welcome with no protocol word\r\n", None),  # ambiguous 220: abstain
        (b"\x00\x01\x02", None),  # binary noise
        # §29.8 regression fixtures, locked at the classifier:
        (b"220 (vsFTPd 3.0.5)\r\n", "ftp"),  # anonymous-FTP greeting (vsFTPd contains "FTP")
        (b"220 ProFTPD 1.3.8 Server ready\r\n", "ftp"),
        (b"200 news.example.com NNTP Service Ready\r\n", None),  # NNTP: not a passive specialist, abstain
        (b"+OK POP3 ready\r\n", None),  # POP3 200-class greeting is not a 220: abstain, do not guess
        (b"SSH-2.0-OpenSSH_9.6", "ssh"),  # SSH identification with no trailing CRLF yet
    ],
)
def test_identify_protocol(banner: bytes, expected: str | None) -> None:
    assert identify_protocol(banner) == expected


def test_a_silent_open_port_never_becomes_a_protocol() -> None:
    # The honesty rule: a port that answers with nothing distinctive stays OPEN with no protocol_id,
    # never a port-number guess. This is the open-but-silent TCP/119 regression in fixture form.
    assert identify_protocol(b"") is None


def test_telnet_iac_outranks_a_later_ascii_word() -> None:
    # A telnet negotiation that happens to carry "FTP"-ish bytes later is still telnet: IAC wins.
    assert identify_protocol(b"\xff\xfd\x18 FTP") == "telnet"


def test_a_telnet_port_with_an_ssh_banner_is_ssh_not_telnet() -> None:
    # The port is never consulted: telnet-on-23 that actually answers with an SSH id is SSH.
    assert identify_protocol(b"SSH-2.0-Dropbear\r\n") == "ssh"


# ── active specialists: SMTP EHLO (STARTTLS) and FTP FEAT (AUTH TLS) ───────────


def test_the_specialist_commands_are_bounded_metadata_only() -> None:
    # EHLO and FEAT only: never DATA / MAIL / RCPT / STOR, so nothing is delivered or written.
    assert SMTP_EHLO_COMMAND == b"EHLO ares-assessment.invalid\r\n"
    assert FTP_FEAT_COMMAND == b"FEAT\r\n"


def test_smtp_ehlo_reports_starttls_when_advertised() -> None:
    reply = (
        b"250-mail.example.com\r\n"
        b"250-PIPELINING\r\n"
        b"250-SIZE 10485760\r\n"
        b"250-STARTTLS\r\n"
        b"250 AUTH PLAIN LOGIN\r\n"
    )
    caps = smtp_ehlo_capabilities(reply)
    assert {"PIPELINING", "SIZE", "STARTTLS", "AUTH"} <= caps
    assert smtp_supports_starttls(reply) is True


def test_smtp_ehlo_without_starttls_is_a_read_negative_not_an_abstention() -> None:
    reply = b"250-mail.example.com\r\n250-PIPELINING\r\n250 AUTH PLAIN LOGIN\r\n"
    caps = smtp_ehlo_capabilities(reply)
    assert caps  # a reply WAS read and parsed
    assert "STARTTLS" not in caps
    assert smtp_supports_starttls(reply) is False


def test_smtp_ehlo_abstains_on_an_unreadable_or_error_reply() -> None:
    assert smtp_ehlo_capabilities(b"") == frozenset()
    assert smtp_ehlo_capabilities(b"\x00\x01\x02") == frozenset()
    # a 5xx rejection is not a 250 capability line, so nothing is read as a capability
    assert smtp_ehlo_capabilities(b"502 command not implemented\r\n") == frozenset()
    assert smtp_supports_starttls(b"") is False


def test_ftp_feat_reports_auth_tls_when_advertised() -> None:
    reply = (
        b"211-Features:\r\n"
        b" AUTH TLS\r\n"
        b" EPSV\r\n"
        b" UTF8\r\n"
        b"211 End\r\n"
    )
    features = ftp_feat_features(reply)
    assert "AUTH TLS" in features
    assert "UTF8" in features
    assert "211 END" not in {f for f in features}  # the framing line is not a feature
    assert ftp_supports_auth_tls(reply) is True


def test_ftp_feat_without_auth_tls_is_a_read_negative() -> None:
    reply = b"211-Features:\r\n EPSV\r\n UTF8\r\n MLST\r\n211 End\r\n"
    features = ftp_feat_features(reply)
    assert features
    assert ftp_supports_auth_tls(reply) is False


def test_ftp_feat_recognises_auth_ssl_too() -> None:
    assert ftp_supports_auth_tls(b"211-Features:\r\n AUTH SSL\r\n211 End\r\n") is True


def test_ftp_feat_abstains_on_an_error_or_empty_reply() -> None:
    assert ftp_feat_features(b"") == frozenset()
    assert ftp_feat_features(b"500 FEAT not understood\r\n") == frozenset()
    assert ftp_supports_auth_tls(b"500 FEAT not understood\r\n") is False
