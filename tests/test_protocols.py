"""Passive protocol identification: identify from the service's bytes, never from the port."""

from __future__ import annotations

import pytest

from agent.protocols import identify_protocol


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
