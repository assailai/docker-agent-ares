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
        (b"", None),  # nothing read: abstain
        (b"HTTP/1.1 200 OK\r\n", None),  # not a passive management protocol here
        (b"220 just a welcome with no protocol word\r\n", None),  # ambiguous 220: abstain
        (b"\x00\x01\x02", None),  # binary noise
    ],
)
def test_identify_protocol(banner: bytes, expected: str | None) -> None:
    assert identify_protocol(banner) == expected


def test_a_telnet_port_with_an_ssh_banner_is_ssh_not_telnet() -> None:
    # The port is never consulted: telnet-on-23 that actually answers with an SSH id is SSH.
    assert identify_protocol(b"SSH-2.0-Dropbear\r\n") == "ssh"
