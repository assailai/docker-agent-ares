"""Passive protocol identification from a service's opening bytes (PR-08, the specialists).

Honesty rule, carried from the spec: a protocol is identified from what the SERVICE emits, never
from the port number. Port 23 open is not telnet; a telnet IAC negotiation on it is. So these
detectors read only the banner the server sends first and match on its distinctive bytes; a service
that answers with nothing distinctive stays unidentified (``None``), which the result records as an
OPEN service with no ``protocol_id`` rather than a guess.

``identify_protocol`` is pure: bytes in, a protocol id or ``None`` out. The bounded read that
produces those bytes lives in the agent's discover handler, so this stays trivially testable from
fixtures and carries no network or timing behaviour. Only the passive, server-speaks-first
protocols are here (telnet, SSH, FTP, SMTP, rsync); the active follow-ups the §29.8 fixtures also
name (SMTP EHLO, FTP FEAT/SYST, a bounded DNS query) are a later refinement.
"""

from __future__ import annotations

# telnet negotiates with IAC (Interpret As Command, 0xFF) option commands the instant a client
# connects, so a banner that opens with IAC is telnet and nothing else passive looks like it.
_IAC = 0xFF

# How many opening bytes are distinctive enough to classify. The handler reads a bounded banner; we
# only ever look at its head, so a larger read never changes the verdict.
_HEAD = 256


def identify_protocol(banner: bytes) -> str | None:
    """The protocol a service's opening ``banner`` identifies it as, or ``None`` to abstain.

    Deterministic and port-blind: the same bytes always yield the same answer, and a service is
    never labelled from the port it happened to answer on. Abstains (``None``) on empty or
    non-distinctive bytes, which the discover result then carries as an OPEN service with no
    ``protocol_id``.
    """
    if not banner:
        return None
    if banner[0] == _IAC:
        return "telnet"
    head = banner[:_HEAD]
    if head.startswith(b"SSH-"):
        return "ssh"
    if head.startswith(b"@RSYNCD:"):
        return "rsync"
    # SMTP and FTP both greet with a 3-digit "220 ..." line, so the code alone cannot tell them
    # apart: disambiguate on the greeting's own words, and abstain if it names neither.
    if head[:3] == b"220" and head[3:4] in (b" ", b"-"):
        upper = head.upper()
        if b"SMTP" in upper:  # covers "SMTP" and "ESMTP"
            return "smtp"
        if b"FTP" in upper:
            return "ftp"
    return None
