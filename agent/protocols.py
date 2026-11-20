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


# ── active specialists: one bounded, read-only command, then parse the reply ──────────────────────
#
# Unlike identify_protocol these describe an ACTIVE probe: the agent sends one metadata command (an
# SMTP EHLO, an FTP FEAT) and reads the capability reply. The spec bounds this hard: EHLO never DATA,
# FEAT/SYST never a write, so nothing is delivered and no state changes. The functions here are the
# PURE half (reply bytes in, a capability set out); the socket write that produces those bytes lives
# in the discover handler, so this stays trivially testable from fixtures. The honesty rule mirrors
# identify_protocol: a reply the agent cannot parse yields an EMPTY set (abstain), never a confident
# "capability absent", so a missing STARTTLS is only ever asserted from a reply we actually read.

# The command line each specialist sends. EHLO takes a client name; a bare, non-routable literal is
# used so the probe reveals nothing about the agent's host and asks only for the capability list.
SMTP_EHLO_COMMAND = b"EHLO ares-assessment.invalid\r\n"
FTP_FEAT_COMMAND = b"FEAT\r\n"


def _reply_lines(reply: bytes) -> list[str]:
    """Decode a bounded multiline reply into text lines, tolerant of a server's odd bytes: a line
    that will not decode is dropped rather than raising, since this is untrusted remote output."""
    try:
        text = reply.decode("ascii", "ignore")
    except (UnicodeDecodeError, ValueError):
        return []
    return [line.rstrip("\r") for line in text.split("\n") if line.strip()]


def smtp_ehlo_capabilities(reply: bytes) -> frozenset[str]:
    """The ESMTP capability keywords an EHLO reply advertised, uppercased (e.g. ``STARTTLS``,
    ``AUTH``, ``PIPELINING``). A multiline ``250-CAP`` / ``250 CAP`` reply; a line that is not a 250
    response contributes nothing, and an unreadable or non-EHLO reply yields an empty set, never a
    false claim that a capability is absent.

    The FIRST 250 line is the server's greeting (its domain/identification), not a capability, so it
    is skipped: capability keywords begin on the second 250 line. A real reply opens with
    ``250-mail.example.com`` and that host name must not land in the capability set."""
    reply_250 = [
        line
        for line in _reply_lines(reply)
        if len(line) >= 4 and line[:3] == "250" and line[3] in (" ", "-")
    ]
    capabilities: set[str] = set()
    for line in reply_250[1:]:  # skip the greeting line
        token = line[4:].strip().split()
        if token:
            capabilities.add(token[0].upper())
    return frozenset(capabilities)


def smtp_supports_starttls(reply: bytes) -> bool:
    """Whether the EHLO reply advertised STARTTLS. False means "not advertised in a reply we read",
    which the caller pairs with the fact that it DID read one, so an unread reply is never a finding."""
    return "STARTTLS" in smtp_ehlo_capabilities(reply)


def ftp_feat_features(reply: bytes) -> frozenset[str]:
    """The feature tokens an FTP ``FEAT`` reply listed, uppercased. FEAT frames the list between
    ``211-Features:`` and ``211 End`` with each feature on its own indented line; the ``211`` framing
    lines are not features. An unreadable or error reply yields an empty set (abstain)."""
    features: set[str] = set()
    for line in _reply_lines(reply):
        stripped = line.strip()
        if not stripped or stripped[:3] == "211" or stripped[:3] == "500":
            continue
        features.add(stripped.upper())
    return frozenset(features)


def ftp_supports_auth_tls(reply: bytes) -> bool:
    """Whether FEAT advertised AUTH TLS or AUTH SSL (FTPS over the control channel). The absence of
    this in a reply we read is what makes a reachable FTP service a cleartext-credentials finding."""
    return any(
        feature.startswith("AUTH") and ("TLS" in feature or "SSL" in feature)
        for feature in ftp_feat_features(reply)
    )
