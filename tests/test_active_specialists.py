"""The active-specialist dispatch in the discover handler (PR-08 sub-slice 4c).

The transport (`_probe_specialist`) is monkeypatched, so these pin the dispatch logic: an identified
SMTP service is enriched from its EHLO reply, an FTP service from its FEAT reply, the result is
sorted/deterministic, and a service with no specialist is NEVER written to (the honesty + safety
rule: the active probe touches only SMTP and FTP, and only after identification).
"""

from __future__ import annotations

import pytest

from agent import main, protocols


async def test_an_smtp_service_is_enriched_with_its_ehlo_capabilities(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _probe(ip: str, port: int, command: bytes, *, timeout: float) -> bytes:
        assert command == protocols.SMTP_EHLO_COMMAND  # EHLO, never DATA
        return b"250-mail.example.com\r\n250-STARTTLS\r\n250 AUTH PLAIN LOGIN\r\n"

    monkeypatch.setattr(main, "_probe_specialist", _probe)
    caps = await main._specialist_capabilities("10.0.0.1", 25, "smtp", timeout=1.0)
    assert "STARTTLS" in caps
    assert "AUTH" in caps
    assert caps == tuple(sorted(caps))  # deterministic ordering on the observation


async def test_an_ftp_service_is_enriched_with_its_feat_features(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _probe(ip: str, port: int, command: bytes, *, timeout: float) -> bytes:
        assert command == protocols.FTP_FEAT_COMMAND  # FEAT, never a write
        return b"211-Features:\r\n AUTH TLS\r\n EPSV\r\n211 End\r\n"

    monkeypatch.setattr(main, "_probe_specialist", _probe)
    caps = await main._specialist_capabilities("10.0.0.1", 21, "ftp", timeout=1.0)
    assert "AUTH TLS" in caps


async def test_a_service_with_no_specialist_is_never_written_to(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    probed = False

    async def _probe(ip: str, port: int, command: bytes, *, timeout: float) -> bytes:
        nonlocal probed
        probed = True
        return b""

    monkeypatch.setattr(main, "_probe_specialist", _probe)
    # an unidentified port and a non-enriched protocol both skip the active probe entirely
    assert await main._specialist_capabilities("10.0.0.1", 80, None, timeout=1.0) == ()
    assert await main._specialist_capabilities("10.0.0.1", 22, "ssh", timeout=1.0) == ()
    assert probed is False, "no command may be sent to a protocol with no specialist"


async def test_an_empty_specialist_reply_yields_no_capabilities(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _probe(ip: str, port: int, command: bytes, *, timeout: float) -> bytes:
        return b""  # the service did not answer the metadata command

    monkeypatch.setattr(main, "_probe_specialist", _probe)
    # abstain, never a confident "no STARTTLS": an empty reply is no observation
    assert await main._specialist_capabilities("10.0.0.1", 25, "smtp", timeout=1.0) == ()
