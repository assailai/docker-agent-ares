"""The agent's CA trust: what it discovers, what it refuses to be fooled by, and the two call
sites that must keep using it.

The bug these guard against is subtle enough to have cost a customer a week. httpx given
``verify=True`` verifies against certifi's bundle *inside site-packages* and ignores the OS trust
store, so an operator can install their corporate root in the container, watch ``urllib`` succeed,
and still have every agent request fail. The regression tests at the bottom are the ones that
matter most: they assert the agent hands httpx and websockets an explicit context, not a bare
``True``.
"""

from __future__ import annotations

import logging
import ssl
from pathlib import Path

import pytest
import trustme

from agent import control_plane, tlsconf
from agent.config import Settings


@pytest.fixture(autouse=True)
def _isolate_trust(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Point discovery at tmp_path and drop the cache, so tests never see the real /host-ca
    (or each other's contexts, which lru_cache would happily hand back)."""
    host_ca = tmp_path / "host-ca"
    extra = tmp_path / "certs"
    monkeypatch.setattr(tlsconf, "HOST_CA_DIR", host_ca)
    monkeypatch.setattr(tlsconf, "EXTRA_CA_DIR", extra)
    tlsconf.build_trust.cache_clear()
    yield host_ca, extra
    tlsconf.build_trust.cache_clear()


def _build(*, insecure: bool = False, ca_bundle: str = "") -> tlsconf.AgentTrust:
    """build_trust with test defaults. The real one takes both arguments required, so that two
    spellings cannot cache two different contexts (see its docstring); the defaults live here
    instead, where a second context costs nothing."""
    return tlsconf.build_trust(insecure=insecure, ca_bundle=ca_bundle)


def _hint(exc: BaseException) -> str:
    """verification_hint with the same test defaults."""
    return tlsconf.verification_hint(exc, insecure=False, ca_bundle="")


def _write_ca(directory: Path, name: str, *, filename: str | None = None) -> tuple[Path, str]:
    """A real CA PEM on disk, plus the organization name to look for in a loaded context.

    ``filename`` where the host's own name for the file is what the test is about
    (``tls-ca-bundle.pem`` and friends); otherwise ``<name>.crt``.
    """
    directory.mkdir(parents=True, exist_ok=True)
    organization = f"{name}.test"
    authority = trustme.CA(organization_name=organization)
    path = directory / (filename or f"{name}.crt")
    authority.cert_pem.write_to_path(str(path))
    return path, organization


def _write_bundle(path: Path, *names: str) -> list[str]:
    """One PEM holding several roots, the way a host's extracted bundle holds many.

    Returns the organization names, in order, so a test can say which of them reached the context.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    organizations = [f"{name}.test" for name in names]
    authorities = [trustme.CA(organization_name=organization) for organization in organizations]
    path.write_bytes(b"".join(authority.cert_pem.bytes() for authority in authorities))
    return organizations


def _rhel_extracts(host_ca: Path) -> dict[str, str]:
    """A directory shaped like /etc/pki/ca-trust/extracted/pem: one bundle per purpose.

    This is what scripts/bootstrap.sh mounts at /host-ca on a RHEL-family host, because
    `readlink -f /etc/pki/tls/certs/ca-bundle.crt` lands inside it.
    """
    return {
        purpose: _write_ca(host_ca, f"{purpose}-root", filename=f"{purpose}-ca-bundle.pem")[1]
        for purpose in ("tls", "email", "objsign")
    }


def _organizations(context: ssl.SSLContext) -> set[str]:
    return {
        value
        for cert in context.get_ca_certs()
        for rdn in cert.get("subject", ())
        for key, value in rdn
        if key == "organizationName"
    }


def test_given_nothing_mounted_then_public_roots_are_still_trusted() -> None:
    """The normal case for every customer who is not behind an inspecting proxy."""
    trust = _build()

    assert trust.verifies
    assert trust.loaded == ()
    assert trust.rejected == ()
    assert trust.skipped == ()
    # certifi alone is hundreds of roots; an empty store would mean we broke ordinary TLS.
    assert len(trust.context.get_ca_certs()) > 50
    assert trust.summary() == "image store, certifi"


def test_given_a_ca_in_host_ca_then_it_is_trusted_alongside_the_public_roots(
    _isolate_trust: tuple[Path, Path],
) -> None:
    """The whole point: the install command mounts the host store, and the agent picks it up
    with nothing configured."""
    host_ca, _ = _isolate_trust
    _, organization = _write_ca(host_ca, "corp-root")

    trust = _build()

    assert organization in _organizations(trust.context)
    assert len(trust.context.get_ca_certs()) > 50  # union, never replacement
    assert [path.name for path in trust.loaded] == ["corp-root.crt"]
    assert "(1 file)" in trust.summary()


def test_given_a_ca_in_certs_then_it_is_trusted(_isolate_trust: tuple[Path, Path]) -> None:
    """The manual drop-in, which is how Kubernetes supplies a root (no host dir to mount)."""
    _, extra = _isolate_trust
    _, organization = _write_ca(extra, "k8s-root")

    assert organization in _organizations(_build().context)


def test_given_both_directories_then_every_root_is_trusted(
    _isolate_trust: tuple[Path, Path],
) -> None:
    host_ca, extra = _isolate_trust
    _, from_host = _write_ca(host_ca, "host-root")
    _, from_mount = _write_ca(extra, "drop-in-root")

    organizations = _organizations(_build().context)

    assert {from_host, from_mount} <= organizations


def test_given_the_rhel_extract_layout_then_only_the_tls_bundle_is_trusted(
    _isolate_trust: tuple[Path, Path],
) -> None:
    """A host trusts a set of roots *per purpose*, and RHEL writes one file per purpose. Loading
    all three would make an S/MIME or code-signing root a valid issuer for the control plane."""
    host_ca, _ = _isolate_trust
    _rhel_extracts(host_ca)

    trust = _build()

    assert [path.name for path in trust.loaded] == ["tls-ca-bundle.pem"]
    assert [path.name for path in trust.skipped] == [
        "email-ca-bundle.pem",
        "objsign-ca-bundle.pem",
    ]
    assert len(trust.context.get_ca_certs()) > 50  # still a union, not a replacement


def test_given_a_root_only_in_the_email_extract_then_it_never_enters_the_ssl_context(
    _isolate_trust: tuple[Path, Path],
) -> None:
    """The finding itself: an on-path attacker holding a certificate for the control-plane name
    under a root the host trusts only for e-mail must not complete the handshake."""
    host_ca, _ = _isolate_trust
    organizations = _rhel_extracts(host_ca)

    trusted = _organizations(_build().context)

    assert organizations["tls"] in trusted
    assert organizations["email"] not in trusted
    assert organizations["objsign"] not in trusted


def test_given_an_inspection_root_in_every_extract_then_it_is_still_trusted(
    _isolate_trust: tuple[Path, Path],
) -> None:
    """The regression that would hurt a paying customer. A corporate root installed the ordinary
    RHEL way carries no purpose restriction, so update-ca-trust writes it into all three extracts;
    the rule selects files, never certificates, so it survives in the TLS one."""
    host_ca, _ = _isolate_trust
    host_ca.mkdir(parents=True, exist_ok=True)
    corp, public = _write_bundle(host_ca / "tls-ca-bundle.pem", "corp-proxy", "a-public-root")
    _write_bundle(host_ca / "email-ca-bundle.pem", "corp-proxy", "an-email-only-root")
    (email_only,) = _write_bundle(host_ca / "objsign-ca-bundle.pem", "an-objsign-only-root")

    trusted = _organizations(_build().context)

    assert {corp, public} <= trusted
    assert email_only not in trusted
    assert "an-email-only-root.test" not in trusted


def test_given_a_tls_bundle_beside_other_roots_then_the_other_roots_survive(
    _isolate_trust: tuple[Path, Path],
) -> None:
    """The regression an earlier shape of this rule introduced, caught on review.

    "If the directory holds tls-ca-bundle.pem, take only that file" reads the RHEL extract layout
    correctly and a /certs drop-in wrongly: an operator who put their own root next to a file by
    that name would lose it on upgrade, silently, and a root someone installed by hand is the one
    thing here that has no other copy. The two rules agree on the RHEL directory anyway.
    """
    host_ca, extra = _isolate_trust
    _, from_bundle = _write_ca(extra, "bundled-root", filename="tls-ca-bundle.pem")
    _, from_drop_in = _write_ca(extra, "an-operators-own-root")

    trust = _build()

    assert [path.name for path in trust.loaded] == [
        "an-operators-own-root.crt",
        "tls-ca-bundle.pem",
    ]
    assert trust.skipped == ()
    assert {from_bundle, from_drop_in} <= _organizations(trust.context)


def test_given_a_non_tls_extract_without_its_tls_sibling_then_it_is_still_declined(
    _isolate_trust: tuple[Path, Path],
) -> None:
    """A half-copied extract directory, or a ConfigMap built from two of the three files. There is
    no TLS sibling to anchor on, so the name rule is the whole of it."""
    host_ca, _ = _isolate_trust
    _, email = _write_ca(host_ca, "email-root", filename="email-ca-bundle.pem")
    _, corp = _write_ca(host_ca, "corp-root")

    trust = _build()

    assert [path.name for path in trust.loaded] == ["corp-root.crt"]
    assert [path.name for path in trust.skipped] == ["email-ca-bundle.pem"]
    assert corp in _organizations(trust.context)
    assert email not in _organizations(trust.context)


def test_given_the_debian_layout_then_the_bundle_loads_and_nothing_is_skipped(
    _isolate_trust: tuple[Path, Path],
) -> None:
    """Debian, Ubuntu, Alpine and SUSE mount one real bundle (plus symlinks that dangle inside the
    container). Nothing about that layout may change."""
    host_ca, _ = _isolate_trust
    _, organization = _write_ca(host_ca, "corp-root", filename="ca-certificates.crt")
    for name in ("3513523f.0", "a94d09e5.0", "Corp_Root.pem"):
        (host_ca / name).symlink_to("/usr/share/ca-certificates/nothing-here.crt")

    trust = _build()

    assert [path.name for path in trust.loaded] == ["ca-certificates.crt"]
    assert trust.skipped == ()
    assert "skipped" not in trust.summary()
    assert organization in _organizations(trust.context)


def test_given_a_skipped_bundle_then_the_summary_says_so_rather_than_dropping_it_silently(
    _isolate_trust: tuple[Path, Path], caplog: pytest.LogCaptureFixture
) -> None:
    """Mounting three files and reading "(1 file)" is otherwise a mystery worth a support ticket.
    And it is not a WARNING: skipping those two is normal on RHEL, not an operator mistake."""
    host_ca, _ = _isolate_trust
    _rhel_extracts(host_ca)

    with caplog.at_level(logging.WARNING, logger="ares.agent.tls"):
        summary = _build().summary()

    assert "(1 file)" in summary
    assert "skipped as not TLS server-auth" in summary
    assert "email-ca-bundle.pem" in summary and "objsign-ca-bundle.pem" in summary
    assert caplog.records == []


def test_given_a_drop_in_named_like_a_non_tls_extract_then_it_is_declined(
    _isolate_trust: tuple[Path, Path],
) -> None:
    """The prefix match, not the exact basename, so p11-kit's .trust.crt variants go too."""
    _, extra = _isolate_trust
    _, objsign = _write_ca(extra, "objsign-root", filename="objsign-ca-bundle.trust.crt")
    _, corp = _write_ca(extra, "corp-root")

    trust = _build()

    assert [path.name for path in trust.loaded] == ["corp-root.crt"]
    assert [path.name for path in trust.skipped] == ["objsign-ca-bundle.trust.crt"]
    assert objsign not in _organizations(trust.context)


def test_given_ares_ca_bundle_names_a_non_tls_file_then_the_operator_still_wins(
    _isolate_trust: tuple[Path, Path],
) -> None:
    """We filter what we *discover*, never what we were pointed at. This is the escape hatch for
    anyone who genuinely wants a root the host extracts for another purpose."""
    host_ca, _ = _isolate_trust
    path, organization = _write_ca(host_ca / "elsewhere", "email-root", filename="email-ca-bundle.pem")

    trust = _build(ca_bundle=str(path))

    assert trust.loaded == (path,)
    assert trust.skipped == ()
    assert organization in _organizations(trust.context)


def test_given_dangling_symlinks_then_the_real_bundle_loads_and_nothing_is_logged(
    _isolate_trust: tuple[Path, Path], caplog: pytest.LogCaptureFixture
) -> None:
    """A mounted /etc/ssl/certs is one real bundle plus ~150 symlinks into a directory that was
    not mounted. Every one of those dangles inside the container, and warning about each would
    bury the line an operator actually needs."""
    host_ca, _ = _isolate_trust
    _, organization = _write_ca(host_ca, "real-root")
    for index in range(5):
        (host_ca / f"{index:08x}.0").symlink_to("/usr/share/ca-certificates/nowhere.crt")

    with caplog.at_level(logging.WARNING, logger="ares.agent.tls"):
        trust = _build()

    assert organization in _organizations(trust.context)
    assert [path.name for path in trust.loaded] == ["real-root.crt"]
    assert trust.rejected == ()
    assert caplog.records == []


def test_given_a_malformed_ca_then_it_is_reported_and_the_valid_one_still_loads(
    _isolate_trust: tuple[Path, Path], caplog: pytest.LogCaptureFixture
) -> None:
    """Unlike a dangling symlink, a file the operator meant us to trust is worth a warning; it
    must not cost us the rest of the bundle."""
    host_ca, _ = _isolate_trust
    _, organization = _write_ca(host_ca, "good-root")
    (host_ca / "broken.pem").write_text("-----BEGIN CERTIFICATE-----\nnot a certificate\n")

    with caplog.at_level(logging.WARNING, logger="ares.agent.tls"):
        trust = _build()

    assert organization in _organizations(trust.context)
    assert [path.name for path in trust.rejected] == ["broken.pem"]
    assert "broken.pem" in caplog.text
    assert "broken.pem" in trust.summary()


def test_given_ares_ca_bundle_as_a_file_then_it_is_trusted(tmp_path: Path) -> None:
    path, organization = _write_ca(tmp_path / "elsewhere", "bundle-file-root")

    trust = _build(ca_bundle=str(path))

    assert organization in _organizations(trust.context)


def test_given_ares_ca_bundle_as_a_directory_then_every_pem_inside_is_trusted(
    tmp_path: Path,
) -> None:
    """Operators reasonably expect either, and guessing wrong should not fail silently."""
    directory = tmp_path / "bundle-dir"
    _, first = _write_ca(directory, "dir-root-a")
    _, second = _write_ca(directory, "dir-root-b")

    organizations = _organizations(_build(ca_bundle=str(directory)).context)

    assert {first, second} <= organizations


def test_given_insecure_then_verification_is_off_and_the_summary_says_so() -> None:
    trust = _build(insecure=True)

    assert not trust.verifies
    assert trust.context.verify_mode == ssl.CERT_NONE
    assert not trust.context.check_hostname
    assert "DISABLED" in trust.summary()


def test_given_a_certificate_error_then_the_hint_names_the_remedy() -> None:
    """The raw OpenSSL string says what happened and nothing about what to do. That gap is what
    turned a five-minute mount into a week of email."""
    error = ssl.SSLCertVerificationError("self-signed certificate in certificate chain")
    wrapped = ConnectionError("cannot connect")
    wrapped.__cause__ = error

    hint = _hint(wrapped)

    assert "inspecting TLS" in hint
    assert "/certs" in hint
    assert "Trust loaded:" in hint


def test_given_an_ordinary_connection_error_then_there_is_no_hint() -> None:
    """Appended unconditionally by the caller, so it has to stay empty for a plain timeout."""
    assert _hint(TimeoutError("timed out")) == ""


def test_given_a_self_referential_cause_chain_then_the_hint_terminates() -> None:
    """__cause__ chains can loop; walking one must not hang the agent's error path."""
    first = ConnectionError("a")
    second = ConnectionError("b")
    first.__cause__ = second
    second.__cause__ = first

    assert _hint(first) == ""


def test_the_control_plane_client_verifies_with_the_shared_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The regression guard for the actual bug. `verify=True` sends httpx to certifi's bundle
    inside site-packages, so a root CA installed in the container does nothing. Asserted on the
    argument we pass, which is the thing that has to stay right, rather than on httpcore
    internals that are free to move."""
    captured: dict[str, object] = {}

    def _record(**kwargs: object) -> object:
        captured.update(kwargs)
        return object()

    monkeypatch.setattr(control_plane.httpx, "AsyncClient", _record)
    control_plane._client(Settings(token="t", url="https://ares.example.com"))

    assert captured["verify"] is tlsconf.build_trust(insecure=False, ca_bundle="").context
    assert captured["verify"] is not True  # the bug, spelled out


def test_the_tunnel_takes_a_context_rather_than_building_its_own() -> None:
    """Control plane and data plane must verify against the same CAs; two independently built
    contexts is how they silently drift apart."""
    from agent.tunnel import TunnelClient

    context = _build().context
    client = TunnelClient("wss://x/api/v1/agent/tunnel", "tok", [], set(), ssl_context=context)

    assert client._ssl_context is context
