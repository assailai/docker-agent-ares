"""Make the updater trust the same CAs the host does, cosign included.

The updater's outbound TLS is not all Python: ``cosign verify`` is a Go binary we shell out to,
and it reaches the registry and the Sigstore transparency log itself. So the agent's approach of
building an ``ssl.SSLContext`` cannot work here, because nothing would hand that context to a
subprocess.

``SSL_CERT_FILE`` is the one lever both halves respect: Python's ``ssl`` picks it up through
OpenSSL's default verify paths, and Go's ``crypto/x509`` reads the same variable on Linux. So we
merge the image's bundle with the mounted CAs the host trusts for TLS server authentication,
write the result once at startup, and export it into our own environment, which every child
process inherits.

Without this, a network that inspects TLS leaves the updater failing closed forever: cosign
cannot verify a signature it cannot fetch, so the agent silently stops updating while looking
perfectly healthy. That is a worse failure than the agent's, because nothing reports it.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

logger = logging.getLogger("ares.updater.tls")

# Mirrors agent.tlsconf: the host CA directory the install command mounts, and the manual
# drop-in. The purpose rule below is the same text as the agent's, deliberately - the updater
# image ships updater/ only, so it cannot import agent.tlsconf, and a cosign that trusts a
# wider set of roots than the agent does would be its own hole.
HOST_CA_DIR = Path("/host-ca")
EXTRA_CA_DIR = Path("/certs")
# Alpine's system bundle, the base we merge on top of so public roots survive.
IMAGE_BUNDLE = Path("/etc/ssl/certs/ca-certificates.crt")
# Written at startup. /tmp so this works whether or not the updater runs as root.
MERGED_BUNDLE = Path("/tmp/ares-ca-bundle.pem")

_PEM_SUFFIXES = frozenset({".crt", ".pem", ".cer"})

# A host does not trust one set of roots; it trusts a set *per purpose*. RHEL-family hosts make
# that explicit: /etc/pki/ca-trust/extracted/pem - the directory the install command mounts - holds
# tls-ca-bundle.pem next to email-ca-bundle.pem and objsign-ca-bundle.pem. Loading all three would
# make a root the host trusts only for S/MIME or code signing a valid issuer for the control
# plane's certificate, which is an on-path attacker's way in. These two names are how we tell the
# difference without parsing certificates (see _server_auth_only for why we do not).
_TLS_BUNDLE_NAME = "tls-ca-bundle.pem"
_NON_TLS_BUNDLE_PREFIXES = ("email-ca-bundle", "objsign-ca-bundle")


def _pems_in(directory: Path) -> list[Path]:
    """Every readable PEM directly inside ``directory``, sorted; empty when it is not mounted.

    Skips anything that is not a readable regular file in silence: a mounted ``/etc/ssl/certs``
    brings ~150 symlinks that dangle inside the container, and they are not worth a line each.

    Purpose filtering is :func:`_server_auth_only`'s job, not this one's.
    """
    try:
        entries = sorted(directory.iterdir())
    except OSError:
        return []
    return [path for path in entries if path.suffix in _PEM_SUFFIXES and path.is_file()]


def _server_auth_only(paths: list[Path]) -> tuple[list[Path], list[Path]]:
    """Split one directory's PEMs into (trusted for TLS server auth, extracted for another purpose).

    Two halves. ``tls-ca-bundle.pem`` is written by exactly one thing,
    ``p11-kit extract --purpose server-auth``, so its presence means this directory is a set of
    per-purpose extracts *and* that the server-auth answer is sitting right there: take only it,
    and a fourth extract nobody has invented yet is excluded by construction. Everywhere else, fall
    back to declining the two non-TLS names, which still catches a half-copied directory that has
    ``email-ca-bundle.pem`` without its TLS sibling. Prefix match, so ``.trust.crt`` variants go too.

    This selects **files**, never certificates, which is what keeps TLS inspection working: a
    corporate root installed the ordinary RHEL way carries no purpose restriction, so
    ``update-ca-trust`` writes it into all three extracts and it survives in the TLS one.

    Deliberately no per-certificate check. ``ssl``'s decoded certificate dict carries no
    ``basicConstraints`` and no ``extendedKeyUsage``, so the stdlib cannot answer "is this a CA,
    and what for"; the alternative is ``cryptography`` in both shipped images for a check that runs
    once at startup. The residual is bounded: OpenSSL will not anchor a chain at a stray that is
    not self-signed (it needs ``EXFLAG_SS``, and Python never sets ``X509_V_FLAG_PARTIAL_CHAIN``),
    so the only stray that could be used as an anchor is a self-signed certificate the host
    administrator put in their own trust store on purpose.

    Order is preserved and the two lists together are the input, so a caller can report what it
    declined instead of dropping it silently.
    """
    extracts = any(path.name == _TLS_BUNDLE_NAME for path in paths)
    keep: list[Path] = []
    skipped: list[Path] = []
    for path in paths:
        eligible = (
            path.name == _TLS_BUNDLE_NAME
            if extracts
            else not path.name.startswith(_NON_TLS_BUNDLE_PREFIXES)
        )
        (keep if eligible else skipped).append(path)
    return keep, skipped


def install_ca_bundle() -> Path | None:
    """Merge the mounted CAs with the image bundle and point ``SSL_CERT_FILE`` at the result.

    Returns the bundle path, or ``None`` when there is nothing mounted and the image's own store
    is already the whole truth. Never raises: a broken CA mount must not stop the updater from
    running, it should only stop it from trusting more than it did before.
    """
    if os.environ.get("SSL_CERT_FILE"):
        # An operator set it explicitly. Theirs wins; we do not second-guess it.
        return None
    mounted: list[Path] = []
    skipped: list[Path] = []
    for directory in (HOST_CA_DIR, EXTRA_CA_DIR):
        keep, declined = _server_auth_only(_pems_in(directory))
        mounted += keep
        skipped += declined
    if skipped:
        # Said before the early return below, or "I mounted a directory and the updater did
        # nothing" has no explanation anywhere.
        logger.info(
            "Not merging %s: the host extracts those for a purpose other than TLS server auth.",
            ", ".join(str(path) for path in skipped),
        )
    if not mounted:
        # Nothing eligible. SSL_CERT_FILE *replaces* the default trust, so the choice here is only
        # ever "widen or leave alone", and leaving the image's own store in place is the answer.
        return None

    # The image's public roots have to come first and have to be there. SSL_CERT_FILE *replaces*
    # the default trust rather than adding to it, so a bundle holding only the mounted roots would
    # quietly narrow the updater to the corporate CA and break public TLS. If the base is
    # unreadable, leave SSL_CERT_FILE unset: the image's own store is a worse answer than the
    # union, but a far better one than a partial replacement.
    try:
        chunks = [IMAGE_BUNDLE.read_text(encoding="utf-8", errors="ignore")]
    except OSError as exc:
        logger.warning(
            "Cannot read %s (%s); leaving the default trust in place rather than narrowing it.",
            IMAGE_BUNDLE,
            exc,
        )
        return None

    for source in mounted:
        try:
            # errors="ignore" because a DER-encoded .cer among the PEMs would otherwise raise and
            # cost us the whole bundle. OpenSSL skips anything outside the BEGIN/END markers, so
            # the mangled bytes are inert and the real certificates around them still load.
            chunks.append(source.read_text(encoding="utf-8", errors="ignore"))
        except OSError as exc:
            logger.warning("Ignoring CA file %s: %s", source, exc)
    if len(chunks) == 1:
        return None  # every mounted file failed to read; the image store already covers us

    try:
        MERGED_BUNDLE.write_text("\n".join(chunks), encoding="utf-8")
    except OSError as exc:
        logger.warning("Could not write the merged CA bundle to %s: %s", MERGED_BUNDLE, exc)
        return None

    os.environ["SSL_CERT_FILE"] = str(MERGED_BUNDLE)
    logger.info(
        "TLS trust: image store plus %d mounted CA file(s) -> %s", len(mounted), MERGED_BUNDLE
    )
    return MERGED_BUNDLE
