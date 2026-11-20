"""Where the agent's TLS trust comes from.

One SSL context, shared by the control plane and the data-plane tunnel, so the two can never
disagree about what is trusted. It is the **union** of every CA we can find, never a replacement:

* the image's own store (which also honours ``SSL_CERT_FILE`` / ``SSL_CERT_DIR``),
* certifi's public roots, so those are present even where a store is thin,
* every PEM under :data:`HOST_CA_DIR` and :data:`EXTRA_CA_DIR` that the host trusts for TLS
  server authentication (see :func:`_server_auth_only`),
* whatever ``ARES_CA_BUNDLE`` names.

The reason this module exists: httpx does **not** use the OS trust store. Given ``verify=True``
it verifies against ``certifi.where()``, a PEM inside site-packages, unless ``SSL_CERT_FILE`` or
``SSL_CERT_DIR`` is set. So on a network that inspects TLS, an operator can install their root CA
in the container the ordinary way (``update-ca-certificates``), watch ``urllib`` succeed, and
still have every agent request fail with ``CERTIFICATE_VERIFY_FAILED``. That is not a
configuration mistake, it is two trust stores in one container, and it cost a customer a week.

Discovery is deliberately zero-configuration. A network that inspects TLS has already had to make
its root trusted on the host, or nothing on that machine could browse; the install command mounts
that host directory read-only at :data:`HOST_CA_DIR`, and the agent picks it up with nothing to
set. A host with no interception mounts an ordinary public bundle, which is a harmless no-op.
"""

from __future__ import annotations

import logging
import ssl
from collections import Counter
from functools import lru_cache
from pathlib import Path

import certifi
from pydantic import BaseModel, ConfigDict

logger = logging.getLogger("ares.agent.tls")

# The host's own CA directory, mounted read-only by the install command. Read-only, and only ever
# the public certificate directory: /etc/ssl/private is never mounted.
HOST_CA_DIR = Path("/host-ca")
# The manual drop-in, for a root that is not in the host store: an internal CA on an air-gapped
# build, or a Kubernetes ConfigMap, where there is no host directory to mount.
EXTRA_CA_DIR = Path("/certs")

_PEM_SUFFIXES = frozenset({".crt", ".pem", ".cer"})

# A host does not trust one set of roots; it trusts a set *per purpose*. RHEL-family hosts make
# that explicit: /etc/pki/ca-trust/extracted/pem - the directory the install command mounts - holds
# tls-ca-bundle.pem next to email-ca-bundle.pem and objsign-ca-bundle.pem. Loading all three would
# make a root the host trusts only for S/MIME or code signing a valid issuer for the control
# plane's certificate, which is an on-path attacker's way in. These two names are how we tell the
# difference without parsing certificates (see _server_auth_only for why we do not).
_TLS_BUNDLE_NAME = "tls-ca-bundle.pem"
_NON_TLS_BUNDLE_PREFIXES = ("email-ca-bundle", "objsign-ca-bundle")


class AgentTrust(BaseModel):
    """The trust the agent ended up with, and where each part of it came from."""

    model_config = ConfigDict(arbitrary_types_allowed=True, frozen=True)

    context: ssl.SSLContext
    loaded: tuple[Path, ...] = ()
    rejected: tuple[Path, ...] = ()
    skipped: tuple[Path, ...] = ()  # found, but extracted by the host for a non-TLS purpose

    @property
    def verifies(self) -> bool:
        """Whether certificates are checked at all.

        Derived from the context rather than stored alongside it, so the two cannot drift apart.
        False only under ARES_INSECURE, which main.py already refuses against a production URL.
        """
        return self.context.verify_mode != ssl.CERT_NONE

    def summary(self) -> str:
        """One line for the startup log, so ``docker logs`` answers "did it see my CA?" before
        anything has failed rather than after."""
        if not self.verifies:
            return "verification DISABLED (ARES_INSECURE)"
        parts = ["image store", "certifi"]
        # Grouped by directory, because which mount worked is the useful half of the answer:
        # "/host-ca (1 file)" says the host store came through, "/certs (1 file)" the drop-in did.
        for directory, count in sorted(Counter(path.parent for path in self.loaded).items()):
            parts.append(f"{directory} ({count} file{'' if count == 1 else 's'})")
        line = ", ".join(parts)
        # Before "unreadable", which is the clause that needs action, so that one ends the line.
        # A RHEL mount of three files reporting "(1 file)" is otherwise a mystery worth a ticket.
        if self.skipped:
            line += (
                "; skipped as not TLS server-auth: "
                + ", ".join(str(path) for path in self.skipped)
            )
        if self.rejected:
            line += f"; unreadable: {', '.join(str(path) for path in self.rejected)}"
        return line


def _pems_in(directory: Path) -> list[Path]:
    """Every readable PEM directly inside ``directory``, sorted; empty when it is not there.

    Anything that is not a readable regular file is skipped **in silence**. That is not laziness:
    ``/etc/ssl/certs`` on a Debian host is one real bundle plus ~150 symlinks into
    ``/usr/share/ca-certificates``, and mounting the directory alone leaves every one of those
    dangling inside the container. Warning about each on every start would bury the one line that
    matters.

    Purpose filtering is :func:`_server_auth_only`'s job, not this one's.
    """
    try:
        entries = sorted(directory.iterdir())
    except OSError:
        return []  # not mounted, which is the normal case
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


def _candidate_files(ca_bundle: str) -> tuple[list[Path], list[Path]]:
    """The extra CA files to load on top of the image store and certifi, and the ones declined.

    Per directory, because the rule reads one directory's layout to decide what that directory
    means: a ``/certs`` drop-in is not reinterpreted by what happens to sit in ``/host-ca``.
    """
    candidates: list[Path] = []
    skipped: list[Path] = []
    for directory in (HOST_CA_DIR, EXTRA_CA_DIR):
        keep, declined = _server_auth_only(_pems_in(directory))
        candidates += keep
        skipped += declined
    if not ca_bundle:
        return candidates, skipped
    # ARES_CA_BUNDLE takes a file or a directory, because operators reasonably expect both. A
    # named file is passed through unfiltered, suffix and all: they told us to trust it, and a
    # path that turns out not to exist should say so rather than vanish. That is also the escape
    # hatch for anyone who genuinely wants a root the host extracts for another purpose - we filter
    # what we *discover*, never what we were pointed at.
    configured = Path(ca_bundle)
    if not configured.is_dir():
        return candidates + [configured], skipped
    keep, declined = _server_auth_only(_pems_in(configured))
    return candidates + keep, skipped + declined


@lru_cache(maxsize=None)
def build_trust(*, insecure: bool, ca_bundle: str) -> AgentTrust:
    """The agent's trust, built once and shared.

    Cached because ``control_plane`` opens a fresh ``AsyncClient`` per call: without it, every
    heartbeat and every task poll would re-parse the whole bundle. An ``SSLContext`` is meant to
    be shared across connections, so handing the same one out is the intended use.

    Both arguments are required on purpose. ``lru_cache`` keys on the arguments as *written*, so
    with defaults ``build_trust()`` and ``build_trust(insecure=False, ca_bundle="")`` would be two
    cache entries holding two different contexts, and the "one context for the whole agent"
    promise above would quietly hold only because every caller happened to spell it the same way.
    """
    if insecure:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return AgentTrust(context=context)

    # The image's own store first. This is also what picks up SSL_CERT_FILE / SSL_CERT_DIR, so an
    # operator who already set either (the documented fix for older agents) keeps working.
    context = ssl.create_default_context()
    # certifi on top, never instead: a store that has been narrowed to one corporate root must not
    # cost us the public roots.
    context.load_verify_locations(cafile=certifi.where())

    candidates, skipped = _candidate_files(ca_bundle)
    loaded: list[Path] = []
    rejected: list[Path] = []
    for path in candidates:
        try:
            context.load_verify_locations(cafile=str(path))
        except OSError as exc:  # ssl.SSLError is an OSError; so is an unreadable file
            # Loud, because this one *is* an operator mistake: a file they meant us to trust and
            # we could not. One bad file never costs us the rest.
            logger.warning("Ignoring CA file %s: %s", path, exc)
            rejected.append(path)
        else:
            loaded.append(path)
    return AgentTrust(
        context=context,
        loaded=tuple(loaded),
        rejected=tuple(rejected),
        skipped=tuple(skipped),
    )


def verification_hint(exc: BaseException, *, insecure: bool, ca_bundle: str) -> str:
    """A remedy to append to a connection error, when that error is a certificate rejection.

    Returns ``""`` for every other failure, and is prefixed with its own space when it is not
    empty, so a caller can append it unconditionally. The raw OpenSSL string ("self-signed
    certificate in certificate chain") tells an operator what happened and nothing about what to
    do, which is exactly the gap that turns a five-minute mount into a week of email.
    """
    seen: set[int] = set()
    cause: BaseException | None = exc
    while cause is not None and id(cause) not in seen:
        seen.add(id(cause))
        if isinstance(cause, ssl.SSLCertVerificationError):
            trust = build_trust(insecure=insecure, ca_bundle=ca_bundle)
            return (
                " Nothing in the agent's trust store signed that certificate, which usually means "
                "the network is inspecting TLS. Re-run the install command from the dashboard "
                "(Settings -> Agents): it mounts this host's CA store into the container. Or "
                "mount your root CA yourself with -v /path/to/ca-dir:/certs:ro. "
                f"Trust loaded: {trust.summary()}."
            )
        cause = cause.__cause__ or cause.__context__
    return ""
