"""Normalize a mail domain's published SPF / DMARC policy into executable-control facts (the DNS slice
of the mail cohort).

Read-only and UNAUTHENTICATED: derives the mail host's own domain from its Postfix config (the
``postfix_maincf`` evidence the host tier already reads over SSH), then resolves that domain's SPF and
DMARC TXT records through the agent's system resolver. No credential, no new secret: the records are
public DNS. Like every collector it ABSTAINS rather than invents: a domain that cannot be derived, or
a record that does not resolve, leaves the control UNAVAILABLE.

Only SPF and DMARC live here, the two policies a single TXT read proves. MTA-STS needs an HTTPS policy
fetch (not just DNS), and DKIM needs the selector set, so both stay DESIGNED until that transport
exists. The mailbox-audit / forwarding / anti-phish controls are cloud-mail-tenant APIs.
"""

from __future__ import annotations

import asyncio
import ssl

import dns.resolver
import httpx

SERVES = frozenset(
    {"mail.spf.not_enforced", "mail.dmarc.not_enforced", "mail.mtasts.not_enforced"}
)


def serves(control_id: str) -> bool:
    """Whether this collector reads ``control_id`` from DNS."""
    return control_id in SERVES


def domain_from_postfix(postfix_main_cf: str) -> str | None:
    """The mail domain to query, derived from Postfix ``main.cf``: ``mydomain`` if set, else the parent
    of ``myhostname`` (Postfix's own default for ``mydomain``). ``None`` when neither is present, which
    makes the DNS controls abstain rather than query a guessed name."""
    values: dict[str, str] = {}
    for raw in postfix_main_cf.splitlines():
        line = raw.split("#", 1)[0].strip()
        key, sep, rest = line.partition("=")
        if sep:
            values[key.strip().lower()] = rest.strip()
    mydomain = values.get("mydomain")
    if mydomain:
        return mydomain.strip().rstrip(".").lower() or None
    myhostname = values.get("myhostname")
    if myhostname and "." in myhostname:
        return myhostname.strip().rstrip(".").lower().split(".", 1)[1] or None
    return None


def _spf_record(txt_values: object) -> str | None:
    """The single ``v=spf1`` record from a list of TXT strings, or ``None``."""
    if not isinstance(txt_values, list):
        return None
    for value in txt_values:
        if isinstance(value, str) and value.strip().lower().startswith("v=spf1"):
            return value.strip()
    return None


def parse_spf_enforced(txt_values: object) -> bool | None:
    """Whether the domain's SPF policy is ENFORCED (a hard ``-all`` fail), or ``None`` to abstain when
    the TXT values are not a list. ``True`` only for ``-all``; a soft ``~all``, a neutral ``?all``, a
    permissive ``+all``, or NO SPF record at all read ``False`` (a finding): unauthorized senders are
    not rejected."""
    if not isinstance(txt_values, list):
        return None
    record = _spf_record(txt_values)
    if record is None:
        return False  # no SPF published is "not enforced"
    return record.lower().replace(" ", "").endswith("-all")


def parse_dmarc_enforced(txt_values: object) -> bool | None:
    """Whether the domain's DMARC policy is ENFORCED (``p=quarantine`` or ``p=reject``), or ``None`` to
    abstain when the TXT values are not a list. ``p=none`` or NO DMARC record read ``False`` (a
    finding): a failing message is still delivered."""
    if not isinstance(txt_values, list):
        return None
    for value in txt_values:
        if not isinstance(value, str) or "v=dmarc1" not in value.lower():
            continue
        policy = ""
        for tag in value.split(";"):
            name, sep, val = tag.partition("=")
            if sep and name.strip().lower() == "p":
                policy = val.strip().lower()
        return policy in ("quarantine", "reject")
    return False  # no DMARC published is "not enforced"


def spf_field(txt_values: object) -> dict[str, object] | None:
    """The ``mail.spf.not_enforced`` field dict, or ``None`` to abstain."""
    value = parse_spf_enforced(txt_values)
    return None if value is None else {"spf_enforced": value}


def dmarc_field(txt_values: object) -> dict[str, object] | None:
    """The ``mail.dmarc.not_enforced`` field dict, or ``None`` to abstain."""
    value = parse_dmarc_enforced(txt_values)
    return None if value is None else {"dmarc_policy_enforced": value}


# ── MTA-STS ───────────────────────────────────────────────────────────────────────────────────────
# MTA-STS is published in two parts: a DNS TXT record at ``_mta-sts.<domain>`` announcing a policy, and
# the policy itself served over HTTPS at ``https://mta-sts.<domain>/.well-known/mta-sts.txt`` with a
# ``mode:`` of enforce / testing / none. Enforcement is the HTTPS policy's mode, so the enabled fact is
# "published AND mode is enforce".
def parse_mtasts_published(txt_values: object) -> bool | None:
    """Whether an MTA-STS policy is announced in DNS (``v=STSv1`` at ``_mta-sts.<domain>``), or ``None``
    to abstain when the TXT values are not a list."""
    if not isinstance(txt_values, list):
        return None
    return any(isinstance(v, str) and v.strip().lower().startswith("v=stsv1") for v in txt_values)


def parse_mtasts_mode(policy_text: object) -> str | None:
    """The ``mode`` of an MTA-STS policy file (``enforce`` / ``testing`` / ``none``), or ``None`` when
    the text carries no ``mode:`` line (not a policy)."""
    if not isinstance(policy_text, str):
        return None
    for line in policy_text.splitlines():
        key, sep, value = line.partition(":")
        if sep and key.strip().lower() == "mode":
            return value.strip().lower() or None
    return None


def parse_mtasts_enforce_enabled(published: object, mode: object) -> bool:
    """Whether MTA-STS is ENFORCED: a policy is published AND its mode is ``enforce``. Anything else
    (not published, ``testing``, ``none``, no mode) is not enforced (a finding)."""
    return bool(published) and mode == "enforce"


def mtasts_field(published: object, mode: object) -> dict[str, object]:
    """The ``mail.mtasts.not_enforced`` field dict from the DNS-published flag and the policy mode."""
    return {"mta_sts_enforce_mode_enabled": parse_mtasts_enforce_enabled(published, mode)}


def _resolve_txt(name: str, timeout: float) -> list[str]:
    """The TXT strings published at ``name``, read through the system resolver. Returns an empty list
    when the name has no TXT record (NXDOMAIN / NoAnswer), which the parsers read as "not published"."""
    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    resolver.timeout = timeout
    try:
        answer = resolver.resolve(name, "TXT")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return []
    out: list[str] = []
    for record in answer:
        # a TXT rdata is one or more quoted strings; join them (long records are split at 255 bytes)
        out.append("".join(part.decode() for part in record.strings))
    return out


async def fetch_spf_txt(domain: str, *, timeout: float) -> list[str]:
    """The TXT records at ``domain`` (where SPF is published), read in a thread (dnspython is sync)."""
    return await asyncio.to_thread(_resolve_txt, domain, timeout)


async def fetch_dmarc_txt(domain: str, *, timeout: float) -> list[str]:
    """The TXT records at ``_dmarc.<domain>`` (where DMARC is published)."""
    return await asyncio.to_thread(_resolve_txt, f"_dmarc.{domain}", timeout)


def _unverified_tls() -> ssl.SSLContext:
    """A TLS context that encrypts but does not verify the MTA-STS policy host's certificate: a lab /
    on-prem host commonly serves its own self-signed certificate. Mirrors the other tiers."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def _fetch_mtasts_policy(domain: str, timeout: float) -> str | None:
    """The MTA-STS policy text from ``https://mta-sts.<domain>/.well-known/mta-sts.txt``, or ``None``
    when it cannot be fetched (no policy host / non-200). Synchronous (runs in a thread)."""
    url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
    try:
        response = httpx.get(url, timeout=timeout, verify=_unverified_tls(), follow_redirects=False)
    except Exception:  # noqa: BLE001 - an unreachable policy host is read as "no policy"
        return None
    return response.text if response.status_code == 200 else None


async def fetch_mtasts_posture(domain: str, *, timeout: float) -> tuple[bool, str | None]:
    """The domain's MTA-STS posture as ``(published, mode)``: whether a policy is announced in DNS, and
    the mode of the HTTPS-served policy (fetched only when it is announced). Read in a thread."""

    def _read() -> tuple[bool, str | None]:
        published = parse_mtasts_published(_resolve_txt(f"_mta-sts.{domain}", timeout)) or False
        mode = parse_mtasts_mode(_fetch_mtasts_policy(domain, timeout)) if published else None
        return published, mode

    return await asyncio.to_thread(_read)
