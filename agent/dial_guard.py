"""The dial guard: the one place a tunnel destination becomes an address this agent connects to.

Why it exists (ARES-2308). ares approves a hostname destination by NAME and pushes the name on the
heartbeat; this agent resolves it on the customer's own DNS at dial time, because only this agent
can. ares has no way to bind the answer it saw when it approved the name to the socket opened here,
so whoever controls that name's DNS decides where the stream lands: answer a public address while
ares looks, then 169.254.169.254 or 127.0.0.1 when the agent dials, and an approved login host
becomes a read of this host's cloud credentials or of a service bound to its localhost. Only the
agent sees the answer that is actually used, so only the agent can close that gap. It closes it
here, with three rules applied to every address a pushed name yields, however the name was approved
(an operator's scope entry, the exact target of a run, a domain suffix, or ``*``):

* **Some address classes are never dialled.** Loopback, link-local (169.254.0.0/16 and fe80::/10,
  which is where most cloud metadata services live), the metadata endpoints that live elsewhere
  (Alibaba's 100.100.100.200 in CGNAT space, AWS's fd00:ec2::254 in ULA space, ...), unspecified
  (0.0.0.0/8 and ::, since a connect to 0.0.0.0 reaches the local host on Linux), multicast and
  broadcast. None of those is a host on the customer's network that an assessment could be for,
  and each is a route to this host itself or to its cloud identity. Private space (RFC 1918, ULA,
  CGNAT) stays dialable: reaching the customer's internal network is the reason the agent exists.
* **An address is judged by what it really is.** ``::ffff:169.254.169.254`` is reduced to the IPv4
  address it maps before it is judged or dialled, and an IPv4 address embedded in IPv6 by NAT64,
  6to4 or the deprecated compatible form is judged too, so a second spelling cannot carry a
  forbidden address past the check.
* **One resolution per dial, and the connect goes to the literal that was checked.** The caller
  runs :func:`lookup` once per OPEN, :func:`vet` drops what may never be dialled, and
  :func:`open_vetted` connects to an IP literal and re-checks it at the socket. A name therefore
  never reaches ``open_connection``, and no second lookup can swap the destination after the check.

A mixed answer is filtered rather than refused outright: the forbidden records are dropped and only
the rest are tried. That is safe precisely because the dial goes to the vetted literals and to
nothing else, and it keeps a legitimate name with one stray record working.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from enum import StrEnum

from agent.hostpins import HostPins

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

# Resolved addresses a refusal names before it counts the rest.
ADDRESSES_NAMED = 3


class Refused(Exception):
    """The destination is not authorized for this agent; the message is the log reason."""


class Forbidden(StrEnum):
    """Why an address is never dialled. The value is the wording a refusal reason uses."""

    UNPARSEABLE = "not an IP address"
    UNSPECIFIED = "unspecified"
    LOOPBACK = "loopback"
    CLOUD_METADATA = "cloud metadata"
    LINK_LOCAL = "link-local"
    MULTICAST = "multicast"
    BROADCAST = "broadcast"


# Cloud metadata and platform endpoints. Most sit in link-local space and are refused by that rule
# anyway; they are listed so a refusal names the metadata service rather than just "link-local".
# The rest are the reason this list exists: they sit in space that is otherwise dialable, so no
# address-class rule would catch them.
CLOUD_METADATA_ADDRESSES: frozenset[IPAddress] = frozenset(
    ipaddress.ip_address(value)
    for value in (
        "169.254.169.254",  # AWS, GCP, Azure, OCI, DigitalOcean, OpenStack instance metadata
        "169.254.170.2",  # AWS ECS task credentials
        "169.254.170.23",  # AWS EKS Pod Identity
        "100.100.100.200",  # Alibaba Cloud metadata, inside 100.64.0.0/10 (CGNAT)
        "168.63.129.16",  # Azure WireServer, a public address
        "192.0.0.192",  # Oracle Cloud Classic metadata, inside 192.0.0.0/24
        "fd00:ec2::254",  # AWS instance metadata over IPv6, inside ULA space
        "fd00:ec2::23",  # AWS EKS Pod Identity over IPv6, inside ULA space
    )
)

# RFC 1122 "this host on this network". A connect to 0.0.0.0 reaches the local host on Linux, which
# is loopback by another name, and nothing else in the block is a destination.
_THIS_NETWORK = ipaddress.IPv4Network("0.0.0.0/8")
_LIMITED_BROADCAST = ipaddress.IPv4Address("255.255.255.255")
# IPv6 prefixes that carry an IPv4 address in their low 32 bits.
_NAT64_WELL_KNOWN = ipaddress.IPv6Network("64:ff9b::/96")
_IPV4_COMPATIBLE = ipaddress.IPv6Network("::/96")


def canonical_address(address: str) -> IPAddress | None:
    """The address as it is judged and dialled, or None when ``address`` is not an IP literal.

    An IPv4-mapped IPv6 address is reduced to the IPv4 address it maps: ``::ffff:127.0.0.1`` IS
    127.0.0.1 to the kernel, and judged as IPv6 it would look like an ordinary global address.
    Dialling the IPv4 form also avoids needing a dual-stack socket to reach it. A zone index is
    dropped, because it never changes which host an address names (and the only addresses that
    need one, link-local, are refused anyway): left on, ``fd00:ec2::254%eth0`` would not compare
    equal to the metadata address it is.
    """
    try:
        parsed = ipaddress.ip_address(address.strip().split("%", 1)[0])
    except ValueError:
        return None
    if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped is not None:
        return parsed.ipv4_mapped
    return parsed


def _embedded_ipv4(address: ipaddress.IPv6Address) -> ipaddress.IPv4Address | None:
    """The IPv4 address a NAT64, 6to4 or IPv4-compatible IPv6 address carries, if it carries one."""
    if address.sixtofour is not None:
        return address.sixtofour
    if address in _NAT64_WELL_KNOWN or address in _IPV4_COMPATIBLE:
        return ipaddress.IPv4Address(int(address) & 0xFFFF_FFFF)
    return None


def _classify(address: IPAddress) -> Forbidden | None:
    if isinstance(address, ipaddress.IPv4Address):
        if address in _THIS_NETWORK:
            return Forbidden.UNSPECIFIED
        if address == _LIMITED_BROADCAST:
            return Forbidden.BROADCAST
    elif address.is_unspecified:
        return Forbidden.UNSPECIFIED
    if address.is_loopback:
        return Forbidden.LOOPBACK
    if address in CLOUD_METADATA_ADDRESSES:
        return Forbidden.CLOUD_METADATA
    if address.is_link_local:
        return Forbidden.LINK_LOCAL
    if address.is_multicast:
        return Forbidden.MULTICAST
    return None


def _judge(address: IPAddress) -> Forbidden | None:
    """Why a parsed address may never be dialled, judging an embedded IPv4 address as well."""
    reason = _classify(address)
    if reason is None and isinstance(address, ipaddress.IPv6Address):
        embedded = _embedded_ipv4(address)
        if embedded is not None:
            reason = _classify(embedded)
    return reason


def forbidden_class(address: str) -> Forbidden | None:
    """Why ``address`` may never be dialled, or None when the guard has no objection to it.

    Fails closed: anything that does not parse as an IP address is :attr:`Forbidden.UNPARSEABLE`,
    so a hostname handed in where an address belongs is refused rather than resolved.
    """
    parsed = canonical_address(address)
    if parsed is None:
        return Forbidden.UNPARSEABLE
    return _judge(parsed)


def summarize_addresses(addresses: Sequence[str]) -> str:
    """Name the first few addresses and count the rest, so one refusal stays one readable line.

    A name behind a large CDN or anycast pool resolves to a dozen-plus A/AAAA records; printing all
    of them turns every refusal into an unreadable wall.
    """
    if len(addresses) <= ADDRESSES_NAMED:
        return ", ".join(addresses)
    named = ", ".join(addresses[:ADDRESSES_NAMED])
    return f"{named}, +{len(addresses) - ADDRESSES_NAMED} more"


def _labelled(dropped: Sequence[tuple[str, Forbidden]]) -> str:
    return summarize_addresses([f"{address} ({reason})" for address, reason in dropped])


def literal_refusal(address: str, reason: Forbidden) -> str:
    """The refusal reason for one address the guard will not dial."""
    return f"{address} is {reason}, which this agent never dials however it was approved"


@dataclass(frozen=True)
class Vetted:
    """One resolution after the guard: what may be dialled, in resolver order, and what was not."""

    addresses: tuple[str, ...]
    dropped: tuple[tuple[str, Forbidden], ...]

    def drop_note(self, host: str) -> str:
        """The log line for a mixed answer: what was skipped, and what will be tried instead."""
        return (
            f"{host} also resolved to {_labelled(self.dropped)}, which this agent never dials; "
            f"trying only {summarize_addresses(self.addresses)}"
        )


def vet(host: str, addresses: Iterable[str]) -> Vetted:
    """Drop every address the guard forbids, or raise :class:`Refused` when none remains.

    The kept addresses come back in canonical form (see :func:`canonical_address`) and
    deduplicated, order preserved, so the string the caller dials is exactly the one judged here.
    """
    kept: dict[str, None] = {}
    dropped: list[tuple[str, Forbidden]] = []
    for address in addresses:
        parsed = canonical_address(address)
        reason = Forbidden.UNPARSEABLE if parsed is None else _judge(parsed)
        if parsed is None or reason is not None:
            dropped.append((address, reason or Forbidden.UNPARSEABLE))
            continue
        kept[str(parsed)] = None
    if not kept:
        if not dropped:
            raise Refused(f"{host} resolved to no address on this agent")
        raise Refused(
            f"{host} resolves only to {_labelled(dropped)}, which this agent never dials however "
            "the name was approved: no DNS answer can move a destination onto loopback, "
            "link-local, cloud metadata, unspecified, multicast or broadcast space"
        )
    return Vetted(addresses=tuple(kept), dropped=tuple(dropped))


async def lookup(
    host: str, port: int, *, timeout: float, pins: HostPins | None = None
) -> list[str]:
    """Every address for ``host`` from ONE resolution: a static pin if one exists, else this
    agent's resolver. Deduplicated, order preserved.

    Call it once per dial and hand the result to :func:`vet`. A pin short-circuits DNS entirely,
    which is the point of one: it is what an operator reaches for when the resolver will not answer
    a name at all. It is still vetted like any DNS answer, because the host's ``/etc/hosts`` maps
    the machine's own hostname to 127.0.1.1 on many distributions, and that name must not become a
    way onto this host's loopback.
    """
    if pins is not None and (pinned := pins.lookup(host)):
        return list(pinned)
    try:
        infos = await asyncio.wait_for(
            asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM),
            timeout,
        )
    except asyncio.TimeoutError as exc:
        # str(TimeoutError()) is EMPTY, so interpolating the exception the way the OSError arm
        # does produced "... did not resolve on this agent: " and left the reader staring at a
        # sentence that stopped at the colon. Say what actually happened instead.
        raise Refused(
            f"{host} did not resolve on this agent within {timeout:.0f}s "
            "(the resolver did not answer; pin it in the host's /etc/hosts or "
            "ARES_HOST_ALIASES if it never will)"
        ) from exc
    except OSError as exc:
        raise Refused(f"{host} did not resolve on this agent: {exc}") from exc
    addresses = list(dict.fromkeys(str(info[4][0]) for info in infos))
    if not addresses:
        raise Refused(f"{host} resolved to no address on this agent")
    return addresses


async def open_vetted(
    address: str, port: int, *, timeout: float, loopback_ok: bool = False
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Connect to one IP literal, re-checking it here, at the socket.

    :func:`vet` already filtered the addresses a caller passes, and this checks again so the
    property does not rest on every caller remembering to: whatever reaches a socket has been
    judged, and a hostname is refused (as :attr:`Forbidden.UNPARSEABLE`) rather than resolved, so
    the connect can never perform a lookup of its own.

    ``loopback_ok`` is the single exception, for an IP literal inside this agent's own registered
    networks (see ``TunnelClient._loopback_permitted``). It never applies to a name.
    """
    parsed = canonical_address(address)
    reason = Forbidden.UNPARSEABLE if parsed is None else _judge(parsed)
    if reason is Forbidden.LOOPBACK and loopback_ok:
        reason = None
    if parsed is None or reason is not None:
        raise Refused(literal_refusal(address, reason or Forbidden.UNPARSEABLE))
    return await asyncio.wait_for(asyncio.open_connection(str(parsed), port), timeout=timeout)
