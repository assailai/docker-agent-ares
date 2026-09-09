"""Data-plane tunnel client: the agent side of the multiplexed WebSocket.

While an internal hunt is running (the heartbeat says ``tunnel_required``), the agent
holds one outbound WebSocket to ares. ares opens logical streams over it to internal
hosts; the agent dials each one locally and relays the bytes.

Two kinds of destination are authorized, and the agent is the one that decides:

* an **IP literal** must fall inside the agent's own registered networks, exactly as it
  always has, so a discovered host can only be reached inside the ranges this agent was
  registered for;
* a **hostname** is resolved *here*, on the agent's resolver (that is the whole point: the
  name may only exist on the customer's internal DNS, and split-horizon DNS would give ares
  the wrong answer). The dial then goes to the address we checked, never back through the
  resolver, so a second lookup cannot swap the destination out from under the check.

Approval alone is not enough: how a name was approved bounds where it may
point (see :class:`HostApproval` and :func:`globally_routable`). A name somebody
actually chose - an address in this agent's scope, or the named target of a running
hunt - may resolve anywhere, private space included, since that is a deliberate
statement about one destination. A pattern (``*``, or a domain suffix) matches names
nobody enumerated, so it carries no such intent and the address it resolves to has to
earn the dial by being publicly routable. Otherwise an approved login domain becomes
a route to loopback, link-local metadata, or a private segment this agent never
registered for.

The frame format mirrors ``ares/infra/net/tunnel.py`` byte for byte; the two repos must
change it together.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import socket
import ssl
import struct
import time
from collections import Counter
from collections.abc import Iterable
from enum import Enum

import websockets

from agent.hostpins import HostPins

logger = logging.getLogger("ares.agent.tunnel")

_OPEN = 1
_OPEN_OK = 2
_OPEN_ERR = 3
_DATA = 4
_CLOSE = 5
_HEADER = struct.Struct(">BQ")
_RELAY_CHUNK = 65536
_DIAL_TIMEOUT = 10.0
# How long one destination lookup may take on this agent's resolver.
#
# 5.0 was too tight and cost a customer hours. glibc walks the nameservers in
# ``/etc/resolv.conf`` IN ORDER at roughly five seconds each, so a name the FIRST server will not
# answer only resolves once the resolver falls through to the second: a 5s cap gives up in the
# middle of that first server's own timeout and never sees the answer that was coming. The host's
# shell waits it out and succeeds, which is exactly why "but I can curl it from the box" and "the
# agent says it cannot resolve" were both true at once.
#
# 15.0 clears a two-server fallback with margin. It is an upper bound, not a delay: a name that
# resolves normally still returns in milliseconds, and a name that is genuinely dead still fails
# fast with NXDOMAIN rather than burning the budget.
_RESOLVE_TIMEOUT = 15.0
_RECONNECT_BACKOFF_MIN = 1.0
_RECONNECT_BACKOFF_MAX = 30.0
# Startup rehearsal of the data plane (see probe). Bounded so a network that blackholes the
# upgrade costs one slow startup rather than hanging the agent before it comes online.
_PROBE_TIMEOUT = 15.0
_ADDRESSES_NAMED = 3  # resolved addresses a refusal names before it counts the rest
_ROLLUP_INTERVAL = 60.0  # seconds between rollups of the repeats that were not logged in full
# Distinct hosts explained in full before the log falls back to counting. The page under test decides
# what the browser dials, so a page referencing a thousand third parties would otherwise still cost a
# thousand WARNING lines.
_HOSTS_REPORTED_MAX = 50


def _encode(opcode: int, stream_id: int, payload: bytes = b"") -> bytes:
    return _HEADER.pack(opcode, stream_id) + payload


def _decode(frame: bytes) -> tuple[int, int, bytes]:
    opcode, stream_id = _HEADER.unpack_from(frame)
    return opcode, stream_id, frame[_HEADER.size :]


def tunnel_url(base_url: str) -> str:
    """Derive the WebSocket tunnel URL from the control-plane base URL."""
    ws = base_url.rstrip("/")
    if ws.startswith("https://"):
        ws = "wss://" + ws[len("https://") :]
    elif ws.startswith("http://"):
        ws = "ws://" + ws[len("http://") :]
    return f"{ws}/api/v1/agent/tunnel"


async def probe(url: str, token: str, *, ssl_context: ssl.SSLContext | None) -> None:
    """Open the tunnel, prove the upgrade works, and close it again. Raises if it does not.

    The data plane is only opened while a hunt is running, so without this an operator does not
    find out that their network blocks the WebSocket upgrade until the first real assessment,
    which is the worst possible moment. ares authenticates the upgrade on the agent token alone
    and does not require a running hunt, so this is a true rehearsal of the real thing.

    It is a real tunnel while it lasts, so ares briefly lists this agent as reachable. That window
    is the length of one handshake and it opens before the serve loop starts, i.e. before this
    agent would ever have carried a hunt, so nothing can be routed into it and lost. Sending no
    frames keeps it unambiguous: ares sees a connect and a clean close, never a stream.
    """
    context = ssl_context if url.startswith("wss://") else None
    async with websockets.connect(
        url,
        additional_headers={"Authorization": f"Bearer {token}"},
        ssl=context,
        open_timeout=_PROBE_TIMEOUT,
        close_timeout=_PROBE_TIMEOUT,
    ):
        pass  # the upgrade completing is the whole result


def explain_probe_failure(exc: BaseException) -> str:
    """What to actually do about a failed probe, or "" when we have nothing specific to add.

    An HTTP status where a 101 belongs is the signature worth naming: it means something spoke
    HTTP back to us, so we reached a server and it declined to upgrade. On a network that
    inspects TLS that is usually the proxy rather than ares.
    """
    if isinstance(exc, websockets.exceptions.InvalidStatus):
        status = exc.response.status_code
        if status in (401, 403):
            # Genuinely ambiguous: ares answers 403 when it rejects the token (Starlette turns a
            # close-before-accept into one), and a proxy refusing an upgrade usually answers 403
            # too. Rather than guess, hand over the discriminator.
            return (
                " Either ares rejected the agent token on the upgrade, or something in the path "
                "refused it. The control-plane line above tells you which: if that succeeded, "
                "the same token is good, so the upgrade is being blocked or its Authorization "
                "header stripped, most likely by a proxy."
            )
        return (
            f" Something answered with HTTP {status} where a 101 upgrade belongs, so the "
            "WebSocket was refused rather than the connection blocked. A proxy that inspects "
            "TLS often needs WebSocket upgrades allowed explicitly for this host."
        )
    if isinstance(exc, TimeoutError):
        return (
            " The upgrade timed out. Traffic reached the network but nothing completed the "
            "handshake, which is what a proxy silently dropping WebSocket upgrades looks like."
        )
    return ""


def normalize_host(host: str) -> str:
    """Comparable form of a hostname: lowercase, no trailing root dot."""
    return host.strip().rstrip(".").lower()


def is_ip_literal(value: str) -> bool:
    """Whether ``value`` is already an address, so nothing needs resolving."""
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


# What ares pushes to mean "any hostname, for as long as this stays on the list". It is sent only
# while an interactive login is parked waiting for a human, and withdrawn the moment that window
# closes, because a federated sign-in visits hosts nobody can enumerate in advance: the operator's
# browser is handed to an identity provider, bounced through whatever asset CDNs the login page
# pulls from, and handed back. Enumerating those was a guessing game the customer always lost.
#
# It widens NAMES ONLY, and only as far as public address space. An IP literal is still bounded by
# the registered networks below; a name it approves is still resolved on this agent's own resolver,
# and the address that comes back must still be globally routable, because a pattern matching
# everything says nothing about which destination was intended. Loopback, link-local, private and
# other special-use space stay unreachable through it.
ANY_HOST = "*"


class HostApproval(Enum):
    """How ares approved a name, because how broadly it was approved bounds where it may point.

    An exact name is a destination somebody chose, so it is trusted the way an operator-scoped
    address is. A suffix or ``*`` matches names nobody enumerated in advance, proving nothing about
    intent, so :func:`globally_routable` has to vouch for the address instead. The wider the
    pattern, the narrower the address privilege.
    """

    NONE = "none"
    EXACT = "exact"
    SUFFIX = "suffix"
    WILDCARD = "wildcard"


# Narrowest first. A host can match several entries at once - ares pushes ``*`` alongside the run's
# real target while an interactive login is parked - and the narrowest match is the one that
# describes what was actually intended, so it is the one that decides.
_APPROVAL_PRECEDENCE = (HostApproval.EXACT, HostApproval.SUFFIX, HostApproval.WILDCARD)


def _entry_matches(host: str, raw: str) -> HostApproval:
    """How one allowed-hosts entry matches ``host``.

    Three forms, in the order an operator would expect:

    * ``*`` - any hostname (see :data:`ANY_HOST`).
    * ``*.example.com`` / ``.example.com`` - that domain and anything under it. Exact-match-only
      was a silent hole: ares ships ``okta.com``, ``auth0.com``, ``pingone.com`` and friends as
      built-in identity providers, but every real tenant is ``acme.okta.com``, so none of them ever
      matched anything and the entries did nothing at all.
    * anything else - an exact hostname.

    A suffix entry never matches the bare label it is a suffix of by accident: ``.okta.com`` covers
    ``acme.okta.com`` and ``okta.com``, but never ``notokta.com``.
    """
    needle = normalize_host(host)
    entry = normalize_host(raw)
    if not needle or not entry:
        return HostApproval.NONE
    if entry == ANY_HOST:
        return HostApproval.WILDCARD
    if entry.startswith("*."):
        entry = entry[1:]  # "*.example.com" -> ".example.com"
    if entry.startswith("."):
        domain = entry.lstrip(".")
        if domain and (needle == domain or needle.endswith(f".{domain}")):
            return HostApproval.SUFFIX
        return HostApproval.NONE
    return HostApproval.EXACT if needle == entry else HostApproval.NONE


def host_approval(host: str, allowed_hosts: Iterable[str]) -> HostApproval:
    """How ares approved ``host`` for a running assessment, or :attr:`HostApproval.NONE`.

    Every entry is considered, not just the first that matches, because the answer has to be the
    narrowest way this host was approved. ``{"*", "intranet.acme.local"}`` is a real and common
    set - the wildcard for the login detour, the exact name for the target - and grading that host
    as a wildcard match would refuse the very destination the hunt is for.
    """
    matched = {_entry_matches(host, raw) for raw in allowed_hosts}
    for kind in _APPROVAL_PRECEDENCE:
        if kind in matched:
            return kind
    return HostApproval.NONE


def _normalized_address(address: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """The address to judge, or None if it will not parse.

    An IPv4-mapped IPv6 answer is reduced to the IPv4 address it really is, because
    ``::ffff:169.254.169.254`` is link-local reached by a second spelling: judged as a v6 address it
    looks globally routable, and the guard below would wave it through.
    """
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return None
    if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped is not None:
        return parsed.ipv4_mapped
    return parsed


def globally_routable(address: str) -> bool:
    """Whether a *pattern*-approved name is allowed to resolve here: the public internet only.

    Fails closed on anything that will not parse. ``is_global`` is the right primitive because it
    carries the special-use registries - False for loopback, link-local (169.254/16, so cloud
    metadata), RFC 1918, CGNAT, the unspecified address and the reserved test/benchmark ranges -
    unlike ``is_private``, which :func:`agent.reachability.is_private_v4` documents as unreliable.

    Multicast is excluded explicitly because ``is_global`` is **True** for it in both families
    (``224.0.0.1``, ``ff02::1``). A tunnel has no business dialling a group address, and
    ``is_global`` alone would have left that open.
    """
    parsed = _normalized_address(address)
    if parsed is None:
        return False
    return parsed.is_global and not parsed.is_multicast


class Refused(Exception):
    """The destination is not authorized for this agent; the message is the log reason."""


def summarize_addresses(addresses: list[str]) -> str:
    """Name the first few addresses and count the rest, so one refusal stays one readable line.

    A name behind a large CDN or anycast pool resolves to a dozen-plus A/AAAA records; printing all
    of them turns every refusal into an unreadable wall.
    """
    if len(addresses) <= _ADDRESSES_NAMED:
        return ", ".join(addresses)
    named = ", ".join(addresses[:_ADDRESSES_NAMED])
    return f"{named}, +{len(addresses) - _ADDRESSES_NAMED} more"


class RefusalLog:
    """Collapses repeated refusals into one full line per host plus a periodic rollup.

    A browser driven through the tunnel re-dials its vendor's telemetry and the target page's
    third-party assets on every page load, so one assessment refuses the same handful of hosts
    hundreds of times. Logged once per dial, that buries the refusal an operator actually needs to
    see (a dial at something they did not expect). So a host is reported in full the first time it is
    refused, up to ``_HOSTS_REPORTED_MAX`` distinct hosts, and everything after that is counted into
    a rollup instead.
    """

    def __init__(self) -> None:
        self._reported: set[str] = set()
        self._suppressed: Counter[str] = Counter()
        self._last_rollup = time.monotonic()

    def record(self, host: str, reason: str) -> None:
        unseen = host not in self._reported
        if unseen and len(self._reported) < _HOSTS_REPORTED_MAX:
            self._reported.add(host)
            logger.warning("refused tunnel target: %s", reason)
        else:
            self._suppressed[host] += 1
        if time.monotonic() - self._last_rollup >= _ROLLUP_INTERVAL:
            self.flush()

    def flush(self) -> None:
        """Report the repeats counted since the last rollup, then reset the clock.

        Called on the interval and again at close, so the final batch is never lost. ``_reported``
        deliberately survives a flush: a host already explained in full should not be explained
        again on the next one.
        """
        self._last_rollup = time.monotonic()
        if not self._suppressed:
            return
        logger.info(
            "refused %d further tunnel dial(s) to %d host(s): %s",
            sum(self._suppressed.values()),
            len(self._suppressed),
            ", ".join(f"{host} x{n}" for host, n in self._suppressed.most_common()),
        )
        self._suppressed.clear()


class TunnelClient:
    """One connected WebSocket. Lives for as long as the connection; reconnect is the
    manager's job.

    ``allowed_hosts`` is shared with the :class:`TunnelManager` and mutated in place as the
    heartbeat pushes a new set, so a hunt starting or ending never costs a reconnect.
    """

    def __init__(
        self,
        url: str,
        token: str,
        allowed_networks: list[str],
        allowed_hosts: set[str],
        *,
        scoped_hosts: set[str] | None = None,
        ssl_context: ssl.SSLContext | None,
        pins: HostPins | None = None,
    ) -> None:
        self._url = url
        self._token = token
        self._ssl_context = ssl_context
        self._allowed = [ipaddress.ip_network(n, strict=False) for n in allowed_networks]
        self._allowed_hosts = allowed_hosts
        # Shared with the manager and mutated in place, exactly like ``allowed_hosts``: an address
        # added in the dashboard reaches a live tunnel on the next beat, without a reconnect.
        self._scoped_hosts = scoped_hosts if scoped_hosts is not None else set()
        self._pins = pins if pins is not None else HostPins()
        self._writers: dict[int, asyncio.StreamWriter] = {}
        self._ws: websockets.ClientConnection | None = None
        self._refusals = RefusalLog()

    def _in_allowed_networks(self, address: str) -> bool:
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            return False  # fail closed: an address we cannot parse is never "inside"
        return any(ip in net for net in self._allowed)

    def _in_operator_scope(self, host: str) -> bool:
        """Whether an operator put this exact destination in the agent's scope in the dashboard.

        EXACT match only, deliberately, and that is the difference between this and
        :func:`host_approved` beside it. That one implements a per-run widening that understands
        wildcards and domain suffixes, because an interactive login visits hosts nobody can list in
        advance. This is a standing statement about one address a person typed, so it grants that
        address and nothing adjacent to it: no suffix, no wildcard, no "and anything under it".
        """
        return normalize_host(host) in self._scoped_hosts

    async def _dial_address(self, host: str, port: int) -> str:
        """The address to dial for ``host``, or raise :class:`Refused`.

        An IP literal must be inside the registered networks, or be one an operator put in this
        agent's scope by hand. That second clause exists because the two halves are decided in
        different places: the agent bounds an address by the networks IT detected, while the scope
        is what ares was told, and an operator can legitimately add an address the agent's own
        detection never reached. Without it a scan finds such a host and the tunnel then refuses to
        dial it, which reads as a machine that exists and cannot be assessed. It widens by exact
        address only (see :meth:`_in_operator_scope`), so it can never open a network.

        A hostname is resolved here, and then the authority for dialling it decides how far that
        authority reaches. Strongest first:

        * every address inside the registered networks - allowed, as it always has been;
        * an exact host an operator put in this agent's scope - allowed wherever it resolves,
          because that is a person naming one destination on purpose;
        * an exact name ares pushed for a running hunt - likewise allowed wherever it resolves: the
          assessment names its target, and that target is routinely an internal name that
          split-horizon DNS answers with a private address;
        * a pattern ares pushed - ``*`` or a domain suffix - allowed only if every address it
          resolved to is globally routable. A pattern matches names nobody enumerated, so it is no
          evidence that a particular destination was intended, and it must not become a route to
          loopback, cloud metadata, or a private segment this agent never registered for.

        Every address has to pass, not only the one that gets dialled: whoever controls the DNS
        answer controls its order, so approving a mixed reply and then taking the first record
        would be the same as not checking.

        Returning a concrete address (not the name) is what keeps the check and the connect on the
        same destination.
        """
        if is_ip_literal(host):
            if not self._in_allowed_networks(host) and not self._in_operator_scope(host):
                raise Refused(
                    f"{host} is outside this agent's registered networks and is not in its scope"
                )
            return host
        addresses = await self._resolve(host, port)
        if all(self._in_allowed_networks(value) for value in addresses):
            return addresses[0]
        approval = host_approval(host, self._allowed_hosts)
        # A destination somebody named on purpose: an operator's standing scope entry, or the exact
        # target of this run. Either may legitimately be an internal host on a private address.
        if self._in_operator_scope(host) or approval is HostApproval.EXACT:
            return addresses[0]
        if approval is not HostApproval.NONE:
            unroutable = [value for value in addresses if not globally_routable(value)]
            if unroutable:
                raise Refused(
                    f"{host} is approved for this assessment by {approval.value} match only, and "
                    f"resolves to {summarize_addresses(unroutable)}, which is not public address "
                    "space; a pattern that matches names nobody listed cannot reach loopback, "
                    "link-local, private or reserved destinations. Add the exact host to this "
                    "agent's scope if it is genuinely a target."
                )
            return addresses[0]
        raise Refused(
            f"{host} resolves outside this agent's registered networks "
            f"({summarize_addresses(addresses)}), is not in this agent's scope, and is not an "
            "approved target of a running assessment"
        )

    async def _resolve(self, host: str, port: int) -> list[str]:
        """Addresses for ``host``: a static pin if one exists, else this agent's resolver.

        Deduplicated, order preserved. A pin short-circuits DNS entirely, which is the point: it is
        what an operator reaches for when the resolver will not answer a name at all.
        """
        if pinned := self._pins.lookup(host):
            return pinned
        try:
            infos = await asyncio.wait_for(
                asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM),
                _RESOLVE_TIMEOUT,
            )
        except asyncio.TimeoutError as exc:
            # str(TimeoutError()) is EMPTY, so interpolating the exception the way the OSError arm
            # does produced "... did not resolve on this agent: " and left the reader staring at a
            # sentence that stopped at the colon. Say what actually happened instead.
            raise Refused(
                f"{host} did not resolve on this agent within {_RESOLVE_TIMEOUT:.0f}s "
                "(the resolver did not answer; pin it in the host's /etc/hosts or "
                "ARES_HOST_ALIASES if it never will)"
            ) from exc
        except OSError as exc:
            raise Refused(f"{host} did not resolve on this agent: {exc}") from exc
        addresses = list(dict.fromkeys(str(info[4][0]) for info in infos))
        if not addresses:
            raise Refused(f"{host} resolved to no address on this agent")
        return addresses

    async def run(self) -> None:
        # The same context the control plane verifies with (agent.tlsconf), so the two halves of
        # the agent can never disagree about which CAs are trusted. A plain ws:// URL has no TLS
        # to configure.
        ssl_context = self._ssl_context if self._url.startswith("wss://") else None
        async with websockets.connect(
            self._url,
            additional_headers={"Authorization": f"Bearer {self._token}"},
            ssl=ssl_context,
            max_size=None,
        ) as ws:
            self._ws = ws
            logger.info("tunnel connected")
            try:
                async for message in ws:
                    if not isinstance(message, bytes):
                        continue
                    try:
                        await self._handle(message)
                    except Exception as exc:  # noqa: BLE001 - one bad frame must not drop the tunnel
                        logger.warning("error handling tunnel frame: %s", exc)
            finally:
                self._refusals.flush()  # so the last batch of repeats is never lost
                for writer in self._writers.values():
                    writer.close()
                self._writers.clear()

    async def _handle(self, frame: bytes) -> None:
        opcode, stream_id, payload = _decode(frame)
        if opcode == _OPEN:
            await self._open(stream_id, payload)
        elif opcode == _DATA:
            writer = self._writers.get(stream_id)
            if writer is not None:
                writer.write(payload)
                await writer.drain()
        elif opcode == _CLOSE:
            writer = self._writers.pop(stream_id, None)
            if writer is not None:
                writer.close()

    async def _open(self, stream_id: int, payload: bytes) -> None:
        try:
            target = json.loads(payload)
            host, port = str(target["host"]), int(target["port"])
        except (ValueError, KeyError, TypeError) as exc:
            logger.warning("ignoring malformed OPEN frame: %s", exc)
            await self._send(_encode(_OPEN_ERR, stream_id))
            return
        try:
            address = await self._dial_address(host, port)
        except Refused as exc:
            self._refusals.record(host, str(exc))
            await self._send(_encode(_OPEN_ERR, stream_id))
            return
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(address, port), timeout=_DIAL_TIMEOUT
            )
        except (OSError, asyncio.TimeoutError) as exc:
            logger.info("tunnel dial to %s:%d failed: %s", address, port, exc)
            await self._send(_encode(_OPEN_ERR, stream_id))
            return
        if address != host:
            logger.info("tunnel dialed %s:%d for %s", address, port, host)
        self._writers[stream_id] = writer
        await self._send(_encode(_OPEN_OK, stream_id))
        asyncio.create_task(self._relay_to_ares(stream_id, reader))

    async def _relay_to_ares(self, stream_id: int, reader: asyncio.StreamReader) -> None:
        try:
            while True:
                data = await reader.read(_RELAY_CHUNK)
                if not data:
                    break
                await self._send(_encode(_DATA, stream_id, data))
        except OSError:
            pass
        finally:
            self._writers.pop(stream_id, None)
            await self._send(_encode(_CLOSE, stream_id))

    async def _send(self, frame: bytes) -> None:
        if self._ws is not None:
            try:
                await self._ws.send(frame)
            except websockets.ConnectionClosed:
                pass


class TunnelManager:
    """Opens the tunnel while a hunt needs it and tears it down when it does not.

    Driven by the heartbeat: ``sync(tunnel_required, allowed_hosts)`` each beat. While required,
    a supervisor keeps a ``TunnelClient`` connected, reconnecting with backoff if the socket
    drops; when no longer required, it is cancelled. The pushed host set is updated in place, so
    the live client sees the current one without reconnecting.
    """

    def __init__(
        self,
        url: str,
        token: str,
        allowed_networks: list[str],
        *,
        ssl_context: ssl.SSLContext | None,
        pins: HostPins | None = None,
    ) -> None:
        self._url = url
        self._token = token
        self._allowed_networks = allowed_networks
        self._allowed_hosts: set[str] = set()
        # The addresses an operator put in this agent's scope in the dashboard. Held apart from
        # _allowed_hosts because they authorize differently: this set is matched exactly and holds
        # across runs, that one understands wildcards and lasts as long as a hunt does.
        self._scoped_hosts: set[str] = set()
        self._ssl_context = ssl_context
        self._pins = pins if pins is not None else HostPins()
        self._task: asyncio.Task[None] | None = None

    def set_networks(self, networks: list[str]) -> None:
        """Replace the networks an IP literal is bounded by, as reachability discovery learns more.

        Takes effect on the next tunnel connection rather than on a live one: a connected client
        parsed the list when it was built. That is a window of one reconnect against a re-detection
        cadence measured in hours, and the alternative (re-parsing every CIDR on every dial) buys
        nothing an operator would notice.
        """
        if networks == self._allowed_networks:
            return
        logger.info("tunnel allowed networks: %s", ", ".join(networks) or "none")
        self._allowed_networks = list(networks)

    def sync(
        self,
        required: bool,
        allowed_hosts: Iterable[str] = (),
        scoped_hosts: Iterable[str] = (),
    ) -> None:
        scoped = {normalize_host(h) for h in scoped_hosts if h and h.strip()}
        if scoped != self._scoped_hosts:
            logger.info("tunnel scoped hosts: %s", ", ".join(sorted(scoped)) or "none")
        self._scoped_hosts.clear()
        self._scoped_hosts.update(scoped)
        pushed = {normalize_host(h) for h in allowed_hosts if h and h.strip()}
        if pushed != self._allowed_hosts:
            # name the wildcard for what it means. "tunnel hostname destinations: *" reads like a
            # formatting bug in a log an operator may be asked to send us.
            shown = (
                "any host (interactive login in progress)"
                if ANY_HOST in pushed
                else ", ".join(sorted(pushed)) or "none"
            )
            logger.info("tunnel hostname destinations: %s", shown)
        self._allowed_hosts.clear()
        self._allowed_hosts.update(pushed)
        running = self._task is not None and not self._task.done()
        if required and not running:
            logger.info("internal hunt active; opening data-plane tunnel")
            self._task = asyncio.create_task(self._supervise())
        elif not required and running:
            logger.info("no internal hunt active; closing data-plane tunnel")
            self.stop()

    def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            self._task = None

    async def _supervise(self) -> None:
        backoff = _RECONNECT_BACKOFF_MIN
        while True:
            try:
                await TunnelClient(
                    self._url,
                    self._token,
                    self._allowed_networks,
                    self._allowed_hosts,
                    scoped_hosts=self._scoped_hosts,
                    ssl_context=self._ssl_context,
                    pins=self._pins,
                ).run()
                backoff = _RECONNECT_BACKOFF_MIN  # clean close; the next reconnect starts fresh
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 - reconnect on any transport error
                logger.warning("tunnel disconnected: %s; reconnecting in %.0fs", exc, backoff)
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, _RECONNECT_BACKOFF_MAX)
