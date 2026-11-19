"""Static hostname -> address pins, so an operator can bypass DNS for a name it will not answer.

Two sources, both optional, checked before the resolver:

* ``/host-hosts`` - the **host's** ``/etc/hosts``, mounted read-only by the install command. This
  exists because editing ``/etc/hosts`` on the machine is the first thing anyone reaches for when a
  name will not resolve, and it silently does nothing for the agent: a container gets docker's own
  ``/etc/hosts``, even under ``--network host``, because host networking shares the network
  namespace and not the mount namespace. Exactly the same shape as the CA-trust trap ``tlsconf``
  fixes, and fixed the same way - mount what the host has and read it here.
* ``ARES_HOST_ALIASES`` - explicit ``name=address`` pairs, for a pin the host file does not carry.

The file is re-read when its mtime changes, so an operator can add a name and have the running
agent pick it up on its next dial. That is the whole point of preferring the mount over
``--add-host``: a pin costs an edit, never a container recreate.

A pin is authorization-neutral. It only supplies the address DNS would have; every address it
yields still goes through the same dial guard (:mod:`agent.dial_guard`) and the same
registered-networks / ares-approved check in ``TunnelClient._approved_addresses``, so pinning a
name cannot widen what this agent will dial. That includes the ``127.0.1.1 <hostname>`` line many
distributions put in ``/etc/hosts``: a pushed name equal to this machine's hostname is refused,
not dialled onto loopback.
"""

from __future__ import annotations

import ipaddress
import logging
from pathlib import Path

logger = logging.getLogger("ares.agent.hostpins")

# The host's /etc/hosts, mounted by the install command. Named for its origin rather than its
# content so it can never be confused with the container's own /etc/hosts.
HOST_HOSTS_FILE = Path("/host-hosts")


def parse_hosts_file(text: str) -> dict[str, list[str]]:
    """Parse ``/etc/hosts`` content into ``{lowercase name: [address, ...]}``.

    Standard format: an address followed by one or more names, ``#`` starts a comment. A malformed
    line is skipped rather than fatal - this file is edited by hand under time pressure, and one
    bad line must not cost every good one.
    """
    pins: dict[str, list[str]] = {}
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        address, names = parts[0], parts[1:]
        try:
            ipaddress.ip_address(address)
        except ValueError:
            continue  # first field is not an address, so this is not a hosts line
        for name in names:
            key = name.strip().rstrip(".").lower()
            # localhost and the ipv6 boilerplate every hosts file carries are never destinations
            # worth pinning, and quietly dropping them keeps the summary honest.
            if not key or key == "localhost" or key.startswith("ip6-"):
                continue
            pins.setdefault(key, []).append(address)
    return pins


class HostPins:
    """The pin table, reloaded from the mounted host file whenever it changes on disk."""

    def __init__(self, *, aliases: str = "", path: Path = HOST_HOSTS_FILE) -> None:
        self._path = path
        self._aliases = _parse_aliases(aliases)
        self._from_file: dict[str, list[str]] = {}
        self._mtime: float | None = None
        self._reload_if_changed()

    def lookup(self, host: str) -> list[str]:
        """Pinned addresses for ``host``, or ``[]`` when nothing pins it.

        ``ARES_HOST_ALIASES`` wins over the host file: it is the more specific, more deliberate of
        the two, and it is the escape hatch someone reaches for precisely when the file is wrong.
        """
        self._reload_if_changed()
        key = host.strip().rstrip(".").lower()
        return self._aliases.get(key) or self._from_file.get(key) or []

    def reverse(self, address: str) -> str | None:
        """The pinned name for ``address``, or ``None`` when nothing pins it.

        The inverse of :meth:`lookup`, for naming a discovered host: the operator already told us
        what this address is called when they put it in the host's ``/etc/hosts``, and that is a
        name the resolver frequently will not answer for. Built on demand rather than kept as a
        second index, because the pin table is small and this runs once per discovered host.

        When several names pin the same address the shortest wins, which prefers the canonical
        ``db-01.corp.local`` over a longer alias someone added later.
        """
        self._reload_if_changed()
        target = address.strip()
        names = [
            name
            for table in (self._aliases, self._from_file)
            for name, addresses in table.items()
            if target in addresses
        ]
        return min(names, key=len) if names else None

    def summary(self) -> str:
        """One line for the startup log, so the pin table is never a silent input."""
        parts = []
        if self._aliases:
            parts.append(f"ARES_HOST_ALIASES ({len(self._aliases)})")
        if self._from_file:
            parts.append(f"{self._path} ({len(self._from_file)} name(s))")
        elif self._path.exists():
            parts.append(f"{self._path} (no usable entries)")
        return ", ".join(parts) if parts else "none"

    def _reload_if_changed(self) -> None:
        try:
            mtime = self._path.stat().st_mtime
        except OSError:
            # not mounted (the ordinary case) or unreadable: aliases still apply.
            if self._from_file:
                self._from_file = {}
                self._mtime = None
            return
        if mtime == self._mtime:
            return
        try:
            parsed = parse_hosts_file(self._path.read_text(encoding="utf-8", errors="replace"))
        except OSError as exc:
            logger.warning("could not read %s: %s", self._path, exc)
            return
        self._mtime = mtime
        if parsed != self._from_file:
            logger.info("host pins from %s: %d name(s)", self._path, len(parsed))
        self._from_file = parsed


def _parse_aliases(raw: str) -> dict[str, list[str]]:
    """Parse ``ARES_HOST_ALIASES``: ``name=address`` pairs separated by commas or whitespace."""
    pins: dict[str, list[str]] = {}
    for item in raw.replace(",", " ").split():
        name, sep, address = item.partition("=")
        if not sep:
            logger.warning("ignoring malformed ARES_HOST_ALIASES entry (want name=address): %s", item)
            continue
        try:
            ipaddress.ip_address(address.strip())
        except ValueError:
            logger.warning("ignoring ARES_HOST_ALIASES entry with a bad address: %s", item)
            continue
        pins.setdefault(name.strip().rstrip(".").lower(), []).append(address.strip())
    return pins
