"""Percent-only progress reports for one scan task, coalesced before they reach the control plane.

The scanner calls its progress callback once per percentage point it advances, from inside the
``asyncio.gather`` that probes a chunk's hosts. When a /24's hosts are mostly dead their probes all
time out at the same instant, so every point the chunk is worth arrives at once: up to 90 posts
for one task within a millisecond, each one awaited inside the gather it was reported from.

The control plane takes a task's posts one at a time on that task's row lock, so on 2026-10-14 a
burst of 90 queued for 40 seconds and stalled the scan behind it (ARES-1743). Only the latest
percentage matters, so :class:`ProgressReporter` keeps that, sends one post at a time and spaces
them ``min_interval`` apart. Posts carrying hosts or naming evidence do not go through here.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from collections.abc import Awaitable, Callable

logger = logging.getLogger("ares.agent.progress")


class ProgressReporter:
    """The latest percentage of one task, posted at most once per ``min_interval``, one at a time.

    ``send`` is the post itself. It is expected not to raise (the agent's own reporter swallows a
    failed post, because progress is best-effort), but one that does costs that post and nothing
    else: the next update is sent as usual.
    """

    def __init__(
        self,
        send: Callable[[int], Awaitable[None]],
        *,
        min_interval: float,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self._send = send
        self._min_interval = min_interval
        self._clock = clock
        self._sleep = sleep
        self._pending: int | None = None
        self._last_sent_at: float | None = None
        self._sender: asyncio.Task[None] | None = None

    def update(self, percent: int) -> None:
        """Record ``percent`` as the value to send next. Returns at once, never waits on a post."""
        self._pending = percent
        if self._sender is None or self._sender.done():
            self._sender = asyncio.create_task(self._drain())

    async def idle(self) -> None:
        """Wait until nothing is pending or in flight."""
        while self._sender is not None and not self._sender.done():
            await asyncio.shield(self._sender)

    async def close(self) -> None:
        """Drop whatever has not been sent, and stop a post in flight.

        Called once the task is over. The report that settled it already set its progress on the
        server (a completion or a failure pins it at 100, a hand-back after a pause clears it), and
        the server ignores a progress post for a task that is no longer running, so a percentage
        still waiting here is worth nothing.
        """
        self._pending = None
        if self._sender is not None and not self._sender.done():
            self._sender.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._sender

    async def _drain(self) -> None:
        while self._pending is not None:
            await self._wait_out_interval()
            percent, self._pending = self._pending, None
            if percent is None:  # close() dropped it while this was waiting
                return
            self._last_sent_at = self._clock()
            try:
                await self._send(percent)
            except Exception as exc:  # noqa: BLE001 - one lost post must not stop the next
                logger.debug("progress post failed: %s", exc)

    async def _wait_out_interval(self) -> None:
        if self._last_sent_at is None:
            return
        remaining = self._last_sent_at + self._min_interval - self._clock()
        if remaining > 0:
            await self._sleep(remaining)
