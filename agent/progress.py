"""Percent-only progress reports for one scan task, coalesced before they reach the control plane.

The scanner calls its progress callback once per percentage point it advances, from inside the
``asyncio.gather`` that probes a chunk's hosts. When a /24's hosts are mostly dead their probes all
time out at the same instant, so every point the chunk is worth arrives at once: up to 90 posts
for one task within a millisecond, each one awaited inside the gather it was reported from.

On 2026-10-14 that was most of an outage (ARES-1743). The control plane handles a task's posts one
at a time, because each one takes that task's row lock, and on a 20,000-task discovery operation
each post also cost a few hundred milliseconds. A burst of 90 queued for 40 seconds, parked most of
the API's database connections in lock waits, and held the scan up the whole time, since every
gather branch waited for its own post.

So a percentage is a value to keep current, not an event to deliver. :class:`ProgressReporter`
keeps the latest one, sends at most one post at a time, and leaves at least ``min_interval``
between posts; nothing the scanner calls ever waits on the network. Posts that carry discovered
hosts or naming evidence do not go through here: they are data, and each one is sent as it comes.
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

        Called when the scan is over, because what comes next settles the task's progress on the
        server whatever it was: a completion or a failure pins it at 100, and a task handed back
        after a pause starts again from nothing. A last percentage sent first would be overwritten
        a moment later, after holding the task up for a round trip.
        """
        self._pending = None
        if self._sender is not None and not self._sender.done():
            self._sender.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._sender

    async def _drain(self) -> None:
        while self._pending is not None:
            if self._last_sent_at is not None:
                wait = self._last_sent_at + self._min_interval - self._clock()
                if wait > 0:
                    await self._sleep(wait)
            percent, self._pending = self._pending, None
            if percent is None:
                return
            self._last_sent_at = self._clock()
            try:
                await self._send(percent)
            except Exception as exc:  # noqa: BLE001 - one lost post must not stop the next
                logger.debug("progress post failed: %s", exc)
