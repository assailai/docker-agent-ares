"""When the agent next owes a reachability probe.

The table below is the whole of the "Rescan automatically" contract on the agent side, so it is
pinned case by case: one probe at install whatever the setting, never again while the setting is
off, a failed probe retried on the interval rather than in a loop, and ARES_REACH_REFRESH_SECONDS=0
still meaning no re-detection.
"""

from __future__ import annotations

import pytest

from agent.reach_schedule import probe_delay

_INTERVAL = 21_600
_NOW = 1_760_000_000.0


@pytest.mark.parametrize(
    ("auto_rescan", "has_result", "probed_at", "interval", "expected"),
    [
        # never probed: now, whatever the setting, because an install that never looked has
        # nothing to report and nothing for ares to scan
        (True, False, None, _INTERVAL, 0.0),
        (False, False, None, _INTERVAL, 0.0),
        (False, False, None, 0, 0.0),
        # rescans off with an answer stored: never, however old the answer is
        (False, True, _NOW - 10 * _INTERVAL, _INTERVAL, None),
        (False, True, None, _INTERVAL, None),
        # rescans on: once the last look is older than the interval
        (True, True, _NOW - 100, _INTERVAL, _INTERVAL - 100),
        (True, True, _NOW - _INTERVAL, _INTERVAL, 0.0),
        (True, True, _NOW - 3 * _INTERVAL, _INTERVAL, 0.0),
        # an attempt that failed is retried on the interval, not on every tick, with rescans on
        # or off: a probe that keeps failing must not become a stream of connects
        (False, False, _NOW - 30, _INTERVAL, _INTERVAL - 30),
        (True, False, _NOW - 30, _INTERVAL, _INTERVAL - 30),
        # ARES_REACH_REFRESH_SECONDS=0: no re-detection once a look has been made
        (True, True, _NOW - 3 * _INTERVAL, 0, None),
        (True, False, _NOW - 30, 0, None),
    ],
)
def test_probe_delay(
    auto_rescan: bool,
    has_result: bool,
    probed_at: float | None,
    interval: int,
    expected: float | None,
) -> None:
    assert (
        probe_delay(
            auto_rescan=auto_rescan,
            has_result=has_result,
            probed_at=probed_at,
            now=_NOW,
            interval=interval,
        )
        == expected
    )
