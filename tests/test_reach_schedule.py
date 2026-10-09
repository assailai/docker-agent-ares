"""When the agent next owes a reachability probe.

The table below is the whole of the "Rescan automatically" contract on the agent side, so it is
pinned case by case: one probe at install whatever the setting, never again while the setting is
off, a failed probe retried on the interval rather than in a loop, and ARES_REACH_REFRESH_SECONDS=0
still meaning no re-detection.
"""

from __future__ import annotations

import pytest

from agent.reach_schedule import probe_delay

# the default ARES_REACH_REFRESH_SECONDS: six hours
_INTERVAL = 21_600
# an arbitrary fixed wall clock; only the offsets from it matter
_NOW = 1_760_000_000.0
# seconds since a recent probe, and since a recent failed one: both well inside the interval
_PROBED_AGO = 100
_FAILED_AGO = 30


@pytest.mark.parametrize(
    ("auto_rescan", "has_result", "probed_at", "interval", "expected"),
    [
        # given nothing was ever probed, then probe now whatever the setting: an install that
        # never looked has nothing to report and nothing for ares to scan
        pytest.param(True, False, None, _INTERVAL, 0.0, id="never-probed-on-now"),
        pytest.param(False, False, None, _INTERVAL, 0.0, id="never-probed-off-now"),
        pytest.param(False, False, None, 0, 0.0, id="never-probed-single-pass-now"),
        # given rescans off and an answer stored, then never, however old the answer is
        pytest.param(
            False, True, _NOW - 10 * _INTERVAL, _INTERVAL, None, id="off-stored-stale-never"
        ),
        pytest.param(False, True, None, _INTERVAL, None, id="off-stored-unstamped-never"),
        # given rescans on, then probe once the last look is older than the interval
        pytest.param(
            True,
            True,
            _NOW - _PROBED_AGO,
            _INTERVAL,
            _INTERVAL - _PROBED_AGO,
            id="on-recent-waits-out-the-interval",
        ),
        pytest.param(True, True, _NOW - _INTERVAL, _INTERVAL, 0.0, id="on-due-now"),
        pytest.param(True, True, _NOW - 3 * _INTERVAL, _INTERVAL, 0.0, id="on-overdue-now"),
        # given a failed attempt and nothing stored, then retry on the interval rather than on
        # every tick, with rescans on or off: a failing probe must not become a stream of connects
        pytest.param(
            False,
            False,
            _NOW - _FAILED_AGO,
            _INTERVAL,
            _INTERVAL - _FAILED_AGO,
            id="off-failed-retries-on-the-interval",
        ),
        pytest.param(
            True,
            False,
            _NOW - _FAILED_AGO,
            _INTERVAL,
            _INTERVAL - _FAILED_AGO,
            id="on-failed-retries-on-the-interval",
        ),
        # given ARES_REACH_REFRESH_SECONDS=0 and a look already made, then no re-detection
        pytest.param(True, True, _NOW - 3 * _INTERVAL, 0, None, id="single-pass-stored-never"),
        pytest.param(True, False, _NOW - _FAILED_AGO, 0, None, id="single-pass-failed-never"),
    ],
)
def test_probe_delay(
    auto_rescan: bool,
    has_result: bool,
    probed_at: float | None,
    interval: int,
    expected: float | None,
) -> None:
    """Given the setting, whether an answer is stored, the last attempt and the interval; when the
    loop asks for its next probe; then it gets the row's delay (0 is now, None is none owed)."""
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
