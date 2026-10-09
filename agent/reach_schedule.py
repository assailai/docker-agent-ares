"""When the agent next owes a probe of what it can reach.

Kept apart from the loop that runs the probe so the decision can be read, and tested, without an
event loop: the loop in agent.main asks this question on every heartbeat tick and probes when the
answer is 0.

The rules, in the order they apply:

* **Nothing usable stored, never attempted:** probe now. Every install gets one discovery whatever
  the dashboard says, because an agent that never looked has nothing to report and nothing to scan.
* **Nothing usable stored, an attempt already failed:** try again on the refresh interval, never in
  a hot loop. A probe that keeps failing must not turn into a stream of connects.
* **Automatic rescans off, an answer stored:** never. The stored answer stands until the operator
  turns rescans back on or presses Rescan in the dashboard.
* **Automatic rescans on:** once the last probe is older than the interval.

An interval of 0 (``ARES_REACH_REFRESH_SECONDS=0``) means no re-detection at all, so it only ever
answers "now" for an agent that has never probed.
"""

from __future__ import annotations


def probe_delay(
    *,
    auto_rescan: bool,
    has_result: bool,
    probed_at: float | None,
    now: float,
    interval: int,
) -> float | None:
    """Seconds until the next reachability probe: 0 means now, None means none is owed.

    None is "not while nothing changes", not "never": the caller asks again on its next tick, so
    turning rescans back on in the dashboard is picked up without a restart.
    """
    if has_result and not auto_rescan:
        return None
    if probed_at is None:
        return 0.0
    if interval <= 0:
        return None
    return max(0.0, probed_at + interval - now)
