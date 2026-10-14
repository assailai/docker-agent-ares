"""Coalescing a task's percent-only progress posts (agent.progress, ARES-1743).

The scanner reports every percentage point it passes, and a /24 whose dead hosts time out together
passes all of them at once. Posted one per point, that was 90 requests for one task in the same
millisecond, which the control plane serialises on the task's row lock. These tests pin the three
properties that replace it: one post at a time, the latest value wins, and never two posts closer
than the interval. The clock and the sleep are injected, so none of this depends on wall time.
"""

from __future__ import annotations

import asyncio

import pytest

from agent import main
from agent.progress import ProgressReporter


class _Clock:
    """A clock that only moves when the reporter sleeps, so intervals are exact."""

    def __init__(self) -> None:
        self.now = 1000.0
        self.slept: list[float] = []

    def __call__(self) -> float:
        return self.now

    async def sleep(self, seconds: float) -> None:
        self.slept.append(seconds)
        self.now += seconds


def _reporter(sent: list[int], clock: _Clock, *, min_interval: float = 2.0) -> ProgressReporter:
    async def send(percent: int) -> None:
        sent.append(percent)

    return ProgressReporter(send, min_interval=min_interval, clock=clock, sleep=clock.sleep)


async def test_a_burst_of_points_is_one_post_of_the_latest() -> None:
    # the shape of the incident: every point of a dead /24 reported before anything is sent.
    sent: list[int] = []
    reporter = _reporter(sent, _Clock())

    for percent in range(1, 91):
        reporter.update(percent)
    await reporter.idle()

    assert sent == [90]


async def test_points_closer_than_the_interval_wait_for_it_and_send_only_the_latest() -> None:
    sent: list[int] = []
    clock = _Clock()
    reporter = _reporter(sent, clock, min_interval=2.0)

    reporter.update(10)
    await reporter.idle()
    reporter.update(20)
    reporter.update(30)
    await reporter.idle()

    assert sent == [10, 30]
    assert clock.slept == [2.0]  # the second post waited out the interval, and only once


async def test_a_point_after_the_interval_is_sent_without_waiting() -> None:
    sent: list[int] = []
    clock = _Clock()
    reporter = _reporter(sent, clock, min_interval=2.0)

    reporter.update(10)
    await reporter.idle()
    clock.now += 5.0
    reporter.update(20)
    await reporter.idle()

    assert sent == [10, 20]
    assert clock.slept == []


async def test_only_one_post_is_ever_in_flight() -> None:
    # a slow control plane is exactly when posts pile up; they must queue as one value, not as
    # concurrent requests.
    in_flight = 0
    most_in_flight = 0
    sent: list[int] = []
    release = asyncio.Event()

    async def send(percent: int) -> None:
        nonlocal in_flight, most_in_flight
        in_flight += 1
        most_in_flight = max(most_in_flight, in_flight)
        await release.wait()
        sent.append(percent)
        in_flight -= 1

    reporter = ProgressReporter(send, min_interval=0.0)
    reporter.update(10)
    await asyncio.sleep(0)  # the first post is now waiting on the control plane
    for percent in (20, 30, 40):
        reporter.update(percent)
        await asyncio.sleep(0)
    release.set()
    await reporter.idle()

    assert most_in_flight == 1
    assert sent == [10, 40]


async def test_close_drops_what_was_not_sent_and_stops_the_post_in_flight() -> None:
    # the report that settles the task follows close(), and sets the task's progress itself.
    started: list[int] = []
    finished: list[int] = []

    async def send(percent: int) -> None:
        started.append(percent)
        await asyncio.Event().wait()  # a control plane that never answers
        finished.append(percent)

    reporter = ProgressReporter(send, min_interval=0.0)
    reporter.update(10)
    await asyncio.sleep(0)
    reporter.update(20)
    await reporter.close()
    await asyncio.sleep(0)

    assert started == [10]
    assert finished == []


async def test_a_failed_post_does_not_stop_the_next() -> None:
    attempts: list[int] = []

    async def send(percent: int) -> None:
        attempts.append(percent)
        if percent == 10:
            raise RuntimeError("network blip")

    reporter = ProgressReporter(send, min_interval=0.0)
    reporter.update(10)
    await reporter.idle()
    reporter.update(20)
    await reporter.idle()

    assert attempts == [10, 20]


async def test_the_scan_never_waits_on_a_progress_post(monkeypatch: pytest.MonkeyPatch) -> None:
    # every percentage callback used to await its own post, so a slow control plane slowed the
    # scan itself. With a control plane that never answers a progress post, the scan must still
    # report every point, finish, and complete the task.
    progress_posts: list[int] = []
    completed: list[list[dict]] = []

    async def _ok(*_a, **_k):
        return None

    async def _never_answers(_s, _t, _task_id, *, percent, **_kw):
        progress_posts.append(percent)
        await asyncio.Event().wait()

    async def _task_completed(_s, _t, _task_id, hosts, **_kw):
        completed.append(hosts)

    async def _fake_scan(cidr, ports, **kwargs):
        for percent in range(1, 91):
            await kwargs["on_progress"](percent)
        return []

    monkeypatch.setattr(main.control_plane, "task_started", _ok)
    monkeypatch.setattr(main.control_plane, "task_progress", _never_answers)
    monkeypatch.setattr(main.control_plane, "task_completed", _task_completed)
    monkeypatch.setattr(main.scan, "scan_cidr", _fake_scan)

    await asyncio.wait_for(main._run_task("tok", {"id": "t1", "target_network": "10.0.0.0/24"}), 10)

    assert completed == [[]]
    assert len(progress_posts) <= 1
