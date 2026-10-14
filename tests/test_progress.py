"""Coalescing a task's percent-only progress posts (agent.progress, ARES-1743).

The clock and the sleep are injected, so nothing here depends on wall time.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from agent import main
from agent.progress import ProgressReporter

# every point a /24 of dead hosts reports at once: the sweep's share of the bar
# (scan._SWEEP_PROGRESS_CEILING), which is the burst the incident was made of
_BURST_POINTS = 90
# generous ceiling on one whole fake task run; it only trips if the scan waits on a post
_RUN_TIMEOUT_S = 10.0


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
    # given a dead /24 reporting every point before anything is sent (the incident's shape)
    sent: list[int] = []
    reporter = _reporter(sent, _Clock())

    # when every point arrives at once
    for percent in range(1, _BURST_POINTS + 1):
        reporter.update(percent)
    await reporter.idle()

    # then one post goes out, carrying the last point
    assert sent == [_BURST_POINTS]


async def test_points_closer_than_the_interval_wait_for_it_and_send_only_the_latest() -> None:
    # given a post that has just gone out
    sent: list[int] = []
    clock = _Clock()
    reporter = _reporter(sent, clock, min_interval=2.0)
    reporter.update(10)
    await reporter.idle()

    # when two more points arrive inside the interval
    reporter.update(20)
    reporter.update(30)
    await reporter.idle()

    # then the reporter waits the interval out once and sends only the latest of them
    assert sent == [10, 30]
    assert clock.slept == [2.0]


async def test_a_point_after_the_interval_is_sent_without_waiting() -> None:
    # given a post that went out well over an interval ago
    sent: list[int] = []
    clock = _Clock()
    reporter = _reporter(sent, clock, min_interval=2.0)
    reporter.update(10)
    await reporter.idle()
    clock.now += 5.0

    # when the next point arrives
    reporter.update(20)
    await reporter.idle()

    # then it goes straight out
    assert sent == [10, 20]
    assert clock.slept == []


async def test_only_one_post_is_ever_in_flight() -> None:
    # given a slow control plane, which is exactly when posts pile up
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

    # when more points arrive while it is still waiting
    for percent in (20, 30, 40):
        reporter.update(percent)
        await asyncio.sleep(0)
    release.set()
    await reporter.idle()

    # then they queue as one value behind it, never as concurrent requests
    assert most_in_flight == 1
    assert sent == [10, 40]


async def test_close_drops_what_was_not_sent_and_stops_the_post_in_flight() -> None:
    # given a post stuck on a control plane that never answers, and another point waiting
    started: list[int] = []
    finished: list[int] = []

    async def send(percent: int) -> None:
        started.append(percent)
        await asyncio.Event().wait()
        finished.append(percent)

    reporter = ProgressReporter(send, min_interval=0.0)
    reporter.update(10)
    await asyncio.sleep(0)
    reporter.update(20)

    # when the task is over and the reporter is closed
    await reporter.close()
    await asyncio.sleep(0)

    # then the stuck post is stopped and the waiting point is never sent
    assert started == [10]
    assert finished == []


async def test_a_failed_post_does_not_stop_the_next() -> None:
    # given a control plane that refuses the first post
    attempts: list[int] = []

    async def send(percent: int) -> None:
        attempts.append(percent)
        if percent == 10:
            raise RuntimeError("network blip")

    reporter = ProgressReporter(send, min_interval=0.0)
    reporter.update(10)
    await reporter.idle()

    # when the next point arrives
    reporter.update(20)
    await reporter.idle()

    # then it is still sent
    assert attempts == [10, 20]


async def test_the_scan_never_waits_on_a_progress_post(monkeypatch: pytest.MonkeyPatch) -> None:
    # given a control plane that never answers a progress post (every percentage callback used to
    # await its own post, so a slow control plane slowed the scan itself)
    progress_posts: list[int] = []
    completed: list[list[dict]] = []

    async def _ok(*_args: object, **_kwargs: object) -> None:
        return None

    async def _never_answers(
        _settings: object, _token: str, _task_id: str, *, percent: int, **_kwargs: object
    ) -> None:
        progress_posts.append(percent)
        await asyncio.Event().wait()

    async def _task_completed(
        _settings: object, _token: str, _task_id: str, hosts: list[dict], **_kwargs: object
    ) -> None:
        completed.append(hosts)

    async def _fake_scan(_cidr: str, _ports: list[int], **kwargs: Any) -> list[dict]:
        for percent in range(1, _BURST_POINTS + 1):
            await kwargs["on_progress"](percent)
        return []

    monkeypatch.setattr(main.control_plane, "task_started", _ok)
    monkeypatch.setattr(main.control_plane, "task_progress", _never_answers)
    monkeypatch.setattr(main.control_plane, "task_completed", _task_completed)
    monkeypatch.setattr(main.scan, "scan_cidr", _fake_scan)

    # when a task runs and its scan reports every point
    task = {"id": "t1", "target_network": "10.0.0.0/24"}
    await asyncio.wait_for(main._run_task("tok", task), timeout=_RUN_TIMEOUT_S)

    # then the scan finishes, the task completes, and at most one progress post was ever made
    assert completed == [[]]
    assert len(progress_posts) <= 1
