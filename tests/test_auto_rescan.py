"""The dashboard's "Rescan automatically" setting, as the agent follows it.

The setting exists because a customer saw the agent probe their whole private address space every
six hours (about half a million TCP connects a pass) and asked for it to stop. So these pin the
traffic, not the bookkeeping: with the setting off, a restart sends nothing, an install sends one
probe and no more, and turning it back on resumes within a beat. They also pin the two ways the
setting must NOT move: a control plane that never sends it, and one that sends something malformed.
"""

from __future__ import annotations

import asyncio
import ssl
from pathlib import Path
from unittest.mock import Mock

import pytest

from agent import control_plane, main
from agent.state import AgentState, load_state, save_state

_ATTACHED = "172.23.0.0/16"
_FOUND = [_ATTACHED, "10.20.0.0/16"]
_INTERVAL = 21_600
_SCOPE = "reachable:True"


class _FakeTunnel:
    def __init__(self) -> None:
        self.widened: list[list[str]] = []

    def set_networks(self, networks: list[str]) -> None:
        self.widened.append(networks)


@pytest.fixture
def _reach_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """The default "reachable" scope, a state file in tmp, and nothing left over between tests."""
    monkeypatch.setattr(main.settings, "scan_scope", "reachable")
    monkeypatch.setattr(main.settings, "networks", "")
    monkeypatch.setattr(main.settings, "reach_probe", True)
    monkeypatch.setattr(main.settings, "reach_refresh_seconds", _INTERVAL)
    monkeypatch.setattr(main.settings, "data_dir", tmp_path)
    monkeypatch.setattr(main.netdetect, "scan_targets", lambda scope: [_ATTACHED])
    monkeypatch.setitem(main._reachable, "networks", [])
    monkeypatch.setitem(main._cadence, "heartbeat", 30)


def _counting_discover(monkeypatch: pytest.MonkeyPatch, answer: list[str]) -> dict[str, int]:
    probes = {"n": 0}

    async def _discover(**_kwargs: object) -> list[str]:
        probes["n"] += 1
        return answer

    monkeypatch.setattr(main.reachability, "discover", _discover)
    return probes


def _no_probe_allowed(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _explode(**_kwargs: object) -> list[str]:
        raise AssertionError("the agent probed reachability with automatic rescans off")

    monkeypatch.setattr(main.reachability, "discover", _explode)


def _clock(
    monkeypatch: pytest.MonkeyPatch,
    *,
    advance: float,
    ticks: int,
    on_tick=None,
) -> list[float]:
    """A wall clock moving ``advance`` seconds per sleep, ending the loop after ``ticks`` sleeps.

    The loop under test is endless by design, so the only way out is a cancellation, which is
    exactly what the serve loop does to it on shutdown.
    """
    now = [1_760_000_000.0]
    slept = {"n": 0}

    async def _sleep(_seconds: float) -> None:
        slept["n"] += 1
        if slept["n"] > ticks:
            raise asyncio.CancelledError
        now[0] += advance
        if on_tick is not None:
            on_tick(slept["n"])

    monkeypatch.setattr(main.asyncio, "sleep", _sleep)
    monkeypatch.setattr(main.time, "time", lambda: now[0])
    return now


def _stored(**overrides: object) -> AgentState:
    fields: dict[str, object] = {
        "agent_id": "a1",
        "agent_token": "agtk-1",
        "detected_networks": list(_FOUND),
        "detected_scope": _SCOPE,
        "reach_probed_at": 1_759_000_000.0,
    }
    fields.update(overrides)
    return AgentState(**fields)


@pytest.mark.usefixtures("_reach_env")
async def test_off_with_a_stored_answer_sends_nothing_and_still_publishes_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The restart case, and the one the setting is for: not one connect into private space. The
    # stored answer still has to reach the heartbeat and the tunnel, or a hunt into 10.20 would be
    # refused by an agent that found 10.20 perfectly well at install.
    _no_probe_allowed(monkeypatch)
    _clock(monkeypatch, advance=10 * _INTERVAL, ticks=5)
    tunnel = _FakeTunnel()

    with pytest.raises(asyncio.CancelledError):
        await main._redetect_loop(_stored(auto_rescan=False), tunnel)

    assert main._reachable["networks"] == _FOUND
    assert tunnel.widened == [_FOUND]


@pytest.mark.usefixtures("_reach_env")
async def test_off_with_nothing_stored_probes_exactly_once_and_keeps_the_answer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The install case: one discovery whatever the setting, then nothing however much time passes.
    probes = _counting_discover(monkeypatch, _FOUND)
    _clock(monkeypatch, advance=10 * _INTERVAL, ticks=5)
    state = AgentState(agent_id="a1", agent_token="agtk-1", auto_rescan=False)

    with pytest.raises(asyncio.CancelledError):
        await main._redetect_loop(state, _FakeTunnel())

    assert probes["n"] == 1
    kept = load_state(main.settings.state_path)
    assert kept.stored_detection(_SCOPE) == _FOUND
    assert kept.reach_probed_at is not None
    assert kept.auto_rescan is False


@pytest.mark.usefixtures("_reach_env")
async def test_on_probes_at_start_and_again_once_the_interval_has_passed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Unchanged behaviour for every agent that leaves the setting on, including one with an answer
    # already stored: it looks at start, then on the refresh cadence.
    probes = _counting_discover(monkeypatch, _FOUND)
    _clock(monkeypatch, advance=_INTERVAL, ticks=1)

    with pytest.raises(asyncio.CancelledError):
        await main._redetect_loop(_stored(), _FakeTunnel())

    assert probes["n"] == 2


@pytest.mark.usefixtures("_reach_env")
async def test_on_does_not_probe_again_before_the_interval(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The loop wakes on every heartbeat tick to re-read the setting. Waking must not mean probing.
    probes = _counting_discover(monkeypatch, _FOUND)
    _clock(monkeypatch, advance=30, ticks=20)

    with pytest.raises(asyncio.CancelledError):
        await main._redetect_loop(_stored(), _FakeTunnel())

    assert probes["n"] == 1


@pytest.mark.usefixtures("_reach_env")
async def test_turning_rescans_back_on_probes_at_the_next_tick_when_the_answer_is_stale(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Followed within a beat, not after the six-hour sleep the loop used to take. The stored answer
    # is days old, so the first tick after the switch owes a probe.
    probes = _counting_discover(monkeypatch, _FOUND)
    state = _stored(auto_rescan=False)

    def _switch_on(tick: int) -> None:
        if tick == 2:
            main._apply_auto_rescan(True, state=state)

    _clock(monkeypatch, advance=30, ticks=3, on_tick=_switch_on)

    with pytest.raises(asyncio.CancelledError):
        await main._redetect_loop(state, _FakeTunnel())

    assert probes["n"] == 1


@pytest.mark.usefixtures("_reach_env")
async def test_turning_rescans_off_stops_the_next_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    probes = _counting_discover(monkeypatch, _FOUND)
    state = _stored()

    def _switch_off(tick: int) -> None:
        if tick == 1:
            main._apply_auto_rescan(False, state=state)

    _clock(monkeypatch, advance=_INTERVAL, ticks=5, on_tick=_switch_off)

    with pytest.raises(asyncio.CancelledError):
        await main._redetect_loop(state, _FakeTunnel())

    assert probes["n"] == 1  # the probe at start, and none after the switch


@pytest.mark.usefixtures("_reach_env")
async def test_an_answer_stored_under_another_scope_is_not_reused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Stored with the active probe off, read with it on: a different question, so it is neither
    # published nor trusted, and the agent looks once, as it would on a fresh install.
    probes = _counting_discover(monkeypatch, _FOUND)
    _clock(monkeypatch, advance=10 * _INTERVAL, ticks=3)
    tunnel = _FakeTunnel()
    state = _stored(
        auto_rescan=False,
        detected_networks=["192.168.0.0/16"],
        detected_scope="reachable:False",
    )

    with pytest.raises(asyncio.CancelledError):
        await main._redetect_loop(state, tunnel)

    assert probes["n"] == 1
    assert tunnel.widened == [_FOUND]
    assert state.stored_detection(_SCOPE) == _FOUND


@pytest.mark.usefixtures("_reach_env")
async def test_a_failed_first_probe_is_retried_on_the_interval_not_every_tick(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attempts = {"n": 0}

    async def _fails(**_kwargs: object) -> list[str]:
        attempts["n"] += 1
        raise OSError("no route")

    monkeypatch.setattr(main.reachability, "discover", _fails)
    _clock(monkeypatch, advance=30, ticks=20)

    with pytest.raises(asyncio.CancelledError):
        await main._redetect_loop(AgentState(auto_rescan=False), _FakeTunnel())

    assert attempts["n"] == 1


@pytest.mark.usefixtures("_reach_env")
async def test_a_single_pass_interval_still_means_one_look_per_start_with_rescans_on(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # ARES_REACH_REFRESH_SECONDS=0 keeps its meaning: look at start, then return.
    monkeypatch.setattr(main.settings, "reach_refresh_seconds", 0)
    probes = _counting_discover(monkeypatch, _FOUND)

    await main._redetect_loop(_stored(), _FakeTunnel())

    assert probes["n"] == 1


@pytest.mark.usefixtures("_reach_env")
async def test_preflight_applies_the_setting_before_the_first_probe_and_persists_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _beat(*_args: object, **_kwargs: object) -> dict:
        return {"heartbeat_interval_seconds": 30, "auto_rescan": False}

    async def _tunnel_ok(*_args: object, **_kwargs: object) -> None:
        return None

    monkeypatch.setattr(main.control_plane, "heartbeat", _beat)
    monkeypatch.setattr(main, "tunnel_probe", _tunnel_ok)
    state = AgentState(agent_id="a1", agent_token="agtk-1")

    await main._preflight(state, ssl.create_default_context())

    assert state.auto_rescan is False
    assert load_state(main.settings.state_path).auto_rescan is False


@pytest.fixture
def _instant_beats(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(main, "read_cpu_percent", lambda: 0.0)
    monkeypatch.setattr(main, "read_memory_percent", lambda: 0.0)

    async def _no_sleep(_seconds: float) -> None:
        return None

    monkeypatch.setattr(main.asyncio, "sleep", _no_sleep)


def _beats(monkeypatch: pytest.MonkeyPatch, beats: list[dict]) -> None:
    async def _heartbeat(*_args: object, **_kwargs: object) -> dict:
        if not beats:
            raise asyncio.CancelledError
        return beats.pop(0)

    monkeypatch.setattr(main.control_plane, "heartbeat", _heartbeat)


@pytest.mark.usefixtures("_reach_env", "_instant_beats")
async def test_a_beat_without_the_field_leaves_the_setting_alone(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A control plane older than the setting, or an appliance on an older release, never sends it.
    # Its silence must not read as "on" and undo what the operator chose.
    state = AgentState(agent_id="a1", agent_token="agtk-1", auto_rescan=False)
    save_state(main.settings.state_path, state)
    _beats(monkeypatch, [{"heartbeat_interval_seconds": 30}])

    with pytest.raises(asyncio.CancelledError):
        await main._heartbeat_loop(state, Mock())

    assert state.auto_rescan is False
    assert load_state(main.settings.state_path).auto_rescan is False


@pytest.mark.usefixtures("_reach_env", "_instant_beats")
async def test_a_malformed_field_moves_the_setting_neither_way(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = AgentState(agent_id="a1", agent_token="agtk-1", auto_rescan=False)
    _beats(monkeypatch, [{"auto_rescan": "true"}, {"auto_rescan": 1}, {"auto_rescan": None}])

    with pytest.raises(asyncio.CancelledError):
        await main._heartbeat_loop(state, Mock())

    assert state.auto_rescan is False


@pytest.mark.usefixtures("_reach_env", "_instant_beats")
async def test_the_heartbeat_follows_the_setting_and_persists_each_change(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    state = AgentState(agent_id="a1", agent_token="agtk-1")
    _beats(monkeypatch, [{"auto_rescan": True}, {"auto_rescan": False}, {"auto_rescan": False}])

    with caplog.at_level("INFO", logger="ares.agent"):
        with pytest.raises(asyncio.CancelledError):
            await main._heartbeat_loop(state, Mock())

    assert state.auto_rescan is False
    assert load_state(main.settings.state_path).auto_rescan is False
    # The first beat agreed with what the agent was already doing, so only the switch to off is
    # worth a line, and the repeat of it is not.
    switches = [
        r.getMessage() for r in caplog.records if "Automatic rescans turned" in r.getMessage()
    ]
    assert len(switches) == 1
    assert "turned off" in switches[0]


def test_the_capability_is_advertised() -> None:
    # ares reads its absence as "this build still re-probes every six hours on its own" and says so
    # next to the setting, so a build that follows the setting has to claim it.
    assert "auto_rescan" in control_plane.capabilities(main.settings)
