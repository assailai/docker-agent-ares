"""Control-plane loop resilience and which identity a start serves under: failure logging is
visible but never spammy, the agent only claims to be online once a beat is accepted (and under
the name ares actually holds for it), a sustained authorization failure re-enrolls
(non-destructively) instead of 401-looping forever or stranding a healthy agent on a spent
one-time token, and a re-install handed a *different* registration token enrolls under it rather
than silently going on as the agent it already was."""

from __future__ import annotations

import asyncio
import logging
import time
from pathlib import Path
from unittest.mock import Mock

import httpx
import pytest
from pydantic import SecretStr

from agent import main
from agent.state import AgentState, fingerprint, load_state, save_state


def test_repeated_failure_logging_escalates_then_quiets(caplog: pytest.LogCaptureFixture) -> None:
    # the first failure and every tenth are WARNING (visible at the default INFO level) so a
    # sustained outage is never silent; the noisy middle stays DEBUG so a flaky minute does not
    # flood the log.
    exc = RuntimeError("boom")
    with caplog.at_level(logging.DEBUG, logger="ares.agent"):
        _log_repeated_failure = main._log_repeated_failure
        _log_repeated_failure("heartbeat", 1, exc)
        _log_repeated_failure("heartbeat", 5, exc)
        _log_repeated_failure("heartbeat", 10, exc)

    by_message = {record.getMessage(): record.levelno for record in caplog.records}
    assert by_message["heartbeat failing (attempt 1): boom"] == logging.WARNING
    assert by_message["heartbeat failed (attempt 5): boom"] == logging.DEBUG
    assert by_message["heartbeat failing (attempt 10): boom"] == logging.WARNING


def _unauthorized() -> httpx.HTTPStatusError:
    request = httpx.Request("POST", "http://ares.example/api/v1/agent/heartbeat")
    response = httpx.Response(401, request=request)
    return httpx.HTTPStatusError("401", request=request, response=response)


@pytest.fixture
def _instant_loop(monkeypatch: pytest.MonkeyPatch) -> None:
    """Strip the real delays / sampling out of the heartbeat loop so it iterates instantly."""
    monkeypatch.setattr(main, "read_cpu_percent", lambda: 0.0)
    monkeypatch.setattr(main, "read_memory_percent", lambda: 0.0)

    async def _no_sleep(_seconds: float) -> None:
        return None

    monkeypatch.setattr(main.asyncio, "sleep", _no_sleep)


@pytest.mark.usefixtures("_instant_loop")
async def test_heartbeat_reenrolls_after_sustained_unauthorized(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Every beat is rejected: after the threshold the loop raises _AuthInvalidated so run()
    # can drop the stale identity, rather than logging "unauthorized" forever.
    calls = {"n": 0}

    async def _always_401(*_args: object, **_kwargs: object) -> dict:
        calls["n"] += 1
        raise _unauthorized()

    monkeypatch.setattr(main.control_plane, "heartbeat", _always_401)

    state = AgentState(agent_id="agent-1", agent_token="dead-token")
    with pytest.raises(main._AuthInvalidated):
        await main._heartbeat_loop(state, Mock())

    assert calls["n"] == main._REENROLL_AFTER_UNAUTHORIZED


def _scripted_heartbeat(beats: list[object]):
    """A control_plane.heartbeat stub that plays `beats` in order (an Exception is raised,
    a dict is returned), then ends the otherwise-infinite loop with CancelledError."""

    async def _heartbeat(*_args: object, **_kwargs: object) -> dict:
        if not beats:
            raise asyncio.CancelledError
        beat = beats.pop(0)
        if isinstance(beat, Exception):
            raise beat
        assert isinstance(beat, dict)
        return beat

    return _heartbeat


@pytest.mark.usefixtures("_instant_loop")
async def test_transient_unauthorized_recovers_without_reenroll(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    # A couple of 401s below the threshold, then a good beat, must NOT tear the agent down:
    # the streak resets and the agent simply announces it is online.
    beats: list[object] = [_unauthorized(), _unauthorized(), {"heartbeat_interval_seconds": 30}]
    monkeypatch.setattr(main.control_plane, "heartbeat", _scripted_heartbeat(beats))

    state = AgentState(agent_id="agent-1", agent_token="good-token")
    with caplog.at_level(logging.INFO, logger="ares.agent"):
        with pytest.raises(asyncio.CancelledError):
            await main._heartbeat_loop(state, Mock())

    messages = [record.getMessage() for record in caplog.records]
    assert any("Agent online" in message for message in messages)


@pytest.mark.usefixtures("_instant_loop")
async def test_online_is_announced_only_after_a_beat_is_accepted(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    # The first call is rejected; "Agent online" must not appear until a beat is accepted, so
    # the log never claims the agent is up while its credentials are in fact being refused.
    beats: list[object] = [_unauthorized(), {"heartbeat_interval_seconds": 30}]
    monkeypatch.setattr(main.control_plane, "heartbeat", _scripted_heartbeat(beats))

    state = AgentState(agent_id="agent-1", agent_token="good-token")
    with caplog.at_level(logging.INFO, logger="ares.agent"):
        with pytest.raises(asyncio.CancelledError):
            await main._heartbeat_loop(state, Mock())

    messages = [record.getMessage() for record in caplog.records]
    online_index = next(i for i, m in enumerate(messages) if "Agent online" in m)
    unauthorized_index = next(i for i, m in enumerate(messages) if "unauthorized" in m)
    # the first 401 was reported, and "online" was announced strictly after it (never upfront).
    assert unauthorized_index < online_index


@pytest.mark.usefixtures("_instant_loop")
async def test_two_unauthorized_below_threshold_does_not_reenroll(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The boundary: with the threshold at 3, two consecutive 401s must NOT raise. We feed
    # exactly two 401s then end the loop, and assert no _AuthInvalidated escaped.
    assert main._REENROLL_AFTER_UNAUTHORIZED == 3
    beats: list[object] = [_unauthorized(), _unauthorized()]
    monkeypatch.setattr(main.control_plane, "heartbeat", _scripted_heartbeat(beats))

    state = AgentState(agent_id="agent-1", agent_token="good-token")
    with pytest.raises(asyncio.CancelledError):  # the loop ends, never raising _AuthInvalidated
        await main._heartbeat_loop(state, Mock())


async def test_reenroll_returns_new_state_when_token_is_still_valid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The kept-volume case: ARES_TOKEN is unused, so re-enrollment succeeds and yields a new
    # identity for the caller to adopt.
    fresh = AgentState(agent_id="new", agent_token="agtk-new")

    async def _register(_state: AgentState, _networks: list[str]) -> AgentState:
        return fresh

    monkeypatch.setattr(main, "_register", _register)
    assert await main._reenroll(["10.0.0.0/24"]) is fresh


async def test_reenroll_returns_none_when_token_is_spent(monkeypatch: pytest.MonkeyPatch) -> None:
    # Decommissioned / healthy-transient case: the one-time token is already used, so re-enroll
    # fails and returns None. The caller must keep the existing credentials, not strand them.
    async def _register(_state: AgentState, _networks: list[str]) -> AgentState:
        raise main.control_plane.RegistrationRejected("already used")

    monkeypatch.setattr(main, "_register", _register)
    assert await main._reenroll(["10.0.0.0/24"]) is None


async def test_reenroll_returns_none_when_ares_is_unreachable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _register(_state: AgentState, _networks: list[str]) -> AgentState:
        raise httpx.ConnectError("no route")

    monkeypatch.setattr(main, "_register", _register)
    assert await main._reenroll(["10.0.0.0/24"]) is None


async def test_run_adopts_a_fresh_identity_on_reenroll(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    # End-to-end of the self-heal orchestration in run(): _serve raises _AuthInvalidated once,
    # run() re-enrolls and resumes serving with the NEW state (not the stale one), and never
    # exits the process to do it.
    stale = AgentState(agent_id="stale", agent_token="agtk-stale")
    fresh = AgentState(agent_id="fresh", agent_token="agtk-fresh")
    served: list[AgentState] = []

    async def _enroll(_networks: list[str]) -> AgentState:
        return stale

    async def _serve(state: AgentState, _tunnel: object) -> None:
        served.append(state)
        if len(served) == 1:
            raise main._AuthInvalidated
        raise asyncio.CancelledError  # stop the otherwise-infinite outer loop

    async def _reenroll(_networks: list[str]) -> AgentState:
        return fresh

    class _FakeTunnel:
        def __init__(self, *_args: object, **_kwargs: object) -> None: ...

        def stop(self) -> None: ...

    monkeypatch.setattr(main, "_enroll", _enroll)
    monkeypatch.setattr(main, "_serve", _serve)
    monkeypatch.setattr(main, "_reenroll", _reenroll)
    monkeypatch.setattr(main, "TunnelManager", _FakeTunnel)
    monkeypatch.setattr(main, "tunnel_url", lambda url: url)
    monkeypatch.setattr(main.netdetect, "detect_networks", lambda: ["10.0.0.0/24"])
    monkeypatch.setattr(main.settings, "token", SecretStr("ares_agt_fresh"))
    monkeypatch.setattr(main.settings, "insecure", False)
    monkeypatch.setattr(main.settings, "data_dir", tmp_path)

    with pytest.raises(asyncio.CancelledError):
        await main.run()

    # served the stale identity first, then the freshly re-enrolled one.
    assert served == [stale, fresh]


# --- scan task orchestration: progress + live streaming + auto-scope ----------------------------


async def test_run_task_reports_progress_and_streams_hosts(monkeypatch: pytest.MonkeyPatch) -> None:
    # _run_task must feed scan_cidr's callbacks straight to the control plane: percentages via
    # progress posts, and discovered hosts streamed as they are found, with the authoritative full
    # list sent on completion.
    started: list[str] = []
    progress: list[tuple[int, list[dict] | None]] = []
    completed: list[list[dict]] = []
    host = {"ip": "10.0.0.5", "port": 80, "service": "http", "protocol": "tcp", "evidence": "x"}

    async def _task_started(_s, _t, task_id):
        started.append(task_id)

    async def _task_progress(_s, _t, _task_id, *, percent, discovered_hosts=None, **_kw):
        progress.append((percent, discovered_hosts))

    async def _task_completed(_s, _t, _task_id, hosts, **_kw):
        completed.append(hosts)

    async def _fake_scan(cidr, ports, **kwargs):
        assert ports == [80]  # tool_config.ports is honoured
        await kwargs["on_progress"](50)
        await kwargs["on_hosts"]([host])
        await kwargs["on_progress"](100)
        return [host]

    monkeypatch.setattr(main.control_plane, "task_started", _task_started)
    monkeypatch.setattr(main.control_plane, "task_progress", _task_progress)
    monkeypatch.setattr(main.control_plane, "task_completed", _task_completed)
    monkeypatch.setattr(main.scan, "scan_cidr", _fake_scan)

    await main._run_task(
        "tok",
        {"id": "t1", "target_network": "10.0.0.0/24", "tool_config": {"ports": [80]}},
    )

    assert started == ["t1"]
    assert completed == [[host]]
    percents = [p for p, _ in progress]
    assert 50 in percents and 100 in percents
    assert any(hosts == [host] for _, hosts in progress)  # a chunk was streamed live


async def test_run_task_survives_a_failed_progress_post(monkeypatch: pytest.MonkeyPatch) -> None:
    # a dropped progress post is best-effort: it must never fail the scan or block completion.
    completed: list[list[dict]] = []

    async def _ok(*_a, **_k):
        return None

    async def _boom(*_a, **_k):
        raise RuntimeError("network blip")

    async def _task_completed(_s, _t, _task_id, hosts, **_kw):
        completed.append(hosts)

    async def _fake_scan(cidr, ports, **kwargs):
        await kwargs["on_progress"](25)  # this post raises, and must be swallowed
        return []

    monkeypatch.setattr(main.control_plane, "task_started", _ok)
    monkeypatch.setattr(main.control_plane, "task_progress", _boom)
    monkeypatch.setattr(main.control_plane, "task_completed", _task_completed)
    monkeypatch.setattr(main.scan, "scan_cidr", _fake_scan)

    await main._run_task("tok", {"id": "t1", "target_network": "10.0.0.0/24"})

    assert completed == [[]]  # completed cleanly despite the progress post blowing up


async def test_run_task_fails_without_a_target_network(monkeypatch: pytest.MonkeyPatch) -> None:
    failed: list[str] = []

    async def _task_failed(_s, _t, _task_id, reason):
        failed.append(reason)

    async def _should_not_run(*_a, **_k):
        raise AssertionError("scan must not start without a target network")

    monkeypatch.setattr(main.control_plane, "task_failed", _task_failed)
    monkeypatch.setattr(main.scan, "scan_cidr", _should_not_run)

    await main._run_task("tok", {"id": "t1"})

    assert failed == ["missing target_network"]


# --- scan scope: the agent checks the destination it was told to scan ---------------------------
#
# The agent is the last thing between an instruction and a customer's network, so it re-checks the
# target itself instead of trusting that whoever queued the task got it right. An authenticated
# instruction is still just an instruction.


async def _noop(*_a, **_kw) -> None:
    return None


def _scope_probe(monkeypatch: pytest.MonkeyPatch) -> dict[str, list]:
    """Record what a task actually did: whether it started, scanned, or was refused."""
    seen: dict[str, list] = {"started": [], "scanned": [], "failed": []}

    async def _task_started(_s, _t, task_id):
        seen["started"].append(task_id)

    async def _task_failed(_s, _t, _task_id, reason):
        seen["failed"].append(reason)

    async def _fake_scan(cidr, _ports, **_kwargs):
        seen["scanned"].append(cidr)
        return []

    monkeypatch.setattr(main.control_plane, "task_started", _task_started)
    monkeypatch.setattr(main.control_plane, "task_failed", _task_failed)
    monkeypatch.setattr(main.control_plane, "task_completed", _noop)
    monkeypatch.setattr(main.control_plane, "task_progress", _noop)
    monkeypatch.setattr(main.scan, "scan_cidr", _fake_scan)
    return seen


@pytest.mark.parametrize(
    "target",
    [
        "10.0.1.0/24",  # exactly the approved network
        "10.0.1.64/26",  # a subnet of it
        "10.0.1.7/32",  # a single host inside it
    ],
)
async def test_run_task_scans_a_target_inside_ares_networks(
    monkeypatch: pytest.MonkeyPatch, target: str
) -> None:
    seen = _scope_probe(monkeypatch)
    monkeypatch.setattr(main.settings, "networks", "10.0.1.0/24")

    await main._run_task("tok", {"id": "t1", "target_network": target})

    assert seen["failed"] == []
    assert seen["started"] == ["t1"]
    assert seen["scanned"]


@pytest.mark.parametrize(
    ("target", "why"),
    [
        ("10.0.0.0/16", "a supernet of the approved network"),
        ("10.0.0.0/23", "a supernet that merely contains it"),
        ("10.0.0.0/8", "the whole private block"),
        ("192.168.1.0/24", "an unrelated private network"),
        ("203.0.113.0/24", "a public network"),
        ("127.0.0.0/8", "loopback"),
        ("169.254.0.0/16", "link-local, where cloud metadata lives"),
    ],
)
async def test_run_task_refuses_a_target_outside_ares_networks(
    monkeypatch: pytest.MonkeyPatch, target: str, why: str
) -> None:
    """Containment, not overlap: a supernet of an approved network asks for everything else in it
    too, so merely overlapping is not close enough."""
    seen = _scope_probe(monkeypatch)
    monkeypatch.setattr(main.settings, "networks", "10.0.1.0/24")

    await main._run_task("tok", {"id": "t1", "target_network": target})

    assert seen["scanned"] == []
    assert seen["started"] == []  # never reported as begun, because it never began
    assert len(seen["failed"]) == 1
    assert "scope refused" in seen["failed"][0]
    assert "ARES_NETWORKS" in seen["failed"][0]


@pytest.mark.parametrize(
    ("target", "reason"),
    [
        ("not-a-cidr", "does not appear to be"),
        ("10.0.0.0/33", "does not appear to be"),
        ("::/0", "only IPv4"),
        ("fd00::/8", "only IPv4"),
        ("0.0.0.0/0", "whole address space"),
    ],
)
async def test_run_task_refuses_a_target_that_is_never_a_scope(
    monkeypatch: pytest.MonkeyPatch, target: str, reason: str
) -> None:
    """Malformed, IPv6 and the default route are refused whether or not ARES_NETWORKS is set: there
    is no configuration under which they are a scan scope. The scanner would reject the first two
    itself, but only after the task had been marked started."""
    for networks in ("10.0.1.0/24", ""):
        seen = _scope_probe(monkeypatch)
        monkeypatch.setattr(main.settings, "networks", networks)

        await main._run_task("tok", {"id": "t1", "target_network": target})

        assert seen["scanned"] == []
        assert seen["started"] == []
        assert reason in seen["failed"][0]


async def test_run_task_survives_a_typo_in_ares_networks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ARES_NETWORKS is a free-form string, so one bad entry in a list of three must not take the
    other two down with it. run() names the bad entry at startup instead."""
    seen = _scope_probe(monkeypatch)
    monkeypatch.setattr(main.settings, "networks", "10.0.1.0/24, oops, 192.168.5.0/24")

    await main._run_task("tok", {"id": "t1", "target_network": "192.168.5.128/25"})

    assert seen["scanned"] == ["192.168.5.128/25"]


def test_startup_names_an_unparseable_ares_networks_entry(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setattr(main.settings, "networks", "10.0.1.0/24, oops")
    with caplog.at_level(logging.WARNING, logger="ares.agent"):
        main._warn_unparseable_networks()

    assert "'oops'" in caplog.records[0].getMessage()


async def test_run_task_warns_but_still_scans_outside_the_detected_scope(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Without ARES_NETWORKS the scope is whatever re-detection last worked out, which is evidence
    of reachability rather than an authorization - and it narrows as well as widens, so enforcing it
    would refuse legitimate tasks whenever a task and a re-detect crossed. The operator gets the one
    line they need to notice drift, and the knob that makes it a hard ceiling."""
    seen = _scope_probe(monkeypatch)
    monkeypatch.setattr(main.settings, "networks", "")
    monkeypatch.setitem(main._reachable, "networks", ["10.0.0.0/8"])

    with caplog.at_level(logging.WARNING, logger="ares.agent"):
        await main._run_task("tok", {"id": "t1", "target_network": "203.0.113.0/24"})

    assert seen["scanned"] == ["203.0.113.0/24"]  # scanned, by choice
    warning = caplog.records[0].getMessage()
    assert "outside every network this agent detected" in warning
    assert "ARES_NETWORKS" in warning  # and says how to make it enforceable


async def test_run_task_is_quiet_about_a_target_it_detected(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    seen = _scope_probe(monkeypatch)
    monkeypatch.setattr(main.settings, "networks", "")
    monkeypatch.setitem(main._reachable, "networks", ["10.0.0.0/8"])

    with caplog.at_level(logging.WARNING, logger="ares.agent"):
        await main._run_task("tok", {"id": "t1", "target_network": "10.4.0.0/24"})

    assert seen["scanned"] == ["10.4.0.0/24"]
    assert caplog.records == []


async def test_run_task_does_not_call_an_empty_detection_drift(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """The first task can beat the first reachability probe; an empty answer is "not yet", not
    "outside the scope"."""
    seen = _scope_probe(monkeypatch)
    monkeypatch.setattr(main.settings, "networks", "")
    monkeypatch.setitem(main._reachable, "networks", [])

    with caplog.at_level(logging.WARNING, logger="ares.agent"):
        await main._run_task("tok", {"id": "t1", "target_network": "10.4.0.0/24"})

    assert seen["scanned"] == ["10.4.0.0/24"]
    assert caplog.records == []


async def test_run_task_reports_a_refusal_exactly_once(monkeypatch: pytest.MonkeyPatch) -> None:
    """One auditable failure and zero scan calls, so a denial reads unambiguously in the dashboard
    and cannot be mistaken for a scan that found nothing."""
    seen = _scope_probe(monkeypatch)
    monkeypatch.setattr(main.settings, "networks", "10.0.1.0/24")

    await main._run_task("tok", {"id": "t1", "target_network": "203.0.113.0/24"})

    assert len(seen["failed"]) == 1
    assert seen["scanned"] == []


async def test_run_task_keeps_refusing_a_redelivered_task(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A retry is not a second opinion. Redelivering the same task must not eventually run it."""
    seen = _scope_probe(monkeypatch)
    monkeypatch.setattr(main.settings, "networks", "10.0.1.0/24")
    task = {"id": "t1", "target_network": "203.0.113.0/24"}

    for _ in range(3):
        await main._run_task("tok", task)

    assert seen["scanned"] == []
    assert len(seen["failed"]) == 3


async def test_run_task_scans_the_normalized_target(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A host bit set in the task ("10.0.1.7/24") is scanned as its network either way, since the
    scanner normalizes internally. Passing the normalized form on makes the logs say so too."""
    seen = _scope_probe(monkeypatch)
    monkeypatch.setattr(main.settings, "networks", "10.0.1.0/24")

    await main._run_task("tok", {"id": "t1", "target_network": "10.0.1.7/24"})

    assert seen["scanned"] == ["10.0.1.0/24"]


async def test_run_advertises_auto_scoped_networks(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    # with ARES_NETWORKS unset, run() advertises whatever netdetect.scan_targets resolves for the
    # configured scope -- the operator never has to type a CIDR.
    #
    # Pinned to "supernet16" rather than left on the default. The default is now "reachable", which
    # goes on to read the kernel's routing table and probe private space, so on the default this
    # would sweep the machine running the tests for minutes. That is the behaviour the next test
    # covers, with the probe patched out.
    captured: dict[str, list[str]] = {}

    async def _enroll(networks: list[str]) -> AgentState:
        captured["networks"] = networks
        raise asyncio.CancelledError  # stop run() right after it computes the target networks

    monkeypatch.setattr(main, "_enroll", _enroll)
    monkeypatch.setattr(main.netdetect, "scan_targets", lambda scope: ["10.9.0.0/16"])
    monkeypatch.setattr(main.settings, "scan_scope", "supernet16")
    monkeypatch.setattr(main.settings, "token", SecretStr("ares_agt_x"))
    monkeypatch.setattr(main.settings, "insecure", False)
    monkeypatch.setattr(main.settings, "networks", "")
    monkeypatch.setattr(main.settings, "data_dir", tmp_path)

    with pytest.raises(asyncio.CancelledError):
        await main.run()

    assert captured["networks"] == ["10.9.0.0/16"]


async def test_enrollment_never_waits_for_reachability_discovery(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    # Registration carries the ATTACHED subnets and nothing else, even on the "reachable" scope.
    # Discovery reaches across the customer's private space and takes minutes; awaiting it here
    # would leave a freshly installed agent reading "Offline, never" in the dashboard for all of
    # it. The next test covers where the reachable networks actually come from.
    captured: dict[str, list[str]] = {}

    async def _enroll(networks: list[str]) -> AgentState:
        captured["networks"] = networks
        raise asyncio.CancelledError

    async def _explode(**_kwargs: object) -> list[str]:
        raise AssertionError("enrollment must not block on reachability discovery")

    monkeypatch.setattr(main, "_enroll", _enroll)
    monkeypatch.setattr(main.netdetect, "scan_targets", lambda scope: ["172.23.0.0/16"])
    monkeypatch.setattr(main.reachability, "discover", _explode)
    monkeypatch.setattr(main.settings, "scan_scope", "reachable")
    monkeypatch.setattr(main.settings, "token", SecretStr("ares_agt_x"))
    monkeypatch.setattr(main.settings, "insecure", False)
    monkeypatch.setattr(main.settings, "networks", "")
    monkeypatch.setattr(main.settings, "data_dir", tmp_path)

    with pytest.raises(asyncio.CancelledError):
        await main.run()

    assert captured["networks"] == ["172.23.0.0/16"]


async def test_redetect_publishes_reachable_networks_and_widens_the_tunnel(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The whole point of the default scope: an agent attached to 172.23.x advertised 172.23.0.0/16
    # and nothing else, so a customer's 10.20 estate was never scanned. Discovery adds it, and
    # BOTH halves have to move: the heartbeat reports it (so ares scans it) and the tunnel's
    # allowed networks widen (so the agent will actually dial what the scan finds). Reporting
    # without the second half finds hosts the tunnel then refuses.
    async def _discover(*, attached: list[str], **_kwargs: object) -> list[str]:
        return [*attached, "10.20.0.0/16"]

    widened: list[list[str]] = []

    class _FakeTunnel:
        def set_networks(self, networks: list[str]) -> None:
            widened.append(networks)

    monkeypatch.setattr(main.netdetect, "scan_targets", lambda scope: ["172.23.0.0/16"])
    monkeypatch.setattr(main.reachability, "discover", _discover)
    monkeypatch.setattr(main.settings, "scan_scope", "reachable")
    monkeypatch.setattr(main.settings, "networks", "")
    # 0 means "one pass, then stop", which is what makes an otherwise-endless loop testable.
    monkeypatch.setattr(main.settings, "reach_refresh_seconds", 0)
    monkeypatch.setitem(main._reachable, "networks", [])

    await main._redetect_loop(_FakeTunnel())

    assert main._reachable["networks"] == ["172.23.0.0/16", "10.20.0.0/16"]
    assert widened == [["172.23.0.0/16", "10.20.0.0/16"]]


async def test_redetect_is_off_when_networks_were_given_explicitly(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # ARES_NETWORKS is a decision. Nothing widens it, including the loop that runs for the life of
    # the container, or an operator who scoped an agent to one subnet would find it sweeping the
    # estate six hours later.
    async def _explode(**_kwargs: object) -> list[str]:
        raise AssertionError("discovery must not run when ARES_NETWORKS is set")

    monkeypatch.setattr(main.reachability, "discover", _explode)
    monkeypatch.setattr(main.settings, "networks", "10.1.2.0/24")
    monkeypatch.setattr(main.settings, "scan_scope", "reachable")

    await main._redetect_loop(None)


async def test_explicit_networks_are_never_widened_by_discovery(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # ARES_NETWORKS is a decision, not a hint. Nothing may add to it, so an operator who scoped an
    # agent to one subnet does not find it sweeping the estate after an upgrade.
    async def _explode(**_kwargs: object) -> list[str]:
        raise AssertionError("discovery must not run when ARES_NETWORKS is set")

    monkeypatch.setattr(main.reachability, "discover", _explode)
    monkeypatch.setattr(main.settings, "networks", "10.1.2.0/24")
    monkeypatch.setattr(main.settings, "scan_scope", "reachable")

    assert await main._resolve_networks() == ["10.1.2.0/24"]


# --- network-resilience watchdog + bounded metrics ----------------------------------------------


@pytest.fixture
def _restore_liveness():
    """Snapshot/restore the module-level liveness clock so a test that backdates it does not
    bleed into the next."""
    saved = dict(main._liveness)
    yield
    main._liveness.clear()
    main._liveness.update(saved)


async def test_record_contact_bumps_liveness_and_writes_marker(
    monkeypatch: pytest.MonkeyPatch, tmp_path, _restore_liveness
) -> None:
    # a successful contact advances the watchdog clock and refreshes the healthcheck marker file.
    monkeypatch.setattr(main.settings, "data_dir", tmp_path)
    main._liveness["last_contact"] = 0.0
    main._liveness["last_marker_at"] = 0.0  # ensure the throttle allows this first write

    main._record_contact()

    assert main._liveness["last_contact"] > 0.0
    marker = tmp_path / "last-contact"
    assert marker.exists()
    assert abs(time.time() - float(marker.read_text())) < 5  # a fresh epoch second was written


async def test_record_contact_throttles_the_marker_but_always_bumps_the_clock(
    monkeypatch: pytest.MonkeyPatch, tmp_path, _restore_liveness
) -> None:
    # the marker file is rewritten at most every _MARKER_MIN_INTERVAL_SECONDS (no /data churn on the
    # ~5s poll), but the in-memory watchdog clock advances on every contact.
    monkeypatch.setattr(main.settings, "data_dir", tmp_path)
    monkeypatch.setattr(main, "_MARKER_MIN_INTERVAL_SECONDS", 999)
    main._liveness["last_marker_at"] = 0.0
    main._record_contact()  # first write allowed (last_marker_at was 0)
    marker = tmp_path / "last-contact"
    marker.unlink()  # remove it; a throttled second call must NOT recreate it
    main._liveness["last_contact"] = 0.0

    main._record_contact()

    assert not marker.exists()  # throttled: no rewrite within the interval
    assert main._liveness["last_contact"] > 0.0  # but the watchdog clock still advanced


async def test_watchdog_exits_when_contact_is_stale(
    monkeypatch: pytest.MonkeyPatch, _restore_liveness
) -> None:
    # no successful contact for longer than max_offline_seconds -> exit so the container restarts.
    class _Exited(Exception):
        pass

    codes: list[int] = []

    def _fake_exit(code: int) -> None:
        codes.append(code)
        raise _Exited  # stand in for os._exit so the test can observe it instead of dying

    monkeypatch.setattr(main.os, "_exit", _fake_exit)
    monkeypatch.setattr(main, "_WATCHDOG_INTERVAL_SECONDS", 0.0)
    monkeypatch.setattr(main.settings, "max_offline_seconds", 1)
    main._liveness["last_contact"] = time.monotonic() - 10  # last contact well past the limit

    with pytest.raises(_Exited):
        await asyncio.wait_for(main._watchdog_loop(), timeout=2)
    assert codes == [1]  # non-zero: an unhealthy restart


async def test_watchdog_stays_quiet_while_contact_is_fresh(
    monkeypatch: pytest.MonkeyPatch, _restore_liveness
) -> None:
    # while contact is recent the watchdog leaves the process alone.
    exited: list[int] = []
    monkeypatch.setattr(main.os, "_exit", lambda code: exited.append(code))
    monkeypatch.setattr(main, "_WATCHDOG_INTERVAL_SECONDS", 0.01)
    monkeypatch.setattr(main.settings, "max_offline_seconds", 600)
    main._liveness["last_contact"] = time.monotonic()

    with pytest.raises(asyncio.TimeoutError):  # it keeps watching (never exits) until cancelled
        await asyncio.wait_for(main._watchdog_loop(), timeout=0.2)
    assert exited == []


async def test_sample_cpu_percent_returns_none_on_error(monkeypatch: pytest.MonkeyPatch) -> None:
    # a failing CPU read is best-effort: the beat proceeds with no CPU rather than raising.
    def _boom() -> float:
        raise RuntimeError("cgroup unreadable")

    monkeypatch.setattr(main, "read_cpu_percent", _boom)
    assert await main._sample_cpu_percent() is None


async def test_sample_cpu_percent_returns_none_on_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    # a slow/starved sample must not wedge the beat: it is abandoned past the timeout.
    monkeypatch.setattr(main, "_CPU_SAMPLE_TIMEOUT_SECONDS", 0.05)
    monkeypatch.setattr(main, "read_cpu_percent", lambda: time.sleep(0.5) or 12.3)
    assert await main._sample_cpu_percent() is None


def test_allowed_hosts_keeps_only_strings_and_never_widens() -> None:
    # ares pushes the hostname destinations of running hunts; anything malformed must degrade to
    # "no pushed hosts" (the registered networks stay the only way in), never to a wider set.
    assert main._allowed_hosts(["bank.internal", "echo.internal"]) == [
        "bank.internal",
        "echo.internal",
    ]
    assert main._allowed_hosts(["bank.internal", 42, None]) == ["bank.internal"]
    assert main._allowed_hosts(None) == []
    assert main._allowed_hosts("bank.internal") == []


# ── logging configuration: verbosity is ours to raise, never the dependencies' ──
def test_debug_log_level_does_not_enable_third_party_debug(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ARES_LOG_LEVEL=DEBUG must raise our verbosity only.

    ``websockets`` logs every frame it relays at DEBUG and a frame's repr renders the payload as
    hex, so letting the level reach the root logger would hex-dump the customer's own tunnelled
    traffic (in plaintext whenever the target speaks http) into their agent log.
    """
    monkeypatch.setattr(main.settings, "log_level", "DEBUG")
    main._configure_logging()

    assert logging.getLogger("ares.agent.tunnel").isEnabledFor(logging.DEBUG)
    for noisy in ("websockets", "httpx", "httpcore", "asyncio"):
        assert not logging.getLogger(noisy).isEnabledFor(logging.DEBUG), noisy


def test_the_enrollment_token_never_renders_in_a_log_or_repr() -> None:
    """The token is the one credential this process holds; it must not be printable by accident."""
    from agent.config import Settings

    settings = Settings(token="super-secret-enrollment-token")  # type: ignore[arg-type]
    assert "super-secret-enrollment-token" not in repr(settings)
    assert "super-secret-enrollment-token" not in str(settings)
    assert "super-secret-enrollment-token" not in f"{settings.token}"
    # ...but the real value is still reachable where it is genuinely needed.
    assert settings.token.get_secret_value() == "super-secret-enrollment-token"


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost:8080",
        "https://host.docker.internal",
        "https://box.local",
        "https://staging.internal.example",  # legacy substring match, kept
        "https://staging.assailai.com",
        "https://peregrine.ares.assailai.com",  # any non-prod *.assailai.com
        "https://pr-42.assailai.com",
    ],
)
def test_insecure_allowed_for_local_staging_and_nonprod_assailai(url: str) -> None:
    # ARES_INSECURE skips TLS verification, so it is only tolerable off production. Every host
    # here is local, staging, or a non-production *.assailai.com environment.
    assert main._insecure_allowed(url) is True


@pytest.mark.parametrize(
    "url",
    [
        "https://ares.assailai.com",  # production: must always verify TLS
        "https://ares.assailai.com/api",
        "https://example.com",
        "https://not-assailai.com",  # a look-alike must not match the suffix
        "https://assailai.com.evil.net",
    ],
)
def test_insecure_denied_for_production_and_foreign_hosts(url: str) -> None:
    # production keeps a verified certificate, and a look-alike domain must never qualify.
    assert main._insecure_allowed(url) is False


# --- which identity a start serves under --------------------------------------------------------
#
# The bug these cover: the agent used to short-circuit on any stored identity, so re-installing on
# a host whose /data volume was kept discarded the supplied ARES_TOKEN without a word. The
# container went on heartbeating as the old agent while the newly provisioned one sat at
# "Offline, never" in the dashboard, and both the agent log and the installer called it a success.


def _already_enrolled(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    supplied: str,
    minted_with: str | None,
) -> AgentState:
    """Put a registered identity on disk, as a kept /data volume would hold it.

    ``supplied`` is the ARES_TOKEN this start is handed; ``minted_with`` is the registration token
    the stored identity was enrolled with, or None for a state file written by an agent that
    predates the fingerprint.
    """
    state = AgentState(
        agent_id="already-here",
        agent_token="agtk-already-here",
        registration_token_fingerprint=fingerprint(minted_with) if minted_with else None,
    )
    monkeypatch.setattr(main.settings, "data_dir", tmp_path)
    monkeypatch.setattr(main.settings, "token", SecretStr(supplied))
    save_state(main.settings.state_path, state)
    return state


def _record_register(
    monkeypatch: pytest.MonkeyPatch, *, result: AgentState | Exception
) -> list[list[str]]:
    """Patch _register to record the networks it was called with and then produce ``result``."""
    calls: list[list[str]] = []

    async def _register(_state: AgentState, networks: list[str]) -> AgentState:
        calls.append(networks)
        if isinstance(result, Exception):
            raise result
        return result

    monkeypatch.setattr(main, "_register", _register)
    return calls


async def test_a_restart_with_the_same_token_keeps_its_identity_and_never_registers(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # The most important case to get wrong quietly. The auto-update companion recreates the
    # container with Config.Env copied verbatim, so the same ARES_TOKEN comes back on every
    # version bump: a register call here would mint a duplicate agent each time a fleet upgrades.
    _already_enrolled(monkeypatch, tmp_path, supplied="ares_agt_one", minted_with="ares_agt_one")
    calls = _record_register(monkeypatch, result=AgentState("unexpected", "agtk-unexpected"))

    state = await main._enroll(["10.0.0.0/24"])

    assert state is not None and state.agent_id == "already-here"
    assert calls == []


async def test_a_start_with_no_token_at_all_keeps_its_identity(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # A hand-run container that supplies no ARES_TOKEN has nothing to compare against, and must
    # keep serving on its stored credentials exactly as it did before.
    _already_enrolled(monkeypatch, tmp_path, supplied="", minted_with="ares_agt_one")
    calls = _record_register(monkeypatch, result=AgentState("unexpected", "agtk-unexpected"))

    state = await main._enroll(["10.0.0.0/24"])

    assert state is not None and state.agent_id == "already-here"
    assert calls == []


async def test_a_different_token_re_enrolls_this_host_as_the_new_agent(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # The reported bug, fixed: the operator re-ran the installer with the token Ares minted for a
    # new agent, so that token gets presented and the host adopts the identity it names.
    _already_enrolled(monkeypatch, tmp_path, supplied="ares_agt_two", minted_with="ares_agt_one")
    adopted = AgentState("brand-new", "agtk-brand-new", fingerprint("ares_agt_two"))
    calls = _record_register(monkeypatch, result=adopted)

    state = await main._enroll(["10.0.0.0/24"])

    assert state is adopted
    assert calls == [["10.0.0.0/24"]]


async def test_a_spent_token_keeps_the_working_identity_and_is_not_presented_twice(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    stored = _already_enrolled(
        monkeypatch, tmp_path, supplied="ares_agt_spent", minted_with="ares_agt_one"
    )
    calls = _record_register(
        monkeypatch, result=main.control_plane.RegistrationRejected("401 Unauthorized")
    )

    with caplog.at_level(logging.INFO, logger="ares.agent"):
        first = await main._enroll(["10.0.0.0/24"])

    # The credentials still work, so nothing is torn down over it.
    assert first is not None and first.agent_id == stored.agent_id
    assert len(calls) == 1
    # This exact phrase is what scripts/bootstrap.sh greps to fail the install, and it has to be
    # loud: the operator asked for a new agent and did not get one.
    kept = [r for r in caplog.records if "Keeping the existing agent identity" in r.getMessage()]
    assert [r.levelno for r in kept] == [logging.WARNING]
    assert "ARES_RESET=1" in kept[0].getMessage()

    # A second start must not spend another call on a token already known to be dead.
    second = await main._enroll(["10.0.0.0/24"])

    assert second is not None and second.agent_id == stored.agent_id
    assert len(calls) == 1


async def test_an_agent_that_predates_the_fingerprint_records_it_quietly(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    # Every agent already deployed takes this path once, on the restart that upgrades it: it has
    # no fingerprint, and the ARES_TOKEN in its env is the original, long-spent one. So the
    # rejection is expected, and must neither alarm a whole fleet nor - via the marker bootstrap
    # greps - make an ordinary re-run of the installer look like a failed re-enrollment.
    _already_enrolled(monkeypatch, tmp_path, supplied="ares_agt_original", minted_with=None)
    calls = _record_register(
        monkeypatch, result=main.control_plane.RegistrationRejected("401 Unauthorized")
    )

    with caplog.at_level(logging.INFO, logger="ares.agent"):
        state = await main._enroll(["10.0.0.0/24"])

    assert state is not None and state.agent_id == "already-here"
    assert len(calls) == 1
    assert not any("Keeping the existing agent identity" in r.getMessage() for r in caplog.records)
    assert not any(r.levelno >= logging.WARNING for r in caplog.records)
    # ...and the answer is written down, so this costs one call per agent rather than one per
    # restart forever.
    assert load_state(main.settings.state_path).minted_with("ares_agt_original")


@pytest.mark.usefixtures("_instant_loop")
async def test_an_unreachable_ares_retries_instead_of_settling_for_the_old_identity(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # "Ares was down on this boot" must never be read as "that token is spent". Falling back to
    # the stored identity here would let a single network blip during a re-install decide the
    # host's identity permanently, with the fingerprint written down to make it stick.
    _already_enrolled(monkeypatch, tmp_path, supplied="ares_agt_two", minted_with="ares_agt_one")
    adopted = AgentState("brand-new", "agtk-brand-new", fingerprint("ares_agt_two"))
    attempts: list[int] = []

    async def _register(_state: AgentState, _networks: list[str]) -> AgentState:
        attempts.append(1)
        if len(attempts) < 3:
            raise httpx.ConnectError("no route to host")
        return adopted

    monkeypatch.setattr(main, "_register", _register)

    state = await main._enroll(["10.0.0.0/24"])

    assert state is adopted
    assert len(attempts) == 3


async def test_a_first_install_still_enrolls_and_still_reports_a_rejected_token(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    # Unchanged behaviour, pinned because the branch above it is new: with nothing on disk a
    # refused token is fatal, and says so in the words bootstrap greps to fail fast.
    monkeypatch.setattr(main.settings, "data_dir", tmp_path)
    monkeypatch.setattr(main.settings, "token", SecretStr("ares_agt_new"))
    calls = _record_register(
        monkeypatch, result=main.control_plane.RegistrationRejected("401 Unauthorized")
    )

    with caplog.at_level(logging.ERROR, logger="ares.agent"):
        assert await main._enroll(["10.0.0.0/24"]) is None

    assert len(calls) == 1
    assert any("Registration token rejected" in r.getMessage() for r in caplog.records)


@pytest.mark.usefixtures("_instant_loop")
async def test_the_online_line_reports_the_name_ares_holds_not_ares_agent_name(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    # ARES_AGENT_NAME is a request, not the answer: the deploy wizard's label overrides it at
    # enrollment. Printing the request as though it were the answer is exactly how a container
    # serving on an earlier install's credentials used to read as a success in `docker logs`.
    beats: list[object] = [{"name": "Heffe 2", "heartbeat_interval_seconds": 30}]
    monkeypatch.setattr(main.control_plane, "heartbeat", _scripted_heartbeat(beats))
    monkeypatch.setattr(main.settings, "agent_name", "Heffe 3")

    state = AgentState(agent_id="agent-1", agent_token="good-token")
    with caplog.at_level(logging.INFO, logger="ares.agent"):
        with pytest.raises(asyncio.CancelledError):
            await main._heartbeat_loop(state, Mock())

    online = next(r.getMessage() for r in caplog.records if "Agent online" in r.getMessage())
    assert 'Agent online as "Heffe 2" (agent agent-1).' == online
    # and the disagreement with what the operator asked for is called out rather than buried.
    mismatch = [r for r in caplog.records if "differs from ARES_AGENT_NAME" in r.getMessage()]
    assert [r.levelno for r in mismatch] == [logging.WARNING]


@pytest.mark.usefixtures("_instant_loop")
async def test_an_older_control_plane_sends_no_name_and_the_line_says_so(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    # Against a control plane that predates the field there is no authoritative name to print, so
    # the line falls back to the id and marks the name "local" -- it must not imply the dashboard
    # agrees, and it must not warn about a mismatch it cannot actually see.
    beats: list[object] = [{"heartbeat_interval_seconds": 30}]
    monkeypatch.setattr(main.control_plane, "heartbeat", _scripted_heartbeat(beats))
    monkeypatch.setattr(main.settings, "agent_name", "Heffe 3")

    state = AgentState(agent_id="agent-1", agent_token="good-token")
    with caplog.at_level(logging.INFO, logger="ares.agent"):
        with pytest.raises(asyncio.CancelledError):
            await main._heartbeat_loop(state, Mock())

    online = next(r.getMessage() for r in caplog.records if "Agent online" in r.getMessage())
    assert 'Agent online as agent agent-1 (local name "Heffe 3").' == online
    assert not any("differs from ARES_AGENT_NAME" in r.getMessage() for r in caplog.records)
