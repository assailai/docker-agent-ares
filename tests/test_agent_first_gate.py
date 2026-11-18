"""The agent-first gate: a task the agent cannot run is refused BEFORE any target field is read, so
it produces zero target activity.

Two refusals share that property. An UNHANDLED task type (a type this build does not know) is
refused on sight. A signed Network Assessment DISCOVER job is handled, but only after its signature
verifies against the control plane's keys: an unverifiable one is refused before a socket opens,
with the same zero-target-activity guarantee. This is the hard blocker the module depends on: until
this gate existed, the agent ran every task as a CIDR sweep without reading ``task_type`` at all.
"""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from agent import main
from agent.state import AgentState


@pytest.fixture
def _mock_control_plane_and_scan(monkeypatch: pytest.MonkeyPatch) -> dict[str, AsyncMock]:
    mocks = {
        "task_failed": AsyncMock(),
        "task_started": AsyncMock(),
        "scan_cidr": AsyncMock(return_value=[]),
    }
    monkeypatch.setattr(main.control_plane, "task_failed", mocks["task_failed"])
    monkeypatch.setattr(main.control_plane, "task_started", mocks["task_started"])
    monkeypatch.setattr(main.scan, "scan_cidr", mocks["scan_cidr"])
    return mocks


@pytest.mark.parametrize(
    "task_type",
    ["network_assessment_collect_v1", "something_new", None],
)
async def test_unhandled_task_type_emits_zero_target_activity(
    task_type: str | None, _mock_control_plane_and_scan: dict[str, AsyncMock]
) -> None:
    mocks = _mock_control_plane_and_scan
    task = {"id": "t1", "task_type": task_type, "target_network": "10.0.0.0/24"}

    await main._run_task("token", task, state=AgentState())

    # The scanner was never invoked and the task was never reported as started: zero target activity.
    mocks["scan_cidr"].assert_not_called()
    mocks["task_started"].assert_not_awaited()
    # It was refused with a typed reason naming the unsupported type.
    mocks["task_failed"].assert_awaited_once()
    reason = mocks["task_failed"].await_args.kwargs["reason"]
    assert "unsupported task type" in reason


async def test_unverifiable_discover_job_emits_zero_target_activity(
    _mock_control_plane_and_scan: dict[str, AsyncMock],
) -> None:
    # A discover job the agent cannot verify (here: no control-plane keys known yet, so the empty
    # key list fails closed) is refused BEFORE any probe and before task_started, exactly like an
    # unhandled type. The signed-job path inherits the agent-first guarantee.
    mocks = _mock_control_plane_and_scan
    task = {
        "id": "t2",
        "task_type": "network_assessment_discover_v1",
        "tool_config": {"envelope": {"schema_version": "x", "payload": "y", "signature": "z"}},
    }

    await main._run_task("token", task, state=AgentState(cp_assessment_public_keys=[]))

    mocks["scan_cidr"].assert_not_called()
    mocks["task_started"].assert_not_awaited()
    mocks["task_failed"].assert_awaited_once()
    assert "verification" in mocks["task_failed"].await_args.kwargs["reason"]


def test_handled_task_types() -> None:
    # The existing discovery lane and the signed discover job are both handled; the credentialed
    # collect type is deliberately not, until its collectors land.
    assert "local_network_scan" in main._HANDLED_TASK_TYPES
    assert "network_assessment_discover_v1" in main._HANDLED_TASK_TYPES
    assert "network_assessment_collect_v1" not in main._HANDLED_TASK_TYPES
