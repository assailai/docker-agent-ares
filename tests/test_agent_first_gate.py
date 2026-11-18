"""The agent-first gate: a task type this agent does not handle is refused BEFORE any target field
is read, so it produces zero target activity.

This is the hard blocker the Network Assessment module depends on: until this gate existed, the
agent ran every task as a CIDR sweep without reading ``task_type`` at all, so a new network-
assessment task dispatched to an un-upgraded agent would have scanned instead of refusing.
"""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from agent import main


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
    ["network_assessment_discover_v1", "network_assessment_collect_v1", "something_new", None],
)
async def test_unhandled_task_type_emits_zero_target_activity(
    task_type: str | None, _mock_control_plane_and_scan: dict[str, AsyncMock]
) -> None:
    mocks = _mock_control_plane_and_scan
    task = {"id": "t1", "task_type": task_type, "target_network": "10.0.0.0/24"}

    await main._run_task("token", task)

    # The scanner was never invoked and the task was never reported as started: zero target activity.
    mocks["scan_cidr"].assert_not_called()
    mocks["task_started"].assert_not_awaited()
    # It was refused with a typed reason naming the unsupported type.
    mocks["task_failed"].assert_awaited_once()
    reason = mocks["task_failed"].await_args.kwargs["reason"]
    assert "unsupported task type" in reason


def test_local_network_scan_is_still_handled() -> None:
    # The existing discovery lane must not be broken by the gate: its task type stays handled.
    assert "local_network_scan" in main._HANDLED_TASK_TYPES
