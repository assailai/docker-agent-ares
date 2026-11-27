"""The agent ships the signed Network Assessment handlers, so it must ADVERTISE the matching
capability: the control plane only dispatches network_assessment_discover_v1 /
network_assessment_collect_v1 to an agent that advertised `network_assessment`. Without the
advertisement the handlers are dead code (every assessment task is refused at admission). These
tests pin the advertisement to the handlers so the two cannot drift apart."""

from __future__ import annotations

from agent import control_plane, main


def test_network_assessment_capability_is_advertised() -> None:
    assert "network_assessment" in control_plane.capabilities(main.settings)


def test_the_assessment_task_handlers_exist_for_the_advertised_capability() -> None:
    # The capability is only honest if the agent actually handles the task types it unlocks.
    assert "network_assessment_discover_v1" in main._HANDLED_TASK_TYPES
    assert "network_assessment_collect_v1" in main._HANDLED_TASK_TYPES
