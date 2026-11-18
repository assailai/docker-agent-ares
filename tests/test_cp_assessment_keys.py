"""The agent stores and persists the control plane's assessment signing public keys.

The agent verifies every signed Network Assessment job against these BEFORE reading any target
field, so it must keep the last set the control plane told it (on register and every heartbeat) and
survive a restart with them. A response without the field (an older control plane) must leave the
stored set untouched, so a rollout never blanks an agent's ability to verify.
"""

from __future__ import annotations

from pathlib import Path

from agent import main
from agent.state import AgentState, load_state, save_state


def test_state_round_trips_cp_keys(tmp_path: Path) -> None:
    path = tmp_path / "state.json"
    save_state(path, AgentState(agent_id="a", agent_token="t", cp_assessment_public_keys=["k1", "k2"]))
    assert load_state(path).cp_assessment_public_keys == ["k1", "k2"]


def test_malformed_cp_keys_read_as_absent() -> None:
    assert AgentState(cp_assessment_public_keys="not-a-list").cp_assessment_public_keys is None  # type: ignore[arg-type]
    assert AgentState(cp_assessment_public_keys=[1, 2]).cp_assessment_public_keys is None  # type: ignore[list-item]


def test_apply_stores_a_valid_list_and_persists(monkeypatch) -> None:
    persisted: list[AgentState] = []
    monkeypatch.setattr(main, "_persist", lambda state: persisted.append(state))
    state = AgentState()
    main._apply_cp_assessment_keys(["k1", "k2"], state=state)
    assert state.cp_assessment_public_keys == ["k1", "k2"]
    assert len(persisted) == 1


def test_apply_ignores_absent_or_malformed_and_keeps_last_known(monkeypatch) -> None:
    persisted: list[AgentState] = []
    monkeypatch.setattr(main, "_persist", lambda state: persisted.append(state))
    state = AgentState(cp_assessment_public_keys=["k1"])
    main._apply_cp_assessment_keys(None, state=state)  # a control plane older than the field
    main._apply_cp_assessment_keys("nope", state=state)  # malformed
    main._apply_cp_assessment_keys([1], state=state)  # malformed element
    assert state.cp_assessment_public_keys == ["k1"]  # untouched
    assert persisted == []  # nothing changed, nothing written


def test_apply_is_a_no_op_when_unchanged(monkeypatch) -> None:
    persisted: list[AgentState] = []
    monkeypatch.setattr(main, "_persist", lambda state: persisted.append(state))
    state = AgentState(cp_assessment_public_keys=["k1"])
    main._apply_cp_assessment_keys(["k1"], state=state)
    assert persisted == []  # same set, no rewrite
