"""The agent's identity file, and the fingerprint that decides whether a restart re-enrolls.

The fingerprint is the whole reason this module has a test. It is what separates an ordinary
restart (the auto-update companion recreating the container with the same env) from an operator
re-installing on this host with the registration token for a *different* agent. Get it wrong in
one direction and every version bump mints a duplicate agent; get it wrong in the other and a
host can never be re-enrolled, which is the bug the field was added for.
"""

from __future__ import annotations

import json
import stat
from pathlib import Path

from agent.state import AgentState, fingerprint, load_state, save_state

# a fractional epoch on purpose: the float has to survive the JSON round trip intact
_PROBED_AT = 1_760_000_000.5


def test_a_saved_identity_round_trips_with_its_token_fingerprint(tmp_path: Path) -> None:
    path = tmp_path / "agent-state.json"
    state = AgentState(
        agent_id="a1",
        agent_token="agtk-1",
        registration_token_fingerprint=fingerprint("ares_agt_one"),
    )

    save_state(path, state)

    assert load_state(path) == state


def test_a_state_file_written_before_the_field_existed_still_loads(tmp_path: Path) -> None:
    # The upgrade path. Every agent deployed before this version has exactly these two keys, and
    # its file is now read by a build that expects three.
    path = tmp_path / "agent-state.json"
    path.write_text(json.dumps({"agent_id": "a1", "agent_token": "agtk-1"}))

    state = load_state(path)

    assert state.registered
    assert state.registration_token_fingerprint is None


def test_an_unknown_key_is_ignored_rather_than_failing_the_load(tmp_path: Path) -> None:
    # The other direction of the same compatibility problem: a file written by a NEWER agent and
    # read after a rollback. Losing the identity here would strand the agent.
    path = tmp_path / "agent-state.json"
    path.write_text(
        json.dumps({"agent_id": "a1", "agent_token": "agtk-1", "something_newer": "?"})
    )

    assert load_state(path).registered


def test_minted_with_recognises_only_the_token_it_recorded() -> None:
    state = AgentState("a1", "agtk-1", fingerprint("ares_agt_one"))

    assert state.minted_with("ares_agt_one")
    assert not state.minted_with("ares_agt_two")


def test_an_identity_with_no_recorded_fingerprint_matches_no_token() -> None:
    # False deliberately, and not merely as a side effect of the default: it is what makes an
    # upgrading agent present its stored token exactly once and record the answer. Answering True
    # instead would leave every pre-existing agent permanently unable to notice a new token.
    assert not AgentState("a1", "agtk-1").minted_with("ares_agt_one")


def test_the_registration_token_itself_is_never_written_to_the_file(tmp_path: Path) -> None:
    # The point of storing a hash rather than the token: this file is the agent's only credential
    # store, and a second copy of the enrollment secret would be a second thing to leak.
    path = tmp_path / "agent-state.json"
    token = "ares_agt_the_actual_secret"

    save_state(path, AgentState("a1", "agtk-1", fingerprint(token)))

    assert token not in path.read_text()


def test_the_identity_file_is_not_world_readable(tmp_path: Path) -> None:
    path = tmp_path / "agent-state.json"

    save_state(path, AgentState("a1", "agtk-1", fingerprint("ares_agt_one")))

    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_the_rescan_setting_and_the_last_detection_round_trip(tmp_path: Path) -> None:
    # given rescans off and a stored answer; when the state is saved and loaded; then both survive,
    # which is what lets such an agent restart without probing again
    path = tmp_path / "agent-state.json"
    state = AgentState(
        agent_id="a1",
        agent_token="agtk-1",
        auto_rescan=False,
        detected_networks=["172.23.0.0/16", "10.20.0.0/16"],
        detected_scope="reachable:True",
        reach_probed_at=_PROBED_AT,
    )

    save_state(path, state)

    assert load_state(path) == state


def test_a_state_file_from_before_the_rescan_setting_reads_as_on_with_nothing_stored(
    tmp_path: Path,
) -> None:
    # given a file from an agent deployed before 3.11, without the new keys; when it is loaded;
    # then it reads as "never told" (so on) and "nothing stored" (so it probes once, as it did)
    path = tmp_path / "agent-state.json"
    path.write_text(json.dumps({"agent_id": "a1", "agent_token": "agtk-1"}))

    state = load_state(path)

    assert state.registered
    assert state.auto_rescan is None
    assert state.auto_rescan_on
    assert state.stored_detection("reachable:True") is None


def test_a_hand_edited_detection_reads_as_nothing_stored(tmp_path: Path) -> None:
    # given a hand-edited file with a wrongly typed value in every new field; when it is loaded;
    # then each reads as unset, costing a probe rather than a crash or a scope nobody detected
    path = tmp_path / "agent-state.json"
    path.write_text(
        json.dumps(
            {
                "agent_id": "a1",
                "agent_token": "agtk-1",
                "auto_rescan": "false",
                "detected_networks": ["10.0.0.0/8", 7],
                "detected_scope": 3,
                "reach_probed_at": True,
            }
        )
    )

    state = load_state(path)

    assert state.registered
    assert state.auto_rescan is None
    assert state.detected_networks is None
    assert state.detected_scope is None
    assert state.reach_probed_at is None


def test_a_stored_detection_answers_only_for_the_scope_that_produced_it() -> None:
    # given an answer worked out with the active probe on; when it is asked for under the same
    # scope and under the probe off; then only the first gets it, the second is another question
    state = AgentState(detected_networks=["10.20.0.0/16"], detected_scope="reachable:True")

    assert state.stored_detection("reachable:True") == ["10.20.0.0/16"]
    assert state.stored_detection("reachable:False") is None


def test_an_empty_detection_is_an_answer_not_an_absence() -> None:
    # given a probe that found nothing reachable; when the answer is read back; then it is an empty
    # answer, not "never probed", or a host that reaches nothing would re-probe on every restart
    state = AgentState(detected_networks=[], detected_scope="reachable:True")

    assert state.stored_detection("reachable:True") == []
