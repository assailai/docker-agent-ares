"""Durable agent identity, persisted as a single JSON file.

A deployed agent needs to remember two things: who it is (its id + bearer token), and which
registration token that identity was minted from. The file is written 0600 so the token is not
world-readable.

It also keeps the last reachability answer and the dashboard's "Rescan automatically" setting, so
an agent told not to look again does not probe the customer's private space on every restart.
"""

from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import asdict, dataclass
from pathlib import Path

_lock = threading.Lock()


def fingerprint(registration_token: str) -> str:
    """A stable, non-reversible label for a registration token.

    Only ever compared against another fingerprint: never sent anywhere, and never logged. The
    question it answers is "did the operator re-run the installer with the same token, or a
    different one?", and a hash settles that without keeping a second copy of the secret on disk.
    """
    return hashlib.sha256(registration_token.encode()).hexdigest()


@dataclass
class AgentState:
    agent_id: str | None = None
    agent_token: str | None = None  # bearer token presented on every control-plane call
    # Which ARES_TOKEN this identity is already accounted for by. Two cases share the field: the
    # registration token that minted the identity, or - when a *different* token was presented
    # and the control plane refused it as spent - that refused one, recorded so the agent does
    # not re-present a dead token on every container restart. At the one place this is read the
    # meaning is the same either way: "presenting this token again would tell us nothing new".
    # None for a state file written before the field existed; see minted_with.
    registration_token_fingerprint: str | None = None
    # What the dashboard's "Rescan automatically" setting last said, as the heartbeat reported it.
    # None means never told, which reads as on: that is what every agent did before the setting
    # existed, and a control plane older than it never sends one.
    auto_rescan: bool | None = None
    # The last reachability answer, and the settings that produced it (see detection_scope), so a
    # restart with automatic rescans off reuses it rather than probing again. An answer worked out
    # under a different ARES_SCAN_SCOPE or ARES_REACH_PROBE is not this agent's answer any more.
    detected_networks: list[str] | None = None
    detected_scope: str | None = None
    # When reachability was last probed, successfully or not, in epoch seconds. Wall clock rather
    # than monotonic because it has to mean the same thing after a restart.
    reach_probed_at: float | None = None

    def __post_init__(self) -> None:
        # A hand-edited or half-written file must cost at most one extra probe, never a crash and
        # never a scope nobody detected. Anything malformed reads as "not stored".
        if not isinstance(self.auto_rescan, bool):
            self.auto_rescan = None
        if not (
            isinstance(self.detected_networks, list)
            and all(isinstance(n, str) for n in self.detected_networks)
        ):
            self.detected_networks = None
        if not isinstance(self.detected_scope, str):
            self.detected_scope = None
        probed = self.reach_probed_at
        if isinstance(probed, bool) or not isinstance(probed, (int, float)):
            self.reach_probed_at = None

    @property
    def registered(self) -> bool:
        return bool(self.agent_id and self.agent_token)

    @property
    def auto_rescan_on(self) -> bool:
        return self.auto_rescan is not False

    def stored_detection(self, scope: str) -> list[str] | None:
        """The last reachability answer if it was worked out under ``scope``, else None.

        An empty list is an answer ("probed, found nothing reachable"), not an absence of one.
        """
        if self.detected_networks is None or self.detected_scope != scope:
            return None
        return self.detected_networks

    def minted_with(self, registration_token: str) -> bool:
        """True if this identity is already accounted for by ``registration_token``.

        Deliberately False for a state file that predates the field: that is what makes an
        upgrading agent present its stored token exactly once and record the answer, rather than
        either re-enrolling on every restart or never noticing a new token again.
        """
        if not self.registration_token_fingerprint:
            return False
        return self.registration_token_fingerprint == fingerprint(registration_token)


def load_state(path: Path) -> AgentState:
    if path.exists():
        try:
            known = {f for f in AgentState.__dataclass_fields__}
            data = {k: v for k, v in json.loads(path.read_text()).items() if k in known}
            return AgentState(**data)
        except (ValueError, OSError, TypeError):
            pass
    return AgentState()


def save_state(path: Path, state: AgentState) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with _lock:
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(asdict(state), indent=2))
        tmp.chmod(0o600)
        tmp.replace(path)
