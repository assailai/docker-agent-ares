"""The platform backend contract the updater applies through (Docker or Kubernetes)."""

from __future__ import annotations

from enum import StrEnum
from typing import Protocol

from pydantic import BaseModel

from updater.config import UpdaterSettings


class Role(StrEnum):
    """Where this updater stands relative to the container its settings name as itself."""

    OWNER = "owner"  # this process runs in that container: it acts
    STANDBY = "standby"  # another container holds the name (a handoff in flight, or a leftover)
    UNMANAGED = "unmanaged"  # nothing by that name: the agent still updates, the updater never does


class SelfInspection(BaseModel):
    role: Role
    image: str | None = None  # the image this updater runs, when it is the OWNER


class UpdatePlan(BaseModel):
    """Verified image refs to move to; None leaves that container as it is."""

    agent: str | None = None
    updater: str | None = None


class Backend(Protocol):
    def available(self) -> bool:
        """True if this backend can run here (the Docker socket / an in-cluster service account)."""
        ...

    def running_image(self, settings: UpdaterSettings) -> str | None:
        """The image ref the agent is currently running, or None if it is not deployed yet."""
        ...

    def inspect_self(self, settings: UpdaterSettings) -> SelfInspection:
        """Whether this updater holds its own container name, and the image it runs if so."""
        ...

    def remove_predecessor(self, settings: UpdaterSettings) -> None:
        """Remove an updater that handed over to this one but failed to remove itself."""
        ...

    def apply(self, settings: UpdaterSettings, plan: UpdatePlan) -> None:
        """Move the agent, then this updater, to the plan's images. A Docker handoff that succeeds
        ends this process; returning means the updater was not replaced."""
        ...
