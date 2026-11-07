"""Companion auto-updater: keep the agent, and itself, on the version the server marks current.

Reads the desired version from the shared file the agent writes, and on drift verifies the
target image's signature and applies it via the platform (Docker recreate / k8s rolling
update). The agent stays unprivileged; only this updater touches the runtime.

The agent moves first. The updater follows to the same release once the agent is on it (in the same
tick when both are behind), verified against the same signer, so a fix in the updater reaches every
install rather than only the ones that are reinstalled (ARES-2049).
"""

from __future__ import annotations

import json
import logging
import re
import time
from pathlib import Path

from pydantic import BaseModel

from updater import tlsconf, verify
from updater.backend import Backend, Role, SelfInspection, UpdatePlan
from updater.config import repo_of, settings, tag_of
from updater.dockerd import DockerBackend
from updater.kube import K8sBackend

logger = logging.getLogger("ares.updater")

# k8s wins if both somehow look available (e.g. a socket mounted inside a pod).
_BACKENDS: list[Backend] = [K8sBackend(), DockerBackend()]


def _configure_logging() -> None:
    """Raise the verbosity of ``ares.*`` only, never of the dependencies.

    Same reasoning as the agent's: handing the level to ``basicConfig`` sets the **root** level and
    would enable third-party DEBUG (httpcore traces every request over the docker socket). Root
    stays INFO; only our own loggers follow ``ARES_LOG_LEVEL``.
    """
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    logging.getLogger("ares").setLevel(getattr(logging, settings.log_level.upper(), logging.INFO))


def _pick_backend() -> Backend | None:
    return next((backend for backend in _BACKENDS if backend.available()), None)


def _read_target() -> str | None:
    try:
        raw = settings.target_file.read_text()
    except OSError:
        return None  # not written yet: no update is queued
    try:
        return json.loads(raw).get("version") or None
    except ValueError:
        logger.warning("ignoring malformed update target at %s", settings.target_file)
        return None


# in-memory cache of target version -> the digest ref cosign verified for it. Lets a steady
# state skip re-verifying every tick (an updater restart re-verifies once rather than
# re-applying); the updater mounts the shared data dir read-only, so this stays in memory.
_verified: dict[str, str] = {}  # for the agent's image
_verified_self: dict[str, str] = {}  # for this updater's own
# target version -> monotonic time before which moving the updater is not tried again. A failed
# move (no such image in the repo it runs from, or a successor that crashes) would otherwise repeat
# on every tick, every poll_seconds, for as long as the target stands.
_self_retry_after: dict[str, float] = {}
_SELF_RETRY_SECONDS = 1800.0
_predecessor_removed = False
_said_unmanaged = False
# the release this image was built as (Dockerfile.updater writes it); absent outside an image
_RELEASE_FILE = Path(__file__).with_name("RELEASE")
_RELEASE = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)")
_declined_downgrades: set[str] = set()


class _Resolution(BaseModel):
    current: bool
    pinned: str | None = None  # the verified digest to move to; None when refused (fail-closed)


def _resolve(*, running: str, target: str, repo: str, cache: dict[str, str]) -> _Resolution:
    """Whether ``running`` is already on ``target``, and if not, the verified image to move to."""
    if tag_of(running) == target or cache.get(target) == running:
        return _Resolution(current=True)  # on the target's own tag (initial deploy) or its digest
    image = f"{repo}:{target}"
    logger.info("update requested: target %s (%s)", target, image)
    pinned = verify.verify(image, settings)  # the verified digest ref, or None (fail-closed)
    if pinned is None:
        return _Resolution(current=False)
    cache[target] = pinned
    if running == pinned:
        return _Resolution(current=True)  # already running the verified digest; cache primed
    return _Resolution(current=False, pinned=pinned)


def _release_key(version: str) -> tuple[int, int, int] | None:
    """``3.14.0`` (or ``v3.14.0``, ``3.14.0-rc1``) -> ``(3, 14, 0)``; None when it is no release."""
    match = _RELEASE.match(version)
    return (int(match[1]), int(match[2]), int(match[3])) if match else None


def _own_release() -> str | None:
    try:
        return _RELEASE_FILE.read_text().strip() or None
    except OSError:
        return None  # not an image build: a checkout, or the tests


def _is_backwards(target: str) -> bool:
    """True when ``target`` is older than this updater's own release, or is no release at all while
    that one is known. The updater never moves itself backwards: marking an older release current
    moves the agent back, but an updater taken below 3.14.0 could never update itself again."""
    own = _release_key(_own_release() or "")
    if own is None:
        return False  # no release baked in, so nothing to compare against
    wanted = _release_key(target)
    return wanted is None or wanted < own


def _self_target(me: SelfInspection, target: str) -> str | None:
    """The verified image this updater should move to, or None to stay where it is. An image
    cosign refuses starts the retry wait, so the next ticks do not ask again."""
    if not settings.self_update or me.role is not Role.OWNER or me.image is None:
        return None
    if _is_backwards(target):
        if target not in _declined_downgrades:
            own = _own_release()
            logger.info("staying on release %s rather than moving back to %s", own, target)
            _declined_downgrades.add(target)
        return None
    if time.monotonic() < _self_retry_after.get(target, 0.0):
        return None
    # derived from this updater's own image, as the agent's is from the agent's: it can only move to
    # a new tag of the image it already runs.
    mine = _resolve(running=me.image, target=target, repo=repo_of(me.image), cache=_verified_self)
    if not mine.current and mine.pinned is None:
        _self_retry_after[target] = time.monotonic() + _SELF_RETRY_SECONDS
    return mine.pinned


def _settle_role(backend: Backend, me: SelfInspection) -> None:
    """What a role asks for once per process: an owner removes a predecessor that handed over to it
    and could not remove itself; an updater that cannot find its own container says so."""
    global _predecessor_removed, _said_unmanaged
    if me.role is Role.OWNER and not _predecessor_removed:
        backend.remove_predecessor(settings)
        _predecessor_removed = True
    if me.role is Role.UNMANAGED and settings.self_update and not _said_unmanaged:
        logger.info(
            "cannot identify its own container as %s; updating the agent only "
            "(ARES_UPDATE_SELF_CONTAINER_NAME names it)",
            settings.self_container_name,
        )
        _said_unmanaged = True


def _tick(backend: Backend) -> None:
    target = _read_target()
    if not target:
        return
    me = backend.inspect_self(settings)
    if me.role is Role.STANDBY:
        return  # another container holds this updater's name: a handoff to this one is in flight
    _settle_role(backend, me)
    running = backend.running_image(settings)
    if running is None:
        return  # no agent yet

    # the repo is derived from the running agent's image, so the updater can only move to a new
    # tag of the same image the agent already runs (ARES_UPDATE_IMAGE_REPO overrides it).
    agent = _resolve(
        running=running,
        target=target,
        repo=settings.image_repo or repo_of(running),
        cache=_verified,
    )
    if not agent.current and agent.pinned is None:
        return  # the agent's update was refused; the updater waits for the agent
    plan = UpdatePlan(agent=agent.pinned, updater=_self_target(me, target))
    if not (plan.agent or plan.updater):
        return
    try:
        backend.apply(settings, plan)
    finally:
        # a Docker handoff that succeeds never returns here, and k8s replaces this process with the
        # rollout. Still being here means the updater was not replaced: wait before trying again.
        if plan.updater:
            _self_retry_after[target] = time.monotonic() + _SELF_RETRY_SECONDS


def main() -> None:
    _configure_logging()
    # Before anything reaches out: cosign is a subprocess, so SSL_CERT_FILE is the only way to
    # hand it the host's CAs on a network that inspects TLS.
    tlsconf.install_ca_bundle()
    backend = _pick_backend()
    if backend is None:
        logger.error(
            "no Docker socket and not running in Kubernetes; the updater cannot apply updates."
        )
        raise SystemExit(1)
    logger.info(
        "%s watching %s and itself (%s, self-update %s) every %ss",
        type(backend).__name__,
        settings.container_name,
        settings.self_container_name,
        "on" if settings.self_update else "off",
        settings.poll_seconds,
    )
    while True:
        try:
            _tick(backend)
        except Exception as exc:  # noqa: BLE001 - keep the updater alive through any transient error
            logger.error("update check failed: %s", exc)
        time.sleep(settings.poll_seconds)


if __name__ == "__main__":
    main()
