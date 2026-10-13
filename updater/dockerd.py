"""Docker backend: read the running agent image and recreate it on a target image.

Fail-safe: the replacement is started and verified to stay up BEFORE the old container is
removed, so a bad target never takes the agent down. The agent never has the socket; only
this updater does.
"""

from __future__ import annotations

import logging
import time
from pathlib import Path

import httpx

from updater.config import UpdaterSettings

logger = logging.getLogger("ares.updater.docker")

_SOCK = Path("/var/run/docker.sock")
_TIMEOUT = 300.0
# the replacement must stay up across these checks before we retire the old container.
_VERIFY_CHECKS = 5
_VERIFY_INTERVAL = 2.0

class DockerBackend:
    def available(self) -> bool:
        return _SOCK.exists()

    def running_image(self, settings: UpdaterSettings) -> str | None:
        with _client() as docker:
            resp = docker.get(f"/containers/{settings.container_name}/json")
            if resp.status_code == 404:
                return None
            resp.raise_for_status()
            return resp.json()["Config"]["Image"]

    def apply(self, settings: UpdaterSettings, image_ref: str) -> None:
        name = settings.container_name
        next_name = f"{name}-next"
        with _client() as docker:
            _pull(docker, image_ref)
            old = docker.get(f"/containers/{name}/json")
            old.raise_for_status()
            attrs = old.json()

            # clear any leftover from a prior aborted run, then start the replacement carrying only
            # what the operator owns: the new image supplies the rest. HostConfig is preserved
            # wholesale because it *is* the operator's (mounts, restart policy, network), less what
            # an engine reports but will not accept back (see _replayable_host_config).
            docker.delete(f"/containers/{next_name}", params={"force": "true"})
            body = {
                **_operator_config(docker, attrs),
                "Image": image_ref,
                "HostConfig": _replayable_host_config(attrs["HostConfig"]),
            }
            try:
                created = docker.post("/containers/create", params={"name": next_name}, json=body)
                created.raise_for_status()
                cid = created.json()["Id"]
                docker.post(f"/containers/{cid}/start").raise_for_status()
            except httpx.HTTPError:
                # Never leave the replacement behind. A created-but-unstarted one keeps the data
                # volume in use (so an ARES_RESET install cannot remove it) and carries the old
                # restart=always, so podman-restart would try it at every boot: a second agent, the
                # day some future failure leaves one that does start.
                docker.delete(f"/containers/{next_name}", params={"force": "true"})
                raise

            if not _stays_up(docker, cid):
                logger.error("replacement did not stay up; aborting, the old agent keeps running")
                docker.delete(f"/containers/{cid}", params={"force": "true"})
                return

            # healthy: retire the old container and give its name to the replacement.
            docker.delete(f"/containers/{name}", params={"force": "true"})
            docker.post(f"/containers/{cid}/rename", params={"name": name})
            logger.info("updated %s to %s", name, image_ref)


def _replayable_host_config(host_config: dict) -> dict:
    """The old container's HostConfig, minus what an engine reports but will not take back.

    Podman's Docker-compatible inspect reports ``MemorySwappiness`` 0 for a container that never set
    one (Docker reports null), and crun refuses any explicit swappiness under cgroup v2, which every
    RHEL 9 and Fedora host runs. Copied back, it failed every Podman update at the swap with "crun:
    cannot set memory swappiness with cgroupv2" (ARES-1725, found on a real RHEL 9 host). Docker's
    own "unset" is null or -1, so dropping 0 as well loses only an explicit 0, a cgroup v1 tuning
    that no agent install sets.
    """
    config = dict(host_config)
    if config.get("MemorySwappiness") in (None, 0, -1):
        config.pop("MemorySwappiness", None)
    # A CPU limit (--cpus=N) comes back from Podman three ways at once: CpuPeriod, CpuQuota, and
    # NanoCpus derived from them. Podman's compat create refuses NanoCpus beside the other two
    # ("NanoCpus conflicts with CpuPeriod and CpuQuota"), so an agent run with a CPU limit failed
    # every update. Period and quota are the exact original; Docker never reports all three.
    if config.get("NanoCpus") and (config.get("CpuPeriod") or config.get("CpuQuota")):
        config.pop("NanoCpus")
    return config


def _client() -> httpx.Client:
    return httpx.Client(
        transport=httpx.HTTPTransport(uds=str(_SOCK)), base_url="http://docker", timeout=_TIMEOUT
    )


def _operator_labels(docker: httpx.Client, attrs: dict) -> dict[str, str]:
    """The old container's labels minus the ones its image contributed.

    A container inherits its image's labels, so copying them onto the replacement re-pins
    ``org.opencontainers.image.version`` (and ``revision``, ``created``, ...) to the version the
    agent was FIRST deployed at: ``docker inspect`` then reports a version the agent is not running,
    forever. Docker merges an image's labels in for every key the create body does *not* set, so
    passing only the operator's own labels lets the new image's real ones through.

    Fails toward dropping: if the old image cannot be inspected we keep none, so the new image's
    labels are still correct and only custom operator labels are lost.
    """
    labels: dict[str, str] = attrs["Config"].get("Labels") or {}
    if not labels:
        return {}
    try:
        resp = docker.get(f"/images/{attrs['Image']}/json")
        resp.raise_for_status()
        from_image: dict[str, str] = resp.json()["Config"].get("Labels") or {}
    except (httpx.HTTPError, KeyError, ValueError) as exc:
        logger.warning(
            "could not read the old image's labels (%s); the replacement inherits the new "
            "image's labels and drops any operator-set ones",
            exc,
        )
        return {}
    return {key: value for key, value in labels.items() if from_image.get(key) != value}


def _operator_config(docker: httpx.Client, attrs: dict) -> dict:
    """The slice of the old container's ``Config`` the replacement must carry over.

    Only what the *operator* set. Everything else in ``Config`` (``Entrypoint``, ``Cmd``,
    ``Healthcheck``, ``User``, ``WorkingDir``, ``Volumes``, ``ExposedPorts``, ...) came from the old
    image, and an explicit value in a create body OVERRIDES the new image's own, so carrying those
    forward would pin an updated agent to the old image's behaviour: a release that changed its
    entrypoint or healthcheck would be silently ignored on every deployed agent.

    Each key is omitted rather than set empty, so the new image supplies it unshadowed.
    """
    config: dict = {}
    if env := attrs["Config"].get("Env"):
        config["Env"] = env  # ARES_TOKEN and every other ARES_* setting; kept verbatim
    if labels := _operator_labels(docker, attrs):
        config["Labels"] = labels
    return config


def _stays_up(docker: httpx.Client, cid: str) -> bool:
    """True if the replacement keeps running across the verify window (not crash-looping)."""
    for _ in range(_VERIFY_CHECKS):
        time.sleep(_VERIFY_INTERVAL)
        if not _running(docker, cid):
            return False
    return True


def _pull(docker: httpx.Client, image_ref: str) -> None:
    # a digest ref (repo@sha256:...) is pulled by passing it whole as fromImage; a tag ref
    # splits into repo + tag. the body is a progress stream; reading it to completion = pulled.
    if "@" in image_ref:
        params = {"fromImage": image_ref}
    else:
        repo, _, tag = image_ref.rpartition(":")
        params = {"fromImage": repo, "tag": tag}
    docker.post("/images/create", params=params).raise_for_status()


def _running(docker: httpx.Client, cid: str) -> bool:
    resp = docker.get(f"/containers/{cid}/json")
    resp.raise_for_status()
    return bool(resp.json()["State"]["Running"])
