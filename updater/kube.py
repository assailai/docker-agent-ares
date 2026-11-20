"""Kubernetes backend: read the agent Deployment's images and patch them to target images.

Patching the Deployment triggers a native rolling update. The updater runs as a sidecar with a
ServiceAccount scoped to get/patch only the agent Deployment.

Kubernetes does **not** undo a rollout that fails: ``progressDeadlineSeconds`` only writes a
status condition, and the shipped manifest uses ``strategy: Recreate`` (a ReadWriteOnce PVC cannot
attach to two pods at once), so the working agent is destroyed before the replacement proves
viable. So this backend owns the gate the Docker one has had all along: patch, wait for the
rollout to come up *and stay up*, and put the previous images back when it does not.

The updater is a container in that same Deployment, so it updates itself the same way: when both
the agent and the updater are behind, one patch sets both images and the pod rolls once. Nothing
like the Docker handoff is needed, because k8s replaces the whole pod.
"""

from __future__ import annotations

import logging
import os
import time
from pathlib import Path

import httpx

from updater.backend import Role, SelfInspection, UpdatePlan
from updater.config import UpdaterSettings

logger = logging.getLogger("ares.updater.k8s")

_SA = Path("/var/run/secrets/kubernetes.io/serviceaccount")
_TIMEOUT = 60.0

_ROLLOUT_INTERVAL = 5.0
# Consecutive clean polls before we believe it, the analogue of dockerd's _VERIFY_CHECKS: the
# shipped manifest has a liveness probe and no readiness probe, so a container reads Ready the
# moment it starts - and a crash-looping one is Ready between restarts.
_ROLLOUT_SETTLE_CHECKS = 3
# Recreate + RWO PVC: terminate the old pod (30s default grace), pull the image, start, probe.
# Ready is seconds away on a healthy roll, so what this really has to cover is a cold pull on a
# slow link. It also clears a 90s initialDelay plus 3x30s failureThreshold should an operator add
# a readiness probe, and stays under k8s' 600s progressDeadlineSeconds, because we want to roll
# back rather than wait for the controller to merely note the failure.
_ROLLOUT_DEADLINE = 300.0

# said once, not every poll_seconds, while a rollout is in flight or wedged
_said_not_rolled_out = False


class K8sBackend:
    def available(self) -> bool:
        return bool(os.environ.get("KUBERNETES_SERVICE_HOST")) and (_SA / "token").exists()

    def running_image(self, settings: UpdaterSettings) -> str | None:
        """The agent's image, but only once the status says that image is the one running.

        A patched-but-not-rolled-out spec is not what the agent runs, and reporting it is what
        let a failed rollout be recorded as applied - on that tick and on every later one, and
        after an updater restart too, because the spec outlives the in-memory verified cache.
        """
        global _said_not_rolled_out
        with _client() as kube:
            deployment = _get_deployment(kube, settings)
        if deployment is None:
            return None
        if not _rolled_out(deployment):
            if not _said_not_rolled_out:
                status = deployment.get("status", {})
                logger.info(
                    "Deployment %s is rolling out or stuck (generation %s observed %s, "
                    "%s/%s updated, %s available); not stacking another update on it",
                    settings.container_name,
                    deployment.get("metadata", {}).get("generation"),
                    status.get("observedGeneration"),
                    status.get("updatedReplicas", 0),
                    deployment.get("spec", {}).get("replicas", 1),
                    status.get("availableReplicas", 0),
                )
                _said_not_rolled_out = True
            return None
        _said_not_rolled_out = False
        return _image_in(deployment, container=settings.container_name)

    def inspect_self(self, settings: UpdaterSettings) -> SelfInspection:
        # Deliberately the spec, not the rollout status: mid-roll this updater must still be able
        # to name its own image, or it could never compute a self-target.
        image = _image_of(settings, container=settings.self_container_name)
        if image is None:
            return SelfInspection(role=Role.UNMANAGED)
        return SelfInspection(role=Role.OWNER, image=image)

    def remove_predecessor(self, settings: UpdaterSettings) -> None:
        """Nothing to remove: a rollout replaces the whole pod."""

    def apply(self, settings: UpdaterSettings, plan: UpdatePlan) -> bool:
        """Patch the Deployment, wait for the rollout, and put the old images back if it fails.

        This can block for up to ``_ROLLOUT_DEADLINE``, so one poll cycle can take five minutes.
        The loop is single-threaded with no watchdog, so that is safe, but it is why the caller
        must not treat a slow tick as a hang.

        When ``plan.updater`` is set the gate is best effort: ``Recreate`` destroys this very
        container somewhere between the patch and the first poll, so nobody is left to roll
        anything back. What covers that case is ``running_image`` - the new sidecar in the rolled
        pod runs fine even while the agent crash-loops, sees a Deployment that is not rolled out,
        and records nothing as applied. The gate's live reach is the agent-only patch.
        """
        namespace = _namespace(settings)
        with _client() as kube:
            deployment = _get_deployment(kube, settings)
            if deployment is None:
                logger.error("Deployment %s/%s is gone; nothing to patch", namespace, settings.container_name)
                return False
            wanted = (
                (settings.container_name, plan.agent),
                (settings.self_container_name, plan.updater),
            )
            # Only containers the pod template actually has. A strategic-merge patch naming an
            # unknown container tries to ADD one, and is rejected for the fields it cannot invent
            # - so an operator who deleted the sidecar would otherwise break every update.
            containers = []
            previous = []
            for name, image in wanted:
                if not image:
                    continue
                was = _image_in(deployment, container=name)
                if was is None:
                    logger.info("Deployment has no container %s; leaving it out of the patch", name)
                    continue
                containers.append({"name": name, "image": image})
                previous.append({"name": name, "image": was})
            if not containers:
                return True

            _patch_images(kube, settings, containers)
            logger.info(
                "patched Deployment %s/%s (%s); waiting for the rollout",
                namespace,
                settings.container_name,
                ", ".join(f"{c['name']}={c['image']}" for c in containers),
            )
            if _await_rollout(kube, settings):
                logger.info("rollout complete: %s/%s is up", namespace, settings.container_name)
                return True

            logger.error(
                "the rollout of %s did not come up; rolling back to %s",
                ", ".join(f"{c['name']}={c['image']}" for c in containers),
                ", ".join(f"{c['name']}={c['image']}" for c in previous),
            )
            try:
                _patch_images(kube, settings, previous)
            except httpx.HTTPError as exc:
                logger.error(
                    "could not roll back Deployment %s/%s (%s). Restore it by hand: "
                    "kubectl -n %s rollout undo deploy/%s, or set %s",
                    namespace,
                    settings.container_name,
                    exc,
                    namespace,
                    settings.container_name,
                    ", ".join(f"{c['name']}={c['image']}" for c in previous),
                )
                return False
            logger.info("rolled back; the agent is on the image it was running")
            return False


def _patch_images(kube: httpx.Client, settings: UpdaterSettings, containers: list[dict]) -> None:
    """Strategic-merge patch: set only these containers' images; k8s rolls the Deployment."""
    resp = kube.patch(
        _deployment_path(_namespace(settings), settings.container_name),
        json={"spec": {"template": {"spec": {"containers": containers}}}},
        headers={"Content-Type": "application/strategic-merge-patch+json"},
    )
    resp.raise_for_status()


def _get_deployment(kube: httpx.Client, settings: UpdaterSettings) -> dict | None:
    """The agent Deployment as the API server reports it, or None when it is not there."""
    resp = kube.get(_deployment_path(_namespace(settings), settings.container_name))
    if resp.status_code == 404:
        return None
    resp.raise_for_status()
    return resp.json()


def _image_in(deployment: dict, *, container: str) -> str | None:
    """The image a container of the Deployment's pod template carries, or None."""
    containers = deployment["spec"]["template"]["spec"]["containers"]
    return next((c["image"] for c in containers if c["name"] == container), None)


def _rolled_out(deployment: dict) -> bool:
    """Whether the spec the Deployment carries is the one actually running."""
    spec, status = deployment.get("spec", {}), deployment.get("status", {})
    wanted = spec.get("replicas", 1)
    if wanted == 0:
        return True  # scaled to zero on purpose: not a stuck rollout, and never roll it back
    # observedGeneration first, and this is the load-bearing one. The apiserver bumps
    # metadata.generation synchronously on the patch; the controller writes observedGeneration
    # only once it has reconciled. Without this the first poll reads the status from BEFORE the
    # patch, which still says Ready, and every failed rollout reads as a success.
    if status.get("observedGeneration", 0) < deployment.get("metadata", {}).get("generation", 0):
        return False
    return (
        status.get("updatedReplicas", 0) >= wanted
        and status.get("readyReplicas", 0) >= wanted
        and status.get("availableReplicas", 0) >= 1
        and not status.get("unavailableReplicas")
    )


def _await_rollout(kube: httpx.Client, settings: UpdaterSettings) -> bool:
    """Whether the rollout just started came up AND stayed up inside the deadline."""
    deadline = time.monotonic() + _ROLLOUT_DEADLINE
    settled = 0
    while time.monotonic() < deadline:
        time.sleep(_ROLLOUT_INTERVAL)
        deployment = _get_deployment(kube, settings)
        if deployment is None:
            return False
        # reset rather than accumulate: a container that is Ready, dies, and is Ready again has
        # not stayed up, and counting those three polls as progress is what a crash loop looks
        # like from here.
        settled = settled + 1 if _rolled_out(deployment) else 0
        if settled >= _ROLLOUT_SETTLE_CHECKS:
            return True
    return False


def _image_of(settings: UpdaterSettings, *, container: str) -> str | None:
    """The image a container of the agent Deployment runs, or None if it is not there."""
    with _client() as kube:
        resp = kube.get(_deployment_path(_namespace(settings), settings.container_name))
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        containers = resp.json()["spec"]["template"]["spec"]["containers"]
    return next((c["image"] for c in containers if c["name"] == container), None)


def _namespace(settings: UpdaterSettings) -> str:
    return settings.k8s_namespace or (_SA / "namespace").read_text().strip()


def _client() -> httpx.Client:
    token = (_SA / "token").read_text().strip()
    host = os.environ["KUBERNETES_SERVICE_HOST"]
    port = os.environ.get("KUBERNETES_SERVICE_PORT", "443")
    return httpx.Client(
        base_url=f"https://{host}:{port}",
        headers={"Authorization": f"Bearer {token}"},
        verify=str(_SA / "ca.crt"),
        timeout=_TIMEOUT,
    )


def _deployment_path(namespace: str, name: str) -> str:
    return f"/apis/apps/v1/namespaces/{namespace}/deployments/{name}"
