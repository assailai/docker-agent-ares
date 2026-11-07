"""Kubernetes backend: read the agent Deployment's images and patch them to target images.

Patching the Deployment triggers a native rolling update (and k8s owns the rollback via
``kubectl rollout undo``). The updater runs as a sidecar with a ServiceAccount scoped to
get/patch only the agent Deployment.

The updater is a container in that same Deployment, so it updates itself the same way: when both
the agent and the updater are behind, one patch sets both images and the pod rolls once. Nothing
like the Docker handoff is needed, because k8s replaces the whole pod.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

import httpx

from updater.backend import Role, SelfInspection, UpdatePlan
from updater.config import UpdaterSettings

logger = logging.getLogger("ares.updater.k8s")

_SA = Path("/var/run/secrets/kubernetes.io/serviceaccount")
_TIMEOUT = 60.0


class K8sBackend:
    def available(self) -> bool:
        return bool(os.environ.get("KUBERNETES_SERVICE_HOST")) and (_SA / "token").exists()

    def running_image(self, settings: UpdaterSettings) -> str | None:
        return _image_of(settings, container=settings.container_name)

    def inspect_self(self, settings: UpdaterSettings) -> SelfInspection:
        image = _image_of(settings, container=settings.self_container_name)
        if image is None:
            return SelfInspection(role=Role.UNMANAGED)
        return SelfInspection(role=Role.OWNER, image=image)

    def remove_predecessor(self, settings: UpdaterSettings) -> None:
        """Nothing to remove: a rollout replaces the whole pod."""

    def apply(self, settings: UpdaterSettings, plan: UpdatePlan) -> None:
        namespace = _namespace(settings)
        containers = [
            {"name": name, "image": image}
            for name, image in (
                (settings.container_name, plan.agent),
                (settings.self_container_name, plan.updater),
            )
            if image
        ]
        if not containers:
            return
        # strategic-merge patch: set only these containers' images; k8s rolls the Deployment.
        patch = {"spec": {"template": {"spec": {"containers": containers}}}}
        with _client() as kube:
            resp = kube.patch(
                _deployment_path(namespace, settings.container_name),
                json=patch,
                headers={"Content-Type": "application/strategic-merge-patch+json"},
            )
            resp.raise_for_status()
        logger.info(
            "patched Deployment %s/%s (%s); kubernetes will roll it out",
            namespace,
            settings.container_name,
            ", ".join(f"{c['name']}={c['image']}" for c in containers),
        )


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
