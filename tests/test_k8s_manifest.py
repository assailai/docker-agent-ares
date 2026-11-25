"""The Kubernetes deployment's privilege boundary, and the e2e manifest that is supposed to prove it.

The agent container parses untrusted data from the networks it scans and dials hosts the server
names, and the manifest itself calls it the unprivileged half. The updater needs a ServiceAccount
that can patch this Deployment. Kubernetes automounts a pod's token into *every* container, so
putting `serviceAccountName` on the pod spec and stopping there hands the agent a credential that
can replace its own image with anything, no cosign involved - and, on a cluster without restricted
Pod Security admission, patch in a privileged hostPath pod and own the node.

Nothing fails when this regresses. The deployment keeps working perfectly.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

_REPO = Path(__file__).resolve().parents[1]
MANIFEST = _REPO / "deploy" / "k8s" / "ares-agent.yaml"
E2E = _REPO / "scripts" / "e2e_autoupdate_k8s.sh"
_SA_PATH = "/var/run/secrets/kubernetes.io/serviceaccount"


def _docs(text: str) -> list[dict]:
    return [doc for doc in yaml.safe_load_all(text) if doc]


def _shipped() -> list[dict]:
    return _docs(MANIFEST.read_text())


def _e2e() -> list[dict]:
    """The manifest the k8s e2e applies, lifted out of its heredoc."""
    body = E2E.read_text().split("<<'YAML'", 1)[1].split("\nYAML", 1)[0]
    return _docs(body.split("\n", 1)[1])


def _deployment(docs: list[dict]) -> dict:
    return next(doc for doc in docs if doc.get("kind") == "Deployment")


def _containers(docs: list[dict]) -> dict[str, dict]:
    pod = _deployment(docs)["spec"]["template"]["spec"]
    return {container["name"]: container for container in pod["containers"]}


_MANIFESTS = {"deploy/k8s/ares-agent.yaml": _shipped, "scripts/e2e_autoupdate_k8s.sh": _e2e}


@pytest.mark.parametrize("name", list(_MANIFESTS), ids=lambda n: n.split("/")[-1])
def test_the_pod_does_not_automount_the_service_account_token(name: str) -> None:
    # given the pod spec
    pod = _deployment(_MANIFESTS[name]())["spec"]["template"]["spec"]

    # then the automount is off. It defaults to ON, and the ServiceAccount here is the one with
    # patch rights on this very Deployment, so leaving it unset is what puts a credential in the
    # agent container.
    assert pod.get("serviceAccountName") == "ares-updater"
    assert pod.get("automountServiceAccountToken") is False, (
        f"{name}: the pod automounts its token, so every container gets one"
    )


@pytest.mark.parametrize("name", list(_MANIFESTS), ids=lambda n: n.split("/")[-1])
def test_only_the_updater_container_is_given_the_token(name: str) -> None:
    # given both containers' mounts
    containers = _containers(_MANIFESTS[name]())
    mounts = {
        container: [mount["mountPath"] for mount in spec.get("volumeMounts", [])]
        for container, spec in containers.items()
    }

    # then the agent has no path that could hold a Kubernetes credential, and the updater does:
    # the token is projected into the sidecar alone
    assert _SA_PATH not in mounts["ares-agent"], f"{name}: the agent is mounted a token"
    assert not [path for path in mounts["ares-agent"] if "serviceaccount" in path.lower()], (
        f"{name}: the agent mounts something serviceaccount-shaped: {mounts['ares-agent']}"
    )
    assert _SA_PATH in mounts["ares-updater"], f"{name}: the updater cannot reach the API"


@pytest.mark.parametrize("name", list(_MANIFESTS), ids=lambda n: n.split("/")[-1])
def test_the_token_is_projected_rather_than_taken_from_a_secret(name: str) -> None:
    # given the volume the updater mounts
    pod = _deployment(_MANIFESTS[name]())["spec"]["template"]["spec"]
    volume = next(v for v in pod["volumes"] if v["name"] == "kube-api-access")

    # then it is a projected serviceAccountToken, which is bound and expires, rather than a
    # long-lived Secret
    sources = volume["projected"]["sources"]
    token = next(s["serviceAccountToken"] for s in sources if "serviceAccountToken" in s)
    assert token["path"] == "token"
    assert token.get("expirationSeconds"), f"{name}: the projected token never expires"
    # the API server's CA has to come with it, or the updater cannot verify the endpoint it talks to
    assert any("configMap" in s and s["configMap"]["name"] == "kube-root-ca.crt" for s in sources)


def test_the_updater_role_can_only_patch_the_agent_deployment() -> None:
    # given the Role the ServiceAccount is bound to
    role = next(doc for doc in _shipped() if doc.get("kind") == "Role")

    # then it is one verb set, on one named Deployment. The token above is only as dangerous as
    # this, which is why the blast radius of the automount bug was "patch this Deployment" rather
    # than "anything in the namespace".
    (rule,) = role["rules"]
    assert rule["apiGroups"] == ["apps"]
    assert rule["resources"] == ["deployments"]
    assert rule["resourceNames"] == ["ares-agent"]
    assert sorted(rule["verbs"]) == ["get", "patch"]


def test_the_e2e_exercises_the_topology_we_ship() -> None:
    # the e2e is the only thing that runs this against a real API server, so a divergence here
    # means it proves a deployment nobody has.
    shipped = _deployment(_shipped())["spec"]["template"]["spec"]
    e2e = _deployment(_e2e())["spec"]["template"]["spec"]

    for key in ("serviceAccountName", "automountServiceAccountToken"):
        assert shipped.get(key) == e2e.get(key), f"{key} differs between the manifests"
    # strategy sits on the Deployment, not the pod spec: Recreate is what makes a failed rollout
    # destroy the working agent first, so the e2e has to run it too (ARES-2327).
    assert _deployment(_shipped())["spec"]["strategy"] == _deployment(_e2e())["spec"]["strategy"]
