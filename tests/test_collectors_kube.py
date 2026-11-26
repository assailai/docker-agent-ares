"""The Kubernetes collector counts privileged workloads from a read-only pod LIST, excluding the
Kubernetes-owned system namespaces (so a stock cluster's platform pods do not read as a finding) and
abstaining when the input is not a pod list."""

from __future__ import annotations

from agent.collectors import kube_collect


def _pod(namespace: str, *, privileged: bool, section: str = "containers") -> dict:
    container: dict = {"name": "c", "image": "x"}
    if privileged:
        container["securityContext"] = {"privileged": True}
    return {"metadata": {"name": "p", "namespace": namespace}, "spec": {section: [container]}}


def test_counts_privileged_pods_in_user_namespaces() -> None:
    pods = {
        "items": [
            _pod("team-a", privileged=True),
            _pod("team-b", privileged=True),
            _pod("team-c", privileged=False),
        ]
    }
    assert kube_collect.parse_privileged_workloads(pods) == 2


def test_system_namespace_privileged_pods_are_excluded() -> None:
    # kube-proxy / CNI run privileged in kube-system by design: not a finding.
    pods = {
        "items": [
            _pod("kube-system", privileged=True),
            _pod("kube-public", privileged=True),
            _pod("kube-node-lease", privileged=True),
        ]
    }
    assert kube_collect.parse_privileged_workloads(pods) == 0


def test_privileged_init_and_ephemeral_containers_count() -> None:
    assert kube_collect.parse_privileged_workloads({"items": [_pod("app", privileged=True, section="initContainers")]}) == 1
    assert (
        kube_collect.parse_privileged_workloads(
            {"items": [_pod("app", privileged=True, section="ephemeralContainers")]}
        )
        == 1
    )


def test_a_clean_cluster_reads_zero() -> None:
    assert kube_collect.parse_privileged_workloads({"items": [_pod("app", privileged=False)]}) == 0
    assert kube_collect.parse_privileged_workloads({"items": []}) == 0


def test_not_a_pod_list_abstains() -> None:
    assert kube_collect.parse_privileged_workloads({}) is None
    assert kube_collect.parse_privileged_workloads({"items": "nope"}) is None
    assert kube_collect.parse_privileged_workloads({"kind": "Status", "code": 403}) is None


def test_privileged_is_exactly_true_not_truthy() -> None:
    # A securityContext without privileged, or privileged set to a non-True value, is not privileged.
    pod = {"metadata": {"namespace": "app"}, "spec": {"containers": [{"securityContext": {"runAsUser": 0}}]}}
    assert kube_collect.parse_privileged_workloads({"items": [pod]}) == 0


def test_serves_and_field_dict() -> None:
    assert kube_collect.serves("kubernetes.workload.privileged") is True
    assert kube_collect.serves("server.ssh.password") is False
    assert kube_collect.serves("kubernetes.api.anonymous") is False  # probe control, not this tier
    assert kube_collect.privileged_workloads_field({"items": [_pod("app", privileged=True)]}) == {
        "privileged_workloads": 1
    }
    assert kube_collect.privileged_workloads_field({"items": "nope"}) is None


def test_api_for_builds_the_standard_api_endpoint() -> None:
    api = kube_collect.api_for("10.0.0.5", "tok", timeout=5.0)
    assert api.base_url == "https://10.0.0.5:6443"
    assert api.token == "tok"
    assert api.verify is False
