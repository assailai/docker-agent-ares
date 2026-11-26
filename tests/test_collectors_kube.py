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


# ── NetworkPolicy (kubernetes.network.no_default_deny) ────────────────────────────────────────────
def _default_deny_ingress() -> dict:
    # Selects all pods, denies all ingress (a policyType with no allow rules).
    return {"spec": {"podSelector": {}, "policyTypes": ["Ingress"]}}


def test_a_default_deny_ingress_policy_reads_present() -> None:
    assert kube_collect.parse_default_deny_present({"items": [_default_deny_ingress()]}) is True


def test_a_default_deny_egress_policy_reads_present() -> None:
    policy = {"spec": {"podSelector": {}, "policyTypes": ["Egress"]}}
    assert kube_collect.parse_default_deny_present({"items": [policy]}) is True


def test_no_default_deny_reads_absent() -> None:
    # Empty list, and a targeted allow policy (selects specific pods, has allow rules): no default-deny.
    assert kube_collect.parse_default_deny_present({"items": []}) is False
    allow = {
        "spec": {
            "podSelector": {"matchLabels": {"app": "web"}},
            "policyTypes": ["Ingress"],
            "ingress": [{"from": [{"podSelector": {}}]}],
        }
    }
    assert kube_collect.parse_default_deny_present({"items": [allow]}) is False


def test_all_pods_but_with_allow_rules_is_not_default_deny() -> None:
    # Selects all pods but permits some ingress: not a default-deny.
    policy = {"spec": {"podSelector": {}, "policyTypes": ["Ingress"], "ingress": [{"from": []}]}}
    assert kube_collect.parse_default_deny_present({"items": [policy]}) is False


def test_netpol_not_a_list_abstains() -> None:
    assert kube_collect.parse_default_deny_present({}) is None
    assert kube_collect.parse_default_deny_present({"items": "nope"}) is None


def test_netpol_serves_and_field() -> None:
    assert kube_collect.serves("kubernetes.network.no_default_deny") is True
    assert "kubernetes.network.no_default_deny" in kube_collect.NETPOL_CONTROLS
    assert kube_collect.default_deny_field({"items": [_default_deny_ingress()]}) == {
        "default_deny_network_policy_present": True
    }
    assert kube_collect.default_deny_field({"items": "nope"}) is None


# ── Namespace Pod Security admission (kubernetes.admission.pod_security_disabled) ──────────────────
def _ns(name: str, enforce: str | None = None) -> dict:
    labels = {"pod-security.kubernetes.io/enforce": enforce} if enforce else {}
    return {"metadata": {"name": name, "labels": labels}}


def test_all_user_namespaces_enforcing_reads_enforced() -> None:
    nss = {"items": [_ns("kube-system"), _ns("team-a", "restricted"), _ns("team-b", "baseline")]}
    assert kube_collect.parse_pod_security_enforced(nss) is True


def test_a_user_namespace_without_enforce_label_reads_not_enforced() -> None:
    nss = {"items": [_ns("team-a", "restricted"), _ns("default")]}
    assert kube_collect.parse_pod_security_enforced(nss) is False


def test_privileged_enforce_level_is_not_enforcing() -> None:
    nss = {"items": [_ns("team-a", "privileged")]}
    assert kube_collect.parse_pod_security_enforced(nss) is False


def test_system_namespaces_are_excluded_and_only_system_abstains() -> None:
    # Only Kubernetes-owned namespaces: nothing user-facing to assess, so abstain.
    nss = {"items": [_ns("kube-system"), _ns("kube-public"), _ns("kube-node-lease")]}
    assert kube_collect.parse_pod_security_enforced(nss) is None


def test_namespaces_not_a_list_abstains() -> None:
    assert kube_collect.parse_pod_security_enforced({}) is None
    assert kube_collect.parse_pod_security_enforced({"items": "nope"}) is None


def test_namespace_serves_and_field() -> None:
    assert kube_collect.serves("kubernetes.admission.pod_security_disabled") is True
    assert "kubernetes.admission.pod_security_disabled" in kube_collect.NAMESPACE_CONTROLS
    assert kube_collect.pod_security_field({"items": [_ns("team-a", "restricted")]}) == {
        "pod_security_admission_enforced": True
    }
    assert kube_collect.pod_security_field({"items": "nope"}) is None
def test_anonymous_auth_field_and_serves() -> None:
    from agent.collectors import kube_collect as kc
    assert kc.serves("kubernetes.api.anonymous") is False  # a probe, not the token tier
    assert kc.probes("kubernetes.api.anonymous") is True
    # the probe returns True when the API did NOT answer 401 (anonymous accepted)
    assert kc.anonymous_auth_field(True) == {"anonymous_auth_enabled": True}
    assert kc.anonymous_auth_field(False) == {"anonymous_auth_enabled": False}
    assert kc.anonymous_auth_field("x") is None
