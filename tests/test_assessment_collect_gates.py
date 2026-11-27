"""The three-gate stamping in `control_facts`, and the baseline-control exception that omits the
policy gate so the control plane earns it from the tenant baseline."""

from __future__ import annotations

from agent import assessment_collect


def test_factual_control_stamps_all_three_gates() -> None:
    out = assessment_collect.control_facts(
        "kubernetes.workload.privileged", {"privileged_workloads": 2}, collection_complete=True
    )
    facts = out["facts"]
    assert facts["applicable"]["value"] is True
    assert facts["policy_approved"]["value"] is True
    assert facts["collection_complete"]["value"] is True
    assert facts["privileged_workloads"]["value"] == 2


def test_baseline_control_omits_the_policy_gate() -> None:
    out = assessment_collect.control_facts(
        "kubernetes.rbac.cluster_admin_bindings",
        {"observed_cluster_admin_members": ["user:alice"]},
        collection_complete=True,
        include_policy_gate=False,
    )
    facts = out["facts"]
    # the agent asserts what it OBSERVED, but NOT policy_approved: the control plane earns that gate.
    assert "policy_approved" not in facts
    assert facts["applicable"]["value"] is True
    assert facts["collection_complete"]["value"] is True
    assert facts["observed_cluster_admin_members"]["value"] == ["user:alice"]
