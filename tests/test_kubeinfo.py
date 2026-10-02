"""Reading a cluster's own names for the addresses a scan finds.

Driven against a stub API rather than a mocked client, because the things that break here are
wire-shaped: a paged list that stops early, a headless Service whose clusterIP is the string
"None", a role that grants two kinds out of three.
"""

from __future__ import annotations

import asyncio

import httpx
import pytest

from agent import kubeinfo
from agent.kubeinfo import KubeApi, KubeConfigError, KubernetesEvidence


def _svc(name: str, namespace: str, cluster_ip: str | None) -> dict:
    return {
        "metadata": {"name": name, "namespace": namespace},
        "spec": {"clusterIP": cluster_ip} if cluster_ip is not None else {},
    }


def _slice(service: str, namespace: str, addresses: list[str]) -> dict:
    return {
        "metadata": {
            "name": f"{service}-abcde",
            "namespace": namespace,
            "labels": {"kubernetes.io/service-name": service},
        },
        "endpoints": [{"addresses": addresses}],
    }


def _pod(
    name: str, namespace: str, ip: str, owner: dict | None, labels: dict | None = None
) -> dict:
    meta: dict = {"name": name, "namespace": namespace}
    if owner is not None:
        meta["ownerReferences"] = [owner]
    if labels:
        meta["labels"] = labels
    return {"metadata": meta, "status": {"podIP": ip}}


def _api(routes: dict[str, list[dict]], *, refuse: set[str] | None = None) -> KubeApi:
    """A KubeApi answering from ``routes``, one page at a time so paging is exercised."""
    refuse = refuse or set()

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path in refuse:
            return httpx.Response(403, json={"message": "forbidden"})
        items = routes.get(path, [])
        start = int(request.url.params.get("continue", 0) or 0)
        limit = 2  # smaller than any fixture below, so every list is at least two pages
        page = items[start : start + limit]
        nxt = start + limit
        meta = {"continue": str(nxt)} if nxt < len(items) else {}
        return httpx.Response(200, json={"items": page, "metadata": meta})

    return KubeApi(base_url="https://kube.test", token="t", transport=httpx.MockTransport(handler))


SERVICES = "/api/v1/services"
SLICES = "/apis/discovery.k8s.io/v1/endpointslices"
PODS = "/api/v1/pods"


async def test_a_pod_address_is_named_after_the_service_that_fronts_it() -> None:
    api = _api(
        {
            SERVICES: [_svc("checkout", "payments", "10.43.0.9")],
            SLICES: [_slice("checkout", "payments", ["10.42.0.5", "10.42.0.6"])],
            PODS: [],
        }
    )
    found = await kubeinfo.collect(api)
    assert found["10.42.0.5"].service == "checkout"
    assert found["10.42.0.5"].namespace == "payments"
    assert found["10.42.0.6"].service == "checkout"


async def test_a_services_own_address_is_named_too() -> None:
    api = _api({SERVICES: [_svc("checkout", "payments", "10.43.0.9")], SLICES: [], PODS: []})
    found = await kubeinfo.collect(api)
    assert found["10.43.0.9"].service == "checkout"


async def test_a_headless_services_none_is_not_read_as_an_address() -> None:
    # a headless Service carries the STRING "None", which would otherwise become a key
    api = _api({SERVICES: [_svc("db", "data", "None")], SLICES: [], PODS: []})
    assert await kubeinfo.collect(api) == {}


async def test_a_pod_no_service_fronts_is_named_after_its_workload() -> None:
    api = _api(
        {
            SERVICES: [],
            SLICES: [],
            PODS: [
                _pod(
                    "batch-7c9f8-xk2",
                    "jobs",
                    "10.42.0.9",
                    {"kind": "ReplicaSet", "name": "batch-7c9f8"},
                    {"pod-template-hash": "7c9f8"},
                )
            ],
        }
    )
    found = await kubeinfo.collect(api)
    # the ReplicaSet's hash is stripped, so this is the Deployment's name
    assert found["10.42.0.9"].workload == "batch"
    assert found["10.42.0.9"].service is None


async def test_a_statefulsets_pod_keeps_the_controllers_own_name() -> None:
    api = _api(
        {
            SERVICES: [],
            SLICES: [],
            PODS: [_pod("pg-0", "data", "10.42.0.3", {"kind": "StatefulSet", "name": "pg"})],
        }
    )
    assert (await kubeinfo.collect(api))["10.42.0.3"].workload == "pg"


async def test_the_service_and_the_workload_are_both_reported() -> None:
    # ares prefers the Service; the workload is there for the pods that have no Service
    api = _api(
        {
            SERVICES: [],
            SLICES: [_slice("checkout", "payments", ["10.42.0.5"])],
            PODS: [
                _pod(
                    "checkout-5d4-xx",
                    "payments",
                    "10.42.0.5",
                    {"kind": "ReplicaSet", "name": "checkout-5d4"},
                    {"pod-template-hash": "5d4"},
                )
            ],
        }
    )
    found = await kubeinfo.collect(api)
    assert found["10.42.0.5"].service == "checkout"
    assert found["10.42.0.5"].workload == "checkout"


async def test_a_pod_fronted_by_two_services_keeps_one_stable_answer() -> None:
    # the cluster genuinely has two answers. Picking the first and keeping it is what stops the
    # name flipping between scans, which is the churn this feature exists to remove.
    api = _api(
        {
            SERVICES: [],
            SLICES: [
                _slice("checkout", "payments", ["10.42.0.5"]),
                _slice("checkout-metrics", "payments", ["10.42.0.5"]),
            ],
            PODS: [],
        }
    )
    first = (await kubeinfo.collect(api))["10.42.0.5"].service
    second = (await kubeinfo.collect(api))["10.42.0.5"].service
    assert first == second == "checkout"


async def test_every_page_is_followed() -> None:
    addresses = [f"10.42.0.{n}" for n in range(1, 8)]
    api = _api({SERVICES: [], SLICES: [_slice("web", "default", addresses)], PODS: []})
    found = await kubeinfo.collect(api)
    # the slice list itself pages; the addresses inside one slice do not, so this proves the
    # service list and pod list paging below rather than the slice contents
    assert len(found) == len(addresses)


async def test_many_services_are_read_across_pages() -> None:
    services = [_svc(f"svc{n}", "default", f"10.43.0.{n}") for n in range(1, 8)]
    api = _api({SERVICES: services, SLICES: [], PODS: []})
    found = await kubeinfo.collect(api)
    assert len(found) == 7
    assert found["10.43.0.7"].service == "svc7"


async def test_a_refused_kind_costs_only_that_kind() -> None:
    # the common deployment error: the ClusterRole was trimmed. What was granted still names hosts.
    api = _api(
        {
            SERVICES: [_svc("checkout", "payments", "10.43.0.9")],
            SLICES: [_slice("checkout", "payments", ["10.42.0.5"])],
            PODS: [],
        },
        refuse={PODS},
    )
    found = await kubeinfo.collect(api)
    assert found["10.42.0.5"].service == "checkout"
    assert found["10.43.0.9"].service == "checkout"


async def test_the_cluster_label_rides_on_every_answer() -> None:
    api = _api({SERVICES: [_svc("checkout", "payments", "10.43.0.9")], SLICES: [], PODS: []})
    found = await kubeinfo.collect(api, cluster="prod")
    assert found["10.43.0.9"].cluster == "prod"


async def test_an_unreachable_cluster_is_an_empty_inventory_not_a_failed_scan() -> None:
    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("no route to host")

    api = KubeApi(
        base_url="https://kube.test", token="t", transport=httpx.MockTransport(boom)
    )
    assert await kubeinfo.safe_collect(api) == {}


def test_an_unconfigured_cluster_is_refused_rather_than_guessed(monkeypatch) -> None:
    monkeypatch.delenv("KUBERNETES_SERVICE_HOST", raising=False)
    with pytest.raises(KubeConfigError):
        KubeApi.in_cluster()
    with pytest.raises(KubeConfigError):
        KubeApi.from_settings(api_url="", token_file="", ca_file="")


def test_a_missing_token_file_is_refused_rather_than_sent_empty(tmp_path) -> None:
    with pytest.raises(KubeConfigError):
        KubeApi.from_settings(
            api_url="https://kube.test", token_file=str(tmp_path / "nope"), ca_file=""
        )
    empty = tmp_path / "token"
    empty.write_text("   ")
    with pytest.raises(KubeConfigError):
        KubeApi.from_settings(api_url="https://kube.test", token_file=str(empty), ca_file="")


def test_an_empty_block_is_not_reported() -> None:
    assert KubernetesEvidence().is_empty()
    assert KubernetesEvidence().as_payload() == {}
    assert KubernetesEvidence(service="web", namespace="default").as_payload() == {
        "service": "web",
        "namespace": "default",
    }


# --- scale and shape, where a real cluster differs from a fixture ---------------------------------


def _big_api(services: int, pods_per: int) -> KubeApi:
    """A cluster with ``services`` Services and ``pods_per`` pods behind each, paged realistically."""
    svcs = [_svc(f"svc{n}", "default", f"10.43.{n // 254}.{n % 254}") for n in range(services)]
    slices = [
        _slice(f"svc{n}", "default", [f"10.42.{(n * pods_per + i) // 254}.{(n * pods_per + i) % 254}"
                                      for i in range(pods_per)])
        for n in range(services)
    ]

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        items = {SERVICES: svcs, SLICES: slices, PODS: []}.get(path, [])
        start = int(request.url.params.get("continue", 0) or 0)
        limit = int(request.url.params.get("limit", 500))
        page = items[start : start + limit]
        nxt = start + limit
        meta = {"continue": str(nxt)} if nxt < len(items) else {}
        return httpx.Response(200, json={"items": page, "metadata": meta})

    return KubeApi(base_url="https://kube.test", token="t", transport=httpx.MockTransport(handler))


async def test_a_large_cluster_is_read_whole_across_pages() -> None:
    # 2000 Services with 10 pods each: bigger than the page size by a wide margin, so this fails
    # if the continue token is ever dropped.
    found = await kubeinfo.collect(_big_api(services=2000, pods_per=10))
    assert len(found) == 2000 + 2000 * 10
    assert found["10.42.0.0"].service == "svc0"
    assert found[f"10.43.{1999 // 254}.{1999 % 254}"].service == "svc1999"


async def test_a_cluster_past_the_cap_is_truncated_rather_than_read_without_bound() -> None:
    # the guard that stops one scan growing the agent's memory with somebody else's cluster
    big = kubeinfo._MAX_OBJECTS + 1000
    api = _big_api(services=big, pods_per=0)
    found = await kubeinfo.collect(api)
    assert len(found) == kubeinfo._MAX_OBJECTS


async def test_a_custom_cluster_domain_is_read_the_same_way() -> None:
    # the API answers with object names, so the cluster's DNS domain never enters into it. This is
    # the half of the feature that works on a cluster not using cluster.local.
    api = _api(
        {
            SERVICES: [_svc("checkout", "payments", "10.43.0.9")],
            SLICES: [_slice("checkout", "payments", ["10.42.0.5"])],
            PODS: [],
        }
    )
    found = await kubeinfo.collect(api, cluster="k8s.acme.internal")
    assert found["10.42.0.5"].service == "checkout"
    assert found["10.42.0.5"].cluster == "k8s.acme.internal"


async def test_an_ipv6_pod_address_is_carried_through() -> None:
    api = _api({SERVICES: [], SLICES: [_slice("web", "default", ["2001:db8::1"])], PODS: []})
    assert (await kubeinfo.collect(api))["2001:db8::1"].service == "web"


async def test_a_malformed_page_does_not_abort_the_whole_read() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == SLICES:
            return httpx.Response(200, json={"items": "not a list"})
        if request.url.path == SERVICES:
            return httpx.Response(200, json={"items": [_svc("checkout", "payments", "10.43.0.9")]})
        return httpx.Response(200, json={"items": []})

    api = KubeApi(base_url="https://kube.test", token="t", transport=httpx.MockTransport(handler))
    found = await kubeinfo.collect(api)
    assert found["10.43.0.9"].service == "checkout"


async def test_a_pod_with_no_owner_is_skipped_rather_than_half_named() -> None:
    api = _api({SERVICES: [], SLICES: [], PODS: [_pod("loose", "default", "10.42.0.7", None)]})
    assert await kubeinfo.collect(api) == {}


# --- the limits that protect the scan this runs inside ---------------------------------------------


async def test_an_overlong_cluster_label_is_trimmed_not_sent() -> None:
    # ares bounds this field at 253 and rejects the WHOLE report if it is longer, and a rejected
    # report fails the task, so an unbounded label here would throw away an entire scan's
    # inventory to carry a name nobody can read.
    api = _api({SERVICES: [_svc("checkout", "payments", "10.43.0.9")], SLICES: [], PODS: []})
    found = await kubeinfo.collect(api, cluster="x" * 400)
    assert len(found["10.43.0.9"].cluster or "") == kubeinfo._MAX_CLUSTER_LABEL


async def test_a_kind_that_never_answers_costs_its_share_and_not_the_scan(monkeypatch) -> None:
    # this runs BEFORE the sweep and ahead of the first progress post, so an API that hangs would
    # otherwise hold the scan's own clock with no ceiling.
    async def hang(request: httpx.Request) -> httpx.Response:
        await asyncio.sleep(30)
        return httpx.Response(200, json={"items": []})

    api = KubeApi(
        base_url="https://kube.test",
        token="t",
        timeout=0.05,
        transport=httpx.MockTransport(hang),
    )
    # monkeypatch, not assignment: a module global left shortened here would silently shorten the
    # budget for every test that runs after this one
    monkeypatch.setattr(kubeinfo, "_BUDGET_SECONDS", 0.3)
    found = await kubeinfo.collect(api)
    assert found == {}


async def test_a_refused_kind_is_still_only_that_kind_after_the_budget_change() -> None:
    api = _api(
        {
            SERVICES: [_svc("checkout", "payments", "10.43.0.9")],
            SLICES: [_slice("checkout", "payments", ["10.42.0.5"])],
            PODS: [],
        },
        refuse={PODS},
    )
    found = await kubeinfo.collect(api)
    assert found["10.42.0.5"].service == "checkout"
    assert found["10.43.0.9"].service == "checkout"
