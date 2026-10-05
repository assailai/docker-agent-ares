"""What a Kubernetes cluster calls the addresses a scan finds.

A scan sees pod and Service addresses. The cluster is the only thing that knows which Service
fronts which pod, and that mapping is what turns thousands of churning pod rows into a handful of
workloads an operator recognises.

Read once per scan, not once per host. The API answers for the whole cluster in a few paged calls,
so the identity phase looks each address up in a dict and pays no network cost per host. That
matters because that phase is already on a time budget.

Opt-in, because it needs cluster read credentials the agent does not otherwise hold. Nothing here
decides a name: it reports what the cluster declared, and ares turns that into a display name.
"""

from __future__ import annotations

import asyncio
import logging
import os
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

import httpx

logger = logging.getLogger("ares.agent.kubeinfo")

# where kubernetes projects a pod's ServiceAccount credentials
_SA_DIR = Path("/var/run/secrets/kubernetes.io/serviceaccount")
# objects per API page. Large enough that an ordinary cluster is one or two calls, small enough
# that one response stays a sane size.
_PAGE_LIMIT = 500
# ceiling on objects read per kind. A kind with more is skipped rather than read in part, and
# paging stops here rather than growing the agent's memory without bound.
_MAX_OBJECTS = 20_000
# default wall clock for the whole cluster read, shared between the four kinds
# (ARES_KUBE_BUDGET_SECONDS)
_BUDGET_SECONDS = 120.0
# the label kubernetes puts on an EndpointSlice naming the Service it belongs to
_SERVICE_LABEL = "kubernetes.io/service-name"
# the label a Deployment's ReplicaSet stamps on its pods. The ReplicaSet is named
# "<deployment>-<hash>", so this is what recovers the Deployment name without another API call.
_TEMPLATE_HASH_LABEL = "pod-template-hash"
# owner kinds whose name is already the workload's name
_DIRECT_OWNER_KINDS = frozenset({"StatefulSet", "DaemonSet", "Job", "CronJob"})
# the longest cluster label we will send. ares bounds this field at 253 and rejects the WHOLE
# report if it is longer, and a rejected report fails the task, so an operator's over-long label
# would throw away an entire scan's inventory to carry a name nobody can read anyway. Trimmed here
# rather than refused, because the label is cosmetic and the inventory is not.
_MAX_CLUSTER_LABEL = 253


@dataclass(slots=True)
class KubernetesEvidence:
    """What the cluster declared about one address."""

    cluster: str | None = None
    namespace: str | None = None
    service: str | None = None
    workload: str | None = None
    # How the Service is published: ClusterIP, NodePort, LoadBalancer or ExternalName. This is the
    # difference between a port that only the cluster can reach and one the world can, which is
    # what decides whether a surface is worth assessing at all.
    service_type: str | None = None
    # The hostname an Ingress routes to this Service, when one does. The strongest exposure signal
    # there is: something outside the cluster was deliberately pointed at this workload.
    ingress_host: str | None = None

    def is_empty(self) -> bool:
        return not any(
            (
                self.cluster,
                self.namespace,
                self.service,
                self.workload,
                self.service_type,
                self.ingress_host,
            )
        )

    def as_payload(self) -> dict:
        payload: dict = {}
        for key in ("cluster", "namespace", "service", "workload", "service_type", "ingress_host"):
            value = getattr(self, key)
            if value:
                payload[key] = value
        return payload


class KubeConfigError(Exception):
    """No usable way to reach a cluster API was configured."""


@dataclass(slots=True)
class KubeApi:
    """Where the cluster API is and how to authenticate to it.

    Two ways in, both explicit. In-cluster uses the ServiceAccount kubernetes projects into the
    pod. Otherwise an operator points the agent at an API server and supplies a token file, which
    is what an agent on a bastion has. A kubeconfig is deliberately not parsed: it carries exec
    plugins and client certificates, which is a lot of surface for a case an explicit URL and
    token already covers.
    """

    base_url: str
    token: str
    verify: str | bool = True
    timeout: float = 15.0
    # swapped for a stub in tests. A seam rather than a patched method because this is a slots
    # dataclass, and because a test that replaces the transport still exercises the real client.
    transport: httpx.AsyncBaseTransport | None = None

    @classmethod
    def in_cluster(cls, *, timeout: float = 15.0) -> KubeApi:
        host = os.environ.get("KUBERNETES_SERVICE_HOST")
        if not host or not (_SA_DIR / "token").exists():
            raise KubeConfigError("not running in a cluster with a projected ServiceAccount")
        port = os.environ.get("KUBERNETES_SERVICE_PORT", "443")
        ca = _SA_DIR / "ca.crt"
        return cls(
            base_url=f"https://{host}:{port}",
            token=(_SA_DIR / "token").read_text().strip(),
            verify=str(ca) if ca.exists() else True,
            timeout=timeout,
        )

    @classmethod
    def from_settings(
        cls, *, api_url: str, token_file: str, ca_file: str, timeout: float = 15.0
    ) -> KubeApi:
        """An explicitly configured API server, for an agent that is not in the cluster."""
        if not api_url:
            raise KubeConfigError("no cluster API url configured")
        path = Path(token_file)
        if not token_file or not path.exists():
            raise KubeConfigError(f"cluster API token file not readable: {token_file!r}")
        token = path.read_text().strip()
        if not token:
            raise KubeConfigError(f"cluster API token file is empty: {token_file!r}")
        return cls(
            base_url=api_url.rstrip("/"),
            token=token,
            verify=ca_file or True,
            timeout=timeout,
        )

    def client(self) -> httpx.AsyncClient:
        kwargs: dict = {
            "base_url": self.base_url,
            "headers": {"Authorization": f"Bearer {self.token}", "Accept": "application/json"},
            "timeout": self.timeout,
        }
        if self.transport is not None:
            kwargs["transport"] = self.transport
        else:
            kwargs["verify"] = self.verify
        return httpx.AsyncClient(**kwargs)


class _PartialRead(Exception):
    """A kind could not be read whole.

    Raised instead of returning what was read: see :func:`_list_within` for why part of a list is
    worse than none of it.
    """


class _Refused(_PartialRead):
    """The API refused the kind.

    The ordinary answer when the role grants less than the agent asks for (an operator who dropped
    the ``pods`` rule, say), so it is logged below a warning.
    """


def _dict(value: object) -> dict:
    """``value`` when it is an object, otherwise an empty one."""
    return value if isinstance(value, dict) else {}


def _list(value: object) -> list:
    """``value`` when it is an array, otherwise an empty one."""
    return value if isinstance(value, list) else []


def _pick(value: object, keys: tuple[str, ...]) -> dict:
    """The named keys of ``value``, or nothing when it is not an object."""
    if not isinstance(value, dict):
        return {}
    return {key: value[key] for key in keys if key in value}


def _slim_service(obj: dict) -> dict:
    return {
        "metadata": _pick(obj.get("metadata"), ("name", "namespace")),
        "spec": _pick(obj.get("spec"), ("type", "clusterIP", "clusterIPs")),
    }


def _slim_slice(obj: dict) -> dict:
    endpoints = obj.get("endpoints")
    if not isinstance(endpoints, list):
        endpoints = []
    return {
        "metadata": _pick(obj.get("metadata"), ("namespace", "labels")),
        "endpoints": [_pick(endpoint, ("addresses",)) for endpoint in endpoints],
    }


def _slim_ingress(obj: dict) -> dict:
    return {
        "metadata": _pick(obj.get("metadata"), ("namespace",)),
        "spec": _pick(obj.get("spec"), ("defaultBackend", "rules")),
    }


def _slim_pod(obj: dict) -> dict:
    return {
        "metadata": _pick(obj.get("metadata"), ("namespace", "labels", "ownerReferences")),
        "status": _pick(obj.get("status"), ("podIP", "podIPs")),
    }


@dataclass(frozen=True, slots=True)
class _Kind:
    """One list call, and the fields worth keeping from each object it returns.

    Objects are cut down as each page arrives: 20,000 Pods held whole come to about 700 MiB, more
    than the agent container's 512Mi limit.
    """

    path: str
    slim: Callable[[dict], dict]


_SERVICES = "/api/v1/services"
_SLICES = "/apis/discovery.k8s.io/v1/endpointslices"
_INGRESSES = "/apis/networking.k8s.io/v1/ingresses"
_PODS = "/api/v1/pods"
# read in this order: the two that produce names first, so they get the budget while it is whole
_KINDS = (
    _Kind(_SERVICES, _slim_service),
    _Kind(_SLICES, _slim_slice),
    _Kind(_INGRESSES, _slim_ingress),
    _Kind(_PODS, _slim_pod),
)


async def _list_all(client: httpx.AsyncClient, kind: _Kind) -> list[dict]:
    """Every object of ``kind`` across all pages, or :class:`_PartialRead`.

    Never returns part of a list, so :func:`_list_within` alone decides what an incomplete read is
    worth.
    """
    items: list[dict] = []
    token = ""
    while True:
        params: dict[str, str | int] = {"limit": _PAGE_LIMIT}
        if token:
            params["continue"] = token
        resp = await client.get(kind.path, params=params)
        if resp.status_code in (401, 403):
            raise _Refused(str(resp.status_code))
        resp.raise_for_status()
        body = resp.json()
        page = body.get("items") if isinstance(body, dict) else None
        if not isinstance(page, list):
            raise _PartialRead("a page with no item list")
        items.extend(kind.slim(obj) for obj in page if isinstance(obj, dict))
        if len(items) > _MAX_OBJECTS:
            raise _PartialRead(f"more than {_MAX_OBJECTS} objects")
        meta = body.get("metadata") or {}
        if not isinstance(meta, dict):
            raise _PartialRead("a page with malformed metadata")
        token = meta.get("continue")
        if token is None or token == "":
            return items
        if not isinstance(token, str):
            raise _PartialRead("a page with a malformed continue token")
        if len(items) == _MAX_OBJECTS:
            raise _PartialRead(f"more than {_MAX_OBJECTS} objects")


async def _list_within(client: httpx.AsyncClient, kind: _Kind, budget: float) -> list[dict]:
    """:func:`_list_all`, abandoned when ``budget`` runs out or the kind will not answer.

    Returns an empty list rather than a partial one. A half-read EndpointSlice list is worse than
    none: the addresses it did not reach are not merely unnamed, they would fold separately from
    the ones it did, so one Service would render as two cards that disagree.

    EVERY failure is contained here, not just a timeout and not just a refusal. Letting one escape
    meant a single 404 or a transient 503 on the last and largest kind threw away the kinds that
    had already succeeded, because the caller's guard returns ``{}`` for the whole read. A cluster
    older than ``networking.k8s.io/v1`` answers 404 for Ingresses, and pods is both read last and
    the most likely to meet a 503 under load, so that was the common case rather than the exotic
    one.
    """
    try:
        async with asyncio.timeout(budget):
            return await _list_all(client, kind)
    except _Refused as exc:
        logger.info("cluster API refused %s (%s); skipping that kind", kind.path, exc)
    except _PartialRead as exc:
        logger.warning("reading %s stopped short (%s); skipping that kind", kind.path, exc)
    except TimeoutError:
        logger.warning("reading %s passed its %.1fs share; skipping that kind", kind.path, budget)
    except (httpx.HTTPError, ValueError, RecursionError) as exc:
        # ValueError covers a body that is not JSON, which an error page from a proxy in front of
        # the API server will be. RecursionError is a deeply nested body, and is a RuntimeError,
        # so nothing else here would catch it.
        logger.warning("reading %s failed (%s); skipping that kind", kind.path, exc)
    return []


async def _read_kinds(
    client: httpx.AsyncClient, kinds: Sequence[_Kind], *, budget: float
) -> dict[str, list[dict]]:
    """Each kind's objects keyed by path, the whole read finished inside ``budget`` seconds.

    ONE deadline over the whole read, not just per request. Paging a large cluster is up to 40
    sequential calls per kind, so a per-request timeout bounds nothing an operator can reason
    about.

    Each kind is read under its own slice of what is left, so a slow or enormous ``pods`` cannot
    starve the kinds after it, and a kind that overruns contributes nothing (see
    :func:`_list_within`).

    A RUNNING deadline, not a fixed share each. ``max(api.timeout, budget / kinds)`` was wrong in
    the direction that matters: ``api.timeout`` is operator-settable, so raising it to cope with a
    slow API server RAISED the ceiling it was supposed to sit under, four times over. The remaining
    time is divided by the kinds left, so the total is bounded by ``budget`` whatever the
    per-request timeout is, and an early kind that finishes fast hands its unused time to the ones
    after it.
    """
    loop = asyncio.get_running_loop()
    deadline = loop.time() + budget
    out: dict[str, list[dict]] = {}
    for index, kind in enumerate(kinds):
        share = max(deadline - loop.time(), 0.0) / (len(kinds) - index)
        out[kind.path] = await _list_within(client, kind, share)
    return out


def _meta(obj: dict) -> tuple[str | None, str | None]:
    meta = _dict(obj.get("metadata"))
    name = meta.get("name")
    namespace = meta.get("namespace")
    return (
        name if isinstance(name, str) else None,
        namespace if isinstance(namespace, str) else None,
    )


def _service_types(services: list[dict]) -> dict[tuple[str, str], str]:
    """How each ``(namespace, service)`` is published.

    Kept apart from the address map because it is keyed by the Service rather than by an address:
    a pod behind a LoadBalancer Service has no address of the Service's own, and that pod is
    exactly the one an operator wants told is reachable from outside.
    """
    out: dict[tuple[str, str], str] = {}
    for svc in services:
        name, namespace = _meta(svc)
        kind = _dict(svc.get("spec")).get("type")
        if name and namespace and isinstance(kind, str) and kind:
            out[(namespace, name)] = kind
    return out


def _ingress_hosts(ingresses: list[dict]) -> dict[tuple[str, str], str]:
    """The hostname each ``(namespace, service)`` is published under, when an Ingress publishes it.

    An Ingress names a host and routes its paths to backend Services, so this walks the rules to
    find which Service each host reaches. The first host wins for a Service fronted by several,
    which keeps the answer stable between scans rather than following whichever rule sorted first.
    """
    out: dict[tuple[str, str], str] = {}
    for item in ingresses:
        _, namespace = _meta(item)
        if not namespace:
            continue
        spec = _dict(item.get("spec"))
        default = _dict(_dict(spec.get("defaultBackend")).get("service")).get("name")
        for rule in _list(spec.get("rules")):
            if not isinstance(rule, dict):
                continue
            host = rule.get("host")
            paths = _list(_dict(rule.get("http")).get("paths"))
            for path in paths:
                if not isinstance(path, dict):
                    continue
                backend = _dict(_dict(path.get("backend")).get("service")).get("name") or default
                if isinstance(host, str) and host and isinstance(backend, str) and backend:
                    out.setdefault((namespace, backend), host)
    return out


def _service_addresses(services: list[dict]) -> dict[str, tuple[str, str]]:
    """Each Service's own addresses, mapped to ``(service, namespace)``.

    A Service's ClusterIP already resolves to a clean name in cluster DNS, so this mostly
    corroborates the PTR. It is read anyway because a headless Service has no ClusterIP and an
    agent may be looking at a cluster whose DNS it cannot use.
    """
    out: dict[str, tuple[str, str]] = {}
    for svc in services:
        name, namespace = _meta(svc)
        if not name or not namespace:
            continue
        spec = _dict(svc.get("spec"))
        addresses = [spec.get("clusterIP"), *_list(spec.get("clusterIPs"))]
        for address in addresses:
            # "None" is what a headless Service carries, and it is a string, not a null
            if isinstance(address, str) and address and address != "None":
                out[address] = (name, namespace)
    return out


def _endpoint_addresses(slices: list[dict]) -> dict[str, tuple[str, str]]:
    """Every backing pod address, mapped to the Service that fronts it.

    This is the mapping that does the real work: it is what lets a pod address be reported as the
    Service it belongs to rather than as itself.
    """
    out: dict[str, tuple[str, str]] = {}
    for item in slices:
        _, namespace = _meta(item)
        service = _dict(_dict(item.get("metadata")).get("labels")).get(_SERVICE_LABEL)
        if not namespace or not isinstance(service, str) or not service:
            continue
        for endpoint in _list(item.get("endpoints")):
            if not isinstance(endpoint, dict):
                continue
            for address in _list(endpoint.get("addresses")):
                # first writer wins, so a pod fronted by two Services keeps one answer rather than
                # flipping between them from scan to scan
                if isinstance(address, str) and address and address not in out:
                    out[address] = (service, namespace)
    return out


def _workload_name(pod: dict) -> str | None:
    """The workload a pod belongs to, from its owner reference.

    A ReplicaSet is named ``<deployment>-<pod-template-hash>`` and the hash is a label on the pod,
    so the Deployment name comes back without a second API call. Every other controller names
    itself after the workload already.
    """
    owners = _list(_dict(pod.get("metadata")).get("ownerReferences"))
    for owner in owners:
        if not isinstance(owner, dict):
            continue
        kind, name = owner.get("kind"), owner.get("name")
        if not isinstance(kind, str) or not isinstance(name, str) or not name:
            continue
        if kind in _DIRECT_OWNER_KINDS:
            return name
        if kind == "ReplicaSet":
            suffix = _dict(_dict(pod.get("metadata")).get("labels")).get(_TEMPLATE_HASH_LABEL)
            if isinstance(suffix, str) and suffix and name.endswith(f"-{suffix}"):
                return name[: -len(suffix) - 1]
            return name
    return None


def _pod_addresses(pods: list[dict]) -> dict[str, tuple[str, str]]:
    """Each pod address mapped to ``(workload, namespace)``.

    The only name a pod no Service fronts has at all, and that pod has no PTR record either, so
    this is the one source for it.
    """
    out: dict[str, tuple[str, str]] = {}
    for pod in pods:
        _, namespace = _meta(pod)
        workload = _workload_name(pod)
        if not namespace or not workload:
            continue
        status = _dict(pod.get("status"))
        addresses = [status.get("podIP")]
        addresses.extend(
            entry.get("ip") for entry in _list(status.get("podIPs")) if isinstance(entry, dict)
        )
        for address in addresses:
            if isinstance(address, str) and address and address not in out:
                out[address] = (workload, namespace)
    return out


async def collect(
    api: KubeApi, *, cluster: str | None = None, budget: float = _BUDGET_SECONDS
) -> dict[str, KubernetesEvidence]:
    """Every address this cluster can name, keyed by address.

    Each kind is read independently, so a role granted only part of what was asked for still
    produces what it did grant. Raises nothing the caller has to handle beyond the API being
    unreachable: see :func:`safe_collect`.
    """
    async with api.client() as client:
        read = await _read_kinds(client, _KINDS, budget=budget)
    services = read[_SERVICES]
    slices = read[_SLICES]
    ingresses = read[_INGRESSES]
    pods = read[_PODS]

    by_service = _endpoint_addresses(slices)
    by_service.update(_service_addresses(services))
    by_workload = _pod_addresses(pods)
    types = _service_types(services)
    hosts = _ingress_hosts(ingresses)

    label = (cluster or "").strip()[:_MAX_CLUSTER_LABEL] or None
    if cluster and label != cluster.strip():
        logger.warning("cluster label is longer than %d characters; trimmed", _MAX_CLUSTER_LABEL)

    out: dict[str, KubernetesEvidence] = {}
    for address in set(by_service) | set(by_workload):
        service, service_ns = by_service.get(address, (None, None))
        workload, workload_ns = by_workload.get(address, (None, None))
        # exposure is a property of the SERVICE, so it reaches every address behind it: the pod an
        # operator is looking at is the one that needs telling it is reachable from outside.
        key = (service_ns, service) if service and service_ns else None
        evidence = KubernetesEvidence(
            cluster=label,
            namespace=service_ns or workload_ns,
            service=service,
            workload=workload,
            service_type=types.get(key) if key else None,
            ingress_host=hosts.get(key) if key else None,
        )
        if not evidence.is_empty():
            out[address] = evidence
    logger.info("cluster inventory: %d addresses named", len(out))
    return out


async def safe_collect(
    api: KubeApi, *, cluster: str | None = None, budget: float = _BUDGET_SECONDS
) -> dict[str, KubernetesEvidence]:
    """:func:`collect`, with a total failure reported as an empty inventory.

    This is the outer guard, and it should now be unreachable for anything a single kind can do:
    :func:`_list_within` contains a refusal, a partial read, a timeout and an HTTP error per kind,
    so one bad kind costs its own names and no others. What is left here is the client failing to
    be built at all.

    Naming is an enrichment. A cluster that will not answer must cost the scan its names, never
    the scan itself.
    """
    try:
        return await collect(api, cluster=cluster, budget=budget)
    except Exception:  # noqa: BLE001 - an unreachable cluster is not a reason to fail a scan
        logger.warning("cluster inventory unavailable; scan continues without it", exc_info=True)
        return {}
