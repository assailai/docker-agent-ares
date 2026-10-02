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
from dataclasses import dataclass
from pathlib import Path

import httpx

logger = logging.getLogger("ares.agent.kubeinfo")

# where kubernetes projects a pod's ServiceAccount credentials
_SA_DIR = Path("/var/run/secrets/kubernetes.io/serviceaccount")
# objects per API page. Large enough that an ordinary cluster is one or two calls, small enough
# that one response stays a sane size.
_PAGE_LIMIT = 500
# ceiling on objects read per kind. A cluster larger than this is read partially and says so,
# rather than growing the agent's memory without bound.
_MAX_OBJECTS = 20_000
# wall clock for the whole cluster read, shared between the three kinds. The agent is a scanner,
# and this runs before the scan it belongs to: a cluster that will not answer must cost a bounded
# amount of time, not the scan.
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


async def _list_all(client: httpx.AsyncClient, path: str) -> list[dict]:
    """Every object at ``path``, followed across pages and capped.

    A 403 is the ordinary answer when the agent was granted a narrower role than it asked for, so
    it reads as "this kind is unavailable" rather than an error: the kinds that did answer are
    still worth reporting.
    """
    items: list[dict] = []
    token = ""
    while True:
        params = {"limit": _PAGE_LIMIT}
        if token:
            params["continue"] = token
        resp = await client.get(path, params=params)
        if resp.status_code in (401, 403):
            logger.info("cluster API refused %s (%d); skipping that kind", path, resp.status_code)
            return items
        resp.raise_for_status()
        body = resp.json()
        page = body.get("items")
        if not isinstance(page, list):
            return items
        items.extend(obj for obj in page if isinstance(obj, dict))
        if len(items) >= _MAX_OBJECTS:
            logger.warning(
                "cluster has more than %d %s; reading the first page set", _MAX_OBJECTS, path
            )
            return items[:_MAX_OBJECTS]
        token = (body.get("metadata") or {}).get("continue") or ""
        if not token:
            return items


async def _list_within(client: httpx.AsyncClient, path: str, budget: float) -> list[dict]:
    """:func:`_list_all`, abandoned when ``budget`` runs out rather than read without end.

    Returns an empty list on a timeout rather than a partial one. A half-read EndpointSlice list
    is worse than none: the addresses it did not reach are not merely unnamed, they would fold
    separately from the ones it did, so one Service would render as two cards that disagree.
    """
    try:
        async with asyncio.timeout(budget):
            return await _list_all(client, path)
    except TimeoutError:
        logger.warning("reading %s passed its %.0fs share; skipping that kind", path, budget)
        return []


def _meta(obj: dict) -> tuple[str | None, str | None]:
    meta = obj.get("metadata") or {}
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
        kind = (svc.get("spec") or {}).get("type")
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
        spec = item.get("spec") or {}
        default = ((spec.get("defaultBackend") or {}).get("service") or {}).get("name")
        for rule in spec.get("rules") or []:
            if not isinstance(rule, dict):
                continue
            host = rule.get("host")
            paths = ((rule.get("http") or {}).get("paths")) or []
            for path in paths:
                if not isinstance(path, dict):
                    continue
                backend = ((path.get("backend") or {}).get("service") or {}).get("name") or default
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
        spec = svc.get("spec") or {}
        addresses = [spec.get("clusterIP"), *(spec.get("clusterIPs") or [])]
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
        service = ((item.get("metadata") or {}).get("labels") or {}).get(_SERVICE_LABEL)
        if not namespace or not isinstance(service, str) or not service:
            continue
        for endpoint in item.get("endpoints") or []:
            if not isinstance(endpoint, dict):
                continue
            for address in endpoint.get("addresses") or []:
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
    owners = (pod.get("metadata") or {}).get("ownerReferences") or []
    for owner in owners:
        if not isinstance(owner, dict):
            continue
        kind, name = owner.get("kind"), owner.get("name")
        if not isinstance(name, str) or not name:
            continue
        if kind in _DIRECT_OWNER_KINDS:
            return name
        if kind == "ReplicaSet":
            suffix = ((pod.get("metadata") or {}).get("labels") or {}).get(_TEMPLATE_HASH_LABEL)
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
        status = pod.get("status") or {}
        addresses = [status.get("podIP")]
        addresses.extend(
            entry.get("ip") for entry in (status.get("podIPs") or []) if isinstance(entry, dict)
        )
        for address in addresses:
            if isinstance(address, str) and address and address not in out:
                out[address] = (workload, namespace)
    return out


async def collect(api: KubeApi, *, cluster: str | None = None) -> dict[str, KubernetesEvidence]:
    """Every address this cluster can name, keyed by address.

    Each kind is read independently, so a role granted only part of what was asked for still
    produces what it did grant. Raises nothing the caller has to handle beyond the API being
    unreachable: see :func:`safe_collect`.
    """
    # ONE deadline over the whole read, not just per request. Paging a large cluster is up to 40
    # sequential calls per kind, so a per-request timeout bounds nothing an operator can reason
    # about: this runs before the scan starts and ahead of the first progress post, so a slow API
    # would otherwise hold the scan's own clock with no ceiling.
    #
    # Each kind is read under its own share of the budget rather than one deadline over all three,
    # so a slow or enormous `pods` cannot starve the two kinds that do the naming. Whatever a kind
    # returned before its share ran out is kept: a partial inventory still names hosts, and the
    # order below puts the two that matter first.
    share = max(api.timeout, _BUDGET_SECONDS / 4)
    async with api.client() as client:
        services = await _list_within(client, "/api/v1/services", share)
        slices = await _list_within(client, "/apis/discovery.k8s.io/v1/endpointslices", share)
        ingresses = await _list_within(client, "/apis/networking.k8s.io/v1/ingresses", share)
        pods = await _list_within(client, "/api/v1/pods", share)

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
    api: KubeApi, *, cluster: str | None = None
) -> dict[str, KubernetesEvidence]:
    """:func:`collect`, with every failure reported as an empty inventory.

    Naming is an enrichment. A cluster that will not answer must cost the scan its names, never
    the scan itself.
    """
    try:
        return await collect(api, cluster=cluster)
    except Exception:  # noqa: BLE001 - an unreachable cluster is not a reason to fail a scan
        logger.warning("cluster inventory unavailable; scan continues without it", exc_info=True)
        return {}
