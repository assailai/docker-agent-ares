"""Normalize a Kubernetes cluster's read-only API LIST output into executable-control facts (the
credentialed Kubernetes cohort slice).

Read-only: authenticates to the API server with a bearer token from the agent's local vault
(``k8s_token`` credential kind) and does paged LIST GETs only (no watch, no create/patch/delete, no
exec), then parses the returned objects into the ``kubernetes.*`` fields. Like the device/host
collectors it ABSTAINS rather than invents: a LIST the token is not authorized for, or a cluster not
reachable, leaves the control UNAVAILABLE / the field out, so it stays NOT_ASSESSED.

Only controls a normal read token can actually answer live here. The controls that need the API
server's own startup flags (etcd / secret at-rest encryption, audit policy, kubelet auth) and the
admission / supply-chain controls stay DESIGNED: a LIST token cannot read them, so shipping a
collector for them would have to guess.

The parse functions are PURE (LIST JSON in, typed value out); the networked LIST is a separate
coroutine so the handler is testable by monkeypatching the fetch.
"""

from __future__ import annotations

from agent.kubeinfo import KubeApi

# The kubernetes controls this collector reads from the authenticated API.
SERVES = frozenset({"kubernetes.workload.privileged"})

# The Kubernetes-owned namespaces: privileged system pods (CNI, kube-proxy) live here and are expected
# platform components, so a privileged-workload finding counts USER namespaces only to avoid a false
# positive on every stock cluster.
_SYSTEM_NAMESPACES = frozenset({"kube-system", "kube-public", "kube-node-lease"})

# Bound the read so a huge cluster cannot make one collection unbounded (build-for-scale). A cluster
# larger than this still yields a lower-bound count, which only ever UNDER-reports a gt-0 finding,
# never a false positive.
_MAX_PODS = 10_000
_PAGE_LIMIT = 500
# The standard API-server port; the collect target is the API host.
_API_PORT = 6443


def serves(control_id: str) -> bool:
    """Whether this collector reads ``control_id`` from the Kubernetes API."""
    return control_id in SERVES


def _is_privileged(container: object) -> bool:
    """Whether a container runs privileged (``securityContext.privileged`` is exactly ``True``)."""
    if not isinstance(container, dict):
        return False
    security_context = container.get("securityContext")
    return isinstance(security_context, dict) and security_context.get("privileged") is True


def parse_privileged_workloads(pods: dict) -> int | None:
    """The number of pods in non-system namespaces running at least one privileged container, or
    ``None`` to abstain when the input is not a pod list. Privileged = ``securityContext.privileged``
    true on any of a pod's containers (incl. init / ephemeral). The Kubernetes-owned namespaces
    (kube-system, kube-public, kube-node-lease) are excluded, so the expected platform components do
    not read as a finding; a privileged workload a tenant deployed does."""
    items = pods.get("items")
    if not isinstance(items, list):
        return None
    count = 0
    for pod in items:
        if not isinstance(pod, dict):
            continue
        namespace = (pod.get("metadata") or {}).get("namespace")
        if namespace in _SYSTEM_NAMESPACES:
            continue
        spec = pod.get("spec") or {}
        containers: list[object] = []
        for key in ("containers", "initContainers", "ephemeralContainers"):
            value = spec.get(key)
            if isinstance(value, list):
                containers.extend(value)
        if any(_is_privileged(container) for container in containers):
            count += 1
    return count


async def fetch_pods(api: KubeApi) -> dict:
    """Page through ``GET /api/v1/pods`` and return one ``{"items": [...]}`` document, bounded by
    ``_MAX_PODS``. Read-only: a LIST GET, no watch, no write. Raises on connect/auth/HTTP error, which
    the caller records as honest UNAVAILABLE."""
    items: list[dict] = []
    continue_token = ""
    async with api.client() as client:
        while len(items) < _MAX_PODS:
            params: dict[str, object] = {"limit": _PAGE_LIMIT}
            if continue_token:
                params["continue"] = continue_token
            response = await client.get("/api/v1/pods", params=params)
            response.raise_for_status()
            body = response.json()
            page = body.get("items")
            if isinstance(page, list):
                items.extend(page)
            continue_token = (body.get("metadata") or {}).get("continue") or ""
            if not continue_token:
                break
    return {"items": items[:_MAX_PODS]}


def api_for(target: str, token: str, *, timeout: float, verify: str | bool = False) -> KubeApi:
    """A :class:`KubeApi` for the target's API server on the standard port, authenticated by the vault
    bearer token. ``verify`` defaults to False because a cluster's API serves its own CA-signed (often
    self-signed) certificate, which the agent has no store for; the connection is still TLS, and the
    token authenticates us to the server (the inverse trust from the ares control plane, where a bad
    certificate must fail)."""
    return KubeApi(base_url=f"https://{target}:{_API_PORT}", token=token, verify=verify, timeout=timeout)


def privileged_workloads_field(pods: dict) -> dict[str, object] | None:
    """The ``kubernetes.workload.privileged`` field dict from a pod list, or ``None`` to abstain."""
    count = parse_privileged_workloads(pods)
    return None if count is None else {"privileged_workloads": count}
