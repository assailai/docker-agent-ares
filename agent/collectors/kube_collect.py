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

import ssl

import httpx

from agent.kubeinfo import KubeApi

# The kubernetes controls this collector reads from the authenticated API, grouped by the resource
# each one LISTs so the tier fetches a resource only when a control needs it.
POD_CONTROLS = frozenset({"kubernetes.workload.privileged"})
NETPOL_CONTROLS = frozenset({"kubernetes.network.no_default_deny"})
NAMESPACE_CONTROLS = frozenset({"kubernetes.admission.pod_security_disabled"})
# A BASELINE-COMPARISON control: the agent sends the RAW observed cluster-admin member set and leaves
# the `policy_approved` gate for the control plane, which diffs the set against the tenant's approved
# baseline (the agent has none). Distinct from the factual-absolute controls above, whose field IS the
# finding; here the agent never judges which members are "unapproved".
RBAC_CONTROLS = frozenset({"kubernetes.rbac.cluster_admin_bindings"})
SERVES = POD_CONTROLS | NETPOL_CONTROLS | NAMESPACE_CONTROLS | RBAC_CONTROLS
# Probed WITHOUT the token, so NOT part of the authenticated LIST tier (SERVES): whether the API
# server (and the kubelet) accept the anonymous identity at all. A separate `probes()` predicate so
# the dispatcher runs these as no-credential probes, not through the k8s_token tier.
PROBE_CONTROLS = frozenset({"kubernetes.api.anonymous", "kubernetes.kubelet.unauthenticated"})

# The kubelet's read-only/authenticated API port. An anonymous request reaching a non-401 answer here
# means the kubelet accepts unauthenticated callers (a node-takeover surface).
_KUBELET_PORT = 10250

# Pod Security admission enforce levels that actually restrict workloads; "privileged" (or an absent
# label) does not enforce.
_PSA_ENFORCING_LEVELS = frozenset({"baseline", "restricted"})
_PSA_ENFORCE_LABEL = "pod-security.kubernetes.io/enforce"

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
    """Whether this collector reads ``control_id`` from the Kubernetes API with the token (the
    authenticated LIST tier). The anonymous-auth probe is NOT here: it uses no credential."""
    return control_id in SERVES


def probes(control_id: str) -> bool:
    """Whether ``control_id`` is a no-credential Kubernetes PROBE (the anonymous-auth check), run
    without the token rather than through the authenticated LIST tier."""
    return control_id in PROBE_CONTROLS


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


def _selects_all_pods(pod_selector: object) -> bool:
    """Whether a NetworkPolicy podSelector selects EVERY pod in its namespace (an empty selector: no
    matchLabels and no matchExpressions), which is what a default-deny policy uses."""
    if not isinstance(pod_selector, dict):
        return False
    return not pod_selector.get("matchLabels") and not pod_selector.get("matchExpressions")


def parse_default_deny_present(netpols: dict) -> bool | None:
    """Whether at least one NetworkPolicy enforces a namespace default-deny (selects all pods and names
    a policyType with no allow rules), or ``None`` to abstain when the input is not a NetworkPolicy
    list. The field is the present sense, so ABSENCE reads ``False`` (a finding). Under-reports rather
    than over-reports: a default-deny in one namespace reads present even if another lacks it, so this
    never false-positives a cluster that does have default-deny."""
    items = netpols.get("items")
    if not isinstance(items, list):
        return None
    for policy in items:
        if not isinstance(policy, dict):
            continue
        spec = policy.get("spec") or {}
        if not _selects_all_pods(spec.get("podSelector", {})):
            continue
        policy_types = spec.get("policyTypes") or []
        if "Ingress" in policy_types and not spec.get("ingress"):
            return True
        if "Egress" in policy_types and not spec.get("egress"):
            return True
    return False


def default_deny_field(netpols: dict) -> dict[str, object] | None:
    """The ``kubernetes.network.no_default_deny`` field dict from a NetworkPolicy list, or ``None`` to
    abstain."""
    present = parse_default_deny_present(netpols)
    return None if present is None else {"default_deny_network_policy_present": present}


def parse_pod_security_enforced(namespaces: dict) -> bool | None:
    """Whether Pod Security admission is enforced across the cluster: every USER namespace carries a
    ``pod-security.kubernetes.io/enforce`` label of baseline or restricted. ``None`` to abstain when
    the input is not a namespace list or there are no user namespaces. A single user namespace without
    an enforcing level (absent, or ``privileged``) makes the posture not-enforced (a finding), because
    an unconstrained namespace is where an attacker lands; the Kubernetes-owned namespaces are
    excluded."""
    items = namespaces.get("items")
    if not isinstance(items, list):
        return None
    user_namespaces = [
        ns
        for ns in items
        if isinstance(ns, dict)
        and (ns.get("metadata") or {}).get("name") not in _SYSTEM_NAMESPACES
    ]
    if not user_namespaces:
        return None
    for namespace in user_namespaces:
        labels = (namespace.get("metadata") or {}).get("labels") or {}
        if labels.get(_PSA_ENFORCE_LABEL) not in _PSA_ENFORCING_LEVELS:
            return False
    return True


def pod_security_field(namespaces: dict) -> dict[str, object] | None:
    """The ``kubernetes.admission.pod_security_disabled`` field dict from a namespace list, or ``None``
    to abstain."""
    enforced = parse_pod_security_enforced(namespaces)
    return None if enforced is None else {"pod_security_admission_enforced": enforced}


async def _fetch_list(api: KubeApi, path: str, max_items: int) -> dict:
    """Page through a read-only LIST GET and return one ``{"items": [...]}`` document, bounded by
    ``max_items`` (build-for-scale). A LIST GET only, no watch, no write. Raises on connect/auth/HTTP
    error, which the caller records as honest UNAVAILABLE."""
    items: list[dict] = []
    continue_token = ""
    async with api.client() as client:
        while len(items) < max_items:
            params: dict[str, object] = {"limit": _PAGE_LIMIT}
            if continue_token:
                params["continue"] = continue_token
            response = await client.get(path, params=params)
            response.raise_for_status()
            body = response.json()
            page = body.get("items")
            if isinstance(page, list):
                items.extend(page)
            continue_token = (body.get("metadata") or {}).get("continue") or ""
            if not continue_token:
                break
    return {"items": items[:max_items]}


async def fetch_pods(api: KubeApi) -> dict:
    """The cluster's pods, paged read-only (bounded by ``_MAX_PODS``)."""
    return await _fetch_list(api, "/api/v1/pods", _MAX_PODS)


async def fetch_networkpolicies(api: KubeApi) -> dict:
    """The cluster's NetworkPolicies across all namespaces, paged read-only (bounded)."""
    return await _fetch_list(api, "/apis/networking.k8s.io/v1/networkpolicies", _MAX_PODS)


async def fetch_namespaces(api: KubeApi) -> dict:
    """The cluster's namespaces (metadata + labels), paged read-only (bounded)."""
    return await _fetch_list(api, "/api/v1/namespaces", _MAX_PODS)


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


def anonymous_auth_field(anonymous_enabled: object) -> dict[str, object] | None:
    """The ``kubernetes.api.anonymous`` field dict from the anonymous-auth probe result, or ``None``
    to abstain when the probe did not return a boolean."""
    if not isinstance(anonymous_enabled, bool):
        return None
    return {"anonymous_auth_enabled": anonymous_enabled}


async def fetch_anonymous_auth(target: str, *, timeout: float, verify: str | bool = False) -> bool:
    """Whether the API server accepts the ANONYMOUS identity, probed WITHOUT a token: a GET to the
    API root with no Authorization header. ``401 Unauthorized`` means anonymous is rejected
    (disabled); any other status (``200``/``403``) means the request was processed as
    ``system:anonymous`` (enabled). ``verify`` is False because the API serves its own CA-signed cert,
    exactly as the token path; the probe sends no credential, so there is nothing to protect on the
    wire. Raises on connect failure, which the caller records as honest UNAVAILABLE."""
    url = f"https://{target}:{_API_PORT}/api"
    verify_arg: ssl.SSLContext | str | bool = verify
    if verify is False:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        verify_arg = ctx
    async with httpx.AsyncClient(verify=verify_arg, timeout=timeout) as client:
        response = await client.get(url, headers={"Accept": "application/json"})
    return response.status_code != 401


def kubelet_anonymous_field(anonymous_enabled: object) -> dict[str, object] | None:
    """The ``kubernetes.kubelet.unauthenticated`` field dict from the kubelet anonymous-auth probe, or
    ``None`` to abstain when the probe did not return a boolean."""
    if not isinstance(anonymous_enabled, bool):
        return None
    return {"kubelet_anonymous_auth_enabled": anonymous_enabled}


async def fetch_kubelet_anonymous(target: str, *, timeout: float) -> bool:
    """Whether the kubelet accepts the ANONYMOUS identity, probed WITHOUT a token: a GET to the
    kubelet's ``/pods`` with no Authorization header. ``401 Unauthorized`` means anonymous is rejected
    (``--anonymous-auth=false``, the hardened default); any other status means the kubelet served an
    unauthenticated caller (enabled, a node-takeover surface). TLS without verification (the kubelet
    serves its own cert); the probe sends no credential. Raises on connect failure (UNAVAILABLE)."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    url = f"https://{target}:{_KUBELET_PORT}/pods"
    async with httpx.AsyncClient(verify=ctx, timeout=timeout) as client:
        response = await client.get(url)
    return response.status_code != 401


# The built-in ClusterRole whose binding to a named principal is a cluster-takeover grant. The
# cluster's own `cluster-admin -> system:masters` Group binding is NOT a named principal and is
# excluded by `_member_identity` (Group subjects return None), so a stock cluster reports an empty set.
_CLUSTER_ADMIN_ROLE = "cluster-admin"


def _member_identity(subject: object) -> str | None:
    """A stable identifier for a named User/ServiceAccount subject, or ``None`` for a Group (including
    the built-in ``system:masters``) or an unparseable subject. The format is what an operator approves
    in the baseline: ``user:<name>`` or ``serviceaccount:<namespace>:<name>``."""
    if not isinstance(subject, dict):
        return None
    name = subject.get("name")
    if not isinstance(name, str) or not name:
        return None
    kind = subject.get("kind")
    if kind == "User":
        return f"user:{name}"
    if kind == "ServiceAccount":
        namespace = subject.get("namespace")
        ns = namespace if isinstance(namespace, str) and namespace else "default"
        return f"serviceaccount:{ns}:{name}"
    return None


def parse_cluster_admin_members(clusterrolebindings: dict) -> list[str] | None:
    """The named User/ServiceAccount principals bound to the built-in ``cluster-admin`` ClusterRole, as
    a sorted, de-duplicated list of stable identifiers, or ``None`` to abstain when the input is not a
    binding list. This is the RAW OBSERVED SET: the agent does NOT judge which are "unapproved" (it has
    no baseline); the control plane diffs this against the tenant's approved baseline. Group subjects
    (the cluster's own ``cluster-admin -> system:masters`` binding among them) are excluded, so a stock
    cluster reports ``[]`` rather than a false member."""
    items = clusterrolebindings.get("items")
    if not isinstance(items, list):
        return None
    members: set[str] = set()
    for binding in items:
        if not isinstance(binding, dict):
            continue
        role_ref = binding.get("roleRef") or {}
        if role_ref.get("kind") != "ClusterRole" or role_ref.get("name") != _CLUSTER_ADMIN_ROLE:
            continue
        subjects = binding.get("subjects")
        if not isinstance(subjects, list):
            continue
        for subject in subjects:
            identity = _member_identity(subject)
            if identity is not None:
                members.add(identity)
    return sorted(members)


def cluster_admin_members_field(clusterrolebindings: dict) -> dict[str, object] | None:
    """The observed-set field the agent sends for ``kubernetes.rbac.cluster_admin_bindings``: the raw
    named principals bound to cluster-admin, under the wire key the control plane's approved-policy
    normalizer reads (``observed_cluster_admin_members``). Abstains (``None``) when the input is not a
    binding list."""
    members = parse_cluster_admin_members(clusterrolebindings)
    return None if members is None else {"observed_cluster_admin_members": members}


async def fetch_clusterrolebindings(api: KubeApi) -> dict:
    """The cluster's ClusterRoleBindings, paged read-only (bounded)."""
    return await _fetch_list(
        api, "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings", _MAX_PODS
    )
