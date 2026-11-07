#!/usr/bin/env bash
# =============================================================================
# k8s auto-update e2e: the real ares-updater sidecar patching the real ares-agent
# Deployment on a kind cluster, using only its scoped RBAC, and k8s rolling it out.
#
#   build ares-agent and ares-updater at 2.4.0 and 2.5.0 -> load into kind
#   apply the Deployment (agent 2.4.0 + updater 2.4.0 sidecar + Role/RoleBinding + RWO PVC, Recreate)
#   write /data/update-target.json = 2.5.0 (stands in for the agent's heartbeat handoff)
#   the updater patches BOTH images in one patch -> k8s rolls the pod once -> agent and updater 2.5.0
#
# The agent-side heartbeat/handoff and the cosign path are covered by the docker e2e + unit tests;
# this isolates the k8s backend (RBAC-scoped patch + Recreate rollout), so the agent container is a
# bare `sleep` on the real image and signature verification is off (locally built, unsigned images).
#
# Needs Docker + kind. Usage:  bash scripts/e2e_autoupdate_k8s.sh
#   E2E_UPDATER_IMAGE=<ref>  use a prebuilt updater image instead of building Dockerfile.updater
# =============================================================================
set -uo pipefail

AGENT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
CLUSTER=ares-k8s-e2e
NS=ares-e2e
KCTL="kubectl --context kind-$CLUSTER"

fail() { echo "K8S E2E FAILED: $1" >&2; $KCTL -n "$NS" get pods -o wide 2>/dev/null; exit 1; }
cleanup() { kind delete cluster --name "$CLUSTER" >/dev/null 2>&1; git -C "$AGENT_DIR" checkout agent/__version__.py >/dev/null 2>&1; }
trap cleanup EXIT

command -v kind >/dev/null 2>&1 || { echo "kind is required (brew install kind)"; exit 1; }

echo "==> Build agent images at 2.4.0 and 2.5.0 (version injected into __version__.py)"
( cd "$AGENT_DIR" \
  && perl -pi -e 's/__version__ = ".*"/__version__ = "2.4.0"/' agent/__version__.py \
  && docker build -q -t ares-agent:2.4.0 . >/dev/null \
  && perl -pi -e 's/__version__ = ".*"/__version__ = "2.5.0"/' agent/__version__.py \
  && docker build -q -t ares-agent:2.5.0 . >/dev/null \
  && git checkout agent/__version__.py ) || fail "agent image build"

echo "==> Updater images at 2.4.0 and 2.5.0 (one build, two tags with distinct digests)"
BASE="${E2E_UPDATER_IMAGE:-}"
if [ -z "$BASE" ]; then
  ( cd "$AGENT_DIR" && docker build -q -f Dockerfile.updater -t ares-updater:e2e . >/dev/null ) || fail "updater image build"
  BASE=ares-updater:e2e
fi
for v in 2.4.0 2.5.0; do
  # each knows its own release, as Dockerfile.updater's RELEASE file gives it, or the 2.4.0 updater
  # would read itself as the repo's version and decline to "move back" to 2.5.0
  printf 'FROM %s\nLABEL e2e.version=%s\nRUN echo %s > /app/updater/RELEASE\n' "$BASE" "$v" "$v" |
    docker build -q -t "ares-updater:$v" - >/dev/null || fail "updater $v"
done

echo "==> Create kind cluster + load images (no registry needed)"
kind create cluster --name "$CLUSTER" >/dev/null 2>&1 || fail "kind create"
kind load docker-image ares-agent:2.4.0 ares-agent:2.5.0 ares-updater:2.4.0 ares-updater:2.5.0 \
  --name "$CLUSTER" >/dev/null 2>&1 || fail "kind load"

echo "==> Apply manifest (agent 2.4.0 + updater 2.4.0 sidecar + scoped RBAC + RWO PVC, Recreate)"
$KCTL create namespace "$NS" >/dev/null 2>&1
$KCTL -n "$NS" apply -f - >/dev/null <<'YAML' || fail "apply"
apiVersion: v1
kind: PersistentVolumeClaim
metadata: { name: ares-agent-data }
spec: { accessModes: ["ReadWriteOnce"], resources: { requests: { storage: 64Mi } } }
---
apiVersion: v1
kind: ServiceAccount
metadata: { name: ares-updater }
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: { name: ares-updater }
rules:
  - apiGroups: ["apps"]
    resources: ["deployments"]
    resourceNames: ["ares-agent"]
    verbs: ["get", "patch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: { name: ares-updater }
roleRef: { apiGroup: rbac.authorization.k8s.io, kind: Role, name: ares-updater }
subjects: [{ kind: ServiceAccount, name: ares-updater }]
---
apiVersion: apps/v1
kind: Deployment
metadata: { name: ares-agent }
spec:
  replicas: 1
  strategy: { type: Recreate }
  selector: { matchLabels: { app: ares-agent } }
  template:
    metadata: { labels: { app: ares-agent } }
    spec:
      serviceAccountName: ares-updater
      securityContext: { fsGroup: 10001 }
      containers:
        - name: ares-agent
          image: ares-agent:2.4.0
          imagePullPolicy: IfNotPresent
          command: ["sleep", "infinity"]
          volumeMounts: [{ name: data, mountPath: /data }]
        - name: ares-updater
          image: ares-updater:2.4.0
          imagePullPolicy: IfNotPresent
          env:
            - { name: ARES_UPDATE_CONTAINER, value: "ares-agent" }
            - { name: ARES_UPDATE_REQUIRE_SIGNATURE, value: "false" }
            - { name: ARES_UPDATE_POLL_SECONDS, value: "5" }
          volumeMounts: [{ name: data, mountPath: /data, readOnly: true }]
      volumes: [{ name: data, persistentVolumeClaim: { claimName: ares-agent-data } }]
YAML

echo "==> Wait for the initial pod (agent 2.4.0) to be Ready"
$KCTL -n "$NS" rollout status deploy/ares-agent --timeout=120s >/dev/null 2>&1 || fail "initial rollout"

echo "==> Write the update target (2.5.0) into the shared volume (stands in for the agent handoff)"
POD="$($KCTL -n "$NS" get pod -l app=ares-agent -o jsonpath='{.items[0].metadata.name}')"
$KCTL -n "$NS" exec "$POD" -c ares-agent -- sh -c 'printf "{\"version\": \"2.5.0\"}" > /data/update-target.json' || fail "write target"

echo "==> Wait for the updater to patch the Deployment -> agent AND updater :2.5.0, and k8s to roll it"
OK=""
for _ in $(seq 1 40); do
  img="$($KCTL -n "$NS" get deploy ares-agent -o jsonpath='{.spec.template.spec.containers[0].image}' 2>/dev/null)"
  upd="$($KCTL -n "$NS" get deploy ares-agent -o jsonpath='{.spec.template.spec.containers[1].image}' 2>/dev/null)"
  echo "    deployment agent image=$img updater image=$upd"
  [ "$img" = "ares-agent:2.5.0" ] && [ "$upd" = "ares-updater:2.5.0" ] && { OK=1; break; }
  sleep 3
done
[ -n "$OK" ] || { echo "--- updater logs ---"; $KCTL -n "$NS" logs -l app=ares-agent -c ares-updater --tail=30 2>/dev/null; fail "updater did not patch the deployment to 2.5.0 for both containers"; }

echo "==> Confirm the rolled pod is Running on 2.5.0"
$KCTL -n "$NS" rollout status deploy/ares-agent --timeout=120s >/dev/null 2>&1 || fail "post-swap rollout"
# one patch for both: the controller numbers the rollout once it has made the new ReplicaSet, so this
# is read after the rollout, and again after the new updater has polled a few times, to show it does
# not start a second one (one patch per container would be revision 3)
revision() { $KCTL -n "$NS" get deploy ares-agent -o jsonpath='{.metadata.annotations.deployment\.kubernetes\.io/revision}'; }
[ "$(revision)" = "2" ] || fail "expected one rollout (revision 2), got revision $(revision)"
sleep 15
[ "$(revision)" = "2" ] || fail "the new updater rolled the Deployment again (revision $(revision))"
RUNNING_IMG="$($KCTL -n "$NS" get pod -l app=ares-agent -o jsonpath='{.items[0].spec.containers[0].image}')"
RUNNING_UPD="$($KCTL -n "$NS" get pod -l app=ares-agent -o jsonpath='{.items[0].spec.containers[1].image}')"
PHASE="$($KCTL -n "$NS" get pod -l app=ares-agent -o jsonpath='{.items[0].status.phase}')"
[ "$RUNNING_UPD" = "ares-updater:2.5.0" ] || fail "the rolled pod runs updater $RUNNING_UPD"
UPD_READY="$($KCTL -n "$NS" get pod -l app=ares-agent -o jsonpath='{.items[0].status.containerStatuses[?(@.name=="ares-updater")].ready}')"
[ "$UPD_READY" = "true" ] || fail "the new updater container is not ready"
echo ""
echo "K8S E2E PASSED: updater patched ares-agent and itself via scoped RBAC in one rollout;"
echo "                the pod runs $RUNNING_IMG with $RUNNING_UPD (pod $PHASE)."
