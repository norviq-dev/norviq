#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Customer-eval LOCAL bootstrap (Option A = build YOUR local code into images).
# kind = real upstream Kubernetes running as Docker containers on this machine.
#
# Default: builds api+ui images from the working tree, kind-loads them, runs the eval against
# THAT code (no Docker Hub round-trip). The engine pod is disabled (API evaluates in-process).
#
# Usage:
#   bash scripts/eval/00-bootstrap-local.sh
# Options (env):
#   EVAL_PULL=1        skip building; pull published sanman97/norviq-engine:*-latest instead
#                      (only meaningful AFTER you've pushed the fixed images to Docker Hub)
#   SKIP_CLUSTER_B=1   deploy only lumina-a (skips the multi-cluster test; lightest footprint)
#
# Mac mini footprint (defaults): cluster A = pg+redis+api+ui, cluster B = pg+redis+api.
# Give Docker Desktop >= 6 GB. If RAM is tight, use SKIP_CLUSTER_B=1.
#
# NOTE: not executed from the assistant sandbox (no Docker there). The first run on your Mac IS
# the R1 onboarding-effort evidence — record whatever breaks.

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"
mkdir -p "$STATE_DIR/findings"

BUILD=1; [ "${EVAL_PULL:-0}" = "1" ] && BUILD=0
PF_PID=""
cleanup() { [ -n "$PF_PID" ] && kill "$PF_PID" >/dev/null 2>&1 || true; }
trap cleanup EXIT

build_images_once() {
  log "building api + ui + webhook images from local working tree (Option A)..."
  docker build -t sanman97/norviq-engine:api-latest     -f "$REPO_ROOT/Dockerfile.api" "$REPO_ROOT"
  docker build -t sanman97/norviq-engine:ui-latest      -f "$REPO_ROOT/Dockerfile.ui"  "$REPO_ROOT"
  docker build -t sanman97/norviq-engine:webhook-latest -f "$REPO_ROOT/webhook/Dockerfile" "$REPO_ROOT/webhook"
  log "images built (engine skipped — replicas 0; opa sidecar pulls openpolicyagent/opa)."
}

load_and_patch() {
  local cluster="$1" ctx="kind-$1"
  kind load docker-image \
    sanman97/norviq-engine:api-latest sanman97/norviq-engine:ui-latest sanman97/norviq-engine:webhook-latest \
    --name "$cluster"
  for d in norviq-api norviq-ui norviq-webhook; do
    kubectl --context "$ctx" -n "$NS" patch deploy "$d" --type=json \
      -p '[{"op":"replace","path":"/spec/template/spec/containers/0/imagePullPolicy","value":"IfNotPresent"}]' \
      >/dev/null 2>&1 || warn "could not patch pullPolicy on $d"
  done
}

deploy_cluster() {
  local cluster="$1"; shift            # remaining args = extra helm --set flags
  local ctx="kind-$cluster"
  if kind get clusters 2>/dev/null | grep -qx "$cluster"; then
    log "[$cluster] kind cluster exists, reusing"
  else
    log "[$cluster] creating kind cluster..."
    kind create cluster --name "$cluster"
  fi

  log "[$cluster] helm upgrade --install norviq $*"
  helm --kube-context "$ctx" upgrade --install norviq "$REPO_ROOT/helm/norviq" \
    -n "$NS" --create-namespace -f "$EVAL_DIR/values-local.yaml" \
    --set api.secretKey="$EVAL_SECRET" "$@" --timeout 600s || \
    warn "[$cluster] helm reported an error; continuing to rollout wait for a clearer signal"

  # DB_SSL_MODE: the configmap alias now works post-fix, but keep this as belt-and-suspenders.
  # NRVQ_REQUIRE_STRONG_SECRET=true turns ON the new guard; we deploy a strong rotated secret so the
  # API still starts — demonstrating the product now refuses the default secret in prod.
  kubectl --context "$ctx" -n "$NS" set env deploy/norviq-api \
    DB_SSL_MODE=disable NRVQ_REQUIRE_STRONG_SECRET=true >/dev/null 2>&1 || \
    warn "[$cluster] could not set api env"

  [ "$BUILD" = "1" ] && load_and_patch "$cluster"
  wait_workloads "$ctx"
  log "[$cluster] core is up."
}

# ---- 1. prereqs + (build once) + clusters ------------------------------------
require_prereqs
[ "$BUILD" = "1" ] && need kind && build_images_once
deploy_cluster "$CLUSTER_A"
# cluster B is the multi-cluster test target: api only (no ui/engine) to save RAM.
[ "${SKIP_CLUSTER_B:-0}" = "1" ] || deploy_cluster "$CLUSTER_B" --set ui.replicas=0 --set webhook.enabled=false

# ---- 2. port-forward cluster A api for seed + traffic -------------------------
log "port-forwarding $CLUSTER_A api -> 127.0.0.1:$PORT_API_A"
PF_PID="$(start_pf "$CTX_A" norviq-api "$PORT_API_A" 8080)"
for i in $(seq 1 30); do api_up "$PORT_API_A" && break; sleep 2; done
api_up "$PORT_API_A" || die "API on $CLUSTER_A never became healthy on :$PORT_API_A"

API_A="http://127.0.0.1:$PORT_API_A"
ADMIN_TOKEN="$(mint_jwt admin)"
VIEWER_TOKEN="$(mint_jwt viewer)"

# ---- 3. seed a real policy (comprehensive.rego @ priority 700) ----------------
log "seeding policy default:customer-support from comprehensive.rego..."
python3 - "$REPO_ROOT/comprehensive.rego" > /tmp/nrvq-policy.json <<'PY'
import sys, json
rego = open(sys.argv[1]).read()
print(json.dumps({"namespace":"default","agent_class":"customer-support",
                  "rego_source":rego,"enforcement_mode":"block","priority":700,
                  "saved_by":"eval-bootstrap"}))
PY
seed_http=$(curl -sS -o /tmp/nrvq-seed.out -w '%{http_code}' -X POST "$API_A/api/v1/policies" \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  --data @/tmp/nrvq-policy.json) || true
case "$seed_http" in
  200|201) log "policy seeded (HTTP $seed_http)";;
  *) warn "policy seed returned HTTP $seed_http: $(cat /tmp/nrvq-seed.out) — RECORD THIS as a finding";;
esac

# ---- 4. write state file the scouts read -------------------------------------
python3 - <<PY
import json
b = None if "${SKIP_CLUSTER_B:-0}" == "1" else "$CLUSTER_B"
json.dump({
  "clusters": {"a": "$CLUSTER_A", "b": b},
  "contexts": {"a": "$CTX_A", "b": (None if b is None else "$CTX_B")},
  "namespace": "$NS",
  "urls": {"api_a": "$API_A", "ui_a": "http://127.0.0.1:$PORT_UI_A",
           "api_b_hint": (None if b is None else "kubectl --context $CTX_B -n $NS port-forward svc/norviq-api $PORT_API_B:8080")},
  "tokens": {"admin": "$ADMIN_TOKEN", "viewer": "$VIEWER_TOKEN"},
  "secret_used": "$EVAL_SECRET",
  "note": "HS256 tokens signed with the eval secret. UI scout: set localStorage nrvq_token=<admin>, reload."
}, open("$ENV_FILE","w"), indent=2)
print("wrote $ENV_FILE")
PY

# ---- 5. generate minimal-but-representative data -----------------------------
log "generating data (multi-agent, trust spread, attack-paths) against $CLUSTER_A..."
API_BASE="$API_A" TOKEN="$ADMIN_TOKEN" bash "$EVAL_DIR/10-generate-traffic.sh" || \
  warn "data generation hit an error (record it)"

log "DONE. State: $ENV_FILE"
log "Next: 'bash scripts/eval/20-portforward.sh' (leave running) so scouts can reach UI+API."
log "Teardown: 'bash scripts/eval/99-teardown-local.sh'"
