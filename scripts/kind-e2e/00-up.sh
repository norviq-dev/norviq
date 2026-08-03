#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
#
# Bring up a local kind cluster running the console, from a clean checkout.
#
# Every non-obvious line here is a trap that cost real time, and each is commented where it sits
# rather than in a list nobody reads at the point of failure.
#
#   make kind-up && make seed && make test-all
#
# Idempotent: re-running against an existing cluster reuses it and re-installs the chart.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CLUSTER="${NRVQ_KIND_CLUSTER:-norviq-local}"
NS="${NRVQ_NAMESPACE:-norviq}"
UI_PORT="${NRVQ_UI_PORT:-3400}"
TOKEN_FILE="${NRVQ_TOKEN_FILE:-/tmp/nrvq-signin-token.txt}"

stage() { printf '\n\033[1;36m▶ %s\033[0m\n' "$*"; }
fail()  { printf '\033[1;31m✗ %s\033[0m\n' "$*" >&2; exit 1; }

# --- 1. preconditions -----------------------------------------------------------------------------
stage "Preconditions"
for bin in docker kind kubectl helm; do command -v "$bin" >/dev/null || fail "$bin not on PATH"; done
# opa is needed by the test layers, not by the cluster — checked here so the failure lands before a
# 10-minute install rather than after it.
command -v opa >/dev/null || fail "opa not on PATH — rego-backed tests would silently skip and print green"

# A multi-image build on a nearly-full disk does not fail cleanly: Docker starts reclaiming space and
# has already deleted the kind node container once in this project's history, which presents as a
# cluster that vanished mid-run.
avail_gb=$(df -g / | awk 'NR==2 {print $4}')
[ "${avail_gb:-99}" -lt 10 ] && fail "only ${avail_gb}GB free — build five images with <10GB and docker starts deleting things, including the kind node"
echo "  disk ${avail_gb}GB free · opa $(opa version | head -1)"

# --- 2. cluster -----------------------------------------------------------------------------------
stage "Cluster ${CLUSTER}"
if kind get clusters 2>/dev/null | grep -qx "$CLUSTER"; then
  echo "  reusing existing cluster"
  # A stopped node looks identical to a missing one to most commands; start it explicitly.
  docker start "${CLUSTER}-control-plane" >/dev/null 2>&1 || true
else
  kind create cluster --name "$CLUSTER" --wait 120s
fi
kubectl cluster-info --context "kind-${CLUSTER}" >/dev/null

# --- 3. images ------------------------------------------------------------------------------------
# FIVE, not four. `bootstrap` runs behind a Helm hook rather than as a Deployment, so a cluster
# missing it fails during install on the `norviq-internal-tls` hook — a failure that reads as a chart
# problem rather than a missing image.
#
# NEVER pass --platform. Pinning it produces `exec format error` on Apple Silicon, surfacing as a
# CrashLoopBackOff with no useful message.
stage "Building and loading five images"
# The webhook is the odd one out: it is a Go module rooted at `webhook/` with its own go.mod, so its
# Dockerfile lives INSIDE that directory and takes it as the build context. Four of the five follow the
# repo-root `Dockerfile.<name>` convention and the fifth silently does not — this loop assumed the
# convention held and died on `open Dockerfile.webhook: no such file or directory`.
for img in api ui engine webhook bootstrap; do
  echo "  build ${img}"
  if [ "$img" = "webhook" ]; then
    docker build -q -t "norviq/norviq-engine:webhook-latest" "${REPO_ROOT}/webhook" >/dev/null
  else
    docker build -q -t "norviq/norviq-engine:${img}-latest" -f "${REPO_ROOT}/Dockerfile.${img}" "$REPO_ROOT" >/dev/null
  fi
done
kind load docker-image --name "$CLUSTER" \
  norviq/norviq-engine:api-latest \
  norviq/norviq-engine:ui-latest \
  norviq/norviq-engine:engine-latest \
  norviq/norviq-engine:webhook-latest \
  norviq/norviq-engine:bootstrap-latest

# --- 4. install -----------------------------------------------------------------------------------
stage "Installing the chart"
kubectl apply -f "${REPO_ROOT}/helm/norviq/crds/" >/dev/null
# EVERY namespace in `policyQuotaNamespaces` must exist BEFORE install, or the chart fails applying a
# quota to a namespace that is not there. The persona namespaces are created here too — a persona is a
# tenant, and creating its namespace after install would leave it outside the baseline cluster policy.
TENANT_NS=(default agents analytics persona-health persona-fintech persona-shop persona-legal)
for ns in "$NS" "${TENANT_NS[@]}"; do
  kubectl create namespace "$ns" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
done
# `policyQuotaNamespaces` defaults to [] and the chart REFUSES to install with a baseline cluster
# policy and no tenant namespaces — deliberately, so nobody ships a cluster whose baseline covers
# nothing. It has to be passed explicitly; there is no sensible default it could pick for us.
QUOTA_NS="$(IFS=,; echo "${TENANT_NS[*]}")"

# values-light: api replicas 1. The chart defaults to 2, and verb promotion does not propagate across
# replicas, so a two-replica local cluster flaps in a way that looks like a product bug.
# IfNotPresent: values-dev sets Always, which defeats `kind load` entirely — the node pulls from the
# registry and never sees the image just loaded.
helm upgrade --install norviq "${REPO_ROOT}/helm/norviq" \
  -n "$NS" \
  -f "${REPO_ROOT}/helm/norviq/values-light.yaml" \
  --set images.registry="norviq/" \
  --set images.api.pullPolicy=IfNotPresent \
  --set images.ui.pullPolicy=IfNotPresent \
  --set images.engine.pullPolicy=IfNotPresent \
  --set images.webhook.pullPolicy=IfNotPresent \
  --set images.bootstrap.pullPolicy=IfNotPresent \
  --set "policyQuotaNamespaces={${QUOTA_NS}}" \
  --wait --timeout 10m
kubectl -n "$NS" get pods

# --- 4b. PROVE THE CLUSTER IS RUNNING *THIS* CODE --------------------------------------------------
# This cost a full run. The chart's `images.registry` defaults to `ghcr.io/norviq-dev/`, the build
# above tags `norviq/…`, and `pullPolicy=IfNotPresent` found the PUBLISHED image already on the node —
# so five freshly-built images were loaded, ignored, and the whole cluster silently tested `main`.
# Nothing failed. The pods were Running, the console served, and every route added on this branch
# 404'd as if the feature had never been written.
#
# Two assertions, because either alone can be fooled:
stage "Verifying the cluster runs the locally-built images"
for dep in norviq-api norviq-ui norviq-engine norviq-webhook; do
  img="$(kubectl -n "$NS" get deploy "$dep" -o jsonpath='{.spec.template.spec.containers[0].image}')"
  case "$img" in
    norviq/norviq-engine:*) echo "  ok  ${dep} -> ${img}" ;;
    *) fail "${dep} runs ${img}, not the image built from this working tree. A published image with the
    same tag was already on the node and IfNotPresent preferred it." ;;
  esac
done
# The image name only proves what was scheduled. This proves what the process actually serves: a route
# that exists on this branch and does not exist in the published image.
api_pod0="$(kubectl -n "$NS" get pods -l app.kubernetes.io/component=api -o jsonpath='{.items[0].metadata.name}')"
routes="$(kubectl -n "$NS" exec "$api_pod0" -c api -- \
  python -c "import json,urllib.request;print(' '.join(json.load(urllib.request.urlopen('http://127.0.0.1:8080/openapi.json',timeout=20))['paths']))" 2>/dev/null || true)"
case "$routes" in
  *"/api/v1/mcp/pins"*) echo "  ok  API serves /api/v1/mcp/pins — this is branch code" ;;
  *) fail "the running API does not serve /api/v1/mcp/pins. The image is scheduled correctly but the
    process is serving different code — rebuild, or check Dockerfile.api's COPY layer." ;;
esac

# --- 5. access ------------------------------------------------------------------------------------
stage "Console access"
pkill -f "port-forward.*norviq-ui" 2>/dev/null || true
sleep 1
kubectl -n "$NS" port-forward "svc/norviq-ui" "${UI_PORT}:80" >/tmp/nrvq-kind-ui.log 2>&1 &
# Poll, never sleep-once: a forward that is not up yet is indistinguishable from a broken one.
for _ in $(seq 1 40); do curl -sf -o /dev/null "http://localhost:${UI_PORT}/" && break; sleep 0.5; done
curl -sf -o /dev/null "http://localhost:${UI_PORT}/" || fail "console never came up on ${UI_PORT} — see /tmp/nrvq-kind-ui.log"

api_pod="$(kubectl -n "$NS" get pods -o name | grep api | head -1)"
kubectl -n "$NS" exec "${api_pod#pod/}" -c api -- \
  python -m norviq.api.token_mint --ttl 7200 | tail -1 > "$TOKEN_FILE"
[ -s "$TOKEN_FILE" ] || fail "failed to mint an admin token"

cat <<EOF

  console   http://localhost:${UI_PORT}
  token     ${TOKEN_FILE}
  next      make seed && make test-all

  The port-forward DIES on every deployment restart. Re-establish it with:
    kubectl -n ${NS} port-forward svc/norviq-ui ${UI_PORT}:80 &
EOF
