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
for img in api ui engine webhook bootstrap; do
  echo "  build ${img}"
  docker build -q -t "norviq/norviq-engine:${img}-latest" -f "${REPO_ROOT}/Dockerfile.${img}" "$REPO_ROOT" >/dev/null
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
# quota to a namespace that is not there.
for ns in "$NS" agents analytics; do
  kubectl create namespace "$ns" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
done

# values-light: api replicas 1. The chart defaults to 2, and verb promotion does not propagate across
# replicas, so a two-replica local cluster flaps in a way that looks like a product bug.
# IfNotPresent: values-dev sets Always, which defeats `kind load` entirely — the node pulls from the
# registry and never sees the image just loaded.
helm upgrade --install norviq "${REPO_ROOT}/helm/norviq" \
  -n "$NS" \
  -f "${REPO_ROOT}/helm/norviq/values-light.yaml" \
  --set images.api.pullPolicy=IfNotPresent \
  --set images.ui.pullPolicy=IfNotPresent \
  --set images.engine.pullPolicy=IfNotPresent \
  --set images.webhook.pullPolicy=IfNotPresent \
  --wait --timeout 10m
kubectl -n "$NS" get pods

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
