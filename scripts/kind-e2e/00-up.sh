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
# EVERY cluster-touching command below goes through these. They are not a tidiness measure.
#
# This script issued `kubectl apply`, `kubectl create namespace` and `helm upgrade --install` with no
# --context at all, so a script whose entire purpose is a LOCAL kind cluster targeted whatever context
# happened to be current. Run with a remote context selected, it would have applied CRDs there, created
# seven namespaces there, and helm-installed values-light.yaml over that release — repointing it at
# `norviq/…` images that exist only on the kind node, with pullPolicy=IfNotPresent, i.e. an
# ImagePullBackOff on every component of a cluster it was never meant to touch.
#
# It nearly happened: this ran with the AKS context current and was stopped only because that cluster's
# DNS failed to resolve at that moment, so the first apply errored and `set -e` aborted. "A remote
# cluster was saved by a DNS outage" is not a safety property.
KCTX=(--context "kind-${CLUSTER}")
KUBECTL=(kubectl "${KCTX[@]}")
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
"${KUBECTL[@]}" cluster-info >/dev/null

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

# Record the exact image IDs just built. These are what the running pods must be proved to carry — see
# the verification stage. A tag proves nothing: `:api-latest` names whatever was loaded last.
API_IMAGE_ID="$(docker image inspect -f '{{.Id}}' norviq/norviq-engine:api-latest)"

# --- 4. install -----------------------------------------------------------------------------------
stage "Installing the chart"
"${KUBECTL[@]}" apply -f "${REPO_ROOT}/helm/norviq/crds/" >/dev/null
# EVERY namespace in `policyQuotaNamespaces` must exist BEFORE install, or the chart fails applying a
# quota to a namespace that is not there. The persona namespaces are created here too — a persona is a
# tenant, and creating its namespace after install would leave it outside the baseline cluster policy.
TENANT_NS=(default agents analytics persona-health persona-fintech persona-shop persona-legal)
for ns in "$NS" "${TENANT_NS[@]}"; do
  "${KUBECTL[@]}" create namespace "$ns" --dry-run=client -o yaml | "${KUBECTL[@]}" apply -f - >/dev/null
done
# `policyQuotaNamespaces` defaults to [] and the chart REFUSES to install with a baseline cluster
# policy and no tenant namespaces — deliberately, so nobody ships a cluster whose baseline covers
# nothing. It has to be passed explicitly; there is no sensible default it could pick for us.
QUOTA_NS="$(IFS=,; echo "${TENANT_NS[*]}")"

# values-light: api replicas 1. The chart defaults to 2, and verb promotion does not propagate across
# replicas, so a two-replica local cluster flaps in a way that looks like a product bug.
# IfNotPresent: values-dev sets Always, which defeats `kind load` entirely — the node pulls from the
# registry and never sees the image just loaded.
helm --kube-context "kind-${CLUSTER}" upgrade --install norviq "${REPO_ROOT}/helm/norviq" \
  -n "$NS" \
  -f "${REPO_ROOT}/helm/norviq/values-light.yaml" \
  --set images.registry="norviq/" \
  --set images.api.pullPolicy=IfNotPresent \
  --set images.ui.pullPolicy=IfNotPresent \
  --set images.engine.pullPolicy=IfNotPresent \
  --set images.webhook.pullPolicy=IfNotPresent \
  --set images.bootstrap.pullPolicy=IfNotPresent \
  --set "policyQuotaNamespaces={${QUOTA_NS}}" \
  --set webhook.injection.enabled=true \
  --set-string config.extraEnv.NRVQ_HTTP_RATE_LIMIT_DEFAULT_PER_WINDOW=5000 \
  --set-string "podAnnotations.nrvq-local-image-id=${API_IMAGE_ID}" \
  --wait --timeout 10m

# FORCE THE ROLL. Rebuilding under the SAME TAG leaves the Deployment's pod template byte-identical, so
# Kubernetes correctly concludes there is nothing to do and the pods keep running the old image — even
# though the node now holds a new one under that tag. The cluster then reports a successful upgrade
# while serving code from a previous build, which is indistinguishable from the change not working.
# Stamping the built image ID into a pod annotation makes the template change exactly when the image
# does, so the roll happens for real builds and is skipped for no-op re-runs.
"${KUBECTL[@]}" -n "$NS" rollout status deployment/norviq-api --timeout=5m
"${KUBECTL[@]}" -n "$NS" get pods

# NOTE on the rate-limit ceiling above. The browser suite drives ~190 specs through ONE admin
# identity, and the limiter keys on the JWT `sub` — so all 190 share a single bucket and the run sits
# at 300-480 requests per 60s window against a 300 default. The 429s then land on whichever spec
# happens to be running, which is why the failing SET moved between runs while the count stayed flat.
# No real operator generates that load; the ceiling is right for production and wrong for a test rig.
#
# Raised HERE, in the local harness, and nowhere else. The product default stays 300, and the defect
# this exposed — console READS being charged the suite runner's tight budget — is fixed properly in
# `norviq/api/rate_limit.py` and pinned by a unit test, not papered over by this number.

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
  img="$("${KUBECTL[@]}" -n "$NS" get deploy "$dep" -o jsonpath='{.spec.template.spec.containers[0].image}')"
  case "$img" in
    norviq/norviq-engine:*) echo "  ok  ${dep} -> ${img}" ;;
    *) fail "${dep} runs ${img}, not the image built from this working tree. A published image with the
    same tag was already on the node and IfNotPresent preferred it." ;;
  esac
done
# Did the pods actually ROLL onto this build? Rebuilding under the same `:api-latest` tag leaves the
# Deployment's pod template identical, so Kubernetes has nothing to reconcile and the old pods stay —
# the cluster serves a previous build while helm reports success. The route check below cannot catch
# that, because the route it looks for existed in the older build too.
#
# The comparison is against the POD ANNOTATION, not the container's imageID. `kind load` re-imports the
# image into the node's containerd under a fresh digest (`import-<date>@sha256:…`), so a node-side image
# ID never equals the local docker one and asserting on it can only ever fail. The annotation is
# stamped from the build, so a pod that predates this build carries the PREVIOUS id — which is exactly
# the question being asked.
# `.items[0]` is NOT safe here. The just-replaced pod is still terminating — for at least
# gracefulShutdown.preStopSleepSeconds — and it sorts first as often as not, so the check would read
# the annotation of the pod the roll just replaced and declare the roll never happened. Pick a pod that
# is Running and NOT being deleted. (chaos.py hit this same trap from the other direction: it killed a
# sidecar in a pod that was already going away.)
live_api_pod() {
  "${KUBECTL[@]}" -n "$NS" get pods -l app.kubernetes.io/component=api \
    -o jsonpath='{range .items[*]}{.metadata.name}|{.metadata.deletionTimestamp}|{.status.phase}{"\n"}{end}' \
    | awk -F'|' '$2 == "" && $3 == "Running" { print $1; exit }'
}
# EVERY first-party component, not just the api. The first version of this guard checked the api pod
# alone, and a UI-only change then sailed through it: the new bundle was built, loaded into the node,
# and the pod serving the console kept running the previous one. The console is the component a human
# actually looks at, so "the cluster runs this build" has to mean all of them.
for comp in api ui engine webhook; do
  live_pod="$("${KUBECTL[@]}" -n "$NS" get pods -l "app.kubernetes.io/component=${comp}" \
    -o jsonpath='{range .items[*]}{.metadata.name}|{.metadata.deletionTimestamp}|{.status.phase}{"\n"}{end}' \
    | awk -F'|' '$2 == "" && $3 == "Running" { print $1; exit }')"
  [ -n "$live_pod" ] || fail "no Running, non-terminating ${comp} pod after the rollout"
  running_id="$("${KUBECTL[@]}" -n "$NS" get pod "$live_pod" -o jsonpath='{.metadata.annotations.nrvq-local-image-id}')"
  if [ "$running_id" = "$API_IMAGE_ID" ]; then
    echo "  ok  ${comp} pod was rolled onto this build (${API_IMAGE_ID:7:12})"
  else
    fail "the ${comp} pod was built from ${running_id:-<no annotation>}, but this run built ${API_IMAGE_ID}.
    The node has the new images under the same tags and this pod was never rolled onto them."
  fi
  [ "$comp" = "api" ] && api_live="$live_pod"
done

# The image ID only proves what was scheduled. This proves what the process actually serves: a route
# that exists on this branch and does not exist in the published image.
routes="$("${KUBECTL[@]}" -n "$NS" exec "$api_live" -c api -- \
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
# SUPERVISED, not a bare `&`. One kubectl port-forward does not survive a long run: it drops on a pod
# restart, on an idle timeout, and under sustained load. Unsupervised, the browser suite then fails
# every remaining spec with net::ERR_CONNECTION_RESET — which reads exactly like a broken product
# when the console is fine and only the tunnel to it is gone.
#
# Sharding made this unmissable. The two shards that finished in ~2 minutes passed 46 of 47; the two
# that ran 26 and 45 minutes returned 20 and 39 failures. Duration correlating with failure is the
# signature of an environmental fault, not a real one.
#
# The loop restarts the forward whenever kubectl exits and logs each restart, so a flapping tunnel is
# visible in the log rather than indistinguishable from product breakage.
(
  while true; do
    "${KUBECTL[@]}" -n "$NS" port-forward "svc/norviq-ui" "${UI_PORT}:80" >>/tmp/nrvq-kind-ui.log 2>&1 &
    _pf=$!
    # HEALTH-CHECKED, because waiting for kubectl to exit is not enough. A restarted Deployment
    # leaves the port-forward PROCESS alive while the tunnel to the old pod is gone, so every
    # request returns ECONNRESET and a supervisor watching only for process death never fires.
    # Measured: with an exit-only supervisor, 30 ECONNRESETs landed on ONE shard and zero on the
    # other three — the shard carrying the specs that apply policies and therefore roll the
    # Deployment (policy-editor-create-delete, policy-catalog-lifecycle, packs-governance-batch1,
    # posture-apply-ux, intent-allowlist-effect). Not random flakiness; a specific, reproducible
    # consequence of the thing under test.
    while kill -0 "$_pf" 2>/dev/null; do
      sleep 5
      curl -sf -o /dev/null --max-time 4 "http://localhost:${UI_PORT}/" && continue
      echo "console unreachable at $(date -u +%H:%M:%S) — cycling the forward" >>/tmp/nrvq-kind-ui.log
      kill "$_pf" 2>/dev/null || true
      break
    done
    wait "$_pf" 2>/dev/null || true
    echo "port-forward down, re-establishing $(date -u +%H:%M:%S)" >>/tmp/nrvq-kind-ui.log
    sleep 1
  done
) &
echo $! > /tmp/nrvq-kind-ui-supervisor.pid
# Poll, never sleep-once: a forward that is not up yet is indistinguishable from a broken one.
for _ in $(seq 1 40); do curl -sf -o /dev/null "http://localhost:${UI_PORT}/" && break; sleep 0.5; done
curl -sf -o /dev/null "http://localhost:${UI_PORT}/" || fail "console never came up on ${UI_PORT} — see /tmp/nrvq-kind-ui.log"

# Reuse `$api_live` from the verification stage — a pod already proved Running and NOT terminating.
# This line used to be `get pods -o name | grep api | head -1`, which is the same alphabetical-pod trap
# this script warns about at the `.items[0]` note above: it can hand back a terminating or Init pod, and
# `exec` into one fails with an error that reads like a broken token minter rather than a bad choice of
# pod. (login-gate.sh had the identical bug and it cost a 34-minute browser run.)
[ -n "${api_live:-}" ] || fail "no live api pod recorded by the verification stage"
"${KUBECTL[@]}" -n "$NS" exec "$api_live" -c api -- \
  python -m norviq.api.token_mint --ttl 7200 | tail -1 > "$TOKEN_FILE"
[ -s "$TOKEN_FILE" ] || fail "failed to mint an admin token"

cat <<EOF

  console   http://localhost:${UI_PORT}
  token     ${TOKEN_FILE}
  next      make seed && make test-all

  The port-forward DIES on every deployment restart. Re-establish it with:
    kubectl -n ${NS} port-forward svc/norviq-ui ${UI_PORT}:80 &
EOF
