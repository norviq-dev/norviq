#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Defect-hunt campaign environment (LOCAL kind only; AKS untouched). Staggered phases to fit ~11.67 GiB:
#   PHASE=A  single rich cluster (nv-a)            — enforcement/trust/API/DB/graph/audit/console/api-keys
#   PHASE=B  identity cluster (reuses scripts/identity-local) — OIDC + SPIRE
#   PHASE=C  fleet hub + spokes (reuses scripts/fleet-local)  — signed policy-push / residency / cross-cluster
# Build images FROM THE WORKING TREE so the uncommitted F046 endpoints exist in the pods.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
NS="${NS:-norviq}"
SECRET="${SECRET:-campaign-secret-7f3c91aa2b}"   # rotated, non-default; shared so HS256 tokens validate
PHASE="${PHASE:-A}"
PLAT="linux/$(uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/')"

log() { echo -e "\n\033[1;36m== $* ==\033[0m"; }
kb() { kubectl --context "kind-$1" "${@:2}"; }
hb() { helm --kube-context "kind-$1" "${@:2}"; }

build_images() {
  log "build api + ui images from the WORKING TREE (captures uncommitted F046)"
  docker build --platform "$PLAT" -t sanman97/norviq-engine:api-campaign -f "$REPO_ROOT/Dockerfile.api" "$REPO_ROOT"
  docker build --platform "$PLAT" -t sanman97/norviq-engine:ui-campaign  -f "$REPO_ROOT/Dockerfile.ui"  "$REPO_ROOT"
}

phase_a() {
  local c=nv-a
  kind get clusters | grep -qx "$c" || { log "kind create $c"; kind create cluster --name "$c"; }
  kb "$c" create namespace "$NS" --dry-run=client -o yaml | kb "$c" apply -f -
  kb "$c" label ns "$NS" app.kubernetes.io/managed-by=Helm --overwrite >/dev/null
  kb "$c" annotate ns "$NS" meta.helm.sh/release-name=norviq meta.helm.sh/release-namespace="$NS" --overwrite >/dev/null
  log "kind load images into $c"
  kind load docker-image --name "$c" sanman97/norviq-engine:api-campaign sanman97/norviq-engine:ui-campaign
  log "helm install norviq (right-sized Phase A) on $c"
  hb "$c" upgrade --install norviq "$REPO_ROOT/helm/norviq" -n "$NS" \
    -f "$HERE/values-campaign.yaml" \
    --set api.secretKey="$SECRET" --set imagePullSecrets=null \
    --set images.api.tag=api-campaign --set images.ui.tag=ui-campaign \
    --set images.api.pullPolicy=IfNotPresent --set images.ui.pullPolicy=IfNotPresent \
    --set images.engine.pullPolicy=IfNotPresent --set images.webhook.pullPolicy=IfNotPresent \
    --timeout 600s
  kb "$c" -n "$NS" rollout status statefulset/norviq-postgresql --timeout=300s
  kb "$c" -n "$NS" rollout status deploy/norviq-api --timeout=300s
  log "Phase A UP on $c. api.secretKey=$SECRET"
}

case "$PHASE" in
  A) build_images; phase_a ;;
  images) build_images ;;
  B) log "Phase B: run scripts/identity-local/00-up.sh (Keycloak+SPIRE) — staggered separately"; bash "$REPO_ROOT/scripts/identity-local/00-up.sh" ;;
  C) log "Phase C: run scripts/fleet-local/00-up.sh (hub+spokes) — staggered separately"; bash "$REPO_ROOT/scripts/fleet-local/00-up.sh" ;;
  *) echo "unknown PHASE=$PHASE (use A|B|C|images)"; exit 1 ;;
esac
