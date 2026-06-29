#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Bring up the IDENTITY local e2e: kind + SPIRE + Keycloak + Norviq (OIDC on, workload-api SPIFFE).
# Idempotent-ish; safe to re-run. Stages can be run individually via: STAGE=spire ./00-up.sh
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
CLUSTER="${CLUSTER:-norviq-identity}"
CTX="kind-${CLUSTER}"
NS="${NS:-norviq}"
SECRET="${SECRET:-identity-local-secret-7c1f}"
STAGE="${STAGE:-all}"
K="kubectl --context $CTX"
H="helm --kube-context $CTX"

log() { echo -e "\n\033[1;36m== $* ==\033[0m"; }

ensure_cluster() {
  if ! kind get clusters | grep -qx "$CLUSTER"; then
    log "kind create cluster $CLUSTER"
    kind create cluster --config "$HERE/kind-config.yaml"
  fi
  $K create namespace "$NS" --dry-run=client -o yaml | $K apply -f -
}

install_spire() {
  log "SPIRE (spire-crds + spire umbrella, trust domain norviq)"
  helm repo add spiffe https://spiffe.github.io/helm-charts-hardened/ >/dev/null 2>&1 || true
  helm repo update >/dev/null
  $H upgrade --install spire-crds spiffe/spire-crds -n spire-system --create-namespace --wait
  $H upgrade --install spire spiffe/spire -n spire-system \
    -f "$HERE/spire-values.yaml" --wait --timeout 600s
  $K apply -f "$HERE/spire-clusterspiffeid.yaml"
  $K -n spire-system rollout status statefulset/spire-server --timeout=300s || true
}

fix_coredns() {
  log "CoreDNS rewrite: keycloak.localtest.me -> keycloak.$NS.svc (issuer-host match)"
  local cf; cf="$($K -n kube-system get configmap coredns -o jsonpath='{.data.Corefile}')"
  if echo "$cf" | grep -q "keycloak.localtest.me"; then echo "rewrite already present"; return; fi
  echo "$cf" | awk -v ns="$NS" '
    /\.:53 \{/ && !done { print; print "    rewrite name keycloak.localtest.me keycloak." ns ".svc.cluster.local"; done=1; next }
    { print }' > /tmp/Corefile.norviq
  $K -n kube-system create configmap coredns --from-file=Corefile=/tmp/Corefile.norviq --dry-run=client -o yaml | $K apply -f -
  $K -n kube-system rollout restart deploy/coredns
  $K -n kube-system rollout status deploy/coredns --timeout=120s
}

deploy_keycloak() {
  log "Keycloak (realm import: norviq)"
  $K -n "$NS" create configmap keycloak-realm --from-file=realm-norviq.json="$HERE/realm-norviq.json" \
    --dry-run=client -o yaml | $K apply -f -
  $K apply -f "$HERE/keycloak.yaml"
  $K -n "$NS" rollout status deploy/keycloak --timeout=300s
}

build_load_images() {
  log "build + kind load images (api, ui, webhook, engine)"
  local plat="linux/$(uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/; s/arm64/arm64/')"
  docker build --platform "$plat" -t sanman97/norviq-engine:api-latest     -f "$REPO_ROOT/Dockerfile.api"     "$REPO_ROOT"
  docker build --platform "$plat" -t sanman97/norviq-engine:ui-latest      -f "$REPO_ROOT/Dockerfile.ui"      "$REPO_ROOT"
  docker build --platform "$plat" -t sanman97/norviq-engine:engine-latest  -f "$REPO_ROOT/Dockerfile.engine"  "$REPO_ROOT"
  docker build --platform "$plat" -t sanman97/norviq-engine:webhook-latest -f "$REPO_ROOT/webhook/Dockerfile" "$REPO_ROOT/webhook"
  kind load docker-image --name "$CLUSTER" \
    sanman97/norviq-engine:api-latest sanman97/norviq-engine:ui-latest \
    sanman97/norviq-engine:engine-latest sanman97/norviq-engine:webhook-latest
}

install_norviq() {
  log "helm install norviq (OIDC on, workload-api, CSI, injector, controller client-creds)"
  $H upgrade --install norviq "$REPO_ROOT/helm/norviq" -n "$NS" --create-namespace \
    -f "$HERE/values-identity.yaml" \
    --set api.secretKey="$SECRET" \
    --set imagePullSecrets=null \
    --set images.api.pullPolicy=IfNotPresent \
    --set images.ui.pullPolicy=IfNotPresent \
    --set images.engine.pullPolicy=IfNotPresent \
    --set images.webhook.pullPolicy=IfNotPresent \
    --timeout 600s
  $K -n "$NS" rollout status statefulset/norviq-postgresql --timeout=300s
  $K -n "$NS" rollout status statefulset/norviq-redis --timeout=300s
  $K -n "$NS" rollout status deploy/norviq-api --timeout=300s
}

case "$STAGE" in
  cluster)  ensure_cluster ;;
  spire)    ensure_cluster; install_spire ;;
  keycloak) ensure_cluster; fix_coredns; deploy_keycloak ;;
  images)   build_load_images ;;
  norviq)   install_norviq ;;
  all)
    ensure_cluster
    install_spire
    fix_coredns
    deploy_keycloak
    build_load_images
    install_norviq
    log "UP. Next: ./10-verify.sh"
    ;;
  *) echo "unknown STAGE=$STAGE"; exit 1 ;;
esac
