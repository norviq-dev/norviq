#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Bring up the fleet local validation: TWO kind clusters (fleet-a = hub+spoke, fleet-b = spoke).
# fleet-b's relay reaches fleet-a's fleet-api over the shared `kind` docker network (NodePort 31090).
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
NS="${NS:-norviq}"
SECRET="${SECRET:-fleet-local-secret-4d2a}"   # SHARED across clusters so relay HS256 tokens validate at the hub
STAGE="${STAGE:-all}"

log() { echo -e "\n\033[1;36m== $* ==\033[0m"; }
hb() { helm --kube-context "kind-$1" "${@:2}"; }
kb() { kubectl --context "kind-$1" "${@:2}"; }

ensure_clusters() {
  for c in fleet-a fleet-b; do
    kind get clusters | grep -qx "$c" || { log "kind create cluster $c"; kind create cluster --name "$c"; }
    # The chart templates the Namespace, but helm needs it to exist first to store the release secret.
    # Pre-create it WITH helm ownership metadata so the chart's namespace.yaml adopts it (no conflict).
    kubectl --context "kind-$c" create namespace "$NS" --dry-run=client -o yaml | kubectl --context "kind-$c" apply -f -
    kubectl --context "kind-$c" label ns "$NS" app.kubernetes.io/managed-by=Helm --overwrite >/dev/null
    kubectl --context "kind-$c" annotate ns "$NS" meta.helm.sh/release-name=norviq meta.helm.sh/release-namespace="$NS" --overwrite >/dev/null
  done
}

build_load() {
  log "build + kind load (api, ui) into both clusters"
  local plat="linux/$(uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/')"
  docker build --platform "$plat" -t norviq/norviq-engine:api-latest -f "$REPO_ROOT/Dockerfile.api" "$REPO_ROOT"
  docker build --platform "$plat" -t norviq/norviq-engine:ui-latest  -f "$REPO_ROOT/Dockerfile.ui"  "$REPO_ROOT"
  for c in fleet-a fleet-b; do
    kind load docker-image --name "$c" norviq/norviq-engine:api-latest norviq/norviq-engine:ui-latest
  done
}

common_set() {
  echo "--set api.secretKey=$SECRET --set imagePullSecrets=null \
        --set images.api.pullPolicy=IfNotPresent --set images.ui.pullPolicy=IfNotPresent \
        --set images.engine.pullPolicy=IfNotPresent --set images.webhook.pullPolicy=IfNotPresent"
}

install_hub() {
  bash "$HERE/gen-keys.sh"
  local nodeip; nodeip="$(docker inspect fleet-a-control-plane -f '{{.NetworkSettings.Networks.kind.IPAddress}}')"
  log "fleet-a: install norviq HUB+spoke (fleet-api + fleet-postgresql + relay + signing key)"
  # fleet-a's own relay reaches the hub via the NodePort too (so the bound endpoint is reachable for drill-down).
  # shellcheck disable=SC2046
  hb fleet-a upgrade --install norviq "$REPO_ROOT/helm/norviq" -n "$NS" \
    -f "$HERE/values-fleet.yaml" $(common_set) \
    --set fleet.clusterId=fleet-a --set fleet.clusterName=fleet-a --set fleet.region=local \
    --set fleet.apiUrl=http://norviq-fleet-api.norviq.svc:8080 \
    --set fleet.clusterEndpoint=http://norviq-api.norviq.svc:8080 \
    --set fleet.labels.env=prod \
    --set-file fleet.hub.signingKey="$HERE/fleet-signing-priv.pem" \
    --set-file fleet.bundlePubkey="$HERE/fleet-signing-pub.pem" \
    --set fleet.hub.enabled=true --timeout 600s
  kb fleet-a -n "$NS" rollout status statefulset/fleet-postgresql --timeout=300s
  kb fleet-a -n "$NS" rollout status deploy/norviq-fleet-api --timeout=300s
  kb fleet-a -n "$NS" rollout status deploy/norviq-api --timeout=300s
}

install_spoke_b() {
  local nodeip; nodeip="$(docker inspect fleet-a-control-plane -f '{{.NetworkSettings.Networks.kind.IPAddress}}')"
  local bnodeip; bnodeip="$(docker inspect fleet-b-control-plane -f '{{.NetworkSettings.Networks.kind.IPAddress}}')"
  log "fleet-b: install norviq SPOKE -> hub at http://$nodeip:31090 (shared kind network), pubkey trust root"
  # fleet-b advertises env=staging (so an env=prod-selected policy targets only fleet-a) + residency on.
  # shellcheck disable=SC2046
  hb fleet-b upgrade --install norviq "$REPO_ROOT/helm/norviq" -n "$NS" \
    -f "$HERE/values-fleet.yaml" $(common_set) \
    --set fleet.clusterId=fleet-b --set fleet.clusterName=fleet-b --set fleet.region=local \
    --set fleet.apiUrl="http://$nodeip:31090" \
    --set fleet.labels.env=staging --set fleet.residency=true \
    --set-file fleet.bundlePubkey="$HERE/fleet-signing-pub.pem" \
    --set fleet.hub.enabled=false --timeout 600s
  kb fleet-b -n "$NS" rollout status deploy/norviq-api --timeout=300s
}

case "$STAGE" in
  clusters) ensure_clusters ;;
  images)   build_load ;;
  hub)      install_hub ;;
  spoke)    install_spoke_b ;;
  all)
    ensure_clusters; build_load; install_hub; install_spoke_b
    log "UP. fleet-a=hub+spoke, fleet-b=spoke. Next: ./10-verify.sh"
    ;;
  *) echo "unknown STAGE=$STAGE"; exit 1 ;;
esac
