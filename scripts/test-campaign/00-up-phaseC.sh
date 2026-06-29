#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Phase C — fleet: 1 hub (fleet-a, env=prod) + 2 spokes (fleet-b env=staging+residency, fleet-c env=dev).
# Right-sized (api.replicas=1) for ~11.67 GiB. Reuses scripts/fleet-local gen-keys + values-fleet.yaml.
# Working-tree image via api-latest/ui-latest (already tagged from the campaign build). Adaptive: set
# SPOKES="fleet-b" to fall back to 1 hub + 1 spoke if compute is tight.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
FL="$REPO_ROOT/scripts/fleet-local"
NS="${NS:-norviq}"; SECRET="${SECRET:-fleet-local-secret-4d2a}"
SPOKES="${SPOKES:-fleet-b fleet-c}"
log(){ echo -e "\n\033[1;36m== $* ==\033[0m"; }
kb(){ kubectl --context "kind-$1" "${@:2}"; }
hb(){ helm --kube-context "kind-$1" "${@:2}"; }

own_ns(){ kb "$1" create namespace "$NS" --dry-run=client -o yaml | kb "$1" apply -f -; kb "$1" label ns "$NS" app.kubernetes.io/managed-by=Helm --overwrite >/dev/null; kb "$1" annotate ns "$NS" meta.helm.sh/release-name=norviq meta.helm.sh/release-namespace="$NS" --overwrite >/dev/null; }
common(){ echo "--set api.secretKey=$SECRET --set imagePullSecrets=null --set api.replicas=1 --set images.api.tag=api-latest --set images.ui.tag=ui-latest --set images.api.pullPolicy=IfNotPresent --set images.ui.pullPolicy=IfNotPresent --set images.engine.pullPolicy=IfNotPresent --set images.webhook.pullPolicy=IfNotPresent"; }

bash "$FL/gen-keys.sh"
ALLC="fleet-a $SPOKES"
for c in $ALLC; do
  kind get clusters | grep -qx "$c" || { log "kind create $c"; kind create cluster --name "$c"; }
  own_ns "$c"
  kind load docker-image --name "$c" sanman97/norviq-engine:api-latest sanman97/norviq-engine:ui-latest
done
nodeip="$(docker inspect fleet-a-control-plane -f '{{.NetworkSettings.Networks.kind.IPAddress}}')"

log "fleet-a HUB+spoke (env=prod, signing key)"
# shellcheck disable=SC2046
hb fleet-a upgrade --install norviq "$REPO_ROOT/helm/norviq" -n "$NS" -f "$FL/values-fleet.yaml" $(common) \
  --set fleet.clusterId=fleet-a --set fleet.clusterName=fleet-a --set fleet.region=local \
  --set fleet.apiUrl=http://norviq-fleet-api.norviq.svc:8080 --set fleet.clusterEndpoint=http://norviq-api.norviq.svc:8080 \
  --set fleet.labels.env=prod --set-file fleet.hub.signingKey="$FL/fleet-signing-priv.pem" \
  --set-file fleet.bundlePubkey="$FL/fleet-signing-pub.pem" --set fleet.hub.enabled=true --timeout 600s
kb fleet-a -n "$NS" rollout status deploy/norviq-fleet-api --timeout=300s
kb fleet-a -n "$NS" rollout status deploy/norviq-api --timeout=300s

for c in $SPOKES; do
  env_label=staging; extra="--set fleet.residency=true"
  [ "$c" = "fleet-c" ] && { env_label=dev; extra=""; }
  log "$c SPOKE (env=$env_label) -> hub $nodeip:31090"
  # shellcheck disable=SC2046
  hb "$c" upgrade --install norviq "$REPO_ROOT/helm/norviq" -n "$NS" -f "$FL/values-fleet.yaml" $(common) \
    --set fleet.clusterId="$c" --set fleet.clusterName="$c" --set fleet.region=local \
    --set fleet.apiUrl="http://$nodeip:31090" --set fleet.labels.env="$env_label" $extra \
    --set-file fleet.bundlePubkey="$FL/fleet-signing-pub.pem" --set fleet.hub.enabled=false --timeout 600s
  kb "$c" -n "$NS" rollout status deploy/norviq-api --timeout=300s
done
log "Phase C UP: hub fleet-a + spokes [$SPOKES]"
