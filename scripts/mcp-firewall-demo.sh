#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
#
# Reproducible end-to-end demo of the Norviq MCP action-firewall on a local kind cluster.
#
#   MCP client (official `mcp` SDK)
#        -> norviq MCP proxy            (in-cluster pod, namespace `agents`)
#        -> POST /api/v1/evaluate       (norviq-api, namespace `norviq`)
#        -> OPA / Rego decision
#        -> enforcement + audit record
#        -> adversarial MCP server      (child process of the proxy)
#
# Everything runs IN the cluster. The only thing this script does from outside is kubectl.
#
# Usage:  scripts/mcp-firewall-demo.sh [--skip-build]
set -euo pipefail

CLUSTER="${CLUSTER:-norviq-local}"
NS_CTRL="${NS_CTRL:-norviq}"
NS_AGENT="${NS_AGENT:-agents}"
IMAGE="${IMAGE:-norviq-mcp:local}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${OUT:-${REPO_ROOT}/.mcp-demo-evidence}"
SKIP_BUILD=0
[[ "${1:-}" == "--skip-build" ]] && SKIP_BUILD=1

mkdir -p "$OUT"
say() { printf '\n\033[1m== %s\033[0m\n' "$*"; }

# ---------------------------------------------------------------- 0. provenance
# The no-stale-image rule. HEAD alone is not sufficient evidence here because this work is
# deliberately never committed, so HEAD does not move when the source does. The tree digest does.
GIT_SHA="$(cd "$REPO_ROOT" && git rev-parse HEAD)"
TREE_DIGEST="$("${REPO_ROOT}/scripts/tree-digest.sh")"
say "provenance"
echo "  git HEAD     : $GIT_SHA"
echo "  tree digest  : $TREE_DIGEST"

# ---------------------------------------------------------------- 1. build + load
if [[ $SKIP_BUILD -eq 0 ]]; then
  say "building $IMAGE from the working tree"
  docker build --provenance=false --sbom=false --network host \
    --build-context "certs=${CA_DIR:-/root/.ccr}" \
    -f "${REPO_ROOT}/scripts/mcp-demo.Dockerfile" \
    --build-arg NRVQ_GIT_SHA="$GIT_SHA" \
    --build-arg NRVQ_TREE_DIGEST="$TREE_DIGEST" \
    -t "$IMAGE" "$REPO_ROOT" 2>&1 | tail -2
  say "loading $IMAGE into kind/$CLUSTER"
  docker save --platform linux/amd64 "$IMAGE" -o /tmp/mcp-image.tar
  kind load image-archive --name "$CLUSTER" /tmp/mcp-image.tar
  rm -f /tmp/mcp-image.tar
fi

# ---------------------------------------------------------------- 2. credentials
say "minting the proxy's service token (same claim shape the webhook mints for a sidecar)"
# Newest RUNNING api pod — see the note in mcp-chatbot-scenario.sh about the rollout race.
API_POD="$(kubectl -n "$NS_CTRL" get pod -l app.kubernetes.io/component=api \
            --field-selector=status.phase=Running --sort-by=.metadata.creationTimestamp \
            -o jsonpath='{.items[-1:].metadata.name}')"
SVC_TOKEN="$(kubectl -n "$NS_CTRL" exec "$API_POD" -c api -- python -c "
import time, jwt
from norviq.config import settings
now = int(time.time())
print(jwt.encode({
    'sub': 'norviq-mcp-proxy', 'role': 'service',
    'namespace': '${NS_AGENT}', 'agent_class': 'mcp-agent',
    'spiffe_id': 'spiffe://norviq/ns/${NS_AGENT}/sa/default',
    'iat': now, 'exp': now + 86400,
}, settings.api_secret_key, algorithm='HS256'))
")"
kubectl -n "$NS_AGENT" create secret generic norviq-mcp-token \
  --from-literal=NRVQ_API_TOKEN="$SVC_TOKEN" \
  --dry-run=client -o yaml | kubectl apply -f - >/dev/null

# ---------------------------------------------------------------- 3. agent pod
say "starting the agent pod (MCP client + firewall + adversarial servers)"
kubectl -n "$NS_AGENT" delete pod mcp-agent --ignore-not-found --wait=true >/dev/null 2>&1 || true
kubectl -n "$NS_AGENT" apply -f - >/dev/null <<YAML
apiVersion: v1
kind: Pod
metadata:
  name: mcp-agent
  labels: {app: mcp-agent}
spec:
  restartPolicy: Never
  containers:
  - name: agent
    image: ${IMAGE}
    imagePullPolicy: IfNotPresent
    command: ["sleep", "3600"]
    env:
    # The proxy talks to the central engine exactly the way the thin-proxy sidecar does — same URL,
    # same bearer token contract, same fail-closed posture. Nothing MCP-specific in the wiring.
    - {name: NRVQ_POLICY_ENGINE_URL, value: "http://norviq-api.${NS_CTRL}.svc.cluster.local:8080"}
    - {name: NRVQ_API_URL,           value: "http://norviq-api.${NS_CTRL}.svc.cluster.local:8080"}
    - {name: NRVQ_NAMESPACE,         value: "${NS_AGENT}"}
    - {name: NRVQ_AGENT_CLASS,       value: "mcp-agent"}
    - {name: NRVQ_SERVICE_ACCOUNT,   value: "default"}
    - {name: NRVQ_MCP_PIN_STORE,     value: "file"}
    - {name: NRVQ_MCP_PIN_PATH,      value: "/tmp/pins/pins.json"}
    - {name: PYTHONUNBUFFERED,       value: "1"}
    envFrom:
    - secretRef: {name: norviq-mcp-token}
    volumeMounts:
    - {name: pins, mountPath: /tmp/pins}
  volumes:
  - {name: pins, emptyDir: {}}
YAML
kubectl -n "$NS_AGENT" wait --for=condition=Ready pod/mcp-agent --timeout=180s >/dev/null

# ---------------------------------------------------------------- 4. no-stale-image proof
say "no-stale-image check: running image vs working tree"
RUN_SHA="$(kubectl -n "$NS_AGENT" exec mcp-agent -- cat /app/.build_git_sha | tr -d '\r\n')"
RUN_TREE="$(kubectl -n "$NS_AGENT" exec mcp-agent -- cat /app/.build_tree_digest | tr -d '\r\n')"
echo "  image git sha    : $RUN_SHA"
echo "  image tree digest: $RUN_TREE"
[[ "$RUN_SHA"  == "$GIT_SHA"     ]] || { echo "STALE IMAGE: git sha mismatch" >&2; exit 1; }
[[ "$RUN_TREE" == "$TREE_DIGEST" ]] || { echo "STALE IMAGE: tree digest mismatch" >&2; exit 1; }
echo "  OK — the running image was built from this working tree"
{ echo "git_sha=$GIT_SHA"; echo "tree_digest=$TREE_DIGEST"; } > "$OUT/provenance.txt"

# ---------------------------------------------------------------- 5. the demo itself
say "1/3  a dangerous tools/call is deterministically blocked (Gate B)"
kubectl -n "$NS_AGENT" exec mcp-agent -- python -m norviq.mcp.demo_client 2>&1 \
  | tee "$OUT/gate-b-demo.txt"

say "2/3  adversarial harness (tool poisoning, evasion, rug pull, confused deputy)"
kubectl -n "$NS_AGENT" exec mcp-agent -- \
  python -m norviq.mcp.adversarial.harness --json /tmp/harness.json 2>/dev/null \
  | tee "$OUT/adversarial-scoreboard.txt"
kubectl -n "$NS_AGENT" exec mcp-agent -- cat /tmp/harness.json > "$OUT/adversarial-scoreboard.json"

say "3/3  audit records written by the engine for the blocked MCP calls"
ADMIN_TOKEN="$(kubectl -n "$NS_CTRL" exec "$API_POD" -c api -- \
                 python -m norviq.api.token_mint --ttl 600 2>/dev/null)"
kubectl -n "$NS_CTRL" exec "$API_POD" -c api -- python -c "
import json, urllib.request
req = urllib.request.Request(
    'http://127.0.0.1:8080/api/v1/audit/records?limit=25&framework=mcp&range=1h',
    headers={'Authorization': 'Bearer ${ADMIN_TOKEN}'})
rows = json.loads(urllib.request.urlopen(req).read())
rows = rows if isinstance(rows, list) else rows.get('items', rows.get('records', []))
for r in rows[:25]:
    print(f\"{r.get('decision','?'):9} {r.get('rule_id',''):32} {r.get('tool_name','')}\")
" 2>&1 | tee "$OUT/audit-records.txt"

say "evidence written to $OUT"
ls -1 "$OUT"
