#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
#
# The customer scenario: govern a support chatbot that has FOUR MCP integrations.
#
#   github      read/comment on issues        postgres    query the customer replica
#   slack       post messages, DM users       filesystem  read runbooks
#
# Two agent CLASSES share those four servers and get very different power:
#   faq-bot        public, unauthenticated  -> docs + issue reads only
#   support-agent  tier-2, human in loop    -> may query customers and post internally, but not
#                                              run arbitrary SQL, not egress externally, and
#                                              GitHub writes are escalated for approval
#
# Usage:  scripts/mcp-chatbot-scenario.sh [--skip-build]
set -euo pipefail

CLUSTER="${CLUSTER:-norviq-local}"
NS_CTRL="${NS_CTRL:-norviq}"
NS_AGENT="${NS_AGENT:-agents}"
IMAGE="${IMAGE:-norviq-mcp:local}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${OUT:-${REPO_ROOT}/.mcp-demo-evidence}"
mkdir -p "$OUT"
# shellcheck source=scripts/_demo-common.sh
source "${REPO_ROOT}/scripts/_demo-common.sh"
say() { printf '\n\033[1m== %s\033[0m\n' "$*"; }

demo_preflight
CA_BUILD_DIR="$(demo_ca_dir)"

GIT_SHA="$(cd "$REPO_ROOT" && git rev-parse HEAD)"
TREE_DIGEST="$("${REPO_ROOT}/scripts/tree-digest.sh")"

if [[ "${1:-}" != "--skip-build" ]]; then
  say "building $IMAGE from the working tree"
  docker build --provenance=false --sbom=false --network host \
    --build-context "certs=${CA_BUILD_DIR}" \
    -f "${REPO_ROOT}/scripts/mcp-demo.Dockerfile" \
    --build-arg NRVQ_GIT_SHA="$GIT_SHA" --build-arg NRVQ_TREE_DIGEST="$TREE_DIGEST" \
    -t "$IMAGE" "$REPO_ROOT" 2>&1 | tail -2
  demo_kind_load "$IMAGE"
fi

# Roll the API onto the freshly-built image before anything reads from it. The scenario's policies
# are Python modules INSIDE that image, and the no-stale-image rule applies to the control plane as
# much as to the data plane — a demo run against a stale API proves nothing about this working tree.
if [[ "${1:-}" != "--skip-build" ]]; then
  say "rolling the API onto the fresh image"
  kubectl -n "$NS_CTRL" rollout restart deploy/norviq-api >/dev/null
  kubectl -n "$NS_CTRL" rollout status deploy/norviq-api --timeout=400s >/dev/null
fi

API_POD="$(demo_api_pod)"
API_TREE="$(kubectl -n "$NS_CTRL" exec "$API_POD" -c api -- cat /app/.build_tree_digest | tr -d '\r\n')"
[[ "$API_TREE" == "$TREE_DIGEST" ]] || { echo "STALE API IMAGE: $API_TREE != $TREE_DIGEST" >&2; exit 1; }
ADMIN="$(kubectl -n "$NS_CTRL" exec "$API_POD" -c api -- python -m norviq.api.token_mint --ttl 7200 2>/dev/null)"

# ---------------------------------------------------------------- policies
say "installing the two agent-class policies"
kubectl -n "$NS_CTRL" exec "$API_POD" -c api -- python -c "
import json, urllib.request
from norviq.mcp.adversarial.chatbot_policies import POLICIES
for agent_class, rego in POLICIES.items():
    body = json.dumps({
        'namespace': '${NS_AGENT}', 'agent_class': agent_class, 'rego_source': rego,
        'enforcement_mode': 'block', 'saved_by': 'chatbot-scenario', 'priority': 100,
        'policy_name': f'chatbot-{agent_class}',
    }).encode()
    req = urllib.request.Request('http://127.0.0.1:8080/api/v1/policies', data=body, method='POST',
        headers={'Authorization': 'Bearer ${ADMIN}', 'Content-Type': 'application/json'})
    print(' ', agent_class, '->', json.loads(urllib.request.urlopen(req).read()))
"

# ---------------------------------------------------------------- credentials
# One service token PER AGENT CLASS. This is the mechanism that makes two bots sharing four servers
# get different power: the class is bound to the CREDENTIAL, not asserted in the request body, so a
# compromised FAQ bot cannot evaluate as the support agent.
say "minting a namespace+class-bound service token per agent class"
for CLS in faq-bot support-agent; do
  TOK="$(kubectl -n "$NS_CTRL" exec "$API_POD" -c api -- python -c "
import time, jwt
from norviq.config import settings
now = int(time.time())
print(jwt.encode({'sub': 'chatbot-${CLS}', 'role': 'service', 'namespace': '${NS_AGENT}',
                  'agent_class': '${CLS}',
                  'spiffe_id': 'spiffe://norviq/ns/${NS_AGENT}/sa/default',
                  'iat': now, 'exp': now + 86400}, settings.api_secret_key, algorithm='HS256'))")"
  kubectl -n "$NS_AGENT" create secret generic "norviq-token-${CLS}" \
    --from-literal=NRVQ_API_TOKEN="$TOK" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
  # Also exported to the scenario runner so it can drive BOTH classes from one pod, and so it can
  # demonstrate that presenting the wrong class's token is refused rather than honoured.
  if [[ "$CLS" == "faq-bot" ]]; then TOK_FAQ="$TOK"; else TOK_SUPPORT="$TOK"; fi
  echo "  ${CLS}: bound"
done
kubectl -n "$NS_AGENT" create secret generic norviq-scenario-tokens \
  --from-literal=NRVQ_TOKEN_FAQ_BOT="$TOK_FAQ" \
  --from-literal=NRVQ_TOKEN_SUPPORT_AGENT="$TOK_SUPPORT" \
  --dry-run=client -o yaml | kubectl apply -f - >/dev/null

# ---------------------------------------------------------------- the chatbot pod
say "starting the chatbot pod (MCP client + firewall + 4 integrations)"
kubectl -n "$NS_AGENT" delete pod chatbot --ignore-not-found --wait=true >/dev/null 2>&1 || true
kubectl -n "$NS_AGENT" apply -f - >/dev/null <<YAML
apiVersion: v1
kind: Pod
metadata: {name: chatbot, labels: {app: chatbot}}
spec:
  restartPolicy: Never
  containers:
  - name: agent
    image: ${IMAGE}
    imagePullPolicy: IfNotPresent
    command: ["sleep", "7200"]
    env:
    - {name: NRVQ_POLICY_ENGINE_URL, value: "http://norviq-api.${NS_CTRL}.svc.cluster.local:8080"}
    - {name: NRVQ_API_URL,           value: "http://norviq-api.${NS_CTRL}.svc.cluster.local:8080"}
    - {name: NRVQ_NAMESPACE,         value: "${NS_AGENT}"}
    - {name: NRVQ_SERVICE_ACCOUNT,   value: "default"}
    # Pins live in the CONTROL PLANE: tenant-scoped, audited, console-visible, and — the point for a
    # supply-chain check — they survive this pod being restarted.
    - {name: NRVQ_MCP_PIN_STORE,     value: "control-plane"}
    - {name: NRVQ_MCP_PIN_MODE,      value: "tofu"}
    - {name: PYTHONUNBUFFERED,       value: "1"}
    envFrom:
    - secretRef: {name: norviq-token-support-agent}
    - secretRef: {name: norviq-scenario-tokens}
YAML
kubectl -n "$NS_AGENT" wait --for=condition=Ready pod/chatbot --timeout=180s >/dev/null

say "no-stale-image check"
RUN_TREE="$(kubectl -n "$NS_AGENT" exec chatbot -- cat /app/.build_tree_digest | tr -d '\r\n')"
[[ "$RUN_TREE" == "$TREE_DIGEST" ]] || { echo "STALE IMAGE: $RUN_TREE != $TREE_DIGEST" >&2; exit 1; }
echo "  OK — running image built from this working tree ($TREE_DIGEST)"

# ---------------------------------------------------------------- run it
say "running the scenario"
kubectl -n "$NS_AGENT" exec chatbot -- env \
  NRVQ_ADMIN_TOKEN="$ADMIN" \
  NRVQ_LOG_LEVEL=WARNING \
  python -m norviq.mcp.adversarial.chatbot_scenario \
    --api "http://norviq-api.${NS_CTRL}.svc.cluster.local:8080" \
    --json /tmp/chatbot.json 2>/dev/null | tee "$OUT/chatbot-scenario.txt"
kubectl -n "$NS_AGENT" exec chatbot -- cat /tmp/chatbot.json > "$OUT/chatbot-scenario.json"

say "MCP inventory as the console sees it"
kubectl -n "$NS_CTRL" exec "$API_POD" -c api -- python -c "
import json, urllib.request
req = urllib.request.Request('http://127.0.0.1:8080/api/v1/mcp/servers?namespace=${NS_AGENT}',
                             headers={'Authorization': 'Bearer ${ADMIN}'})
rows = json.loads(urllib.request.urlopen(req).read())
print(f\"{'SERVER':<14}{'TOOLS':<7}{'DRIFTED':<9}{'FLAGGED':<9}{'HEALTH'}\")
for r in rows:
    print(f\"{r['server_id']:<14}{r['tools']:<7}{r['drifted']:<9}{r['flagged']:<9}{r['health']}\")
" 2>&1 | tee "$OUT/mcp-inventory.txt"

say "evidence written to $OUT"
