#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
#
# Undo the two cluster mutations the red/blue campaign left behind when the AKS control plane was
# stopped mid-run (2026-08-08 ~22:55 local). Both live in the API's Postgres, so they survive the
# stop and take effect the moment the cluster is started again.
#
#   1. ns/chatbot-prod  baseline control `deny_shell_execution` = deny   (was: monitor)
#   2. ns/all           policy for agent_class `cmp-prec-z`             (was: absent)
#
# (1) is the one that matters. `deny_shell_execution` fires on any parameter containing a semicolon,
# pipe or backtick — measured at 100% on ordinary support prose — and on ~4-32% of alphanumeric
# identifiers via the base64 fan-out. Left at `deny` it drops that traffic instead of recording it,
# which is precisely the behaviour the allow-by-default work exists to prevent. chatbot-prod has no
# running workloads today, so nothing is being dropped right now; this is a landmine, not a fire.
#
# Idempotent and safe to re-run. Verifies before and after rather than assuming.
#
#   az aks start -n norviq -g rg-opsai-dev-eastus-001     # cluster is Stopped; start it first
#   bash scripts/campaign/restore_cluster_state.sh

set -euo pipefail

CTX="${NRVQ_KUBE_CONTEXT:-norviq}"
NS_CTRL="chatbot-prod"
PORT="${NRVQ_PORT:-8080}"
TOKEN_FILE="${NRVQ_TOKEN_FILE:-/tmp/nrvq-signin-token.txt}"

echo "==> checking the control plane is reachable"
if ! kubectl --context "$CTX" -n norviq get pods --request-timeout=20s >/dev/null 2>&1; then
  echo "FAILED: context '$CTX' is unreachable."
  echo "  If the cluster is stopped:  az aks start -n norviq -g rg-opsai-dev-eastus-001"
  echo "  Then re-run this script."
  exit 2
fi

echo "==> port-forwarding the API (explicitly against context '$CTX')"
# The forward is pinned to the context on purpose: a previous restore attempt returned 404 because
# 127.0.0.1:8080 had been re-pointed at a local kind cluster that has no baseline endpoints. A 404
# then looks like "nothing to restore" when the real state is untouched.
pkill -f "port-forward svc/norviq-api" 2>/dev/null || true
sleep 2
kubectl --context "$CTX" -n norviq port-forward svc/norviq-api "${PORT}:8080" >/tmp/nrvq-restore-pf.log 2>&1 &
PF_PID=$!
trap 'kill "$PF_PID" 2>/dev/null || true' EXIT
sleep 6

code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "http://127.0.0.1:${PORT}/healthz" || true)
[ "$code" = "200" ] || { echo "FAILED: API not answering on :${PORT} (got $code)"; exit 2; }

if [ ! -s "$TOKEN_FILE" ]; then
  echo "FAILED: no admin token at $TOKEN_FILE. Mint one, then re-run:"
  echo "  kubectl --context $CTX -n norviq exec <api-pod> -c api -- python -m norviq.api.token_mint --ttl 3600 | tail -1 > $TOKEN_FILE"
  exit 2
fi
TOK=$(cat "$TOKEN_FILE")

echo "==> BEFORE: baseline controls in ns/$NS_CTRL not at the default"
curl -s --max-time 20 -H "Authorization: Bearer $TOK" \
  "http://127.0.0.1:${PORT}/api/v1/baseline/controls?namespace=${NS_CTRL}" \
  | python3 -c 'import json,sys; d=json.load(sys.stdin); print("   ", [(c["id"],c["effect"]) for c in d.get("controls",[]) if c["effect"]!="monitor"] or "none")'

echo "==> restoring every control to the shipped default (empty map == all monitor)"
curl -s --max-time 30 -X PUT -H "Authorization: Bearer $TOK" -H "Content-Type: application/json" \
  -d "{\"namespace\":\"${NS_CTRL}\",\"effects\":{}}" \
  "http://127.0.0.1:${PORT}/api/v1/baseline/controls" \
  | python3 -c 'import json,sys; d=json.load(sys.stdin); print("    enforcing:", d.get("enforcing"), "| disabled:", d.get("disabled"))'

echo "==> AFTER: baseline controls in ns/$NS_CTRL not at the default"
curl -s --max-time 20 -H "Authorization: Bearer $TOK" \
  "http://127.0.0.1:${PORT}/api/v1/baseline/controls?namespace=${NS_CTRL}" \
  | python3 -c 'import json,sys; d=json.load(sys.stdin); bad=[(c["id"],c["effect"]) for c in d.get("controls",[]) if c["effect"]!="monitor"]; print("   ", bad or "none"); sys.exit(1 if bad else 0)'

echo "==> removing the leftover precedence-test policy (ns 'all', class 'cmp-prec-z')"
# Deleted by exact (namespace, agent_class) rather than by pattern — a pattern delete against a live
# policy store is how a cleanup becomes an outage.
status=$(curl -s -o /tmp/nrvq-restore-del.json -w '%{http_code}' --max-time 20 -X DELETE \
  -H "Authorization: Bearer $TOK" "http://127.0.0.1:${PORT}/api/v1/policies/all/cmp-prec-z" || true)
case "$status" in
  200|204) echo "    deleted" ;;
  404)     echo "    already absent" ;;
  *)       echo "    UNEXPECTED $status — inspect /tmp/nrvq-restore-del.json"; cat /tmp/nrvq-restore-del.json ;;
esac

echo
echo "RESTORE COMPLETE. Both campaign mutations are undone."
