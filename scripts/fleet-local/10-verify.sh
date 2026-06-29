#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Validate the fleet P1: heartbeat+register, cross-cluster aggregation, cluster-scope RBAC (403),
# hub-down fail-safe (spoke keeps enforcing). Evidence -> .reviews/fleet-local/.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
NS="${NS:-norviq}"
SECRET="${SECRET:-fleet-local-secret-4d2a}"
PY="$REPO_ROOT/.venv/bin/python"
OUT="$REPO_ROOT/.reviews/fleet-local"; mkdir -p "$OUT"
kb() { kubectl --context "kind-$1" "${@:2}"; }
log() { echo -e "\n\033[1;36m== $* ==\033[0m"; }
TOK() { $PY -c "from jose import jwt; print(jwt.encode($1, '$SECRET', algorithm='HS256'))"; }

ADMIN=$(TOK "{'sub':'a','role':'admin','cluster':'*'}")

log "port-forwards (hub fleet-api, both spoke apis + fleet-b redis/pg)"
pkill -f "port-forward.*fleet" 2>/dev/null; sleep 1
kb fleet-a -n "$NS" port-forward svc/norviq-fleet-api 18091:8080 >/tmp/pf-hub.log 2>&1 &
kb fleet-a -n "$NS" port-forward svc/norviq-api 18081:8080 >/tmp/pf-a.log 2>&1 &
kb fleet-b -n "$NS" port-forward svc/norviq-api 18082:8080 >/tmp/pf-b.log 2>&1 &
kb fleet-b -n "$NS" port-forward svc/norviq-redis 16382:6379 >/tmp/pf-b-redis.log 2>&1 &
kb fleet-b -n "$NS" port-forward svc/norviq-postgresql 15482:5432 >/tmp/pf-b-pg.log 2>&1 &
sleep 6
HUB=http://127.0.0.1:18091

seed_traffic() {  # $1=spoke api port, $2=cluster label
  local api="http://127.0.0.1:$1"
  for tool in search_kb get_order send_email; do
    curl -s -o /dev/null -X POST -H "Authorization: Bearer $ADMIN" -H "Content-Type: application/json" "$api/api/v1/evaluate" \
      -d "{\"tool_name\":\"$tool\",\"tool_params\":{\"q\":\"x\"},\"agent_identity\":{\"spiffe_id\":\"spiffe://norviq/ns/default/sa/$2-bot\",\"namespace\":\"default\",\"agent_class\":\"$2-bot\"},\"session_id\":\"s\",\"trust_score\":0.8,\"chain_depth\":0}"
  done
}

log "seed agents+traffic on both spokes"
seed_traffic 18081 fleet-a; seed_traffic 18082 fleet-b

log "wait for relays to push rollups (interval 15s)"; sleep 22

log "HUB: clusters registered + status"
curl -s -H "Authorization: Bearer $ADMIN" "$HUB/api/v1/fleet/clusters" | tee "$OUT/clusters.json"; echo
log "HUB: aggregated agents across clusters"
curl -s -H "Authorization: Bearer $ADMIN" "$HUB/api/v1/fleet/agents" | tee "$OUT/agents.json"; echo
log "HUB: audit summary per cluster"
curl -s -H "Authorization: Bearer $ADMIN" "$HUB/api/v1/fleet/audit/summary?range=24h" | tee "$OUT/audit-summary.json"; echo

log "RBAC: a fleet-a-scoped viewer is denied fleet-b data (403), allowed fleet-a (200)"
VA=$(TOK "{'sub':'v','role':'viewer','cluster':'fleet-a'}")
echo "viewer?cluster=fleet-b -> $(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $VA" "$HUB/api/v1/fleet/agents?cluster=fleet-b")" | tee "$OUT/rbac.txt"
echo "viewer?cluster=fleet-a -> $(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $VA" "$HUB/api/v1/fleet/agents?cluster=fleet-a")" | tee -a "$OUT/rbac.txt"

log "FAIL-SAFE: scale the hub fleet-api to 0, then prove the spoke still ENFORCES locally"
kb fleet-a -n "$NS" scale deploy/norviq-fleet-api --replicas=0
# seed the comprehensive policy on fleet-b so a SQL injection blocks locally
RURL="$(kb fleet-b -n $NS get secret norviq-secrets -o jsonpath='{.data.NRVQ_REDIS_URL}' | base64 -d | sed -E 's#@[^:/]+:[0-9]+#@127.0.0.1:16382#')"
PURL="$(kb fleet-b -n $NS get secret norviq-secrets -o jsonpath='{.data.NRVQ_PG_URL}' | base64 -d | sed -E 's#@[^:/]+:[0-9]+#@127.0.0.1:15482#')"
NRVQ_REDIS_URL="$RURL" NRVQ_PG_URL="${PURL}?sslmode=disable" NRVQ_DB_SSL_MODE=disable "$PY" "$REPO_ROOT/scripts/seed-local-policies.py" 2>/dev/null | tail -1
BLOCK=$(curl -s -X POST -H "Authorization: Bearer $ADMIN" -H "Content-Type: application/json" http://127.0.0.1:18082/api/v1/evaluate \
  -d '{"tool_name":"execute_sql","tool_params":{"query":"DELETE FROM customers WHERE 1=1"},"agent_identity":{"spiffe_id":"spiffe://norviq/ns/default/sa/customer-support","namespace":"default","agent_class":"customer-support"},"session_id":"s","trust_score":0.8,"chain_depth":0}')
echo "hub DOWN, spoke eval of SQL injection -> $BLOCK" | tee "$OUT/failsafe.txt"
echo "(decision must be 'block' — local enforcement is independent of the hub)"
log "restore the hub"; kb fleet-a -n "$NS" scale deploy/norviq-fleet-api --replicas=1; kb fleet-a -n "$NS" rollout status deploy/norviq-fleet-api --timeout=120s

log "evidence in $OUT"
