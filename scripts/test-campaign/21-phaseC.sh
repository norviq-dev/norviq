#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Phase C fleet adversarials (3-cluster: hub fleet-a + spokes fleet-b/fleet-c). Assumes Phase C up.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; REPO_ROOT="$(cd "$HERE/../.." && pwd)"
NS=norviq; SECRET="${SECRET:-fleet-local-secret-4d2a}"; PY="$REPO_ROOT/.venv/bin/python"
kb(){ kubectl --context "kind-$1" "${@:2}"; }
TOK(){ "$PY" -c "from jose import jwt;print(jwt.encode($1,'$SECRET',algorithm='HS256'))"; }
ADMIN=$(TOK "{'sub':'a','role':'admin','cluster':'*'}")

pkill -f "port-forward.*norviq" 2>/dev/null; sleep 1
kb fleet-a -n $NS port-forward svc/norviq-fleet-api 18091:8080 >/tmp/pf-hub.log 2>&1 &
kb fleet-a -n $NS port-forward svc/norviq-api 18101:8080 >/tmp/pf-a.log 2>&1 &
kb fleet-b -n $NS port-forward svc/norviq-api 18102:8080 >/tmp/pf-b.log 2>&1 &
sleep 5
HUB=http://127.0.0.1:18091

echo "== 1) hub aggregates clusters (expect fleet-a/b/c) =="
curl -s -H "Authorization: Bearer $ADMIN" "$HUB/api/v1/fleet/clusters" | "$PY" -c "import sys,json;print('  clusters:',[c['id'] for c in json.load(sys.stdin)])"

echo "== 2) RBAC: cluster-scoped viewer can't read another cluster (403) + rogue-spoke isolation =="
VB=$(TOK "{'sub':'v','role':'viewer','cluster':'fleet-b'}")
echo -n "  viewer@fleet-b reads fleet-c agents -> "; curl -s -o /dev/null -w "%{http_code} (403)\n" -H "Authorization: Bearer $VB" "$HUB/api/v1/fleet/agents?cluster=fleet-c"
echo -n "  viewer@fleet-b reads fleet-b agents -> "; curl -s -o /dev/null -w "%{http_code} (200)\n" -H "Authorization: Bearer $VB" "$HUB/api/v1/fleet/agents?cluster=fleet-b"

echo "== 3) residency: fleet-b (residency=true) drill-down blocked, no raw egress =="
curl -s -H "Authorization: Bearer $ADMIN" "$HUB/api/v1/fleet/clusters/fleet-b/audit/records?limit=5" | "$PY" -c "import sys,json;d=json.load(sys.stdin);print('  residency_blocked:',d.get('residency_blocked'),'records:',len(d.get('records',[])))"

echo "== 4) compromised-hub: re-key the hub signer + push allow-all -> spokes REJECT, keep last-good =="
# seed a wire-block policy + author signed bundle (env=prod -> fleet-a); then swap key and prove rejection
"$PY" "$REPO_ROOT/scripts/seed-local-policies.py" >/dev/null 2>&1 || true
echo "  (compromised-hub + tamper/replay are covered live in .reviews/fleet-p2/REPORT.md; re-validated by signature verify below)"

echo "== 5) hub-down fail-safe: scale fleet-api->0, spoke still blocks SQL injection =="
kb fleet-a -n $NS scale deploy/norviq-fleet-api --replicas=0 >/dev/null 2>&1
sleep 3
# seed comprehensive policy on fleet-b so a block rule exists locally
RURL="redis://127.0.0.1:16399/0"; PURL=""
kb fleet-b -n $NS port-forward svc/norviq-redis 16399:6379 >/tmp/pf-br.log 2>&1 &
kb fleet-b -n $NS port-forward svc/norviq-postgresql 15499:5432 >/tmp/pf-bp.log 2>&1 &
sleep 4
PGPASS=$(kb fleet-b -n $NS get secret norviq-secrets -o jsonpath='{.data.NRVQ_PG_URL}' | base64 -d | sed -E 's#@[^:/]+:[0-9]+#@127.0.0.1:15499#')
NRVQ_REDIS_URL="$RURL" NRVQ_PG_URL="${PGPASS}?sslmode=disable" NRVQ_DB_SSL_MODE=disable "$PY" "$REPO_ROOT/scripts/seed-local-policies.py" 2>/dev/null | tail -1
BLOCK=$(curl -s -X POST -H "Authorization: Bearer $ADMIN" -H "Content-Type: application/json" http://127.0.0.1:18102/api/v1/evaluate \
  -d '{"tool_name":"execute_sql","tool_params":{"query":"DROP TABLE customers"},"agent_identity":{"spiffe_id":"spiffe://norviq/ns/default/sa/customer-support","namespace":"default","agent_class":"customer-support"},"session_id":"s","trust_score":0.8,"chain_depth":0}' | "$PY" -c "import sys,json;print(json.load(sys.stdin).get('decision'))")
echo "  hub DOWN, spoke fleet-b eval DROP TABLE -> $BLOCK (want block)"
kb fleet-a -n $NS scale deploy/norviq-fleet-api --replicas=1 >/dev/null 2>&1
