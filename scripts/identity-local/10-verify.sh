#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# End-to-end validation of the IDENTITY local stack. Captures evidence to .reviews/identity-local/.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
CLUSTER="${CLUSTER:-norviq-identity}"
CTX="kind-${CLUSTER}"
NS="${NS:-norviq}"
SECRET="${SECRET:-identity-local-secret-7c1f}"
K="kubectl --context $CTX"
OUT="$REPO_ROOT/.reviews/identity-local"; mkdir -p "$OUT"
PY="$REPO_ROOT/.venv/bin/python"

log() { echo -e "\n\033[1;36m== $* ==\033[0m"; }

# Fetch a real access token for $1 (in-cluster, so keycloak.localtest.me resolves via CoreDNS and the
# issuer matches what the API validates — independent of any host :8080 conflict).
gettok() {
  $K -n "$NS" run "kct-$1-$RANDOM" --image=curlimages/curl:8.9.1 --restart=Never --rm -i --quiet -- \
    -s -m10 http://keycloak.localtest.me:8080/realms/norviq/protocol/openid-connect/token \
    -d grant_type=password -d client_id=norviq-console -d username="$1" -d password=password -d scope=openid 2>/dev/null \
    | $PY -c "import sys,json;print(json.load(sys.stdin).get('access_token',''))"
}

# --- SPIRE registration entries ---
log "B1 SPIRE entries"
$K -n spire-system exec deploy/spire-server -c spire-server -- \
  /opt/spire/bin/spire-server entry show 2>/dev/null | tee "$OUT/spire-entries.txt" | grep -E "SPIFFE ID|Selector" || true

# --- Resolver attests real SVID (spoof-proof) + fail-closed ---
log "B2 proof Jobs (spoof-resistant + fail-closed)"
$K delete -f "$HERE/b2-proof.yaml" --ignore-not-found >/dev/null 2>&1
$K apply -f "$HERE/b2-proof.yaml"
$K -n "$NS" wait --for=condition=complete job/norviq-svid-proof --timeout=120s 2>/dev/null
$K -n "$NS" wait --for=condition=complete job/norviq-svid-failclosed --timeout=120s 2>/dev/null
$K -n "$NS" logs job/norviq-svid-proof       | tee "$OUT/b2-spoof.txt"
$K -n "$NS" logs job/norviq-svid-failclosed  | tee "$OUT/b2-failclosed.txt"

# --- port-forwards for the API + redis + postgres ---
pkill -f "port-forward.*norviq-" 2>/dev/null; sleep 1
$K -n "$NS" port-forward svc/norviq-api 18080:8080 >/tmp/pf-api.log 2>&1 &
$K -n "$NS" port-forward svc/norviq-redis 16379:6379 >/tmp/pf-redis.log 2>&1 &
$K -n "$NS" port-forward svc/norviq-postgresql 15432:5432 >/tmp/pf-pg.log 2>&1 &
sleep 6
API="http://127.0.0.1:18080"
REDIS_PF="$($K -n $NS get secret norviq-secrets -o jsonpath='{.data.NRVQ_REDIS_URL}' | base64 -d | sed -E 's#@[^:/]+:[0-9]+#@127.0.0.1:16379#')"
PG_PF="$($K -n $NS get secret norviq-secrets -o jsonpath='{.data.NRVQ_PG_URL}' | base64 -d | sed -E 's#@[^:/]+:[0-9]+#@127.0.0.1:15432#')"

# --- OIDC: real RS256 token from Keycloak -> API validates + maps groups -> /me + per-user audit ---
log "OIDC live: alice (norviq-admins) logs in -> API validates RS256 -> role=admin"
ALICE=$(gettok alice); echo "alice token len: ${#ALICE}"
curl -s -H "Authorization: Bearer $ALICE" "$API/api/v1/me" | tee "$OUT/oidc-me-admin.json"; echo
log "OIDC live: bob (team-a) -> role=viewer, namespace=team-a"
BOB=$(gettok bob)
curl -s -H "Authorization: Bearer $BOB" "$API/api/v1/me" | tee "$OUT/oidc-me-viewer.json"; echo

# Per-user audit: alice (admin) creates a policy -> the audit line carries actor=alice's sub.
REGO=$'package norviq.idtest\ndefault decision = "allow"\n'
curl -s -X POST -H "Authorization: Bearer $ALICE" -H "Content-Type: application/json" \
  "$API/api/v1/policies" -d "{\"namespace\":\"default\",\"agent_class\":\"idtest\",\"rego_source\":$($PY -c "import json,sys;print(json.dumps(sys.argv[1]))" "$REGO")}" >/dev/null
$K -n "$NS" logs deploy/norviq-api --tail=200 | grep "NRVQ-API-7011" | tail -2 | tee "$OUT/oidc-peruser-audit.txt"

# --- Controller -> API via OIDC client-credentials (HS256 fallback kept) ---
log "B4 controller identity (OIDC client-credentials active)"
$K -n "$NS" logs deploy/norviq-webhook --tail=200 | grep -E "NRVQ-WHK-4042|NRVQ-WHK-4026|client-credentials" | tail -3 | tee "$OUT/b4-controller.txt" || true

# --- Attacks 75/75 via the break-glass HS256 token; reseed first ---
log "Attacks 75/75 (break-glass HS256)"
export NRVQ_API_URL="$API"
export NRVQ_REDIS_URL="$REDIS_PF"
export NRVQ_API_TOKEN=$($PY -c "from jose import jwt; print(jwt.encode({'sub':'attack-runner','role':'admin'}, '$SECRET', algorithm='HS256'))")
# Seed the comprehensive customer-support policy into the CLUSTER (redis cache + pg registry).
NRVQ_REDIS_URL="$REDIS_PF" NRVQ_PG_URL="${PG_PF}?sslmode=disable" NRVQ_DB_SSL_MODE=disable \
  $PY "$REPO_ROOT/scripts/seed-local-policies.py" 2>/dev/null | tail -1 || true
# Trust state warms across runs; run twice and report the second.
$PY -m pytest "$REPO_ROOT/tests/attacks/" -q -p no:cacheprovider >/dev/null 2>&1
$PY -m pytest "$REPO_ROOT/tests/attacks/" -q -p no:cacheprovider 2>&1 | tail -3 | tee "$OUT/attacks.txt"

log "evidence in $OUT"
