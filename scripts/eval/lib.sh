# SPDX-License-Identifier: Apache-2.0
# Shared helpers for the local customer-eval harness. Source this; don't run it.
# shellcheck shell=bash

set -euo pipefail

# Resolve repo root from this file's location (scripts/eval/ -> repo root).
EVAL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${EVAL_DIR}/../.." && pwd)"
STATE_DIR="${REPO_ROOT}/.reviews/customer-eval"
ENV_FILE="${STATE_DIR}/env.json"

# Clusters / contexts / namespace
CLUSTER_A="${CLUSTER_A:-lumina-a}"
CLUSTER_B="${CLUSTER_B:-lumina-b}"
CTX_A="kind-${CLUSTER_A}"
CTX_B="kind-${CLUSTER_B}"
NS="${NRVQ_NS:-norviq}"

# Local port-forward ports (scouts hit these)
PORT_API_A="${PORT_API_A:-18080}"   # cluster A api
PORT_UI_A="${PORT_UI_A:-18081}"     # cluster A ui
PORT_API_B="${PORT_API_B:-18082}"   # cluster B api
# Post-remediation: deploy with a ROTATED (non-default) secret, injected into the chart via
# `--set api.secretKey=$EVAL_SECRET`. This proves the key is now rotatable (the NRVQ_API_SECRET_KEY
# alias fix) and that forging with the old default ("change-me-in-production") now fails. Tokens are
# minted with this same value (single source of truth).
EVAL_SECRET="${EVAL_SECRET:-eval-rotated-secret-9f3a2c}"

c_red=$'\033[31m'; c_grn=$'\033[32m'; c_yel=$'\033[33m'; c_rst=$'\033[0m'
log()  { printf '%s[eval]%s %s\n' "$c_grn" "$c_rst" "$*"; }
warn() { printf '%s[eval]%s %s\n' "$c_yel" "$c_rst" "$*" >&2; }
die()  { printf '%s[eval] FATAL:%s %s\n' "$c_red" "$c_rst" "$*" >&2; exit 1; }

need() { command -v "$1" >/dev/null 2>&1 || die "missing prereq: '$1' (install it and re-run)"; }

require_prereqs() {
  for b in docker kind kubectl helm python3; do need "$b"; done
  docker info >/dev/null 2>&1 || die "Docker is not running. Launch Docker Desktop and retry."
  log "prereqs OK (docker, kind, kubectl, helm, python3)"
}

# mint_jwt <role>  -> prints a HS256 JWT signed with $EVAL_SECRET (pure stdlib, no pip installs)
mint_jwt() {
  local role="${1:-admin}"
  python3 - "$EVAL_SECRET" "$role" <<'PY'
import sys, hmac, hashlib, base64, json, time
secret, role = sys.argv[1], sys.argv[2]
b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b'=')
hdr = b64(json.dumps({"alg":"HS256","typ":"JWT"}, separators=(',',':')).encode())
now = int(time.time())
pay = b64(json.dumps({"sub":"lumina-secops","role":role,"namespace":"default",
                      "iat":now,"exp":now+86400}, separators=(',',':')).encode())
sig = b64(hmac.new(secret.encode(), hdr+b'.'+pay, hashlib.sha256).digest())
print((hdr+b'.'+pay+b'.'+sig).decode())
PY
}

# wait_workloads <context> : block until core deployments/statefulsets are ready (or fail loud)
wait_workloads() {
  local ctx="$1"
  log "[$ctx] waiting for datastores..."
  kubectl --context "$ctx" -n "$NS" rollout status statefulset/norviq-postgresql --timeout=300s
  kubectl --context "$ctx" -n "$NS" rollout status statefulset/norviq-redis --timeout=300s
  log "[$ctx] waiting for app deployments..."
  kubectl --context "$ctx" -n "$NS" rollout status deploy/norviq-api --timeout=300s
  kubectl --context "$ctx" -n "$NS" rollout status deploy/norviq-engine --timeout=300s || \
    warn "[$ctx] engine not ready (non-fatal for API-driven eval)"
  kubectl --context "$ctx" -n "$NS" rollout status deploy/norviq-ui --timeout=300s || \
    warn "[$ctx] ui not ready"
}

# start_pf <context> <svc> <localport> <remoteport> : background port-forward, echo its PID
start_pf() {
  local ctx="$1" svc="$2" lp="$3" rp="$4"
  ( kubectl --context "$ctx" -n "$NS" port-forward "svc/$svc" "$lp:$rp" >/dev/null 2>&1 ) &
  echo $!
}

api_up() { curl -fsS "http://127.0.0.1:$1/healthz" >/dev/null 2>&1; }
