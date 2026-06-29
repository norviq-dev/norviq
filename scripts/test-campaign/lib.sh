#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Shared helpers for the defect-hunt campaign: persona HS256 token minting + port-forwards.
# (HS256 break-glass is the Phase-A/C auth; Phase B uses real Keycloak RS256.)
set -euo pipefail

SECRET="${SECRET:-campaign-secret-7f3c91aa2b}"

# mint_token <role> <namespace> [cluster]  -> HS256 JWT signed with $SECRET (pure stdlib).
# role: admin|service|viewer ; namespace: tenant scope ; cluster: fleet scope (default "*").
mint_token() {
  local role="${1:-admin}" ns="${2:-default}" cluster="${3:-*}"
  python3 - "$SECRET" "$role" "$ns" "$cluster" <<'PY'
import sys, hmac, hashlib, base64, json, time
secret, role, ns, cluster = sys.argv[1:5]
b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b'=')
hdr = b64(json.dumps({"alg":"HS256","typ":"JWT"}, separators=(',',':')).encode())
now = int(time.time())
claims = {"sub": f"{role}-{ns}", "role": role, "namespace": ns, "cluster": cluster,
          "iat": now, "exp": now+86400}
pay = b64(json.dumps(claims, separators=(',',':')).encode())
sig = b64(hmac.new(secret.encode(), hdr+b'.'+pay, hashlib.sha256).digest())
print((hdr+b'.'+pay+b'.'+sig).decode())
PY
}

# pf <kind-context> <svc> <localport> <remoteport>  -> background port-forward (idempotent)
pf() {
  local ctx="$1" svc="$2" lport="$3" rport="$4"
  pkill -f "port-forward.*$svc.*$lport:" 2>/dev/null || true
  kubectl --context "kind-$ctx" -n "${NS:-norviq}" port-forward "svc/$svc" "$lport:$rport" >/tmp/pf-$svc-$lport.log 2>&1 &
  sleep 3
}

# jqget <json> <key>  -> extract a top-level string field without requiring jq
jqget() { python3 -c "import sys,json; print(json.load(sys.stdin).get('$2',''))" <<<"$1" 2>/dev/null || true; }
