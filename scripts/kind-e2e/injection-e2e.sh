#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
#
# LIVE sidecar-injection + credential-rotation checks against a real cluster.
#
# WHY THIS EXISTS. webhook/*_test.go covers the injector's decision logic against synthetic
# AdmissionReviews, which is the right place for that. What no test covered is whether a pod created
# in a real, injection-enabled namespace on a real cluster actually comes back governed — and, the
# part that matters most, what the injected CREDENTIAL does over time.
#
# That last question is not academic. `mintSidecarToken` (webhook/injector.go) says outright:
#
#     The token is baked into the pod env (cannot self-refresh), hence the long TTL
#
# So the sidecar's credential is fixed for the life of the pod. Every claim about rotation therefore
# reduces to: does a NEW pod get a NEW token, is that token bound to the identity it was minted for,
# and does the enforcement path fail CLOSED when it finally expires? This script answers the first
# two on a live cluster; the third is proved hermetically in tests/sdk/test_dataplane_failure_posture.py
# and tests/sidecar/test_remote_evaluator_retry.py, which assert a 4xx blocks regardless of
# `sdk_fallback_mode` (otherwise an expired credential would become a total governance bypass).
#
#   NRVQ_KUBE_CONTEXT=norviq bash scripts/kind-e2e/injection-e2e.sh
#
# Creates and deletes its own throwaway namespace. Safe to re-run.
set -uo pipefail

KCTX="${NRVQ_KUBE_CONTEXT:-}"
KUBECTL=(kubectl)
[ -n "$KCTX" ] && KUBECTL=(kubectl --context "$KCTX")
NS="${NRVQ_INJECT_NS:-nrvq-inject-live}"
ENABLE_LABEL="${NRVQ_ENABLE_LABEL:-norviq-injection}"
TIMEOUT="${NRVQ_INJECT_TIMEOUT:-180}"

pass=0; fail=0
ok()   { printf '  \033[0;32mok  \033[0m %s\n' "$1"; pass=$((pass+1)); }
bad()  { printf '  \033[0;31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
note() { printf '       %s\n' "$1"; }
stage(){ printf '\n\033[1;36m▶ %s\033[0m\n' "$1"; }

cleanup() { "${KUBECTL[@]}" delete ns "$NS" --wait=false >/dev/null 2>&1 || true; }
trap cleanup EXIT

command -v kubectl >/dev/null || { echo "kubectl not on PATH" >&2; exit 2; }
"${KUBECTL[@]}" get ns >/dev/null 2>&1 || { echo "cluster unreachable (context '${KCTX:-current}')" >&2; exit 2; }

# ---------------------------------------------------------------------------------------------------
stage "Preconditions"
if ! "${KUBECTL[@]}" get mutatingwebhookconfiguration norviq-sidecar-injector >/dev/null 2>&1; then
  echo "  norviq-sidecar-injector is not registered — nothing to test" >&2; exit 2
fi
ok "norviq-sidecar-injector is registered"

cleanup; sleep 2
"${KUBECTL[@]}" create ns "$NS" >/dev/null 2>&1
"${KUBECTL[@]}" label ns "$NS" "${ENABLE_LABEL}=enabled" --overwrite >/dev/null 2>&1
ok "throwaway namespace ${NS} created and labelled ${ENABLE_LABEL}=enabled"

# A pod that declares NOTHING about Norviq. Governance must arrive without the author's cooperation —
# that is the whole premise of admission-time injection.
run_pod() {  # $1=name  $2...=extra metadata lines
  local name="$1"; shift
  {
    echo "apiVersion: v1"; echo "kind: Pod"; echo "metadata:"; echo "  name: ${name}"
    echo "  labels:"; echo "    norviq.io/agent-class: inject-probe"
    if [ $# -gt 0 ]; then echo "  annotations:"; for a in "$@"; do echo "    ${a}"; done; fi
    echo "spec:"; echo "  restartPolicy: Never"; echo "  containers:"
    echo "  - name: app"; echo "    image: busybox:1.36"
    echo "    command: [\"sh\",\"-c\",\"sleep 600\"]"
  } | "${KUBECTL[@]}" -n "$NS" apply -f - >/dev/null 2>&1
}

containers()  { "${KUBECTL[@]}" -n "$NS" get pod "$1" -o jsonpath='{range .spec.containers[*]}{.name} {end}' 2>/dev/null; }
env_of()      { "${KUBECTL[@]}" -n "$NS" get pod "$1" -o jsonpath="{range .spec.containers[?(@.name=='$2')].env[*]}{.name}={.value}{\"\\n\"}{end}" 2>/dev/null; }
annotations() { "${KUBECTL[@]}" -n "$NS" get pod "$1" -o jsonpath='{.metadata.annotations}' 2>/dev/null; }

# ---------------------------------------------------------------------------------------------------
stage "1. A pod that asks for nothing comes back governed"
run_pod inject-a
for i in $(seq 1 "$TIMEOUT"); do [ -n "$(containers inject-a)" ] && break; sleep 1; done
CONS="$(containers inject-a)"
note "containers: ${CONS:-<none>}"
case "$CONS" in
  *norviq*) ok "a sidecar was injected into a pod whose author declared nothing" ;;
  "")       bad "pod inject-a never admitted — the webhook may be refusing (check its logs)" ;;
  *)        bad "no norviq container present: ${CONS}" ;;
esac

SIDECAR="$(echo "$CONS" | tr ' ' '\n' | grep norviq | head -1)"
if [ -n "$SIDECAR" ]; then
  ENV_A="$(env_of inject-a "$SIDECAR")"
  # The env the injector ALWAYS sets (injector.go buildSidecar). NRVQ_SPIFFE_MODE is deliberately
  # conditional on cfg.SpiffeInject and so is NOT asserted here — an earlier version of this script
  # demanded it unconditionally, plus a `NRVQ_POLICY_ENGINE_URL` that does not exist under that name,
  # and reported two failures against a product that was behaving correctly.
  for want in NRVQ_API_URL NRVQ_SOCKET_PATH NRVQ_AGENT_CLASS NRVQ_NAMESPACE; do
    echo "$ENV_A" | grep -q "^${want}=" && ok "sidecar carries ${want}" || bad "sidecar is MISSING ${want}"
  done
  # The sidecar must be told WHICH workload it is speaking for, or every decision is mis-scoped.
  echo "$ENV_A" | grep -q "^NRVQ_NAMESPACE=${NS}\$" && ok "sidecar's namespace matches the pod's (${NS})" \
    || bad "sidecar NRVQ_NAMESPACE does not match ${NS}"
  echo "$ENV_A" | grep -q "^NRVQ_AGENT_CLASS=inject-probe\$" && ok "sidecar's agent class matches the pod label" \
    || bad "sidecar NRVQ_AGENT_CLASS does not match the pod's norviq.io/agent-class label"
  # The token is what makes the sidecar able to ask the engine anything at all.
  if echo "$ENV_A" | grep -q "^NRVQ_API_TOKEN=."; then
    ok "sidecar carries a minted NRVQ_API_TOKEN"
  else
    bad "sidecar has NO NRVQ_API_TOKEN — with no signing secret the injector mints nothing, so this sidecar cannot authenticate to the engine"
  fi
fi

# ---------------------------------------------------------------------------------------------------
stage "2. The injected token is bound, and says what it is"
TOK_A="$(env_of inject-a "${SIDECAR:-none}" | sed -n 's/^NRVQ_API_TOKEN=//p')"
if [ -n "$TOK_A" ]; then
  CLAIMS_A="$(python3 - "$TOK_A" <<'PY'
import base64, json, sys
def seg(t, i):
    p = t.split(".")[i]; p += "=" * (-len(p) % 4)
    return json.loads(base64.urlsafe_b64decode(p))
try:
    c = seg(sys.argv[1], 1)
    print(json.dumps({k: c.get(k) for k in ("sub","role","namespace","agent_class","spiffe_id","iat","exp")}))
except Exception as e:
    print(json.dumps({"error": str(e)}))
PY
)"
  note "claims: ${CLAIMS_A}"
  echo "$CLAIMS_A" | grep -q '"role": *"service"' && ok "token is role=service (not an admin credential handed to a workload)" \
    || bad "token role is not 'service' — a workload holding a broader role is a privilege problem"
  echo "$CLAIMS_A" | grep -q "\"namespace\": *\"${NS}\"" && ok "token is pinned to its own namespace (${NS})" \
    || bad "token namespace claim does not match the pod's namespace — it is not scope-bound"
  echo "$CLAIMS_A" | grep -qE '"exp": *[0-9]+' && ok "token carries an expiry" \
    || bad "token has NO exp — a credential that never expires cannot be rotated by any means"
fi

# ---------------------------------------------------------------------------------------------------
stage "3. ROTATION — a new pod gets a NEW credential, not the old one"
# This is what rotation MEANS for a credential that cannot self-refresh: the replacement carries a
# fresh one. If two pods minted seconds apart shared a token, every pod in the namespace would share
# one credential for its whole TTL and revoking one would revoke all of them.
sleep 2
run_pod inject-b
for i in $(seq 1 "$TIMEOUT"); do [ -n "$(containers inject-b)" ] && break; sleep 1; done
SIDECAR_B="$(containers inject-b | tr ' ' '\n' | grep norviq | head -1)"
TOK_B="$(env_of inject-b "${SIDECAR_B:-none}" | sed -n 's/^NRVQ_API_TOKEN=//p')"
if [ -n "$TOK_A" ] && [ -n "$TOK_B" ]; then
  if [ "$TOK_A" = "$TOK_B" ]; then
    bad "two pods admitted seconds apart carry the IDENTICAL token — the credential is not per-pod, so it cannot be rotated or revoked per workload"
  else
    ok "a second pod received a DIFFERENT token (per-pod minting, so a replacement pod rotates)"
    IAT_A=$(echo "$CLAIMS_A" | python3 -c 'import json,sys;print(json.load(sys.stdin).get("iat") or 0)' 2>/dev/null)
    IAT_B=$(python3 - "$TOK_B" <<'PY'
import base64, json, sys
p = sys.argv[1].split(".")[1]; p += "=" * (-len(p) % 4)
print(json.loads(base64.urlsafe_b64decode(p)).get("iat") or 0)
PY
)
    [ "${IAT_B:-0}" -ge "${IAT_A:-0}" ] && ok "the newer pod's token was issued no earlier than the first (iat ${IAT_A} -> ${IAT_B})" \
      || bad "the newer pod's token is OLDER than the first (iat ${IAT_A} -> ${IAT_B}) — a cached credential is being reissued"
  fi
else
  bad "could not compare tokens across pods (one or both absent)"
fi

# ---------------------------------------------------------------------------------------------------
stage "4. Opt-out is honoured, and cannot be self-granted silently"
run_pod inject-skip "norviq.io/skip-injection: \"true\""
for i in $(seq 1 60); do [ -n "$(containers inject-skip)" ] && break; sleep 1; done
SKIP_CONS="$(containers inject-skip)"
note "containers: ${SKIP_CONS:-<none>}"
case "$SKIP_CONS" in
  *norviq*) note "opt-out was REFUSED — injection happened anyway (SkipAllowed=false). That is a valid, stricter posture." ; ok "opt-out annotation did not silently disable governance" ;;
  "")       bad "pod inject-skip never admitted" ;;
  *)        ok "opt-out annotation honoured (SkipAllowed=true) — governance is opt-out-able by a pod author, which RBAC must therefore control" ;;
esac

# ---------------------------------------------------------------------------------------------------
stage "5. The injector marks its work, and does not double-inject"
ANN="$(annotations inject-a)"
echo "$ANN" | grep -q "norviq.io/injected" && ok "pod is stamped norviq.io/injected" || note "no norviq.io/injected stamp (idempotency is keyed some other way)"
COUNT="$(containers inject-a | tr ' ' '\n' | grep -c norviq)"
[ "${COUNT:-0}" -le 1 ] && ok "exactly one norviq container (no double-injection)" || bad "${COUNT} norviq containers — the pod was injected more than once"

# ---------------------------------------------------------------------------------------------------
printf '\n%s\n' "======================================================================"
printf 'injection e2e: %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ] || exit 1
