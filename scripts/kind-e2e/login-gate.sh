#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
#
# The e2e login gate: put the admin account into the state the real-form-login specs need, and print
# the password they should use.
#
# WHAT IT IS FOR. Eleven specs (auth-logout, catalog-hierarchy-batch2, compliance-remediation,
# consolidation-smoke, graph-global-ns-sync, graph-redteam-ux, graph-scope-search, overview-kpi,
# packs-governance-batch1, posture-apply-ux, posture-trust-controls) opt OUT of the seeded token —
# `test.use({ storageState: { cookies: [], origins: [] } })` — because driving the actual login form
# is the thing they exist to test. They read `NRVQ_E2E_PASSWORD` and fall back to the literal
# placeholder `CHANGE_ME-e2e-pw`.
#
# `overview-kpi.spec.ts:11` refers to "the gate" that resets admin to a known value with
# `must_change=false`. No such gate existed in this repository. Unset, those 27 tests did not skip —
# each waited 20 SECONDS for a navigation that could not happen and then failed pointing at a login
# helper rather than at the cause. Nine minutes of runtime, 27 failures, and nothing in the message
# naming the reason.
#
# WHY IT DRIVES THE REAL FLOW RATHER THAN SETTING A FLAG. `norviq.api.admin_reset` always sets
# `must_change=True`; that is deliberate, and a `--no-force-change` escape hatch would weaken a real
# security property for a test's convenience. So this uses only shipped endpoints, in the order a
# human would:
#
#   1. reset to a TEMPORARY password in-pod              -> must_change=True
#   2. POST /auth/login with it                          -> a token flagged must_change
#   3. POST /auth/change-password to the FINAL password  -> clears must_change
#
# The account ends in exactly the state the specs assume, the forced-change path is exercised rather
# than bypassed, and no test-only code reaches the product.
#
# Usage:
#   eval "$(scripts/kind-e2e/login-gate.sh)"   # exports NRVQ_E2E_PASSWORD into the calling shell
#   scripts/kind-e2e/login-gate.sh --quiet     # run the gate, print only the password

set -euo pipefail

NS="${NRVQ_NAMESPACE:-norviq}"
# Explicit context. The gate runs `kubectl exec` into the api pod, and defaulting to whatever context
# happens to be current is how a fixture ends up resetting the password on the WRONG cluster — or on
# none at all, silently, when the current context points at a cluster that has since been deleted.
KCTX="${NRVQ_KUBE_CONTEXT:-}"
KUBECTL=(kubectl)
[ -n "$KCTX" ] && KUBECTL=(kubectl --context "$KCTX")
BASE_URL="${PLAYWRIGHT_BASE_URL:-http://localhost:3400}"
USERNAME="${NRVQ_E2E_USERNAME:-admin}"

# Deterministic, not secret. This is a local test cluster's throwaway admin credential; it is printed
# to stdout by design so the caller can export it. Long enough to clear `auth_min_password_length`.
FINAL_PW="${NRVQ_E2E_PASSWORD:-nrvq-e2e-Passw0rd-2026}"
TEMP_PW="nrvq-e2e-Temp0rary-2026-xyz"

note() { [ "${1:-}" = "--quiet" ] || printf '%s\n' "$*" >&2; }
QUIET=""
[ "${1:-}" = "--quiet" ] && QUIET="--quiet"

fail() { printf 'login-gate: %s\n' "$*" >&2; exit 1; }

command -v kubectl >/dev/null || fail "kubectl not on PATH"
curl -sf -o /dev/null "${BASE_URL}/" || fail "console unreachable at ${BASE_URL} (port-forward svc/norviq-ui)"

# --- 1. reset in-pod to a temporary password -------------------------------------------------------
# A RUNNING, non-terminating pod — not `get pods -o name | head -1`, which is alphabetical order and
# will happily hand back a pod that is Completed, Terminating, or stuck in Init. `kubectl exec` into
# one of those fails, the reset never happens, and the 11 real-form-login specs (~27 tests) all fail
# on a 20s waitForURL timeout that says nothing about why. Observed exactly that on a cluster carrying
# an old ReplicaSet's pod in Init:1/2 alongside two healthy ones.
#
# scripts/kind-e2e/00-up.sh already learned this and documents it at length ("`.items[0]` is NOT safe
# here"). This script is the sibling that never got the fix.
api_pod="$("${KUBECTL[@]}" -n "$NS" get pods -l app.kubernetes.io/component=api \
  -o jsonpath='{range .items[*]}{.metadata.name}|{.metadata.deletionTimestamp}|{.status.phase}{"\n"}{end}' \
  | awk -F'|' '$2 == "" && $3 == "Running" { print $1; exit }')"
# Fall back to a NAME match only if the label lookup finds nothing, so a chart that labels differently
# still works rather than failing for a reason unrelated to the login.
#
# The fallback applies the SAME Running + non-terminating filter. It used to be a bare
# `get pods -o name | grep api | head -1`, which quietly reintroduced the exact defect the block above
# exists to prevent: on a cluster with no healthy api pod the label lookup returns empty, the fallback
# then returns a Terminating or Init pod, and the `[ -n ... ]` guard below is satisfied by that
# non-empty string — so the gate proceeds to exec into a pod that cannot answer, and reports it as
# "admin_reset failed" instead of "no live pod". A fallback that can defeat the guard it falls back
# past is worse than no fallback.
[ -n "$api_pod" ] || api_pod="$("${KUBECTL[@]}" -n "$NS" get pods \
  -o jsonpath='{range .items[*]}{.metadata.name}|{.metadata.deletionTimestamp}|{.status.phase}{"\n"}{end}' \
  | awk -F'|' '$1 ~ /api/ && $2 == "" && $3 == "Running" { print $1; exit }')"
api_pod="${api_pod#pod/}"
[ -n "$api_pod" ] || fail "no Running, non-terminating api pod in namespace ${NS}"

# stderr is NOT suppressed. It was, and that is why the gate could only ever say "in-pod admin_reset
# failed" while the actual message — the exec refusing a non-Running pod — went to /dev/null. This
# repo's own rule: never suppress the output of a step whose failure you have not yet seen.
reset_out="$("${KUBECTL[@]}" -n "$NS" exec "$api_pod" -c api -- \
  python -m norviq.api.admin_reset --username "$USERNAME" --password "$TEMP_PW" 2>&1)" \
  || fail "in-pod admin_reset failed for '${USERNAME}' on pod ${api_pod}: ${reset_out}"

# --- 2. log in with it, collecting the must_change token -------------------------------------------
login_body="$(curl -sS -X POST "${BASE_URL}/api/v1/auth/login" \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"${USERNAME}\",\"password\":\"${TEMP_PW}\"}")"
# `access_token`, not `token` — the field name is the one the login response actually uses.
token="$(printf '%s' "$login_body" | sed -n 's/.*"access_token"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
[ -n "$token" ] || fail "login with the temporary password returned no token: ${login_body:0:200}"

# --- 3. complete the forced change to the FINAL password -------------------------------------------
change_body="$(curl -sS -o /dev/null -w '%{http_code}' -X POST "${BASE_URL}/api/v1/auth/change-password" \
  -H 'Content-Type: application/json' -H "Authorization: Bearer ${token}" \
  -d "{\"current_password\":\"${TEMP_PW}\",\"new_password\":\"${FINAL_PW}\"}")"
[ "$change_body" = "200" ] || fail "change-password returned HTTP ${change_body} (expected 200)"

# --- 4. PROVE it, rather than assuming -------------------------------------------------------------
# The whole point is `must_change=false`. Asserting it here means a silent regression in the reset or
# change path fails HERE, with a clear message, instead of 27 tests later as a navigation timeout.
verify="$(curl -sS -X POST "${BASE_URL}/api/v1/auth/login" \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"${USERNAME}\",\"password\":\"${FINAL_PW}\"}")"
printf '%s' "$verify" | grep -q '"must_change"[[:space:]]*:[[:space:]]*false' \
  || fail "admin still has must_change set after the change — the form-login specs would still fail: ${verify:0:200}"

# --- 5. REPLACE the seeded token, because changing the password REVOKED it ---------------------------
#
# This is not tidiness — it is the whole correctness of the gate. Changing a password revokes that
# user's outstanding tokens, and ~160 of the suite's ~190 tests authenticate with the token in
# $NRVQ_TOKEN_FILE rather than through the form. Running the gate without this step fixed 27 tests and
# broke 160: a run went from 59 failed to 173 failed, and the new failures pointed at every page in
# the console rather than at the credential that had just been invalidated underneath them.
#
# The verification login above already returned a token for the FINAL password with must_change
# cleared — exactly the token the rest of the suite needs — so it is written back rather than minted
# again.
TOKEN_FILE="${NRVQ_TOKEN_FILE:-/tmp/nrvq-signin-token.txt}"
fresh_token="$(printf '%s' "$verify" | sed -n 's/.*"access_token"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
[ -n "$fresh_token" ] || fail "the verification login returned no token to re-seed ${TOKEN_FILE} with"
printf '%s' "$fresh_token" > "$TOKEN_FILE"

note "$QUIET" "login-gate: '${USERNAME}' ready with must_change=false; ${TOKEN_FILE} re-seeded"
# The only thing on stdout, so `eval "$(...)"` works.
printf 'export NRVQ_E2E_PASSWORD=%s\n' "$FINAL_PW"
