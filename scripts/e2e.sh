#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
#
# Playwright END-TO-END gate. Drives the REAL console + backend on kind (never AKS) and asserts
# UI + backend TOGETHER (not just 200s): every route renders with zero console errors / zero API
# failures, every interactive control produces its effect + the right API call, plus the Attack Graph
# and Asset Graph regression suite (horizontal on-screen kill-chain, normal-weight labels, no inner
# scrollbars, global intent → dry-run draft that surfaces in Policies, crisp asset-graph, clickable
# stat tiles) and the audit/PEP block visibility.
#
# Usage (against a running kind deployment):
#   kubectl -n norviq port-forward svc/norviq-ui 3400:80 &
#   printf '%s' "$NRVQ_ADMIN_JWT" > /tmp/nrvq-signin-token.txt   # admin HS256 token (role=admin, ns=*)
#   PLAYWRIGHT_BASE_URL=http://localhost:3400 bash scripts/e2e.sh
#
# CI job: after `helm install` on the ephemeral kind cluster + a healthz gate, port-forward the
# UI, mint an admin token into $NRVQ_TOKEN_FILE, then run this. Fails closed on any spec failure.
set -euo pipefail

E2E_DIR="ui/tests/e2e"
BASE_URL="${PLAYWRIGHT_BASE_URL:-http://localhost:3400}"
TOKEN_FILE="${NRVQ_TOKEN_FILE:-/tmp/nrvq-signin-token.txt}"

[ -s "$TOKEN_FILE" ] || { echo "✗ R10: admin token file '$TOKEN_FILE' missing/empty (mint an HS256 admin token first)"; exit 2; }
curl -fsS -o /dev/null "$BASE_URL/" || { echo "✗ R10: console not reachable at $BASE_URL (port-forward svc/norviq-ui)"; exit 2; }

# THE LOGIN GATE. Eleven specs opt OUT of the seeded storageState token
# (`test.use({ storageState: {} })`) and drive the real login form, because that is the thing they
# exist to test. They read NRVQ_E2E_PASSWORD and fall back to the literal placeholder
# "CHANGE_ME-e2e-pw". `overview-kpi.spec.ts:11` refers to "the gate" that resets admin to a known
# value with must_change=false — and no such gate existed in this repo.
#
# Unset, those 27 tests did not skip. Each waited 20 SECONDS for a navigation that could not happen,
# then failed pointing at a login helper rather than at the cause: nine minutes of runtime producing
# 27 failures whose messages named nothing useful.
#
# `login-gate.sh` drives the real reset -> login -> forced-change flow (no test-only backdoor) and
# asserts must_change=false before returning. Skipped when the caller already exported a password, so
# a CI job managing its own credential is not overridden.
# A SUPPLIED PASSWORD MUST BE VERIFIED, exactly like the token below. The skip-if-exported rule
# exists so a CI job managing its own credential is not overridden — but it also means that exporting
# a WRONG password silently disables the gate that would have fixed it. On a freshly rebuilt cluster
# the admin credential is new, and a value carried over from the previous cluster 401s: ~27 form-login
# tests then fail on a 20s page.waitForURL timeout, naming nothing useful. That is precisely the
# failure the gate was written to prevent, arriving through the door marked "trust the caller".
# Clearing the failed-attempt counter is part of PREPARING to authenticate, not a workaround.
# `admin` locks out after N failures (auth_login_max_attempts) and the lock is a plain Redis counter,
# `callcount:login-fail:<user>`. The login gate itself performs three logins, so it cannot recover a
# locked account — it just inherits the 429 and reports a failure that has nothing to do with the
# credential. Verifying a password COSTS one of those attempts, which is how this bit me: the probe
# below tripped the lock, and the gate that would have fixed everything then failed with
# "Too many failed attempts."
clear_login_lockout() {
  # `|| true` on BOTH lookups is load-bearing, not defensive noise. Under `set -euo pipefail` an
  # assignment from a failing command substitution aborts the script, and `kubectl get pods -l <label>`
  # exits NON-ZERO when nothing matches. The redis pod is labelled `app=norviq-redis`, not
  # `app.kubernetes.io/name=redis` — so this function killed e2e.sh on its first call, before a single
  # line of output, and because I had also sent kubectl's stderr to /dev/null there was nothing at all
  # to read: a zero-byte log and exit 1. Suppressing the output of a step whose failure you have not
  # yet seen, again, in the very file that documents the rule.
  local pod pw
  pod="$(kubectl ${NRVQ_KUBE_CONTEXT:+--context "$NRVQ_KUBE_CONTEXT"} -n "${NRVQ_NAMESPACE:-norviq}" \
    get pods -l app=norviq-redis -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"
  [ -n "$pod" ] || pod="norviq-redis-0"
  pw="$(kubectl ${NRVQ_KUBE_CONTEXT:+--context "$NRVQ_KUBE_CONTEXT"} -n "${NRVQ_NAMESPACE:-norviq}" \
    get secret norviq-secrets -o go-template='{{index .data "NRVQ_REDIS_PASSWORD" | base64decode}}' 2>/dev/null || true)"
  kubectl ${NRVQ_KUBE_CONTEXT:+--context "$NRVQ_KUBE_CONTEXT"} -n "${NRVQ_NAMESPACE:-norviq}" \
    exec "$pod" -- sh -c "redis-cli ${pw:+-a '$pw'} --no-auth-warning DEL callcount:login-fail:admin" \
    >/dev/null 2>&1 || true
  # Also start from a COLD http bucket. The limiter keys on the JWT `sub` and every spec carries the
  # same admin token, so a previous run's window carries over into this one's first minute and the
  # 429s land on whichever spec is unlucky. That is what made the failing set move between runs while
  # the count stayed flat — a moving set is the signature G3 uses to detect leaked state, so leaving
  # it in place would make the gate unpassable for a reason that has nothing to do with the product.
  kubectl ${NRVQ_KUBE_CONTEXT:+--context "$NRVQ_KUBE_CONTEXT"} -n "${NRVQ_NAMESPACE:-norviq}" \
    exec "$pod" -- sh -c "redis-cli ${pw:+-a '$pw'} --no-auth-warning --scan --pattern 'callcount:http:*' | xargs -r redis-cli ${pw:+-a '$pw'} --no-auth-warning DEL" \
    >/dev/null 2>&1 || true
}

if [ -n "${NRVQ_E2E_PASSWORD:-}" ]; then
  _pw_code="$(curl -s -o /dev/null -w '%{http_code}' -X POST -H "Content-Type: application/json" \
    -d "{\"username\":\"admin\",\"password\":\"${NRVQ_E2E_PASSWORD}\"}" \
    "$BASE_URL/api/v1/auth/login")"
  case "$_pw_code" in
    200)
      echo "password: supplied NRVQ_E2E_PASSWORD verified" ;;
    429)
      # NOT a wrong password — the account is locked, and every further attempt digs the hole deeper.
      # Distinguishing this from 401 is the whole point of reading the status instead of `curl -sf`.
      echo "password: admin is locked out (HTTP 429) — clearing the counter, then re-checking" >&2
      clear_login_lockout
      _pw_code="$(curl -s -o /dev/null -w '%{http_code}' -X POST -H "Content-Type: application/json" \
        -d "{\"username\":\"admin\",\"password\":\"${NRVQ_E2E_PASSWORD}\"}" \
        "$BASE_URL/api/v1/auth/login")"
      [ "$_pw_code" = "200" ] && echo "password: verified after clearing the lockout" \
        || { echo "password: still rejected (HTTP ${_pw_code}) — running the login gate" >&2; unset NRVQ_E2E_PASSWORD; } ;;
    *)
      echo "password: supplied NRVQ_E2E_PASSWORD is REJECTED (HTTP ${_pw_code}) — running the login gate" >&2
      unset NRVQ_E2E_PASSWORD ;;
  esac
fi

# The gate performs three logins of its own; give it a clean counter to spend, whether the failures
# above came from this run or a previous one.
[ -z "${NRVQ_E2E_PASSWORD:-}" ] && clear_login_lockout

if [ -z "${NRVQ_E2E_PASSWORD:-}" ] && [ -x "$(dirname "$0")/kind-e2e/login-gate.sh" ]; then
  # stderr is NOT suppressed. The first version sent it to /dev/null, so when the gate failed — it
  # was reaching for whatever kubectl context happened to be current, which after a cluster delete was
  # a dangling one — the run printed "login gate FAILED" and nothing about WHY, and 27 tests failed
  # again. Suppressing the output of a step whose failure you have not yet seen is how a fixable
  # error becomes an unexplained one.
  if gate_out="$(PLAYWRIGHT_BASE_URL="$BASE_URL" NRVQ_KUBE_CONTEXT="${NRVQ_KUBE_CONTEXT:-}" \
                 NRVQ_NAMESPACE="${NRVQ_NAMESPACE:-norviq}" \
                 "$(dirname "$0")/kind-e2e/login-gate.sh")"; then
    eval "$gate_out"
    export NRVQ_E2E_PASSWORD
    echo "login gate: admin ready (must_change=false) for the 11 form-login specs"
  else
    # Not fatal — the other ~160 specs authenticate via the seeded token and are unaffected. But say
    # so loudly, because the alternative is 27 silent 20-second timeouts.
    echo "WARNING: login gate FAILED — the 11 real-form-login specs (~27 tests) will fail on a 20s" >&2
    echo "  page.waitForURL timeout. Run scripts/kind-e2e/login-gate.sh directly to see why." >&2
  fi
fi

# THE TOKEN MUST ACTUALLY WORK. Not "the file exists" — the file always exists, it just goes stale.
#
# ~160 of the 190 specs authenticate with the token in $TOKEN_FILE. `token_mint --ttl 7200` gives it
# two hours; a full serial run is twenty minutes, and the file survives across runs, so a token minted
# earlier in a working session expires silently between one run and the next. Nothing checked it.
#
# What that looks like: 136 failed, 38 passed, ONE HOUR AND FORTY-TWO MINUTES — because every spec sat
# through its own 60s timeout waiting for content that a 401 was never going to deliver. The failure
# list named 136 different features and not one of them was broken. Worse, it arrived immediately
# after a seeding change, and the obvious reading — "the change I just made broke everything" — was
# wrong.
#
# It is also reachable through the front door: the login gate above re-seeds this file, and it is
# skipped whenever the caller exports NRVQ_E2E_PASSWORD. Doing exactly that is what left the stale
# token in place. So the check lives HERE, after the gate, unconditional.
if [ -s "$TOKEN_FILE" ] && curl -sf -o /dev/null -H "Authorization: Bearer $(cat "$TOKEN_FILE")" \
     "$BASE_URL/api/v1/version"; then
  echo "token: valid"
else
  echo "token: MISSING OR EXPIRED — re-minting rather than running 190 specs against a 401" >&2
  _api_pod="$(kubectl ${NRVQ_KUBE_CONTEXT:+--context "$NRVQ_KUBE_CONTEXT"} -n "${NRVQ_NAMESPACE:-norviq}" \
    get pods -l app.kubernetes.io/component=api \
    -o jsonpath='{range .items[*]}{.metadata.name}|{.metadata.deletionTimestamp}|{.status.phase}{"\n"}{end}' \
    2>/dev/null | awk -F'|' '$2 == "" && $3 == "Running" { print $1; exit }')"
  if [ -n "$_api_pod" ]; then
    kubectl ${NRVQ_KUBE_CONTEXT:+--context "$NRVQ_KUBE_CONTEXT"} -n "${NRVQ_NAMESPACE:-norviq}" \
      exec "$_api_pod" -c api -- python -m norviq.api.token_mint --ttl 28800 2>/dev/null \
      | tail -1 > "$TOKEN_FILE"
  fi
  # Re-check, and REFUSE to run if it still fails. A 20-minute suite whose every assertion is a
  # disguised 401 is worse than no run: it produces a failure list that reads as 136 product defects.
  curl -sf -o /dev/null -H "Authorization: Bearer $(cat "$TOKEN_FILE" 2>/dev/null)" \
    "$BASE_URL/api/v1/version" \
    || { echo "✗ R10: no working admin token for $BASE_URL — refusing to run the suite" >&2; exit 2; }
  echo "token: re-minted and verified"
fi

# NRVQ_API_URL. Four specs (audit-filters-and-volume, and the traffic-generating helpers others
# share) POST to `${NRVQ_API_URL}/api/v1/evaluate` and default to `http://127.0.0.1:18080` — a port
# nothing in this script forwards. Unset, they fail with `connect ECONNREFUSED 127.0.0.1:18080`,
# which reads as a broken backend rather than as a missing variable.
#
# The console already proxies `/api/v1` to the API — every other spec and `seed.py` reach the API
# through it — so the base URL is the correct value and needs no extra forward.
export NRVQ_API_URL="${NRVQ_API_URL:-$BASE_URL}"

# RESET + SEED before every run. The suite mutates shared, namespace-scoped state — enforcing policies
# for throwaway classes, `apply_mode: dry_run_only`, `enforcement_mode: audit` — and a spec that fails
# partway leaves it behind, so the NEXT run fails somewhere else entirely. Measured across consecutive
# full runs the failing SET moved while the count stayed flat, which is the signature of leaked state
# rather than of N separate defects. Starting from a known baseline is what makes a run comparable to
# the one before it.
#
# A FAILED SEED ABORTS THE RUN. This used to warn and carry on, and that cost a full 7.3-minute run to
# diagnose: `seed_redteam` timed out, `main` exited before `seed_backdate`, and the only visible
# symptom was `range-selector-scope.spec.ts` failing because the 1h and 24h windows held identical
# traffic. 189 specs passed. The one that failed named the range selector, and the range selector was
# fine — the week of backdated rows it measures had never been written.
#
# That is the same argument as the paragraph above, one level up: a run against a partially-seeded
# cluster is not a weaker signal, it is a MISLEADING one, because the failure surfaces wherever the
# missing fixture happens to be read rather than where it was missed. `seed.py` already returns a
# nonzero count of failed steps; honour it.
if [ -x "$(dirname "$0")/kind-e2e/seed.py" ] || [ -f "$(dirname "$0")/kind-e2e/seed.py" ]; then
  if [ -x .venv/bin/python ]; then
    if .venv/bin/python "$(dirname "$0")/kind-e2e/seed.py" --base-url "$BASE_URL" --token-file "$TOKEN_FILE" \
         >/tmp/nrvq-e2e-seed.log 2>&1; then
      echo "seed: reset + fixtures applied"
    else
      echo "FATAL: seeding failed — refusing to run against a partially-seeded cluster." >&2
      echo "       A run started here reports the failure wherever the missing fixture is READ," >&2
      echo "       not where it was missed. Last 20 lines of /tmp/nrvq-e2e-seed.log:" >&2
      tail -20 /tmp/nrvq-e2e-seed.log >&2
      exit 1
    fi
  fi
fi

echo "▶ R10 — Playwright E2E against $BASE_URL"
( cd "$E2E_DIR" && [ -d node_modules/@playwright ] || npm ci --silent )
( cd "$E2E_DIR" && npx playwright install chromium >/dev/null 2>&1 || true )
# WORKER COUNT. The config defaults to 3, and 3 workers share ONE storageState token against a
# backend with ONE admin identity — so a spec that logs out or rotates the password breaks whatever is
# running beside it. Measured over full runs: 3 workers gave 21 failed / 12 flaky, 1 worker gave
# noticeably fewer of both. Serial costs ~21m against ~9m, which is the right trade for a gate whose
# whole value is that its result means something; override for a quick local sweep.
#
# ALWAYS run this script rather than calling playwright directly: it exports NRVQ_API_URL (four specs
# otherwise hit an unforwarded 127.0.0.1:18080 and fail with ECONNREFUSED, which reads as a broken
# backend) and it resets + seeds first. A direct `npx playwright test` skips both and produces failures
# that belong to the invocation, not to the product — that mistake cost a whole 21-minute run.
PLAYWRIGHT_BASE_URL="$BASE_URL" NRVQ_TOKEN_FILE="$TOKEN_FILE" \
  bash -c "cd '$E2E_DIR' && npx playwright test --workers=${NRVQ_E2E_WORKERS:-1} --reporter=line"
echo "✓ R10 — Playwright E2E green (coverage matrix: $E2E_DIR/COVERAGE-MATRIX.md)"
