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
if [ -z "${NRVQ_E2E_PASSWORD:-}" ] && [ -x "$(dirname "$0")/kind-e2e/login-gate.sh" ]; then
  if gate_out="$(PLAYWRIGHT_BASE_URL="$BASE_URL" "$(dirname "$0")/kind-e2e/login-gate.sh" 2>/dev/null)"; then
    eval "$gate_out"
    export NRVQ_E2E_PASSWORD
    echo "\u25b6 login gate: admin ready (must_change=false) for the 11 form-login specs"
  else
    # Not fatal — the other ~160 specs authenticate via the seeded token and are unaffected. But say
    # so loudly, because the alternative is 27 silent 20-second timeouts.
    echo "WARNING: login gate FAILED — the 11 real-form-login specs (~27 tests) will fail on a 20s" >&2
    echo "  page.waitForURL timeout. Run scripts/kind-e2e/login-gate.sh directly to see why." >&2
  fi
fi

echo "▶ R10 — Playwright E2E against $BASE_URL"
( cd "$E2E_DIR" && [ -d node_modules/@playwright ] || npm ci --silent )
( cd "$E2E_DIR" && npx playwright install chromium >/dev/null 2>&1 || true )
PLAYWRIGHT_BASE_URL="$BASE_URL" NRVQ_TOKEN_FILE="$TOKEN_FILE" \
  bash -c "cd '$E2E_DIR' && npx playwright test --reporter=line"
echo "✓ R10 — Playwright E2E green (coverage matrix: $E2E_DIR/COVERAGE-MATRIX.md)"
