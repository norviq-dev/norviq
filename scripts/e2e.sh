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

# PREFLIGHT: the real-form-login specs.
#
# Eleven specs opt OUT of the seeded storageState token (`test.use({ storageState: {} })`) and drive
# the actual login form, because that is the thing they exist to test. They read the password from
# NRVQ_E2E_PASSWORD and fall back to the literal placeholder "CHANGE_ME-e2e-pw", which is never any
# cluster's admin password. Nothing in this repo sets that variable.
#
# Unset, those 27 tests do not skip — they each wait 20 SECONDS for a navigation that cannot happen,
# then fail with `page.waitForURL: Timeout 20000ms exceeded` pointing at a helper rather than at the
# cause. That is nine minutes of runtime producing 27 failures whose message names nothing useful; it
# cost most of a session to trace once, which is exactly why this check is loud and up front.
#
# Not fatal: the other ~160 tests are perfectly valid without it, and refusing to run them would be a
# worse trade. Stated plainly, before the run, so the summary is never a mystery.
if [ -z "${NRVQ_E2E_PASSWORD:-}" ]; then
  cat >&2 <<'WARN'
⚠ NRVQ_E2E_PASSWORD is not set.

  The 11 real-form-login specs (auth-logout, catalog-hierarchy-batch2, compliance-remediation,
  consolidation-smoke, graph-global-ns-sync, graph-redteam-ux, graph-scope-search, overview-kpi,
  packs-governance-batch1, posture-apply-ux, posture-trust-controls) will FAIL — roughly 27 tests,
  each after a 20s `page.waitForURL` timeout.

  They need the admin account reset to a known password with must_change=false, and that password
  exported here. Every other spec authenticates via the seeded token and is unaffected.

WARN
fi

echo "▶ R10 — Playwright E2E against $BASE_URL"
( cd "$E2E_DIR" && [ -d node_modules/@playwright ] || npm ci --silent )
( cd "$E2E_DIR" && npx playwright install chromium >/dev/null 2>&1 || true )
PLAYWRIGHT_BASE_URL="$BASE_URL" NRVQ_TOKEN_FILE="$TOKEN_FILE" \
  bash -c "cd '$E2E_DIR' && npx playwright test --reporter=line"
echo "✓ R10 — Playwright E2E green (coverage matrix: $E2E_DIR/COVERAGE-MATRIX.md)"
