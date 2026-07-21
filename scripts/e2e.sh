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

echo "▶ R10 — Playwright E2E against $BASE_URL"
( cd "$E2E_DIR" && [ -d node_modules/@playwright ] || npm ci --silent )
( cd "$E2E_DIR" && npx playwright install chromium >/dev/null 2>&1 || true )
PLAYWRIGHT_BASE_URL="$BASE_URL" NRVQ_TOKEN_FILE="$TOKEN_FILE" \
  bash -c "cd '$E2E_DIR' && npx playwright test --reporter=line"
echo "✓ R10 — Playwright E2E green (coverage matrix: $E2E_DIR/COVERAGE-MATRIX.md)"
