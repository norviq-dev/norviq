#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
set -uo pipefail

# ═══════════════════════════════════════════════════════════════════════════
# Norviq verification tiers — T1..T5. A 200 is NOT proof (see AGENTS.md rule 1).
#
# Usage:
#   scripts/verify.sh <FEAT> [--tier T1|T2|T3|T4|T5|all]   (default: all)
#   scripts/verify.sh <FEAT> --tier T1        # author's fast local pre-hand-off
#
# Tiers:
#   T1 STATIC+UNIT   ruff · tsc · opa check+test · vitest unit · pytest unit · fast SAST   (fail-closed)
#   T2 INTEGRATION   attack suite (78/78) · webhook · fleet — on KIND ONLY (never AKS)      (fail-closed)
#   T3 REGRESSION    full pytest + full vitest, zero NEW failures vs baseline               (fail-closed)
#   T4 EFFECT        drive real UI+backend on kind, EMIT evidence for the reviewer          (NOT a 200)
#   T5 SECURITY      the SAST gate is green — no NEW high/critical                           (fail-closed)
#
# T4 never self-certifies: it produces before/after screenshots + a decision-flip log under
# .reviews/<FEAT>-t4-evidence/ and exits "evidence-emitted". The REVIEWER (Claude) asserts the effect.
# ═══════════════════════════════════════════════════════════════════════════

FEAT="${1:?Usage: scripts/verify.sh FEATURE_ID [--tier T1|T2|T3|T4|T5|all]}"
TIER="all"
if [ "${2:-}" = "--tier" ]; then TIER="${3:-all}"; fi

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
EVID_DIR=".reviews/${FEAT}-t4-evidence"
FAILED=0

say()  { printf '\n\033[1m▶ %s\033[0m\n' "$*"; }
pass() { printf '  \033[32m✔ %s\033[0m\n' "$*"; }
warn() { printf '  \033[33m⚠ %s\033[0m\n' "$*"; }
fail() { printf '  \033[31m✗ %s\033[0m\n' "$*"; FAILED=1; }

# Run a required check: fail-closed if the tool is present and the check fails.
# If the tool is MISSING locally, warn (CI enforces it via security.yml / the gate).
req() { # req "<label>" <cmd...>
  local label="$1"; shift
  if ! command -v "$1" >/dev/null 2>&1; then warn "$label — '$1' not installed (CI enforces)"; return 0; fi
  if "$@" >/dev/null 2>&1; then pass "$label"; else fail "$label"; fi
}

req_in_dir() { # req_in_dir "<dir>" "<label>" <cmd...>
  local dir="$1"; shift
  local label="$1"; shift
  if ! command -v "$1" >/dev/null 2>&1; then warn "$label — '$1' not installed (CI enforces)"; return 0; fi
  if ( cd "$dir" && "$@" >/dev/null 2>&1 ); then pass "$label"; else fail "$label"; fi
}

# Refuse T2/T4 against AKS — its teardowns delete policy rows (see AGENTS.md rule 4 + baseline doc).
guard_not_aks() {
  local ctx; ctx="$(kubectl config current-context 2>/dev/null || echo none)"
  case "$ctx" in
    norviq|*aks*|*eastus*) fail "REFUSING to run integration/effect tiers against AKS context '$ctx' — use kind"; return 1 ;;
    *) pass "kube context '$ctx' is not AKS — safe for kind integration" ;;
  esac
}

# Require explicit AKS context + served cluster identity for post-deploy checks.
# This prevents accidental verification against local kind contexts.
guard_aks_context() {
  local expected_ctx="${1:-norviq}"
  local expected_cluster="${2:-aks-dev}"
  local ctx cluster_id

  ctx="$(kubectl config current-context 2>/dev/null || echo none)"
  if [ "$ctx" != "$expected_ctx" ]; then
    fail "AKS preflight failed: current context '$ctx' != '$expected_ctx'"
    return 1
  fi
  pass "AKS preflight: context '$ctx' confirmed"

  if ! command -v curl >/dev/null 2>&1; then
    fail "AKS preflight failed: curl required for cluster-info check"
    return 1
  fi

  # Require an explicit bearer token from the caller to keep this guard read-only.
  if [ -z "${NRVQ_API_TOKEN:-}" ]; then
    fail "AKS preflight failed: set NRVQ_API_TOKEN to query /api/v1/cluster-info"
    return 1
  fi

  cluster_id="$(curl -fsS \
    -H "Authorization: Bearer ${NRVQ_API_TOKEN}" \
    "${NRVQ_API_BASE_URL:-http://127.0.0.1:8080}/api/v1/cluster-info" \
    | python3 -c 'import json,sys; print(json.load(sys.stdin).get("cluster_id",""))' 2>/dev/null || true)"

  if [ "$cluster_id" != "$expected_cluster" ]; then
    fail "AKS preflight failed: served cluster_id '$cluster_id' != '$expected_cluster'"
    return 1
  fi
  pass "AKS preflight: served cluster_id '$cluster_id' confirmed"
}

# ─── T1 — static + unit (fast; fail-closed) ────────────────────────────────
tier_t1() {
  say "T1 — static + unit"
  req "ruff"           ruff check norviq/ tests/
  req_in_dir "ui" "tsc (ui)" npx --no-install tsc --noEmit
  req "opa check"      opa check --v0-compatible comprehensive.rego policies/
  req "opa test"       opa test --v0-compatible policies/
  req_in_dir "ui" "vitest unit" npm run test:run --silent
  # pytest unit only — attacks/integration run in T2
  req "pytest unit"    pytest tests/ -q --ignore=tests/attacks -p no:cacheprovider
  # fast SAST subset (secrets + python) — full set is T5 / security.yml
  req "bandit (fast)"  bandit -q -r norviq/ -ll
  req "gitleaks (diff)" gitleaks protect --staged --no-banner
}

# ─── T2 — integration on kind only (fail-closed) ───────────────────────────
tier_t2() {
  say "T2 — integration (kind only)"
  guard_not_aks || return
  req "attacks 78/78"  pytest tests/attacks -q -p no:cacheprovider
  req "webhook inject" pytest tests/webhook -q -p no:cacheprovider
  req "fleet push/pull" pytest tests/fleet -q -p no:cacheprovider
}

# ─── T3 — full regression, zero NEW failures vs baseline (fail-closed) ──────
tier_t3() {
  say "T3 — regression (zero new failures vs baseline)"
  req "pytest full"    pytest tests/ -q -p no:cacheprovider
  req_in_dir "ui" "vitest full" npm run test:run --silent
  if [ -f tests/.baseline ]; then
    pass "baseline present: $(head -1 tests/.baseline)"
  else
    warn "no tests/.baseline snapshot — record current full-suite pass + attacks 78/78 so 'zero new' is checkable"
  fi
}

# ─── T4 — end-to-end EFFECT: EMIT evidence, do NOT self-certify ─────────────
tier_t4() {
  say "T4 — end-to-end EFFECT (emit evidence for the reviewer; a 200 is NOT proof)"
  guard_not_aks || return
  mkdir -p "$EVID_DIR"
  warn "T4 does not pass/fail here — it produces evidence the REVIEWER inspects."
  echo "  Author must drop into $EVID_DIR:"
  echo "    - before.png / after.png (UI state change: open AND close; or /evaluate before+after)"
  echo "    - decision-flip.log       (allow↔block on RUNNING pods — remember the seed→reload gotcha)"
  echo "    - notes.md                (what route/control/decision was exercised, and the expected effect)"
  # If a headless driver exists, run it to generate the evidence (non-blocking on absence).
  if [ -x scripts/review-ui.sh ]; then
    warn "running scripts/review-ui.sh to capture UI screenshots into $EVID_DIR (best-effort)"
    EVID_DIR="$EVID_DIR" bash scripts/review-ui.sh "$FEAT" || warn "review-ui.sh incomplete — capture evidence manually"
  fi
  if [ -s "$EVID_DIR/decision-flip.log" ] || ls "$EVID_DIR"/*.png >/dev/null 2>&1; then
    pass "T4 evidence present in $EVID_DIR — reviewer must ASSERT the effect (not accept a 200)"
  else
    warn "no T4 evidence yet — reviewer will REJECT a UI/enforcement change without it"
  fi
}

# ─── T5 — security gate (fail-closed on NEW high/critical) ──────────────────
tier_t5() {
  say "T5 — security gate (no NEW high/critical)"
  req "bandit"     bandit -q -r norviq/ -ll
  req "semgrep"    semgrep --error --quiet --config=auto norviq/ ui/src
  req "pip-audit"  pip-audit -q
  req "gitleaks"   gitleaks detect --no-banner --redact --log-opts="-1"
  req_in_dir "ui" "npm audit (high)" npm audit --audit-level=high
  req "checkov (helm/crds)" checkov -d helm --quiet --compact
  req "kube-linter" kube-linter lint helm/
  echo "  (Container-image trivy runs post-build in build.yml, not here — images don't exist at PR/local time.)"
}

case "$TIER" in
  T1) tier_t1 ;;
  T2) tier_t2 ;;
  T3) tier_t3 ;;
  T4) tier_t4 ;;
  T5) tier_t5 ;;
  all) tier_t1; tier_t5; tier_t2; tier_t3; tier_t4 ;;
  *) echo "Unknown tier '$TIER' (T1|T2|T3|T4|T5|all)"; exit 2 ;;
esac

echo ""
if [ "$FAILED" -ne 0 ]; then
  printf '\033[31m✗ verify.sh %s [%s]: FAIL-CLOSED — fix the red tiers before review.\033[0m\n' "$FEAT" "$TIER"
  exit 1
fi
printf '\033[32m✓ verify.sh %s [%s]: gate tiers green. T4 effect is asserted by the reviewer from evidence.\033[0m\n' "$FEAT" "$TIER"
exit 0
