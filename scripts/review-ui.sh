#!/usr/bin/env bash
set -euo pipefail

FEAT="${1:?Usage: ./scripts/review-ui.sh F018}"
REVIEW_DIR=".reviews"
REVIEW_FILE="${REVIEW_DIR}/${FEAT}-ui.md"
mkdir -p "$REVIEW_DIR"

echo "════════════════════════════════════════════════════"
echo "  Norviq UI Review: ${FEAT}"
echo "════════════════════════════════════════════════════"

PASS=0
FAIL=0
CHECK_LOG=""

run_check() {
  local name="$1" cmd="$2"
  local out
  out=$(eval "$cmd" 2>&1) || true
  if echo "$out" | grep -qE "PASS|passed|^0$"; then
    echo "  ✅ ${name}"
    CHECK_LOG="${CHECK_LOG}| ${name} | PASS | clean |\n"
    PASS=$((PASS+1))
  else
    echo "  ❌ ${name}: $(echo "$out" | head -1)"
    CHECK_LOG="${CHECK_LOG}| ${name} | FAIL | $(echo "$out" | head -1) |\n"
    FAIL=$((FAIL+1))
  fi
}

echo "��� Running UI checks..."

# Build check
run_check "npm build" "cd ui && npm run build 2>&1 | tail -1 && cd .."

# TypeScript
run_check "TypeScript" "cd ui && npx tsc --noEmit 2>&1 | tail -1 && cd .."

# Font files
run_check "Outfit fonts" "test -f ui/public/fonts/Outfit-Regular.ttf && echo PASS || echo FAIL"

# Logo assets
run_check "Logo SVG" "test -f ui/public/norviq-mark.svg && echo PASS || echo FAIL"

# Design system CSS
run_check "CSS variables" "grep -q 'bg-void\|bg-surface' ui/src/index.css && echo PASS || echo FAIL"

# Font family
run_check "Outfit font-family" "grep -qi 'outfit' ui/src/index.css && echo PASS || echo FAIL"

# Pages exist
run_check "Dashboard page" "test -f ui/src/pages/Dashboard.tsx && echo PASS || echo FAIL"
run_check "Policies page" "test -f ui/src/pages/Policy*.tsx && echo PASS || echo FAIL"
run_check "Audit page" "test -f ui/src/pages/Audit*.tsx && echo PASS || echo FAIL"
run_check "Agents page" "test -f ui/src/pages/Agent*.tsx && echo PASS || echo FAIL"
run_check "Threats page" "test -f ui/src/pages/Threat*.tsx && echo PASS || echo FAIL"
run_check "Settings page" "test -f ui/src/pages/Settings.tsx && echo PASS || echo FAIL"

# Components exist
run_check "KPI Card" "find ui/src -name '*KPI*' -o -name '*kpi*' | grep -q . && echo PASS || echo FAIL"
run_check "Decision Badge" "find ui/src -name '*Badge*' -o -name '*badge*' -o -name '*Decision*' | grep -q . && echo PASS || echo FAIL"
run_check "Sidebar" "find ui/src -name '*Sidebar*' -o -name '*sidebar*' | grep -q . && echo PASS || echo FAIL"

# API integration
run_check "API client" "find ui/src -name '*api*' -o -name '*client*' | grep -q . && echo PASS || echo FAIL"
run_check "No hardcoded URLs" "grep -rn 'localhost:8080\|127.0.0.1:8080' ui/src/ 2>/dev/null | wc -l | xargs test 0 -eq && echo PASS || echo FAIL"

echo ""
echo "════════════════════════════════════════════════════"
echo "  Result: ${PASS}/$((PASS+FAIL)) passed, ${FAIL}/$((PASS+FAIL)) failed"
echo "════════════════════════════════════════════════════"
echo ""

echo "��� Claude Code UI deep review..."
echo ""

claude "Review the Norviq UI for feature ${FEAT}.

## Automated Check Results (trust these, do NOT re-run):
| Check | Result | Details |
|-------|--------|---------|
$(echo -e "$CHECK_LOG")

Total: ${PASS}/$((PASS+FAIL)) passed

## Instructions:
- Read docs/design-system/colors_and_type.css for the design system
- Read docs/design-system/SKILL for component specs
- Read each preview HTML in docs/design-system/preview/ and compare against corresponding component in ui/src/
- Check: Do colors match? Do fonts match? Do spacings match? Do component patterns match?
- Check all 6 pages exist and are routable
- Check design system assets are used (logo, fonts)
- Check API integration (all F017 endpoints called via proxy, no hardcoded URLs)
- Check badge colors consistent across all pages (ALLOW/BLOCK/ESCALATE/AUDIT)
- Report MATCH or MISMATCH for each design system preview vs actual component
- This is a FRESH review. Ignore previous reviews." --print | tee "${REVIEW_FILE}"

echo ""
echo "════════════════════════════════════════════════════"
echo "  Review written to: ${REVIEW_FILE}"
echo "════════════════════════════════════════════════════"
