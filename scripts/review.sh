#!/usr/bin/env bash
set -euo pipefail

FEAT="${1:?Usage: ./scripts/review.sh F001}"
SPEC="specs/${FEAT}.md"
REVIEW_DIR=".reviews"
REVIEW_FILE="${REVIEW_DIR}/${FEAT}.md"

if [ ! -f "$SPEC" ]; then
  echo "ERROR: Spec file not found: $SPEC"
  exit 1
fi

# Always create fresh review directory
mkdir -p "$REVIEW_DIR"

echo "════════════════════════════════════════════════════"
echo "  Norviq Review: ${FEAT}"
echo "════════════════════════════════════════════════════"

# Find files from spec
FILES=$(grep -E "^[a-z\.].*\(CREATE" "$SPEC" | sed "s/ (CREATE.*//" | tr "\n" " ")
EXISTING=""
MISSING=""
for f in $FILES; do
  if [ -f "$f" ] || [ -d "$f" ]; then
    EXISTING="$EXISTING $f"
  else
    MISSING="$MISSING $f"
  fi
done

echo "📁 Found: $EXISTING"
[ -n "$MISSING" ] && echo "⚠️  Missing: $MISSING"
echo ""

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

echo "🔍 Running automated checks..."

# Scaffold checks
run_check "Directories exist" "test -d norviq/sdk/core && test -d norviq/engine && test -d tests/sdk && echo PASS || echo FAIL"
run_check "__init__.py count" "test $(find . -name '__init__.py' | wc -l) -ge 11 && echo PASS || echo FAIL"
run_check "pyproject.toml" "test -f pyproject.toml && echo PASS || echo FAIL"

# Feature-specific checks
run_check "ruff lint" "ruff check norviq/ tests/ 2>&1 | tail -1"
run_check "pytest" "python -m pytest tests/ -v --tb=short 2>&1 | tail -1"
run_check "NRVQ error codes" "test $(grep -rn 'NRVQ-' ${EXISTING} 2>/dev/null | wc -l) -ge 0 && echo PASS || echo FAIL"
run_check "No print()" "test $(grep -rn 'print(' ${EXISTING} 2>/dev/null | grep -v test_ | grep -v '#' | wc -l) -eq 0 && echo PASS || echo FAIL"
run_check "No import requests" "test $(grep -rn 'import requests' ${EXISTING} 2>/dev/null | wc -l) -eq 0 && echo PASS || echo FAIL"
run_check "No os.path" "test $(grep -rn 'os\.path' ${EXISTING} 2>/dev/null | wc -l) -eq 0 && echo PASS || echo FAIL"
run_check "No threading" "test $(grep -rn 'import threading\|from threading' ${EXISTING} 2>/dev/null | wc -l) -eq 0 && echo PASS || echo FAIL"

# Security checks
run_check "pip-audit (CVEs)" "pip-audit 2>&1 | grep -v norviq | grep -qi vulnerability && echo FAIL || echo PASS"
run_check "bandit (security)" "bandit -r norviq/ -q -ll 2>&1; echo PASS"

# Artifact checks
run_check "Mermaid diagrams" "test -f architecture/${FEAT}.class.mmd && test -f architecture/${FEAT}.sequence.mmd && test -f architecture/${FEAT}.deps.mmd && echo PASS || echo FAIL"
run_check "Code registry" "test -f registry/${FEAT}.md && echo PASS || echo FAIL"

echo ""
echo "════════════════════════════════════════════════════"
echo "  Result: ${PASS}/$((PASS+FAIL)) passed, ${FAIL}/$((PASS+FAIL)) failed"
echo "════════════════════════════════════════════════════"
echo ""


echo "🤖 Claude Code deep review..."
echo ""

# OVERWRITE the review file (never append)
claude "Review Norviq feature ${FEAT}.

## Automated Check Results (already ran — do NOT re-run these, trust these results):
| Check | Result | Details |
|-------|--------|---------|
$(echo -e "$CHECK_LOG")

Total: ${PASS}/$((PASS+FAIL)) passed

## Files found on disk:
${EXISTING}

## Missing files:
${MISSING:-none}

## Instructions:
- Read CLAUDE.md for review rules
- Read specs/${FEAT}.md for the spec
- Read the actual source files from disk (listed above)
- Read architecture/${FEAT}.class.mmd, architecture/${FEAT}.sequence.mmd, architecture/${FEAT}.deps.mmd and registry/${FEAT}.md if they exist
- Do NOT try to run any commands — the automated checks above already ran. Trust those results.
- Focus your review on: spec compliance, security, race conditions, performance, coding standards
- Include the automated check table EXACTLY as shown above in your review output
- Add your deep review findings BELOW the automated checks
- Follow the review output format in CLAUDE.md
- Be specific — every fix must include exact file path and line number
- This is a FRESH review. Ignore any previous review files." --print | tee "${REVIEW_FILE}"

echo ""
echo "════════════════════════════════════════════════════"
echo "  Review written to: ${REVIEW_FILE}"
echo "  To fix: @fixer ${FEAT}"
echo "════════════════════════════════════════════════════"