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

run_check() {
  local name="$1" cmd="$2"
  local out
  out=$(eval "$cmd" 2>&1) || true
  if echo "$out" | grep -qE "PASS|passed|^0$"; then
    echo "  ✅ ${name}"
    PASS=$((PASS+1))
  else
    echo "  ❌ ${name}: $out"
    FAIL=$((FAIL+1))
  fi
}

echo "🔍 Running checks..."
run_check "Directories exist" "test -d norviq/sdk/core && test -d norviq/engine && test -d tests/sdk && echo PASS || echo FAIL"
run_check "__init__.py count" "test $(find . -name '__init__.py' | wc -l) -ge 11 && echo PASS || echo FAIL"
run_check "pyproject.toml" "test -f pyproject.toml && echo PASS || echo FAIL"
run_check "go.mod" "test -f go.mod && echo PASS || echo FAIL"
run_check "Makefile" "test -f Makefile && echo PASS || echo FAIL"
run_check ".gitignore" "test -f .gitignore && echo PASS || echo FAIL"
run_check "README.md" "test -f README.md && echo PASS || echo FAIL"

echo ""
echo "Result: ${PASS}/$((PASS+FAIL)) passed, ${FAIL}/$((PASS+FAIL)) failed"
echo ""

echo "🤖 Claude Code deep review..."
echo ""

# OVERWRITE the review file (never append)
claude "Review Norviq feature ${FEAT}.

Spec file: specs/${FEAT}.md
Automated checks: ${PASS}/$((PASS+FAIL)) passed

Read CLAUDE.md for review rules.
Read specs/${FEAT}.md for the spec.
Check all files listed in the spec exist and match.
Follow the review output format in CLAUDE.md.
Be specific — every fix must include the exact file path and what to change.

IMPORTANT: This is a FRESH review. Ignore any previous review files." --print | tee "${REVIEW_FILE}"

echo ""
echo "════════════════════════════════════════════════════"
echo "  Review written to: ${REVIEW_FILE}"
echo "  To fix: tell Cursor to read ${REVIEW_FILE}"
echo "════════════════════════════════════════════════════"