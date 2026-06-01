#!/usr/bin/env bash
set -euo pipefail

# ═══════════════════════════════════════════════════
# Norviq Feature Review — Gate + Claude (no infinite loops)
#
# Usage: bash scripts/review.sh F027
#
# Flow:
#   Phase 1: Gate script (concrete checks, must pass)
#   Phase 2: Claude deep review (runs ONCE, advisory)
#   Phase 3: Generate fix instructions (CRITICAL only blocks)
#
# Rules:
#   - Gate must pass before Claude runs
#   - Claude runs exactly ONCE per feature per commit
#   - Only CRITICAL from Claude blocks commit
#   - HIGH/MEDIUM/LOW go to docs/backlog.md
#   - After fixing CRITICAL, re-run gate only (not Claude)
# ═══════════════════════════════════════════════════

FEAT="${1:?Usage: bash scripts/review.sh FEATURE_ID}"
FEAT_LOWER=$(echo "$FEAT" | tr '[:upper:]' '[:lower:]')
GATE_SCRIPT="scripts/gate-${FEAT_LOWER}.sh"
CLAUDE_PROMPT="prompts/reviews/${FEAT}-review.md"
GATE_OUTPUT=".reviews/${FEAT}-gate.md"
CLAUDE_OUTPUT=".reviews/${FEAT}-claude.md"
FIX_OUTPUT=".reviews/${FEAT}-fixes.md"
BACKLOG="docs/backlog.md"

mkdir -p .reviews
touch "$BACKLOG"

echo "═══════════════════════════════════════════════════"
echo "  Norviq Review: ${FEAT}"
echo "═══════════════════════════════════════════════════"

# ─── PHASE 1: Gate Script ───────────────────────────
echo ""
echo "╔═══════════════════════════════════════╗"
echo "║  PHASE 1: Gate Script                 ║"
echo "╚═══════════════════════════════════════╝"

if [ ! -f "$GATE_SCRIPT" ]; then
    echo "  ⚠️  No gate script found: $GATE_SCRIPT"
    echo "  Skipping gate, proceeding to Claude review."
else
    echo "  Running: $GATE_SCRIPT"
    echo ""

    set +e
    bash "$GATE_SCRIPT" 2>&1 | tee "$GATE_OUTPUT"
    GATE_EXIT=${PIPESTATUS[0]}
    set -e

    if [ "$GATE_EXIT" -eq 0 ]; then
        echo ""
        echo "  🟢 Gate PASSED — proceeding to Claude review"
    else
        echo ""
        echo "  🔴 Gate FAILED — fix failed items before Claude review"
        echo ""
        echo "  ┌─────────────────────────────────────────────┐"
        echo "  │ Tell Cursor:                                │"
        echo "  │ Read ${GATE_OUTPUT}"
        echo "  │ Fix all failed items.                       │"
        echo "  │ Do NOT edit scripts/ or prompts/.           │"
        echo "  │                                             │"
        echo "  │ Then re-run: bash scripts/review.sh ${FEAT} │"
        echo "  └─────────────────────────────────────────────┘"
        exit 1
    fi
fi

# ─── PHASE 2: Claude Deep Review (ONCE) ────────────
echo ""
echo "╔═══════════════════════════════════════╗"
echo "║  PHASE 2: Claude Deep Review (1 pass) ║"
echo "╚═══════════════════════════════════════╝"

if [ ! -f "$CLAUDE_PROMPT" ]; then
    echo "  ⚠️  No Claude prompt found: $CLAUDE_PROMPT"
    echo "  Gate passed — safe to commit."
    echo ""
    echo "  git add -A && git commit -s -m 'feat(${FEAT}): description'"
    exit 0
fi

# Check if Claude already reviewed since last gate pass
GATE_HASH=$(md5sum "$GATE_OUTPUT" 2>/dev/null | cut -d' ' -f1 || echo "none")
REVIEW_MARKER=".reviews/${FEAT}-reviewed-${GATE_HASH}"

if [ -f "$REVIEW_MARKER" ]; then
    echo "  ℹ️  Claude already reviewed after this gate pass."
    echo "  Re-run gate only if you made fixes:"
    echo "    bash ${GATE_SCRIPT}"
    echo ""
    echo "  If gate passes → commit. No re-review."
    exit 0
fi

echo "  Running Claude review (this is the ONLY run)..."
echo ""

set +e
claude "$(cat "$CLAUDE_PROMPT")" --print 2>&1 | tee "$CLAUDE_OUTPUT"
set -e

# Mark as reviewed for this gate state
touch "$REVIEW_MARKER"

# ─── PHASE 3: Parse & Decide ──────────────────────
echo ""
echo "╔═══════════════════════════════════════╗"
echo "║  PHASE 3: Results & Decision          ║"
echo "╚═══════════════════════════════════════╝"

# Count issues
CRITICAL_COUNT=$(grep -c "CRITICAL\|CRIT-" "$CLAUDE_OUTPUT" 2>/dev/null || echo "0")
HIGH_COUNT=$(grep -c "HIGH-\|HIGH:" "$CLAUDE_OUTPUT" 2>/dev/null || echo "0")
MEDIUM_COUNT=$(grep -c "MEDIUM-\|MEDIUM:" "$CLAUDE_OUTPUT" 2>/dev/null || echo "0")
LOW_COUNT=$(grep -c "LOW-\|LOW:" "$CLAUDE_OUTPUT" 2>/dev/null || echo "0")

echo ""
echo "  ┌──────────────────────────────┐"
echo "  │ CRITICAL: $CRITICAL_COUNT (blocks commit)   │"
echo "  │ HIGH:     $HIGH_COUNT (backlog)          │"
echo "  │ MEDIUM:   $MEDIUM_COUNT (backlog)          │"
echo "  │ LOW:      $LOW_COUNT (backlog)          │"
echo "  └──────────────────────────────┘"
echo ""

# ─── Generate CRITICAL fix instructions ─────────────
cat > "$FIX_OUTPUT" << FIXEOF
# ${FEAT} — CRITICAL Fix Instructions
# Generated: $(date)
# Gate: PASSED
# Claude: REVIEWED (one pass)
#
# ONLY fix items below. Then re-run gate:
#   bash ${GATE_SCRIPT}
# Do NOT re-run Claude. Do NOT edit gate script.

## CRITICAL items (extracted from Claude review):
FIXEOF

grep -B1 -A5 "CRITICAL\|CRIT-" "$CLAUDE_OUTPUT" 2>/dev/null >> "$FIX_OUTPUT" || echo "None." >> "$FIX_OUTPUT"

# ─── Append non-critical to backlog ─────────────────
echo "" >> "$BACKLOG"
echo "## ${FEAT} — deferred $(date +%Y-%m-%d)" >> "$BACKLOG"
echo "" >> "$BACKLOG"
grep -A2 "HIGH-\|HIGH:" "$CLAUDE_OUTPUT" 2>/dev/null | head -30 >> "$BACKLOG" || true
grep -A2 "MEDIUM-\|MEDIUM:" "$CLAUDE_OUTPUT" 2>/dev/null | head -20 >> "$BACKLOG" || true
grep -A2 "LOW-\|LOW:" "$CLAUDE_OUTPUT" 2>/dev/null | head -15 >> "$BACKLOG" || true

# ─── Decision ──────────────────────────────────────
HAS_REAL_CRITICAL=$(grep -ci "CRITICAL.*must.fix\|CRITICAL.*block\|CRIT-[0-9].*fix" "$CLAUDE_OUTPUT" 2>/dev/null || echo "0")

if [ "$HAS_REAL_CRITICAL" -gt 0 ]; then
    echo "  🔴 CRITICAL issues found"
    echo ""
    echo "  ┌─────────────────────────────────────────────┐"
    echo "  │ Fix instructions: ${FIX_OUTPUT}"
    echo "  │                                             │"
    echo "  │ Tell Cursor:                                │"
    echo "  │   Read ${FIX_OUTPUT}                        │"
    echo "  │   Fix CRITICAL items ONLY.                  │"
    echo "  │   Do NOT edit scripts/ or prompts/.         │"
    echo "  │                                             │"
    echo "  │ After fixing, re-run GATE ONLY:             │"
    echo "  │   bash ${GATE_SCRIPT}                       │"
    echo "  │                                             │"
    echo "  │ If gate passes → commit.                    │"
    echo "  │ Do NOT re-run Claude.                       │"
    echo "  └─────────────────────────────────────────────┘"
    echo ""
    echo "  HIGH/MEDIUM/LOW → $BACKLOG (fix later)"
    exit 1
else
    echo "  🟢 No CRITICAL issues — SAFE TO COMMIT"
    echo ""
    echo "  ┌─────────────────────────────────────────────┐"
    echo "  │ git add -A                                  │"
    echo "  │ git commit -s -m 'feat(${FEAT}): desc'      │"
    echo "  │ git push origin main                        │"
    echo "  └─────────────────────────────────────────────┘"
    echo ""
    if [ "$HIGH_COUNT" -gt 0 ] || [ "$MEDIUM_COUNT" -gt 0 ]; then
        echo "  HIGH/MEDIUM/LOW → $BACKLOG (fix in testing phase)"
    fi
    exit 0
fi