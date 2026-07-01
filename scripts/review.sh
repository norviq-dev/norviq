#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
set -euo pipefail

# ═══════════════════════════════════════════════════════════════════════════
# Norviq Feature Review — Gate + verification tiers + Claude (no infinite loops)
#
# Usage: bash scripts/review.sh F027
#
# Flow:
#   Phase 1: Feature gate script (concrete checks, must pass)
#   Phase 2: Verification tiers — scripts/verify.sh (T1 static+unit, T2 kind integration,
#            T3 regression, T5 SAST). T4 effect evidence is emitted for the reviewer.
#   Phase 3: Claude deep review (runs ONCE per gate-pass; marker file guards against loops)
#   Phase 4: Report + verdict
#
# Discipline (see AGENTS.md):
#   - The gate + T1–T3 + SAST must pass before Claude reviews.
#   - Claude runs exactly ONCE per feature per gate state.
#   - HIGH/CRITICAL security findings FAIL-CLOSED (block). Not just CRITICAL.
#   - Doable in-scope findings are FIXED now — nothing is routed to a backlog.
#   - This script NEVER commits or pushes. San commits after PASS (a push to main is a deploy).
# ═══════════════════════════════════════════════════════════════════════════

FEAT="${1:?Usage: bash scripts/review.sh FEATURE_ID}"
FEAT_LOWER=$(echo "$FEAT" | tr '[:upper:]' '[:lower:]')
GATE_SCRIPT="scripts/gate-${FEAT_LOWER}.sh"
CLAUDE_PROMPT="prompts/reviews/${FEAT}-review.md"
GATE_OUTPUT=".reviews/${FEAT}-gate.md"
VERIFY_OUTPUT=".reviews/${FEAT}-verify.md"
CLAUDE_OUTPUT=".reviews/${FEAT}-claude.md"
FIX_OUTPUT=".reviews/${FEAT}-fixes.md"

mkdir -p .reviews

echo "═══════════════════════════════════════════════════"
echo "  Norviq Review: ${FEAT}"
echo "═══════════════════════════════════════════════════"

# ─── PHASE 1: Feature Gate ─────────────────────────────────────────────────
echo ""
echo "╔═══════════════════════════════════════╗"
echo "║  PHASE 1: Feature Gate                 ║"
echo "╚═══════════════════════════════════════╝"

if [ ! -f "$GATE_SCRIPT" ]; then
    echo "  ⚠️  No gate script found: $GATE_SCRIPT — proceeding to verification tiers."
else
    echo "  Running: $GATE_SCRIPT"
    set +e
    bash "$GATE_SCRIPT" 2>&1 | tee "$GATE_OUTPUT"
    GATE_EXIT=${PIPESTATUS[0]}
    set -e
    if [ "$GATE_EXIT" -eq 0 ]; then
        echo "  🟢 Feature gate PASSED"
    else
        echo "  🔴 Feature gate FAILED — tell Cursor: read $GATE_OUTPUT, fix, re-run review.sh ${FEAT}"
        echo "     (Do NOT edit scripts/ or prompts/.)"
        exit 1
    fi
fi

# ─── PHASE 2: Verification Tiers (T1–T3 + SAST; fail-closed) ────────────────
echo ""
echo "╔═══════════════════════════════════════╗"
echo "║  PHASE 2: Verification Tiers           ║"
echo "╚═══════════════════════════════════════╝"

set +e
bash scripts/verify.sh "$FEAT" --tier T1 2>&1 | tee "$VERIFY_OUTPUT"
T1_EXIT=${PIPESTATUS[0]}
bash scripts/verify.sh "$FEAT" --tier T5 2>&1 | tee -a "$VERIFY_OUTPUT"
T5_EXIT=${PIPESTATUS[0]}

KIND_CTX="$(kubectl config get-contexts -o name 2>/dev/null | rg '^kind-' --no-line-number | awk 'NR==1{print; exit}')"
CURRENT_CTX="$(kubectl config current-context 2>/dev/null || echo none)"
T2_EXIT=0
T4_EXIT=0

if [ -n "${KIND_CTX:-}" ]; then
    echo "" | tee -a "$VERIFY_OUTPUT"
    echo "  ℹ️  kind context detected: $KIND_CTX (current=$CURRENT_CTX)." | tee -a "$VERIFY_OUTPUT"
    echo "     Running T2/T4 on kind context for integration/effect evidence." | tee -a "$VERIFY_OUTPUT"
    if [ "$CURRENT_CTX" != "$KIND_CTX" ]; then
        kubectl config use-context "$KIND_CTX" >/dev/null 2>&1 || true
    fi
    bash scripts/verify.sh "$FEAT" --tier T2 2>&1 | tee -a "$VERIFY_OUTPUT"
    T2_EXIT=${PIPESTATUS[0]}
    # T4 emits evidence for the reviewer to assert — it is env-gated and non-blocking.
    bash scripts/verify.sh "$FEAT" --tier T4 2>&1 | tee -a "$VERIFY_OUTPUT"
    T4_EXIT=${PIPESTATUS[0]}
    if [ "$CURRENT_CTX" != "$KIND_CTX" ]; then
        kubectl config use-context "$CURRENT_CTX" >/dev/null 2>&1 || true
    fi
else
    echo "" | tee -a "$VERIFY_OUTPUT"
    echo "  ℹ️  T2/T4 not run: no kind context — effect validated separately via P-10 on AKS." | tee -a "$VERIFY_OUTPUT"
fi

bash scripts/verify.sh "$FEAT" --tier T3 2>&1 | tee -a "$VERIFY_OUTPUT"
T3_EXIT=${PIPESTATUS[0]}
set -e

if [ "$T1_EXIT" -ne 0 ] || [ "$T5_EXIT" -ne 0 ] || [ "$T3_EXIT" -ne 0 ]; then
    echo ""
    echo "  🔴 Required verification tiers FAILED (T1=$T1_EXIT T5=$T5_EXIT T3=$T3_EXIT)"
    echo "     Tell Cursor: read $VERIFY_OUTPUT, fix the red tiers, re-run review.sh ${FEAT}."
    echo "     HIGH/CRITICAL security (T5) is fail-closed — it blocks."
    exit 1
fi
echo "  🟢 Required tiers green (T1/T5/T3). T2/T4 env-gated status: T2=$T2_EXIT T4=$T4_EXIT"
echo "     Proceeding to Claude review."

# ─── PHASE 3: Claude Deep Review (ONCE per gate state) ─────────────────────
echo ""
echo "╔═══════════════════════════════════════╗"
echo "║  PHASE 3: Claude Deep Review (1 pass)  ║"
echo "╚═══════════════════════════════════════╝"

if [ ! -f "$CLAUDE_PROMPT" ]; then
    echo "  ⚠️  No Claude prompt found: $CLAUDE_PROMPT"
    echo "  Gate + tiers green. Claude (reviewer) still owns the verdict + T4-effect assertion + memory write-back."
    exit 0
fi

STATE_HASH=$(cat "$GATE_OUTPUT" "$VERIFY_OUTPUT" 2>/dev/null | md5sum | cut -d' ' -f1 || echo "none")
REVIEW_MARKER=".reviews/${FEAT}-reviewed-${STATE_HASH}"
if [ -f "$REVIEW_MARKER" ]; then
    echo "  ℹ️  Claude already reviewed after this gate state. Re-run gate only if you made fixes."
    exit 0
fi

echo "  Running Claude review (the ONLY run for this gate state)..."
set +e
claude "$(cat "$CLAUDE_PROMPT")" --print < /dev/null 2>&1 | tee "$CLAUDE_OUTPUT"
set -e
touch "$REVIEW_MARKER"

# ─── PHASE 4: Report + Verdict ─────────────────────────────────────────────
echo ""
echo "╔═══════════════════════════════════════╗"
echo "║  PHASE 4: Verdict                      ║"
echo "╚═══════════════════════════════════════╝"

# HIGH-security and CRITICAL both BLOCK (fail-closed). No severity is routed to a backlog.
BLOCKERS=$(grep -ciE "CRITICAL|CRIT-|HIGH[- ]*SEC|HIGH[- ]*SECURITY|SECURITY.*HIGH" "$CLAUDE_OUTPUT" 2>/dev/null || echo 0)

cat > "$FIX_OUTPUT" << FIXEOF
# ${FEAT} — Fix Instructions (author applies; reviewer verifies)
# Generated: $(date)
# Apply the doable in-scope fixes now (AGENTS.md). Escalate only genuine spec/threat-model calls to San.
# Then re-run: bash scripts/review.sh ${FEAT}

## Blocking items (CRITICAL + HIGH-security) extracted from the review:
FIXEOF
grep -B1 -A6 -iE "CRITICAL|CRIT-|HIGH[- ]*SEC|HIGH[- ]*SECURITY" "$CLAUDE_OUTPUT" 2>/dev/null >> "$FIX_OUTPUT" || echo "None." >> "$FIX_OUTPUT"

if [ "$BLOCKERS" -gt 0 ]; then
    echo "  🔴 BLOCKING findings (CRITICAL or HIGH-security) — fail-closed."
    echo "     Tell Cursor: read $FIX_OUTPUT, apply the fixes in-scope, re-run: bash scripts/review.sh ${FEAT}"
    echo "     Do NOT commit. Do NOT edit scripts/ or prompts/."
    exit 1
else
    echo "  🟢 No blocking findings. Reviewer must still: assert the T4 EFFECT from evidence,"
    echo "     then do the Review Step N memory write-back (CLAUDE.md), then hand to San to COMMIT."
    echo "     This script does not commit or push."
    exit 0
fi
