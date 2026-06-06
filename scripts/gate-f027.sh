#!/usr/bin/env bash
set -euo pipefail

PASS=0
FAIL=0

check() {
  local name="$1" cmd="$2"
  if eval "$cmd" > /dev/null 2>&1; then
    echo "  ✅ $name"
    PASS=$((PASS+1))
  else
    echo "  ❌ $name"
    FAIL=$((FAIL+1))
  fi
}

echo "═══════════════════════════════════════"
echo "  F027 Automated Gate"
echo "═══════════════════════════════════════"

echo ""
echo "── File Structure ──"
check "calculator.py exists" "test -f norviq/engine/trust/calculator.py"
check "base.py exists" "test -f norviq/engine/trust/signals/base.py"
check "violation_rate.py exists" "test -f norviq/engine/trust/signals/violation_rate.py"
check "tool_novelty.py exists" "test -f norviq/engine/trust/signals/tool_novelty.py"
check "scope_drift.py exists" "test -f norviq/engine/trust/signals/scope_drift.py"
check "param_entropy.py exists" "test -f norviq/engine/trust/signals/param_entropy.py"
check "time_decay.py exists" "test -f norviq/engine/trust/signals/time_decay.py"
check "chain_depth.py exists" "test -f norviq/engine/trust/signals/chain_depth.py"
check "session_velocity.py exists" "test -f norviq/engine/trust/signals/session_velocity.py"
check "history.py exists" "test -f norviq/engine/trust/history.py"
check "profile.py exists" "test -f norviq/engine/trust/profile.py"

echo ""
echo "── 7 Signals Present ──"
check "ViolationRateSignal class" "grep -q 'class ViolationRateSignal' norviq/engine/trust/signals/violation_rate.py"
check "ToolNoveltySignal class" "grep -q 'class ToolNoveltySignal' norviq/engine/trust/signals/tool_novelty.py"
check "ScopeDriftSignal class" "grep -q 'class ScopeDriftSignal' norviq/engine/trust/signals/scope_drift.py"
check "ParamEntropySignal class" "grep -q 'class ParamEntropySignal' norviq/engine/trust/signals/param_entropy.py"
check "TimeDecaySignal class" "grep -q 'class TimeDecaySignal' norviq/engine/trust/signals/time_decay.py"
check "ChainDepthSignal class" "grep -q 'class ChainDepthSignal' norviq/engine/trust/signals/chain_depth.py"
check "SessionVelocitySignal class" "grep -q 'class SessionVelocitySignal' norviq/engine/trust/signals/session_velocity.py"

echo ""
echo "── Calculator Correctness ──"
check "TrustCalculator class" "grep -q 'class TrustCalculator' norviq/engine/trust/calculator.py"
check "All 7 weights defined" "grep -q 'violation_rate.*0.25' norviq/engine/trust/calculator.py"
check "Weight tool_novelty 0.20" "grep -q 'tool_novelty.*0.2' norviq/engine/trust/calculator.py"
check "Weight scope_drift 0.15" "grep -q 'scope_drift.*0.15' norviq/engine/trust/calculator.py"
check "Weight param_entropy 0.15" "grep -q 'param_entropy.*0.15' norviq/engine/trust/calculator.py"
check "Weight time_decay 0.10" "grep -q 'time_decay.*0.1' norviq/engine/trust/calculator.py"
check "Weight chain_depth 0.10" "grep -q 'chain_depth.*0.1' norviq/engine/trust/calculator.py"
check "Weight session_velocity 0.05" "grep -q 'session_velocity.*0.05' norviq/engine/trust/calculator.py"
check "calculate method exists" "grep -q 'async def calculate' norviq/engine/trust/calculator.py"
check "weighted_sum method exists" "grep -q '_weighted_sum\|weighted_sum' norviq/engine/trust/calculator.py"
check "categorize method exists" "grep -q '_categorize\|categorize' norviq/engine/trust/calculator.py"

echo ""
echo "── CRIT-1: No Score Ratchet (trust recovers) ──"
check "No min() on previous score" "! grep -q 'min(.*prev\|min(.*old\|min(.*cached' norviq/engine/trust/calculator.py"
check "No score can only decrease" "! grep -q 'score.*only.*decrease\|score.*cannot.*increase' norviq/engine/trust/calculator.py"
check "Fresh computation each call" "grep -q 'weighted_sum\|_weighted_sum' norviq/engine/trust/calculator.py"

echo ""
echo "── HIGH-2: Old penalty model removed ──"
check "No violation_penalty in evaluator" "! grep -q 'violation_penalty' norviq/engine/evaluator.py"
check "No trust -= in evaluator" "! grep -q 'trust.*-=\|trust_score.*-=' norviq/engine/evaluator.py"
check "No old penalty subtraction" "! grep -q 'initial_score.*violations.*penalty' norviq/engine/evaluator.py"

echo ""
echo "── HIGH-3: Frozen is admin-only ──"
check "Category low not frozen for computed 0" "grep -q 'return.*low\|\"low\"' norviq/engine/trust/calculator.py"
check "Frozen requires manual flag" "grep -q 'manually_frozen\|is_frozen\|agent_frozen' norviq/engine/trust/calculator.py"
check "Frozen key in Redis" "grep -q 'agent_frozen' norviq/engine/trust/calculator.py"

echo ""
echo "── HIGH-4: Scope drift reads class data ──"
check "Profile reads allowed_tools" "grep -q 'allowed_tools' norviq/engine/trust/profile.py"
check "Profile reads blocked_tools" "grep -q 'blocked_tools' norviq/engine/trust/profile.py"
check "Profile reads agent_class key" "grep -q 'agent_class' norviq/engine/trust/profile.py"

echo ""
echo "── HIGH-7: Persistence is fire-and-forget ──"
check "create_task for persistence" "grep -q 'create_task\|fire.*forget' norviq/engine/trust/calculator.py"
check "No await record in hot path" "grep '_persist\|create_task' norviq/engine/trust/calculator.py | grep -q '.'"

echo ""
echo "── Evaluator Integration ──"
check "Evaluator imports TrustCalculator" "grep -q 'TrustCalculator\|trust_calculator\|trust.*calc' norviq/engine/evaluator.py"
check "Evaluator calls calculate" "grep -q 'calculate\|trust.*calc' norviq/engine/evaluator.py"
check "Low trust overrides to escalate" "grep -q 'escalate' norviq/engine/evaluator.py"
check "Frozen overrides to block" "grep -q 'frozen.*block\|block.*frozen' norviq/engine/evaluator.py"

echo ""
echo "── Redis Data Stores ──"
check "History uses sorted set" "grep -q 'zadd\|zrangebyscore\|ZADD\|sorted.*set' norviq/engine/trust/history.py"
check "History key pattern" "grep -q 'agent_history' norviq/engine/trust/history.py"
check "History 1h window" "grep -q '3600\|WINDOW' norviq/engine/trust/history.py"
check "Profile uses hash" "grep -q 'hset\|hgetall\|HSET\|HGETALL' norviq/engine/trust/profile.py"
check "Profile key pattern" "grep -q 'agent_profile' norviq/engine/trust/profile.py"
check "Profile updates known_tools" "grep -q 'known_tools' norviq/engine/trust/profile.py"
check "Profile updates entropy baseline" "grep -q 'param_entropy\|entropy' norviq/engine/trust/profile.py"

echo ""
echo "── Error Codes ──"
check "NRVQ-ENG-2040 present" "grep -rq 'NRVQ-ENG-2040' norviq/engine/trust/"
check "NRVQ-ENG-2041 present" "grep -rq 'NRVQ-ENG-2041' norviq/engine/trust/"
check "NRVQ-ENG-2042 present" "grep -rq 'NRVQ-ENG-2042' norviq/engine/trust/"

echo ""
echo "── Tests ──"
check "test_calculator.py exists" "test -f tests/engine/trust/test_calculator.py"
check "test_violation_rate.py exists" "test -f tests/engine/trust/test_violation_rate.py"
check "test_tool_novelty.py exists" "test -f tests/engine/trust/test_tool_novelty.py"
check "test_scope_drift.py exists" "test -f tests/engine/trust/test_scope_drift.py"
check "test_param_entropy.py exists" "test -f tests/engine/trust/test_param_entropy.py"
check "test_time_decay.py exists" "test -f tests/engine/trust/test_time_decay.py"
check "test_chain_depth.py exists" "test -f tests/engine/trust/test_chain_depth.py"
check "test_session_velocity.py exists" "test -f tests/engine/trust/test_session_velocity.py"
check "Recovery test exists" "grep -q 'recover\|recovery\|Test.*13\|trust.*returns.*high' tests/engine/trust/test_calculator.py"
check "Frozen admin-only test" "grep -q 'frozen.*admin\|manually.*frozen\|not.*auto.*freeze\|category.*low.*not.*frozen' tests/engine/trust/test_calculator.py"

echo ""
echo "── Architecture ──"
check "class.mmd exists" "test -f architecture/F027.class.mmd"
check "sequence.mmd exists" "test -f architecture/F027.sequence.mmd"
check "deps.mmd exists" "test -f architecture/F027.deps.mmd"
check "registry exists" "test -f registry/F027.md"

echo ""
echo "── No Stale Code ──"
check "No print() in trust" "! grep -rq 'print(' norviq/engine/trust/"
check "SPDX headers" "head -1 norviq/engine/trust/calculator.py | grep -q 'SPDX'"

echo ""
echo "── Regression check ──"
check "history file exists" "test -f tests/.history/F027.md"
check "no @pytest.mark.xfail without reason" "! grep -rn 'pytest.mark.xfail(' tests/.history/ 2>/dev/null | grep -v reason"

echo ""
echo "═══════════════════════════════════════"
echo "  Result: $PASS passed, $FAIL failed"
echo "═══════════════════════════════════════"

if [ $FAIL -eq 0 ]; then
  echo "  🟢 GATE PASSED — safe to commit"
  exit 0
else
  echo "  🔴 GATE FAILED — fix $FAIL items"
  exit 1
fi
