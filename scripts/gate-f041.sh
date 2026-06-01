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
echo "  F041 Automated Gate"
echo "═══════════════════════════════════════"

echo ""
echo "── File Structure ──"
check "simulator.py exists" "test -f norviq/redteam/simulator.py"
check "attacks.py exists" "test -f norviq/redteam/attacks.py"
check "payloads.py exists" "test -f norviq/redteam/payloads.py || test -f norviq/redteam/attacks.py"
check "reporter.py exists" "test -f norviq/redteam/reporter.py"
check "runner.py exists" "test -f norviq/redteam/runner.py"
check "__init__.py exists" "test -f norviq/redteam/__init__.py"

echo ""
echo "── Attack Catalog ──"
check "25+ attacks defined" "grep -c 'AttackDefinition' norviq/redteam/attacks.py | awk '{ if (\$1 >= 25) exit 0; else exit 1 }'"
check "OWASP_LLM01 attacks" "grep -q 'OWASP_LLM01\|prompt_injection' norviq/redteam/attacks.py"
check "OWASP_LLM02 attacks" "grep -q 'OWASP_LLM02\|data_leakage' norviq/redteam/attacks.py"
check "OWASP_LLM05 attacks" "grep -q 'OWASP_LLM05\|supply_chain' norviq/redteam/attacks.py"
check "OWASP_LLM06 attacks" "grep -q 'OWASP_LLM06\|excessive_agency' norviq/redteam/attacks.py"
check "OWASP_LLM10 attacks" "grep -q 'OWASP_LLM10\|unbounded_consumption' norviq/redteam/attacks.py"
check "Cross-tenant attacks" "grep -q 'CROSS_TENANT\|cross_tenant' norviq/redteam/attacks.py"
check "SQL injection attacks" "grep -q 'SQL_INJECTION\|sql_injection' norviq/redteam/attacks.py"
check "Shell injection attacks" "grep -q 'SHELL_INJECTION\|shell_injection' norviq/redteam/attacks.py"
check "PII/PCI attacks" "grep -q 'pii\|pci\|ssn\|credit_card' norviq/redteam/attacks.py"
check "Policy bypass attacks" "grep -q 'POLICY_BYPASS\|bypass\|unicode' norviq/redteam/attacks.py"
check "MITRE technique IDs" "grep -q 'AML.T00' norviq/redteam/attacks.py"

echo ""
echo "── Simulator ──"
check "AttackSimulator class" "grep -q 'class AttackSimulator' norviq/redteam/simulator.py"
check "run method" "grep -q 'async def run' norviq/redteam/simulator.py"
check "run_suite method" "grep -q 'async def run_suite' norviq/redteam/simulator.py"
check "run_by_id method" "grep -q 'async def run_by_id\|run_by_id' norviq/redteam/simulator.py"
check "AttackResult dataclass" "grep -q 'class AttackResult\|AttackResult' norviq/redteam/simulator.py"
check "SuiteReport dataclass" "grep -q 'class SuiteReport\|SuiteReport' norviq/redteam/simulator.py"
check "Uses httpx" "grep -q 'httpx' norviq/redteam/simulator.py"
check "Posts to /evaluate endpoint" "grep -q 'evaluate' norviq/redteam/simulator.py"
check "Checks expected vs actual decision" "grep -q 'expected_decision\|passed' norviq/redteam/simulator.py"
check "Category filtering in run_suite" "grep -q 'categories\|category' norviq/redteam/simulator.py"

echo ""
echo "── Reporter ──"
check "RedTeamReporter class" "grep -q 'class RedTeamReporter' norviq/redteam/reporter.py"
check "to_json method" "grep -q 'def to_json' norviq/redteam/reporter.py"
check "to_markdown method" "grep -q 'def to_markdown' norviq/redteam/reporter.py"
check "failed_only method" "grep -q 'def failed_only' norviq/redteam/reporter.py"
check "Markdown table output" "grep -q '|' norviq/redteam/reporter.py"

echo ""
echo "── CLI Runner ──"
check "redteam CLI group" "grep -q 'redteam\|red.team' norviq/redteam/runner.py"
check "run command" "grep -q 'def run' norviq/redteam/runner.py"
check "single command" "grep -q 'def single' norviq/redteam/runner.py"
check "catalog command" "grep -q 'def catalog' norviq/redteam/runner.py"
check "Uses click" "grep -q 'click' norviq/redteam/runner.py"

echo ""
echo "── API Endpoints ──"
check "Redteam router exists" "test -f norviq/api/routers/redteam.py"
check "Run endpoint" "grep -q 'run\|attack' norviq/api/routers/redteam.py"
check "Suite endpoint" "grep -q 'suite' norviq/api/routers/redteam.py"
check "Catalog endpoint" "grep -q 'catalog' norviq/api/routers/redteam.py"
check "Router registered in main" "grep -q 'redteam' norviq/api/main.py"

echo ""
echo "── Error Codes ──"
check "NRVQ-RED-13000 present" "grep -rq 'NRVQ-RED-1300' norviq/redteam/"
check "NRVQ-RED-13001 present" "grep -rq 'NRVQ-RED-13001' norviq/redteam/"
check "NRVQ-RED-13003 present" "grep -rq 'NRVQ-RED-13003' norviq/redteam/"

echo ""
echo "── Tests ──"
check "test_simulator.py exists" "test -f tests/redteam/test_simulator.py"
check "test_attacks.py exists" "test -f tests/redteam/test_attacks.py"
check "test_reporter.py exists" "test -f tests/redteam/test_reporter.py"
check "Test run method" "grep -q 'run\|simulate' tests/redteam/test_simulator.py"
check "Test suite report" "grep -q 'suite\|report\|pass_rate' tests/redteam/test_simulator.py"

echo ""
echo "── Architecture ──"
check "class.mmd exists" "test -f architecture/F041.class.mmd"
check "sequence.mmd exists" "test -f architecture/F041.sequence.mmd"
check "deps.mmd exists" "test -f architecture/F041.deps.mmd"
check "registry exists" "test -f registry/F041.md"

echo ""
echo "── No Stale Code ──"
check "No print() in redteam" "! grep -rq 'print(' norviq/redteam/"
check "SPDX headers" "head -1 norviq/redteam/simulator.py | grep -q 'SPDX'"

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
