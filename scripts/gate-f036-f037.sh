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
echo "  F036-F037 Automated Gate"
echo "═══════════════════════════════════════"

echo ""
echo "── File Structure ──"
check "models.py exists" "test -f norviq/engine/graph/models.py"
check "asset_graph.py exists" "test -f norviq/engine/graph/asset_graph.py"
check "attack_graph.py exists" "test -f norviq/engine/graph/attack_graph.py"
check "analyzer.py exists" "test -f norviq/engine/graph/analyzer.py"
check "store.py exists" "test -f norviq/engine/graph/store.py"
check "__init__.py exists" "test -f norviq/engine/graph/__init__.py"

echo ""
echo "── Data Models ──"
check "NodeType enum" "grep -q 'class NodeType' norviq/engine/graph/models.py"
check "EdgeType enum" "grep -q 'class EdgeType' norviq/engine/graph/models.py"
check "GraphNode dataclass" "grep -q 'class GraphNode' norviq/engine/graph/models.py"
check "GraphEdge dataclass" "grep -q 'class GraphEdge' norviq/engine/graph/models.py"
check "AttackPath dataclass" "grep -q 'class AttackPath' norviq/engine/graph/models.py"
check "BlastRadius dataclass" "grep -q 'class BlastRadius' norviq/engine/graph/models.py"
check "RiskLevel enum" "grep -q 'class RiskLevel' norviq/engine/graph/models.py"

echo ""
echo "── Asset Graph (F036) ──"
check "AssetGraphBuilder class" "grep -q 'class AssetGraphBuilder' norviq/engine/graph/asset_graph.py"
check "Uses networkx" "grep -q 'networkx\|nx.DiGraph' norviq/engine/graph/asset_graph.py"
check "add_agent method" "grep -q 'def add_agent' norviq/engine/graph/asset_graph.py"
check "add_tool method" "grep -q 'def add_tool' norviq/engine/graph/asset_graph.py"
check "add_data method" "grep -q 'def add_data' norviq/engine/graph/asset_graph.py"
check "record_tool_call method" "grep -q 'def record_tool_call' norviq/engine/graph/asset_graph.py"
check "record_delegation method" "grep -q 'def record_delegation' norviq/engine/graph/asset_graph.py"
check "record_data_access method" "grep -q 'def record_data_access' norviq/engine/graph/asset_graph.py"
check "to_dict method" "grep -q 'def to_dict' norviq/engine/graph/asset_graph.py"
check "from_dict method" "grep -q 'def from_dict' norviq/engine/graph/asset_graph.py"
check "Tool risk map exists" "grep -q 'TOOL_RISK_MAP\|tool_risk\|risk_map' norviq/engine/graph/asset_graph.py"

echo ""
echo "── Attack Graph (F037) ──"
check "AttackGraphEngine class" "grep -q 'class AttackGraphEngine' norviq/engine/graph/attack_graph.py"
check "compute_blast_radius method" "grep -q 'def compute_blast_radius' norviq/engine/graph/attack_graph.py"
check "find_attack_paths method" "grep -q 'def find_attack_paths' norviq/engine/graph/attack_graph.py"
check "find_critical_paths method" "grep -q 'def find_critical_paths' norviq/engine/graph/attack_graph.py"
check "find_chokepoints method" "grep -q 'def find_chokepoints' norviq/engine/graph/attack_graph.py"
check "compute_risk_matrix method" "grep -q 'def compute_risk_matrix' norviq/engine/graph/attack_graph.py"
check "Uses nx.descendants" "grep -q 'descendants\|reachable' norviq/engine/graph/attack_graph.py"
check "Uses all_simple_paths" "grep -q 'all_simple_paths\|simple_paths' norviq/engine/graph/attack_graph.py"
check "Path cutoff limit" "grep -q 'cutoff' norviq/engine/graph/attack_graph.py"

echo ""
echo "── Analyzer ──"
check "GraphAnalyzer class" "grep -q 'class GraphAnalyzer' norviq/engine/graph/analyzer.py"
check "full_analysis method" "grep -q 'def full_analysis' norviq/engine/graph/analyzer.py"

echo ""
echo "── Store ──"
check "GraphStore class" "grep -q 'class GraphStore' norviq/engine/graph/store.py"
check "save method" "grep -q 'async def save' norviq/engine/graph/store.py"
check "load method" "grep -q 'async def load' norviq/engine/graph/store.py"
check "Uses Redis for cache" "grep -q 'graph:' norviq/engine/graph/store.py"

echo ""
echo "── API Endpoints ──"
check "graph router file exists" "test -f norviq/api/routers/graph.py"
check "GET /graph endpoint" "grep -q 'get_graph\|/graph' norviq/api/routers/graph.py"
check "GET /blast-radius endpoint" "grep -q 'blast.radius\|blast_radius' norviq/api/routers/graph.py"
check "GET /attack-paths endpoint" "grep -q 'attack.path' norviq/api/routers/graph.py"
check "GET /critical-paths endpoint" "grep -q 'critical.path' norviq/api/routers/graph.py"
check "GET /chokepoints endpoint" "grep -q 'chokepoint' norviq/api/routers/graph.py"
check "GET /analysis endpoint" "grep -q 'analysis' norviq/api/routers/graph.py"
check "Router registered in main" "grep -q 'graph' norviq/api/main.py"

echo ""
echo "── Integration ──"
check "Evaluator records tool calls in graph" "grep -q 'record_tool_call\|graph.*record\|asset_graph' norviq/engine/evaluator.py"

echo ""
echo "── Error Codes ──"
check "NRVQ-GRP-11000 present" "grep -rq 'NRVQ-GRP-11000' norviq/engine/graph/"
check "NRVQ-GRP-11011 present" "grep -rq 'NRVQ-GRP-11011' norviq/engine/graph/"
check "NRVQ-GRP-11012 present" "grep -rq 'NRVQ-GRP-11012' norviq/engine/graph/"

echo ""
echo "── Tests ──"
check "test_asset_graph.py exists" "test -f tests/engine/graph/test_asset_graph.py"
check "test_attack_graph.py exists" "test -f tests/engine/graph/test_attack_graph.py"
check "test_analyzer.py exists" "test -f tests/engine/graph/test_analyzer.py"
check "Blast radius test" "grep -q 'blast_radius\|blast' tests/engine/graph/test_attack_graph.py"
check "Attack path test" "grep -q 'attack_path\|find_attack' tests/engine/graph/test_attack_graph.py"
check "Chokepoint test" "grep -q 'chokepoint' tests/engine/graph/test_attack_graph.py"
check "Round-trip test" "grep -q 'to_dict\|from_dict\|round.trip' tests/engine/graph/test_asset_graph.py"

echo ""
echo "── Architecture ──"
check "F036 class.mmd exists" "test -f architecture/F036.class.mmd"
check "F036 sequence.mmd exists" "test -f architecture/F036.sequence.mmd"
check "F037 class.mmd exists" "test -f architecture/F037.class.mmd"
check "F037 sequence.mmd exists" "test -f architecture/F037.sequence.mmd"
check "F036 registry exists" "test -f registry/F036.md"
check "F037 registry exists" "test -f registry/F037.md"

echo ""
echo "── No Stale Code ──"
check "No print() in graph" "! grep -rq 'print(' norviq/engine/graph/"
check "SPDX header" "head -1 norviq/engine/graph/asset_graph.py | grep -q 'SPDX'"

echo ""
echo "── Regression check ──"
check "history file exists" "test -f tests/.history/F036.md"
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
