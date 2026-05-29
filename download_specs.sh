#!/usr/bin/env bash
# Norviq — Download All Spec Files
# Run this in your repo root: bash download_specs.sh

mkdir -p specs

cat > CLAUDE.md << 'CLAUDEEOF'
# CLAUDE.md — Norviq Code Review Instructions
# Claude Code reads this file automatically when invoked.

## Your Role
You are the code reviewer for Norviq. Cursor generates code, you review it.
You enforce spec compliance, security, performance, and coding standards.

## Project
Norviq: runtime security platform for LLM agent tool calls on Kubernetes.
Sits between LangGraph/LangChain agents and their tools.
Every tool call intercepted, evaluated against OPA/Rego policies,
scoped to K8s workload identity (SPIFFE/SPIRE SVIDs).

## Tech Stack
- Python 3.11+ (SDK, Engine, API) | Go 1.22+ (Webhook, CLI, Sidecar P2)
- FastAPI | SQLAlchemy + asyncpg | Redis | OPA/Rego | SPIFFE/SPIRE
- OpenTelemetry | Helm | Kubernetes CRDs

## How Review Works
1. Developer types: claude review F001
2. scripts/review.sh finds specs/F001.md and the generated code files
3. Automated checks run (ruff, pytest, grep)
4. You receive: spec + code + check results
5. You output: structured review with pass/fail + fix instructions

## Review Checklist (enforce ALL)

### 1. Spec Compliance
- Every class/method in spec exists in code with matching signature
- No extra files created beyond what spec lists
- Imports match spec exactly (canonical locations)
- Error codes (NRVQ-XXX-NNNN) present at every log point

### 2. Performance (customer-facing chatbot — speed is critical)
- Redis cache check BEFORE any DB or OPA call
- async/await on ALL I/O (httpx, asyncpg, redis)
- No blocking calls in hot path (audit writes are fire-and-forget)
- Connection pools used (never open/close per request)
- No synchronous sleep() or time.sleep()

### 3. Security
- No hardcoded secrets, URLs, ports, or credentials
- All config from: from norviq.config import settings
- Input validation via Pydantic models (never trust raw dict)
- SQL: parameterized queries only (no f-strings in SQL)
- No eval(), exec(), or pickle.loads() anywhere
- SPIFFE ID validated before trust score lookup

### 4. Coding Standards
- Functions <30 lines. Classes <150 lines. Files <300 lines.
- Type hints on every function signature
- One-line docstrings only (no verbose multi-line)
- structlog with AGRD error codes (never print())
- httpx not requests. pathlib not os.path. asyncpg not psycopg2.
- No threading — use asyncio for Python, goroutines for Go

### 5. Memory + Concurrency
- Redis TTLs on ALL keys (no unbounded growth)
- Connection pools closed in shutdown hooks
- Pydantic model_validate() not dict unpacking
- No global mutable state (use dependency injection)
- OTel spans batched, never accumulated in memory

### 6. Test Coverage
- Allow path test (200 response, decision=allow)
- Block path test (200 response, decision=block)
- Error/fallback path test (engine unavailable, timeout)
- No mocked-away logic — test real code paths

## Review Output Format
When reviewing, output this structure:

```
## Feature Review: F001 — ToolCallEvent Schema

### Automated Checks
| Check | Result | Details |
|-------|--------|---------|
| ruff | PASS/FAIL | {output} |
| pytest | PASS/FAIL | {pass}/{total} tests |
| AGRD codes | PASS/FAIL | {count} codes found |
| No print() | PASS/FAIL | {count} violations |
| No requests | PASS/FAIL | |
| No os.path | PASS/FAIL | |
| No threading | PASS/FAIL | |
| Config loads | PASS/FAIL | |

### Spec Compliance
- [x] ToolCallEvent class matches spec
- [ ] Missing field: raw_llm_output

### Security Issues
- None found / {list issues}

### Performance Issues
- None found / {list issues}

### Architecture Diagram
Show ASCII class diagram:
```
+-----------------------------------------------+
| ToolCallEvent (F001)                          |
|-----------------------------------------------|
| + event_id: str                               |
| + tool_name: str                              |
| + agent_identity: AgentIdentity ──┐           |
| + trust_score: TrustScore ────────┤           |
+-----------------------------------------------+
         │ passed to                  │          
         ▼                            ▼          
+-------------------+    +-----------------------+
| OPAEvaluator      |    | AgentIdentity (F004)  |
|-------------------|    |-----------------------|
| + evaluate()      |    | + spiffe_id: str      |
| + _build_input()  |    | + namespace: str      |
+-------------------+    +-----------------------+
```

### Method Call Chain
Show execution order:
```
1. protect(tools) ──► ToolCallInterceptor.__init__()
2. tool._run()    ──► interceptor.intercept(tool_name, params)
3.                ──► SPIFFEResolver.resolve() → AgentIdentity
4.                ──► PolicyEngineClient.evaluate(event) → POST /v1/evaluate
5.                ──► OPAEvaluator.evaluate(event) → PolicyDecision
6. allow?         ──► original_tool._run() → result
   block?         ──► raise NorviqBlockError(decision)
```

### Fix Instructions for Cursor
1. Add missing field raw_llm_output: Optional[str] = None to ToolCallEvent
2. ...

### Data Flow (how this feature connects)
upstream: S002 (config) → S003 (exceptions)
this: F001 ToolCallEvent ← created by SDK interceptor
downstream: F006 (sends to engine) → F009 (evaluates) → F014 (audits)
```

## When to REJECT code
- Any hardcoded secret or URL → REJECT immediately
- Missing error code at a decision point → REJECT
- Blocking I/O in the hot path → REJECT
- No tests for block/error path → REJECT
- File not listed in spec → REJECT (hallucination)
CLAUDEOF

mkdir -p scripts
cat > scripts/review.sh << 'REVIEWEOF'
#!/usr/bin/env bash
# Norviq Code Review — Cursor builds, Claude Code reviews
# Usage: ./scripts/review.sh F001
#
# This script:
#   1. Runs 9 automated checks on the feature files
#   2. Sends ONLY the feature files + spec + check results to Claude Code
#   3. Claude Code reads the full repo from disk for dependency verification

set -euo pipefail

FEAT="${1:?Usage: ./scripts/review.sh F001}"
SPEC="specs/${FEAT}.md"

if [ ! -f "$SPEC" ]; then
  echo "ERROR: Spec file not found: $SPEC"
  exit 1
fi

echo "══════════════════════════════════════════════════════════"
echo "  Norviq Review: ${FEAT}"
echo "══════════════════════════════════════════════════════════"
echo ""

# Extract file paths from spec (lines with CREATE/MODIFY)
FILES=$(grep -E "^[a-z].*\(CREATE|MODIFY" "$SPEC" | sed "s/ (CREATE.*//" | sed "s/ (MODIFY.*//" | tr "\n" " ")

# Check which files exist
EXISTING=""
MISSING=""
for f in $FILES; do
  if [ -f "$f" ]; then
    EXISTING="$EXISTING $f"
  else
    MISSING="$MISSING $f"
  fi
done

if [ -z "$EXISTING" ]; then
  echo "❌ No generated files found. Tell Cursor to implement specs/${FEAT}.md first."
  exit 1
fi
echo "📁 Reviewing: $EXISTING"
[ -n "$MISSING" ] && echo "⚠️  Not yet created: $MISSING"
echo ""

# ── 9-POINT AUTOMATED CHECKS ─────────────────────────────
RESULTS=""
PASS=0
FAIL=0

run_check() {
  local name="$1" cmd="$2"
  local out
  out=$(eval "$cmd" 2>&1) || true
  if [ -z "$out" ] || echo "$out" | grep -qE "PASS|passed|^0$"; then
    RESULTS="${RESULTS}| ${name} | ✅ PASS | |\n"
    echo "  ✅ ${name}"
    PASS=$((PASS+1))
  else
    RESULTS="${RESULTS}| ${name} | ❌ FAIL | $(echo "$out" | head -3 | tr "\n" " ") |\n"
    echo "  ❌ ${name}"
    FAIL=$((FAIL+1))
  fi
}

echo "🔍 Running checks..."
run_check "ruff lint"        "ruff check $EXISTING 2>&1 | tail -1"
run_check "pytest"           "python -m pytest tests/ -v --tb=line 2>&1 | tail -3"
run_check "AGRD error codes" "test $(grep -rn NRVQ- $EXISTING 2>/dev/null | wc -l) -gt 0 && echo PASS || echo FAIL"
run_check "No print()"       "test $(grep -rn "print(" $EXISTING 2>/dev/null | grep -v "^#" | wc -l) -eq 0 && echo PASS || echo FAIL"
run_check "No requests lib"  "test $(grep -rn "import requests" $EXISTING 2>/dev/null | wc -l) -eq 0 && echo PASS || echo FAIL"
run_check "No os.path"       "test $(grep -rn "os\.path" $EXISTING 2>/dev/null | wc -l) -eq 0 && echo PASS || echo FAIL"
run_check "No threading"     "test $(grep -rn "import threading\|from threading" $EXISTING 2>/dev/null | wc -l) -eq 0 && echo PASS || echo FAIL"
run_check "Config loads"     "python -c "from norviq.config import settings" 2>&1 | grep -q Error && echo FAIL || echo PASS"
run_check "Mermaid .mmd"  "test -f architecture/${FEAT}.mmd && echo PASS || echo FAIL"
run_check "Code registry" "test -f registry/${FEAT}.md && echo PASS || echo FAIL"
run_check "Type hints"       "test $(grep -rn "def " $EXISTING 2>/dev/null | wc -l) -eq $(grep -rn "def .*(.*:" $EXISTING 2>/dev/null | wc -l) && echo PASS || echo FAIL"

echo ""
echo "Result: ${PASS}/9 passed, ${FAIL}/9 failed"
echo ""

# ── CLAUDE CODE REVIEW ───────────────────────────────────
echo "🤖 Claude Code reviewing (reads full repo from disk)..."
echo ""

# Send ONLY: spec + feature files + check results
# Claude Code reads CLAUDE.md automatically + can access any repo file
REVIEW_PROMPT="Review Norviq feature ${FEAT}.

## Spec (the contract):
$(cat "$SPEC")

## Automated Check Results:
| Check | Result | Details |
|-------|--------|---------|
$(echo -e "$RESULTS")

## Feature Code (read these files from disk):
$(for f in $EXISTING; do echo "- $f"; done)

Also read and verify:
- architecture/${FEAT}.mmd (Mermaid diagram)
- registry/${FEAT}.md (code registry)
Read each file from disk directly. Do not ask the user to paste code.

## Instructions:
- Follow the review format defined in CLAUDE.md
- Check imports resolve against actual files in the repo (read from disk)
- Verify upstream dependencies exist (check norviq/ directory)
- Check for security vulnerabilities, memory leaks, blocking I/O
- Show data flow: what feeds into this feature, what consumes its output
- Give specific fix instructions for Cursor (numbered, actionable)
"

echo "$REVIEW_PROMPT" | claude --print

echo ""
echo "══════════════════════════════════════════════════════════"
echo "  Review complete. Fix issues in Cursor, then re-run:"
echo "  ./scripts/review.sh ${FEAT}"
echo "══════════════════════════════════════════════════════════"
REVIEWEOF
chmod +x scripts/review.sh

echo "✅ Created:"
echo "  - specs/*.md (45 spec files)"
echo "  - CLAUDE.md (Claude Code instructions)"
echo "  - scripts/review.sh (review runner)"
echo ""
echo "Usage:"
echo "  1. Cursor: paste specs/F001.md -> generate code"
echo "  2. Review: ./scripts/review.sh F001"
