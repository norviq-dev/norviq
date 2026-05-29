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
1. Developer types: ./scripts/review.sh F001
2. review.sh finds specs/F001.md and the generated code files
3. Automated checks run (ruff, pytest, grep)
4. You receive: spec + file paths + check results
5. You read the code files directly from disk
6. You output: structured review with pass/fail + fix instructions

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
- structlog with NRVQ error codes (never print())
- httpx not requests. pathlib not os.path. asyncpg not psycopg2.
- No threading — use asyncio for Python, goroutines for Go

### 5. Memory + Concurrency
- Redis TTLs on ALL keys (no unbounded growth)
- Connection pools closed in shutdown hooks
- Pydantic model_validate() not dict unpacking
- No global mutable state (use dependency injection)
- OTel spans batched, never accumulated in memory

### 6. Architecture Diagram
- architecture/{FEAT}.mmd file exists
- Class diagram includes ALL upstream dependency classes (not just this feature)
- Every class shows ALL fields with types and ALL methods with return types
- Sequence diagram shows complete runtime flow from entry to return
- Dependency graph shows upstream imports + downstream consumers
- If .mmd file is missing: REJECT the feature

### 7. Code Registry
- registry/{FEAT}.md file exists
- All 12 sections present
- Every class in the code appears in Section 3 (Structure) with correct file:line
- Every method appears with correct args and return types
- Every NRVQ error code appears in Section 10 (Error Code Map) with file:line
- Section 9 (Upstream Table) includes ALL upstream dependency classes
- Section 11 (Concurrency) documents shared resources and protection
- Section 12 (Debug Guide) covers at least: error case, timeout case, fallback case
- File:line references are ACCURATE (not guessed)
- If registry is missing or incomplete: REJECT the feature

### 8. Test Coverage
- Allow path test (200 response, decision=allow)
- Block path test (200 response, decision=block)
- Error/fallback path test (engine unavailable, timeout)
- No mocked-away logic — test real code paths

### 9. Race Condition Review
- Redis read-then-write without atomic ops → REJECT
- PostgreSQL check-then-insert without ON CONFLICT → REJECT
- Trust score update without WATCH or Lua script → REJECT
- Shared mutable state between async coroutines without Lock → REJECT
- In-memory policy mutated in place during hot-reload → REJECT
- Missing asyncio.Semaphore on concurrent OPA evaluations → WARN
- Fire-and-forget tasks not tracked for shutdown → WARN
- Go shared state without Mutex/channels → REJECT

## Review Output Format
When reviewing, output this structure:

```
## Feature Review: {FEAT_ID} — {FEAT_NAME}

### Automated Checks
| Check | Result | Details |
|-------|--------|---------|
| ruff | PASS/FAIL | {output} |
| pytest | PASS/FAIL | {pass}/{total} tests |
| NRVQ codes | PASS/FAIL | {count} codes found |
| No print() | PASS/FAIL | {count} violations |
| No requests | PASS/FAIL | |
| No os.path | PASS/FAIL | |
| No threading | PASS/FAIL | |
| Config loads | PASS/FAIL | |
| Mermaid .mmd | PASS/FAIL | |
| Code registry | PASS/FAIL | |
| Type hints | PASS/FAIL | {typed}/{total} |

### Spec Compliance
- [x] ClassName matches spec
- [ ] Missing field: field_name

### Security Issues
- None found / {list issues}

### Performance Issues
- None found / {list issues}

### Race Condition Issues
- None found / {list issues}

### Architecture Diagram
Show ASCII class diagram:
+-----------------------------------------------+
| ToolCallEvent (F001)                          |
|-----------------------------------------------|
| + event_id: str                               |
| + agent_identity: AgentIdentity ──┐           |
+-----------------------------------------------+
         │ passed to                  │
         ▼                            ▼
+-------------------+    +-----------------------+
| OPAEvaluator      |    | AgentIdentity (F004)  |
| + evaluate()      |    | + spiffe_id: str      |
+-------------------+    +-----------------------+

### Method Call Chain
Show execution order:
1. protect(tools) ──► ToolCallInterceptor.__init__()
2. tool._run()    ──► interceptor.intercept(tool_name, params)
3.                ──► PolicyEngineClient.evaluate(event)
4. allow?         ──► original_tool._run() → result
   block?         ──► raise NorviqBlockError(decision)

### Fix Instructions for Cursor
1. {specific fix with file path and line number}
2. {specific fix}
3. ...
```

## When to REJECT code
- Any hardcoded secret or URL → REJECT immediately
- Missing error code at a decision point → REJECT
- Blocking I/O in the hot path → REJECT
- No tests for block/error path → REJECT
- File not listed in spec → REJECT (hallucination)
- Missing architecture/{FEAT}.mmd file → REJECT
- Missing registry/{FEAT}.md file → REJECT
- Redis read-then-write without atomic ops → REJECT
- PostgreSQL check-then-insert without ON CONFLICT → REJECT
- Shared mutable state without Lock/Mutex → REJECT
