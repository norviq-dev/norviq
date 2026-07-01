# Conventions, Review Discipline & Spec Workflow

`AGENTS.md` (repo root) is the shared law both tools read; `CLAUDE.md` is the thin REVIEWER wrapper
and `.cursor/rules/coder.mdc`+`fixer.mdc` the AUTHOR wrapper. **Cursor authors + fixes ALL code;
Claude reviews only and owns the lessons/memory write-back.** Full orchestration: `docs/WORKFLOW.md`.

## Coding standards (enforced)
- Functions <30 lines, classes <150, files <300.
- Type hints on every signature. One-line docstrings.
- `structlog` with an NRVQ error code at every log/decision point. Never `print()`.
- `httpx` not `requests`; `pathlib` not `os.path`; `asyncpg` not `psycopg2`.
- async/await on ALL I/O. No threading (asyncio in Python, goroutines in Go).
- No hardcoded secrets/URLs/ports — config only via `from norviq.config import settings`.
- Pydantic `model_validate()`, never raw dict unpacking. Parameterized SQL only.
- No `eval`/`exec`/`pickle.loads`.

## Performance (customer-facing chatbot)
- Redis cache check BEFORE any DB or OPA call. Connection pools, never per-request open/close.
- Audit writes are fire-and-forget. No blocking I/O in the hot path.

## Race conditions → REJECT
- Redis read-then-write without atomic op / Lua. PG check-then-insert without ON CONFLICT.
- Shared mutable async state without Lock. In-memory policy mutated in place during hot-reload.

## Required artifacts per feature (missing any = REJECT)
- `specs/{FEAT}.md` — the contract; do NOT create files not listed in it.
- `registry/{FEAT}.md` — strict 12-section format, tables with accurate `file:line`
  (sections 3 Structure, 9 Upstream, 10 Error-Code Map, 12 Debug Guide must be tables).
- `architecture/{FEAT}.class.mmd`, `.sequence.mmd`, `.deps.mmd` — ONE diagram type per file, names match source.

## Feature IDs
S001–S003 (setup), F001–F041 (features), DAY7–DAY9 (UI). See specs/ and registry/.

## Must-read engineering docs before touching related code
- `docs/engineering/bug-patterns.md` — real incidents (P-1..P-16). Highest cost: async/session lifecycle (P-12/15/16) and the OPA field-path bug (`input.agent` vs `input.agent_identity`).
- `docs/engineering/opa-input-schema.md` — authoritative OPA input.
- `docs/engineering/test-baseline-discipline.md` — attacks **78/78** zero-xfail; AKS is source of truth; local drifts.
- `docs/engineering/aks-operations.md` — startup-race (P-14) fix, recovery, image-SHA check.

## Review flow (dual-tool; a 200 is NOT proof)
`./scripts/review.sh F0xx` runs the feature gate → `scripts/verify.sh` verification tiers → a single
Claude review (marker-guarded, no loops). Verification tiers (`docs/WORKFLOW.md` Part D):
- **T1** static+unit (ruff, tsc, opa check+test, vitest/pytest unit, fast SAST) — fail-closed.
- **T2** integration on **kind ONLY** (never AKS): attacks **78/78**, webhook, fleet.
- **T3** regression: full pytest+vitest, zero NEW failures vs baseline.
- **T4** end-to-end EFFECT (UI/enforcement): reviewer asserts the decision flip / UI state change from
  evidence (screenshots + decision-flip log) — NOT a 200.
- **T5** security gate green (SAST).
Findings: **CRITICAL and HIGH-security BLOCK (fail-closed).** Everything doable is **fixed in-scope
now — nothing is routed to a backlog** (AGENTS.md). Escalate only genuine spec/threat-model calls to
San. On PASS, the **reviewer** does the memory + `_bug-catalog`/`bug-patterns` write-back (the author
never writes lessons).
