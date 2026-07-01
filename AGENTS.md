<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Norviq Contributors -->

# AGENTS.md — Norviq shared rules (role-neutral)

**Both tools read this file natively.** Cursor (the author) and Claude Code (the reviewer) load this
as the shared contract. It holds everything that is true regardless of who is acting: the project,
the standards, the security rules, the conventions, and the **process discipline**. Role-specific
instructions live in the thin wrappers — `CLAUDE.md` (reviewer) and `.cursor/rules/coder.mdc` +
`fixer.mdc` (author). The orchestration contract is `docs/WORKFLOW.md`; the capability map is
`docs/registry-capabilities.md`.

> **Do NOT symlink `CLAUDE.md` ↔ `AGENTS.md`.** `CLAUDE.md` is the reviewer file; symlinking would
> bleed the reviewer role into the author's context. If a neutral alias is ever wanted, alias it to
> **this** file, never to the reviewer file.

---

## Project
Norviq: runtime security platform for LLM agent tool calls on Kubernetes. Sits between
LangGraph/LangChain agents and their tools. Every tool call is intercepted, evaluated against
OPA/Rego policies, and scoped to K8s workload identity (SPIFFE/SPIRE SVIDs).

## Tech stack
- Python 3.11+ (SDK, Engine, API) · Go 1.22+ (Webhook, CLI, Sidecar P2)
- FastAPI · SQLAlchemy + asyncpg · Redis · OPA/Rego · SPIFFE/SPIRE
- OpenTelemetry · Helm · Kubernetes CRDs · React/TypeScript + Vite (console UI)

## Feature IDs
S001–S003 (setup), F001–F0xx (features), DAY7–DAY9 (UI). See `specs/` and `registry/`.

---

## Coding standards (enforced — a violation is a REJECT)
- Functions <30 lines, classes <150, files <300.
- Type hints on every signature. One-line docstrings only.
- `structlog` with an `NRVQ-XXX-NNNN` error code at every log/decision point. Never `print()`.
- `httpx` not `requests`; `pathlib` not `os.path`; `asyncpg` not `psycopg2`.
- async/await on ALL I/O. No threading (asyncio in Python, goroutines in Go).
- No hardcoded secrets/URLs/ports — config only via `from norviq.config import settings`.
- Pydantic `model_validate()`, never raw dict unpacking. Parameterized SQL only.
- No `eval` / `exec` / `pickle.loads`.
- SPDX header on every source file (`# SPDX-License-Identifier: Apache-2.0` /
  `# Copyright 2026 Norviq Contributors`).

## Performance (customer-facing chatbot — <5ms p99 evaluation budget)
- Redis cache check BEFORE any DB or OPA call. Connection pools, never per-request open/close.
- Audit writes are fire-and-forget (`asyncio.create_task`). No blocking I/O in the hot path.
- No synchronous `sleep()` / `time.sleep()`. Reuse the `httpx` client; don't recreate per call.

## Race conditions → REJECT
- Redis read-then-write without atomic op / Lua. PG check-then-insert without `ON CONFLICT`.
- Trust-score update without `WATCH`/Lua. Shared mutable async state without a Lock.
- In-memory policy mutated in place during hot-reload. Go shared state without Mutex/channels.
- (WARN) missing `asyncio.Semaphore` on concurrent OPA evals; fire-and-forget tasks not tracked
  for shutdown.

---

## Required artifacts per feature (missing any = REJECT)
- `specs/{FEAT}.md` — the contract; do NOT create files not listed in it.
- `registry/{FEAT}.md` — strict 12-section format, tables with accurate `file:line`.
- `architecture/{FEAT}.class.mmd`, `.sequence.mmd`, `.deps.mmd` — ONE diagram type per file, names
  match the actual source.
- New `NRVQ-XXX-NNNN` codes added to `docs/error-codes.md`.

### Registry quality (STRICT — reject if unmet)
Sections 3 (Structure), 9 (Upstream), 10 (Error-Code Map), 12 (Debug Guide) MUST be tables:
- **§3 Structure:** `| Class | File:Line | Parent | Fields | Methods |` — prose or guessed lines → REJECT.
- **§9 Upstream:** `| Feature | Class | File:Line | Key Methods | Error Codes |` — must list EVERY
  imported upstream class; prose like "Upstream: S002 provides config" → REJECT.
- **§10 Error-Code Map:** `| Code | Level | File:Line | When It Fires | What To Check |` — every NRVQ
  code in the source appears here; "What To Check" must be actionable (not "see logs").
- **§12 Debug Guide:** `| Symptom | Cause | File:Line | Fix |` — min 3 rows (error, timeout,
  fallback); "Fix" is an exact command (`redis-cli DEL eval:{ns}:{class}:{tool}`, env var
  `NRVQ_SDK_TIMEOUT_MS`, `kubectl …`) — "investigate"/"tune settings"/"check logs" → REJECT.
- §12b (Downstream Impact) REQUIRED for any feature others depend on.

### Mermaid rules (STRICT)
- ONE diagram type per `.mmd` (parser limitation). Each feature needs all 3 files:
  `architecture/{FEAT}.class.mmd` (classDiagram), `.sequence.mmd` (sequenceDiagram), `.deps.mmd`
  (graph LR). All names match ACTUAL source. Missing any / content mismatching source → REJECT.

---

## Auditor criteria (shared — the same lists Cursor's `.cursor/agents` and Claude's review use)
These are consolidated here so author self-audit and reviewer verdict apply the **same** bar. Full
agent prompts: `.cursor/agents/norviq-{correctness,security,performance,verifier}.md`.

### Correctness — the 10 Day-8 bug patterns (P-1…P-10)
- **P-1** Hardcoded MVP stubs — a function returns a hardcoded dict/value while the real downstream
  call is suppressed (F009 `_evaluate_opa` returned `{"decision":"allow"}` without calling OPA).
- **P-2** Regex shortcuts bypassing real logic — `re.search/match` near a `return` that skips the
  real path.
- **P-3** Sub-second subprocess timeouts — `timeout=` < 1.0s on a subprocess (OPA takes ~150ms).
- **P-4** Memory-vs-DB state mismatch — in-memory dict updated but no DB INSERT/UPDATE (or vice versa).
- **P-5** Cache TTLs hiding behavior — cache set before the result is verified, or TTL < 30s masking bugs.
- **P-6** Ambiguous decision provenance — `decision="allow"` with `rule_id=""`/`default_allow` that
  looks like a real result; use distinct `no_policy` / `evaluator_error` / `evaluator_timeout`.
- **P-7** xfail masking real failures — `@pytest.mark.xfail`/`pytest.xfail()` without reason+date; a
  connection error must ERROR, not xfail.
- **P-8** Wrong subprocess query paths — OPA query must be specific `data.<package>.<rule>`, not `data`.
- **P-9** Version-incompat flags — `--v0-compatible` present on `opa eval`; tool versions pinned.
- **P-10** Deploy mismatches — schema change without an Alembic migration; new env var not in Helm values.
- Also: **P-14** startup race (Ready-for-real, not racing); **P-16** async/session lifecycle. Do NOT
  take "this is MVP placeholder" at face value — verify the real path runs.

### Security (Norviq IS a security control — its own bugs are security gaps)
- **Fail-open** — any except/timeout handler returning `decision="allow"`; security decisions must
  **fail closed (block)**. Swallowed errors → REJECT.
- **Secrets in logs/audit** — unredacted tool params, passwords/tokens/api_keys/JWTs in audit or errors.
- **Injection** — raw SQL in policy/audit endpoints; user input to subprocess unsanitized;
  user-uploaded Rego must be validated.
- **AuthN/Z bypass** — endpoint missing the auth dependency; JWT verification skipped on a path;
  token via query string not header.
- **OPA tampering** — lower-priority policy must not override higher; admin actions may need re-auth.
- **Cross-tenant isolation** — a namespace's policy/trust/audit leaking to another; queries not
  filtered by the caller's namespace. Validate SPIFFE ID before any trust lookup.

### Performance (defend the <5ms p99 budget)
- Subprocess spawn in hot path (150ms cold); sync I/O in async (`open`/`requests`/sync session →
  `aiofiles`/`httpx`/`asyncpg`); DB queries in hot path (cache-first, DB only on miss); pool sizing
  set (asyncpg/redis/httpx reused); unbounded in-memory growth; N+1 (batch via IN/JOIN).

### Verifier — "done" is not a claim, it's four proven layers
Code **exists** (defined + imported + called) · **runs** (tests/gate pass, note skips/xfails) ·
**produces expected behavior** (run a known attack → decision == expected; POST a policy → row
present; UI → navigate + screenshot + console) · **edge cases** (timeout, error, empty, boundary).
Verdict: PASS | FAIL | PASS_WITH_CAVEATS.

---

## Process discipline (non-negotiable — ported from Cowork memory/specs so both tools obey it)
1. **Prove the EFFECT, not a 200.** A `200`, a green test count, or "endpoint returned OK" is NOT
   proof. Prove the actual effect: the decision flips (allow↔block) on running pods, the UI state
   changes (open AND close), data reconciles, before/after evidence exists. This is the T4 bar (see
   `docs/WORKFLOW.md`).
2. **Apply doable in-scope fixes now — do NOT backlog.** If a finding is fixable within the change's
   scope, fix it in this cycle. Do not route it to a backlog file. Escalate to San only genuine
   spec-ambiguity or threat-model decisions.
3. **No auto-commit — San commits.** Never `git commit`/`git push` on the human's behalf; a push to
   `main` triggers deploy. Summarize what changed and let San commit. (Scripts must never contain a
   `git push`.)
4. **Never write the shared hub/fleet DB without explicit approval.** The app policy DB is writable
   in dev; the hub/fleet Postgres (`norviq_fleet`) is not, unless San has approved AKS-as-hub for
   that action. Confirm which DB before any write.
5. **Record every significant prompt in `specs/prompts/` + the index** (`specs/prompts/README.md`).

## Test baseline
The `tests/attacks/` suite baseline is **78/78, 0 failed, 0 xfailed**. `xfail` from a connection
error is a masked failure (P-7), not "fine." AKS is the source of truth; local Postgres/Redis drift
— clear runtime keys and re-seed before measuring. Full rules: `docs/engineering/test-baseline-discipline.md`.

## Security / SAST triage rule (see `docs/WORKFLOW.md` Part E for the gate)
- **HIGH / CRITICAL findings BLOCK** the review/merge — fail-closed.
- **MEDIUM / LOW** are triaged by the reviewer: fix in-scope if doable (rule 2 above), else log with
  rationale + a ticket in `docs/engineering/security-baseline.md`.
- The SAST gate ships with a **baseline/allowlist** (`.gitleaks.toml`, `.semgrepignore`,
  `.trivyignore`, bandit baseline) so it starts GREEN on the existing codebase and then ratchets:
  only NEW high/critical fails the gate. Every baselined item is recorded with rationale.

## Engineering references (consult before touching related code)
- `docs/engineering/bug-patterns.md` — real incidents (P-1..P-16). The AUTHOR reads this BEFORE coding.
- `docs/engineering/opa-input-schema.md` — authoritative OPA input & field paths (`input.agent` vs
  `input.agent_identity`).
- `docs/engineering/test-baseline-discipline.md` — baseline, drift check, guard tests.
- `docs/engineering/aks-operations.md` — startup-race fix, recovery, image-SHA check.
- `docs/error-codes.md` — the NRVQ error-code registry.

## Platform note
Dev is **macOS**. The Windows-era `scripts/*.ps1` files (`dev-setup.ps1`, `aks-verify.ps1`,
`dev.ps1`) were **removed** during this hardening — `aks-verify.ps1` contained a `git push origin
main` (a deploy) that violates the no-auto-commit rule. Use the `scripts/*.sh` entrypoints. A stale
`migrate-pack.ps1` remains at the repo root (benign, no git ops) — do not rely on it.
