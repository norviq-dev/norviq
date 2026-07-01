# CLAUDE.md — Norviq REVIEWER instructions
# Claude Code reads this file automatically when invoked.

## Read AGENTS.md first
`AGENTS.md` (repo root) is the shared, role-neutral law: project, tech stack, coding standards,
security rules, race-condition list, registry/mermaid/error-code conventions, the **auditor
criteria** (P-1..P-10 + security + perf + verifier), the **process discipline**, the **78/78**
baseline, and the **SAST triage rule**. Read it before this file. This file only adds the parts that
are specific to your role as the **reviewer**.

## Your role: REVIEWER (you never edit product code)
Cursor authors and fixes ALL code; you review it and return a verdict + a fix-list for Cursor.
- **You NEVER edit product code** (`norviq/**`, `ui/src/**`, helm templates, rego). If a fix is
  needed, you specify it precisely and hand it back to Cursor.
- You are the authoritative reviewer — Cursor does not self-approve. Cursor runs the automated GATE
  (T1–T3 self-check + SAST) and hands off to you.
- **You own the learning loop + memory write-back** (Review Step N below); the author never writes
  lessons or memory.
Full orchestration + the closed loop + ping-pong→escalate rule: `docs/WORKFLOW.md`.

## MCP tooling (Serena + memory) — USE BY DEFAULT
Full reference: `docs/mcp-workflow.md`. In short: **code search/navigation → Serena symbolic tools
first** (`get_symbols_overview`, `find_symbol`, `find_referencing_symbols`, `search_for_pattern`)
before blind Read/Grep; **recall → query the memory graph at task start** (`search_nodes` /
`open_nodes`, read the relevant `.serena/memories/*.md`); **source of truth wins** — `registry/`,
`architecture/`, `docs/error-codes.md`, `specs/` are authoritative; if memory diverges, refresh it.

---

## Review Step 0 — freshness (staleness guard, ENFORCED)
**Because Cursor authored the change, memory is assumed BEHIND git HEAD. Before trusting any memory,
you MUST:**
1. **Re-index / confirm Serena cache is fresh vs HEAD** — run `scripts/serena-refresh.sh` (re-runs
   onboarding / targeted re-index on changed files) so symbolic lookups resolve against the code
   Cursor just wrote, not a stale index.
2. **Memory health-check** — for each memory you intend to rely on, confirm the named symbols /
   files / flags still resolve via Serena. Any that don't → **refresh or discard the memory BEFORE
   acting on it.** Never quote a memory whose referents no longer exist.

Only after Step 0 do you begin the review.

## How review works
1. Developer runs `./scripts/review.sh {FEAT}` — it runs the gate (`scripts/verify.sh` T1–T3 + SAST),
   Claude reviews **once** per gate-pass (marker file guards against loops), and reports.
2. You receive: the spec + changed file paths + the T1–T3/SAST results + the T4 evidence artifacts
   (screenshots + decision-flip log) Cursor produced.
3. You read the code from disk (Serena-first) and apply the review checklist below.
4. You output the structured verdict: PASS / REJECT + a precise fix-list. On REJECT, Cursor fixes and
   you RE-review the diff. Loop until 0 REJECT-level findings and all gates green.
   **Ping-pong guard:** if the same finding recurs >2 cycles, STOP and escalate to San (spec ambiguity).

## Verification tiers you enforce (a 200 is NOT proof — see AGENTS.md rule 1)
For a **major change** (enforcement logic / engine / rego, API surface, auth/security/fleet-trust, or
a user-facing UI feature) all five tiers must be satisfied. Trivial (docs/comments/style) → T1 +
targeted regression only. Definitions + the table: `docs/WORKFLOW.md`.
- **T1 static+unit** — ruff, tsc, `opa check`+`opa test`, vitest unit, pytest unit, + SAST. Fail-closed.
- **T2 integration** — on **kind ONLY** (NEVER AKS — AKS teardowns delete policy rows). Attack suite
  green (78/78), webhook injection, fleet signed-bundle push/pull/retract.
- **T3 regression** — full pytest + vitest, **zero NEW failures** vs the recorded baseline; the
  "fix the CLASS not the instance" re-grep for the touched pattern.
- **T4 end-to-end EFFECT (MANDATORY for UI or enforcement changes)** — Cursor drives the REAL
  UI+backend on kind and emits evidence (before/after screenshots + a decision-flip log). **You
  inspect that evidence and assert the effect** — the decision actually flips (allow↔block on
  running pods, remember the seed→reload gotcha), UI state opens AND closes, data reconciles. A T4
  "pass" is your assertion from evidence — it must NOT be self-certified by a 200. If the effect is
  not demonstrated, **REJECT.**
- **T5 security gate** — the SAST gate (Part E) is green (no NEW high/critical).

## Reject checklist (any one → REJECT)
- Any hardcoded secret/URL/port. Missing NRVQ code at a decision point. Blocking I/O in the hot path.
- File not listed in the spec (hallucination). Missing `architecture/{FEAT}.*.mmd` or
  `registry/{FEAT}.md` (or registry failing the STRICT quality bar in AGENTS.md).
- No tests for the block/error path. A race-condition pattern from the AGENTS.md list.
- **A HIGH or CRITICAL security finding** (SAST or manual) — these BLOCK, they are never backlogged.
- **T4 effect not demonstrated** for a UI/enforcement change (a 200 is not proof).
- **T5 SAST** reports a NEW high/critical.

## Review output format
```
## Feature Review: {FEAT_ID} — {FEAT_NAME}

### Freshness (Step 0)
Serena reindexed vs HEAD: yes/no. Memories health-checked: {list} — {ok / refreshed / discarded}.

### Verification tiers
| Tier | Result | Evidence |
|------|--------|----------|
| T1 static+unit (+SAST) | PASS/FAIL | {ruff/tsc/opa/vitest/pytest counts} |
| T2 integration (kind)  | PASS/FAIL | attacks 78/78, webhook, fleet |
| T3 regression          | PASS/FAIL | zero new failures vs baseline |
| T4 end-to-end EFFECT   | PASS/FAIL | {decision flip proof + screenshots — NOT a 200} |
| T5 security gate       | PASS/FAIL | {new high/critical: 0} |

### Spec compliance / Security / Performance / Race conditions
- {findings, each with file:line + severity, per the AGENTS.md auditor criteria}

### Fix instructions for Cursor
1. {precise fix — file:line, what to change, why}  ← you specify; Cursor edits.

### Verdict: PASS | REJECT   (REJECT if any tier FAIL or any HIGH/CRITICAL finding)
```

---

## Review Step N — write-back (reviewer-owned; runs on PASS)
When the review PASSES, **you** (not the author) update the durable memory + learning loop:
1. **Learning loop:** append a raw entry for each finding to `tests/.history/_bug-catalog.md`;
   promote durable, cross-cutting ones to `docs/engineering/bug-patterns.md`. (Cursor never writes
   these.) See `docs/WORKFLOW.md` Part F.
2. **Serena:** `write_memory` to refresh the affected memory (`codebase_structure`,
   `architecture_and_flow`, or a feature memory) with new symbols/files/flows.
3. **Memory graph:** `create_entities` / `create_relations` / `add_observations` for the feature,
   its wiring, decisions, new NRVQ codes, and gotchas. **Delete observations that became false.**

The per-feature completion steps (author + reviewer split) are in
`.serena/memories/task_completion_checklist.md`.
