# Task / Feature Completion Checklist

Run through this whenever a coding task or new feature is "done", before reporting success.
Ownership is split: the **AUTHOR (Cursor)** does steps 1–7 + T4 evidence; the **REVIEWER (Claude)**
does the verification verdict + steps 8–10 (memory + lessons write-back). See `docs/WORKFLOW.md`.

## AUTHOR — code is correct + tiers (a 200 is NOT proof)
1. `make lint` (`ruff check norviq/ tests/`) is clean — no new violations. **T1** also: tsc,
   `opa check`+`opa test`, vitest/pytest unit, fast SAST — run `scripts/verify.sh {FEAT} --tier T1`.
2. **T2 integration on kind ONLY (never AKS):** `tests/attacks/` is **78/78** with **zero xfails**
   (clear Redis drift first: DEL `agent_history:* agent_profile:* trust:* eval:*`, restart API);
   webhook + fleet integration green.
3. **T3 regression:** full pytest + full vitest, **zero NEW failures** vs the recorded baseline.
4. **T4 end-to-end EFFECT (UI or enforcement change):** don't stop at `npm run build`/a 200 — drive
   the REAL UI+backend on kind and produce before/after screenshots + a decision-flip log proving the
   actual effect (allow↔block on running pods — mind the seed→reload gotcha; UI state open AND close).
   Attach as the T4 evidence for the reviewer.
5. **T5 security gate** (SAST) green — no NEW high/critical.

## AUTHOR — required artifacts updated (per AGENTS.md — missing any = REJECT)
6. `specs/{FEAT}.md` matches what was built (no files created outside the spec).
7. `registry/{FEAT}.md` (12 sections, accurate `file:line`, every NRVQ code mapped) +
   `architecture/{FEAT}.class.mmd`/`.sequence.mmd`/`.deps.mmd` match source + new NRVQ codes in
   `docs/error-codes.md`.

## REVIEWER (Claude) — memory + lessons write-back on PASS (see [[mcp_workflow]] Review Step N)
8. **Freshness first (Step 0):** run `scripts/serena-refresh.sh` — reindex + memory health-check
   before trusting any memory.
9. **Serena + graph:** `write_memory` to refresh the affected memory (`codebase_structure`,
   `architecture_and_flow`, or a feature memory) with new symbols/files/flows; `create_entities` /
   `create_relations` / `add_observations` for the feature, wiring, decisions, error codes, gotchas.
   **Remove observations that are now false.**
10. **Learning loop:** append each finding to `tests/.history/_bug-catalog.md`; promote durable ones
    to `docs/engineering/bug-patterns.md`. The author never writes these.

## Done means done
11. Report honestly: if a tier failed or a step was skipped, say so with the output. Do NOT commit —
    San commits after PASS.
