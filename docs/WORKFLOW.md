<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Norviq Contributors -->

# WORKFLOW.md — the Norviq dual-tool orchestration contract

The one doc a new session reads to understand how **Cursor**, **Claude Code**, and the **Planner
(Cowork) + San** interact. Shared rules live in [`AGENTS.md`](../AGENTS.md); this file is the
process.

## Roles & ownership (non-negotiable)
| Concern | Owner | Never |
|---------|-------|-------|
| Product code — author **and fixes** | **Cursor** | Claude never edits product code |
| Code review (findings + verdict) | **Claude Code** | Cursor does not self-approve |
| Lessons + Serena/graph memory write-back | **Claude Code** (reviewer) | Cursor never writes its own lessons/memory |
| Specs / plans / roadmap / approvals / commits | **Planner (Cowork) + San** | tools never auto-commit |

Each tool loads the shared law natively: Cursor reads `AGENTS.md` + `.cursor/rules/*`; Claude reads
`AGENTS.md` + `CLAUDE.md`. **No symlink** between `CLAUDE.md` and `AGENTS.md` (avoids bleeding the
reviewer role into the author). A push to `main` is a deploy — only San commits/pushes.

## The closed loop (must terminate)
```
Planner: spec (specs/{FEAT}.md)
   │
Cursor (AUTHOR): read AGENTS.md + bug-patterns.md → write code + registry + architecture + tests
   → run T1 locally → self-audit (3 .cursor/agents) → produce T4 evidence → hand off
   │
Claude (REVIEWER): Review Step 0 freshness (serena-refresh.sh) → review against T1–T5 + reject checklist
   → verdict
        REJECT → fix-list → Cursor fixes → Claude RE-reviews the diff ──┐ (loop)
        PASS   → Review Step N write-back (memory + _bug-catalog + bug-patterns) → hand to San to COMMIT
   │
Termination: loop until 0 REJECT-level findings AND all gate tiers green.
Ping-pong guard: if the SAME finding recurs > 2 cycles, STOP and escalate to San (spec ambiguity).
```

### Review→fix handoff (file-based, no human relay)
The REJECT→fix arrow above runs through files, not a human paste:
- **Path convention:** the reviewer WRITES `.reviews/{FEAT}-fixes.md` (actionable verdict + fix-list)
  and `.reviews/{FEAT}-claude.md` (full review); the author's `fixer` rule READS `-fixes.md` first
  (STEP 1) and applies the fixes in-scope, then re-runs the gate.
- **OVERWRITE semantics:** each review overwrites both files — the latest review is the single
  source of truth (never appended). Durable, cross-cutting findings are promoted to
  `tests/.history/_bug-catalog.md` (Part F) — that is the append-only history, not `.reviews/`.
- **Reviewer writes / author reads.** Holds both via `scripts/review.sh` (stdout capture) and
  interactive review (Claude writes the two files itself).
- **Ephemeral:** `.reviews/` is gitignored — per-cycle scratch, NOT committed.

## "Major change" (triggers the full gate set)
Any change to: **enforcement logic (engine / rego)**, **API surface**, **auth / security /
fleet-trust surface**, or a **user-facing UI feature**. Trivial (docs, comments, string/style) →
**T1 + targeted regression only**.

## Verification tiers (a 200 is NOT proof — AGENTS.md rule 1)
`scripts/verify.sh {FEAT} [--tier ...]` orchestrates these; `scripts/review.sh` runs T1–T3+T5 as the
gate and emits T4 evidence for the reviewer.

| Tier | What | Where | Gates how |
|------|------|-------|-----------|
| **T1 static + unit** | ruff · tsc · opa check+test · vitest/pytest unit · fast SAST | local + CI | fail-closed |
| **T2 integration** | attacks **78/78** · webhook injection · fleet push/pull/retract | **kind ONLY — never AKS** (AKS teardowns delete policy rows) | fail-closed |
| **T3 regression** | full pytest + full vitest, **zero NEW failures** vs baseline; "fix the CLASS" re-grep | local + CI | fail-closed |
| **T4 end-to-end EFFECT** | real UI+backend on kind; decision flips (allow↔block on running pods, mind seed→reload); UI state open AND close; before/after screenshots | kind | **reviewer asserts from evidence — NOT self-certified by a 200** |
| **T5 security gate** | the SAST gate (below) is green (no NEW high/critical) | pre-commit + CI | fail-closed |

T4 is mandatory for UI or enforcement changes: `verify.sh` produces the evidence under
`.reviews/{FEAT}-t4-evidence/`; the reviewer REJECTs if the effect isn't demonstrated.

## Security gate (SAST) — start green, then ratchet
Wired via `.github/workflows/security.yml` (PR) + `.github/workflows/build.yml` (image scan on main)
+ `.pre-commit-config.yaml` (fast subset). Tools: bandit · semgrep · pip-audit (Python) · eslint-security
· npm/osv audit (TS) · gitleaks (secrets, **diff/PR-range only, not history**) · checkov · kube-linter
(Helm/CRDs) · trivy (config on PR, **image** post-build on main).
- **HIGH/CRITICAL BLOCK** (fail-closed). **MED/LOW** triaged by the reviewer (fix in-scope if doable,
  else logged with rationale in `docs/engineering/security-baseline.md`).
- The gate ships with baselines/allowlists (`.gitleaks.toml`, `.semgrepignore`, `.trivyignore`,
  `[tool.bandit]`, `.checkov.yaml`) so it starts GREEN and only NEW findings fail. Ratchet plan +
  triage log: `docs/engineering/security-baseline.md`.

## Part F — the learning loop (both directions; reviewer owns write-back)
- **AUTHOR** reads `docs/engineering/bug-patterns.md` BEFORE coding (`.cursor/rules/coder.mdc`) and
  updates only its own `tests/.history/{FEAT}.md`.
- **REVIEWER**, on every finding, APPENDS a raw entry to `tests/.history/_bug-catalog.md` and
  promotes durable, cross-cutting ones to `docs/engineering/bug-patterns.md`; and does the Serena +
  memory-graph write-back (Review Step N). **Cursor never writes lessons or memory.**
- Periodic hygiene: a monthly "promote raw→curated" + de-dup pass over `_bug-catalog.md` →
  `bug-patterns.md` (reviewer-owned).

## Non-negotiables (from AGENTS.md, restated at the seam)
Prove the EFFECT not a 200 · apply doable fixes now, don't backlog · no auto-commit (San commits) ·
never write the shared hub/fleet DB without explicit approval · record every significant prompt in
`specs/prompts/` + index · attack baseline is **78/78** zero-xfail.

## Bootstrap note
This workflow itself was bootstrapped by Claude Code directly (docs/config/CI only — the one
exception, because the author/review split wasn't live yet). From the next FEATURE on, the split is
live: Cursor authors, Claude reviews.
