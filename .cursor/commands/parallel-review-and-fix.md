---
name: parallel-review-and-fix
description: Run all 3 Norviq reviewer subagents in parallel against changed files, then apply the doable in-scope P0/P1 fixes now (do NOT backlog). Only genuine spec-ambiguity or threat-model decisions are escalated to San.
---

# Parallel Review and Auto-Fix

When invoked:

## Step 1 — Determine Target Files

Try these in priority order. Use the first non-empty result:

a. **User passed file paths as arguments** → use those exactly

b. **Staged changes**:
   ```bash
   git diff --cached --name-only
   ```

c. **Uncommitted changes (working tree vs last commit)**:
   ```bash
   git diff --name-only HEAD
   ```

d. **Last commit**:
   ```bash
   git diff --name-only HEAD~1
   ```
   Tell user: "Reviewing last commit. Want a wider range? Use `/parallel-review-and-fix --since=HEAD~5`"

e. **Nothing found** → ask user: "No changes detected. Which files would you like reviewed?"

Filter results to Norviq source files only:
- **Keep**: `norviq/**/*.py`, `ui/**/*.tsx`, `ui/**/*.ts`, `webhook/**/*.go`, `cli/**/*.go`
- **Exclude**: `tests/`, `docs/`, `.cursor/`, `scripts/`, `prompts/`, `helm/`, `*.md`, `*.yaml`

Echo the list to user before proceeding:
```
Reviewing N files:
  - norviq/engine/evaluator.py
  - norviq/api/routers/evaluate.py
  - ...
Proceed? (yes/no)
```

If user says no, abort.

## Step 2 — Spawn 3 Subagents in Parallel

Use Cursor's Task tool to spawn all three simultaneously (not sequentially):

```
Task: subagent_type=norviq-correctness-auditor, prompt="Review these files: <list>"
Task: subagent_type=norviq-security-auditor, prompt="Review these files: <list>"
Task: subagent_type=norviq-performance-auditor, prompt="Review these files: <list>"
```

Wait for all 3 to complete. Each saves its report to `.reviews/<dim>-{sha}.md`.

## Step 3 — Merge Findings

Read all 3 reports. Create consolidated report at `.reviews/parallel-{sha}.md`:

- Deduplicate findings appearing in multiple dimensions (count once, keep worst severity)
- Sort by severity: P0 → P1 → P2
- Group by file path
- Include executive summary at top (5 bullets max)

## Step 4 — Categorize for Auto-Fix

For each finding, decide:

**AUTO-FIX** (apply automatically):
- P0 findings that are:
  - Fail-open patterns (exception/timeout returning "allow")
  - Hardcoded MVP stubs in production code paths
  - Missing input validation that's a quick fix
- P1 findings matching bug catalog patterns P-1, P-2, P-4, P-5, P-6, P-7, P-8, P-9
- P1 findings tagged "fail-open" or "security risk"
- All findings about sensitive data in logs (gate behind env var)

**ESCALATE TO SAN** (do not auto-fix — genuine design decisions only):
- Anything touching `norviq/engine/evaluator.py` `_evaluate_opa` subprocess design (architectural)
- Anything requiring a threat-model decision (e.g. Rego signing) or a spec change
- Findings touching files in `.cursor/`, `scripts/`, `prompts/` (out of this command's scope)

**APPLY IN-SCOPE NOW** (per AGENTS.md — do NOT backlog): everything else that is doable within the
change's scope, including DB-schema fixes (add the Alembic migration), new env vars (add to Helm
values), and P2 style. If a "doable" fix balloons past the change's scope, escalate to San with a
one-line rationale rather than silently deferring.

## Step 5 — Apply Auto-Fixes

For each AUTO-FIX finding:

1. Read the suggested fix from the subagent report
2. Show the diff to user:
   ```
   FIX: <pattern> at norviq/engine/evaluator.py:410
   ```
   ```diff
   - if value is None:
   -     return {"decision": "allow", "rule_id": "default_allow"}
   + if value is None:
   +     return {"decision": "block", "rule_id": "evaluator_invalid_payload", "reason": "OPA returned malformed output"}
   ```
3. Apply the fix (edit the file)
4. After each fix, spawn `norviq-verifier` subagent:
   ```
   Task: subagent_type=norviq-verifier, prompt="Verify the fix at norviq/engine/evaluator.py:410 doesn't regress behavior. Run relevant tests."
   ```
5. If verifier returns FAIL:
   - Revert the fix
   - Log to `.reviews/verifier-rejections-{sha}.md` with reason
6. If verifier returns PASS or PASS_WITH_CAVEATS:
   - Keep the fix
   - Move to next finding

## Step 6 — Escalate genuine design decisions to San (no backlog file)

Do NOT route findings to `docs/backlog.md`. For each ESCALATE finding (genuine spec-ambiguity or
threat-model decision only), summarize it to San in the run output so a decision can be made:

```markdown
## Escalations from parallel-review {sha} — {date}  (need San's decision)

- [P0] OPA subprocess in hot path → long-lived process (architectural)
  - File: norviq/engine/evaluator.py:381 — needs design discussion
- [P1] JWT tenant claim binding (threat-model / RBAC redesign)
  - File: norviq/api/routers/evaluate.py:46
```

Everything doable in-scope was already applied in Step 5 — nothing is silently deferred.

## Step 7 — Final Output

Display to user:

```
═══════════════════════════════════════
  Parallel Review Complete
═══════════════════════════════════════

Reviewed: N files
Total findings: M (P0=A, P1=B, P2=C)

✅ Auto-fixed (verified): X findings
   - norviq/engine/evaluator.py:410 (P1: fail-closed on malformed OPA output)
   - norviq/engine/evaluator.py:436 (P1: explicit error provenance)
   - norviq/engine/evaluator.py:374 (P1: gate debug logs)

⚠️ Verifier rejected: Y fixes (reverted)
   - <list>

⤴️ Escalated to San: Z findings (genuine design/threat-model decisions)
   - <list>

📄 Full report: .reviews/parallel-{sha}.md

Run `git diff` to inspect fixes. Reply 'revert' to undo all fixes.
Do NOT commit here — summarize the diff; San commits after Claude's review PASSes.
```

## Step 8 — Await User Decision

**Do NOT commit or push automatically — ever.** Cursor authors; San commits (a push to `main` is a
deploy). Wait for user response:

- "revert" → run:
  ```bash
  git checkout -- norviq/ ui/ webhook/ cli/
  ```

- "show fix N" → show the diff for that specific fix

- "skip fix N" → revert just that one fix

When the user is satisfied, hand the diff to Claude review (`./scripts/review.sh {FEAT}`) and stop.
San commits after Claude PASSes. This command never runs `git commit` or `git push`.

## Norviq-Specific Forbidden Auto-Fixes

These are NEVER auto-fixed (even if subagents flag them):

1. **`_evaluate_opa` subprocess architecture** — Day 14 task, needs design discussion
2. **Trust calculator signal weights** — Day 14 hardening, needs trust-score-design.md update
3. **JWT verification logic** — security-critical, needs Phase 2 RBAC design
4. **Rego policy validator** — needs threat model decision on signing
5. **Mutating webhook injection logic** — F016 stable, changes need full E2E test
6. **Database schema** — needs Alembic migration, can't auto-add
7. **Helm chart values** — needs operator review

If a subagent recommends a fix in these areas:
- Log to backlog as "Architectural - requires design discussion"
- Do not modify the file
- Continue with other fixes

## Usage Examples

```
# Review staged changes (default workflow)
git add -A
/parallel-review-and-fix

# Review specific files
/parallel-review-and-fix norviq/engine/evaluator.py norviq/api/routers/evaluate.py

# Review wider commit range
/parallel-review-and-fix --since=HEAD~5

# Review only files modified today
/parallel-review-and-fix --since=midnight
```

## What This Command Does NOT Do

- Does NOT run tests on its own (verifier subagent does that)
- Does NOT push to remote (user controls)
- Does NOT modify .cursor/, scripts/, prompts/, helm/, or tests/.history/
- Does NOT touch source code if subagents return no actionable findings
- Does NOT bypass user confirmation before final commit
