# Prompt — Dual-tool workflow hardening (Cursor authors · Claude reviews · closed loop + gates)

**Date:** 2026-07-01
**Decision (San):** Shift execution to save Claude tokens — **Cursor writes all code, Claude reviews only** — and
harden the seams so nothing we fought for regresses. Most of the machinery already exists (`CLAUDE.md` reviewer spec,
`.cursor/rules` + `.cursor/agents`, `docs/mcp-workflow.md` Serena+memory protocol, `tests/.history/_bug-catalog.md` →
`docs/engineering/bug-patterns.md` learning loop). This change hardens the **seams**: role-neutral shared rules,
an *enforced* Serena staleness guard, a properly-closed author/review loop, mandatory verification tiers after every
major change (unit + integration + regression + end-to-end EFFECT — a 200 is NOT proof), and a security/SAST gate.
**Platform note:** dev is macOS (the `*.ps1` scripts are stale). Symlinks are viable but NOT used — see Part B.
**Base branch:** new branch `chore/dual-tool-workflow-hardening` off `main` (`0d3aef0`). Docs/config/CI only — no
product-code change. plan mode · do NOT auto-commit · record in `specs/prompts/` + index.
**Result:** **DONE (2026-07-01, branch `chore/dual-tool-workflow-hardening` off main `0d3aef0`;
docs/config/CI only — NOT committed; San commits).** All Parts A–G + the exact ADD/REWRITE/EDIT
deltas executed. **ADDED:** `AGENTS.md` (shared law + consolidated auditor P-1..P-10/sec/perf
criteria + the 5 process-discipline rules + SAST triage + 78/78 baseline), `docs/WORKFLOW.md`
(orchestration contract: roles, closed-loop, major-change, T1–T5 table, security gate,
ping-pong→escalate, Part-F learning loop), `docs/registry-capabilities.md`,
`.github/workflows/security.yml` (PR: gitleaks[diff]/bandit/semgrep[diff-aware]/eslint/pip+npm
audit/checkov/kube-linter/trivy-**config** — image scan NOT here), `.pre-commit-config.yaml`,
`scripts/verify.sh` (T1–T5; T4 EMITS evidence, never self-certifies on a 200; kind-only guard refuses
AKS), `scripts/serena-refresh.sh` (reindex + memory health-check), the SAST baselines
(`.gitleaks.toml` diff-scope, `.semgrepignore`, `.trivyignore`, `[tool.bandit]`, `.checkov.yaml`) +
`docs/engineering/security-baseline.md` (start-green→ratchet). **REWROTE** `scripts/review.sh` — the
3 violations fixed (removed `git push origin main`; removed HIGH/MED/LOW→backlog routing; HIGH-security
now fail-closed) + it calls `verify.sh`. **build.yml** gained a post-build **trivy IMAGE** scan of the
4 images (**report-only** for now — ratchet to fail-closed after a first-scan `.trivyignore` baseline,
per San's decision below). **EDITED** CLAUDE.md (thin reviewer wrapper + Review Step 0 freshness +
Step N write-back), `.cursor/rules/{coder,fixer,review,subagent-delegation}.mdc`,
`.cursor/commands/parallel-review-and-fix.md`, `.cursor/skills/visual-qa-testing`, and the memories
(`conventions_and_review`, `task_completion_checklist`, `dev_setup_and_run`, `eval-tier-a-remediation`)
+ `docs/mcp-workflow.md` + `docs/engineering/{test-baseline-discipline,aks-operations}.md`.
**STALE-CHECK:** ran `serena-refresh.sh` health-check over all 14 memories — all now resolve (fixed a
dangling PCI-rego ref in eval-tier-a; the epic memories eval-*/fleet-*/identity-*/opa-as-server are
current); **removed 3 stale Windows `.ps1`** (`aks-verify.ps1` contained a `git push origin main`),
kept benign root `migrate-pack.ps1`. **VERIFIED:** scope-guard clean (NO product code —
`norviq/`/`ui/src/`/helm-templates/`*.rego` untouched); all YAML+TOML parse; verify.sh + serena-refresh.sh
executable + smoke-run clean (AKS guard cleared `kind-fleet-c`); no `git push` in scripts/, no
backlog-routing (only negations), no stale `66/66`.
**⚠ OPEN DECISION FOR SAN (genuine policy/threat-model call — NOT auto-resolved):** the repo's
`.gitignore` deliberately keeps the AI-workflow config **private** ("keep private / not for public
release") — `CLAUDE.md`, `.cursor/**` (except the already-tracked `subagent-delegation.mdc` +
`visual-qa/SKILL.md`), `.serena/**`, `docs/mcp-workflow.md` are gitignored. Their edits are **live on
disk** (both tools read from disk, so the hardened workflow is ACTIVE now) but git won't track them
without a `git add -f`, which would **publish** files San chose to keep private. Committable-as-is
(not ignored): AGENTS.md, docs/WORKFLOW.md, registry-capabilities.md, security-baseline.md,
security.yml, verify.sh, serena-refresh.sh, the SAST config files, + tracked-file edits (build.yml,
review.sh, pyproject.toml, subagent-delegation.mdc, visual-qa SKILL.md, test-baseline-discipline.md,
aks-operations.md) + the 3 `.ps1` deletions. **San to decide: force-add the private wrappers into this
PR, or keep them private (public contract = AGENTS.md/WORKFLOW.md; tool-specific wrappers stay local).**
**DECISION (San, 2026-07-01):** repo is **private now** (GitHub `norviq-dev/norviq` private; only Docker Hub is
public), end-state = everything public later → **TRACK the wrappers now** for durability + history. Un-ignore
`CLAUDE.md`, `.cursor/**`, `.serena/memories/**` + `project*.yml`, `docs/mcp-workflow.md`, and the `.mcp-memory`
graph; **keep `.serena/cache/**` ignored** (regenerable binaries); `.gitignore` carries a "re-review before going
public" note. Gitleaks over the newly-tracked files before staging (zero secrets). **build.yml trivy IMAGE scan set
to REPORT-ONLY** (not fail-closed) until a `.trivyignore` baseline is captured from a first real image scan —
otherwise the first merge to main would break build→deploy; PR-side SAST stays fail-closed (baselined). Committed on
branch `chore/dual-tool-workflow-hardening` → PR (base main), San merges after review; merge re-runs build+deploy
(docs/config only → identical images, P-10 holds, trivy report-only won't block). See commit prompt in-session.

---

## Design — the target workflow

### Roles & ownership (non-negotiable)
| Concern | Owner | Never |
|---------|-------|-------|
| Product code (author + **fixes**) | **Cursor** | Claude must never edit product code |
| Code review (findings + verdict) | **Claude Code** | Cursor does not self-approve |
| Lessons + Serena/graph memory write-back | **Claude Code** (reviewer) | Cursor does not write its own lessons |
| Specs / plans / roadmap / approvals | **Planner (Cowork) + San** | — |

### The closed loop (must terminate)
```
Planner: spec (specs/{FEAT}.md)  →
Cursor: author code + registry + architecture + tests + self-run T1 locally + evidence  →
Claude: staleness-guard (Part C) → review (Part D gates) → REJECT/PASS + fix-list for Cursor  →
   if REJECT → Cursor writes fixes → Claude RE-reviews the diff (loop)
   if PASS   → Claude writes back lessons+memory (Part F) → commit gate (no auto-commit; San)
Termination: loop until 0 REJECT-level findings AND all gates green.
   Ping-pong guard: if the same finding recurs >2 cycles, STOP and escalate to San (spec ambiguity).
```

### "Major change" (triggers the full gate set)
Any change to: enforcement logic (engine / rego), API surface, auth / security / fleet-trust surface, or a
user-facing UI feature. Trivial (docs, comments, string/style) → T1 + targeted regression only.

---

## Repo audit — exact file deltas (audited 2026-07-01)

Full sweep of every workflow-governing file. The existing author pipeline (coder→tester→diagram→registry→review→
fixer + 4 `.cursor/agents` auditors + `parallel-review-and-fix`) is good and mostly KEPT. The conflicts below are with
the new discipline (Claude-reviews-only, apply-doable-not-backlog, no-auto-commit, reviewer-owns-lessons, T1–T5).

**ADD (new files):**
- `AGENTS.md` (root) — role-neutral shared rules (Part B).
- `docs/WORKFLOW.md` — orchestration contract (Part A).
- `docs/registry-capabilities.md` — capability registry (Part G).
- `.github/workflows/security.yml` — SAST gate (Part E).
- `.pre-commit-config.yaml` — gitleaks + ruff + tsc-lite + fast SAST (Part E).
- `scripts/serena-refresh.sh` — reindex + memory health-check (Part C).
- `scripts/verify.sh` — unified T1–T5 orchestrator (Part D) — supersedes the routing logic in `review.sh`.

**REWRITE (breaks the discipline today):**
- `scripts/review.sh` — THREE violations: (1) routes HIGH/MEDIUM/LOW → `docs/backlog.md` (violates
  apply-doable-not-backlog); (2) ends with `git push origin main` (violates no-auto-commit — and push == deploy!);
  (3) only CRITICAL blocks, so a HIGH security finding ships. Rewrite: keep the gate-then-Claude-once /
  no-infinite-loop bones + marker file; remove the git-push; make HIGH-security **fail-closed** (block); replace
  backlog-routing with "fix in-scope now, else log with rationale"; call the T1–T5 tiers + SAST.

**EDIT (reconcile ownership / stale rules):**
- `CLAUDE.md` — becomes the thin REVIEWER wrapper: reference `AGENTS.md`; hard rule "NEVER edit product code";
  add Review Step 0 (staleness guard) + Step N (memory write-back, reviewer-owned); replace the old "How Review
  Works" 15-check flow with T1–T5; HIGH-security BLOCKS (not backlog); add T4-effect + T5-SAST to reject criteria.
- `.cursor/rules/fixer.mdc` — `_bug-catalog.md` is marked "read-only, humans curate" → change to "reviewer (Claude)
  appends; author does NOT"; remove "Add TODO → docs/backlog.md" (apply-doable); keep author-owned
  `tests/.history/{FEAT}.md` updates, but memory/`_bug-catalog`/`bug-patterns` = reviewer-owned.
- `.cursor/rules/review.mdc` — repurpose from "Cursor reviews" to "Cursor runs the automated GATE (T1–T3 + SAST
  self-check) then HANDS OFF to Claude" (Claude is the authoritative reviewer now).
- `.cursor/rules/coder.mdc` — add "read `AGENTS.md` + `docs/engineering/bug-patterns.md` before coding; run T1
  locally before handoff; produce the T4 evidence artifacts."
- `.cursor/rules/subagent-delegation.mdc` — "before committing" → "before handoff to Claude review" (Cursor doesn't
  commit); keep the parallel self-audit as the cheap pre-review layer.
- `.cursor/commands/parallel-review-and-fix.md` — its "defer architectural/threat-model → docs/backlog.md" conflicts
  apply-doable; change to "fix in-scope; escalate only genuine spec/threat-model decisions to San."
- `.serena/memories/conventions_and_review.md` — remove the "HIGH/MEDIUM/LOW → docs/backlog.md" line; add T1–T5 +
  reviewer-owned write-back; **fix the STALE baseline** (says attacks 66/66 — current baseline is 78/78).
- `.serena/memories/task_completion_checklist.md` — **fix STALE 66/66 → 78/78**; reassign memory-update (steps 8–9)
  to the REVIEWER; add T2 integration / T3 regression / T4 effect / T5 SAST steps; UI step must require live EFFECT,
  not just `npm run build`.
- `docs/engineering/test-baseline-discipline.md` — reconcile the baseline number (66→78) if it still says 66.

**KEEP (good; align by reference to AGENTS.md):**
- `.cursor/rules/tester.mdc`, `diagram.mdc`, `registry.mdc` — solid pipeline roles.
- `.cursor/agents/*` (correctness/security/performance/verifier) — excellent; consolidate their CRITERIA into the
  shared rules so Claude's review uses the same 10 patterns/security/perf lists (today they're duplicated in CLAUDE.md).
- `.cursor/skills/visual-qa-testing` — the T4 UI mechanism (Cursor side); register it + Claude's browser equivalent.

**STALE-CHECK (audit, don't blindly delete):**
- `.serena/memories/{eval-*,fleet-mvp-p1,fleet_p2_signed_push_aks,identity-*,opa-as-server}.md` — point-in-time epic
  memories; run the Part-C health-check (do referenced symbols still resolve after fleet-console-overhaul?) and
  refresh/prune the stale ones. `scripts/*.ps1` are stale on macOS — note or remove.

---

## Prompt

```
ROLE: You are CLAUDE CODE. Set up the Norviq dual-tool workflow hardening (repo: norviq-migration/repo). USE PLAN
MODE; present the plan, WAIT for approval, implement part by part. This is DOCS/CONFIG/CI only — no product-code
change. Do NOT auto-commit.
After each part, show the created/edited files. Record this prompt + outcome in specs/prompts/ + index.
BOOTSTRAP NOTE: this is a CRITICAL task and the new model isn't active yet, so Claude Code AUTHORS this bootstrap
directly (the one exception — it is docs/config/CI, no product code); San + planner review the result; from the next
FEATURE on, the Cursor-authors / Claude-reviews split is live. The exact per-file ADD/REWRITE/EDIT/KEEP/STALE-CHECK
list is in the "Repo audit — exact file deltas" section above — execute every item there; Parts A–G give the rationale.

PART A — WORKFLOW.md (the single orchestration contract).
  - Author docs/WORKFLOW.md: the roles/ownership table, the closed-loop diagram, the "major change" definition, the
    verification-tier table (Part D), the security gate (Part E), and the loop-termination + ping-pong-escalation rule.
    This is the one doc a new session reads to understand how Cursor + Claude + Planner interact.

PART B — Shared rules refactor (role-neutral AGENTS.md + thin wrappers; NO symlink).
  - Extract the role-NEUTRAL content from CLAUDE.md into a new root AGENTS.md (both Cursor and Claude read it natively):
    project overview, tech stack, coding standards, security rules, registry/mermaid/error-code conventions, engineering
    references, AND the PROCESS DISCIPLINE (port these in — they currently live only in Cowork memory / specs):
      * "Prove the EFFECT, not a 200" validation bar.
      * "Apply doable in-scope fixes now; don't backlog."
      * "No auto-commit — summarize; San commits."
      * "Never write the shared hub/fleet DB without explicit approval."
      * "Record every significant prompt in specs/prompts/ + index."
  - Rewrite CLAUDE.md as a thin REVIEWER wrapper: "read AGENTS.md first; you are the reviewer; you NEVER edit product
    code; here is the review flow, the reject checklist, the output format, the Part C staleness guard, and the Part F
    memory write-back you own."
  - Update .cursor/rules/coder.mdc (+ fixer.mdc) as the AUTHOR wrapper: "read AGENTS.md first; you are the author/fixer;
    you own ALL code edits including review fixes; read docs/engineering/bug-patterns.md BEFORE coding; run T1 locally
    before handing to review; produce the evidence artifacts (Part D)."
  - Do NOT symlink CLAUDE.md↔AGENTS.md (role bleed + reviewer-role file). If a neutral alias is ever wanted, alias to
    AGENTS.md, never to the reviewer file. Verify both tools load AGENTS.md.

PART C — Serena staleness guard (ENFORCED, not aspirational; reviewer-owned).
  - Add a "Review Step 0 — freshness" section to CLAUDE.md + docs/mcp-workflow.md: because CURSOR authored, the memory
    is assumed BEHIND. Before trusting memory the reviewer MUST:
      1. Re-index / confirm Serena cache is fresh vs git HEAD (re-run onboarding or targeted re-index on changed files).
      2. Memory health-check: for each memory it will rely on, confirm the named symbols/files/flags still resolve via
         Serena; any that don't → refresh or discard BEFORE acting.
  - Add a "Review Step N — write-back" section: on PASS, the reviewer updates Serena write_memory + the memory graph
    (new symbols/files/flows, new NRVQ codes, gotchas; delete observations that became false). Ownership: REVIEWER, so
    the author (Cursor) never writes memory. Update task_completion_checklist.md accordingly.
  - Provide scripts/serena-refresh.sh (macOS) as the concrete reindex+health-check entrypoint the reviewer runs.

PART D — Verification tiers after every major change (a 200 is NOT proof). Wire into review.sh + CI + WORKFLOW.md.
  - T1 STATIC + UNIT (fast; local pre-hand-off + CI): ruff, tsc, opa check + opa test, vitest unit, pytest unit,
    + Part-E SAST. Fail-closed.
  - T2 INTEGRATION (local kind — NEVER AKS; AKS teardowns delete policy rows): backend API+DB+engine integration,
    webhook injection, fleet signed-bundle push/pull/retract, contract tests. The attack suite green on kind
    (baseline count — currently 78/78).
  - T3 REGRESSION: full pytest + full vitest green with NO new failures vs the recorded baseline; parity tests; the
    "fix the CLASS not the instance" re-grep for the touched pattern (per bug-patterns.md).
  - T4 END-TO-END EFFECT (the 200-is-not-enough bar; MANDATORY for UI or enforcement changes): drive the REAL
    UI + backend on live kind and prove the actual EFFECT — decision actually flips (allow↔block), UI interaction
    state (open AND close), before/after screenshots, data reconciles. NOT "endpoint returned 200." For UI: walk every
    touched route + control. For engine/rego: live /evaluate shows the decision change on running pods (remember the
    seed→reload gotcha: restart/reload after a policy change).
  - T5 SECURITY GATE (Part E) must be green.
  - review.sh {FEAT} orchestrates T1–T3 and reports; T4 is driven (headless Playwright + screenshot review) and its
    evidence attached to the review; the reviewer REJECTS if T4 effect isn't demonstrated.

PART E — Security gating + static analysis (SAST), fail-closed on high/critical.
  - Add these gates (pre-commit for the fast ones, PR CI for the full set); wire results into review.sh + the reviewer
    checklist:
      * Python SAST: bandit + semgrep (python + owasp rulesets); deps: pip-audit.
      * TS/JS: eslint security plugin; deps: npm audit / osv-scanner.
      * Secrets: gitleaks (pre-commit AND CI) — block any secret/key/token.
      * IaC / K8s / Helm: checkov + kube-linter on helm/ + crds/; conftest/opa on policy.
      * Container images: trivy on the 4 built images in build.yml (fail on HIGH/CRITICAL).
      * (Optional) SBOM: syft.
  - Policy: HIGH/CRITICAL findings BLOCK the review/merge; MEDIUM/LOW triaged by the reviewer (fix-in-scope if doable,
    else logged with a ticket). Add .github/workflows/security.yml (PR-triggered) + a pre-commit config. Document the
    triage rule in AGENTS.md.

PART F — Close the learning loop (both directions; reviewer owns write-back).
  - Confirm/enforce: AUTHOR reads docs/engineering/bug-patterns.md before coding (coder.mdc). REVIEWER, on every
    finding, APPENDS a raw entry to tests/.history/_bug-catalog.md and promotes durable ones to bug-patterns.md; and
    updates Serena/graph memory (Part C). Cursor never writes lessons.
  - Add a periodic "promote raw→curated" checklist item and a monthly de-dup pass. State the ownership in WORKFLOW.md.

PART G — Capability / skill registry (so neither tool expects what the other owns).
  - Author docs/registry-capabilities.md: each capability → owning tool (Cursor skill / Claude skill / Cowork skill /
    CI script) → trigger → script equivalent (if runnable by the other side). Cover .cursor/skills, the auditor agents,
    the verification tiers, and the SAST tools. The reviewer must not demand a capability the author can't invoke.

GATES:
  - Docs/config/CI only; no product code touched. tsc/ruff/opa still clean; the new CI workflows lint-valid. Do NOT
    auto-commit — summarize per part. Record this prompt + outcome in specs/prompts/ + index; deliverable = WORKFLOW.md
    + AGENTS.md + updated CLAUDE.md/.cursor rules + security.yml + serena-refresh.sh + registry-capabilities.md.
```
