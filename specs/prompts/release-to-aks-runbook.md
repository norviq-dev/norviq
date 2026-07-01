# Prompt — Release to AKS: land PR #12 on main + deploy + re-seed + live attack re-verify

**Date:** 2026-06-30
**This is THE live-release prompt — the ONE prompt authorized to touch `origin/main` and the real AKS cluster.**
Merging PR #12 to `main` AUTOMATICALLY triggers `Build & Push` → `Deploy to AKS` (deploy.yml `workflow_run`). So the
merge *is* the deploy — treat the merge click as the go/no-go trigger.

**Topology (verified 2026-06-30, ground truth — not from memory):**
- PR #12 = `feat/fleet-console-overhaul` @ `bcc1ff9` — a **single linear stack, 7 commits ahead of `origin/main`**,
  `0` real commits behind: `1b6a0ad`(company-sim F-08–19) → `e843555`(live-pentest F-20–28) →
  `9287ea5`(ui-audit F-29–39) → `0361ede`(F-40) → `f6e8965`(round2 F-42–51) → `1632f47`(fleet-console F-52–69) →
  `bcc1ff9`(R1–R5 hardening).
- The branch tree **already supersets `origin/main`**: `git diff branch...origin/main` is **empty**; `origin/main`'s
  one extra commit `4fd1881` (PR #7 docs merge) adds **zero file content** → **merge to main is conflict-free**.
- All intermediate feature branches (company-sim/live-pentest/ui-audit/F-40/round2) are **ancestors already inside**
  `feat/fleet-console-overhaul` → one merge lands everything.
- **LOCAL `main` is 16 behind `origin/main`** — irrelevant to the release (we merge via GitHub against `origin/main`,
  never local main). Reconciled in P5.

**Decision (San → assistant's call): SINGLE retarget + merge (Option A).** Retarget PR #12 base
`feat/round2-remediation-f42-f49` → `main`, merge once (merge commit, keep the 7 per-unit commits — NOT squash), close
the superseded intermediate PRs pointing at #12. One deploy. Per-unit history preserved in the commits + `specs/prompts/`.

**Deploy machinery (real):** `build.yml` on push→`main` builds+pushes `engine-/api-/ui-/webhook-<sha>`;
`deploy.yml` fires on Build success (`workflow_run`, branch `main`) → `helm upgrade --install norviq helm/norviq/ -n
norviq -f values-aks-dev.yaml --set images.*.tag=*-<github.sha> --set config.requireStrongSecret=true` against RG
`rg-opsai-dev-eastus-001`, AKS `norviq`. **Issue #4:** comprehensive.rego + sector packs are **DB-seeded** (Postgres),
NOT baked into images — the deploy ships code but the rego must be (re)seeded on AKS or homoglyph/zero-width + any
updated rego won't enforce (`scripts/seed-local-policies.py`).

**Gates:** plan mode · WAIT for approval · do NOT merge/deploy until San says go · capture rollback state BEFORE deploy
· prove enforcement by EFFECT (attacks pass live on AKS), never a 200 · if any gate is red, STOP + roll back, don't
paper over · record outcome + this prompt in `specs/prompts/` + index.

**Result:** **SHIPPED (2026-07-01).** PR #12 retargeted → `main` and merged as a **merge commit** → main HEAD
**`0d3aef0`** (7 per-unit commits preserved); intermediate PRs #8–#11 closed (superseded). Build & Push + Deploy to
AKS both succeeded; **P-10 GREEN** — all 5 deployments at `*-0d3aef0`, helm rev **78** (rollback target 77). **P3
re-seed (app DB only, fleet DB untouched):** `default:customer-support` **8629→11807 chars, v1→v2** (updated
comprehensive). **P4 EFFECT proof on the running pods** (after an `norviq-api` restart to reload the seeded rego):
live `/evaluate` **6/6** — the 2 issue-#4 **homoglyph + zero-width** cases now `block llm01_prompt_injection`
(+ fullwidth/sql block, benign allow); console smoke green (new UI build, real KPIs, 0 errors). Local `main`
reconciled `11e8e7e→0d3aef0` (ff-only). AKS is the only cluster touched. Full detail:
`.reviews/live-pentest/CLOSEOUT-RELEASE.md`.

---

## Prompt

```
ROLE: Execute the Norviq release to AKS (repo: norviq-migration/repo). USE PLAN MODE — present the staged plan and
WAIT for approval. THIS IS THE ONE PROMPT AUTHORIZED TO TOUCH origin/main AND THE REAL AKS CLUSTER. Merging PR #12 to
main AUTO-TRIGGERS Build & Push → Deploy to AKS (deploy.yml). So the merge is the deploy: do NOT merge until San gives
an explicit go, and treat re-seed + live-attack re-verify as required gates, not optional. If any gate is red, STOP
and roll back to the state captured in P0 — never leave AKS half-migrated. Validation bar: prove the EFFECT (live
attacks enforce on AKS), not a 200.

P0 — PRE-FLIGHT (no remote/AKS impact).
  - git fetch; confirm PR #12 head == feat/fleet-console-overhaul @ bcc1ff9; confirm branch is 7 ahead / conflict-free
    vs origin/main (git diff feat/fleet-console-overhaul...origin/main is EMPTY; git merge-tree / GitHub "mergeable").
  - Re-run the FULL offline gate on the branch tip and require green before touching main:
    attacks (scripts/live-pentest/round2_audit.py or the engine/API attack suite) = 78/78, vitest = 73/73,
    offline backend = 97, opa check, ruff, tsc — all clean. Any red → STOP, report, do not proceed.
  - Capture AKS ROLLBACK state (save to the closeout): current image of each deployment
    (kubectl get deploy norviq-{engine,api,ui,webhook} -n norviq -o jsonpath of the container image),
    current `helm history norviq -n norviq` revision, and an inventory of the currently-seeded policies
    (count + versions) so P3/P4 can be compared. This is the rollback target.

P1 — LAND ON MAIN (single retarget + merge; Option A). REQUIRES SAN'S EXPLICIT GO — this triggers the deploy.
  - On GitHub, RETARGET PR #12 base from feat/round2-remediation-f42-f49 → main. Confirm GitHub reports mergeable,
    no conflicts, exactly the 7 commits.
  - gh pr list — identify which intermediate PRs (company-sim / live-pentest / ui-audit / F-40 / round2) are actually
    OPEN. (Do not assume.)
  - MERGE PR #12 → main as a MERGE COMMIT (preserve the 7 per-unit F-xx commits; do NOT squash).
  - CLOSE the superseded open intermediate PRs with a comment pointing at the PR #12 merge commit ("superseded by
    #12 <sha>; all commits landed via the fleet-console-overhaul stack"). Do not delete branches yet (P5).
  - NOTE: this merge auto-starts Build & Push (main) → on success → Deploy to AKS. Confirm San is ready for the live
    deploy at this exact step.

P2 — CI + DEPLOY VERIFICATION.
  - Watch Build & Push on main: all 4 images (engine/api/ui/webhook) tagged with the NEW main HEAD sha built + pushed.
  - Watch Deploy to AKS (workflow_run on Build success): helm upgrade succeeded; rollout complete; all pods Ready.
  - P-10 GATE (deployed == HEAD): assert kubectl deployment images == engine-<HEAD>/api-<HEAD>/ui-<HEAD>/webhook-<HEAD>
    where HEAD == new origin/main sha. cluster-info / health endpoints green; servedCluster correct.

P3 — AKS DB RE-SEED (issue #4 — rego is DB-seeded, NOT in the image). PRIORITY.
  - The deploy ships code + images, but comprehensive.rego + the sector packs live in Postgres — (re)seed them on AKS
    or homoglyph/zero-width + any updated rego (R1–R5 engine, weaken-floor, pack precedence, F-42+…) won't enforce.
  - Run scripts/seed-local-policies.py against the AKS app Postgres — either via `kubectl port-forward` to the AKS
    postgres service, or a one-shot in-cluster `kubectl run`/Job using the deployed image (preferred: runs with the
    real in-cluster DSN, no local exposure). Seed comprehensive + all sector packs.
  - This is a DELIBERATE write to the AKS APP DB (intended). Do NOT write to any shared HUB/fleet DB unless AKS is
    explicitly running as a hub and San has approved it — confirm which DB before writing.
  - VERIFY the seed took: query policy count + versions; confirm the updated rego is present (not the old set).

P4 — LIVE ATTACK RE-VERIFY on AKS (prove enforcement by EFFECT).
  - Run the live attack harness against the DEPLOYED AKS endpoint (scripts/live-pentest/round2_audit.py +
    run_waves.py / portal_validate.py as applicable). With P3 done, the 2 homoglyph/zero-width cases that previously
    xfailed on AKS (issue #4) must now PASS → target the same 78/78 seen locally. If they still xfail, the re-seed did
    NOT take — investigate and fix, do not hand-wave. Record the exact AKS pass count.
  - SMOKE-CHECK the console on AKS: load + auth, Overview KPIs show real data, walk 2–3 pages, run one Dry-Run (no
    mutation) — prove the new UI build is live and healthy. Screenshot.

P5 — CLOSE-OUT + CLEANUP.
  - Reconcile local main: git checkout main && git fetch origin && git merge --ff-only origin/main (clears the "16
    behind"). List merged local feature branches; delete only with confirmation (no force).
  - Write .reviews/live-pentest/CLOSEOUT-RELEASE.md: merged sha, deployed sha (P-10 match), re-seed confirmation +
    policy counts, AKS live-attack result (before/after the 2 homoglyph cases), console smoke screenshot, and the P0
    rollback state (prev images + helm revision).
  - Record this runbook prompt + outcome in specs/prompts/ + index. Do NOT auto-commit any repo changes beyond what
    San approves; summarize per stage.

ROLLBACK (if any P2–P4 gate fails):
  - Redeploy the prior images (P0 capture) via `helm rollback norviq <prev-revision> -n norviq` or a pinned
    `helm upgrade --set images.*.tag=<prev>`; confirm pods roll back + healthy. The DB seed is additive/idempotent
    (document its effect); if a bad rego was seeded, re-seed the prior known-good set. Never leave AKS on a new image
    with an un-seeded/half-seeded policy store.

GATES (recap): plan mode; WAIT for approval; merge only on explicit go (= the deploy trigger); P0 rollback captured
before deploy; P-10 deployed==HEAD; P3 re-seed verified; P4 attacks pass LIVE on AKS (effect, not 200) + console smoke;
STOP + roll back on any red. AKS is the only cluster touched; do not touch a shared hub DB without explicit approval.
```
