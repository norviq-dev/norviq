# Prompt — Remediate round-2 audit findings F-42…F-49

**Date:** 2026-06-30
**Work item:** Close the round-2 audit ledger (`.reviews/live-pentest/UI-AUDIT-ROUND2.md`). Lead is security/
accuracy: F-44 (red-team not target-aware) + F-45 (7 baseline coverage gaps + the Dashboard coverage-vs-efficacy
mismatch); then quick security F-42 (apply reserved-scope guard) + F-43 (gate red-team endpoints); then UI F-49
(PolicySheet custom params not wired), F-46 (dead Export), F-47 (uniform path severity), F-48 (asset node-click,
confirm first). Security auditor on F-44/F-45/F-42/F-43.
**Base branch:** `feat/f40-fleet-push-guard` (head of the stack). New branch `feat/ui-audit-round2-remediation-f42-f49`.
**Decisions:** F-45 (strengthen baseline vs recalibrate catalog expectations), F-49 (wire params vs label
preview-only), F-47 (fix scorer vs document) — recommend + confirm before building each.
**Source:** `.reviews/live-pentest/UI-AUDIT-ROUND2.md`. **Gates:** plan mode · do NOT auto-commit · keep **attacks
75/75** on any engine/rego touch · tsc+vitest green · AKS untouched (local kind) · honest status.
**Result:** **DONE (2026-06-30, `feat/round2-remediation-f42-f49`).** 6 CLOSED + 2 NOT-A-DEFECT. **F-44** target-aware
red-team (iterates seeded `agent_registry` classes, `targets[]`+per-row identity, `/redteam/targets`, UI selector +
Agent column, +3 sector scenarios FIN/PHI/OT) — live per-sector now **96.6/93.1/93.1** (was uniform 73.1). **F-45**
strengthened `comprehensive.rego` (DL-001 value-scan, DL-003 secret-egress, CT-002 schema-qualified cross-ns SQL,
CE-001 `chain_depth_limit`) + recalibrated catalog (RL-001/CE-002→allow stateful/intent, TM-001→block) — finance-agent
**26/26**, parity 13/13, attacks 75/75. **Coverage** relabeled "rules present — not efficacy-tested" + audit
overlay + `basis` field. **F-42** apply→`__pack__`/`__baseline__` now 422 (NRVQ-API-7016). **F-43** red-team
admin-gated (viewer 403). **F-49** PolicySheet params bound + honest "not yet enforced" preview label (live: `rateLimit:
99` reflects). **F-46** authored `lib/csv.ts` + wired both Export controls (live: downloads CSV). **F-47/F-48
NOT-A-DEFECT** (scorer correct; node-click D3-wired + passing test). Gates: opa 139/139, tsc, vitest 47/47, ruff;
zero new regressions (base==branch 71 pre-existing infra failures, +5 new passing). New code `NRVQ-RED-13006`. AKS
untouched. Deliverable `.reviews/live-pentest/CLOSEOUT-ROUND2.md`.

---

## Prompt

```
ROLE: Remediate the round-2 audit findings F-42…F-49 for Norviq (repo: norviq-migration/repo). USE PLAN MODE —
present a staged plan (security/accuracy first, UI polish last), WAIT for approval, implement stage by stage with a
regression test per fix AND a live re-verification on the running 3-cluster kind fleet (reuse
scripts/live-pentest/round2_audit.py + headless Playwright; screenshot before/after). Bring the security auditor for
F-44, F-45, F-42, F-43. Read .reviews/live-pentest/UI-AUDIT-ROUND2.md first. BASE ON branch feat/f40-fleet-push-guard
(new branch off it). Nothing may break the single-cluster path, SDK/sidecar hot path, fleet path, packs/compose
machinery, the horizontal PCI/PII parity check, or existing tests. Keep attacks 75/75 at the start and end of every
engine/rego-touching stage. Do NOT auto-commit — summarize per stage.

STAGE 1 — F-44 + F-45 (security/accuracy — the lead; security auditor). Do F-44 FIRST: it's the prerequisite to
judging F-45.
  - F-44: make the red-team suite/run TARGET-AWARE. Accept a real target (agent_class + namespace); default to the
    namespace's actually-seeded agent classes/packs (iterate them) instead of the fixed synthetic
    redteam-test/default identity. Surface WHICH identity each scenario was evaluated against in the report + the
    Policy-Tester UI. Verify: the suite now returns DIFFERENT per-sector results on fleet-a/b/c (not the uniform
    73.1%), and exercises the seeded packs.
  - F-45: re-run the now-targeted suite per sector and TRIAGE the 7 failures (DL-001/DL-003/CT-002/RL-001/CE-001/
    CE-002/TM-001) into (i) real comprehensive-baseline holes vs (ii) covered once the sector pack is targeted.
    DECISION (recommend + confirm): for the genuine baseline holes — strengthen the comprehensive baseline (llm02
    data-leakage: send_email/api_key + read_env/secret egress; cross-tenant namespace mismatch; llm10 unbounded/
    session-flood; chain-depth/recursion) vs recalibrate the catalog's `expected` to the documented deployment
    posture. Reconcile TM-001 (catalog expects escalate, engine hard-blocks). For any baseline rule changes, use the
    partial-set reasons pattern + keep parity 13/13 + attacks 75/75; re-verify each fixed scenario actual==/evaluate.
  - COVERAGE-VS-EFFICACY RECONCILIATION: the Dashboard "Policy Coverage by Category" shows Data Protection / Tenant
    Isolation = 100% while the red-team proved those attacks pass on the baseline. Make coverage HONEST — either
    drive it from real rule efficacy, or relabel it explicitly as "rules present (not efficacy-tested)" so it can't
    be read as a protection guarantee. (Same trust-of-the-number principle as F-37/F-39.)

STAGE 2 — F-42 + F-43 (quick security; auditor).
  - F-42: add the reserved-scope guard to apply_policy (policies.py:313) — agent_class in {"__baseline__","__pack__"}
    → 422 (reuse NRVQ-API-7016 / the create-path guard). Regression test mirroring the create-path test; re-verify
    POST /policies/default/__pack__/apply → 422 (was 200).
  - F-43: gate the red-team router (redteam.py) behind require_admin — /run, /suite, and (recommend) /catalog,
    /report. Regression test: viewer token → 403 on each; admin → 200. Re-verify live viewer→403.

STAGE 3 — UI (F-49 + F-46 + F-47 + F-48).
  - F-49 (DECISION — recommend + confirm): the PolicySheet "Custom Parameters" (rate limit, keywords, trust
    threshold) + generated-YAML preview are not threaded into Save/Apply. Determine if they SILENTLY no-op (if a user
    sets rate-limit and nothing applies, that's misleading → treat as P2). Recommended: WIRE the inputs into the
    authored policy so they take effect; if out of scope, label them clearly "preview-only / not yet applied".
    Test: a custom param set in the sheet is present in the applied policy (or the preview-only label renders).
  - F-46: wire the dead Dashboard top-level "Export" button to the CSV export (reuse Report ▼ → Export CSV) or
    remove it. Test: click → CSV (or button gone).
  - F-47 (DECISION — recommend + confirm): attack-path severity renders uniformly "low-0.20" (Critical/High/Medium
    = 0). Confirm whether the path-risk scorer is broken (always low) or the seeded graph is genuinely all-low.
    Recommended: fix the scorer to differentiate severity from blast-radius/criticality; if it's correct for this
    data, document why. Test/screenshot the differentiated severities (or the documented rationale).
  - F-48: first CONFIRM whether the asset-graph node-click detail is a real app bug or a headless-click artifact
    (manual/real click). If real → fix the node-click → detail-panel wiring + test; if artifact → mark not-a-defect
    in the ledger with evidence. No silent pass.

GATES (per stage):
  - ruff + make test + opa check green; tsc + vitest green for UI; pack tests + horizontal PCI/PII parity green;
    new/updated NRVQ-* codes in docs/error-codes.md; registry/architecture updated where structure changes.
  - attacks 75/75 at start and end of every engine/rego-touching stage. AKS untouched (all kind).
  - Re-verify each finding against its UI-AUDIT-ROUND2.md repro (no longer reproduces); update the ledger status
    (closed / partial / not-a-defect / roadmap). Re-run scripts/live-pentest/round2_audit.py to confirm: suite is
    target-aware (per-sector differs), red-team endpoints 403 for viewer, apply→__pack__ 422, Export works.
  - NOTE (issue #4): baseline/pack rego is DB-seeded — fixes are kind-validated + in the working-tree image; live
    AKS rides the re-seed path.
  - Do NOT auto-commit; summarize per stage. Append CLOSEOUT-ROUND2.md (before/after F-42..F-49). Record this prompt
    + outcome in specs/prompts/ + index.
```
