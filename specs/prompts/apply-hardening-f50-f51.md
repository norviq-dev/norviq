# Prompt — Apply-hardening F-50 (confirm/diff preview) + F-51 (per-namespace dry-run-only mode)

**Date:** 2026-06-30
**Work item:** Finish the policy-apply hardening recommended by the round-2 apply-model evaluation — the two
controls that were GAPS and should have shipped with the F-42…F-49 pass (not parked). F-50: a confirm + diff
preview before Apply. F-51: an opt-in per-namespace "dry-run-only / require-approval" mode (server-enforced), for
high-assurance (gov) tenants. Apply directly — these are in-scope, not backlog.
**Base branch:** CONTINUE ON the round-2 remediation branch `feat/round2-remediation-f42-f49` (same branch — land
F-50/F-51 WITH the round-2 fixes so it's ONE PR; do NOT start a new branch).
**Source:** `.reviews/live-pentest/UI-AUDIT-ROUND2.md` §(e) policy-apply model evaluation (controls b + e = GAPS).
**Gates:** plan mode · do NOT auto-commit · keep **attacks 75/75** on any engine/API touch · tsc+vitest green ·
AKS untouched (local kind) · security auditor on F-51 · honest status.
**Result:** **DONE (2026-06-30, `feat/round2-remediation-f42-f49`).** **F-50** — Configure-Policy sheet now has a
confirm + diff review step (enforcement old→new + target; "Confirm Apply"/"Back"; new-policy state); no silent
overwrite. **F-51** — per-namespace `apply_mode` (enforce|dry_run_only) on `namespace_settings` (idempotent ALTER),
shared `assert_apply_allowed` gate → **409 NRVQ-API-7087** on apply + pack-enable for a dry-run-only ns
(server-enforced, admin too); Settings → Apply Governance toggle. Live on fleet-a: dry_run_only → apply/pack 409,
dry-run 200, `/evaluate` enforcement unaffected, reset→enforce clean. Tests: `test_apply_mode.py` (4),
`PolicySheet.test.tsx` (3); attacks 75/75, opa 139/139, parity 13/13, tsc, vitest 50/50, ruff. AKS untouched.
§(e) controls b+e → EXISTS. Landed WITH F-42…F-49 in one branch/PR. See `CLOSEOUT-ROUND2.md` Stage 4.

---

## Prompt

```
ROLE: Implement the two policy-apply hardening controls F-50 + F-51 for Norviq (repo: norviq-migration/repo). USE
PLAN MODE — present the plan, WAIT for approval, implement each with a regression test + a live re-verification on
the running 3-cluster kind fleet (headless Playwright + API). Security auditor on F-51 (must be server-enforced, not
UI-only). Read .reviews/live-pentest/UI-AUDIT-ROUND2.md §(e) first. CONTINUE ON the existing branch
feat/round2-remediation-f42-f49 (land F-50/F-51 WITH the round-2 fixes in ONE PR — do NOT start a new branch).
Nothing may break the single-cluster path, the
SDK/sidecar hot path, the fleet path, or existing tests. Keep attacks 75/75 at start and end of any engine/API
stage. Do NOT auto-commit — summarize per stage.

STAGE 1 — F-50: confirm + diff preview before Apply.
  - In the Apply flow (the Configure Policy drawer → Apply, POST /api/v1/policies/{ns}/{ac}/apply): before the write,
    show the user a DIFF of the CURRENTLY-applied policy vs the policy about to be applied (rego/target/enforcement),
    and require an explicit confirm action. No silent one-click overwrite of a live policy.
  - Compute the diff from the existing stored policy (GET /policies/{ns}/{ac}) vs the new authored content; render an
    added/removed/changed view; "Apply" is disabled until the user confirms. (Reuse dry-run where useful, but the
    diff is the new requirement.)
  - Tests: tsc+vitest — applying over an existing policy shows a non-empty diff + requires confirm; applying a brand
    new policy shows "new policy" state; confirm → POST fires, cancel → no request. Screenshot the diff+confirm.

STAGE 2 — F-51: opt-in per-namespace dry-run-only / require-approval mode (SERVER-ENFORCED; auditor).
  - Add a per-namespace setting (e.g. settings.apply_mode = enforce | dry_run_only, default enforce) persisted
    server-side. When a namespace is dry_run_only:
      - the API REJECTS mutating policy applies for that ns — POST /policies/{ns}/{ac}/apply → 409 (or 403) with a
        clear reason + NRVQ-* code; dry-run + create-draft still allowed; fleet/pack mutations honor the same gate.
      - the console reflects it: Apply is disabled with an explanatory note; Dry-Run remains.
    This MUST be enforced at the API (a UI-only hide is not acceptable — auditor verifies a direct API apply is
    rejected when the ns is dry_run_only).
  - Wire the toggle into the existing General Settings page (per-namespace), documented in the registry.
  - Tests: with apply_mode=dry_run_only — direct API apply → 409 (admin too); dry-run → 200; toggling back to
    enforce → apply works. UI shows the disabled state + note. attacks 75/75 (enforcement of EXISTING policies
    unaffected — this only gates new applies).

GATES (per stage):
  - ruff + make test + opa check green; tsc + vitest green; new NRVQ-* codes in docs/error-codes.md; registry/
    architecture updated where structure changes.
  - attacks 75/75 at start and end of any engine/API-touching stage. AKS untouched (all kind).
  - Live re-verify: F-50 diff+confirm renders and gates the write; F-51 direct API apply rejected under
    dry_run_only, allowed under enforce. Update UI-AUDIT-ROUND2.md §(e) (controls b + e now EXIST).
  - Do NOT auto-commit; summarize per stage. Append to CLOSEOUT-ROUND2.md. Record this prompt + outcome in
    specs/prompts/ + index.
```
