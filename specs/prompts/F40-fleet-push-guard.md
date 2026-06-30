# Prompt — F-40 fleet-push reserved-scope guard + F-41 harness pack-seeding fix

**Date:** 2026-06-29
**Work item:** Close the two follow-ups surfaced by the UI-audit run before the stack merges to main/AKS.
**F-40 (P1, security):** a fleet push targeting a reserved scope (`__baseline__`/`__pack__`) is distributed by the
relay and overwrites `comprehensive` across the whole fleet — one mis-targeted push disabled enforcement on all 3
clusters during the F-33 test (43 attacks failed, MITRE 0/8). The fleet-push path has no reserved-scope guard.
**F-41 (P2, harness):** the pentest/campaign seeder enables packs via a direct `__pack__` POST (now 422-guarded by
S1) — the root cause of F-37 (finance pack not enforcing); harness must enable via the real packs API.
**Base branch:** `feat/ui-audit-remediation-f29-f39` (head of the stack — so the S1 `__pack__` guard + packs API are
present). New branch `feat/fleet-push-guard-f40` off it.
**Source:** `.reviews/live-pentest/UI-AUDIT.md` (F-40, F-41) + `CLOSEOUT-UI.md` incident.
**Gates:** plan mode · do NOT auto-commit · keep **attacks 75/75** · AKS untouched (local kind) · honest status.
**Result:** **CLOSED (2026-06-30)** on branch `feat/f40-fleet-push-guard`. F-40: author-path guard rejects
`__baseline__`/`__pack__` (422, `NRVQ-FLT-15023`) + fleet-wide pushes require `confirm_fleet_wide` (422,
`NRVQ-FLT-15027`); `_resolve_for_cluster` filters reserved scopes (defense-in-depth). F-41: harness already enables
packs via the real packs API; verified a clean re-seed enforces (SoD/wire/export block, coverage 3/3). Live on the
3-cluster kind fleet: the exact incident push → 422, comprehensive intact on all 3, attacks 75/75, MITRE 8/8.
See `.reviews/live-pentest/CLOSEOUT-F40.md`.

---

## Prompt

```
ROLE: Close findings F-40 + F-41 for Norviq (repo: norviq-migration/repo). USE PLAN MODE — present the 2-stage plan,
WAIT for approval, implement stage by stage with a regression test per fix AND a live re-verification on the running
3-cluster kind fleet. Bring the security auditor for F-40. Read .reviews/live-pentest/UI-AUDIT.md (F-40, F-41) and
CLOSEOUT-UI.md (the incident) first. BASE THIS WORK ON branch feat/ui-audit-remediation-f29-f39 (S1's reserved-scope
guard for direct __pack__ writes + the real packs-enable path are already there — reuse them). Nothing may break the
single-cluster path, the SDK/sidecar hot path, the fleet path, the packs/compose machinery, or existing tests. Keep
attacks 75/75 at the start and end of every stage. Do NOT auto-commit — summarize per stage. New branch off the base.

STAGE 1 — F-40 (P1, security): fleet-push reserved-scope guard.
  - On the FLEET-PUSH path (fleet-api `POST /api/v1/fleet/policies` + the relay/distribute + bundle-build), REJECT a
    push whose target policy scope is reserved — `__baseline__` or `__pack__` — with 422 and a clear reason (reuse /
    mirror the S1 direct-__pack__ guard + code NRVQ-API-7016, or add a sibling fleet-specific code). A fleet push must
    NOT be able to replace a cluster's baseline/pack scope; baseline/pack changes go through the per-cluster
    seed/packs path, not fleet distribution.
  - Add a second safety: any FLEET-WIDE push (env-scoped target like {"env":"prod"}, i.e. matches >1 cluster) must
    carry an explicit confirm flag (e.g. `confirm_fleet_wide=true`); without it → 422 "fleet-wide push requires
    confirmation". Single-cluster target ({"cluster_id":"…"}) unaffected.
  - Tests: push to `__baseline__`/`__pack__` → 422 (no distribution); env-scoped push without confirm → 422; a
    normal named-policy single-cluster push → 200 and distributes. attacks 75/75.
  - LIVE re-verify on the running fleet: attempt the exact incident push (`agent_class=__baseline__`, {"env":"prod"})
    → now REJECTED, comprehensive intact on all 3 clusters, attacks 75/75, MITRE 8/8 (prove the incident can't recur).

STAGE 2 — F-41 (P2, harness): seed packs the right way.
  - Update scripts/live-pentest (and any campaign/fleet seeder that enables sector packs) to enable packs via the
    real packs API (NamespacePack + materialize) instead of a direct __pack__ POST (which S1 now 422s). So a fresh
    pentest/campaign actually enforces the sector pack (no F-37 regression).
  - Test/verify: a clean re-seed of one cluster via the harness → the sector pack ENFORCES (SoD/wire/export block,
    coverage non-zero) without manual UI toggling.

GATES (per stage):
  - ruff + make test + opa check green; tsc + vitest green if any UI touch; new/updated NRVQ-* codes in
    docs/error-codes.md; registry/architecture updated where structure changes.
  - attacks 75/75 at start and end of every stage. AKS untouched (all kind).
  - Re-verify each finding against its repro (F-40 incident push rejected; F-41 harness re-seed enforces). Update the
    UI-AUDIT.md status for F-40/F-41 (closed). Append to CLOSEOUT-UI.md (or a short CLOSEOUT-F40.md).
  - Do NOT auto-commit; summarize per stage. Record this prompt + outcome in specs/prompts/ + index.
```
