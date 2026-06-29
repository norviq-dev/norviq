# Prompt — F047 Sector Starter Policy Packs + in-product delivery

**Date:** 2026-06-29
**Work item:** Ship 5 sector starter policy packs (Energy/Finance/Healthcare/Government/Telecom) + a catalog +
enable/disable backend + a console view, so a customer picks their sector and gets out-of-box coverage of their
flagship risk instead of writing rego. Everything OPT-IN / default-OFF. Plan mode (4 stages); security auditor on Energy.
**Source:** `.reviews/company-sim/SECTOR-RECON.md` (flagship risks + compliance hooks); `policies/data_protection/
hipaa_phi.rego` + `pci_card_numbers.rego` as the rego template precedent. **FEAT:** F047 (+ F046 reuse).
**Commit:** do NOT auto-commit (summarize per stage) · keep attacks 75/75.

## Result (DONE — not committed)

- **Stage 1 — 5 packs (real v0 `--v0-compatible` rego, mirroring comprehensive.rego).** `policies/sector/<sector>/*.rego`
  + `_test.rego` (allow/block/escalate/benign). Composable (PACK-CONTRIB + shared RESOLVER markers) so multiple packs
  combine into one `(ns,__pack__)` module. `policies/sector/packs.json` manifest (verbs/thresholds as tunable data);
  `category_mapping.json` += 5 sector categories; `docs/error-codes.md` += NRVQ-API-7094–7097.
  **Energy security-audited** — auditor found the first version was a `tool_name`-only substring blocklist that failed
  open on param-based protocol calls (`modbus`+`{function:write_register}`), word-order/device-class variants, and the
  OT long tail. Rewrote to scan `tool_params` (+ engine `tool_params_normalized`), broaden verbs/device-classes, and
  adopt **fail-safe on the OT surface** (definite control → block, ambiguous OT non-read → escalate, reads → allow).
  `opa test --v0-compatible policies/` = **136/136**.
- **Stage 2 — catalog + enable/disable backend.** `norviq/api/packs.py` (manifest + combiner), `routers/packs.py`
  (`GET /policy-packs`, admin `enable`/`disable`, idempotent, audited, materialize the combined rego via `loader.create`
  at `(ns,__pack__)`). Evaluator: additive **in-memory-only** `(ns,__pack__)` candidate + **`_resolve_with_packs`** —
  a pack is an ADDITIVE-ONLY OVERLAY (can only TIGHTEN the base decision, never loosen, independent of priority; the
  F-07 trap). `NamespacePack` table + `NamespaceSettings.sector` (idempotent startup ALTER). Enable/disable invalidates
  the **whole namespace** eval cache so it takes effect immediately. Tests: `tests/api/test_packs.py` (9) +
  `tests/engine/test_pack_precedence.py` (7). `registry/F047.md` + `architecture/F047.*.mmd`.
- **Stage 3 — console.** `ui/src/pages/PolicyPacks.tsx` (catalog grouped by sector, enable/disable per namespace,
  viewer read-only, loading/empty/error) + **Sector field** on General Settings (suggests matching packs) + api client
  + `PolicyPacks.test.tsx`. `tsc` clean; **vitest 40/40**.
- **Stage 4 — gates.** ruff clean; opa 136/136; `helm lint` + `template` both overlays clean (packs add **0** rendered
  resources — opt-in content, not infra); tsc + vitest green; Python collect 527, the 14 new tests green (other
  failures are the pre-existing no-local-DB `ConnectionRefused`). **kind live-verify** (campaign nv-a, rebuilt api
  image): enable energy → `open_breaker`/`modbus write_register`/`breaker_open` → **block** `ot_control_command_blocked`,
  IT read → allow, **disable reverts**; finance → wire 25000 **escalate**; healthcare/telecom/government spot-checks
  escalate; viewer enable → **403**. **Attacks on default (no pack) → 76 passed + 2 xfailed = green** (after re-seeding
  default, whose `customer-support` policy had been removed by earlier deny-storm isolation work on the same cluster —
  a pre-existing cluster artifact, NOT an F047 regression; packs are default-OFF and never touch a pack-less namespace).

**Honest labeling:** packs are STARTER templates (customers tune verbs/thresholds in the materialized policy). The
Finance SoD rule is an in-params heuristic (initiator==approver); true SoD needs approval-workflow state. Healthcare
PHI field list is a representative subset of the 18 HIPAA identifiers. AKS untouched (local kind only).

---

## Prompt

```
ROLE: Build SECTOR STARTER POLICY PACKS + their in-product delivery for Norviq. USE PLAN MODE. Security auditor on
the ENERGY OT pack. Read .reviews/company-sim/SECTOR-RECON.md + the existing policies/ tree (hipaa_phi/pci_card_numbers
= template). Goal: a customer picks their sector and gets out-of-box coverage of THEIR flagship risk. Everything
OPT-IN / default-OFF; single-cluster/AKS/attack-suite (75/75) unchanged unless a pack is enabled for a namespace.
No auto-commit; summarize per stage.
STAGE 1 — author the 5 packs (real rego under policies/sector/, rule_id+decision+reason+tests; ENERGY OT control →
block, OT-adjacent → escalate, IT read → allow; FINANCE wire-over-threshold/SoD; HEALTHCARE clinical HITL/min-necessary;
GOVERNMENT rights-impacting/CUI-FTI; TELECOM sim-swap/CPNI). New NRVQ codes; category_mapping.json; registry/F047 + arch.
STAGE 2 — pack catalog backend (list from real rego; admin-only audited enable-for-namespace via the existing
policy-create path; idempotent; disable removes). STAGE 3 — UI (Policy Packs catalog grouped by sector; Sector field on
GeneralSettings via /settings). STAGE 4 — gates (make lint/test; tsc+vitest; helm lint/template both overlays; attacks
75/75 start+end; kind live-verify enable→block/allow, disable reverts). Record prompt + outcome in specs/prompts/.
```
