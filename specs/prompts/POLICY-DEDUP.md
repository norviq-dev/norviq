# Prompt — Policy-architecture dedup audit + consolidation

**Date:** 2026-06-29
**Work item:** One canonical definition per rule_id; eliminate duplicate/unloaded rego; make F047 sector packs
REFERENCE the canonical horizontal rules instead of re-implementing. No change to runtime enforcement; attacks stay
75/75. Plan mode (read-only audit → report → approval → consolidate). **Commit:** do NOT auto-commit.
**Audit report:** `.reviews/policy-dedup/REPORT.md`.

## SHIPPED — merged to main `12fe936` (PR #6, the sector-packs stack: F047 5 packs `1f52da8` + this dedup `7999236` + 3 extension packs `4b4415e`)
**Stage C AKS verify GREEN:** P-10 (api+webhook == `12fe936`), `/readyz` ok, **default-OFF** (catalog 8 packs all
`enabled=false`, 0 `namespace_packs` rows, 0 `(ns,__pack__)` policies — new table + sector ALTER applied dormant),
default enforcement unchanged (benign→allow, injection→block `llm01_prompt_injection`), attacks 74 passed + 2 xfailed +
2 homoglyph/zero-width failures (KNOWN issue #4 gap — F-02 rego not re-seeded on AKS; unchanged by this stack). Packs
are DB-seeded content → live-AKS pack ENFORCEMENT still rides issue #4; done-bar = kind-validated + default-off.

## Result (DONE)

**Stage 1 audit (read-only):** Source of truth = `comprehensive.rego` (seeded as the default tenant policy) +
`webhook/presets/*` (baselines) + `policies/sector/*` (F047 packs). The entire modular tree
`policies/{owasp,data_protection,access_control,rate_limiting,tool_safety,trust,industry}/` (33 rego) and
`policies/presets/` were **NOT loaded by anything** (no seeder/loader reads them; runtime iterates only the in-memory
`_policies` from the DB) — a reference/à-la-carte library that had **drifted** from canonical (duplicate ids
`llm01_prompt_injection`/`deny_sql_injection`/`deny_shell_execution`/`pii_detection`/`cross_tenant_access`; divergent
ids for llm02/llm05/llm06/pci; `policies/presets/` a dead dup of the live `webhook/presets/` with different ids;
`hipaa_phi.rego` doubly dead). `category_mapping.json` already pointed at the live ids.

**Decision (approved):** Aggressive removal of the dead tree + compose-at-materialize for packs.

**Stage 3 applied:**
- **Removed** `policies/presets/` + the 8 unloaded modular dirs (**69 files**: rego + tests). One canonical definition
  per live rule_id now: horizontal in `comprehensive.rego`, sector in `policies/sector/`. Rewrote `policies/README.md`
  to describe what actually loads. `comprehensive.rego` **untouched** → seeded decision byte-for-decision identical
  (injection/card/sql/pii/benign diff = IDENTICAL).
- **Compose-at-materialize:** new canonical `policies/sector/_shared/horizontal.rego` (PCI + PII, mirroring
  comprehensive.rego — **parity-verified** on all cases). `packs.json` `requires` (finance→pci, healthcare→pii,
  government→pii); `norviq/api/packs.py combine()` composes the required SHARED-RULE section into the materialized
  `(ns,__pack__)` module (deduped). Slimmed the healthcare pack (dropped generic `ssn`/`date_of_birth` from
  `hc_phi_fields` — now covered by composed canonical PII; kept clinical-specific fields). Catalog + UI surface
  `composes`.
- **Gates:** `opa test --v0-compatible policies/` 44/44; ruff clean; `tests/api/test_packs.py` + `test_pack_precedence`
  16 passed; tsc + vitest 40/40; helm lint + template clean; no Go changes. **kind live-verify** (rebuilt api):
  finance pack → `card_number` **block `pci_card_numbers`** (composed) + wire **escalate**; healthcare pack → SSN value
  **block `pii_detection`** (composed) + `order_medication` **escalate**; **default attacks 76 passed + 2 xfailed**
  (comprehensive unchanged). AKS untouched.

---

## Prompt
```
ROLE: Policy-architecture DEDUP AUDIT for Norviq. USE PLAN MODE — READ-ONLY audit first, report, WAIT for approval
before deleting/moving. Goal: one canonical definition per rule_id; eliminate duplicate/unloaded rego; sector packs
(F047) REFERENCE canonical horizontal rules. Do NOT change runtime enforcement; attacks stay 75/75.
STAGE 1 AUDIT -> .reviews/policy-dedup/REPORT.md: source of truth (comprehensive.rego seeded vs the modular
policies/ tree — confirm loaded or not); rule_id -> files matrix (LIVE/PRESET/REFERENCE/DEAD); category_mapping
cross-check. STAGE 2 RECOMMEND (await approval): per file KEEP-AS-LIBRARY / KEEP-AS-REFERENCE / REMOVE; one canonical
home per rule; how packs reference horizontal rules. STAGE 3 CONSOLIDATE (after approval): single definition per
rule_id; category_mapping at canonical; packs reference. Gates: make test/go test/tsc/vitest; comprehensive.rego seeds
identically (diff standard cases); attacks 75/75; no live AKS change. Record in specs/prompts/.
```
**Approved:** Aggressive (remove dead tree) + Compose-at-materialize.
