# Prompt — Sector starter policy packs + pack catalog & sector profile (F047)

**Date:** 2026-06-29
**Work item:** Ship 5 sector STARTER POLICY PACKS (healthcare, finance, government, energy, telecom) as real rego —
each covering that sector's flagship high-impact ACTION scenarios the defaults don't (per `.reviews/company-sim/SECTOR-RECON.md`) —
PLUS a minimal in-product delivery: a **Policy Pack catalog** (browse/enable packs) and a **sector field on the org profile**
that suggests the matching packs. Packs are **opt-in / default-OFF** (single-cluster + AKS unchanged; attacks stay 75/75).
Plan mode (staged); security auditor on the energy OT pack. Mirrors the existing `hipaa_phi.rego` / `pci_card_numbers.rego` packs.
**FEAT:** F047 (+ F018 console, F046 endpoints, F007/F017 engine). **Commit:** do NOT auto-commit. Real data only (no fabrication).

---

## Prompt

```
ROLE: Build SECTOR STARTER POLICY PACKS + their in-product delivery for Norviq (repo: norviq-migration/repo).
USE PLAN MODE — present a staged plan, WAIT for approval, implement stage by stage. Bring the security auditor for the
ENERGY OT pack (highest stakes). Read .reviews/company-sim/SECTOR-RECON.md (per-sector flagship scenarios + compliance
hooks) and the existing policies/ tree (comprehensive.rego, policies/data_protection/hipaa_phi.rego + pci_card_numbers.rego
are the TEMPLATE/precedent). Goal: a customer picks their sector and gets out-of-box coverage of THEIR flagship risk,
instead of writing rego. Everything OPT-IN / default-OFF — the single-cluster path, AKS, and the headless attack suite
(75/75) must be UNCHANGED unless a pack is explicitly enabled for a namespace. Do NOT auto-commit; summarize per stage.

STAGE 1 — AUTHOR THE 5 PACKS (real rego, under policies/sector/<sector>/; mirror the hipaa_phi/pci_card_numbers structure
with rule_id + decision + reason + tests). Each pack encodes the sector's FLAGSHIP allow/block/escalate/audit rules:
  - ENERGY (PRIORITY, security-auditor): OT/control-command tools (e.g. open_breaker, close_relay, set_setpoint, trip,
    write_register, scada_*, dispatch) → HARD BLOCK; OT-adjacent (OMS/ADMS writes) → escalate; IT-only reads → allow.
    This is the IT/OT proof — the load-bearing energy scenario. rule_id e.g. ot_control_command_blocked.
  - FINANCE: money-movement (wire_transfer/ach_transfer/payment) with amount over a configurable threshold → escalate;
    unknown/new beneficiary → escalate; segregation-of-duties (same identity can't initiate AND approve) → block. Reuse
    pci_card_numbers for CHD. rule_ids e.g. wire_over_threshold_escalate, sod_violation.
  - HEALTHCARE: clinical-action tools (order_medication/prescribe/place_order/modify_chart) → escalate (human-in-loop);
    minimum-necessary / bulk-PHI read over a threshold → escalate/block; extend PHI detection toward the 18 HIPAA
    identifiers (build on hipaa_phi). rule_ids e.g. clinical_action_escalate, phi_min_necessary.
  - GOVERNMENT: rights-impacting decisions (benefit.deny/approve, adjudicate) → escalate/HITL; CUI/FTI classification
    (SSN/tax markings) on egress tools → block. rule_ids e.g. rights_impacting_escalate, cui_fti_egress_blocked.
  - TELECOM: SIM-swap / number-port (sim_swap/port_number/provision) without strong-auth flag → block+escalate;
    bulk CPNI / location read over a threshold → block/escalate. rule_ids e.g. sim_swap_escalate, cpni_bulk_blocked.
  Each pack: unit tests (allow + block + escalate + benign-not-falsely-blocked); new NRVQ-* codes in docs/error-codes.md;
  add the new rule_ids → categories in policies/category_mapping.json (extend the taxonomy, sector categories);
  registry/F047.md + architecture/F047.*.mmd. Thresholds/verbs configurable (data), not hardcoded magic.

STAGE 2 — PACK CATALOG BACKEND (F046-style, real, no fabrication): an endpoint that LISTS available starter packs
sourced from the real rego files (id, sector tag, title, what-it-enforces, rule_ids, mapped categories), and an
admin-only, audited "ENABLE pack for namespace" action that materializes the pack's rules via the EXISTING policy-create
path (so an enabled pack is just normal namespace-scoped policies). Enable/disable is idempotent; disabling removes them.
Namespace/RBAC consistent; never monkeypatch get_session; unit tests (list / enable / disable / non-admin 403 / empty).

STAGE 3 — UI (console, real data per the F046 discipline — loading/empty/error states; no fabricated values):
  - A "Policy Packs" catalog view: packs grouped by SECTOR, each showing what it enforces + mapped categories +
    enabled state per namespace; admin can enable/disable for the selected namespace (viewer = read-only, no 403 surprises).
  - A SECTOR field on the org profile (GeneralSettings, persisted via the /settings endpoint): when set, the catalog
    highlights/suggests the matching sector's packs. Keep it minimal — a field + suggestion, NOT a multi-step wizard.
  - tsc + vitest green; new view covered by a test.

STAGE 4 — GATES + VALIDATE:
  - make lint + make test green; tsc + vitest green; helm lint+template clean both overlays (packs add no default
    resources — they're opt-in content, not infra). Packs DEFAULT-OFF → single-cluster/AKS render + behave as today.
  - **attacks 75/75** (the attack namespaces don't enable sector packs → unaffected; confirm at start + end).
  - Live-verify on one kind cluster: enable the energy pack on a namespace → OT control command BLOCKED, IT read ALLOWED;
    enable finance → over-threshold wire ESCALATES; spot-check one rule per other pack. Disable → behavior reverts.
  - Do NOT auto-commit; summarize per stage. Record this prompt + outcome in specs/prompts/ + index.
  - Honest labeling: packs are STARTER templates (customers tune thresholds/verbs); note any sector rule left as a stub.
```
