# Prompt — Role-based company simulation (5 critical-infra sectors)

**Date:** 2026-06-29
**Work item:** Opus orchestrator + 5 Sonnet sector eval-team personas driving the live product (API + console) as
skeptical buyers; scored "would we pilot this" across healthcare/finance/government/energy/telecom; defects → ledger.
Run on current main (8 shipped sector packs, dedup/compose, F-04 deny-default, baseline wiring). Local kind only; AKS
untouched; attacks 75/75 start+end; no auto-commit. **Source:** `.reviews/company-sim/SECTOR-RECON.md`.

## Result (DONE — local only, nothing committed)

**Stage 1 seed:** one rich kind cluster `nv-a` (current-main 8-pack image), 5 sector tenants = namespaces
(`mercy-health`, `atlas-bank`, `state-benefits`, `cascade-power`, `northstar-mobile`), each = comprehensive
horizontal policy at `<ns>:__baseline__` + its sector pack enabled via the real catalog/enable flow (composing
pci/pii). Agents incl. low-trust + spoof. **attacks 76p+2xfail (75/75) at START and END.** → `COMPANIES.md`.

**Stage 2-3 (Phase A):** 5 Sonnet persona eval teams each ran their sector-flagship + the universal battery
(action-boundary, HITL+audit, least-priv, exfil, SVID-spoof, audit-integrity), scored 1–5 on 6 dimensions with
observed evidence, raised the scripted objections, and logged defects. **Verdicts:** healthcare/finance/gov/telecom
= **pilot-with-conditions**; energy = **NOT YET** (P1 OT bypass). The differentiated CORE held in every sector —
every dangerous action blocked/escalated, fail-closed, clean cross-ns 403, usable pack onboarding.

**Stage 4 synthesis** (`REPORT.md` + `FINDINGS.md` F-08..F-19 + `NIW-APPENDIX.md`). **Top findings (root-caused by
the orchestrator):**
- **F-08 (P1, ALL 5):** comprehensive.rego block rules log `reason:"Allowed"` (0 reason clauses, default "Allowed")
  → audit trail mislabels every injection/PII/PCI/SQL block as allowed. The #1 cross-sector fix (gates every regime's
  auditor test).
- **F-09 (P1, energy):** noun_verb OT control names (`valve_close`, `pump_start`, …) → allow (OT-surface list missing
  valve/pump/gate; verbs verb-first only). The energy hold.
- **F-10 (P1, finance):** SoD bypass — case (`Alice/alice`), empty-approver, homoglyph → allow (exact string eq).
- P2/P3: empty rule_id on SVID-fallback (F-11), compound→evaluator_error (F-12), latency_ms:0.0 telemetry (F-13),
  no deny-by-default/tool-scope (F-14), top-level-only PII scan (F-15), energy OT-scope gaps (F-16), telecom export
  bypass (F-17), trust_threshold not enforced (F-18), audit not tamper-evident / no masked params (F-19).
- **Rolled-up GA call: SHIP-WITH-CONDITIONS (not-yet-GA)** — fix F-08 (1 cross-cutting change) + F-09 + F-10, then
  5/5 reach pilot-ready; the P2 attribution/coverage set for audit-grade completeness; procurement gates (BAA,
  FedRAMP path, tamper-evident SIEM, residency) parallel.
- **Phase B (identity) + C (fleet) DEFERRED this run** (nv-a is SPIFFE-mock/OIDC-off; cumulative session compute) —
  scenarios mapped to prior in-codebase validation (identity + fleet epics); recommend a focused follow-up. Phase A
  already showed the fail-safe DIRECTION (SVID/evaluator errors → block).

`NIW-APPENDIX.md`: per-sector national-importance + Dhanasar Prong-1 mapping (gov = lead exhibit) + sources, with a
primary-source re-verification checklist (ATLAS labels, 800-53 inferences, incident stats).

**The sim found genuine defects in shipped code** (F-08 comprehensive.rego, F-09 energy pack, F-10 finance pack) —
its purpose. Nothing committed; defects are a fix backlog for the next pass.

---

## Prompt
```
ROLE: Role-based COMPANY SIMULATION across the 5 critical-infra sectors. USE PLAN MODE; WAIT for approval; execute
stage by stage. Opus orchestrator + Sonnet SCOUT PERSONAS as a buyer eval team driving API+console; scored
"would we pilot this"; defects→ledger. Read .reviews/company-sim/SECTOR-RECON.md. Current main; AKS untouched; local
kind; attacks 75/75. 12GB: 5 sectors as TENANTS on one cluster; identity (Keycloak+SPIRE) + fleet phases staggered.
STAGE 1 seed (shipped packs, not ad-hoc) + COMPANIES.md. STAGE 2 run flagship + universal scenarios. STAGE 3 score
1-5 + verdict + objections. STAGE 4 REPORT.md + ranked commonalities + GA call; FINDINGS.md (F-xx); NIW-APPENDIX.md.
No auto-commit; record in specs/prompts/.
```
**Approved:** 5 Sonnet persona agents + API-primary (console spot-checks).
