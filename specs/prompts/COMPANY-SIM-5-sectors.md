# Prompt — Role-based COMPANY SIMULATION across 5 critical-infrastructure sectors (scored + EB2-NIW)

**Date:** 2026-06-29
**Work item:** Scored "would we pilot this" buyer simulation for 5 fictional companies — healthcare, finance,
government, energy, telecom — each evaluated by a sector buyer team running that sector's pilot scenarios against
the product. Output = per-sector verdicts + CROSS-SECTOR COMMONALITIES (the recurring gaps = the priority fixes) +
GA-readiness call + an EB2-NIW evidence appendix. Plan mode (staged). Run on the FIXED post-remediation build.
**Design source:** `.reviews/company-sim/SECTOR-RECON.md` (per-sector context, threats, compliance, personas,
pilot scenarios, procurement gates, national-importance). **FEAT:** all. **Docker:** 12 GB. **AKS:** untouched (local).
**Commit:** do NOT auto-commit. Keep **attacks 75/75**.

This is a SCORED eval (buyer judgment), not a defect hunt — but log any defect it surfaces. Sectors are seeded as
TENANTS on the campaign cluster (not 5 live clusters); identity/fleet phases brought in only where a scenario needs them.

---

## Prompt

```
ROLE: Role-based COMPANY SIMULATION for Norviq (repo: norviq-migration/repo) across 5 critical-infrastructure
sectors. USE PLAN MODE — present the staged plan, WAIT for approval, execute stage by stage. Opus orchestrator +
Sonnet SCOUT PERSONAS that play a buyer EVALUATION TEAM and drive the product like real customers (API + the
console UI). This is a SCORED "would we pilot this" eval, NOT a defect hunt — but log any defect you surface into
the test-campaign ledger. Read .reviews/company-sim/SECTOR-RECON.md FIRST — it has, per sector, the context,
threat model, compliance hooks, buyer personas, the 6-10 pilot scenarios, the procurement gates, and the
national-importance points. Run on the FIXED post-remediation build (F-01..F-05 fixed + committed). AKS untouched —
local kind only. Do NOT auto-commit. Keep attacks 75/75.

COMPUTE MODEL (12 GB-aware): do NOT stand up 5 live clusters. Reuse the scripts/test-campaign harness; seed the 5
sectors as TENANTS (namespace sets + per-sector policy pack + per-sector agents/tools/data + persona tokens) on one
rich cluster, and run sector-by-sector. Bring in the identity phase (Keycloak+SPIRE) for the identity/confused-deputy
scenarios and the fleet phase (hub+spokes, incl. a residency-flagged spoke) for the residency/cross-cluster/fail-safe
scenarios — staggered, as the existing harness already does. Tear down between phases.

=== STAGE 1: SECTOR SEED (extend the SEED MANIFEST) ===
For EACH of the 5 sectors, create a fictional company and seed it as a tenant. Record in
.reviews/company-sim/COMPANIES.md (company → systems its agents call → regulated data → eval-team personas →
pilot scenarios → procurement gates → scripted objections), drawn from SECTOR-RECON.md:
  - HEALTHCARE  (e.g. "Mercy Health Net") — EHR/FHIR tools, PHI; team: CISO, CMIO, Privacy Officer, platform-eng.
  - FINANCE     (e.g. "Atlas Federal Bank") — payment rails/core-banking/cards, PII+CHD; team: CISO, Head of Fraud,
                Compliance, Model-Risk-Mgmt, platform-eng.
  - GOVERNMENT  (e.g. "State Benefits Agency / a federal program") — case/records/identity systems, PII+CUI+FTI;
                team: CAIO, Authorizing Official, CISO/ISSO, program office.
  - ENERGY      (e.g. "Cascade Power & Light") — IT + OT-adjacent OMS/ADMS, operational data; team: CISO,
                OT-security lead, NERC-CIP compliance, platform/SRE.
  - TELECOM     (e.g. "Northstar Mobile") — OSS/BSS/provisioning/CRM, CPNI+location; team: CISO, network-security
                lead, fraud/threat-intel, cloud-native platform-eng.
Each sector gets: its policy pack (allow/block/escalate/audit rules for that sector's tools), its agents (incl. a
low-trust + a spoofing one), and realistic traffic. Reuse the campaign personas/identity where possible.

=== STAGE 2: RUN THE PILOT SCENARIOS (per sector) ===
For each company, the eval-team personas execute that sector's pilot scenarios from SECTOR-RECON.md §per-sector
"standout scenarios" (e.g. healthcare: autonomous med order → escalate; bulk-PHI exfil → block. finance: wire
above threshold → escalate; cardholder exfil → block. government: benefit.deny → HITL; CUI egress → block; SPIFFE
deny (IA-9). energy: operational/control command → HARD BLOCK + escalate, IT-only read → allow (the IT/OT proof).
telecom: SIM-swap → block+escalate+audit; CPNI bulk read → block). Record setup → action → OBSERVED behavior →
expected → PASS/FAIL. Drive via API AND the console (use the Playwright/browser path where it proves a UI gap).
ALSO run the UNIVERSAL scenario set in every sector:
  injection→dangerous tool call blocked/escalated (action-boundary); high-impact→HITL with audit-grade record;
  out-of-scope tool→least-privilege block; sensitive-data exfil egress blocked + residency honored; workload-identity
  spoof→deny + operator OIDC attribution; audit/SIEM export integrity (actor+tool+decision+policy+ts, tamper-evident);
  fail-safe (component/hub down → keep enforcing).

=== STAGE 3: SCORE (buyer judgment) ===
Score EACH company 1-5 on 6 dimensions, with evidence per score:
  1 Enforcement correctness (safe behavior on every scenario)
  2 Audit/evidence quality (per-decision log = the regime's evidence; auditor test; SIEM export)
  3 Identity & least privilege (SPIFFE/OIDC + RBAC + SoD under adversarial cases)
  4 Deployability/fit (k8s-native fit, hot-path latency, fail-open vs fail-closed, residency, in-boundary/self-host)
  5 Procurement readiness (clears the sector's HARD gate: BAA / SoD+SIEM / FedRAMP-path / IT-OT proof / CPNI controls)
  6 Product/usability (onboarding friction, console clarity, "would a real team operate this")
→ Per-sector VERDICT: pilot / pilot-with-conditions / not-yet, with the BLOCKING GAPS named.
The eval team must also raise the sector's SCRIPTED OBJECTIONS and record whether the product answers them.

=== STAGE 4: CROSS-SECTOR SYNTHESIS (the decision input) ===
.reviews/company-sim/REPORT.md:
  - per-sector scorecards + verdicts + blocking gaps;
  - **COMMONALITIES** — gaps/objections that recur across ≥2 sectors, RANKED (these are the highest-leverage fixes —
    this is what we'll act on); separate "sector-specific" from "universal" gaps;
  - a rolled-up **GA-readiness call** (ship / ship-with-conditions / not-yet) with the blocking set;
  - regressions/defects found → into .reviews/test-campaign/FINDINGS.md (continue the F-xx numbering).
  - EB2-NIW EVIDENCE APPENDIX → .reviews/company-sim/NIW-APPENDIX.md: the per-sector national-importance points +
    the Matter-of-Dhanasar Prong-1 mapping + sources, framed as petition-exhibit material. Mark any claim that still
    needs primary-source verification (per the SECTOR-RECON verify-flags).

GATES:
  - Local kind only; AKS untouched; 12 GB-aware (tenants not 5 clusters; stagger identity/fleet phases).
  - Attacks 75/75 at start + end. Reuse scripts/test-campaign/ harness + SEED MANIFEST; extend, don't fork.
  - Do NOT auto-commit; summarize per stage. Record this prompt + outcome in specs/prompts/ + index.
  - Honest labeling: scores backed by observed evidence; deferred/unreached scenarios listed with reason.
```
