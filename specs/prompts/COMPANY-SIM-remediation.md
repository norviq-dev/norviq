# Prompt — Remediate the company-sim findings (F-08..F-19)

**Date:** 2026-06-29
**Work item:** Staged, plan-mode remediation of the genuine shipped-code defects the 5-sector company simulation
found (`.reviews/company-sim/FINDINGS.md`, F-08..F-19). Security-auditor lens on F-08/F-09/F-10. Local kind only
(`nv-a`); AKS untouched; no auto-commit; summarize per stage; attacks 75/75 at start+end of every rego-touching stage.
**Source:** `.reviews/company-sim/{FINDINGS,REPORT}.md`.

## Result (DONE — local only, nothing committed)

All 12 findings remediated across 5 stages; every repro re-verified non-reproducing LIVE on nv-a; FINDINGS.md
statuses updated. attacks **76p+2xfail (75/75)** at start and end of every stage. opa tree 75→**115/115**; horizontal
PCI/PII parity guard 8→**13/13**; ruff clean; masking/chain unit tests **12/12**. Engine changes required rebuilding +
kind-loading the api image (issue #4: rego is DB-seeded, but engine code rides the image) — done and live-validated.

- **STAGE 1 — F-08 (P1, all 5) + F-12 (P2).** Rewrote `comprehensive.rego` from 14 scalar `rule_id="x"{}` clauses
  (which conflicted on multi-match → OPA `eval_conflict_error` = the F-12 root cause) to the packs' **partial-set +
  resolver** pattern (`blocks/escalates/audits[id]` + static `reasons` map + deterministic resolver). Detection
  predicates byte-unchanged; decision parity verified on all 16 cases. F-08: every block/escalate/audit now carries a
  real reason (live: 26 non-allow records, **0 `reason=="Allowed"`**). F-12: compound PCI+PII+injection+`<|endoftext|>`
  → one named `block/deny_shell_execution`, no `evaluator_error`. Guard: `comprehensive_test.rego` (8/8).
- **STAGE 2 — F-09 (P1 energy) + F-16.** energy.rego: noun-first control verbs (valve_close/pump_start/…) → block;
  device-noun ROOTS in OT-surface → any non-read → fail-safe escalate; set_voltage/configure_protection → block;
  decomposed `{verb,device_type}` phrasing → block (action/device-key-scoped, FP-guarded). Engine `_build_input` emits
  **`tool_name_normalized`** (skeleton fold) → Cyrillic `open_bгeaker` → block. energy pack 31/31; live-validated.
- **STAGE 3 — F-10 (P1 finance).** SoD compares the engine confusable-skeleton fold + a raw `lower()` fallback;
  empty/whitespace/missing approver = violation. Live: alice/alice, Alice/alice, empty, missing, Cyrillic аlice → block;
  distinct → allow. finance pack 12/12.
- **STAGE 4 — F-11 + F-13 + F-15.** F-11: `InvalidSpiffeIdentity` → named `invalid_spiffe_identity` block (NRVQ-ENG-2006).
  F-13: stamp the real measured end-to-end latency on the decision before persist (multi-candidate path was 0.0). F-15:
  `walk()` recursion for nested PII/PCI in BOTH comprehensive.rego and `_shared/horizontal.rego` (identical → parity).
  Live: invalid SVID → named block; nested SSN → block; real latency in new audit rows.
- **STAGE 5 — F-17 + F-14 + F-19 + F-18.** F-17: telecom param-semantic CPNI exfil (external dest → block; internal
  egress → escalate). F-14 (decision = opt-in/escalate, default OFF): `policies/templates/tool_allowlist.rego` loaded as
  the additive `(ns,__guardrail__)` overlay (engine resolver generalized to tighten-only for __pack__ AND __guardrail__);
  unlisted → escalate, never weakens a baseline block (proven live). F-19 (opt-in, default OFF): `masking.py` masked
  param capture + `/audit/export?signed=true` SHA-256 hash-chain + HMAC manifest (live: masked, chain valid, sig verifies).
  F-18 (decision = advisory + recompute visible): documented in trust-score-design.md §11b (caller score stripped &
  recomputed; threshold tunes escalation, not a gate; recompute returned + audited).

**Gates:** ruff clean; opa 115/115; PCI/PII parity 13/13; masking+chain 12/12; attacks 75/75 every stage. The
infra-dependent engine pytest set (redis/postgres) is the documented pre-existing local-infra gap, not a regression.
Nothing committed. See `.reviews/company-sim/FINDINGS.md` for per-finding STATUS.

## Prompt
```
Remediate the company-sim findings for Norviq (repo: norviq-migration/repo). USE PLAN MODE — staged fix plan
(highest-leverage first), WAIT for approval, implement stage by stage with a regression test per fix. Security
auditor on F-08/F-09/F-10. Read .reviews/company-sim/FINDINGS.md (F-08..F-19 + repros) and REPORT.md first. Nothing
may break the single-cluster path, the SDK/sidecar hot path, the packs' compose machinery, the horizontal PCI/PII
parity check, or existing tests. Keep attacks 75/75. Do NOT auto-commit — summarize per stage.
STAGE 1 F-08+F-12 (partial-set/resolver, no scalar reason); STAGE 2 F-09+F-16 (energy OT noun roots/verbs/decomposed/
homoglyph); STAGE 3 F-10 (finance SoD normalize+empty); STAGE 4 F-11/F-13/F-15; STAGE 5 F-17/F-19 + DECISION F-14 +
DECISION F-18. GATES per stage: ruff+make test+opa check+tsc+vitest+parity+attacks 75/75; re-verify each repro; update
FINDINGS; record in specs/prompts.
```
**Decisions approved:** F-14 = opt-in per-namespace allowlist → escalate (default OFF); F-18 = document as advisory +
make recompute visible (no enforcement change).
