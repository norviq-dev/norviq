# Prompt — Remediate company-sim findings F-08…F-19 (before the live-chatbot test)

**Date:** 2026-06-29
**Work item:** Fix all company-sim defects (`.reviews/company-sim/FINDINGS.md`) — P1 audit-reason (F-08, all 5
sectors), energy OT noun-name bypass (F-09), finance SoD bypass (F-10); P2 attribution/telemetry/coverage
(F-11..F-16); P3 telecom-export / trust-threshold / tamper-evident-audit (F-17..F-19). Regression test per fix.
Plan mode (staged, highest-leverage first); security auditor on F-08/F-09/F-10. Run BEFORE the live-chatbot test.
**Source:** `.reviews/company-sim/FINDINGS.md` + `REPORT.md`. **Commit:** do NOT auto-commit. Keep **attacks 75/75**.

---

## Prompt

```
ROLE: Remediate the company-sim findings for Norviq (repo: norviq-migration/repo). USE PLAN MODE — present a
staged fix plan (highest-leverage first), WAIT for approval, implement stage by stage with a regression test per
fix. Security auditor on F-08/F-09/F-10. Read .reviews/company-sim/FINDINGS.md (F-08..F-19 + repros) and REPORT.md
first. Nothing may break the single-cluster path, the SDK/sidecar hot path, the packs' compose machinery, the
horizontal PCI/PII parity check, or existing tests. Keep attacks 75/75. Do NOT auto-commit — summarize per stage.

STAGE 1 — F-08 (P1, all sectors) + F-12 (P2) TOGETHER (they interact): comprehensive.rego block decisions log
reason:"Allowed".
  - Add a reason for every block/escalate rule_id in comprehensive.rego — but DO NOT use scalar `reason = "x"
    { guard }` clauses: when two rules match one call (PCI+PII+injection in one payload — the exact F-12 repro)
    multiple complete-rule `reason =` values CONFLICT → OPA eval error → `evaluator_error`. Use the PARTIAL-SET
    pattern the packs already use (`reasons[id] = "…" { guard }`) + a deterministic resolver pick (same precedence
    the rule_id resolver uses), so multi-match is conflict-free.
  - F-12: confirm the compound/control-char (`<|endoftext|>`) `evaluator_error` is this multi-match conflict (or
    root-cause whatever it is); ensure the reasons fix eliminates it; emit a NAMED fallback rule_id+reason on any
    residual eval error (never empty/`evaluator_error` with no attribution).
  - Tests: each block rule_id logs decision+rule_id+reason all correct; a single payload matching PCI+PII+injection
    → one deterministic named decision (no evaluator_error); add a lint/test that EVERY block rule_id has a reason
    (so it can't regress). attacks 75/75.

STAGE 2 — F-09 (P1, energy) + F-16: noun-first OT control names bypass.
  - Add device-noun ROOTS to `energy_ot_surface` (valve, pump, gate, switch, motor, generator, turbine,
    transformer, feeder, busbar, capacitor, regulator, …) so ANY non-read tool touching them → escalate
    (the pack's fail-safe net — close the hole, don't just chase a blocklist).
  - Add missing verbs (`set_voltage`, `configure_protection`) and catch decomposed param phrasing
    ({verb:"open",device_type:"breaker"}).
  - ASCII-skeleton-fold the TOOL NAME (homoglyph parity with tool_params — fixes `open_bгeaker`).
  - Tests: valve_close/valve_open/pump_start/pump_stop/gate_close/switch_open → block-or-escalate (NOT allow);
    open_bгeaker (Cyrillic) → blocked; benign get_valve_status/read_* → allow. Energy verdict must clear to pilot.

STAGE 3 — F-10 (P1, finance): SoD bypass. lower()+NFKC+confusable-skeleton-fold BOTH initiator and approver before
compare; treat empty/missing approver as a violation. Tests: Alice/alice → block; approver:"" → block; Cyrillic
аlice/alice → block; distinct legit initiator≠approver → allow.

STAGE 4 — P2 attribution/telemetry/coverage:
  - F-11: named rule_id (e.g. invalid_spiffe_identity) + reason on the identity-failure fallback (was empty).
  - F-13: populate audit `latency_ms` from the measured eval duration (was 0.0).
  - F-15: recurse nested objects/arrays in the shared PCI/PII scan (_shared/horizontal.rego) — keep the horizontal
    parity check green; tests: nested {payload:{ssn,card}} → block, benign nested → allow.

STAGE 5 — P3 + TWO PRODUCT DECISIONS (surface these as decisions BEFORE implementing — recommend + ask):
  - F-17: param-semantic CPNI/egress detection on telecom export tools (keys call_records/location + external
    destination) so a renamed export_* tool can't bypass the bulk-read block.
  - F-19: signed/hash-chained audit-export option (tamper-evidence, PCI 10.5) + masked tool_params capture
    (PAN→****1111, PCI 10.3) — opt-in.
  - DECISION F-14: deny-by-default / per-agent-class tool ALLOWLIST — build it as an OPT-IN per-namespace option
    (default off, so nothing regresses)? For energy/OT, "unknown tool → escalate" is the safer default. Recommend + ask.
  - DECISION F-18: trust_threshold — make it a REAL enforcement gate, or DOCUMENT that trust is recomputed and the
    setting is advisory? Recommend + ask.

GATES (per stage):
  - ruff + make test + opa check + tsc + vitest green; pack tests + the horizontal PCI/PII parity check green;
    new NRVQ-* codes in docs/error-codes.md; registry/architecture updated where structure changes.
  - attacks 75/75 at start and end of EVERY rego-touching stage.
  - Re-verify each fix against its FINDINGS.md repro (no longer reproduces); update the company-sim FINDINGS status
    (closed / partially-mitigated). Re-run the sim's previously-failing flagship scenarios → now safe (esp. energy
    valve_close→blocked, the F-08 reason on a real block, finance SoD case/empty/homoglyph→block).
  - NOTE (issue #4): comprehensive.rego + pack rego are DB-seeded content → these fixes are kind-validated +
    present in the working-tree image used by the live-chatbot test; live-AKS enforcement still rides the re-seed path.
  - Do NOT auto-commit; summarize per stage. Record this prompt + outcome in specs/prompts/ + index.
```
