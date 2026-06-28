# Norviq Prompt Archive

Record of significant Claude prompts driving Norviq development — for
reproducibility and engineering-process documentation (NIW/CNCF evidence).

Each prompt file contains: prompt text, outcome (commit SHA, result), date.

## Index

| Date | File | Work item | Commit | Result |
|------|------|-----------|--------|--------|
| 2026-06-15 | [P0-D-namespace-scoping.md](P0-D-namespace-scoping.md) | P0-D namespace scoping (agents + policies-list) | `96d060e` | Done — agents+policies ns-scoped; verified local + AKS (policies 1/0/0, agents 1/1/0); 66/66 held |
| 2026-06-15 | [P0-B-prod-config.md](P0-B-prod-config.md) | P0-B UI production configuration | `7a24b56` | Done — VITE_API_BASE_URL + .env.production + nginx /ws + dev-token-clean; verified prod image on AKS (same-origin /api 200, ns-scoping 1/0). Found: /ws/audit has no API backend (404) → P1 backlog |
| 2026-06-28 | [UI-fixes-and-regression.md](UI-fixes-and-regression.md) | UI punch-list fixes + post-fix regression | pending | Phase 1 run; regression 19/27 fixed, 353 pass / 8 fail / 1 skip, attacks 66/66, vitest+lint+tsc green; 8 residual = stale/test-isolation debt |
| 2026-06-28 | [EVAL-customer-sim.md](EVAL-customer-sim.md) | Customer-style eval (Opus orchestrator + Sonnet scouts, local kind) | pending | Ran → `.reviews/customer-eval/REPORT.md` (verdict ≈1.4/5, "do not pilot yet") |
| 2026-06-28 | [EVAL-remediation.md](EVAL-remediation.md) | Remediate eval findings (plan mode → Tier-A fixes) | done (uncommitted) | Tier A (A1–A8) + Tier C stubs. attacks 72/72, make test 377 pass / 6 pre-existing fail / 1 skip, vitest 37/37, lint+tsc+helm clean; live: unauth 401, viewer cross-ns/DELETE 403, ws token-gated, `/metrics` norviq_*, PII free-text blocks |
| 2026-06-28 | [EVAL-rerun-v2.md](EVAL-rerun-v2.md) | Re-evaluation v2 (verify Tier-A fixes, delta report) | done (uncommitted) | Ran → REPORT-v2.md. Verdict **1.4→3.1/5**. R8/R2/R1/R5/R6 Fixed (attacks 75/75 cluster); R7 HA fixed + 0 timeouts @50/100 but <5ms unmet; R3/R4 open-by-design. Bootstrap surfaced + fixed 3 install regressions (cert image, openssl, regex cap) |

| 2026-06-28 | [EVAL-closeout-tierB.md](EVAL-closeout-tierB.md) | Close out bounded findings (base64, webhook TLS, RBAC bindings, SIEM export) | done (uncommitted) | C1 base64 decode+block (attacks 75/75), C2 turnkey webhook TLS (helm hook), C3 RBAC bindings + prod-config doc, C4 audit export + SIEM forwarder; make test 387 pass / 6 pre-existing fail, vitest 37/37, lint+tsc+helm clean |

| 2026-06-28 | [EVAL-opa-server.md](EVAL-opa-server.md) | OPA-as-server (latency + HA, R7/R01) | done (uncommitted) | Long-lived OPA over HTTP (per-policy package isolation, fail-closed, NRVQ_OPA_MODE rollback, per-replica sidecar). Parity identical; attacks 75/75 both modes; cache-miss p99 ~25–31ms→~9–12ms (~3×), 0 timeouts @50/100-conc; <5ms not met (trust/Redis floor). make test 396 pass/6 pre-existing |


| 2026-06-28 | [COMMIT-and-aks-validate.md](COMMIT-and-aks-validate.md) | Commit remediation + validate AKS deploy | pending | Plan-then-push (auto-deploys to AKS); prod-secret + node-capacity guardrails |

## Convention
- One file per significant work item (P0/P1 fix, feature, major diagnosis)
- Filename: {item-id}-{short-name}.md
- Include: prompt text, outcome summary, commit SHA, date
- Update the index table when adding a file
