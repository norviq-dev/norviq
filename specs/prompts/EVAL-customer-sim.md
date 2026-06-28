# Prompt — Customer-style evaluation (orchestrator + scout fleet)

**Date:** 2026-06-28
**Work item:** Role-based product evaluation. Opus 4.8 orchestrator + 5 Sonnet scouts role-play
"Lumina Retail SecOps" (manages multiple k8s clusters) evaluating Norviq; produce a scorecard +
engineering backlog at `.reviews/customer-eval/REPORT.md`.
**Environment:** local, scripted under `scripts/eval/` (kind = real k8s on local Docker). Option A
(builds local code into images); 2 clusters (lumina-a full, lumina-b api-only = multi-cluster test
target); engine pod off; ~30-call data seed; see `scripts/eval/README.md`.
**Commit:** (pending — run after the regression cleanup; eval does not block on the 8 residual tests)
**Result:** (to be filled after the run — link REPORT.md + commit)

Run order: `bash scripts/eval/00-bootstrap-local.sh` → `nohup bash scripts/eval/20-portforward.sh &`
→ paste the master prompt below into Claude Code (Opus) → `bash scripts/eval/99-teardown-local.sh`.

Verified config-wiring findings folded into scout context: `api_secret_key` reads
API_SECRET_KEY/JWT_SECRET (chart's NRVQ_API_SECRET_KEY ignored → JWT secret pinned to the committed
default, unrotatable — R8); `db_ssl_mode` reads DB_SSL_MODE (NRVQ_DB_SSL_MODE ignored; harness sets
the real alias).

---

## Master prompt

```
ROLE & MODEL
Run on Opus 4.8. Lead evaluator for a customer-style evaluation of Norviq (repo: norviq-migration/
repo). Orchestrate Sonnet scout subagents (Task tool, model: sonnet, parallel), verify evidence,
write the report. NEVER fabricate findings — every claim needs an artifact. Environment scripted
under scripts/eval/.

PRECONDITIONS — proceed if: attacks 66/66 (0 xfail/skip), 13 new backend tests, 35 vitest, lint,
tsc all GREEN (latest backend run 353 passed / 8 failed / 1 skipped, the 8 being known stale/test-
isolation debt: cached_block, 2× test_proxy, langchain-allowed, telemetry, 2× test_api/proxy_runtime,
policy_loader). STOP only if attacks regressed or NEW failures appeared. Also: Docker >= 6 GB; kind/
kubectl/helm/python3/node on PATH; internet for first build; git clean.

PHASE 0 — ENVIRONMENT (Option A builds local code):
  1. bash scripts/eval/00-bootstrap-local.sh   (clusters; engine off; seeds comprehensive.rego +
     ~30 calls incl. trust spread + frozen agent + attack-paths; sets DB_SSL_MODE via the real
     alias). Onboarding friction = R1 evidence.
  2. nohup bash scripts/eval/20-portforward.sh >/tmp/nrvq-pf.log 2>&1 &
  3. API_A=$(python3 -c 'import json;print(json.load(open(".reviews/customer-eval/env.json"))["urls"]["api_a"])'); curl -fsS "$API_A/healthz"
     env.json: urls.api_a/ui_a/api_b_hint, tokens.admin/viewer, contexts.a/b, namespace, secret_used.

PERSONA "Lumina Retail" / "Lumina SecOps" (multi-cluster). Requirements:
  R1 Helm install effort. R2 Block OWASP-LLM attacks, low false positives. R3 Single-pane across
  ALL clusters. R4 RBAC (SecOps not devs) + SSO. R5 SIEM/export + dashboards + MITRE. R6 Trust
  explainable + catches anomalies. R7 <5ms p99 + HA. R8 Product itself secure.

EVIDENCE CONTRACT: every finding needs an artifact + repro; reject evidence-free claims & re-task.
Scouts append to .reviews/customer-eval/findings/<scout>.md:
  id | R# | dimension | status | severity | claim | evidence | repro | customer-impact | recommendation
Record positives too.

TEST STATE & SCOUT CONTEXT (interpret correctly; report the product-relevant ones with live evidence):
  - TRUST (R6): block does NOT sync-decrement trust; recomputed from history async — assess against this.
  - METRICS (R5): verify /metrics on the LIVE API (unit test doesn't wire the registry).
  - SIDECAR/PROXY (R2/R8): proxy may forward when it has no policy (fail-open); injection off here —
    assess from code + evidence.
  - CONFIG-WIRING (R8, verified): NRVQ_API_SECRET_KEY ignored → JWT secret pinned to default
    "change-me-in-production", unrotatable via Helm; NRVQ_DB_SSL_MODE ignored too.
  - POLICY PERSISTENCE: no DB isolation; versions accumulate; DELETE may be a no-op (finding).

PHASE 1 — 5 Sonnet scouts (Task, model: sonnet, one message), each reads env.json, non-destructive:
  1 ops-scout: time Helm install (R1); R3 multi-cluster test (one console see/manage both? expected
    NO — prove it); HA pod-delete (R7); footprint/logs/prod-config incl. config-wiring.
  2 ui-scout (Playwright, reuse scripts/ui-validate.mjs): BASE=urls.ui_a (not :5173); set
    localStorage nrvq_token=tokens.admin before nav; walk every page; cross-cluster scoping (R3/R5);
    screenshots to findings/ui-shots/; console errors.
  3 api-scout: auth model, error contracts, OpenAPI, SIEM/export (R5), verify /metrics live; authZ
    (R4/R8) with tokens.viewer cross-namespace; note policy-version accumulation.
  4 security-scout: OWASP-LLM attacks via urls.api_a (R2) + false positives on benign; R8 — forge an
    admin JWT signed with env.json secret_used and confirm acceptance (LIVE); show secret
    unrotatable; unauth /audit & /graph; proxy fail-open from code+evidence.
  5 perf-scout: /api/v1/evaluate latency vs <5ms p99 (note per-call OPA subprocess); modest
    burst/concurrency; cold-start (R7). Light load (Mac mini).

PHASE 2 — VERIFY & RE-TASK: R1–R8 × dimension matrix; reject evidence-free; re-task (SendMessage)
until every requirement has grounded evidence (gaps AND positives).

PHASE 3 — SCORE & REPORT: dimensions 0–5 (Onboarding · Day-1 Value · Multi-cluster/Fleet ·
Observability · Trust · Performance/Scale · Product security · Reliability · Integrations · Docs).
Write .reviews/customer-eval/REPORT.md: exec summary + "Would Lumina SecOps deploy it?" verdict →
scorecard → per-dimension findings (evidence links) → P0/P1/P2 backlog → strengths → appendix.

PHASE 4 — TEARDOWN: kill the port-forward; bash scripts/eval/99-teardown-local.sh.

GUARDRAILS: read-only/non-destructive except the throwaway kind clusters; no commits; throwaway
secrets; report blockers honestly. The harness disables webhook/sidecar/engine/OTel/DB-TLS for the
laptop — assess those from the shipped chart defaults + docs (R1/prod-config), do NOT report
"no sidecar/no engine" as a product gap.
```
