# Prompt — Remediate customer-evaluation findings (plan mode → fix)

**Date:** 2026-06-28
**Work item:** Triage and fix the P0/P1 findings from the customer evaluation
(`.reviews/customer-eval/REPORT.md`). Plan mode first, then implement the bounded (Tier A) fixes.
**Commit:** (uncommitted — per instruction, no auto-commit)
**Result:** Tier A (A1–A8) implemented + Tier C design stubs written. Verification: `make lint`
clean; `tsc --noEmit` clean; **attacks 72/72** (was 66; +6 PII/PCI free-text & guard cases), 0
xfail/skip; `make test` 377 passed / 6 pre-existing failures (confirmed via stash — local-seed
`default:customer-support`-only + non-idempotent crud DB row; not regressions) / 1 skipped; vitest
37/37; helm lint clean (api replicas=2 + PDB render). Live spot-checks on the dev API: unauth
`/audit|/policies|/graph` → 401; admin → 200; viewer `?namespace=payments` → 403, `default` → 200;
viewer DELETE policy → 403; `/ws/audit` rejects missing token (12/12 auth-hardening live); PII
free-text → block/`pii_detection`; `/metrics/` exposes `norviq_*`. New codes: `NRVQ-API-7032`,
`NRVQ-API-7099`, `NRVQ-AUD-6008`, `NRVQ-ENG-2051` (registered in `docs/error-codes.md`). Tier B
(SIEM export, OPA-as-server) deferred as design notes in the plan; Tier C epics written:
`specs/EPIC-multi-cluster-fleet.md`, `specs/EPIC-sso-oidc.md`.

**Report summary (verdict ≈1.4/5, "do not pilot yet"):** strong policy engine (10/12 OWASP-LLM
blocked, 0% FP) + console + MITRE page, but P0 gaps: not multi-cluster (R3), product insecure
(forgeable/unrotatable admin JWT, unauth /audit /policies /graph /ws, viewer can DELETE policy,
sidecar fail-open — R8), latency ~40–120× the <5ms claim (per-call OPA subprocess, R7), no HA,
no SIEM/SSO (R4/R5). Findings independently cross-checked against code — accurate.

**Triage:** Tier A = bounded code/config fixes (auth on all endpoints; config-alias + secret
rotation guard; require_admin on policy writes; sidecar fail-closed; PII free-text regex; HA
defaults + OTel-disable; norviq_* metrics + persistent Agents view; UI polish). Tier B = SIEM
export, OPA-as-server (design note then build). Tier C = EPICS, design spec only: multi-cluster
fleet plane (R3), SSO/OIDC (R4).

---

## Prompt

```
ROLE: Remediate the customer-evaluation findings for Norviq (repo: norviq-migration/repo).
USE PLAN MODE FIRST — investigate and present a plan; do NOT edit any file until I approve it.

INPUTS (read fully first):
  .reviews/customer-eval/REPORT.md and .reviews/customer-eval/findings/{ops,ui,api,security,perf}-scout.md

PLAN REQUIREMENTS (ExitPlanMode with this, then wait):
Triage every REPORT item into three tiers and lay out the plan tier by tier:

  TIER A — bounded code/config fixes to implement THIS pass (with file paths + test impact):
    A1 Authenticate every data endpoint: add Depends(get_current_user) to /api/v1/audit/*,
       GET /api/v1/policies*, /api/v1/graph/*, and the /ws/audit socket; scope by the token's
       namespace claim, not the query param. (api/routers/*.py, api/main.py)
    A2 Fix the config alias bug: api_secret_key must read the env the chart sets (add the
       NRVQ_-prefixed choice or set API_SECRET_KEY in the chart); same for db_ssl_mode; add a
       startup guard that refuses the default secret outside dev. (config.py, helm)
    A3 Enforce require_admin on policy create/update/delete/rollback/apply (helper already exists).
    A4 Sidecar fail-CLOSED: proxy.py / http_fallback.py must return block/drop on error, not forward.
    A5 PII/PCI on free-text: un-anchor / substring-scan the Rego regexes (comprehensive.rego +
       policies/data_protection/*) WITHOUT raising false positives.
    A6 HA defaults: api.replicas>=2 + PodDisruptionBudget; stop OTel exporter init when
       otel.enabled=false (audit_emitter.py). (helm, telemetry)
    A7 Expose norviq_* Prometheus metrics on /metrics; back the Agents view with persistent
       agent_registry instead of the 30s trust:* cache.
    A8 UI polish: Settings Save must actually persist (today it toasts success with no call);
       remove the "Coming in Day 8" Red Team stub from nav; populate Audit Log Agent Class; fix
       Policy Tester SQL preset surfacing evaluator_error.

  TIER B — medium efforts needing a short design note in the plan (do AFTER Tier A, separate):
    SIEM export (authenticated NDJSON/CSV + syslog/webhook); OPA-as-server to fix latency/HA (R01).

  TIER C — EPICS, design spec only (do NOT implement in a fix pass): multi-cluster fleet/control
    plane (R3) and SSO/OIDC (R4). Produce a one-page design stub under specs/ for each.

For each Tier-A item state: files touched, the test(s) you'll add/update, and the rollback risk.
FLAG the test impact explicitly: adding auth will break existing tests that assert unauth 200s —
those tests must be updated to send tokens (not deleted).

AFTER I APPROVE THE PLAN — implement Tier A only:
  - Follow CLAUDE.md gates: for any changed feature, update architecture/{FEAT}.*.mmd + registry/
    {FEAT}.md + tests (allow/block/error paths; assert rule_id; never monkeypatch get_session).
  - Keep the attack baseline 66/66 (0 xfail/skip) — re-run after every production change.
  - Run make lint + make test + vitest + tsc; do NOT auto-commit; summarize results.
  - Record this remediation prompt + outcome in specs/prompts/ and update the index.
```
