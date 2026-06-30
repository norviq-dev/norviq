# Prompt — Exhaustive round-2 UI + pentest-API audit (every route, every control)

**Date:** 2026-06-30
**Work item:** A complete, miss-nothing audit of the console + the productized pentest API + the policy-apply
model — the surfaces round-1 (F-29…F-39) did not reach. DISCOVERY/AUDIT pass: find + document, do not fix in this
pass (fixes follow as F-42+). Drive the live 3-cluster fleet headlessly; exercise EVERY route and EVERY interactive
control; capture network status + console errors + a screenshot per page; produce a coverage matrix proving total
coverage, a findings ledger (F-42+), and the policy-apply security evaluation.
**Base branch:** `feat/f40-fleet-push-guard` (head of the stack — has all fixes through F-41).
**Gates:** do NOT auto-commit · AKS untouched (local kind only) · no destructive actions · revert any state change ·
NEVER fleet-push to `__baseline__`/`__pack__` · honest coverage labeling.
**Result:** **DONE (2026-06-30, discovery).** All 16 routes + 80+ controls driven headlessly on the 3-cluster
fleet; per-page screenshot + network + console captured (`portal/round2/`, harness
`scripts/live-pentest/round2_audit.py`). **Zero app-level console errors**; dashboard KPIs reconcile with the API
(2493/1600/64% ≈ 2498/1601/64.09%). **8 findings F-42…F-49:** F-42 (P2-sec) `apply` lacks the F-40 reserved-scope
guard (`apply` to `__pack__`/`__baseline__` → 200 while create → 422); F-43 (P3) red-team endpoints ungated
(viewer→200); F-44 (P2) red-team suite not target-aware (identical 73.1% across all 3 sectors); F-45 (P2) 7 genuine
baseline coverage gaps (red-team verified trustworthy: actual==`/evaluate`); F-46 (P3) Dashboard "Export" dead
control; F-47 (P3) attack-graph severity uniformly low; F-48 (P4) asset-graph node-click detail (needs manual
confirm); F-49 (P3) PolicySheet custom-params not wired. **RBAC:** all 5 core mutations + fleet push correctly
admin-gated (viewer→403); only the red-team router is ungated (F-43). **Policy-apply eval:** confirmed in-memory
`load_policy` swap, no kubeconfig, boundary = admin JWT; admin-RBAC + actor-audit EXIST, confirm/diff + apply-path
reserved-scope guard + per-ns dry-run-only mode are GAPS. F-40 fleet-push guard + F-31 empty-state both hold from
the UI. AKS untouched; no engine/rego changed. Deliverable `.reviews/live-pentest/UI-AUDIT-ROUND2.md`.

---

## Prompt

```
ROLE: Run an EXHAUSTIVE round-2 UI + pentest-API audit of Norviq (repo: norviq-migration/repo). This is a
DISCOVERY pass — find and document issues, do NOT fix them here (fixes become F-42+ in a later pass). Be
methodical: the goal is that NO page, button, dashboard, visualization, toggle, filter, or API endpoint goes
untested. Base on branch feat/f40-fleet-push-guard.

SETUP (make the environment reachable + KEEP IT UP):
  - Ensure the 3-cluster kind fleet is running; (re)establish PERSISTENT background port-forwards and leave them up:
    fleet-a console 127.0.0.1:8081, fleet-b :8082, fleet-c :8083, Grafana :3001. Verify each (curl -sI → 200).
  - Auth: inject the admin JWT into localStorage (key nrvq_token) as in CLOSEOUT-UI. Also mint a VIEWER token for
    the RBAC checks below.
  - Method per surface: drive headless (Playwright/chromium); for each page capture (a) a screenshot, (b) the
    /api network calls + status, (c) console errors; for each interactive control, actuate it and record what
    happened (endpoint + result, or "no-op / error"). Save screenshots to .reviews/live-pentest/portal/round2/.

COVER EVERY ROUTE (16) — and every control on each:
  1. / (Dashboard): time ranges 1h/6h/24h/7d/30d, global search, Report ▼ (each option), Export, Inbox, Account
     menu, every card (Security Score, Trust Distribution, Top blocked tools, Policy Coverage) — values reconcile
     with the API.
  2. /policies/catalog: Catalog/Editor/Versions tabs, New Policy, Save, Dry-Run, Apply (the drawer: target types
     Agent Class/Workload/Namespace, enforcement Block/Audit/Escalate, Copy YAML), rollback from Versions.
  3. /policies/packs: Enable/Disable EVERY sector pack (revert each after), confirm coverage reflects.
  4. /policies/targets: namespaces + workloads.
  5. /audit: tabs All/Allow/Block/Escalate/Audit, Tool-name filter, Agent-SPIFFE filter, Quick-filter, time range,
     pagination (Prev/Next), row click/detail, any export. Note retention (how far back).
  6. /agents: list, row click, trust history, tool-usage, any filters.
  7. /test (Policy Tester) — PRODUCTIZED PENTEST UI: run a single scenario + the full suite; results render; ties
     to the redteam API below.
  8. /asset-graph: search, all node-type toggles (agent/tool/data/namespace), all severity toggles, node click,
     legend.
  9. /threats/graph (Attack Graph): severity filter (incl. a value with 0 matches → correct empty state, F-31),
     Recompute, node + path click, Simulate Attack button.
  10. /threats/mitre: technique cards, activity overlay counts, any drill-down.
  11. /fleet: cluster table, Drill down per cluster, Push policy (VALID single-cluster named push → 200; empty →
      inline error; reserved-scope/fleet-wide-no-confirm → 422 per F-40 — confirm guards hold from the UI).
  12-16. /settings/account, /settings/api-keys (create + revoke a key, then clean up), /settings/general (save
      changes), /settings/connections, /settings/about; Logout.

PENTEST API (productized red-team — exercise directly, it was never tested as a deliverable):
  - GET /api/v1/redteam/catalog (lists scenarios); POST /api/v1/redteam/run (one attack) → expected vs actual;
    POST /api/v1/redteam/suite → full run report (pass-rate, per-scenario); GET /api/v1/redteam/report/{run_id}.
    Confirm results are correct + trustworthy (decisions match what /evaluate would return) and the Policy Tester
    UI drives these same endpoints. Flag any scenario whose expected≠actual.

RBAC / SECURITY CHECKS (mutation must be gated):
  - With the VIEWER token, attempt: policy Apply (POST /policies/{ns}/{ac}/apply), policy delete, pack enable,
    fleet push, settings save → each MUST be 403. With admin → allowed. Record any mutation a viewer can perform
    (that's a finding). Confirm /apply requires admin (the open item from the apply-model eval).

POLICY-APPLY MODEL EVALUATION (write it up):
  - Document, with code + live evidence: applying policy from the portal does NOT use kubeconfig — apply_policy
    writes to the policy store (DB) and the engine/sidecars hot-reload; the boundary is API RBAC (admin JWT), not
    kubeconfig. Recommend: keep Apply (don't restrict to dry-run-only), gated by admin RBAC + a confirm/diff
    preview + actor-audit + the F-40 reserved-scope guard; offer an OPT-IN per-namespace "dry-run-only / require
    approval" mode for high-assurance (gov) tenants. Note whether each control exists today vs is a gap (F-42+).

SAFETY:
  - Local kind only; AKS untouched. No destructive actions (no data deletes except the API-key you created for the
    test, which you then revoke). REVERT every state change (pack toggles, settings, created policies/keys). NEVER
    fleet-push to __baseline__/__pack__. If a test would mutate shared enforcement irreversibly, describe it instead.

DELIVERABLES (.reviews/live-pentest/, local-only):
  - UI-AUDIT-ROUND2.md = (a) a COVERAGE MATRIX: every route × every control, with status tested/ok | finding |
    n/a (this is the proof nothing was missed); (b) findings ledger F-42+ (severity, repro, root cause, suggested
    fix); (c) the red-team-API result; (d) the RBAC result; (e) the policy-apply model evaluation.
  - portal/round2/*.png screenshots.

GATES:
  - Do NOT auto-commit; summarize at the end. AKS untouched. If anything engine/rego was touched (shouldn't be in a
    discovery pass), attacks 75/75. Record this prompt + outcome in specs/prompts/ + index. Honest coverage labels —
    if a control couldn't be reached, say so explicitly, don't silently skip.
```
