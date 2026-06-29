# Prompt — Console cleanup: eliminate ALL fabricated/static display data (EXHAUSTIVE, wire to live APIs)

**Date:** 2026-06-29
**Work item:** Exhaustively sweep the console (`ui/`) for ANY hardcoded/fabricated data rendered as if
real, and wire every rendered datum to a live API. Where no backend exists, BUILD the real endpoint.
Cluster + namespace selectors become live + fleet-aware. Plan mode (staged); 100%-coverage audit +
runtime network proof + independent re-audit. Miss-nothing is the explicit bar.
**FEAT:** F018 (console) + **F046** (new live-data endpoints). **Commit:** (uncommitted — do NOT auto-commit) ·
**Result:** DONE (8 stages). Audit → `.reviews/ui-cleanup/INVENTORY.md` (every page+component verdict). Built
real endpoints: `/cluster-info`, `/coverage-by-category` (rule→category cross-ref via `policies/category_mapping.json`),
`/agents/{id}/tool-usage` + `/trust-history` (audit_log aggregations), `/settings` GET/PUT (DB-backed override),
`/version` (importlib.metadata single source), `/keys` CRUD (issue/list/revoke, hash-only, admin, + additive
`nrvq_` api-key auth). Wired: live fleet-aware cluster/namespace selector (dropped CLUSTERS/NS_BY_CLUSTER),
Dashboard posture+coverage, CategoryCoverage, AgentMonitor insights, asset-graph edge history (removed pseudo-random
fallback), PolicyCatalog deployments (dropped FALLBACK_DEPLOYMENTS), ConnectionSettings `/readyz`, Header+Account `/me`,
Settings/Target/About+footer, APIKeys, RedTeam suite. Independent re-audit caught + fixed 1 miss (Dashboard KPICard
fake trend strings). Gates: ruff clean; 24 new endpoint tests (happy/empty/error); tsc + vitest 37/37; attacks still
collect 75 (auth change additive); fleet OFF by default; single-cluster selector works. Codes NRVQ-API-7080..7093.
Remaining live step: browser network capture (ROUTES.md is code-traced).

Decisions locked (AskUserQuestion): no-backend data → **build the real endpoint**; selectors → **live
source, fleet-aware**. Inventory → `.reviews/ui-cleanup/INVENTORY.md` (a row for EVERY file). Runtime
route proof → `.reviews/ui-cleanup/ROUTES.md`. Independent re-audit sign-off required.

Confirmed offenders from the pre-scan (NON-exhaustive — the audit must find the rest):
- `CategoryCoverage` DEFAULT_SCORES (92/88/74/63/81) rendered by PolicyCatalog with no data.
- `CLUSTERS` + `NS_BY_CLUSTER` (store/AppContext.tsx) → fake clusters/namespaces in the Header selector.
- `FALLBACK_DEPLOYMENTS` (pages/PolicyCatalog.tsx:89) — hardcoded deployment list.
- `INITIAL_CONNECTIONS` (pages/ConnectionSettings.tsx:16) — hardcoded connections.
- **7 pages make ZERO API calls** → APIKeys, AccountSettings, GeneralSettings, RedTeam, TargetSettings,
  Settings, AboutPage. Each must become real or be justified as legitimately static (and even version/
  build info should come from an endpoint, not a literal).

---

## Prompt

```
ROLE: Console cleanup — EXHAUSTIVELY eliminate fabricated/static DISPLAY data from the Norviq console
and wire every rendered value to a live API. Norviq (repo: norviq-migration/repo). USE PLAN MODE —
first run a 100%-COVERAGE AUDIT (static + runtime), produce the INVENTORY, present a staged plan, WAIT
for approval, fix stage by stage, then RE-AUDIT independently. The bar is MISS NOTHING. Nothing may
break existing wired pages, tests, attacks 75/75, or the single-cluster path.

PRINCIPLE: the console must never render a number, list, chart, status, badge, or label that was
invented in the frontend. Every rendered datum traces to an API response (live or a real, documented
computation). Where a widget shows fabricated data and HAS NO backend, BUILD the backing endpoint with
a defensible real computation — never a fake default, never silently delete a feature.

=== PHASE 1: 100%-COVERAGE AUDIT (do this FIRST, before any fix) ===
The audit is mechanical and complete. Produce .reviews/ui-cleanup/INVENTORY.md with a row for EVERY
file below — none may be skipped; each gets a verdict: CLEAN / WIRE (endpoint exists) / BUILD (new
endpoint) / LEGIT-CONSTANT (config, not data) / JUDGMENT (ask).

  Pages (17) — visit every one:
    Dashboard, PolicyCatalog, PolicyTester, AgentMonitor, AuditLog, MITRECoverage, AttackGraph,
    AssetGraph, Fleet, RedTeam, Settings, GeneralSettings, AccountSettings, ConnectionSettings,
    TargetSettings, APIKeys, AboutPage.
  Components — visit every one under components/** (charts, common, layout, asset-graph, attack-graph;
    the ui/* primitives are presentational — confirm they hold no embedded data).
  State/config: store/AppContext.tsx; api/client.ts; api/fleet.ts.

  Detection passes (run ALL, record findings):
   (a) Static grep sweep: literal arrays/objects assigned to consts and rendered; numeric/% literals in
       JSX; hardcoded status/score/count/trend strings; default-valued props that supply data (e.g.
       `data = DEFAULT_*`); any `FALLBACK_*`/`INITIAL_*`/`DEFAULT_*`/`SAMPLE_*`/`MOCK_*` used at runtime.
   (b) Per-component data-flow walk: for each rendered datum, trace it to a fetch/useApi/prop-from-fetch.
       If it can render populated WITHOUT any API call, it's fabricated → flag.
   (c) NO-API page check: every page must make >=1 real API call OR be justified LEGIT-static in the
       inventory. The 7 known no-API pages (APIKeys, AccountSettings, GeneralSettings, RedTeam,
       TargetSettings, Settings, AboutPage) must each be resolved explicitly.
   (d) Distinguish DATA from CONFIG (see OUT OF SCOPE) and record the call.

=== PHASE 2: FIX (staged, after plan approval) ===
  - Wire each WIRE row to its endpoint; build each BUILD endpoint (real computation) and wire it.
  - Known fixes: CategoryCoverage → real "coverage by category" endpoint (derive from the actual policy
    catalog mapped to risk categories and/or enforcement stats; document the math; no server-side
    hardcode). CLUSTERS/NS_BY_CLUSTER → live fleet-aware source (fleet-api clusters when fleet on, else
    the single real deployment; namespaces from the API), selector still works single-cluster when fleet
    OFF. FALLBACK_DEPLOYMENTS / INITIAL_CONNECTIONS → live lists. The 7 no-API pages → real endpoints
    (API keys, account from /me, general/connection/target settings persisted via API, RedTeam results
    from real runs, About version/build from an endpoint).
  - Every wired widget gets a real LOADING skeleton + real EMPTY state ("no data in range") + ERROR
    state. Empty must look empty — never fall back to invented values.

OUT OF SCOPE (legitimate CONFIG constants — DO NOT remove or "wire"; record as LEGIT-CONSTANT):
  enum/option constants (decision types allow/block/escalate/audit; filter type/risk enums), input
  PLACEHOLDER text, chart fallback COLORS, icon/nav lists (IconRail), table COLUMN definitions, display
  ORDERING arrays (SIGNAL_ORDER), TIER labels, preset tester QUICK_SCENARIOS, units/labels. If unsure,
  mark JUDGMENT and ask — do not guess.

NEW BACKEND ENDPOINTS follow CLAUDE.md gates:
  registry/{FEAT}.md + architecture .mmd; new NRVQ-* codes in docs/error-codes.md; namespace-scoped +
  RBAC consistent with existing reads; real computation, documented; no fabricated server defaults; unit
  tests (happy + empty + error). Never monkeypatch get_session.

=== PHASE 3: RUNTIME PROOF + INDEPENDENT RE-AUDIT (the miss-nothing gate) ===
  - Runtime route proof → .reviews/ui-cleanup/ROUTES.md: load ALL 18 routes (/, /policies/catalog,
    /policies/targets, /audit, /agents, /test, /asset-graph, /threats/graph, /threats/mitre,
    /settings/account, /settings/api-keys, /settings/general, /settings/connections, /settings/about,
    /fleet) against a live API; capture the network calls per route; ANY populated widget with no
    corresponding API request = fabricated → back to Phase 2. Record per-route: widgets ↔ API calls.
  - Independent re-audit: a SECOND pass (fresh subagent / security-auditor lens) re-greps and re-walks
    the full file list trying to find ANY fabricated datum the first pass missed; sign off in INVENTORY.
  - Final completeness proof: INVENTORY has a verdict for 100% of files, ZERO unresolved WIRE/BUILD
    rows, JUDGMENT rows all answered; the closing grep returns no fabricated-data literals.

GATES (after approval, per stage):
  - make lint + make test green (new endpoint tests included); tsc + vitest green; keep attacks 75/75.
  - helm unaffected; fleet stays OFF by default; single-cluster console works with the live selector.
  - Do NOT auto-commit; summarize per stage. Record this prompt + outcome in specs/prompts/ + index.
```
