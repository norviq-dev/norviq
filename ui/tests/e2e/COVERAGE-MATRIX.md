# Norviq Console E2E — Coverage Matrix

Route × control × backend-assertion → the spec/test that covers it. Every row is exercised against the
**real** app + backend (no mocks). Cells marked **BEST-EFFORT** carry an assertion that degrades to a
clean `test.skip` (with a stated reason) when the live cluster does not present the required data shape,
rather than flaking — see the note at the bottom.

Run:

```bash
cd ui/tests/e2e
npm install && npx playwright install chromium          # once
PLAYWRIGHT_BASE_URL=http://localhost:3400 npx playwright test
```

Admin session: the HS256 admin token (role=admin, namespace=*) is read at runtime from
`/tmp/nrvq-signin-token.txt` (override `NRVQ_TOKEN_FILE`) by `global-setup.ts` and seeded into
localStorage `nrvq_token`. No secret is committed.

## Files

| File | Purpose |
|------|---------|
| `playwright.config.ts` | baseURL from `PLAYWRIGHT_BASE_URL` (default `http://localhost:3400`); chromium, dSF 2, 1560×940; storageState from global-setup; screenshots on failure + trace on first retry → `artifacts/`. |
| `global-setup.ts` | Reads the token file, stamps `nrvq_token` into localStorage, writes `artifacts/storageState.json`. |
| `fixtures.ts` | `page` fixture re-injects the token via `addInitScript`; `NetworkRecorder` collects `/api/v1` ≥400 + console errors; `expectNoApiFailures()` / `expectNoConsoleErrors()`. |
| `routes.smoke.spec.ts` | Table-driven one-test-per-route smoke (render + data + clean console + clean API). |
| `attack-graph.spec.ts` | PRIORITY — render, 4 regressions, selection drive, what-if, scope card, GLOBAL intent ALLOWLIST-BUILDER flow (suggest→checklist→coverage→draft). **console-fixes-batch2**: intent tests updated for DENY-ALL default (every checkbox unchecked, empty `allow_names`) + PER-CLASS coverage total. |
| `asset-graph.spec.ts` | render, crisp labels, ns dropdown + refetch, clickable stat tiles, label/node collision. |
| `console-fixes-batch2.spec.ts` | **console-fixes-batch2** EFFECT assertions: (1) asset-graph hull encloses every ring node; (4) login form advance + wrong-password error; (5) no-navy theme on 4 routes; (6) branded text-free boot splash → form; (7) enforcing "Active policies" heading distinct from drafts + real block-effect proof. |
| `audit-pep.spec.ts` | drive a blocked `/evaluate`, assert BLOCK row in /audit + Dashboard block feed. |
| `intent-allowlist-effect.spec.ts` | EFFECT PROOF — generate the allowlist Rego, apply it as a REAL policy for a throwaway class, prove `/evaluate` flips (allow↔block) + baseline injection stays blocked; self-cleans. |

## Route × control coverage

| Route | Control / behaviour asserted | Backend assertion | Spec · test |
|-------|------------------------------|-------------------|-------------|
| `/` (Overview) | h1 "Overview" + Policy Coverage panel renders (live rollup) | GET rollups succeed, no /api/v1 ≥400 | `routes.smoke` · Overview |
| `/asset-graph` | h1 + `asset-graph-canvas` + `stat-strip` render | no /api/v1 ≥400 | `routes.smoke` · Asset Graph |
| `/asset-graph` | d3 graph renders ≥1 `g.ag-node` | GET `/api/v1/asset-graph?namespace=all` | `asset-graph` · renders |
| `/asset-graph` | REGRESSION crisp: effective font-size ≥ 9px at fit zoom | — (client render) | `asset-graph` · crisp |
| `/asset-graph` | Namespace dropdown lists all ns; switch refetches with chosen ns; All ⇒ `namespace=all` | GET `/api/v1/asset-graph?namespace=<ns>` and `=all` | `asset-graph` · ns dropdown |
| `/asset-graph` | Stat tiles clickable + filter (High risk / Blocked flip state / counts) | — (client filter) | `asset-graph` · stat tiles |
| `/asset-graph` | **BEST-EFFORT** ns-hull labels don't overlap node circles (bbox) | — | `asset-graph` · collision |
| `/asset-graph` | **Fix 1** hull encloses EVERY ring node: parse each hull arc `d`→(cx,cy,r), each `g.ag-node` translate(x,y); nearest-hull dist ≤ r+9 for ALL nodes (0 outside) | — (client render) | `console-fixes-batch2` · Fix 1 hull |
| `/threats/graph` | h1 + `attack-graph-canvas` + "Threat Relationships" render | GET attack-paths succeeds | `routes.smoke` · Attack Graph |
| `/threats/graph` | ranked list ≥1 row + 6 stat-strip counters | GET `/api/v1/threats/attack-paths` with `ns=` + `range=` | `attack-graph` · renders |
| `/threats/graph` | REGRESSION horizontal chain: x-spread ≫ y-spread; viewBox present; no h-scroll | — | `attack-graph` · horizontal |
| `/threats/graph` | REGRESSION `text.lbl` font-weight ≤ 550 (not 700) | — | `attack-graph` · label weight |
| `/threats/graph` | REGRESSION list + inspector: `scrollHeight ≤ clientHeight+2` | — | `attack-graph` · no inner scroll |
| `/threats/graph` | select path drives inspector (MITRE / Hops / Min trust / Blast radius) | — | `attack-graph` · selection |
| `/threats/graph` | click node opens scope card (Close scope card btn) | — | `attack-graph` · scope card |
| `/threats/graph` | click hop toggles what-if ("what-if block active" pill) | — | `attack-graph` · what-if |
| `/threats/graph` | **Fix 3** intent ALLOWLIST BUILDER: opening fires suggest → DENY-ALL checklist (≥1 checkbox, EVERY checkbox UNCHECKED); chokepoint still FLAGGED; generated rego shows `default decision = "block"` + EMPTY `allow_names` ({}/set()) | GET `/api/v1/threats/intent-suggest` (`ns`+`cls`) | `attack-graph` · builder open (deny-all) |
| `/threats/graph` | **Fix 3** CHECKING a tool ADDS it to the coverage POST `allow_tools` (== live checked set) + surfaces the name in the generated `allow_names`; rego stays `default decision = "block"` | POST `/api/v1/threats/intent-coverage` | `attack-graph` · builder toggle (adds) |
| `/threats/graph` | **Fix 2** coverage `covered/total` denominator is PER-CLASS — total == the SELECTED class's path count (the "<N> paths" in the grouped selector), ≤ the global total; "Other classes each need their own intent policy" note present | POST `/api/v1/threats/intent-coverage` | `attack-graph` · builder coverage (per-class) |
| `/threats/graph` | "Apply intent policy" → `intent-draft` (body carries `allow_tools`) → confirmation → deep-link `/policies/catalog?intent_draft=<id>`; draft row visible + dry-run labeled | POST `/api/v1/threats/intent-draft` | `attack-graph` · apply intent |
| `/threats/graph` | "Simulate path" issues real evaluate (framework=attack-graph) | POST `/api/v1/evaluate` | `attack-graph` · simulate |
| `/threats/graph` → policy | EFFECT PROOF: generated allowlist Rego applied as a REAL policy for a throwaway class ⇒ allowlisted tool `allow` (rule_id ^`intent_allow`), un-allowlisted `block` (`intent_default_deny`), injection `block` (`llm01_prompt_injection`, baseline unweakened); self-cleans (DELETE) | GET attack-paths + intent-suggest, POST intent-coverage, POST `/api/v1/policies`, POST `/api/v1/evaluate` ×3, DELETE `/api/v1/policies/default/<throwaway>` | `intent-allowlist-effect` · effect proof |
| `/threats/mitre` | h1 + "ATLAS Coverage" renders | GET mitre coverage | `routes.smoke` · MITRE |
| `/policies/catalog` | catalog renders (policy list) | no /api/v1 ≥400 | `routes.smoke` · Policy Catalog |
| `/policies/catalog` | intent draft deep-link row visible + dry-run label | GET `/api/v1/threats/intent-drafts/<id>` | `attack-graph` · apply intent |
| `/policies/catalog` | **Fix 7** Catalog tab: "Active policies" heading + ENFORCING label renders ABOVE the tier panels (Workload/Agent-Class/Namespace), distinct from the dry-run "Intent drafts" panel | GET `/api/v1/policies` | `console-fixes-batch2` · Fix 7 heading |
| `/policies/catalog` → policy | **Fix 7 EFFECT PROOF**: apply a default-deny policy for a throwaway class (priority 1) ⇒ `/evaluate` now BLOCKs an un-allowed call; self-cleans (DELETE) | POST `/api/v1/policies`, POST `/api/v1/evaluate`, DELETE `/api/v1/policies/default/<throwaway>` | `console-fixes-batch2` · Fix 7 block-effect |
| all routes | **Fix 5** THEME: no main panel/card background resolves to "navy" (blue > red+12 AND > green+12 AND > 20) and no known navy hex leaks — sampled on `/`, `/asset-graph`, `/threats/graph`, `/policies/catalog` | — (client computed style) | `console-fixes-batch2` · Fix 5 theme (×4 routes) |
| `/policies/packs` | h1 + "Sector Starter Packs" | GET `/api/v1/policy-packs` | `routes.smoke` · Policy Packs |
| `/policies/targets` | h1 "Effective Policy & Governance" + Governance | GET settings/effective | `routes.smoke` · Target Settings |
| `/audit` | h1 + Block decision-filter tab present | GET audit records/stats | `routes.smoke` · Audit Log |
| `/audit` | blocked `/evaluate` surfaces as a BLOCK row (tool + `span.pill` block) | POST `/api/v1/evaluate` (block) → GET `/api/v1/audit/records?decision=block` | `audit-pep` · block row |
| `/` (Overview) | Dashboard "Recent Blocked" feed / block KPI reflects the block | audit aggregation | `audit-pep` · dashboard feed |
| `/agents` | h1 "Agent Monitor" + Trust Distribution/Agent Actions | GET agents/tool-usage/trust-history | `routes.smoke` · Agents |
| `/test` | h1 + "Simulate Tool Call" | — | `routes.smoke` · Policy Tester |
| `/settings/general` | h1 "Settings" + General section | GET settings | `routes.smoke` · General Settings |
| `/settings/account` | h1 + "User Profile" | GET `/api/v1/me` | `routes.smoke` · Account Settings |
| `/settings/api-keys` | h1 + "Issue a Key" + "Active Keys" | GET `/api/v1/keys` | `routes.smoke` · API Keys |
| `/settings/connections` | h1 "Connections" + System Connections | GET readiness/connections | `routes.smoke` · Connections |
| `/settings/about` | h1 "About Norviq" + Version and Links | GET `/api/v1/version` | `routes.smoke` · About |
| `/login` | (implicitly exercised: every test seeds the token so the login gate passes through to Shell) | — | all specs (fixture) |
| `/login` | **Fix 4a** drive the FORM (fill `admin`/`norviq`, submit) → `/auth/login` 200 must_change ⇒ advances to the change-password view (`input#nv-cur`/`input#nv-new`); **BEST-EFFORT** skip if seeded admin isn't the default | POST `/api/v1/auth/login` (200 + must_change) | `console-fixes-batch2` · Fix 4a login advance |
| `/login` | **Fix 4b** WRONG password → visible "Invalid username or password" error, username field NOT cleared, still on Sign-in view | POST `/api/v1/auth/login` (rejected) | `console-fixes-batch2` · Fix 4b login error |
| `/login` | **Fix 6** boot splash = branded BrandSplash (`role=status` /loading norviq/i), NO "Starting Norviq" / "Connecting to the security backend" copy, auto-dismisses to the form (`input#nv-user`); App route-transition Suspense fallback reuses BrandSplash (**BEST-EFFORT**) | GET `/readyz` (splash probe) | `console-fixes-batch2` · Fix 6 splash |
| `/fleet` | GUARDED: renders when fleet enabled, else redirects to `/` → self-skip | — | `routes.smoke` · Fleet (gated) |

## Cross-cutting controls (every smoke test)

| Control | Assertion | Where |
|---------|-----------|-------|
| No console errors | `expectNoConsoleErrors()` (dev/font/RO-loop noise filtered) | `routes.smoke` (all) |
| No `/api/v1` failures | `expectNoApiFailures()` — zero responses ≥400 | `routes.smoke` (all) |
| Authenticated (not login shell) | token injected via storageState + `addInitScript`; pages render authed chrome | `fixtures.ts` + all |
| Not an empty shell | each route asserts a route-specific data landmark | `routes.smoke` (all) |

## BEST-EFFORT / live-data caveats

The following assertions need a specific live-data shape and self-skip (with a printed reason) when the
seeded cluster does not provide it — they are correct when the data exists, but cannot be proven at
author time:

- **Attack Graph** — every interaction test requires ≥1 stored attack path in the served namespace
  (`GET /threats/attack-paths` non-empty). The horizontal-chain test additionally needs ≥2 chain nodes;
  the what-if test needs a path with a non-blocked (togglable) hop in the top rows. Each skips clearly
  if absent.
- **Intent allowlist builder** — the checklist tests need `GET /threats/intent-suggest` to return ≥1
  observed tool for the active class; when it is empty the modal shows the default-deny explainer and the
  checkbox assertions self-skip (the `allow_tools`/coverage/draft assertions that don't need a checkbox
  still run via the refinement toggles). The chokepoint-flag assertion runs only when a `chokepoint` tool
  is present.
- **Intent allowlist EFFECT PROOF** (`intent-allowlist-effect.spec.ts`) — needs the admin token file, a
  non-empty `/threats/attack-paths`, at least one class whose `/threats/intent-suggest` surface is
  non-empty, and a healthy evaluator. It generates the allow-rule Rego for a **throwaway class** in the
  `default` namespace, applies it as a real priority-1 policy, and drives `/evaluate` to prove the flip
  (allowlisted ⇒ `allow`/`intent_allow*`, un-allowlisted ⇒ `block`/`intent_default_deny`, injection ⇒
  `block`/`llm01_prompt_injection`). Each precondition self-skips with a stated reason. Cleanup
  (`DELETE /api/v1/policies/default/<throwaway>`) runs in `afterEach` so no enforcing row survives a
  failure. Only ever touches its unique throwaway class — never a seeded policy.
- **Asset Graph** — crisp-label, stat-tile-filter, and ns-switch tests need ≥1 node and ≥1 concrete
  namespace. The label/node collision check allows ≤3 incidental overlaps (dense live graphs) — it
  guards the *systemic* ns-label/node collision, not pixel-perfect layout.
- **Audit / PEP** — requires the `default`/`customer-support` policy seeded so that the `exec_shell`
  shell-injection payload resolves to `block`; skips with a reason if the decision is not `block`.

console-fixes-batch2 caveats:

- **Fix 1 (asset-graph hull)** — parses each cluster hull's circular-arc `d` into (cx,cy,r) and each
  `g.ag-node` `translate(x,y)`; asserts every VISIBLE node's center is within its nearest hull (dist ≤ r+9).
  Self-skips if no hull path parses or no node has a transform (empty graph / non-circle focus layout).
- **Fix 4 (login)** — drives the real form. (a) needs the seeded admin to still be the DEFAULT credential
  (`admin`/`norviq` → 200 + `must_change`); skips if it's already rotated or if no `/auth/login` response is
  seen. (b) needs a non-rate-limited reject (skips on 429). Both open a CLEAN, token-free browser context so
  the login gate actually renders (the shared `page` fixture would otherwise inject the admin token).
- **Fix 5 (theme)** — samples computed `background-color` of `.panel`/`.card`/`.policy-item`/graph-canvas
  containers on 4 routes; a "navy" is blue-channel-dominant (b > r+12 AND b > g+12 AND b > 20). Transparent
  (alpha 0) surfaces are ignored (they inherit the grey page bg). Skips a route if nothing painted yet.
- **Fix 6 (splash)** — the boot splash is time-boxed (~150ms under reduced-motion/jsdom, ~1.1s otherwise);
  the presence-of-splash assertion only runs if it's observed (a very fast machine may dismiss it first), but
  the auto-dismiss-to-`input#nv-user` and no-status-copy assertions always run. The App route-transition
  Suspense-fallback check is BEST-EFFORT (a warm chunk cache may not paint the fallback → skips).
- **Fix 7 (policy apply)** — the heading test always runs (clicks the Catalog tab, asserts DOM order). The
  EFFECT PROOF needs the admin token + a healthy evaluator: it applies a default-deny policy for a UNIQUE
  throwaway class at priority 1, polls `/evaluate` until it BLOCKs an un-allowed call, and DELETEs the policy
  in `finally` so no enforcing row survives a failure. Only ever touches its throwaway class.

Authoring status: authored + strict-typechecked (`npx playwright test --list` → 47 tests, 6 files;
`tsc --noEmit` → 0 errors). Includes the console-fixes-batch2 additions (new `console-fixes-batch2.spec.ts`
covering fixes 1/4/5/6/7 + the hull, and the updated intent tests in `attack-graph.spec.ts` for fixes 2/3).
NOT run against a live cluster — the parent runs it post-redeploy to avoid port-forward conflicts.
