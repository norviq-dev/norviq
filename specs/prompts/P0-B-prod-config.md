# P0-B — UI production configuration

**Date:** 2026-06-15
**Work item:** P0-B (from UI production-readiness gap analysis)
**Goal:** Make the UI deployable to a real environment — introduce VITE_API_BASE_URL,
          .env.production, gate the dev token to DEV-only so it never reaches the prod
          build, and stop hardcoding localhost / default cluster.

## Prompt

P0-B: production configuration. The UI can't target a real backend cleanly —
hardcoded localhost, no API base URL env, no .env.production, dev token leaks into
build, cluster defaults hardcoded. Fix so the UI is deployable to a real environment.

STEP 1 — Inventory the config problems (verify): grep localhost/127.0.0.1/VITE_DEV_TOKEN/
production-aks in ui/src; read vite.config, .env files; trace how API base URL resolves.
STEP 2 — Introduce VITE_API_BASE_URL; centralize base URL in one place (not scattered fetch).
STEP 3 — Create .env.production; gate dev-token auto-injection to import.meta.env.DEV only;
don't hardcode default cluster.
STEP 4 — Verify prod build clean (grep dist/ finds NO dev token / localhost); dev still works.
STEP 5 — Wire build/deploy to set prod API URL. Browser (not pod) calls the API, so base URL
must be browser-reachable (ingress/external), not the in-cluster service name. Verify AKS
networking before hardcoding.

RULES:
- Dev token must NEVER reach the production build (gate to import.meta.env.DEV)
- Browser calls the API — base URL must be browser-reachable (ingress/external)
- Don't break dev workflow (proxy or VITE_API_BASE_URL=localhost must still work)
- Save prompt to specs/prompts/, update README index
- Do NOT commit until I review

## Outcome

**Commit:** `7a24b56` — `fix(P0-B): production configuration for UI deployability`
**CI:** Build & Push ✅, Deploy to AKS ✅
**Date completed:** 2026-06-15

**Done:**
- `VITE_API_BASE_URL` env, centralized in `client.ts` (`apiUrl`/`wsUrl`); all HTTP + WS routes
  through it. Default `""` = relative = same-origin (vite proxy in dev, UI nginx in prod).
- `.env.production` (committable, no secrets); `VITE_ENV_LABEL`-driven default cluster (removed the
  hardcoded `production-aks` fallback); typed env vars; updated `.env.local.example`.
- nginx `/ws` upgrade-proxy location added; gitignored `ui/tsconfig.tsbuildinfo`.

**Verified (prod image on AKS, via `svc/norviq-ui` nginx — the browser's same-origin path):**
- UI served (200, "Norviq Security Console").
- Same-origin `/api/v1/audit/stats` → 200, `/healthz` → 200 (nginx → norviq-api in-cluster; no
  in-cluster name exposed to the browser; no API ingress needed).
- Namespace scoping through prod nginx: policies default=1 / nonexistent=0 (P0-D holds end-to-end).
- Prod build clean: dev JWT secret absent, `change-me-in-production` absent, 23 relative `/api`
  paths (no absolute origin baked); 16/16 UI tests pass; dev workflow unchanged.

**Correction / finding:** the commit message's "Audit Log WebSocket now works in prod" is
**optimistic**. Verification (real `websockets` client through nginx) showed `/ws/audit` returns
**404 — the API has no WebSocket route at all**, so the live feed never worked in dev or prod. The
nginx `/ws` proxy is correct (and necessary for prod parity) but has no upstream route yet. The
audit table works via REST regardless. Tracked as a **P1 in `docs/backlog.md`** (implement
`/ws/audit` on the API, or remove the live toggle).

**AKS URL wiring:** standard deploy needs no baked API URL — browser → UI origin → nginx `/api`,`/ws`
→ `norviq-api`. `VITE_API_BASE_URL` is the split-origin (separate API ingress + CORS) opt-in.

**Visual-only checks not run** (no browser in this env): D3 graph render + F12 console cleanliness.
The underlying data paths (same-origin `/api`, namespace scoping) are confirmed via curl.
