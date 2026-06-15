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

(fill in after execution: commit SHA, prod-build-clean evidence, dev-still-works, AKS URL wiring)
