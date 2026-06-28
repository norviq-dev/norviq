# Prompt — UI punch-list fixes + post-fix regression

**Date:** 2026-06-28
**Work item:** Fix all pending UI items found in `.reviews/ui-shots/results.json`, then run the
unit/integration regression.
**Commit:** (pending — Phase 1 run by user; regression in progress)
**Result:** Phase 1 handed off and run. Regression: 19/27 failures fixed (legitimate, no xfail/skip);
full backend 353 passed / 8 failed / 1 skipped; attacks 66/66 held; 13 new backend + 35 vitest green;
lint + tsc clean. 8 residual = stale/test-isolation debt (see EVAL spec "known-OK residual").

---

## Shared preamble (Phase 1)

```
You're working in the Norviq repo (norviq-migration/repo). This is F018-family UI work.
Source of truth for what's broken: the EXISTING .reviews/ui-shots/results.json (already captured).
Do NOT re-run the UI evaluation up front and do NOT re-baseline — treat that file as the punch list.
Workflow: 1) clean git tree. 2) implement ALL fixes (don't run ui-validate between fixes).
3) only after all fixes, run scripts/ui-validate.mjs ONCE, diff vs original. 4) run
./scripts/review-ui.sh, then stop — don't auto-commit. For any backend change, run the attack suite
and keep 66/66 green. Trust the final rerun, not the diff (P-7/P-16).
```

## Fixes (desired state per item)

1. **GET auth header** — `apiGet`/`apiGetWithSignal` (client.ts) send no Authorization; refactor a
   shared helper so all GETs send the `nrvq_token` bearer like `apiSend`. Fixes /agents 401.
2. **Favicon** — add `<link rel="icon" href="/norviq-mark.svg">` to index.html. Kills /favicon.ico 404.
3. **Policy Catalog target_type** — `GET /policies` returns `target_type` so the catalog groups the
   seeded policy (cascades to Monaco + Dry-Run reachable). *(Already applied via `_infer_target_type`.)*
4. **/deployments 404** — add thin derived endpoint or remove the call; no console 404.
5. **/ws/audit** — interim REST-poll fallback + reconnect in useWebSocket; full fix = `@app.websocket`
   route broadcasting audit events.
6. **Attack Graph Simulate** — make discoverable + wire onSimulate to a real backend evaluation
   (not the `blocked_by_policy` echo).
7. **MITRE Coverage** — real ATT&CK/ATLAS matrix from policies/mitre_mapping.json (R12; may defer).
8. **Settings Save / Logout** — Save persists (localStorage MVP) + confirmation; Logout clears
   nrvq_token + redirects.

## Phase 2 — regression (unit + integration)

```
Run after Phase 1. Read docs/engineering/test-baseline-discipline.md + tests/.history/_bug-catalog.md.
A) Add tests per fix (allow/block/error paths; assert rule_id not just decision; real code paths;
   never monkeypatch get_session — use app.dependency_overrides).
B) Full regression must pass: make lint && make test; attacks 66/66 (0 xfail/skip, run vs
   docker-compose.dev.yml); npm run test (vitest) + tsc.
C) Update tests/.history for F017 + F018 per _template.md.
ACCEPTANCE: lint/pytest/attacks/vitest/tsc green; .history updated; do not auto-commit.
```
