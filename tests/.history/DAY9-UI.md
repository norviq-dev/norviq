<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Norviq Contributors -->

# DAY9-UI - Test History

**Last updated:** 2026-06-06
**Status:** active

## Tests Added

| Test Path | Type | Purpose | Date |
|---|---|---|---|
| tests/integration/test_graph_endpoints.py::test_api_is_running | integration | Fail loudly when local API is not reachable | 2026-06-06 |
| tests/integration/test_graph_endpoints.py::test_attack_paths_no_connection_leak | integration | Catch DB pool/session leaks on repeated graph calls | 2026-06-06 |
| tests/integration/test_graph_endpoints.py::test_asset_graph_no_connection_leak | integration | Catch pool/session leaks on asset graph calls | 2026-06-06 |
| ui/src/lib/d3-helpers.test.ts | unit | Validate edge color and time helpers used by graph rendering | 2026-06-06 |
| ui/src/pages/AssetGraph.test.tsx | UI integration | Verify loading/data/error state wiring for asset graph page | 2026-06-06 |
| ui/src/pages/AttackGraph.test.tsx | UI integration | Verify attack graph page data-flow rendering state | 2026-06-06 |

## Bugs Caught

| Bug ID | Date | Severity | Description | Caught By | Commit |
|---|---|---|---|---|---|
| D9-1 | 2026-06-06 | P1 | AsyncSession lifecycle leak exhausted DB pool after repeated graph requests | test_attack_paths_no_connection_leak | local-worktree |
| D9-2 | 2026-06-06 | P2 | Integration tests skipped silently when env vars missing, giving false-green runs | test_api_is_running + conftest defaults | local-worktree |
| D9-3 | 2026-06-06 | P2 | UI canvas fallback stubs shipped instead of D3 SVG rendering | visual QA + canvas replacement review | local-worktree |

## Files Touched

- norviq/api/routers/graphs.py - graph endpoint lifecycle/error handling
- norviq/api/db/session.py - async session dependency lifecycle
- tests/integration/conftest.py - integration fixture defaults
- tests/integration/test_graph_endpoints.py - API + leak regressions
- ui/src/components/asset-graph/*
- ui/src/components/attack-graph/*

## What MUST Continue Passing

- tests/integration/test_graph_endpoints.py
- tests/engine/graph/test_asset_graph.py
- tests/engine/graph/test_attack_graph.py
- ui `npm run test:run`
- ui `npm run build`

## Known Limitations / Workarounds

- Visual QA requires browser tooling/skill availability in local Cursor runtime.
- Integration tests depend on local API and DB services; fixture now emits explicit skip reason if unreachable.

## Performance Baselines

- target unit test runtime: <500ms per test
- target integration test runtime: <5s per test
