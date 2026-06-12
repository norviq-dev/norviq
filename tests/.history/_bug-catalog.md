<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Norviq Contributors -->

# Norviq Bug Catalog

Patterns of bugs we've hit. Cursor reads this before making changes. Humans add new entries.

## P-1: Hardcoded fallbacks disguised as MVP stubs
Symptom: Function says "MVP placeholder" in comment, returns hardcoded values, real logic exists below but never executes.
Real example: F009 _evaluate_opa returned {"decision": "allow"} regardless of Rego.
Test pattern: For every function that has "MVP" or "placeholder" in comments, write a test that proves real logic runs.

## P-2: Regex shortcuts that bypass downstream logic
Symptom: Code uses regex to extract a value from a string, returns early, skipping the function that should process that string.
Real example: F009 _evaluate_single regex-matched `default decision = "allow"` in Rego and returned "allow" without running OPA.
Test pattern: Test that the downstream function (OPA subprocess) is called for inputs that should reach it.

## P-3: Sub-second timeouts on subprocess calls
Symptom: asyncio.wait_for(timeout=0.1) on something that spawns a process. Process startup alone often exceeds 100ms.
Real example: F009 had timeout=0.1 on OPA subprocess that takes ~150ms cold.
Test pattern: Measure subprocess cold start latency. Set timeout to >2x measured worst case. Add timeout-fail-closed test.

## P-4: Memory state vs persistent state mismatches
Symptom: Pod A stores data in its in-memory dict. Pod B has a separate in-memory dict and doesn't see it.
Real example: F010 policy_loader: API stored policies in memory dict, never wrote to PostgreSQL, engine had separate dict.
Test pattern: After write operation, query persistent store directly and assert presence.

## P-5: Cache TTLs that hide real behavior
Symptom: Tests pass once, fail later because cache served stale results. Or tests fail because cache served stale "allow" decisions.
Real example: F009 eval cache (60s TTL) served cached "allow" from before policy was loaded.
Test pattern: Flush cache in test setup. Add cache-hit and cache-miss test variants.

## P-6: Default values that look like real decisions
Symptom: Function returns `decision="allow"` as a "safe default" - looks identical to a real evaluation result.
Real example: All Day 8 failures looked like "policy allows this attack" when really "evaluator never ran".
Test pattern: Decisions should carry provenance, e.g. rule_id="default_allow" vs rule_id="opa_timeout".

## P-7: Test infrastructure that masks bugs
Symptom: conftest.py uses pytest.xfail() for connection errors, hiding real bugs as "expected failures".
Real example: Day 8 tests showed "64 xfailed" instead of failing loudly because API was unreachable.
Test pattern: Connection errors should error (red), not xfail (orange). xfail only for known unfixed bugs with reason+date.

## P-8: Wrong subprocess query paths
Symptom: Subprocess call works but returns wrong data because query path is too broad or too narrow.
Real example: F009 queried `data` (entire OPA data tree) when it should have queried `data.norviq.strict`.
Test pattern: Subprocess integration tests assert specific output paths/keys present in result.

## P-9: Tool version incompatibilities
Symptom: Tool installed but new version has different syntax. Old code/configs silently fail.
Real example: F009 used Rego v0 syntax, OPA 1.17 defaulted to v1, required --v0-compatible flag.
Test pattern: Pin tool versions. Test against installed version. Document required flags in code comments.

## P-10: Deploy mismatches
Symptom: Code changes don't apply because pod is running old image, migration didn't run, or env var wasn't set.
Real example: Day 8 fix deployed but pod cached old image. Schema missing priority column.
Test pattern: After deploy, query pod image SHA and assert it matches expected commit.

## P-11: Destructive-pattern false positives
Symptom: Broad grep checks for destructive SQL (e.g., `DROP TABLE`) fail because attack payload fixtures intentionally include those strings.
Real example: Safety check scanned all `norviq/` and matched red-team attack payloads instead of schema or migration code.
Test pattern: Scope destructive-pattern searches to migration/schema paths only:
- `norviq/api/db/`
- `norviq/engine/policy_loader.py`
- `alembic/`
Skip:
- `norviq/redteam/`
- `norviq/sdk/attacks/`
- `tests/`

## P-7 (extended): Silent skips on missing env
Same root issue as xfail markers. Skip without reason = green test that verifies nothing.

Rule: skip reason MUST be visible. Either auto-default to local dev, or report skip with explicit message.

Real example: Day 9 graph endpoint tests skipped silently because NRVQ_API_URL/NRVQ_API_TOKEN missing from shell. Looked green, verified nothing.

## P-11: Silent test skips on missing env vars
Symptom: Tests skip with no reason when env vars missing.
Looks green, verifies nothing.
Real example: Day 9 graph endpoint tests.
Test pattern: Fixtures auto-default to local dev. Skip reasons visible.

## P-12: DB connection pool exhaustion via leaked sessions
Symptom: After ~15 requests, endpoints 500 with QueuePool TimeoutError.
Real example: Day 9 attack-paths endpoint.
Test pattern: Hit endpoint 30x in loop, assert all return 200.

## P-13: Cursor implements UI fallback stubs instead of real D3
Symptom: UI labeled "fallback renderer" with HTML divs instead of SVG.
Real example: Day 9 AssetGraphCanvas, AttackGraphCanvas.
Detection: grep for "fallback" or "simplified" in UI component code.
Test pattern: Visual verification — SVG element must exist with d3 children.

## P-15: GraphStore session lifecycle mismatch (silent persistence failure)
Symptom: asset_graph table stuck at first snapshot, never grows despite many tool calls.
Root cause: GraphStore expected awaitable session factory, app passed async generator dependency.
Detection: NRVQ-GRP-11001 "async_generator object can't be awaited" in API logs.
Test pattern: After distinct evaluate call, asset_graph node count must increase.
Class: same family as P-12 (DB pool leak) — async session handling.