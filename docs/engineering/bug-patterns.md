<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Norviq Contributors -->

# Bug Patterns (Curated)

Lessons distilled from real Norviq incidents. **Read this before writing or reviewing code.**
The raw, append-only log lives in [`tests/.history/_bug-catalog.md`](../../tests/.history/_bug-catalog.md) —
add new raw entries there; promote durable lessons here.

Each pattern: what it looks like, the real case, and the guard that catches it.

---

## Async / session lifecycle (P-12, P-15, P-16) — the highest-cost family

These are silent: nothing errors loudly, state just stops moving or the pool dies.

> **This bug recurred (P-15 → P-16) because we fixed instances, not the class.**
> The async-generator session bug was patched in `dry_run` + `GraphStore`, but the *same*
> `await get_session()` survived in `audit.py` (×5), `health.py`, and `audit_emitter.py` — breaking
> Dashboard/Audit Log (500) and silently dropping every audit write on AKS. **Two rules, always:**
> 1. **Fix the CLASS, not the instance** — `grep -rn "await get_session()" norviq/` and fix *every*
>    hit in one pass. Re-grep before claiming "closed."
> 2. **NEVER monkeypatch `get_session` in tests** — `Depends(get_session)` captures the original at
>    route-definition time, so the monkeypatch is a no-op that *masks* the real lifecycle. Use
>    `app.dependency_overrides[get_session]` (routes) or the `_acquire_session` drive (non-route).
>    Back it with an **integration test against the real ASGI app** (fail-before / pass-after).

- **P-12 — DB pool exhaustion via leaked sessions.** After ~15 requests, endpoints 500 with
  `QueuePool TimeoutError`. Cause: a session opened per request but never returned to the pool.
- **P-15 — Session-factory shape mismatch.** `GraphStore` expected an *awaitable* session factory
  but the app passed an *async-generator* dependency, so every persist silently failed
  (`NRVQ-GRP-11001: async_generator object can't be awaited`). The `asset_graph` table froze at
  the first snapshot while tool calls kept flowing.
- **P-16 — `await get_session()` in route handlers + engine code.** `get_session` is a FastAPI
  async-generator dependency; `await get_session()` raises
  `TypeError: object async_generator can't be used in 'await' expression`. In a **route**, fix with
  `session: AsyncSession = Depends(get_session)` (FastAPI manages the generator). In **non-route
  code**, drive the generator via `_acquire_session` and `aclose()` in `finally`.

**The `_acquire_session` pattern — use everywhere a background/non-request path needs a DB session:**

```python
async def _acquire_session(self):
    """Yield a session that works whether the factory is a context manager,
    an awaitable, or an async-generator dependency."""
    factory = self._session_factory
    if hasattr(factory, "__aenter__"):            # async context manager
        async with factory() as session:
            yield session
    else:
        gen = factory()
        if hasattr(gen, "__anext__"):             # async generator (FastAPI dep)
            session = await gen.__anext__()
            try:
                yield session
            finally:
                await gen.aclose()
        else:                                     # awaitable factory
            yield await gen
```

**Guards:**
- Hit any persisting endpoint 30× in a loop; assert all return 200 (catches P-12).
- After a *distinct* `evaluate` call, assert the persisted row count **increased** (catches P-15).
- Integration test against the **real ASGI app** (httpx → live API) for every DB-backed endpoint —
  `tests/integration/test_audit_endpoints.py` asserts `/audit/*` + `/readyz` return 200, and would
  have caught P-16 (it fails-before / passes-after). Monkeypatched unit tests cannot catch this.
- Never `await` a factory whose type you haven't pinned. Reproduce the prod wiring in the test —
  do not hand the store a bare `async with session()` when the app injects a generator.

---

## Silent failure & green-but-verifies-nothing (P-6, P-7, P-7-ext, P-11)

- **P-6 — Default values that look like real decisions.** `decision="allow"` as a "safe default"
  is indistinguishable from a real evaluation. **Fix:** decisions carry provenance —
  `rule_id="default_allow"` vs `rule_id="evaluator_timeout"` vs `rule_id="opa_error"`. Assert on
  `rule_id`, never just `decision`.
- **P-7 — Test infra that masks bugs.** `pytest.xfail()` on connection errors turns a dead API into
  "expected failure". A connection error must go **red**, not orange. `xfail` is only for a known,
  unfixed bug with a written reason + date.
- **P-7-ext / P-11 — Silent skips on missing env.** Tests that skip when `NRVQ_API_URL` /
  `NRVQ_API_TOKEN` are absent look green and verify nothing (Day 9 graph endpoints). Fixtures must
  auto-default to local dev, and any skip reason must be visible.

**Guard:** for every function whose comment says "MVP", "placeholder", "fallback", or "simplified",
write a test that proves the *real* path runs (see P-1, P-13).

---

## Schema / query mismatch (P-4, P-8, P-10)

- **P-4 — Memory vs persistent state.** API wrote policies to an in-memory dict and never to
  Postgres; the engine had its own dict and never saw them. **Guard:** after a write, query the
  persistent store directly and assert presence.
- **P-8 — Wrong subprocess query path.** The evaluator queried `data` (whole OPA tree) instead of
  `data.norviq.strict`, getting a dict of every rule instead of the decision object. **Always
  `psql \d <table>` / inspect the real shape before trusting a query.** Assert specific keys/paths
  in subprocess output.
- **P-10 — Deploy mismatch.** A fix "deployed" but the pod served an old image, or a migration
  didn't run (missing `priority` column). **Guard:** after deploy, assert the pod image SHA matches
  HEAD (see [aks-operations.md](aks-operations.md) and [test-baseline-discipline.md](test-baseline-discipline.md)).

---

## Codegen stubs (P-1, P-13)

Cursor (or any codegen) tends to emit a plausible stub and leave the real logic unreachable.

- **P-1 — Hardcoded fallback disguised as MVP.** `_evaluate_opa` once returned
  `{"decision": "allow"}` regardless of Rego; the real OPA call sat below, never executed.
- **P-2 — Regex shortcut bypassing downstream logic.** `_evaluate_single` regex-matched
  `default decision = "allow"` and returned without ever invoking OPA.
- **P-13 — UI fallback stubs.** "fallback renderer" with HTML `<div>`s instead of real D3 SVG.

**Detection:** `grep -rn "fallback\|simplified\|placeholder\|MVP"` over changed files. For each hit,
demand a test that the production path executes (OPA subprocess actually spawned; SVG element with
d3 children actually rendered).

---

## OPA / subprocess specifics (P-3, P-9)

- **P-3 — Sub-second timeouts on subprocess.** `asyncio.wait_for(timeout=0.1)` around the OPA
  process; cold start alone is ~150ms. Measure cold-start latency, set timeout to >2× worst case
  (current evaluator uses 2.0s), and keep a timeout-fail-closed test.
- **P-9 — Tool version incompatibility.** Rego v0 syntax under OPA 1.17 (defaults to v1) needs the
  `--v0-compatible` flag. Pin the tool version, test against the installed one, document required
  flags in a code comment next to the `opa eval` call.

---

## Dynamic OPA query resolution

The evaluator derives the OPA query from the policy's `package` header
(`_extract_package_name` → `_opa_query_for_package` → `data.<package>`), not a hardcoded path.
If a policy declares `package norviq.strict`, the query is `data.norviq.strict`. A mismatch between
the package line and the query yields an empty/!=expected result that *looks* like "no decision".
When adding a policy, confirm the package header and the resolved query agree (turn on
`DEBUG_OPA=true` and read the `nrvq.opa.query.resolved` log).

---

## Input field-path verification — `agent.namespace`, NOT `agent_identity.namespace`

OPA Rego over an undefined path doesn't error — the rule body just silently fails, so a
mistyped path becomes a **dead rule** that always "passes" (allows). The cross-tenant rule in
`comprehensive.rego` read `input.agent_identity.namespace`, but the evaluator emits namespace at
`input.agent.namespace` (see `OPAEvaluator._build_input`). Result: cross-tenant blocking never
fired, yet every test "passed".

**Rule:** before writing any Rego that reads `input.*`, verify the exact path against
`_build_input` and the live `nrvq.opa.input` debug log. The full, authoritative schema is in
[opa-input-schema.md](opa-input-schema.md). Add a positive **and** a negative test for every
field-path rule (mismatch blocks; match allows).

---

## AKS startup race (P-14)

Pods report Ready before their dependencies (Postgres/Redis/migrations) are actually serving, so
the first requests after a roll fail or evaluate against an unmigrated schema. Until the startup
ordering fix lands (Day 14 — see [aks-operations.md](aks-operations.md)), the recovery is an
ordered bring-up: Postgres → Redis → API → engine. **Guard:** gate readiness on a real dependency
probe (migration head applied, Redis `PING`), not just process-up; verify cluster health before
measuring any baseline.
