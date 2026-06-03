
## F027 — deferred 2026-06-01


## F027 — deferred 2026-06-01

- ⚠️ **`_categorize()` does NOT map computed `score==0.0` → `"frozen"`** (`:126-130`). `frozen` is reachable **only** via the admin `agent_frozen:` flag; a computed all-zero score maps to `"low"`. This is a **deliberate, documented** design choice (test `test_no_auto_freeze_when_signals_are_zero`, registry §12) and is arguably safer than auto-freezing, but it **contradicts the `TrustResult` docstring** (`"frozen" (0.0)`) and the review checklist's "frozen = 0" expectation. See HIGH-2.

### 4. INTEGRATION WITH EVALUATOR — PASS
--
- ⚠️ **HIGH-3: profile TTL is `WINDOW_SECONDS = 86400` (1 day), not the spec's "7-day rolling baseline"** (`profile.py:70`). Inactive agents lose their profile after 24h vs. 7 days. Also the entropy "baseline" is a cumulative Welford mean/variance over *all* calls (not a 7-day window) and rpm is an EWMA — neither is actually a "rolling 7-day" computation.

### 6. PERFORMANCE — PASS with notes
--
| Redis down → graceful | PARTIAL — `_safe_*` swallow errors and return `[]`/`{}` → signals default **HIGH** (fail-open for trust). `_is_manually_frozen` returns `False` on error (frozen agent un-frozen). Net evaluate still fails closed, but trust itself fails open. See HIGH-4. |
| Malformed history entry | PASS — `get_history` skips bad JSON (`history.py:36-40`); signals use `.get()` |

--
- ⚠️ **HIGH-1 (baseline poisoning / "boiling-frog"):** entropy mean/std and `baseline_rpm` are learned **from the agent's own allowed calls** (`evaluator._safe_update_profile:208-217`). A patient compromised agent can slowly inflate its entropy baseline and rpm via benign-looking allowed calls, desensitizing `param_entropy` and `session_velocity` before an attack. `known_tools` also grows monotonically, defeating `tool_novelty` for tools introduced while trust was high. Inherent to behavioral baselining, but should be acknowledged/mitigated (e.g., cap baseline growth rate, class-level rather than agent-level baselines).
- ⚠️ **MEDIUM (no RBAC on freeze/reset):** `PUT /agents/{id}/trust` (`agents.py:70-83`) only requires `get_current_user`, no admin-role check. Review explicitly asks "low-trust agent reset-trust on itself → should be admin-only." There is no role gate.

--
- **HIGH-1 — Baseline self-poisoning:** entropy/rpm/known-tools baselines are learned from the agent's own allowed calls; a patient compromised agent can desensitize `param_entropy`, `session_velocity`, and `tool_novelty`. *Fix:* cap per-update baseline growth and/or compute baselines at the agent-class level rather than per-agent (`evaluator.py:208-217`, `profile.py:51`).
- **HIGH-2 — Spec deviation, `score==0.0` → `"low"` not `"frozen"`:** deliberate & documented, but contradicts the `TrustResult` docstring and review spec. *Fix:* either update the spec/docstring to state "frozen is admin-only," or add `if score == 0.0 and not frozen: category="low"` explicitly with a code comment (currently only conveyed by a test).
- **HIGH-3 — Profile window is 1 day, not 7:** `WINDOW_SECONDS = 86400` (`profile.py:70`). *Fix:* `WINDOW_SECONDS = 604800` to match the "7-day baseline," or correct the spec/registry which claim 7 days.
- **HIGH-4 — Trust fails open on Redis error:** `_safe_history/_safe_profile` return empty → signals default HIGH; `_is_manually_frozen` returns `False` (un-freezes). *Fix:* on Redis failure return a conservative low/neutral default and log `NRVQ-ENG-2043/2044` (not generic 2000); consider failing the freeze check closed.

**4. MEDIUM**
--
**Verdict:** The feature is functionally correct and well-engineered (atomic Redis ops, clean signal abstraction, graceful per-signal fallback, override wiring). It does **not** warrant rejection on calculation/security-bypass grounds. However, per CLAUDE.md's strict gates, **two REJECT-class artifact issues must be fixed before sign-off**: the `F027.class.mmd` content mismatch and the inaccurate registry file:line references. I recommend addressing HIGH-1 through HIGH-4 and the missing override/profile tests in the same pass.
- ⚠️ **LOW:** semantic drift — spec defines 2043 = "history *fetch* failed" and 2044 = "profile *fetch* failed," but the code reuses 2043 for a history **write** failure and 2044 for a **trust-set** failure (`_safe_set_trust:188`). Also `_persist`/`_is_manually_frozen` log cache failures under generic **`NRVQ-ENG-2000`** (not an F027 code).

### 11. TESTING — PARTIAL (MEDIUM)

## F027 — deferred 2026-06-01

- Trust signals in audit (`_emit_audit` 387-400). ✓ — *but carries stale fields on cache hits (HIGH-1).*

### 5. Redis Data Stores — PASS
--
- **No test covers the cache-hit trust-field path** — which is exactly where HIGH-1 hides.

### 12. Stale Code — mostly PASS
--
4. **Test gap:** add a cache-hit test asserting `decision.trust_score`/`signals` reflect the *current* agent (would have caught HIGH-1).

### LOW
--
**Verdict: REJECT** — gated solely on HIGH-1 (cache-hit trust-field correctness) and HIGH-2 (architecture/registry accuracy, which CLAUDE.md treats as hard rejects). The signal math, store atomicity, override enforcement, and anti-poisoning design are all correct and genuinely strong; the blockers are a metadata-propagation bug and doc/registry drift, all mechanically fixable.

Note: I could not execute `ruff`/`pytest` this session — please run both before merge to confirm the green bar, since several findings (line numbers, function length) are easy to regress.
- **Redis down → does NOT "return graceful default ~0.8."** `_safe_frozen_only` **fails closed → frozen → block** (calculator.py:168-174, `test_freeze_check_failure_fails_closed`). Defensible security posture, but it **contradicts spec edge-case #7**. Decide and document (MEDIUM-1).

### 8. Security — PASS (strong)
--
1. **Cache-hit trust-field leakage** — `evaluator.py:99-111` & `136-145`. The eval cache key is `namespace:agent_class:tool:param_hash` (not per-SPIFFE). On a cache hit, `_apply_trust_overrides` updates only `decision`/`reason` via `model_copy`, so the returned `trust_score`, `trust_category`, `trust_signals`, `trust_dominant_signal`, `trust_recommendation` remain those of **whichever agent populated the cache**. Audit records (`_emit_audit`) and any decision consumer then report the wrong agent's trust. (`decided_at` is also stale, skewing the recorded history timestamp — MEDIUM-3.)
   **Fix** — refresh trust fields whenever overrides run on a cached decision:
   ```python

## F036-F037 — deferred 2026-06-01

| Analysis-endpoint cost | **FAIL (MEDIUM)** | `find_critical_paths`, `compute_risk_matrix`, and `full_analysis` are O(agents × data) × `all_simple_paths`; `full_analysis` additionally runs `compute_blast_radius` per agent (each enumerates all data). No result caching. See HIGH-5. |

### 4. SECURITY
--
7. Latent concurrency: the shared `_graph_builder` is mutated (`record_tool_call`) and read (router traversals) across coroutines. Safe **only** because every mutate/read is fully synchronous (no `await` mid-operation). If any `await` is later added inside `record_tool_call` or a traversal, an in-flight `all_simple_paths` could see a half-mutated graph. → Add a comment/`asyncio.Lock` guard if persistence (HIGH-3) introduces awaits into these methods.
8. Tool-node poisoning via arbitrary `tool_name` (`record_tool_call:96`) — low impact, but consider validating tool names against a known registry.
9. `store.py:36,68` reach into `cache._pool` (private). Matches spec but is a coupling smell; prefer a public cache method.
--
**Registry note (CLAUDE.md strict standards):** F036/F037 registries exist with 12 sections but **do not meet** the strict format — §3 lacks `file:line` and method signatures, §10 error map lacks the `What To Check` column, and there is **no Debug Guide table (Symptom/Cause/File:Line/Fix)** with the required error/timeout/fallback rows. Per CLAUDE.md §7 this is a reject-level registry-quality gap; flagging rather than blocking since the feature's larger issues (HIGH-1/2/3) dominate.

**Bottom line:** algorithms are sound and tests are present, but the feature is **not production-ready** as integrated: persistence is dead code, the graph leaks across tenants, the update blocks the hot path, and in-memory growth is unbounded. Address HIGH-1/2/3 before merge.

## F040 — deferred 2026-06-01

**Verdict:** REJECT — fix HIGH-1..3 and the empty-ConfigMap bug, verify HIGH-4 against a live `/metrics`, then re-review. The 4 telemetry tests look correct but exercise only happy paths; add coverage for the evaluator timeout/error telemetry and the middleware-vs-evaluator metric separation once fixed.

## F041 — deferred 2026-06-01

| Mermaid .mmd | PARTIAL | 3 files exist but content non-compliant (HIGH-6) |
| Code registry | FAIL | strict table sections missing (HIGH-5) |
| Type hints | PASS | signatures typed |
| Attack count | PASS | 26 attacks (≥25) |
--
- Compares actual vs expected decision: **PARTIAL** — also requires rule match, stricter than spec (HIGH-4) `simulator.py:120`
- `passed=True` when correctly blocked: **PASS (logic)** but depends on broken contract
- `run_suite()` runs all + aggregates: **PASS** `simulator.py:78-90`
- **MEDIUM-11:** `--category` invalid value → uncaught `ValueError` from `AttackCategory(category)` crashes CLI `runner.py:40`

### 5. SECURITY OF THE RED-TEAM TOOL ITSELF

## F041 — deferred 2026-06-01


## CRITICAL: Day 8 — Policy not enforced at runtime ($(date +%Y-%m-%d))

Symptoms:
- POST /api/v1/policies returns 200
- GET /api/v1/policies shows the policy with correct rego_length
- POST /api/v1/evaluate returns "decision":"allow", "rule_id":"default_allow"
- Even simple rules (tool_name == "delete_record" → block) don't fire
- Pod restart does not fix
- Only the earliest simple test policy ever worked, briefly

Likely cause:
- norviq-api stores policy in DB and own in-memory copy
- norviq-engine (evaluator) has separate in-memory _policies dict
- Cache pub/sub invalidation between pods is failing
- OR: evaluator uses key format different from what API writes

Files to investigate:
- norviq/engine/policy_loader.py (where _policies is populated)
- norviq/engine/evaluator.py (where _policies is read in evaluate())
- norviq/sidecar/proxy.py (_watch_policy_events listener)
- norviq/engine/cache.py (listen_policy_events)

Test to reproduce:
1. POST policy via API → 200 OK
2. GET policies → shows policy
3. POST evaluate with matching attack → returns default_allow

Impact: Day 8 attack tests at 25/66 pass — most policies not actually enforced
Blocks: Day 8 sign-off, Day 13 pentest readiness
Priority: P0 — fix before Day 9

## Day 8 — P0 — Policy evaluator broken ($(date +%Y-%m-%d))

Symptoms:
- Policy stored in PostgreSQL (verified: SELECT COUNT(*) FROM policies = 1)
- warm_cache loads policy on API startup (NRVQ-REG-5015 count=1)
- POST /api/v1/evaluate returns "decision":"allow", "rule_id":"default_allow"
- Even simple tool_name == "delete_record" rule doesn't fire
- No NRVQ-ENG logs visible

Likely causes (investigate tomorrow):
1. _collect_candidates returns empty list (key format mismatch)
2. OPA Python evaluator silently fails
3. Rego stored corrupted (verify with SELECT LEFT(rego_source, 200))
4. evaluate() catches exception and falls through to default

Files to check:
- norviq/engine/evaluator.py _collect_candidates and evaluate methods
- norviq/engine/policy_loader.py _policies dict key format
- norviq/api/main.py lifespan startup

Day 8 result: 21/66 passing — most failures because policies not enforced
Blocker for: Day 9 onwards
