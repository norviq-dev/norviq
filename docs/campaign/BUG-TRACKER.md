# BUG TRACKER — rev 30 campaign

One row per **surviving** finding. Findings that did not survive independent re-verification are
not listed here; the count and titles are in `LEDGER.md` §5.

`Status` values: **OPEN** (confirmed, unfixed) · **OPEN-CONTESTED** (reproduces, but at least one
re-verification argued it is intended or has no shipped blast radius) · **UNVERIFIED** (no agent
executed it).

Rows `SEED-*` were confirmed live before this campaign and are carried forward with whatever new
measurement the campaign produced.

---

## Summary

| id | sev | surface | claim | file:line | status |
|----|-----|---------|-------|-----------|--------|
| BUG-001 | blocker | engine / posture | Monitor mode does not soften `evaluator_timeout`, `evaluator_fallback`, `invalid_spiffe_identity` — they bypass `_apply_posture` | `norviq/engine/evaluator.py:604-642` | OPEN |
| BUG-002 | blocker | `/policy-compliance` | A control at `monitor` emits a bare rule_id and is counted as **zero** — the blast-radius view goes blind the moment the feature is used | `norviq/api/routers/compliance_view.py:52-65,101` | OPEN |
| BUG-003 | blocker | console / Overview | Tile never relabels and every would-block is hidden: `monitorScope` reads a posture source that disagrees with the baseline policy | `ui/src/pages/Dashboard.tsx:332-341,386,566` | OPEN |
| BUG-004 | major | strict preset | A `;`, `\|` or backtick in ordinary English prose → `deny_shell_execution`, **100%** | `webhook/presets/strict.rego` (shell_patterns, ~:190) | OPEN |
| BUG-005 | major | strict preset | Every ISO-8601 date parameter is classified as a US SSN, **100%** | `webhook/presets/strict.rego:529` | OPEN |
| BUG-006 | major | strict preset | `[A-Z]{2}\d{7}` business references classified as SSN, **100%** | `webhook/presets/strict.rego:529` | OPEN |
| SEED-01 | major | strict preset | base64 fan-out on opaque identifiers — now quantified: **4.0% @8 → 32.0% @64 chars**, 12.7% overall | `webhook/presets/strict.rego` | OPEN (audit, not block) |
| SEED-02 | major | strict preset | PII detection is SSN-shape-only; no email/phone/DOB/passport | `webhook/presets/strict.rego:529` | OPEN |
| SEED-03 | minor | resolver | Alphabetical `rule_id` attribution — the SQL-vs-shell shadowing fix exists only in the **block** branch, so the shipped monitor default reintroduces the misattribution | `webhook/presets/strict.rego:791-802` | OPEN (widened) |
| SEED-04 | major | SDK adapters | `call_depth` is 0 under CrewAI, AutoGen, LangGraph, Semantic Kernel — `chain_depth_limit` cannot fire on that traffic | `norviq/sdk/core/interceptor.py:63`, `norviq/sdk/langchain/adapter.py:776,796` | OPEN (confirmed) |
| SEED-05 | major | SDK adapters | LangGraph sends `{}` when tool args are not a dict — the engine rules on a call whose arguments it never saw | `norviq/sdk/langgraph/adapter.py:101` | OPEN (confirmed) |
| SEED-06 | — | certs | No cert-rotation test | — | **UNVERIFIED** — no agent exercised it |
| BUG-007 | major | trust engine | `trust_frozen` fires on a Redis **error**, and its monitor exemption then blocks every call under a rule asserting an admin froze the agent | `norviq/engine/trust/calculator.py:263-269` | OPEN |
| BUG-008 | major | `/baseline/controls` | Reported control effects are derived from a DB table and never reconciled against the module the engine is enforcing | `norviq/api/routers/baseline_router.py:55-64,90-118` | OPEN-CONTESTED |
| BUG-009 | major | baseline compiler | `scope_violation_dangerous_tool` cannot be promoted to `deny`, and `PUT` reports it as "enforcing" anyway | `norviq/api/baseline.py:336` | OPEN |
| BUG-010 | major | `/baseline/controls` | `PUT` accepts the console's aggregate sentinel `namespace="all"` and writes a phantom policy the engine can never enforce | `norviq/api/routers/baseline_router.py:101,133` | OPEN |
| BUG-011 | major | red-team suite | Efficacy scores `audit` as a miss, so the **shipped default posture** reports 0.2% proven blocking and buries 25 real bypasses among 494 false reds | `norviq/api/routers/redteam.py` (`_result_row`) | OPEN |
| BUG-012 | major | `POST /policies` | A cross-namespace `target.namespace` stores a permanently dead policy that reports itself as enforcing with 6,516 matches | `norviq/api/routers/policies.py:824` vs `norviq/engine/evaluator.py:2043` | OPEN |
| BUG-013 | major | engine / `/evaluate` | `namespace="all"` silently drops the namespace and workload tiers, so the console's what-if returns `allow` where production blocks | `norviq/engine/evaluator.py:2104` | OPEN |
| BUG-014 | major | policy precedence | A higher-priority policy saved in **audit** mode silently disarms a lower-priority enforcing policy | `norviq/engine/evaluator.py:2242`, `:789` | OPEN |
| BUG-015 | major | `/policy-compliance` | Materializes every audit row in the range with no LIMIT and no aggregation — 6.5s at 34.5k rows on a near-empty cluster | `norviq/api/routers/compliance_view.py:79-82` | OPEN |
| BUG-016 | major | `/audit/stats` | `engine_errors` is not prefix-aware: a softened engine fault reads 0 **and** is miscounted as a policy would-block | `norviq/api/routers/audit.py:249-250` | OPEN |
| BUG-017 | major | console / audit log | UI forked `WOULD_BLOCK_RULE_PREFIXES` and handles only one of the two prefixes; 270/270 live rows render raw | `ui/src/pages/AuditLog.tsx:458-465` | OPEN |
| BUG-018 | major | MCP firewall | Monitor mode lets a destructive MCP call execute, and the shipped adversarial harness fails 19/22 on the default posture | `norviq/sdk/core/decisions.py:37`, `norviq/mcp/firewall.py:821` | OPEN-CONTESTED |
| BUG-019 | major | MCP firewall | Gate-A carry-over catalog is per-process; a cold instance forwards a tool the fleet already quarantined | `norviq/mcp/firewall.py:772,799` | OPEN-CONTESTED |
| BUG-020 | minor | engine / labelling | Monitor-mode would-blocks are emitted under two different rule_id shapes (bare vs prefixed) | `norviq/api/baseline.py:336` vs `norviq/engine/evaluator.py:57-64,826` | OPEN |
| BUG-021 | minor | rate limiter | `rate_limit_exceeded` stays a hard block under monitor and is trivially tripped by ordinary burst traffic (60/60s per SPIFFE id, shared across replicas) | `norviq/config.py:169-170`, `norviq/engine/evaluator.py:350` | OPEN (by design; default value questioned) |
| BUG-022 | minor | `/system-health` | Stale comment asserts `_POSTURE_EXEMPT_RULES` keeps `evaluator_error` hard in monitor mode; it no longer does, and the symbol no longer exists | `norviq/api/routers/system_health.py:88-90` | OPEN |
| BUG-023 | minor | `/policy-compliance` | `samples` are the first 5 rows in unordered DB order, so they under-represent the dominant pattern they exist to reveal | `norviq/api/routers/compliance_view.py:79,114` | OPEN |
| BUG-024 | minor | `/policy-compliance` | `excluded_synthetic` counts every excluded row in the window, not just excluded would-blocks (5,930 scanned vs 21,338 excluded at 30d) | `norviq/api/routers/compliance_view.py:94-98` | OPEN |
| BUG-025 | minor | `/baseline/controls` | `chain_depth_limit`'s caveat states the **inverse** of the truth — says four of five adapters report depth; exactly one does | `norviq/api/baseline.py:166-169` | OPEN |
| BUG-026 | minor | MCP pins | Pin-store degradation is permanent for the process lifetime — no retry after the control plane recovers | `norviq/mcp/http.py:114-144` | OPEN |
| BUG-027 | minor | red-team catalogue | Two of the four evaluate-reachable vectors have no attack in the suite (`resources-read-uri-gate` is the real gap — claimed policy-reachable, nothing exercises it) | `norviq/redteam/attacks.py` | OPEN |
| BUG-028 | minor | `/system-health` | `evaluator_timeout` and `evaluator_invalid_payload` are softened by monitor mode but are not infra rules, so they raise no banner | `norviq/api/routers/system_health.py:61-107` | OPEN-CONTESTED |

---

## Detail

### BUG-001 — monitor mode does not soften three drop paths (BLOCKER)

**Observed vs expected.** rev 30 states monitor mode now softens `policy_load_pending`,
`evaluator_error`, `evaluator_invalid_payload`, `evaluator_timeout`. The exempt-set half is
correct — `_BASE_POSTURE_EXEMPT_RULES == frozenset({"trust_frozen"})` and `_posture_exempt_rules()`
adds `rate_limit_exceeded`. But `_apply_posture` is reached from exactly three call sites
(`:595` fresh, `:716` cache hit, `:733` rate limit), all inside the `try`. Three exception handlers
mint and return decisions **after** it: `except asyncio.TimeoutError` (`:604-616`),
`except InvalidSpiffeIdentity` (`:617-629`), `except Exception` (`:630-642`).

**Repro.**
```
cd /Users/san/Documents/Development/norviq/norviq-migration/repo && \
NRVQ_EVALUATOR_INPROC_CACHE_TTL_S=0 PYTHONPATH=$PWD ./.venv/bin/python \
  <scratchpad>/posture_probe.py
```
Section 2 (`_apply_posture` called directly, monitor=True): `evaluator_timeout -> audit`.
Section 3 (full `evaluate()`, FakeCache returns `{"enforcement_mode":"audit"}`):
```
asyncio.TimeoutError from OPA -> block  evaluator_timeout        HARD
generic Exception from OPA    -> block  evaluator_fallback       HARD
malformed spiffe_id           -> block  invalid_spiffe_identity  HARD
OPA -> evaluator_error dict   -> audit  monitor_would_block:evaluator_error   SOFTENED
```
Live half:
```
curl -s -X POST http://127.0.0.1:8080/api/v1/evaluate -H "Authorization: Bearer $(cat /tmp/nrvq-signin-token.txt)" \
 -H 'Content-Type: application/json' -d '{"tool_name":"list_items","tool_params":{},"agent_identity":{"spiffe_id":"not-a-spiffe-id","namespace":"chatbot-prod","service_account":"a","agent_class":"cmp-drop-inv-a","framework":"langchain"},"session_id":"s1","framework":"langchain"}'
-> {"decision":"block","rule_id":"invalid_spiffe_identity","trust_score":0.0}
```
**Fix shape.** Resolve posture before the `try` and route every handler through the same
`_apply_posture` the happy path uses. If `invalid_spiffe_identity` should stay hard, make it an
explicit entry in `_BASE_POSTURE_EXEMPT_RULES` with a stated reason, not an accident of where the
raise lands.

---

### BUG-002 — monitor-mode hits never reach `/policy-compliance` (BLOCKER)

**Observed vs expected.** `baseline.compile()` maps `monitor` to a plain `audits["<control>"]`
head. The resolver then decides `audit` with the **bare** control id. Neither softener stamps a
prefix (`_apply_policy_mode` and `_apply_posture` both return early unless the decision is
`block`/`escalate`). `_strip_prefix` returns `None` for an unprefixed rule_id and the row is
skipped. Expected: the count moves by N. Observed: it does not move at all.

**Repro (ns/default, baseline already compiled).**
```
for i in $(seq 1 11); do curl -s -X POST $B/evaluate -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' \
 -d '{"tool_name":"cmpdefx307481","tool_params":{"note":"order 4471; rm -rf /tmp/x | cat /etc/passwd"},"agent_identity":{"spiffe_id":"spiffe://norviq.io/ns/default/sa/cmp-support","namespace":"default","service_account":"cmp-support","agent_class":"cmp-support","framework":"langgraph"},"session_id":"s","framework":"langgraph"}'; done
# every response: {"decision":"audit","rule_id":"deny_shell_execution"}   <-- no prefix
curl -s "$B/audit/records?namespace=default&tool_name=cmpdefx307481&range=1h&limit=50" | jq length   # 11
curl -s "$B/policy-compliance?namespace=default&range=1h" | jq '.controls[]|select(.control_id=="deny_shell_execution").count'
# BEFORE 2 -> AFTER 2   (expected 13); scanned 114 -> 125, so the rows are read and dropped
```
Confirmed twice (11 calls, then 5 more). Blast radius in that namespace over 1h: 33 would-block
calls, **7 reported**. Contrast `ns/analytics` (chart baseline, `blocks[]` + policy
`enforcement_mode=audit`): the same payload returns
`policy_audit_would_block:deny_shell_execution` and 13 calls move the count 5 → 18, exactly +13.

**Why it is a blocker.** Compliance looks correct on a fresh install and silently empties out the
moment a customer touches the controls page — the one screen that answers *"what will this break
if I promote it"*. `evaluator.py:55-64` states the invariant in terms: *"Any new softening path
MUST add its prefix here, or its would-blocks become invisible to the dashboard."* The monitor
effect is a new softening path and did not add one.

---

### BUG-003 — Overview tile never relabels; 678 would-blocks render nowhere (BLOCKER)

**Observed vs expected.** Two softening paths exist. `_apply_posture` stamps
`monitor_would_block:` when the **namespace posture** is monitor; the per-policy audit path stamps
`policy_audit_would_block:`. On this deployment only the second fires — `/settings` returns
`enforcement_mode=block` for every namespace, and 0 rows anywhere carry the monitor prefix — yet
the baseline **policy** is `audit`. `coverage.py:195-207` reads `namespace_settings`, so
`namespace_mode=block`, so `monitorScope=false`, so the tile stays `Blocked (24h)` bound to
`stats.blocked=184` while `stats.would_blocked=678` is fetched and discarded.

```
curl -s '.../api/v1/policies?namespace=chatbot-prod'          # __baseline__ enforcement_mode: audit
curl -s '.../api/v1/coverage-by-category?namespace=chatbot-prod' | jq .namespace_mode   # "block"
curl -s '.../api/v1/audit/stats?namespace=chatbot-prod'       # blocked:184, would_blocked:678
```
The console contradicts itself on the same namespace. Someone must decide which knob is
authoritative; if the chart's `enforcementMode: audit` is meant to be namespace posture, it is not
reaching `namespace_settings`.

*Contested detail:* re-verification confirmed the tier separation is deliberate and
regression-pinned (`Dashboard.test.tsx:484-505`) — keying Overview on the policy's mode would
reintroduce an older bug that hid real blocks behind a structurally-0 counter. What survives is
that the Overview is **incomplete**: it omits the dominant signal (678 vs 184, ~3.7×) and offers no
pointer to `/policy-compliance`, which does render it correctly.

---

### BUG-004 — semicolon in prose → shell execution, 100%

```
curl -s -X POST http://127.0.0.1:8080/api/v1/evaluate -H "Authorization: Bearer $(cat /tmp/nrvq-signin-token.txt)" \
 -H 'Content-Type: application/json' -d '{"tool_name":"view_transcript","tool_params":{"note":"Refund approved; please confirm with the customer."},"agent_identity":{"spiffe_id":"spiffe://norviq/ns/chatbot-prod/sa/cmp-support","namespace":"chatbot-prod","service_account":"cmp-support","agent_class":"cmp-support","framework":"langchain"},"session_id":"s1","framework":"langchain"}'
-> {"decision":"audit","rule_id":"policy_audit_would_block:deny_shell_execution"}
```
Replace `;` with `.` in the same sentence → `allow / default_allow`.

| shape | n | flagged | rate |
|---|---|---|---|
| prose_semicolon | 60 | 60 | **100%** |
| prose_pipe | 30 | 30 | **100%** |
| prose_backtick | 30 | 30 | **100%** |
| prose_fullstop | 60 | 0 | 0% |
| prose_comma | 30 | 0 | 0% |

Comma, period, dash, colon, `&`, `$`, `>`, `)` do not fire. **Observed vs expected:** the control's
shipped caveat warns only about base64-decoded identifiers at "roughly 1 in 8"; it does not mention
that raw prose punctuation trips it at 100%. `deny_shell_execution count=460` is the top row of the
customer-facing compliance board, top tools `get_order(256)`, `view_transcript(129)`.

---

### BUG-005 / BUG-006 / SEED-02 — the PII regex

`webhook/presets/strict.rego:529`:
```rego
regex.match(`^(\d{3}-\d{2}-\d{4}|\d{4}-\d{2}-\d{2}|[A-Z]{2}\d{7})$`, val)
```
Branch 2 **is** the ISO-8601 date format. Branch 3 matches sales orders, POs, work orders and
country-prefixed customer refs.

| shape | n | flagged | rate |
|---|---|---|---|
| `since=2026-07-01` (10 key names, 3 years) | 60 | 60 | **100%** |
| `since=2026-07-01T00:00:00Z` | 30 | 0 | 0% |
| date embedded in prose | 30 | 0 | 0% |
| `GB1234567` (GB/SO/IN/PO/RM/AC/CS/WO) | 60 | 60 | **100%** |
| `GB-1234567` | 30 | 0 | 0% |

Operator-visible reason string: **"PII (SSN) detected in tool parameters"**. Top tools on the
`pii_detection` row are `list_shipments(66)` and `get_order(60)`; neither ever handled an SSN. This
does not merely add noise — it **corrupts the evidence the product exists to produce**. Promoting
the control to `deny` in `ns/default` turned the identical call into `block / pii_detection`.

`strict.rego` already contains a long comment establishing that *"SHAPE ALONE IS NOT A SIGNAL"* and
requiring a corroborating key name before acting on a shape-only match. This rule does not follow
it.

---

### SEED-01 — base64 fan-out, now quantified

State-correlated, `tool=get_*` (rate-limit exempt), only the identifier value varies, n=150 each:

```
alnum_8    4.0%   alnum_16   8.7%   alnum_24  12.0%   alnum_32  19.3%   alnum_64  32.0%
upper_32  26.0%   hex_32    10.0%   hex_64    20.0%   b64_44    22.0%   uuid_v4   14.7%
digits_12  0.0%   licence_5x5 0.0%              ALL: 362/2850 = 12.7%
```
The shipped caveat's "roughly 1 in 8 at 16-24 characters" is fair (8.7% / 12.0%) but stops there;
the curve keeps climbing. Per-value, not per-shape: `T-110018` flags while `T-110017` and
`T-110019` allow. Under the shipped monitor default it correctly returns `audit` — allow-by-default
is doing its job here.

---

### SEED-03 — alphabetical rule_id attribution (widened by this campaign)

`strict.rego:791-802` documents a deliberate fix so a stacked-SQL block is not reported as
`deny_shell_execution`. The fix lives only in the **block** branch:
```rego
rule_id = sort([id | blocks[id]; not _shell_shadowed_by_sql(id)])[0] { block_fired }
rule_id = sort([id | audits[id]])[0] { audit_fired; ... }      # no filter
```
Under the compiled monitor effect every control lands in `audits[]`, so the shadowing never
applies. Measured: `execute_sql {"query":"SELECT id FROM t1; SELECT id FROM t2"}` →
`audit / deny_shell_execution` at monitor, `block / deny_sql_multi_statement` at deny. Same call,
same detectors, two different control names depending on effect — and it feeds `/policy-compliance`
grouping, inflating `deny_shell_execution`'s blast-radius estimate with SQL traffic.

---

### SEED-04 — `call_depth` is 0 under four of five adapters

`depth_scope()` is defined at `norviq/sdk/core/interceptor.py:63` and used **only** at
`norviq/sdk/langchain/adapter.py:776` (sync) and `:796` (async). Measured with the real five
framework packages (langchain-core 1.4.9, langgraph 1.2.9, crewai 1.6.1, autogen-core 0.7.5,
semantic-kernel 1.36.0) and the real `ToolInterceptor` — a fake interceptor would have bypassed the
`current_call_depth()` fallback and measured nothing:

```
nested call_depth reaching the engine:  langchain 1 | crewai 0 | autogen 0 | semantic-kernel 0 | langgraph 0
```
`chain_depth_limit` keys on `event.call_depth` (`evaluator.py:1712,927`) so it cannot fire on that
traffic even at `deny`. Disclosed in the control's caveat — but see **BUG-025**, the caveat says
the opposite of the truth.

---

### SEED-05 — LangGraph evaluates a blind `{}`

`norviq/sdk/langgraph/adapter.py:101`: `tool_params = args if isinstance(args, dict) else {}`.

```
dict (control) -> {'to':'ops@acme.com','body':'hello'}
JSON string    -> {}      evaluated, ALLOWED
list           -> {}      evaluated, ALLOWED
None           -> {}      evaluated, ALLOWED
```
The engine renders a verdict on a call whose arguments it never saw, so every per-argument control
is inert. Contrast `norviq/mcp/firewall.py:759-768`, which **refuses** a non-dict arguments value
because *"normalising to {} would silently evaluate a DIFFERENT call than the one sent"* — the MCP
gate fails closed on the same shape; the adapter fails open.

**Honest limit on blast radius:** end-to-end exploitation was **not demonstrated**. A validated
`langchain-core` `AIMessage` rejects non-dict args at the pydantic layer, and the plain-dict
message that does reach this branch is then refused by the real `ToolNode`
(`ValueError: No AIMessage found in input`). The defect today is a blind allow backstopped by
LangGraph's own validation rather than by Norviq.

---

### SEED-06 — cert rotation

**UNVERIFIED.** No agent in this campaign exercised certificate rotation. Do not infer a status
from the adjacent identity work — `invalid_spiffe_identity` (BUG-001) is about a malformed
identity string, not about SVID rotation.

---

### BUG-007 — `trust_frozen` on a Redis error

`norviq/engine/trust/calculator.py:263-269`:
```python
async def _safe_frozen_only(self, spiffe_id: str) -> bool:
    """Return true when admin freeze is set; fail closed on Redis errors."""
    try:
        return bool(await self._cache._client().get(f"agent_frozen:{spiffe_id}"))
    except Exception as exc:
        log.error("nrvq.engine.trust.freeze_check_failed", ..., code="NRVQ-ENG-2050")
        return True
```
→ `_categorize` line 311 → `evaluator.py:946-950` hard block, reason *"Agent trust frozen — all
tool calls blocked"*. Executed with monitor ON:
```
admin freeze set (frozen=True)  -> block  trust_frozen  HARD
Redis outage on freeze lookup   -> block  trust_frozen  HARD   <-- indistinguishable
```
Measured blast radius under real Redis pressure (holding all 64 pooled connections, or 60-100ms
per-command latency through a proxy): **2.4-4.4%** of ordinary benign calls hard-dropped and
labelled as an admin freeze, with `agent_frozen:*` count asserted 0 before and after. A full Redis
outage instead lands on `evaluator_fallback` (because `get_trust` fails first), so this needs a
*partial* failure — failover blip, pool exhaustion, per-command timeout. Live census:
`GET /agents?namespace=all` → 165 agents, 0 frozen, so any `trust_frozen` on this cluster would be
the error path.

**Fix shape.** Tri-state the freeze lookup. Keep `trust_frozen` exempt for a genuinely-read freeze;
mint a distinct rule_id (`trust_state_unavailable`) for the error path so posture can soften it and
system-health can alert on it as the engine-health signal it is.

---

### BUG-008 — `/baseline/controls` reports the table, not the artifact (CONTESTED)

`list_controls` answers purely from `NamespaceBaselineControl` via `_stored_effects`; an absent row
means `DEFAULT_EFFECT = "monitor"`. It never inspects the module loaded at
`(namespace, "__baseline__")`.

```
GET /api/v1/baseline/controls?namespace=default -> {'off':0,'monitor':14,'deny':0}
GET /api/v1/policies/default/__baseline__       -> compiler-generated: False
                                                   heads {'blocks': 22, 'escalates': 1, 'audits': 1}
POST /evaluate delete_thing (ns=default)        -> audit / policy_audit_would_block:strict_default_block
```
The `policy_audit_would_block:` prefix proves the head registered as a **block** and was softened
by the policy's own `enforcement_mode=audit` — not by the control being compiled to `audits[]`.
Same defect in the other direction on `chatbot-prod`: the module **is** compiler-generated
(1 block / 1 escalate / 22 audits) while the table reported `off ×14`, then `monitor ×14`, then
`deny ×14` at different points.

**Why contested.** Three independent re-verifications argued (a) the chart writing the raw preset
is by design (`webhook/controller.go:1058-1061` reads the preset verbatim; the compiler runs only
on `PUT`), (b) the raw-preset-at-audit and compiled-all-monitor artifacts are **behaviourally
identical** — both decide `audit`, call proceeds — so blast radius in the default configuration is
zero blocked calls, and (c) the "chart upgrade flips it to block" hazard does not exist, because
the controller always writes rego and `enforcement_mode` together and always sends `audit`.
**What survives:** the endpoint reports desired state as fact, with no "not yet materialized"
state, and is right only by coincidence with a separate knob it does not display. Under the
documented, supported `baselineClusterPolicy.enforcementMode: block` the report becomes a lie.

---

### BUG-009 — `scope_violation_dangerous_tool` cannot be promoted to deny

`norviq/api/baseline.py:336`: `target = "audits" if effect == "monitor" else head.set_name`.
That control's preset head is already `audits["scope_violation_dangerous_tool"]`
(`strict.rego:754`), so at `deny` it is re-emitted into `audits[]` and can never block.

```
PUT /baseline/controls {"effects":{"scope_violation_dangerous_tool":"deny"}}
  -> 200, body: "enforcing": ["scope_violation_dangerous_tool"]
GET /policies/chatbot-prod/__baseline__  -> audits["scope_violation_dangerous_tool"], NO blocks head
POST /evaluate execute_sql, agent_class="customer-support"
  observed: {"decision":"audit","rule_id":"scope_violation_dangerous_tool"}   call proceeds
  expected: {"decision":"block"}
```
Worse than the no-op is the reporting: `PUT` returns it under `enforcing` and `GET` then shows
`effect="deny"`. The operator is told twice that it is enforcing.

Distinct from `llm06_excessive_agency`, whose `escalates[]` head is intentional and works
(`escalate / llm06_excessive_agency` is a real non-allow outcome). Secondary: the predicate
hardcodes `input.agent.agent_class == "customer-support"` (`strict.rego:705-708`), so the control
is unreachable for every other class even if the compiler bug is fixed. Note that the control is
also invisible to `/policy-compliance` for the same reason as BUG-002 — the bare-audit rule_id
shape is dropped by `_strip_prefix`.

---

### BUG-010 — `namespace="all"` writes a phantom policy

`baseline_router` uses `scoped_namespace(user, body.namespace)`, which passes `"all"` through for
an admin. The codebase has a dedicated helper for exactly this sentinel —
`aggregate_namespace` / `read_namespace` (`auth.py:561-575`) — used by `compliance_view.py` and
`audit.py`. This router does not use it.

```
BEFORE: GET /policies (ns=all) -> []
PUT /baseline/controls {"namespace":"all","preset":"strict","effects":{"llm01_prompt_injection":"deny"}} -> 200
AFTER : {'namespace':'all','agent_class':'__baseline__','priority':1,'enforcement_mode':'block',
         'rego_length':38496,'matches':3}
```
The engine refuses to enforce it — `policy_loader.namespaces_for_class` filters
`AND namespace <> 'all'` (`policy_loader.py:609`) and `_collect_candidates` short-circuits
(`evaluator.py:2013`). An operator with "All namespaces" selected promotes a control, sees a
success toast and a new policy row reporting `matches: 3`, and nothing is enforced anywhere. `GET`
is equally broken: `namespace=does-not-exist-xyz` returns a full 14-control payload.
Cleaned up during the campaign via `PUT effects={}` then
`DELETE /api/v1/policies/all/__baseline__?confirm_managed=true`.

---

### BUG-011 — red-team efficacy scores `audit` as a miss

`compute_efficacy` derives pass/got_through from `actual == attack.expected_decision`, and every
attack expects `block`. At the **shipped default** posture:

```
POST /api/v1/redteam/suite?target_namespace=chatbot-prod   (controls at monitor ×14)
  total 680  passed 41  pass_rate 6.0
  efficacy.overall {"total":520,"caught":1,"got_through":519,"proven_blocking_pct":0.2}
  got_through by actual: {'audit': 494, 'allow': 23, 'escalate': 2}
```
versus the same suite at `deny ×14`: `646 rows, 78.5% pass, 494/469/25, 94.9%`.

494 of 519 "misses" are `decision=audit` — the control fired, recorded the violation, and let the
call proceed exactly as designed. A customer opening the red-team page on a fresh install sees ~0%
efficacy on a correctly-functioning system, and the 25 genuine bypasses are buried among 494 false
reds with no way to separate them without post-processing `actual`. The existing `applicable` flag
already solves this shape for sector packs and MCP vectors; nothing equivalent exists for the
monitor/deny effect axis. The campaign brief anticipated **two** permanent false reds
(RL-001, CE-002 — confirmed, they allow at both postures); the real number is **494**.

---

### BUG-012 — cross-namespace `target.namespace` stores a dead policy

`resolve_policy_key` (`policies.py:824`) turns `{namespace: X, target:{namespace: Y}}` into loader
key `X:namespace:Y`. The evaluator only ever looks up `f"{namespace}:namespace:{namespace}"`
(`evaluator.py:2043`).

```
POST /policies {namespace:'chatbot-prod', agent_class:'', priority:499, target:{namespace:'analytics'}}
  -> 200 {'agent_class':'namespace:analytics','version':1,'priority':499}
eval in analytics    -> allow / default_allow
eval in chatbot-prod -> block / cmp_nstier_block   (the OTHER, real ns-tier policy)
GET /policies?namespace=chatbot-prod
  -> {"agent_class":"namespace:analytics","target_type":"namespace","enforcement_mode":"block",
      "priority":499,"last_applied":"...","matches":6516,"matches_basis":"namespace"}
```
It fires nowhere and reports the **same match count** as the genuinely enforcing row beside it,
because the namespace-tier match basis counts the whole population of `body.namespace` and never
consults the target. The code already guards the identical dead-key outcome for `namespace='all'`
with a 422 whose message is *"a policy stored there can never be evaluated and would show as
enforcing while protecting nothing"* (`policies.py:37-46`). The cross-namespace path is accepted.

---

### BUG-013 — `namespace="all"` in `/evaluate` drops two tiers

`_collect_candidates_union` (`evaluator.py:2104`) claims in its docstring to *"mirror the
concrete-namespace collection above"*. It collects the class policy, `__baseline__`, four namespace
overlays and the remediation overlay — but never `<ns>:namespace:<ns>` or
`<ns>:deployment:<workload>` (`evaluator.py:2043-2054`).

```
CONCRETE ns=chatbot-prod, no workload : block  cmp_nstier_block
SENTINEL ns=all,          no workload : allow  cmp_class_allow
CONCRETE ns=chatbot-prod, wl=cmp-wl   : block  cmp_workload_block
SENTINEL ns=all,          wl=cmp-wl   : allow  cmp_class_allow
```
The Attack Graph and Policy Tester open on "All namespaces", so an operator validating a
namespace-tier or workload-tier policy from the global picker is told the call is allowed while
production blocks it. Secondary: a service token with an **empty** namespace claim and no SVID is
explicitly allowed to take the body's namespace (`routers/evaluate.py:297-304`), so such a token
could send `all` and evade every namespace- and workload-tier control while passing auth.

---

### BUG-014 — an audit-mode policy disarms an enforcing one

Base tiers resolve highest-priority-outright (`_resolve_precedence`, `:2242`), then per-policy
audit softening is applied to the winner only (`_apply_policy_mode`, `:789`).

```
chatbot-prod:cmp-prec-g @100 enforcement_mode=block, blocks cmp_soft_tool
  -> block / cmp_class_hard_block
+ chatbot-prod:namespace:chatbot-prod @300 enforcement_mode=audit (also blocks cmp_soft_tool)
  -> audit / policy_audit_would_block:cmp_nstier_trial_block      call proceeds
```
Each rule is individually defensible and the returned rule_id is honest about which policy decided.
The operational shape is the trap: the documented safe way to trial a rule (save it in audit mode)
is exactly the action that turns off the enforcing rule underneath it, with no warning at write
time and nothing in the decision naming the block that was lost.

---

### BUG-015 — `/policy-compliance` full-table materialization

`compliance_view.py:79-82` issues `select(AuditLogEntry).where(timestamp_utc >= since)` with no
limit, no column projection and no `GROUP BY`, then `.scalars().all()`.

```
range=1h  ns=default : 0.72s   scanned 132
range=30d ns=default : 5.77s   scanned 5930  + 21338 excluded = 27268 ORM rows
range=30d no ns      : 6.47s   scanned 13078 + 21461 excluded = 34539 ORM rows
```
`/audit/stats` solves the same problem by grouping on the discriminating columns and dropping
excluded groups Python-side, with a comment saying exactly this (*"bounded cardinality, not a full
table scan"*, `audit.py:198-214`). At a modest 50 calls/sec a 30d window is ~130M rows — an OOM,
not a slow query. The 30d range is one click away in the UI and is not role-gated.

---

### BUG-016 — `/audit/stats` `engine_errors` is not prefix-aware

`audit.py:249-250` counts `if rule_id == "evaluator_error"` — an exact match. Monitor/audit mode
now stores it as `monitor_would_block:evaluator_error`, so `engine_errors` reads **0** during an
engine fault and `Dashboard.tsx:597` keeps its banner dark. Worse, the same row **does** satisfy
the prefix test on line 247, so the fault is added to `would_blocked` and reported to the operator
as *"policy would have blocked this call"* — attributing an outage in Norviq's own engine to the
customer's policy. Same regression class that `system_health.py:119-123` was fixed for, in the
route that was not fixed. `WOULD_BLOCK_RULE_PREFIXES` is already imported at `audit.py:27`.

---

### BUG-017 — the UI forked the prefix list

`ui/src/pages/AuditLog.tsx:458-465` hardcodes the string literal `"monitor_would_block:"` in both
the `startsWith` test and the slice. The backend deliberately exports
`WOULD_BLOCK_RULE_PREFIXES` with a "do not fork" comment (`evaluator.py:56-64`) and three routers
import it. Census over the 500 newest `chatbot-prod` rows: `{'policy_audit_would_block:': 270}`,
zero monitor-prefixed. So the humane rendering never fires and the Rule column shows the literal
`policy_audit_would_block:deny_shell_execution` on a row whose Decision badge says `audit`.
`compliance_view.py:52-65` already handles both prefixes and guards against double-prefixing — the
pattern to copy exists.

---

### BUG-018 — monitor mode lets a destructive MCP call execute (CONTESTED)

`PolicyDecision.is_allowed()` counts `audit` as allowed (`decisions.py:37`), so
`firewall.py:821` forwards the original bytes upstream. `delete_records` matches
`strict_default_block`, returns `audit`, and **executes on the upstream server**.

```
export NRVQ_POLICY_ENGINE_URL=http://127.0.0.1:8080
export NRVQ_API_TOKEN=$(cat /tmp/nrvq-signin-token.txt)
.venv/bin/python -m norviq.mcp.adversarial.harness --json /tmp/h2.json
-> EXIT=1  "19/22 checks passed"   log: "evaluate.ok: 6  fallback: 0", "decision=audit tool=delete_records"
   row: benign:delete_records executed with {"table": "users"}
```
Critically, the same 19/22 is produced by two very different causes — engine unreachable +
`sdk_fallback_mode=allow`, and engine reachable + monitor→audit — and the harness cannot tell them
apart. An operator reading the scoreboard cannot distinguish a fail-open outage from the intended
posture. Verified: with the engine returning `block`, all three Gate B rows pass and the upstream
never executes; with the engine returning `allow` **or** `audit` and zero fallbacks, it is still
19/22.

**Why contested.** Re-verification established that forward-on-audit is deliberate and pinned by
`tests/mcp/test_firewall.py::test_audit_decision_is_forwarded` (*"Treating it as a block would
break visibility-only mode"*), unchanged since the initial commit. The defect that survives is the
**harness and the docs**, not the enforcement path: `harness.py:118-123` hardcodes
`expected="blocked by policy, never executed"`, and `DESIGN-NOTE-MCP-FIREWALL.md:29,182,418` plus
`MCP-WALKTHROUGH.md:225` still advertise 22/22, a claim no default install can reproduce. Two
sibling artifacts carry the same stale expectation: `norviq/mcp/demo_client.py:78` and
`tests/mcp/integration_sweep.py:68`. Also noted: the harness denominator is not stable — under an
enforcing posture the indirect-injection scenario crashes and the scoreboard silently drops from 22
rows to 20.

---

### BUG-019 — Gate-A carry-over catalog is per-process (CONTESTED)

`firewall.py:772` does `entry = self._catalog.get(name)`; `_catalog` is written only during
`tools/list` mediation (`:1010`) and is held in `HttpProxy._firewalls` (in-memory, per-process,
evicted at 64). When `entry is None` both the Gate-A denial and schema conformance (`:799`) are
skipped.

```
Instance A: tools/list, then tools/call 'add' -> {A_poisoned_call_blocked: true, A_gate: "A"}
Instance B (cold, shared PinRegistry)        -> {B_cold_poisoned_call_blocked: false,
                                                 B_reached_upstream: ["tools/call"]}
```
**Why contested.** Re-verification showed (a) the shipped placement is a **sidecar** with one
client per proxy process — `DESIGN-NOTE-MCP-FIREWALL.md:646-649` explicitly treats the shared
gateway as future work, the default bind is `127.0.0.1`, and the injector emits stdio only — so
the A/B split needs a non-default topology; and (b) a cold instance re-derives the verdict at its
own `tools/list` from the shared control-plane pin store, including drift.

**What survives, and is default-reachable:** two variants of the same cold-catalog mechanism.
(i) *Sidecar restart amnesia* — `examples/chatbot/agent_mcp.py:68-70` caches tools at first use and
`mcp_tools.py::_invoke` opens a fresh session and calls `call_tool` with **no** `tools/list`, so a
restarted `mcp-fw-*` container is a cold instance with zero config change. (ii) *Rug-pull window* —
a warm process that pinned a definition clean forwards a drifted call until the next `tools/list`
it happens to mediate, contradicting the docstring at `mcp_tools.py:150-153` (*"every call re-runs
Gate A"*). Fix is cheap: pins are name-keyed, so the `tools/call` path can consult `self._pins` by
`(server_id, name)` without needing the definition.

---

### BUG-020 — two rule_id shapes for the same softening

```
bare:     {"decision":"audit","rule_id":"deny_shell_execution"}                       (baseline.py:336 compiles blocks[] -> audits[])
prefixed: {"decision":"audit","rule_id":"policy_audit_would_block:deny_shell_execution"} (evaluator.py:826)
```
`evaluator.py:57-64` warns *"Any new softening path MUST add its prefix here, or its would-blocks
become invisible to the dashboard."* The baseline-compile path is a softening path and does not add
one. This is the root cause of **BUG-002**; listed separately because the labelling inconsistency
also affects any future consumer that filters on `WOULD_BLOCK_RULE_PREFIXES`.

---

### BUG-021 · BUG-022 · BUG-023 · BUG-024 · BUG-025 · BUG-026 · BUG-027 · BUG-028

- **BUG-021** — `config.py:169` `evaluator_rate_limit_per_window=60` / 60s per SPIFFE id;
  `evaluator.py:350` keeps `rate_limit_exceeded` posture-exempt. First unpaced 200-call corpus run
  at 6 workers: `{'allow':112,'audit':1,'block':87}` — **43.5% dropped** in a namespace whose 14
  controls all read `monitor`. Read-prefix carve-out works (3/3). Two sub-facts: `NRVQ_RATE_LIMIT`
  in the ConfigMap maps to no settings field and is silently ignored; and the ceiling **is** a
  per-namespace setting exposed in the console (`Settings.tsx:205`, range 1..100000), so the
  "silent floor" framing was refuted — what stands is that 60/min is a functional limit and the
  counter key `callcount:{spiffe_id}` has no pod component, making it a budget shared across every
  replica of a ServiceAccount.
- **BUG-022** — `system_health.py:88-90` says `_POSTURE_EXEMPT_RULES` *"keeps it hard even in
  monitor mode"*. `_BASE_POSTURE_EXEMPT_RULES` is now `frozenset({"trust_frozen"})`; the very next
  block in the same file exists because `evaluator_error` **does** soften. The named symbol no
  longer exists (`evaluator.py:711` repeats the stale name).
- **BUG-023** — no `ORDER BY`; samples are first-come. Observed: control count 18, 13 (72%) from
  one tool, yet 4 of 5 samples were a different tool. The docstring claims samples are *"enough to
  see a pattern"*. Order by timestamp DESC or sample proportionally.
- **BUG-024** — `excluded_synthetic` increments before the would-block test, so allows and hard
  blocks from synthetic identities land in it. `ns/default` 30d: scanned 5930, excluded 21338 (78%
  of the window "excluded", almost none of it would-block). Arithmetic is correct (16 deliberately
  excluded rows moved it by exactly 16); the label is not.
- **BUG-025** — `baseline.py:166-169` caveat reads *"Only four of the five SDK adapters report call
  depth today; under CrewAI, AutoGen, LangGraph and Semantic Kernel a nested call reports depth
  0"*. The two clauses contradict each other and the measurement: exactly **one** (LangChain)
  reports depth. Served verbatim to the console, so an operator concludes the gap covers one
  adapter when it covers four.
- **BUG-026** — `http.py:114-144`: on any exception from `ControlPlanePinStore.load()` it logs
  NRVQ-MCP-5046 and returns, leaving `self._pins` on the per-process registry;
  `store.start_refresh()` is only on the success path. No retry timer anywhere in the module, so a
  proxy that starts during a brief control-plane blip runs on per-process TOFU pins for its entire
  lifetime. The class docstring frames the degradation as lasting *"for the duration of the
  outage"*; the code has no mechanism to end it.
- **BUG-027** — only 5 attacks carry an `mcp_vector`, covering 2 of the 4 evaluate-reachable
  vectors. `eval-cache-key-omits-mcp-context` is defensible (guarded by
  `tests/engine/test_cache_key_scope.py`, 7 passed). `resources-read-uri-gate` is the real gap: its
  own reason claims it is policy-reachable, nothing exercises it, and measured live
  `resources/read` with `uri=file:///proc/self/environ` → `allow / default_allow`. Repo-wide there
  is **no** `uri` reference in any shipped `.rego`; the one apparent hit
  (`uri=file:///etc/shadow` → `deny_shell_execution`) is an incidental substring match from the
  shell wordlist and fires identically on an unrelated tool with the string in an unrelated param.
- **BUG-028** — `_INFRA_RULE_IDS` (`system_health.py:61-107`) omits `evaluator_timeout` and
  `evaluator_invalid_payload` (and `rate_limit_exceeded`, `trust_frozen`,
  `invalid_spiffe_identity`). `evaluator_timeout` is the sharpest: a fail-closed refusal caused
  entirely by engine latency, exempt from softening per BUG-001, and absent from the operator's
  outage view. **Contested:** the curated set is pinned by an equality assertion
  (`tests/api/test_system_health.py:165-187`) with the rationale *"A policy doing its job is not an
  outage"* — which defends excluding `rate_limit_exceeded`/`trust_frozen`, but nobody defended
  excluding the three engine-minted verdicts.
