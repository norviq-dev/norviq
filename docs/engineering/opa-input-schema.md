<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Norviq Contributors -->

# OPA Input Schema

Authoritative reference for the document OPA/Rego policies evaluate against. Built by
[`OPAEvaluator._build_input`](../../norviq/engine/evaluator.py) and logged as `nrvq.opa.input`
(code `NRVQ-ENG-DEBUG-OPA-IN`) when debug logging is on.

## Exact input keys

```json
{
  "tool_name": "execute_sql",
  "tool_name_normalized": "execute_sql",
  "tool_params": { "...": "caller-supplied dict, verbatim" },
  "tool_params_normalized": { "...": "same dict, string values confusable-folded" },
  "agent": {
    "spiffe_id": "spiffe://norviq/ns/<namespace>/sa/<agent_class>",
    "namespace": "default",
    "agent_class": "customer-support"
  },
  "trust_score": 0.62,
  "trust_category": "high | medium | low | frozen",
  "session_id": "sess-123",
  "call_depth": 0
}
```

That is the complete set of top-level keys. There is **no** `agent_identity` object — identity is
under **`input.agent`**. Writing `input.agent_identity.namespace` is a silent dead path (an
undefined reference makes the rule body fail, which reads as "allow"). Always reference
`input.agent.namespace`, `input.agent.agent_class`, `input.agent.spiffe_id`.

### The `_normalized` twins are for MATCHING, not for display

`tool_name_normalized` and `tool_params_normalized` are **confusable skeletons** of the name and of
every string value in the params (`norviq/engine/confusables.py::skeleton`, applied recursively by
`_normalize_for_match`): homoglyphs are folded to ASCII, zero-width characters are stripped, case is
normalized. Cyrillic `open_bгeaker` therefore arrives as `open_breaker`.

- **Match against the `_normalized` twin.** A rule that only inspects `input.tool_name` /
  `input.tool_params` is trivially evaded by a homoglyph or a zero-width joiner. The shipped packs
  match control verbs and injection strings against the skeletons — e.g.
  `energy.rego` blocks on `input.tool_name_normalized`, `threat_intent_sample.rego` derives its verb
  with `split(lower(input.tool_name_normalized), "_")[0]`.
- **Report/log the original.** `tool_name` / `tool_params` are preserved verbatim so the audit record
  shows what the caller actually sent. Never emit the skeleton as the reason string.
- Non-string values (numbers, booleans, nulls) pass through unchanged; the shape of
  `tool_params_normalized` always mirrors `tool_params`.

Both fields are masked (`mask_params`) before they reach any logger, so raw PAN/SSN/PHI in params
never lands in a log line even with debug logging on.

## What is NOT in the input (do not write rules that assume these)

| Field | Status | Where it actually lives |
|-------|--------|-------------------------|
| `frozen` flag | **Absent** | Enforced in Python from `agent_frozen:{spiffe_id}` Redis key; surfaces only as `trust_category == "frozen"` |
| raw velocity / `call_count` / rpm | **Absent** | Folded into `trust_score` via the session-velocity signal; only `call_depth` (chain depth) is a discrete field |
| first-class `tenant_id` | **Conditional** | Only present if the caller puts it in `tool_params`; it is not derived from identity |
| per-signal trust values | **Absent** | Only the aggregate `trust_score` + `trust_category` reach OPA |

## Caller `trust_score` is dropped by design

The `/api/v1/evaluate` router does `payload.model_dump(exclude={"trust_score"})` — any caller-supplied
`trust_score` is **discarded**. Trust is **server-recomputed** from Redis behavioral signals on every
call. This is a deliberate security boundary: a client cannot assert its own trustworthiness.
**Do not "fix" this by accepting caller trust.** To exercise low/frozen trust in tests, seed Redis
state (see the `frozen_agent` / `low_trust_agent` fixtures in `tests/attacks/conftest.py`), not the
request body.

> Related field-name gotcha: the request model field is `call_depth`. The attack `evaluate()` helper
> historically sent `chain_depth`, which is silently ignored — so `call_depth` stays 0. Mind the name.

## Debug toggle: `DEBUG_OPA=true` (not `NRVQ_DEBUG_OPA`)

The setting is declared with `validation_alias=AliasChoices("DEBUG_OPA_LOGGING", "DEBUG_OPA")`. A
Pydantic validation alias **bypasses the `NRVQ_` env_prefix**, so the variable that toggles it is
`DEBUG_OPA=true` (or `DEBUG_OPA_LOGGING=true`) — *not* `NRVQ_DEBUG_OPA`. With it on you get
`nrvq.opa.input`, `nrvq.opa.query.resolved`, and `nrvq.opa.subprocess_done` logs.

## Trust score = 7 weighted signals

`trust_score` is a weighted sum computed by `TrustCalculator`
([`norviq/engine/trust/calculator.py`](../../norviq/engine/trust/calculator.py)) **before** OPA, then
injected into the input. Categories: **high ≥ 0.70, medium ≥ 0.40, low < 0.40**.

`frozen` is **not a score boundary** — it is set only by the admin freeze flag. A *computed* score of
0.0 categorizes as `low`, never `frozen` (`_categorize` returns `"low"` on `score == 0.0` unless
`is_manually_frozen`). Behavior can never auto-freeze an agent.

| Signal | Weight | Source |
|--------|--------|--------|
| violation_rate | 0.25 | rolling block ratio (`agent_history:{spiffe_id}`) |
| tool_novelty | 0.20 | 7-day known-tools profile (`agent_profile:{spiffe_id}`) |
| scope_drift | 0.15 | class allow/block lists (`agent_class:{agent_class}`) |
| param_entropy | 0.15 | Shannon entropy vs per-tool baseline |
| time_decay | 0.10 | hours since last violation |
| chain_depth | 0.10 | `call_depth` |
| session_velocity | 0.05 | recent rpm vs `baseline_rpm` |

**Freeze:** set the `agent_frozen:{spiffe_id}` Redis key to any truthy value → score forced to 0.0,
category `frozen`, and the Python layer overrides the decision to `block` (`rule_id`
`trust_frozen`). Low trust overrides an `allow` to `escalate` (`rule_id` `escalate_low_trust`).
These overrides happen **outside** OPA, in `OPAEvaluator._apply_trust_overrides` — so a rule that
returns `allow` can still be enforced as `escalate`/`block`, and the audit record names the override,
not the rule that allowed.

**Two admin dials shift the boundaries** (both applied before the input is built, so OPA only ever
sees the final `trust_score` / `trust_category`):

- A per-namespace **`trust_threshold`** (resolved from the namespace's posture) moves the high
  boundary; the low boundary is derived proportionally (`low = high × 0.4/0.7`, clamped to [0,1]).
  With no override the literal 0.7/0.4 branch is taken.
- A durable admin **trust cap** — the `agent_trust_override:{spiffe_id}` Redis key — is applied
  **tighten-only**: `effective = min(computed, cap)`. An admin can push an agent toward escalate,
  never raise it above what its behavior justifies.

## Decision precedence (multiple matching policies)

Candidates are collected in two groups.

**Base (floor) candidates** — priority-resolved normally:

1. `namespace:agent_class`
2. `namespace:__baseline__`
3. `__cluster__:__baseline__`
4. `namespace:namespace:<namespace>` — the namespace tier (applies to every call in the namespace)
5. `namespace:deployment:<workload>` — the workload tier, only when the caller identifies its workload

`_resolve_precedence` sorts these by **highest priority first**, then most restrictive decision on
ties (`block < escalate < audit < allow`). A high-priority cluster baseline can therefore override a
per-class policy — watch for stray seeded baselines.

**Overlay candidates** — additive, absent by default, and **tighten-only**:

| Key | What it is |
|-----|------------|
| `namespace:__pack__` | enabled sector pack |
| `namespace:__pack_override__` | operator customization of the pack (tighten-only) |
| `namespace:__pack_weaken__` | admin-authored relaxation, scoped to the **pack family only** |
| `namespace:__guardrail__` | opt-in per-namespace tool allowlist (hard tighten-only) |
| `namespace:<agent_class>__remediation__` | per-class compliance-remediation control (hard tighten-only) |

`_resolve_with_packs` resolves base and overlays separately, then takes the overlay **only if it is
strictly more restrictive**. Consequences worth knowing before you author a policy:

- An overlay can never loosen a decision, *regardless of its priority*. Raising an overlay's priority
  does not let it turn a base `block` into an `allow`.
- `__pack_weaken__` can relax only the pack family. It can never relax a `__guardrail__` or a
  `*__remediation__` overlay, and the base policy remains a hard floor.
- Overlay-ness comes from a provenance flag stamped at candidate construction, not from the key
  string — a real `agent_class` that happens to end in a reserved `__…__` suffix keeps its normal
  priority-based precedence.
- `namespace=all` (the console's global picker) is not a real caller namespace; it resolves to the
  **union** of every namespace holding a policy for that class. Overlays stay tighten-only there too,
  so the union can never weaken a decision.
