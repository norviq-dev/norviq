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
  "tool_params": { "...": "caller-supplied dict, verbatim" },
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

`trust_score` is a weighted sum computed by `TrustCalculator` **before** OPA, then injected into the
input. Categories: high ≥0.70, medium ≥0.40, low >0.0, frozen = 0.0 (admin-only).

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
category `frozen`, and the Python layer overrides the decision to `block`. Low trust (<0.4) overrides
an `allow` to `escalate`. These overrides happen **outside** OPA, in
`OPAEvaluator._apply_trust_overrides`.

## Decision precedence (multiple matching policies)

Candidates are collected as `namespace:agent_class`, then `namespace:__baseline__`, then
`__cluster__:__baseline__`. `_resolve_precedence` sorts by **highest priority first**, then most
restrictive decision on ties (`block < escalate < audit < allow`). A high-priority cluster baseline
can therefore override a per-class policy — watch for stray seeded baselines.
