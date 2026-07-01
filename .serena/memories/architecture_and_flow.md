# Architecture & Runtime Flow

## /api/v1/evaluate flow (the hot path)
1. Request → `routers/evaluate.py` (JWT auth required; caller-supplied `trust_score` is **discarded** via `model_dump(exclude={"trust_score"})`).
2. `OPAEvaluator.evaluate(event)`:
   - Resolve identity (SPIFFE).
   - Compute trust (7 signals) or read `trust:{spiffe_id}` cache.
   - Cache-first: `policy:{ns}:{class}` and `eval:{ns}:{class}:{sha256(sorted_params)}`.
   - On miss, collect candidate policies, run `opa eval` subprocess once per candidate.
   - Resolve precedence: highest priority first, then most restrictive (block < escalate < audit < allow).
   - Apply trust overrides **in Python, outside OPA**: frozen → block; trust < 0.4 → allow becomes escalate.
3. Fire-and-forget audit → Postgres `audit_log` + OTel span.
4. Return `PolicyDecision {decision, rule_id, trust_score, ...}`.

## OPA input schema (authoritative: docs/engineering/opa-input-schema.md)
```json
{
  "tool_name": "...",
  "tool_params": { ... },
  "agent": { "spiffe_id": "...", "namespace": "...", "agent_class": "..." },
  "trust_score": 0.62,
  "trust_category": "high|medium|low|frozen",
  "session_id": "...",
  "call_depth": 0
}
```
**CRITICAL:** identity is under `input.agent`, NOT `input.agent_identity`. Writing the wrong path =
silent dead rule that always allows (this caused a real cross-tenant bug). Always test positive AND
negative cases for any field-path rule. Query path is `data.norviq.strict`.

## Trust score = 7 weighted signals (sum to 1.0)
violation_rate 0.25 · tool_novelty 0.20 · scope_drift 0.15 · param_entropy 0.15 ·
time_decay 0.10 · chain_depth 0.10 · session_velocity 0.05.
Categories: high ≥0.70, medium ≥0.40, low >0.0, frozen =0.0 (Redis key `agent_frozen:{spiffe_id}`).
Signals read Redis: `agent_history:{spiffe_id}`, `agent_profile:{spiffe_id}`, `agent_class:{class}`, `trust:{spiffe_id}`.

## Decision precedence candidates
`namespace:agent_class` → `namespace:__baseline__` → `__cluster__:__baseline__`.

## External dependencies
Redis (cache/pubsub/trust), Postgres (asyncpg; policies/audit/agents/graphs), the `opa` binary
(subprocess), SPIFFE/SPIRE (mocked locally), OTel collector (optional), Prometheus.

## Error code families (NRVQ-XXX-NNNN)
SDK-1xxx, ENG-2xxx, SDC-3xxx, WHK-4xxx, REG-5xxx, AUD-6xxx, API-7xxx, CLI-8xxx, DB-9xxx,
IDT-10xxx, GRP-11xxx, TEL-*. Full map: docs/error-codes.md.

See also: [[dev_setup_and_run]] for the OPA-binary gotcha that makes every eval fail closed.
