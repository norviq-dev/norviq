<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Norviq Contributors -->

# Test Baseline Discipline

How to measure the attack-suite baseline without lying to yourself.

## AKS is the source of truth; local drifts

The authoritative baseline is the suite running against the **AKS** cluster. Local Postgres/Redis
accumulate state across runs and **drift** — stray policies, leftover agent history, stale eval
cache. A green local run does not imply a green cluster run, and a red local run is often local
pollution, not a code regression. When local and AKS disagree, **AKS wins**; investigate the local
drift before "fixing" code.

## Baseline: 66/66

The `tests/attacks/` suite must be **66 passed, 0 failed, 0 xfailed**. `xfailed` is not "fine" —
per [bug-patterns.md](bug-patterns.md) (P-7), an `xfail` from a connection error is a masked failure.
A real 66/66 has zero xfails.

## Verify cluster HEALTH before measuring

A baseline measured against an unhealthy or half-rolled cluster is meaningless.

1. All pods `Ready` (`kubectl get pods -n norviq`) — and Ready for real, not racing
   (see P-14 in [bug-patterns.md](bug-patterns.md)).
2. Postgres reachable and migrated to head; Redis answers `PING`.
3. Only the **intended** policies are seeded (see drift check below).

## Verify image SHA matches HEAD after deploy

Old pods serve stale traffic (P-10). After any deploy, confirm the running image SHA equals the
commit you intend to test — otherwise you are measuring old code:

```
kubectl get pods -n norviq -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.spec.containers[0].image}{"\n"}{end}'
```

Match the tag/SHA to `git rev-parse HEAD`. If they differ, the baseline is invalid.

## Local drift check (Postgres policy pollution)

The official local seed (`scripts/seed-local-policies.py`) creates **only** `default:customer-support`.
Anything else under high priority — especially a `__cluster__:__baseline__` default-`block` policy
left over from `test_priority_enforcement.py` — will override `comprehensive.rego` via precedence and
**block every safe operation**, cascading into a block-history feedback loop. Before measuring:

```sql
SELECT namespace, agent_class, priority, enforcement_mode FROM policies ORDER BY priority DESC;
```

Expect `default:customer-support` (priority 700) to be the top relevant policy. Remove stray
cluster/baseline rows and clear runtime keys (`eval:*`, `agent_history:*`, `agent_profile:*`,
`agent_class:*`, `agent_frozen:*`, `trust:*`) before a clean run, then restart the API so its
in-memory policy cache re-warms from the clean DB.

## Guard tests are sacred

These prove the rules don't over-block (false positives). They MUST stay green; if a new rule breaks
one, **narrow the rule**, never weaken the guard:

- `test_same_tenant_allowed`
- `test_no_tenant_field_allowed`
- `test_normal_rate_allowed`
- `test_safe_select_allowed`
- `test_split_across_params`

## Per-feature workflow

1. Add/modify the Rego in `comprehensive.rego`; validate **each** rule with
   `opa eval --v0-compatible --data comprehensive.rego --input <case>.json data.norviq.strict`
   for both the target payload and every guard payload.
2. For trust-driven behavior, seed Redis state via fixtures — never via caller `trust_score`
   (see [opa-input-schema.md](opa-input-schema.md)).
3. Re-seed: `python scripts/seed-local-policies.py`; restart the API.
4. Run the full suite; require 66/66 with **0 xfailed**.
5. Confirm the five guard tests above are in the passing set.
6. Promote the change to AKS and re-measure there (source of truth).

## Windows note: ephemeral-port exhaustion

Rapid back-to-back full runs can surface `WinError 10048/10055` (ephemeral-port/TIME_WAIT
exhaustion) that masquerades as `xfail`. The attack `api` fixture is **session-scoped with a bounded
keep-alive pool** to avoid this; a stray xfail under repeated runs is environmental, not a logic
failure — let sockets drain and re-run.
