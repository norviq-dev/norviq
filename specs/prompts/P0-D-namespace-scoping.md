# P0-D — Namespace scoping for agents + policies-list

**Date:** 2026-06-15
**Work item:** P0-D (from UI production-readiness gap analysis)
**Goal:** Backend namespace filtering for agents + policies-list endpoints.
          UI already threads namespace; these two endpoints ignore it, leaving
          the multi-tenant claim incomplete. Same pattern as the attack-path leak fix.

## Prompt

PART 1 — P0-D: namespace scoping (the work)

STEP 1 — Confirm the gap (verify live, don't assume):

    curl .../api/v1/agents?namespace=default  vs  ?namespace=payments
    curl .../api/v1/policies?namespace=default vs ?namespace=payments
    Confirm both ignore namespace (same counts regardless of ns). Report.

STEP 2 — Inspect endpoints + data model:
    grep list_agents / /agents / scan_iter trust / agent_registry in agents.py
    grep list_policies in policies.py
    grep namespace / agent_registry / class AgentRegistry in models.py
    For each: where does data come from? does namespace exist to filter by?
    (agents: Redis trust:* scan or agent_registry table? spiffe_id encodes ns as
     spiffe://norviq/ns/{ns}/sa/...; policies: keyed {namespace}:{agent_class})

STEP 3 — Apply namespace filtering (same pattern + default convention as attack-paths/audit):
    AGENTS: honor ?namespace= — filter by ns (parse from spiffe_id ns segment, or
            WHERE namespace column if agent_registry has one).
    POLICIES-LIST: filter where policy key starts with {namespace}: .
    DEFAULT convention: no namespace param -> scope to "default" (consistent with
            attack-paths/audit). Be consistent with what you just shipped.

STEP 4 — Header widgets (don't over-engineer):
    Header inbox/global-search (fetchAllAgents/fetchPolicies/fetchAuditRecordsByTool)
    are global. Decide: scope them to current namespace, OR leave as intentional
    cross-namespace admin view. Note the decision, move on.

STEP 5 — Test:
    Add to tests/integration/ (extend isolation test or new file):
    - agents?namespace=default vs payments -> correctly scoped / disjoint
    - policies?namespace=default vs payments -> only that ns
    - nonexistent namespace -> empty
    - fail-before / pass-after

STEP 6 — Verify local then AKS:
    Local: re-run Step 1 curls -> counts now DIFFER by namespace. Test passes. 66/66 baseline.
    Commit + push, then verify on AKS the same way.

RULES:
- Same namespace pattern + default-to-"default" convention as attack-paths/audit
- DATA scoping only — namespace AUTHZ (any token any ns) stays in the auth batch
- Don't over-engineer header widgets — decide scope-or-global and note it
- Save the prompt to the archive (Parts 0 + 0.5) as part of this work
- Do NOT commit until I review

## Outcome

**Commit:** `96d060e20b6bc020b9f489030ee7171c8a872341` — `fix(P0-D): namespace-scope agents + policies-list endpoints`
**CI:** Build & Push ✅, Deploy to AKS ✅
**Date completed:** 2026-06-15

**Fix:** `agents.py` parses the namespace from the spiffe_id (`.../ns/{ns}/sa/...`) and filters;
`policies.py` filters on the `{namespace}:{agent_class}` loader-key prefix. Both use
`Query("default")` — the project-wide **default-to-'default' fail-safe** convention (a forgotten
param yields incomplete data, never a cross-tenant leak). `namespace=all` admin opt-in deferred to
the auth/RBAC batch. Convention documented in `docs/engineering/namespace-scoping.md`; the audit
`Query(None)` inconsistency flagged in `docs/backlog.md`.

**Before → after:**
| | policies | agents |
|---|---|---|
| Local before | 15 / 15 / 15 (default/payments/nonexistent) | unfiltered |
| Local after | 1 / 2 / 0 | 1 / 1 / 0 |
| AKS after | 1 / 0 / 0 | 1 / 1 / 0 |

**Tests:** new `tests/integration/test_namespace_list_scoping.py` (agents + policies scoping,
fail-before/pass-after) passes; full attack baseline **66/66** held.

**Header decision:** inbox/global-search now default-namespace-scoped (was global) — tenant-safe;
cross-namespace admin search deferred to the auth batch.

**Notes:** started the committed prompt archive (`specs/prompts/`, un-ignored in `.gitignore`).
