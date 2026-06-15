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

(fill in after execution: commit SHA, before/after counts, test result, 66/66 baseline)
