<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Norviq Contributors -->

# Namespace scoping convention

All namespace-scoped **list endpoints default to `namespace="default"`** when no param is given —
**fail-safe**: a forgotten/omitted param yields *incomplete* data, never an accidental cross-tenant
leak. Cross-namespace **admin** views ("show all namespaces") require an **explicit `namespace=all`
opt-in gated by RBAC** (auth batch) — they are never the default.

```python
namespace: str = Query("default")          # default-to-"default" (fail-safe)
# ... filter rows where the row's namespace == namespace
```

## Status by endpoint

| Endpoint | Convention | Notes |
|----------|-----------|-------|
| `/attack-paths` | `Query("default")` ✅ | filters `WHERE namespace = :ns` (data backfilled from asset_graph) |
| `/agents` | `Query("default")` ✅ | namespace parsed from the spiffe_id `.../ns/{ns}/sa/...` segment |
| `/policies` | `Query("default")` ✅ | filters on the `{namespace}:{agent_class}` loader key prefix |
| `/asset-graph` | `Query("default")` ✅ | filters by `asset_graph.namespace` |
| `/audit/*` | `Query(None)` → **all** ⚠️ | **known exception to align** — returns all namespaces when the param is omitted; safe only because the UI always passes namespace. Tracked in [backlog](../backlog.md). |

## Two layers — don't conflate them

- **Data scoping** (this convention): honor the `namespace` param; default-to-`default`. Shipped for
  attack-paths/agents/policies/asset-graph.
- **Authorization** (auth batch): enforce that the *caller* may access the requested namespace
  (bind to JWT/tenant claims). **Not yet enforced** — any valid token can request any namespace.
  `namespace=all` admin views must land here, behind RBAC.

## Header widgets

The header inbox/global-search call the no-param list functions, so they are now
**`default`-namespace-scoped** (tenant-safe), not a global view. A true cross-namespace admin
search is the `namespace=all` + RBAC work in the auth batch.
