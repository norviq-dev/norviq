<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Norviq Contributors -->

# Namespace scoping & tenant isolation

Norviq's read APIs (Audit, Agents, MITRE/compliance coverage, Asset & Attack graph, Policies) are
namespace-scoped and enforce tenant isolation at the **authorization** layer — not merely by convention.

## How a request is scoped

Every scoped endpoint resolves the effective namespace through a single helper
(`read_namespace` / `scoped_namespace` in `norviq/api/auth.py`), which pins the caller to what its
role and JWT namespace claim allow:

- **Admin** (or a token whose namespace claim is `*`) may read any namespace; a request for "all
  namespaces" (`namespace=all`, or an omitted param) returns the whole cluster.
- **A tenant-scoped token** is pinned to the namespace in its claim. A request for a different
  namespace — or for `namespace=all` — resolves to its own namespace; it can never read another
  tenant's data through the query param.
- **A non-admin token with no namespace claim** (the least-privilege floor) receives **403**, not data.

So an omitted or forgotten `namespace` param is fail-safe: it never widens a caller's reach beyond
what its role and claim already permit.

## Two layers — don't conflate them

- **Data scoping** — the `namespace` query param selects which tenant's rows to return.
- **Authorization** — `read_namespace` / `scoped_namespace` enforce that the *caller* may see the
  requested namespace, bound to the JWT role + namespace claim. Cross-namespace ("all") views are
  admin-only.

The header inbox and global search are scoped through the same helper, so they are tenant-safe
rather than a global view.
