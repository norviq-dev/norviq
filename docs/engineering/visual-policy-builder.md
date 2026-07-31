# Visual Policy Builder

A form-based authoring UI that lets an operator compose a Norviq policy without writing Rego, and
compiles it — deterministically, in the browser — into the same canonical Rego the engine already
enforces. It is additive: it sits on top of the existing `/policies` pipeline and changes no engine,
resolver, or evaluation behaviour.

**Status:** feature-complete MVP, verified end-to-end on a real cluster. Not yet merged to `main`.
**Branch:** `feat/visual-policy-builder-mvp` (based on `main` @ `2f18ae9`, v0.1.9).

---

## Why it exists

Authoring policy meant hand-writing Rego. That is fine for the people who wrote the engine and a
wall for everyone else — and a hand-written policy can be subtly wrong in ways that only show up in
production (a decision-less module, a rule that never fires, a policy that silently weakens the
baseline). The builder removes the Rego prerequisite and makes the dangerous shapes
*unrepresentable* rather than merely discouraged.

## Where it lives in the UI

**Policy Catalog** has exactly two create paths:

| Button | What it opens |
|---|---|
| **Visual Builder** | this feature — a guided form |
| **Advanced (raw rego)** | the existing Monaco editor, unchanged |

An earlier React-Flow drag-and-drop canvas was built and then **deliberately cut** — a Norviq policy
is a flat list of *conditions → decision* rules per scope, not a dataflow graph, so the node canvas
borrowed an aesthetic that fought the data. Both surfaces compiled to identical Rego via the same
compiler, so nothing was lost. Do not reintroduce it as a user path without revisiting that call.

## How to use it

The sheet is three numbered steps; later steps stay dimmed until the earlier one is valid, so there
is exactly one place to start.

1. **Who is this policy for?** — pick a scope tier (card), then fill its one identifier.
2. **What should it do?** — pick a policy mode, then add rules (or allowed tools).
3. **Check & enforce** — dry-run against real traffic, then save.

A plain-English sentence states the meaning as you build, with the exact loader key underneath so
nothing is hidden:

> Applies to every `report-gen` agent in namespace `default`.
> <sub>creates default / report-gen</sub>

### Scope tiers

| Tier | Loader key written | Applies to |
|---|---|---|
| Agent class | `<class>` | every agent of that class in the namespace |
| Namespace | `namespace:<ns>` | every agent in the namespace, whatever its class |
| Workload | `deployment:<name>` | agents of that Deployment only |

**Deployments only.** `resolve_policy_key` will happily mint `statefulset:foo`, but
`_collect_candidates` only ever looks up `deployment:<name>` — any other kind would be created and
then silently never enforced. The builder therefore offers Deployment and nothing else.

### Policy modes

- **Tighten-only rules** — adds blocks on top of what is already allowed. Non-matching calls keep
  their current outcome. Emits `package norviq.custom.<token>`.
- **Intent allowlist** — default-deny: everything for this scope is blocked except the tools listed,
  and only while the enabled refinements hold (read-only / no external egress / namespace-scoped /
  rate-limit). Emits `package norviq.intent.<token>`.

### Condition types

`Content detector` (injection / PII / secrets / destructive tool / shell) · `Keyword in tool params`
· `Param matches regex` · `Tool name is one of` · `Source + verb (capability)` · `Agent trust below`
— composable as OR-of-AND rows, each negatable with a NOT toggle.

---

## Architecture

```
BuilderSheet.tsx  ──edits──▶  BuilderGraph (the source of truth, a plain JSON document)
                                   │
                          compileGraph()  ← deterministic, pure, client-side
                                   │
                                   ▼
                    canonical Rego  ──▶  POST /policies/dry-run   (replay vs real traffic)
                                    └─▶  POST /policies           (save → loader → OPA)
```

| File | Role |
|---|---|
| `ui/src/lib/builderGraph.ts` | the graph types (scope tiers, modes, conditions) |
| `ui/src/lib/builderCompile.ts` | graph → Rego compiler, validation, budgets, detachment |
| `ui/src/lib/builderTemplates.ts` | detector predicates, extracted from `comprehensive.rego` |
| `ui/src/lib/capabilitySources.ts` | compile-time mirror of the Python capability registry |
| `ui/src/lib/skeleton.ts` | mirror of the server's confusable normalisation |
| `ui/src/components/policies/BuilderSheet.tsx` | the three-step UI |
| `ui/src/pages/PolicyCatalog.tsx` | entry buttons + the detachment badge |

### The graph is the source of truth

Compiled Rego carries its own graph, base64-encoded in a header comment, plus an FNV-1a hash of the
body:

```
# nrvq-builder-graph/v1: <base64 JSON>
# nrvq-builder-hash: <8 hex>
```

Reopening a policy rehydrates the exact graph. If someone hand-edits the Rego afterwards the hash
stops matching and `detachmentStatusOf()` reports **detached** — the Catalog shows a
"Hand-edited — detached from its visual graph" badge, because reopening it in the builder would no
longer reconstruct what is actually live. **There is deliberately no round-trip** from arbitrary Rego
back into a graph.

### Safety by construction

The builder cannot emit the shapes the write-gate rejects:

- always emits the canonical resolver (`blocks`/`escalates`/`audits` partial sets + deterministic
  precedence + a scoped `builder_default_<scope>` default) — a decision-less module is unrepresentable;
- every user string goes through `JSON.stringify` into a Rego string literal, so graph content cannot
  inject Rego syntax; comment interpolations are newline-stripped;
- client-side budget meter mirrors the server caps (65536 bytes / 500 lines / 25 regex ops);
- **reserved scopes are refused** — `__baseline__`, `__pack__*`, `__guardrail__`, anything matching
  `^__.*__$`, any `:` in a class name, and `__cluster__` as a namespace produce a compile error and
  *no* Rego. This matters: the API **accepts** `__baseline__`/`__guardrail__` on create (200) but
  **refuses to delete them** (422), so without this guard a mistyped scope became a permanently
  unremovable policy.

### Namespace honesty

Under the global "All namespaces" view the builder requires a concrete target namespace before it
will dry-run or save, and always shows the namespace and key it will write. It never silently
defaults to `default`.

---

## Verified

Off-cluster: 477 vitest specs, `tsc`, eslint and `vite build` clean; every compiled fixture passes
`opa check --v0-compatible`.

On a real cluster (kind, Helm-installed, 6/6 pods ready) the shipped posture with no policy is
fail-closed — every call returns `block · no_policy_loaded`. An allowlist policy authored by the
builder flipped that:

| Call | Before | After |
|---|---|---|
| `get_order` (allowlisted) | `block · no_policy_loaded` | `allow · intent_allow_<class>` |
| `delete_kb` (not listed) | block | `block · intent_default_deny` |
| same tool, another class | block | unaffected |

Tighten-only mode likewise: the authored rule blocked its tool (`block · r_block`) while
non-matching calls fell through to `allow · builder_default_<scope>`. Namespace-tier policies were
confirmed to fire for *every* class in the namespace and for no class outside it.

## Known gaps

1. **Sidecar interception is unproven.** The cluster run had the injecting webhook disabled, so what
   is verified is the decision path (API → loader → OPA → verdict), not a real agent pod having a
   tool call physically prevented by an injected sidecar. Close this next.
2. **No `graph_json` column.** The graph rides in a header comment. A production version should
   persist it as structured data so the backend can index/migrate it and verify detachment
   server-side. That is a backend PR (`policies` table + `PolicyCreate`).
3. **Capability registry is mirrored, not fetched.** `capabilitySources.ts` is a hand-maintained
   copy of the Python `_REGISTRY`; it will drift. The fix is a real `/api/v1/capability/sources`
   endpoint.
4. **Detector templates are copies.** They are extracted from `comprehensive.rego` because the write
   gate forbids cross-package `data.*` references. If the shipped detectors change, these drift —
   the intended guard is build-time extraction plus golden `opa test`.
5. **Reduced detector fidelity.** The SQL/shell templates omit the base64-decode chain, and
   prompt-injection keeps the pattern-list and override/context clauses only. Base64-wrapped payloads
   are not unwrapped by builder-authored policies.
6. **Client skeleton is partial.** `skeleton.ts` folds fullwidth/compatibility/accents/case but not
   the server's cross-script confusables table, so `allow_names` (exact, lower-cased) remains the
   primary allowlist match and `allow_skeletons` is defence-in-depth only.

## Gotchas that will cost you an hour

- **The first `/evaluate` right after a save can be wrong.** OPA recompiles its module store on
  policy push, so the immediate call may return `block · evaluator_timeout` or a stale decision.
  Re-issue before concluding anything. Fail-closed, so it is safe — just misleading.
- **`ui/vite.config.js` is a tracked compiled artifact that shadows `vite.config.ts`.** Editing only
  the `.ts` silently does nothing. Change both, and keep dev-only proxy edits out of commits.
- **`allow_names := {…}` must use `:=`.** `coverage.py`'s regex only matches that form; emitting `=`
  compiles and enforces identically but makes the Overview show an intent policy with an empty
  allow-list.

## Running it locally

Postgres and Redis via `docker compose -f docker-compose.dev.yml up -d`, the API with
`uvicorn norviq.api.main:app` (OPA self-spawns when `NRVQ_OPA_URL` is unset), and the UI with
`npm run dev` in `ui/`. Point the Vite proxy at whichever port the API is on — remembering the
`vite.config.js` shadowing above. Bootstrap an admin with
`python -m norviq.api.admin_reset`, which forces a password change on first login.
