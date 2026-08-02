# Cross-compiler fixtures

Two compilers now produce Rego for overlapping intent semantics:

| | source | language | package |
|---|---|---|---|
| Visual Policy Builder | `ui/src/lib/builderCompile.ts` | TypeScript, in the browser | `norviq.intent.<token>` (allowlist mode) |
| Declared intent | `norviq/engine/intent/compiler.py` | Python, on the server | `norviq.intent.<class>` |

They have no shared source of truth, each has its own passing suite, and both implement the same
idea — *an allowlist of tool NAMES is not an intent; you must scope the ARGUMENTS*. That is exactly
the setup in which two implementations drift apart silently.

Each fixture here states **one logical policy twice** — once as a declared intent, once as a
`BuilderGraph` — plus the calls to evaluate and the decision both must reach. Two tests consume them:

- `tests/engine/test_cross_compiler_parity.py` compiles the `intent` half with the real Python
  compiler and evaluates with the real `opa`.
- `ui/src/lib/crossCompilerParity.test.ts` compiles the `graph` half with the real TypeScript
  compiler and evaluates with the real `opa`.

**Decisions are compared, never text.** The two modules legitimately differ in shape — the intent
compiler emits `_predicates`/`_failed` for its near-miss explainer, the builder emits `allow_names`
and refinement helpers. Asserting on strings would pin an irrelevance and fail on every cosmetic
change; asserting on decisions pins the only thing that matters.

## Adding a fixture

Put it in this directory as `<name>.json`:

```jsonc
{
  "name": "...",
  "why": "the property this pins, in one sentence",
  "intent": { ... },                 // input to norviq.engine.intent.compile_intent
  "graph":  { ... },                 // input to compileGraph (allowlist mode — see below)
  "cases": [ { "note": "...", "input": { ... }, "expect": "allow" | "block" } ]
}
```

`input` is a full OPA input document, shaped the way `evaluator._build_input` builds one. Both
compilers see the identical document, so a fixture cannot accidentally give one side an easier job.

## Why the graph half is allowlist mode

Only allowlist mode is comparable. An intent is **default-deny** — it allows what it states and
denies everything else. The builder's *rules* mode is default-allow with tighten-only block rules, so
the same fixture would mean opposite things on the two sides. Allowlist mode is default-deny too, so
the comparison is like-for-like.

## The known gap, deliberately recorded

`data_classes`, `destinations.*`, `sql_tables` and `param_bytes` are expressible by the intent
compiler and, since the scoping-facts work, by the builder's **rules** mode — but not yet inside an
allowlist **grant**. Fixtures needing them set `"graph": null` and assert the intent side only.
`test_every_fixture_is_covered_by_both_sides_or_says_why` fails if a `null` graph appears without a
`gap` field explaining it, so the gap stays visible instead of quietly becoming permanent — and when
allowlist grants gain those conditions, filling `graph` in is the whole change.
