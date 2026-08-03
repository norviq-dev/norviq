# Implementation log — console redesign

Running record of what broke, why, and the rule learned. Appended each loop iteration.

A failure that recurs **after** being logged means the rule was wrong, not the fix.

Product decisions taken autonomously are recorded here too, with the reasoning, so they can be
overturned on their merits rather than rediscovered.

---

## Phase 0a — the vite config shadow

**What was wrong.** `ui/vite.config.js` and `ui/vite.config.d.ts` were tracked `tsc -b` emit artifacts
sitting beside `vite.config.ts`. Vite resolves `.js` first, so the committed copy was the config actually
in effect — and it had drifted. It was missing:

- `environmentOptions.jsdom.url = "http://localhost:59999"`
- `testTimeout: 30000` and `hookTimeout: 30000`

**Why it mattered.** jsdom then defaults its origin to `http://localhost:3000`, msw runs with
`onUnhandledRequest: "bypass"`, and `:3000` is exactly where this repo's own docs say to port-forward the
console. Any unmocked request became a real network call that nginx accepts and never answers, hanging
until timeout — so the suite's result depended on whether the developer had the console open. Separately,
the default 5 s `testTimeout` sat *below* `setup.ts`'s 15 s `asyncUtilTimeout`, the inversion that comment
explicitly warns against, which destroys testing-library's DOM dump on failure.

**Fix.** `composite: true` (required by the project reference) cannot be combined with `noEmit`, so the
emit was redirected to `node_modules/.tmp/` via `outDir` + `tsBuildInfoFile`. The two artifacts were
`git rm --cached`'d and gitignored.

**Rule learned.** *An emitted artifact that can shadow its own source must never be able to land beside
it.* Redirect the emit; do not rely on remembering to regenerate.

**Guard.** `ui/src/test/config-in-effect.test.ts`. Two assertions: the jsdom origin, and the absence of any
`vite.config.{js,mjs,d.ts}` beside the source.

**Verified by deliberate breakage** — I recreated a stale shadow and re-ran. Worth recording *which*
assertion fired: the **file-existence** check failed; the **origin** check still passed. So the origin
assertion alone would not have caught this. The cheap, direct check is the load-bearing one; keep both,
but do not trust the indirect one on its own.

---

## Product decisions taken autonomously

Recorded as they are made. Each is a call I made rather than stopping to ask, per instruction to run
autonomously and decide from a product/user perspective.

_(none yet)_
