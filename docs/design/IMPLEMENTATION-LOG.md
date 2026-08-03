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

### D1 — Reinstall the kind release rather than repair it

**Found.** `norviq-local` came back with helm revision 6 stuck in `pending-upgrade` (an interrupted
`helm upgrade` from two days ago), pods in `Unknown`, image tags from the MCP demo work
(`…norviq-engine:api-mcp-v4`, `ui-mcp-v3`), and a `kubectl set image` override on `norviq-ui` that took
field-manager ownership — so `helm rollback` fails with an apply conflict.

**Decision.** `helm uninstall` and reinstall clean with `values-light.yaml` and freshly built local
images, keeping the kind node itself.

**Why.** The e2e suite's whole value is that a red result means the product is wrong. A cluster carrying
a stuck release, hand-set images and a two-day-old datastore cannot deliver that — every failure would
first have to be proven not to be residue. Repairing costs about as much as reinstalling and leaves the
provenance question open. Recreating the *node* as well was rejected: the mess is entirely in the
release, and the node rebuild buys nothing.

The datastore is deliberately discarded. Deterministic Tools-page data has to be seeded fresh anyway, and
the observed tier is time-windowed, so stale audit rows would age out of the assertions mid-run.

**Also applied here:** `values-light.yaml` drops the API to 1 replica. The chart defaults to 2, and verb
promotion does not propagate between replicas (no pub/sub, no refresh) — with 2 replicas a promotion
flaps depending on which replica serves the read.

---

## Phase 0b — the kind node kept disappearing, and it was disk

**What happened.** `norviq-local-control-plane` had exited with code 137 (killed). I restarted it, it
came up Ready, `kubectl` worked. Ten minutes later — after four `docker build`s — the container was gone
entirely, not stopped: `kind get clusters` no longer listed the cluster and `kind load` failed with
`no nodes found`.

**Root cause.** The host volume was at **96% (9.2 GiB free)** while Docker held 31 GB of images and
11.8 GB of build cache. The builds consumed the remaining headroom and Docker reclaimed space by removing
stopped containers — taking the exited kind node with it. The original exit-137 was the first symptom of
the same pressure, not an unrelated event.

**Fix.** `docker builder prune -af` (14.4 GB) and removal of 36 superseded `norviq-engine-dev:*` /
`norviq-engine:*-mcp-*` tags, all of which are either already pushed to ghcr or rebuildable from source.
Free space 9.2 → 22 GiB. Then recreate the cluster.

**Rule learned.** *Check host disk before a multi-image build, not after the cluster vanishes.* An
environment that silently deletes containers under pressure produces failures that look like
infrastructure bugs — `kubectl` succeeding minutes before `kind` reports no nodes is not a kind bug, it
is a disk symptom. The `00-up.sh` script should preflight free space and refuse to build below a floor.

**Mistake I made and should not repeat.** I ran the first `kind load` sweep with `2>/dev/null` on both the
direct and fallback paths, so all four images reported a generic "ARCHIVE FAILED" and I could not tell
*why*. The real error — `no nodes found for cluster` — was one unsuppressed run away and pointed straight
at the cause. **Do not suppress stderr on a step whose failure you have not yet seen.**

### D2 — Build the bootstrap image rather than disable internal TLS

**Found.** The first clean install failed on the `norviq-internal-tls` **pre-install hook**:
`ImagePullBackOff` on `norviq/norviq-engine:bootstrap-latest`. Five images are needed on a local cluster,
not four — the bootstrap job is easy to miss because it is a hook, not a Deployment. My global
`--set images.registry=norviq/` had also redirected it, so it could not fall back to ghcr.

**Decision.** Build and load `Dockerfile.bootstrap` (a fifth image) rather than set
`config.internalTls.enabled=false`.

**Why.** `values.yaml` says of that flag: *"Set false only for a plaintext dev cluster."* This is not a
dev cluster — its only purpose is to decide whether the product is correct. Internal TLS is default-on
and sits directly on the API path the console talks to, so switching it off would make every green result
mean "correct, on a topology we do not ship". One extra `docker build` is a much cheaper price than a
weaker signal. **Rule: never disable a default-on plane to make a test environment start.**

**Follow-on for `00-up.sh`:** the bring-up script must build **five** images and preflight free disk
before it starts.

---

## Phase 0c — the seeder, and a trap whose *default* is the wrong answer

**The trap.** `EvaluateRequest.framework` defaults to **`"redteam"`** (`routers/evaluate.py:35`), and
`audit_row_is_non_real` excludes `framework == "redteam"`. So the natural way to seed observed traffic —
POST `/evaluate` and let the defaults ride — writes rows that every real-traffic surface, including the
Tools page's observed tier, then deliberately hides. The row exists in the database and does not exist
in the UI, which reads exactly like a product bug in the page you just wrote.

This is the *same* filter as the known `e2e-*` agent-class trap, reached by a different door, and the
door is the default value. Both are now pinned in `scripts/kind-e2e/seed.py` with the reasoning inline.

**Rule learned.** *When a filter exists to hide synthetic traffic, check every field it keys on — one of
them will be a default you did not set.*

### D3 — A purpose-built seeder rather than `mcp-chatbot-scenario.sh`

**Decision.** `scripts/kind-e2e/seed.py`, not the existing scenario script, for e2e fixtures.

**Why.** The scenario script is the right tool for demonstrating the MCP firewall — it builds an image,
rolls the API onto it, and drives four real servers. As a *fixture* it is the wrong shape: slow, it
re-rolls a Deployment every run, and it yields whatever the scenario yields. Assertions need the
opposite — exact, repeatable rows including the states that are easy to get wrong.

The seeder deliberately produces the four awkward states, each verified live on the cluster:

| Row | State it pins |
|---|---|
| `slack/send_dm` | one schema hitting all four `schemaPaths()` outcomes — addressable string, addressable NESTED string, non-addressable integer, non-addressable array |
| `slack/post_message` | critical scan ⇒ `description_withheld`, so the console must show the fact without the text |
| `warehouse/bulk_export` | a padded description that genuinely evicts `inputSchema` past the 8 KiB slice ⇒ declared, pinned, **unscopeable** |
| `filesystem/read_file` + `runbooks/read_file` | one name, two servers — the case that breaks any row keyed on `tool_name` alone |
| `sеnd_email` (observed) | Cyrillic `е`, so `name_skeleton` ≠ `name` and the homoglyph signal has a real subject |

Result on the cluster: 14 rows, 10 declared / 4 observed, all five states confirmed via the live API.

