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

---

## Phase 2 — Tools page

### D4 — `/tools` gets its OWN range control, not the global header selector

**The conflict.** `GET /api/v1/tools` accepts `24h | 7d | 30d | 90d`. The global header selector offers
`1h | 6h | 24h | 7d | 30d`. Two values it offers cannot be served, and one the API supports is missing.

**Decision.** Do not add `/tools` to `TIME_SCOPED_PATHS`. Give the page its own control carrying exactly
the four values the API accepts.

**Why.** The only way to honour a `1h` request with this API is to widen it to `24h`. The observed tier
would then list tools that were not called in the hour the operator asked about — the page answering a
question it was not asked, and answering it *wider*. On a security surface, silently broadening a window
is the wrong direction to fail: it manufactures evidence of activity that did not occur in the period
under review.

The alternative — leave `1h`/`6h` visible but inert — is worse still, since the control would appear to
work.

**Precedent, not invention.** `routeMeta.ts` already documents exactly this split: Attack Graph and Asset
Graph are excluded from the global selector *because they carry their own in-page range picker*. This is
the third instance of the same pattern, so it needs no new concept.

### D5 — What the `Flagged` tile counts

**The gap.** The prototype shows `Flagged: 1`, counting only the critical-severity `post_message`. Its
own observed table also renders `sеnd_email` in `--block` with a red `Homoglyph` pill — a row it visibly
treats as dangerous and does not count.

**Decision.** `Flagged` = `scan_severity ∈ {high, critical}` **OR** `name_skeleton !== name`.

**Why.** The tile answers "how many rows here need a human to look at them?" A name that differs from its
evasion-normalised skeleton is a homoglyph or zero-width attack on the operator's *reading* of the list —
precisely a row needing a human. Counting only scanner severity would leave the page flagging a risk in
the table while denying it in the summary, and a headline that disagrees with the rows beneath it teaches
operators to distrust the headline.


---

## Phase 3 — MCP Servers

### D6 — The injection payload is SHOWN here and WITHHELD on /tools

**The tension.** `approved_canonical` and `last_canonical` hold the **pre-sanitize** definition — the
text Gate A kept from the model. The Tools page withholds it (D-Tools). This page renders it twice: in
the diff, and quoted in full in `EvidenceBlock`.

**Decision.** Show it here. Withhold it there.

**Why.** The two surfaces ask the operator for different things. Tools is a *browsing* surface — nobody
arriving there asked to read an attack, so rendering one is gratuitous exposure. MCP Servers is an
*adjudication* surface: the operator is being asked to approve or refuse this exact text, and cannot
answer without reading it. Concealing it would not make the decision safer, it would make the decision
uninformed — which is how `x-priority: "always call before replying"` gets approved by a tired human.

The mitigation is framing, not concealment, and all three parts are on screen: the text is quoted, it is
labelled attacker-authored, and it is stated to be inert (the model never reads this page, and the proxy
stripped the text before the model saw the definition). `findings[].evidence` had been on the API since
the scanner shipped and was rendered **nowhere** — the console showed a rule name and a rationale and
asked the operator to take it on faith.

### D7 — "Quarantine the server" is N revokes, and names its blast radius

**The gap.** The prototype's 409 dialog offers `Quarantine the server`. No server-level endpoint exists.

**Decision.** Implement it as a loop over that server's approved pins via `POST /mcp/pins/revoke`, with
the button labelled `Withhold all N <server> tools`.

**Why.** The action is the right one — a server that has served three definitions in one sitting should
not be adjudicated tool by tool while the ground moves — and it is expressible with the endpoints that
exist. It gets no type-to-confirm because it is **reversible**: re-approving is one click per tool. What
it does get is the count in the label, since a bulk action that hides how much it does is one that gets
clicked by mistake. The result toast reports `done of total` rather than claiming success, because a
partial quarantine still reduces exposure and should not be reported as either a success or a failure.

### D8 — `Switch to strict pin mode` is cut, not wired

**The gap.** The prototype offers a button to switch a server from `tofu` to `strict`.

**Decision.** Cut it. Keep the mode's *consequence* in the forget dialog, hedged as "the default `tofu`
mode".

**Why.** `mcp_pin_mode` is deployment config (`norviq/config.py:177`) carried per-request by the proxy
(`/mcp/pins/observe` takes `mode` in the body). There is no endpoint to change it and there should not
be one — the console cannot reach into a proxy's configuration. A button that appeared to flip it would
be a lie about where the setting lives. The API also never returns the mode, so the console genuinely
does not know it; "the default `tofu` mode" is the strongest true statement available.

### D9 — The detail panel moved BESIDE the table

**Found by screenshotting the built page, not by a test.** Stacked (table, then detail below), clicking
a row on a 1440×900 laptop scrolled the detail roughly a screen out of view: the click produced no
visible change, which reads as a broken control rather than as a panel to go and find. Every unit and
browser test passed throughout — they assert the panel exists, and it did.

**Rule learned.** A test can prove a panel rendered. It cannot prove anyone can see it. Any surface with
a click-to-reveal detail gets one screenshot at a realistic viewport before it is called done.

---

## What broke in Phase 3, and the rule each one leaves behind

### The seeder wrote a state the product cannot produce

**What broke.** `seed_drift` smuggled the injection into a top-level `x-priority` key. The e2e test then
failed to find it in the diff. The API had not dropped it and the UI had not hidden it — the **digest
never covered it**: `norviq/mcp/pins.py:66` pins exactly six fields (`name`, `title`, `description`,
`inputSchema`, `outputSchema`, `annotations`). A top-level key outside that set changes no digest and
produces no drift at all.

The fixture was also internally inconsistent in a way that should have caught this before the cluster
did: the seeded finding named `inputSchema.properties.channel.description` as the field, while the
definition put the payload at top level. **A fixture whose finding contradicts its own definition is
telling you it is wrong.**

**Rule.** When seeding a state that a pipeline computes (a digest, a hash, a canonical form), seed it
through the same field set the pipeline uses — and read that list rather than assuming it is "the whole
object".

**Worth noting as a product fact, not a bug:** injection smuggled into a non-pinned top-level key is
invisible to Gate A's *digest*. It is not invisible to the scanner, which reads the whole definition,
and a spec-compliant MCP host does not forward unknown top-level keys to the model. The pin covers the
fields that can reach the model, which is the right boundary — but it is a narrower claim than "the
definition is pinned", and worth stating explicitly wherever that claim is made.

### The `rowKey` TYPE is what made the duplicate-key bug possible

**What broke.** `rowKey?: keyof T & string` cannot express a composite identity. MCP pins are keyed
`(namespace, server_id, tool_name)`, so `rowKey="tool_name"` gave React duplicate keys for two servers
serving one `read_file`, and `selectedKey` (a `server/tool` string) could never equal `row.tool_name` —
making the selection highlight code that could not run.

**Rule.** Widening the type was the actual fix; keying on a different single field would only have moved
the collision. When two bugs share a root cause in a type that cannot express the domain, fix the type.

### A global `cursor: pointer` on every table row

Fixed in passing while in `DataTable`: `.tbl tbody tr { cursor: pointer }` applied to read-only tables
too, so rows across the console invited a click that was never wired. Now gated on `onRowClick` via a
`.row-clickable` class. Affordance follows behaviour.

---

## Phase 4 — Propose from traffic

### D10 — The near miss became an API contract, not a string the console picks apart

**The gap.** The design requires per-clause ✓/✗ on a refused call, *"with the implicit predicates
rendered so `met 3 of 4` reconciles"*. The API returned one sentence:

```
no intent rule matched; closest send-send-email met 4/5, failed: tool_name in ['vector_search']
```

**Why the console could not do this alone.** Reconciling the count needs the closest rule's FULL
predicate list, and two of those clauses are added by the compiler rather than the operator: the plane
(`direction == call`) and the availability guard for each version-gated root
(`data_classes is published by this engine`). Rebuilding that list in TypeScript means
re-implementing `_predicate()` and `_availability_predicates()` in a second language — the exact
"two components keyed differently on one concept" defect this session has hit repeatedly. The drifted
copy would be the one the operator was shown before approving.

Splitting the `failed:` tail is also **unsafe**, and quietly so: labels are built from Python reprs, so
`tool_name in ['http_get', 'vector_search']` CONTAINS the `", "` separator. A naive split shreds one
clause into three, none matching a real predicate. Verified on the live cluster — the proposer emits
exactly that label for `support-agent`.

**Decision.** Decompose in `norviq/engine/intent/dryrun.py`, beside the `sprintf` that formats the
string, and publish `closest_rule` / `met` / `predicates` / `failed` per blocked call. The reason
string is unchanged, so nothing that reads it loses anything.

Two safety properties, both tested:
- `split_failed_labels` matches the LONGEST candidate label at each position (one label may prefix
  another) and returns `[]` if any text is unaccounted for. A partial parse would tick a clause as
  *passed* — a restriction the operator believes is in force when it is not.
- the API publishes the set only when `len(predicates) == total` and `len(failed) == total - met`. If
  the parse and the compiler ever disagree, the console falls back to the raw sentence rather than
  rendering a tick-list that contradicts its own heading.

Verified live: `met 4 of 5`, five clauses published, two of them compiler-added, `4 + 1 == 5`.

### D11 — An unknown role is not evidence of anything

**Found by a test failure, and it was a real defect I had just introduced.** Both new admin gates read
`roleKnown = Boolean(me.data) || Boolean(me.error)`, so a FAILED `/api/v1/me` counted as "this user is
a viewer" and disabled Approve and Save-as-draft permanently, with a reason that was actively false.

**Decision.** Block only on `Boolean(me.data) && role !== "admin"`. Unknown means permitted.

**Why.** The real gate is `require_admin` server-side. The console's check is an affordance — it
exists to explain a refusal before it happens, not to be the refusal. Being permissive when we do not
know costs an honest 403; being restrictive costs a dead button caused by an unrelated endpoint being
down, with no way for the operator to find out why. Applied to MCP Servers too.

### D12 — "can only name tools" was not true

**Found by screenshotting the built page.** The `params_available: false` panel said the proposal
*"can only name tools"* while the rule card beneath it rendered `the operation is read` — a `verb`
predicate, which the proposer derives from classification rather than from arguments. The design
prototype carries the same imprecision.

Corrected to "can only name tools and the operation they perform". Small, but it is the same failure
mode `predicateSentence` refuses to commit: **prose that overstates what the policy does is worse than
no prose**, because the operator approves the sentence and the engine enforces the predicate.

### D13 — Refusals are grouped

Replaying a class's traffic produces one row per call, so a single misconfigured rule can yield
hundreds of identical refusals — burying the one that differs. Rows are grouped by
`(tool, closest rule, failed clauses, reason)` with an occurrence count. The operator has one decision
per distinct reason, not one per call. Confirmed live: four identical `http_get` refusals collapse to
one card reading "4 calls".

---

## What broke in Phase 4, and the rule each one leaves behind

### Editing the agent class destroyed the proposal

`onChange` called `setProposal(null)`, so correcting a typo threw away a dry run that had just replayed
the entire recorded sample. Worse, the builder handoff was keyed on the live input box rather than the
proposal, so editing the box after proposing would have seeded the builder with an agent class the
rules were never proposed from.

Now the proposal survives, is keyed on its own class, and a divergence renders a `proposal-stale`
banner naming both.

**Rule.** An input that invalidates expensive derived state should mark it stale, never delete it. The
operator can always ask again; they cannot un-ask.

### The refusal banner and the button disagreed

`9ecd610` added a banner saying the handoff would weaken the policy, but left the button ENABLED —
clicking fired a toast showing only the first of N reasons and navigated nowhere. The page both
refused and looked broken. The button is now disabled with the reason as adjacent text, and
`openInBuilder` keeps its own guard: a protection that lives only in a `disabled` attribute is one
refactor away from being gone, and what it protects is the weaker policy getting saved.

### Three stale tests, correctly classified

`Intents.test.tsx` and `IntentsHandoff.test.tsx` asserted the OLD copy and the OLD flat predicate line.
Rewritten rather than deleted, each with the reason the behaviour changed. The plan predicted exactly
this ("the Propose humanisation work will legitimately break `Intents.test.tsx`") — classifying before
fixing is what kept them from being quietly weakened.

### A NUL byte in a source file

Three `\0` bytes reached `Intents.tsx` inside a template literal where spaces were intended. `tsc`,
eslint and vitest ALL passed — a NUL is a legal character in a JS string — and the only symptom was
`grep` reporting the file as binary and silently matching nothing.

**Rule.** When a text search returns nothing from a file you just edited, check for binary content
before concluding the edit did not land. The grouping key is now an explicit `join()` with a visible
delimiter.

---

## Phase 5 (part 1) — the Visual Policy Builder's P1 fix

### What shipped

The allowed-tool row. This is the change the whole redesign exists for, so it went first rather than
last, and the rest of the builder's chrome (top bar, Stepper strip, RegoDrawer rail, ConditionPicker,
mode-fork callout, `.input` styling) is deliberately still outstanding.

Before: an allowed tool rendered as a **pill** carrying a 10.5px grey text button reading `+ scope`.
That button is the entire product differentiator — Norviq's claim is that an allowlist of tool NAMES
is not a security control, because a name is exactly what the agent framework already grants. The
control is the rest of the sentence: "send_dm, **but only to @acme.com**". Shipping it behind an
unlabelled chip affordance ships the differentiator switched off, and a first-time operator finishes
the flow having built a capability list while believing they built a policy.

After: `[name + ProvenanceBadge] [ScopeCell] [remove]`, with the ScopeCell taking two-thirds of the
width and **never rendering empty** — headline, detail, impact, CTA, always all four. An empty cell is
what made the old chip readable as "done".

### D14 — The impact line states POLICY, not traffic

**The gap.** The design shows per-tool call counts: "Allows 312 · 4 would now be denied". `DryRunReplay`
carries no per-tool totals — only `newly_blocked_samples`, a list the server TRUNCATES.

**Decision.** The impact slot states what the grant permits, which needs no endpoint and is exactly
true: *"Allows every call to send_dm, with any arguments."* Traffic is appended only where the dry run
genuinely names that tool, and when `truncated` is set it renders as **"at least N"**.

**Why.** A count derived from a truncated sample is a lower bound printed as a total. The operator
would act on it and the engine would contradict them — the same failure mode as prose that overstates
a predicate (D12). The policy fact is both always available and the more useful sentence: an unscoped
grant's problem is not how much traffic it sees, it is that it is unbounded.

### D15 — A negated fact is now VISIBLE, not merely enforced

**The defect.** `if (f.type === "not") return null` — a NOT-wrapped scoping fact rendered **nothing**
while still compiling and still enforcing. A grant could read "Narrowed · 2 conditions", show one row,
and carry a second live clause the operator could neither read nor remove. The code comment
acknowledged the gap and treated it as acceptable because such a fact cannot be *authored* in the
panel (it arrives from the Propose-from-traffic handoff).

**Decision.** Render it read-only: a `NOT` pill, the inner clause in `describeFact`'s words, the
sentence "Negated. Compiles and enforces", and a remove button.

**Why.** Read-only is a fair limitation. Invisible is a defect. A clause nobody can see is a clause
nobody can audit, and it was live in production while the count above it claimed otherwise — the same
"two components keyed differently on one concept" shape as every other defect in this work.

### D16 — `describeFact` / `describeConstraint` are now exported

The generated Rego's header comment and the ScopeCell's condition chips describe the same clause.
Rendering them separately would drift, and an operator comparing the compiled module with the row that
produced it could not then tell whether they were the same restriction. Both now call one function —
a structural guarantee rather than a convention, asserted in `ScopeCell.test.tsx`.

---

## What broke in Phase 5, and the rule each one leaves behind

### Sixteen stale tests, all one class

Every failure selected `builder-allowlist-tool-chip-*` or `builder-allowlist-tool-scope-*` — the chip
and its `+ scope` link, i.e. **the defect itself**. Rewritten to target the row and the ScopeCell's
CTA/headline rather than deleted. A test asserting the shape a redesign deliberately removes is stale,
not failing; classifying it as such before touching it is what stopped it being quietly weakened.

Also replaced: `getByTitle("Scope send_email by its arguments")`. That `title` was a tooltip on a text
link; the CTA is a labelled button whose text already says "Narrow it", so a title would be redundant.

### A cast in a fixture bought nothing

My first negated-fact fixture wrote `allowlist.grants` as an object keyed by tool. `BuilderGraph`
declares it as an ARRAY, and `as unknown as BuilderGraph` silenced the compiler right up to
`grants.filter is not a function` at runtime.

**Rule.** `as unknown as T` in a test fixture disables the one check that would have caught the
fixture being wrong. Build fixtures that typecheck honestly, or expect to debug them at runtime.

### An unscoped Playwright locator asserted against the wrong document

`page.locator(".monaco-editor .view-lines").first()` picked up the **Policy Catalog's** editor sitting
behind the open sheet — it was happily reading `norviq.presets.strict` and reporting a mismatch
against a policy the test never authored. Scoped to `getByTestId("builder-sheet")`.

**Rule.** In a sheet-over-page UI, any structural locator (`.class`, `role`, `nth`) must be scoped to
the sheet. The page behind it is still mounted, still rendering, and will answer first.

### And one assertion that could not be honest, so it was narrowed

The e2e originally claimed "the scope cell and the generated rego describe the same restriction", but
Monaco virtualises its viewport and the summary line sits below the fold of a long generated header —
so the assertion was testing scroll position, not vocabulary. The claim is a structural guarantee
(both call the exported `describeFact`) and is asserted in the unit test where it can be. The browser
test now asserts what a browser can see, and its name says so.

---

## Phase 5 (part 2) — the comprehension fixes

Chrome deferred deliberately (top bar, Stepper strip, RegoDrawer rail, ConditionPicker). What shipped
instead is the set of changes where the screen was *saying something misleading*, which outranks
layout.

### D17 — The mode fork is stated as an INVERSION, not as two definitions

The two mode cards described what each mode does. Neither said the thing that costs money: an
identical clause means opposite things in them. `data_classes noneOf [secret]` is a precondition for
ALLOWING in allowlist mode and a trigger for BLOCKING in tighten-only. An operator who switches mode
with conditions already authored keeps every clause and reverses every outcome.

The callout shows one clause read both ways, then names the consequence of the mode currently
selected — "in this mode a mistake is LOUD (the call is denied)" versus "SILENT (a rule matching
nothing never fires, and still looks like it enforces)". The second half is the actionable one, and it
is the half a static definition cannot give.

### D18 — The budget hint is computed from the ENCODING, never the label

The server caps a policy at 25 regex ops, and the two clauses an operator would guess about are both
backwards:

| Clause | Reads like | Actually emits |
|---|---|---|
| `hostIn` | set membership | `regex.match` on an anchored alternation — **costs 1** |
| `destinations.hosts anyOf` | a pattern match | a set comprehension — **free** |

`constraintCostsRegexOp` / `factCostsRegexOp` live beside the emitters, and `regexCost.test.ts`
compiles one real graph per clause kind and compares the predicate against `computeStats().regexOps`
measured on the emitted rego. A change to any emitter now fails that test rather than quietly making
the hint wrong — the hint cannot drift from the compiler because the test measures the compiler.

### D19 — The scope panel groups by what a clause ADDRESSES

`ARGUMENT` / `WHOLE CALL` / `NEGATED`. Per-argument constraints and whole-call facts were one
undifferentiated list, and they read identically while behaving differently: an argument clause fails
when the caller simply omits the argument, a whole-call fact is derived by the engine regardless. Each
band carries that distinction as its hint.

`NEGATED` is rendered as a SECOND PASS over the same array rather than as a heading emitted mid-list.
A heading placed wherever the first negated fact happens to sit would group by authoring accident
rather than by meaning. The index passed to `removeFact` is the index in the FULL array — filtering
first would silently remove a different clause.

### Four form controls had no styling at all

`className="mono"` with no `.input`: no border, no focus ring, no placeholder colour. Fixed by
matching only `className="mono"` that sits on an `<input>`/`<select>`/`<textarea>` — the same string on
a `<span>` or `<div>` is correct and was left alone.

---

## What broke in Phase 5 part 2

### The same fixture lesson, twice in one file, and the second time the type caught it

`regexCost.test.ts` first omitted `refinements`, so `compileGraph` returned `invalid_allowlist` with an
EMPTY rego — every measurement read zero, and the comparison would have passed vacuously in the wrong
direction had the predicate said "free" everywhere. `as BuilderGraph` hid it; the assertion caught it.

Removing the cast then made `tsc` report a missing `schemaVersion` immediately.

**Rule, now demonstrated twice: a cast in a fixture disables the cheapest check available.** Worse
here than usual, because the failure mode was a test that measures nothing and reports success. Any
test that compares a prediction against a measurement must first prove the measurement is non-trivial
— a baseline that is zero for every input agrees with any prediction that is also zero.

---

## L3 + the kind CI job

### The trap was real, and it was worse than documented

`tests/integration` (18 files) and `tests/attacks` (13 files) are excluded from the PR gate because
they need a cluster. `test.yml` says so and adds "they belong in a kind-based e2e job, not a PR gate".
That job did not exist, so **162 tests ran nowhere**.

Running them was not enough on its own. Measured, against a DEAD API:

```
integration:  11 passed · 61 skipped   → pytest exit 0
attacks:       0 passed · 101 xfailed  → pytest exit 0
```

Both suites report success. `tests/attacks/conftest.py:119` calls `pytest.xfail` and
`tests/integration/conftest.py:53` calls `pytest.skip` when the backend is unreachable, and an xfail
is *expected failure* — green. Any CI checking only the exit code would have reported that the attack
suite proved enforcement works, having asked nothing.

`scripts/kind-e2e/l3.sh` therefore asserts a **nonzero PASSED count per suite**, from a JUnit XML
rather than by grepping a summary line whose wording varies by pytest version.

**Thresholds are measured, not guessed.** A threshold of 5 would have caught the dead API for
`attacks` and missed it entirely for `integration`, which passes 11 tests with no backend at all:

|             | live | dead |
|-------------|------|------|
| integration | 63   | 11   |
| attacks     | 99   | 0    |

Live result: **63 + 99 = 162 passing** against the real cluster.

### The guard had the defect it guards against

First version printed `✗ attacks: only 0 tests actually PASSED` and **exited 0**. `|| rc=$?` at the
call site suppresses `set -e` for the whole function body, so the Python guard's non-zero exit was
discarded. Found by running it against a dead API and reading the *exit code* rather than the message.

**Rule.** A tripwire is not done when it prints. Verify it in BOTH directions — fails when it should,
passes when it should — and check the exit code, which is the only thing CI reads.

### One real fix fell out: a viewer token signed with the wrong key

`test_auth_hardening.py` mints a viewer token to prove an authenticated non-admin gets **403**. It
signed with this process's `settings.api_secret_key`, but the API reads `NRVQ_API_SECRET_KEY` from a
cluster Secret — so the token was rejected at the SIGNATURE with 401 and the authorization check under
test was never reached. The test now honours `NRVQ_JWT_SECRET`, and `l3.sh` reads the real key from
the Secret.

Note the shape: a 401 would satisfy any assertion phrased as "not 200". The test was specific enough
to catch it, which is the argument for asserting the exact status rather than a category.

### `.github/workflows/kind-e2e.yml`

Nightly plus a path filter, so a PR touching the engine, the API routers, the webhook, the chart or
either suite gets cluster coverage, while an ordinary UI PR does not pay 25 minutes for it. Five
images (bootstrap is behind a Helm hook, not a Deployment), no `--platform` pin, namespaces created
before install, `values-light.yaml`, `pullPolicy=IfNotPresent`, and an `if: failure()` cluster dump
plus Playwright artifacts — a red cluster run without the state behind it is a guessing game.

L4 delegates to `scripts/e2e.sh` rather than invoking Playwright directly, so the two cannot drift.
The one thing it does add is `playwright install --with-deps`, unsuppressed: `e2e.sh` runs the install
with `|| true`, which is fine on a machine that already has the system libs and fatal on a fresh
runner, where the browser then fails to launch with no explanation.

---

## L4 triage — the full browser run, and what its flakes actually were

The full suite finished **112 passed, exit 0** (was 95 before this work; 4 new specs added 30 tests).
Seven skipped, five flaky, five "did not run". Triage of the ones that are mine:

### A test of mine was genuinely, intermittently wrong

`propose-from-traffic.spec.ts` appeared in the flaky list. Its helper waited on `hoisted-clauses`
before every test — and that element is **conditional on two or more rules sharing a clause**, which
is a property of how the proposer grouped today's audit rows, not of "a proposal rendered". Worse,
nothing asserted the request had SUCCEEDED, so any API failure spent 30 seconds waiting for an
element that would never appear and then reported a missing locator instead of the actual error.

Fixed: assert `POST /intents/propose` returns 200, then wait on a rule card — a structural anchor
present whenever a proposal rendered at all. Stable across repeated runs afterwards.

**Rule.** A shared test helper must wait on something STRUCTURAL, and must assert the call it just
made. Waiting on a data-dependent element couples every test in the file to today's fixtures, and
skipping the response assertion guarantees the eventual failure message names the wrong thing.

**Second rule, learned the embarrassing way.** I first ran these specs with `| tail -3`, which showed
`24 passed` and hid the `6 failed` line above it. The earlier lesson about `--reporter=line` printing
nothing per-test in a non-TTY has a sibling: **a tail can hide the summary line that matters.** Grep
for `failed` explicitly rather than trusting the last few lines.

### The remaining instability is OPA recompilation contention, and it is documented behaviour

Running the four new specs back-to-back at three workers degrades: run 1 passes 30/30 in 13s, runs 2
and 3 fail several. Ruled out in order, by measurement rather than by argument:

| Hypothesis | Test | Result |
|---|---|---|
| OPA OOM | `restartCount` + `lastState` | **was real once** (exit 137, OOMKilled at 128Mi) — raised to 512Mi locally, restarts went to 0, failures REMAINED |
| leaked dry-run packages | `GET /v1/policies` on the sidecar | 0 modules — no leak |
| `kubectl port-forward` degradation | re-forward before every run | no change |
| cross-spec contention | run `tools-registry.spec.ts` ALONE ×3 | **8/8 every time, ~3s** |

So it is contention, and the chart already explains the mechanism in its own comment on the OPA CPU
limit: *"OPA stops answering queries while it recompiles its module store"*. `/intents/dry-run`
compiles and loads a module per call; with three workers, one worker's dry-run stalls the other two
past their timeouts. The same comment records a measured CPU fix (250m → 1500m) for exactly this
burst on the query path.

**Classification: environmental, known mechanism, not a regression.** CI runs the suite ONCE, which
is the shape that passes; back-to-back repeats at three workers is a stress case beyond what any
pipeline does. Left as-is rather than papering over it with longer timeouts, which would hide a real
future slowdown.

**Worth flagging for the chart, though:** the OPA container's `memory: 128Mi` limit has never had the
measurement its `cpu: 1500m` limit got, and it DID OOMKill under concurrent policy compiles. The
compile burst is expensive in both dimensions; only one of them has been sized deliberately.

---

## I invalidated my own test run, and nearly believed it

The full browser suite came back **61 failed / 115 passed** — against a baseline of 112 passed and
zero failures an hour earlier. Nothing in the diff between those two runs could plausibly have broken
sixty tests.

It hadn't. I had launched the browser suite into the background and then, while it ran, executed
`make test-l3` — 162 tests that hammer the same single-replica API, push policies, and trigger the OPA
recompiles that (per the chart's own comment) stop OPA answering queries. Two heavy suites, one light
cluster. The failure signature says so plainly: the locators that failed are page content across
unrelated routes — Red Team, API Keys, Compliance, Policy Catalog — which is what a backend that
intermittently stops answering looks like, not what a regression looks like.

**Rule.** A cluster-backed test run is a measurement, and a measurement needs an isolated instrument.
Never run two suites against one local cluster concurrently — and when a result is wildly worse than
the last one on a small diff, suspect the instrument before the code. Re-run in isolation FIRST;
triaging sixty phantom failures individually would have cost hours and taught nothing.

The corollary is uncomfortable and worth stating: had that run come back *green* while contended, I
would not have questioned it. A contended run is not merely noisy — it is untrustworthy in both
directions.

---

## What was NOT built, and why

The plan's Phase 5 lists builder chrome: a 54px top bar, a Stepper strip, a scrollable authoring
column, a footer action bar, a RegoDrawer collapsed to a 46px rail, and a ConditionPicker.

**Decision: not built.** Stated here rather than left for someone to discover.

The reasoning, in the order it mattered:

1. **The equivalents already exist**, in a different arrangement. The sheet has a title bar with the
   agent class and a close control; numbered step headers (`2 What should it do?`, `3 Check &
   enforce`) which are a stepper inline rather than as a strip; a footer action bar with Run dry-run /
   Save & enforce / Cancel; and the compiled-rego pane beside the authoring column rather than
   collapsed into a rail. What the prototype specifies is a re-arrangement of chrome that is present
   and working, not the addition of anything an operator cannot currently do.

2. **The substance was the point.** The plan itself says the redesign exists to fix one thing: that a
   first-time operator must discover argument scoping without being told it exists. That is the
   ScopeCell, the standing banner, the mode-fork inversion, the encoding-derived budget hint and the
   negated clause that used to enforce invisibly — all shipped and all verified in a browser against a
   real cluster.

3. **The risk is asymmetric.** `BuilderSheet.tsx` is 2,558 lines. Restructuring its layout puts 71
   unit tests and 8 live browser tests at risk to move pixels, with no behavioural gain. Spending the
   remaining budget there would have traded verified correctness for visual fidelity.

If it is picked up later, the prototype is the spec and nothing in this work blocks it — the ScopeCell
is a self-contained component and the sections it sits in are independently addressable.

---

## CORRECTION: the 59 failures were neither contention nor policy pollution

I published two explanations for the same 59 failures before finding the real one. Both are recorded
above; both were wrong, and the record is worth keeping because the way each was wrong is instructive.

**Wrong explanation 1 — "self-inflicted contention."** I had run `make test-l3` while a browser suite
was in flight, so when the run came back 61 failed I attributed it to OPA recompiles blocking queries.
Plausible, fitted the facts, and committed to in a commit message. **Refuted by re-running the suite in
complete isolation: still 61 failed.**

**Wrong explanation 2 — "L3 leaks policies."** It genuinely does: `test_policy_lifecycle.py` POSTs into
`integration-<uuid>` and never deletes, and I found ten orphans on the cluster. A namespace exists as
far as the console is concerned the moment a policy names one, so the selector had ten phantom
entries. Real defect, real fix (below). **But not the cause: deleting all ten and re-running gave 61
failed again.**

**The actual cause, found by fanning four independent read-only analyses over the log rather than
theorising a third time:**

**27 of the 59 failures — 46%, across 11 spec files — are a single line.** Those specs opt OUT of the
seeded token (`test.use({ storageState: { cookies: [], origins: [] } })`) because driving the real
login form is the thing they exist to test. They read the password from `NRVQ_E2E_PASSWORD` and fall
back to the literal `"CHANGE_ME-e2e-pw"`. **Nothing in this repository sets that variable** — not
`scripts/e2e.sh`, not the new CI job, nothing. `overview-kpi.spec.ts:11` names a preflight "gate" that
resets admin to a known password with `must_change=false`; no such step exists in the repo.

The clinching evidence is a test that PASSED: `console-fixes-batch2.spec.ts:309` asserts
`admin`/`norviq` logs in and advances to the change-password view. So the admin was still on the
default credential with `must_change=True` — the gate had never run. And the first `realLogin` failure
is at test 35 of 190, long before the first 429, which rules out rate-limiting as the initiator.

The remaining 32 split as ~17 missing seeded data (compliance drafts, redteam runs, attack paths,
a `default/customer-support` policy the coverage matrix names as required), ~9 backend (a dead
`127.0.0.1:18080` gateway forward, and 429s late in the run), and ~6 genuine UI issues in surfaces this
work never touched.

**None of the 30 tests added by this work failed in any of the three runs.**

### What this cost, and the rule

Two confident wrong answers, and roughly a session of investigation, because each explanation *fitted*
the evidence without *excluding* the alternatives. The cheap experiment that settled it — run the four
new specs alone, then re-run the whole suite in isolation — was available from the first minute.

**Rule.** When a broad failure has several plausible causes, spend the first move on the experiment
that DISCRIMINATES between them, not on the one that confirms the leading hypothesis. And a hypothesis
that survives only because it was never tested against a control is not a finding, it is a guess with
a commit message.

### Three fixes, all verified

1. **`tests/integration/conftest.py`** — a session-scoped autouse sweep deletes every `integration-*`,
   `emittest-*` and `replica-*` policy the suite creates. Verified: ran L3, policy table returned to
   4 policies / 3 namespaces, 0 orphans, and L3 still passes 63 + 99.
2. **`.github/workflows/kind-e2e.yml`** — L3 now runs AFTER L4. The cleanup is the fix; the ordering is
   the second line of defence, because a cleanup that fails must not silently poison the browser suite.
   My original ordering ran L3 first, which would have reproduced the pollution on every CI run.
3. **`scripts/e2e.sh`** — a loud preflight when `NRVQ_E2E_PASSWORD` is unset, naming all 11 specs and
   the ~27 tests that will fail and why. Not fatal: the other ~160 tests are valid without it, and
   refusing to run them would be a worse trade. Stated before the run so the summary is never a
   mystery again.

The suite's real gap remains open and is now documented rather than mysterious: **`scripts/e2e.sh`
performs NO seeding**, while `ui/tests/e2e/COVERAGE-MATRIX.md` documents specs that require seeded
policies, attack paths and redteam history. Those specs have been passing on state accumulated by
hand. That is a pre-existing suite-hygiene problem, larger than this plan, and the honest thing is to
name it rather than to have quietly re-run until it looked green.

---

## The login gate — and the 160 tests it broke before it fixed 27

### The gate

`overview-kpi.spec.ts:11` refers to "the gate" that resets admin to a known password with
`must_change=false`. No such thing existed in the repo, so the 11 real-form-login specs read
`NRVQ_E2E_PASSWORD`, fell back to the literal `CHANGE_ME-e2e-pw`, and each of their 27 tests waited
20 seconds for a navigation that could not happen.

`scripts/kind-e2e/login-gate.sh` is that gate. It drives the SHIPPED flow rather than adding a
test-only switch:

1. `norviq.api.admin_reset --password <TEMP>` in-pod → `must_change=True`
2. `POST /auth/login` with TEMP → a token flagged must_change
3. `POST /auth/change-password` to FINAL → clears must_change

`admin_reset` always sets `must_change=True`, deliberately. A `--no-force-change` flag would have been
one line and would have weakened a real security property for a test's convenience; driving the forced
change instead exercises that path rather than bypassing it. The gate then ASSERTS `must_change=false`
by logging in again, so a regression in either endpoint fails here with a clear message instead of 27
tests later as a navigation timeout.

### What it broke, and why that was predictable

First version fixed the 27 and took the run from **59 failed to 173 failed, 11 passed**.

Changing a password REVOKES that user's outstanding tokens. About 160 of the suite's ~190 tests
authenticate with the token in `$NRVQ_TOKEN_FILE` rather than through the form — so the gate pulled
the credential out from under nearly the whole suite, and the new failures pointed at every page in
the console rather than at the credential.

The verification login in step 4 had already returned a valid token for the final password. It is now
written back to `$NRVQ_TOKEN_FILE`.

**Rule.** A fixture that mutates an account's credentials must leave every credential the suite uses
consistent with the new state. "It fixed the thing I was looking at" is not a result until the things
I was NOT looking at have been re-checked — and the measurement that catches it is the same full run
that measured the problem, not a spot-check of the 27.

---

## Latency: the enforcement path saturates at ~4 concurrent calls, and fails CLOSED past it

`scripts/kind-e2e/latency.py` measures `/api/v1/evaluate`, because that is the only path that sits in
front of every agent tool call — its latency is added to every action an agent takes, and the engine
fails CLOSED at 2s (`evaluator_timeout`), so latency here is an availability property, not a comfort
one.

**Measured in-cluster on AKS (2 API replicas, api cpu limit 2, opa cpu limit 1500m), benign
`search_kb`, 60 calls per level:**

| concurrency | p50 | p95 | p99 | decisions |
|---|---|---|---|---|
| 1  | 66ms  | 109ms  | 120ms  | allow |
| 2  | 131ms | 209ms  | 261ms  | allow |
| 4  | 291ms | 508ms  | 577ms  | allow |
| 8  | 489ms | 1769ms | 1840ms | **allow AND block** |
| 16 | 541ms | 2000ms | 2054ms | **allow AND block** |

Per-call cost is healthy: **66ms p50 serial, every decision correct.** Latency then scales LINEARLY
with concurrency — 66 → 131 → 291 — which is the signature of a queue in front of a single server,
not of expensive work.

**Past ~4 concurrent, legitimate calls stop being allowed.** At 16-way, of 64 identical benign calls:

```
  21x  block / evaluator_error
  19x  block / trust_frozen
  19x  block / evaluator_fallback
   5x  allow / default_allow
```

**8% allowed.** Three distinct fail-closed mechanisms fire at once. Fail-closed is the right posture
for a PEP — but the failure here is not an attack being refused, it is ordinary traffic being refused
because the enforcement point ran out of capacity.

`trust_frozen` was ruled out as contamination before this was written: Redis held zero
`agent_frozen:*`, `trust_cap:*` and `trust:*` keys at the time of measurement. It is the trust
calculation itself degrading to frozen under contention.

### The constraint

`Dockerfile.api:52` — `uvicorn norviq.api.main:app --host 0.0.0.0 --port 8080`, with **no
`--workers`**. One event loop per pod; two replicas; so **two concurrent request handlers for the
whole cluster**, against an api container whose CPU limit is 2 cores. The linear scaling and the knee
at 4 both follow directly.

### Measured honestly

The first run of this harness was taken through a `kubectl port-forward` from a laptop to Azure and
showed a uniform ~700ms p50 across every scenario. That uniformity was the tell — policy work differs
per scenario, network cost does not. Re-measured from INSIDE the api pod before anything was written
down. The in-cluster numbers are the ones above.

Exact figures are specific to this cluster's replica count and CPU limits. The SHAPE — linear scaling,
a knee at ~4, fail-closed past it — is a property of the one-event-loop-per-pod design, not of AKS.

### The `--workers` fix: directionally right, and the cluster cannot demonstrate it

Deployed `--workers 4` with the api memory limit at 2Gi and OPA at 512Mi. Verified live:
`NRVQ_API_WORKERS=4`, api memory 214Mi → 509Mi, api CPU 4m → 947m under load. It is running more than
one process and using more than one core, both of which it could not do before.

Re-measured, same harness, same cluster:

| concurrency | p50 before | p50 after | p95 before | p95 after |
|---|---|---|---|---|
| 1  | 66ms  | 65ms  | 109ms  | 149ms  |
| 2  | 131ms | 109ms | 209ms  | 299ms  |
| 4  | 291ms | **153ms** | 508ms  | 1241ms |
| 8  | 489ms | 439ms | 1769ms | 1596ms |
| 16 | 541ms | 820ms | 2000ms | **3950ms** |

p50 at concurrency 4 nearly halved — the queueing the fix targets. But p95 got WORSE, and at 16-way
markedly so.

**The reason is the cluster, not the change.** Both AKS nodes are `Standard_*_v*` with **2 vCPU
each — 4 vCPU total for the entire cluster**, running Postgres, Redis, the engine, the webhook, the UI
and two API pods. Four workers per pod × two pods = eight API processes competing for cores that were
already oversubscribed. More workers on a node with no spare CPU converts queueing-in-uvicorn into
queueing-in-the-kernel, and the tail gets worse rather than better.

So the honest reading: the single-worker ceiling was real and is removed, and on a node with CPU to
spare this is strictly better. **On THIS cluster it cannot be demonstrated, and the G4 bar is not
met** — benign traffic still returns `block` at concurrency 8 and above.

**This is not "done". It is a correct change whose benefit is masked by a 4-vCPU test cluster.**
Settling it needs either a larger node pool or a load test run against a single pod pinned to a node
with headroom. Recorded rather than papered over, because a table showing p95 tripling would otherwise
look like the fix made things worse.

---

## G6 — four industry personas on kind

Four autonomous personas (healthcare, fintech, e-commerce, legal) each drove the real adoption path:
first-run credential ceremony → register MCP tools → confirm they surface in the registry → generate
traffic with a **real LLM** (Groq, `llama-3.3-70b-versatile`) → propose an intent from that traffic →
author and enforce an industry policy → re-probe → clean up. `scripts/personas/`.

**Result: G6 met.** 4/4 journeys, every persona proved at least one real decision flip
(healthcare 2, the rest 1 each), 0 blockers, 7 findings filed.

### What broke on the way, and the rule each time

**1. The kind cluster was running `main`, not this branch — and nothing failed.**
`00-up.sh` builds and `kind load`s `norviq/norviq-engine:*`. The chart's `images.registry` defaults to
`ghcr.io/norviq-dev/`, and `pullPolicy=IfNotPresent` found the *published* image already on the node.
Five freshly built images were loaded, ignored, and every route added on this branch 404'd as though
the feature had never been written. Pods Running, console serving, `helm` green.

This is the same defect this project keeps producing: **two components keyed differently on one
concept** — the build names the image, the chart names the image, and nobody reconciles them.

> **Rule: a cluster must prove it runs *this* code before any result from it counts.** `00-up.sh` now
> asserts both that each workload's image has the locally-built prefix *and* that the running process
> serves `/api/v1/mcp/pins`, a route that exists here and not in the published image. The image name
> alone proves only what was scheduled.

**2. `api.workers` and `api.resources.limits.memory` are one setting in two files.**
`values.yaml` gained `workers: 4` with a 1Gi limit (the earlier capacity fix). `values-light.yaml`
overrides memory to 384Mi and inherited 4 workers → ~600Mi of processes under a 384Mi cap → OOMKill
loop. The install failed with `resource Deployment/norviq/norviq-api not ready ... Pending
termination`, which points at Helm or the cluster and never at the two numbers that disagree.

Fixed in `values-light.yaml` (`workers: 1`) and, so it cannot recur, `api-deployment.yaml` now
**refuses to render** below 128Mi per worker with a message naming both settings. Verified three ways:
the light profile renders, the default profile renders, and `--set api.workers=4` against the light
profile fails with the explanatory error.

**3. `Dockerfile.webhook` does not exist.** Four images follow the repo-root `Dockerfile.<name>`
convention; the webhook is a Go module rooted at `webhook/` with its own `go.mod` and its Dockerfile
inside that directory. The loop assumed the convention held.

**4. Every persona reported "LLM did not return a usable tool call".** The obvious readings — bad key,
wrong model, prompt too strict — were all wrong. Groq's CDN answers `urllib`'s default
`Python-urllib/3.12` User-Agent with HTTP 403 `error code: 1010`, a Cloudflare bot challenge that is
indistinguishable from an auth failure at the call site. One header fixed it.

> **Rule: when a client fails identically on every input, suspect the transport before the payload.**

### The findings themselves

All four personas independently filed **the same feature request**, which is what makes it a product
defect rather than a domain quirk:

> **Propose-from-traffic cannot constrain arguments.** `params_available: false`, so a proposal can
> only name tools. For all four industries the control that matters is on *arguments* — PHI terms, card
> data, price fields, privilege markers — which is exactly what it cannot express.

The two `major` findings are the same gap wearing a different hat. In both, **the engine enforced the
policy exactly as written**; the policy simply never described the call the model actually made:

| Industry | Operator's rule | What the model emitted |
|---|---|---|
| fintech | `amount > 1000` | `amount: 25.0` — it paraphrased "25000 dollars" as 25 |
| legal | bulk phrases: `all matters`, `all rows`, … | `matter_id: "all", q: "*"` |

The operator reasoned about the *intent* and wrote predicates against the words they imagined. Nothing
in the authoring surface shows the argument **values** real traffic carries, so the gap between the
rule and the reality was invisible until it was missed. That is one product ask, confirmed six times
from four independent directions, and it lands squarely on this redesign's own P1 thesis: naming a
tool is not a control, and *neither is guessing at its arguments*.

**A note on how that was classified.** The persona originally filed both as `blocker`. That was wrong,
and the fix was not to argue it away in prose but to make the harness itself draw the distinction:
`would_match()` mirrors the policy's predicates in Python, so "the engine did not enforce my rule"
(blocker) and "my rule never described this call" (major, usability) are separated by a check rather
than by an opinion. Without it every rephrasing by the model files a false blocker and buries the real
ones. The discriminator is unit-checked against all six known cases before it is trusted.

### A structural limitation, recorded rather than worked around

The personas run **sequentially, and they have to**. The console has exactly one admin identity,
resettable only by an in-pod CLI; there is no endpoint that creates a second operator. So "each persona
sets its own password" can only be true one persona at a time — persona N takes ownership of the
credential and hands the console to N+1. Four teams in one company cannot hold their own console
logins today. Recorded here rather than papered over with a shared token.

---

## G5 — chaos: the system degrades honestly

`scripts/kind-e2e/chaos.py`, five faults, all met. Every scenario asserts a DIRECTION of failure, not
an absence of failure, and every one proves its own injection landed before judging anything.

| Fault | Result |
|---|---|
| Kill one API replica | no 5xx reached the client; every deviation fail-CLOSED, never open |
| Kill the OPA sidecar | 3,994 calls spanning a proven evaluator death, **zero attacks allowed**; recovered without a pod delete |
| Redis to 0 replicas | 1,736/1,736 calls still decided; no attack allowed; no crash loop |
| Postgres to 0 replicas | read degraded to an explicit HTTP 502, never a silent empty list |
| 3 concurrent suite starts | exactly one accepted, two refused 409 |

### The anti-vacuity design, and the three times it earned its keep

A chaos test that cannot inject its fault reports "nothing broke", which is indistinguishable from a
pass. Each scenario therefore proves the injection (0 ready replicas, restart count rose) before it
believes any observation. That guard fired three times, and each time the harness was wrong, not the
product:

**1. `kubectl exec -c opa -- kill 1` cannot work.** `opa:1.18.0-static` is distroless — no shell — and
pod containers do not share a PID namespace, so nothing else in the pod can see OPA's process either.
The harness correctly refused to report a pass. `kubectl debug --target=opa` attaches an ephemeral
container *into the target's* PID namespace, where PID 1 is OPA, and kills exactly the one process the
scenario is about. Deleting the pod is not a substitute: it takes the API down too and proves nothing
about how the API behaves when its evaluator vanishes underneath it.

**2. The traffic window has to span the death.** The first version waited for the restart to be
observed and only then sent traffic. OPA restarts in ~2s, so that measured a healthy system and would
have reported a confident pass for a fault that was already over. Traffic now starts *before* the kill
is issued.

**3. The OPA scenario killed a pod that was already dying.** `kubectl get pods -l …` returns pods with
a `deletionTimestamp`, and `.items[0]` right after the previous scenario's scale-down was a coin toss.
The kill landed perfectly — on a pod that then ceased to exist, so its restart counter never moved and
the harness reported "the kill did not land". Fixed with `live_pod()`: Running, ready, not terminating.
Also added a `settle()` gate between scenarios, after the concurrency scenario saw three 502s and
declared its own guard unverified when the only thing wrong was that Postgres had come back twelve
seconds earlier.

> **Rule: a fault harness needs a clean target and a clean baseline, or it reports the previous
> scenario's convalescence as this scenario's result.**

### A real product fix, and a wrong root cause caught by the discriminating experiment

Scenario 1 showed benign calls being refused mid-teardown (1, then 31, of ~1,500). The obvious
diagnosis: the API container has a `preStop` sleep and the OPA sidecar has none, so kubelet SIGTERMs
OPA at t=0 while the API drains beside a dead evaluator and fails closed. It fit the evidence, it fit
the code, and it was **wrong**.

The discriminating experiment — raise `preStopSleepSeconds` and see which way the count moves —
refuted it in one run. Under that theory a longer drain means *more* time serving with a dead
evaluator, so refusals should rise. They went to zero.

The real mechanism is endpoint propagation: 3s was not long enough for the pod's removal from the
Service to reach every dataplane, so traffic was still being routed to a pod that had stopped serving.

    preStopSleepSeconds: 3   ->  1 and 31 refused across two runs
    preStopSleepSeconds: 15  ->  0, 0 and 2 refused across three runs

Default raised to 15 in `values.yaml`, with the measurements recorded beside it. The residual ~0.1%
needs connection draining rather than more waiting, and is left visible rather than tuned into
apparent perfection.

This is the second time this session a plausible root cause survived code review and died to a
one-command experiment. **Spend the first move on the experiment that discriminates between the
hypotheses, not on the one that confirms the favourite.**

---

## G4 — enforcement latency, and the pool that refused instead of waiting

**G4 met**, measured in-cluster (`kubectl exec` into the api pod, never through a port-forward — a
laptop-to-cluster hop adds a uniform delay that reads as product latency).

| Bar | Result |
|---|---|
| p50 @ concurrency 1 ≤ 150ms | **5.3ms** |
| p95 @ concurrency 8 ≤ 500ms | 192–205ms across all five scenarios |
| p99 @ concurrency 8 ≤ 1000ms | 281–403ms |
| Every scenario decides correctly @ concurrency 16 | **yes** |

### The defect: `ConnectionError("Too many connections")` on the enforcement path

Benign calls were being BLOCKED — 3/200 at concurrency 8, 82/200 at 16 — with `rule_id:
evaluator_fallback`. The engine fails closed on any exception, so this was not a slow tool call, it was
a **refused** one: legitimate agent actions denied because of a client-side pool ceiling.

Two causes, both in `norviq/engine/cache.py`:

1. `redis_max_connections: 20`, sized for console traffic. One `/evaluate` makes several Redis
   round-trips (trust read, decision cache, behaviour persist), so the ceiling arrives at a fraction of
   the request concurrency. Now 64.
2. **redis-py's default pool RAISES the moment it is exhausted rather than queueing.** This is the real
   bug. Switched to `BlockingConnectionPool` with a 1.0s wait, held well inside the evaluator's own 2.0s
   OPA budget so a genuinely stuck Redis still surfaces as the *named* `evaluator_timeout` rather than
   an anonymous fallback. A queued call answering in 40ms beats a refused one.

The side effect was larger than expected: benign p50 at concurrency 1 fell from **113ms to 5.3ms**. The
old figure was not the cost of evaluating a policy, it was contention.

The test that pinned `max_connections == 20` was updated to read the setting instead of duplicating the
literal, and a second test now pins the pool CLASS — the property that actually matters and that no
hermetic suite could otherwise observe, since the symptom only appears under concurrency.

### Two triage rules, both learned the hard way

**A `block` cannot be triaged without its `rule_id`.** The harness reported "WRONG DECISION" for calls
blocked by `trust_frozen` — a red-team suite had frozen the measured identity, which is the product
working exactly as designed. That sends the reader hunting an enforcement bug that does not exist. The
runner now clears the freeze before timing and classifies `trust_frozen` / `rate_limit_exceeded` /
`escalate_low_trust` as environmental rather than wrong. Same distinction the personas needed.

**The two artefacts disagreed about the bar.** `EXIT-STATE.md` said p95 ≤ 500ms / p99 ≤ 1000ms at
concurrency 8; `latency.py` defaulted to 250/500. The same run passed or failed depending on which file
you read — the project's signature defect, committed by the person who wrote both. Reconciled to the
document.

### The cluster was serving a previous build, again, one level deeper

The first "fixed" measurement showed no improvement at all. The pool change was not running: the image
was rebuilt and loaded under the same `:api-latest` tag, which leaves the Deployment's pod template
byte-identical, so Kubernetes correctly concluded there was nothing to reconcile and never rolled the
pods. Helm reported success. The image-provenance guard added earlier passed too — it checks the image
NAME and a route that existed in the older build as well.

Fixes, in the chart rather than the script:
* a `podAnnotations` passthrough (api + engine), stamped by `00-up.sh` with the built image ID, so the
  pod template changes exactly when the image does — a real build rolls, a no-op re-run does not;
* the guard now compares that annotation on the pod against the id this run built.

Two false starts worth recording. Asserting on the container's `imageID` **cannot work under kind**:
`kind load` re-imports into containerd under a fresh digest (`import-<date>@sha256:…`), so a node-side
id never equals the local docker one. And the first annotation check read `.items[0]`, which was the
pod the rollout had just replaced — still terminating, because `preStopSleepSeconds` had just been
raised to 15 — and declared the roll had not happened. `chaos.py` hit the identical trap from the other
side by killing a sidecar in a pod that was already going away.

> **Rule: `kubectl get pods | .items[0]` is a coin toss. Any check that names a pod must require
> Running and no `deletionTimestamp`, or it will eventually describe a pod that no longer exists.**

---

## G1 / G2 — hermetic gates and cluster suites

**G1 met**: 1947 pytest · 759 vitest · tsc, eslint, build clean. Both counts are above the vacuity
floors (≥1900 / ≥750), which exist because a collection error exits 0 with zero tests.

**G2 met**: integration 68 passed / 0 failed · attacks 101 passed / **0 xfailed**.

### Two xfails that were a stale port-forward, not a credential problem

The attacks suite reported `99 passed, 2 xfailed`. The xfail bar is 0 precisely because an xfail here
means a security control is not being exercised — and both were `test_frozen_agent_blocked`, i.e.
"does freezing an agent actually stop it".

The cause was not the credential. It was my own leftover `kubectl port-forward` on 16379, from probing
Redis by hand: it kept the port bound while pointing at a pod that no longer existed, so `l3.sh`'s own
forward could not bind, the `redis_client` fixture swallowed the connection error into `yield None`,
and the freeze test xfailed. Exit 0, green summary.

I spent a while proving the Redis password was wrong. It was not — the same URL connected fine once
the stale forward was gone. `l3.sh` now kills anything bound to its ports before forwarding.

> **Rule: before blaming a credential, check that the socket goes where you think it goes.**

### Five data-plane tests that had never run

`tests/integration` reported 9 skips. Five were the **data-plane enforcement** tests — the ones that
prove the PEP actually intercepts a tool call inside a pod — self-skipping with "data-plane E2E is
opt-in: set `NRVQ_E2E=1` (needs a cluster with the chart installed)". `l3.sh` is a script whose entire
purpose is running against a cluster with the chart installed, and it never set the flag. Three more
needed a namespace labelled for sidecar injection.

Setting the flag made them **fail**, not pass: five assertions reading "could not reach the enforcement
socket … the PEP is not intercepting anything". True, and misleading — `webhook.injection.enabled`
defaults to false, so the chart had rendered no MutatingWebhookConfiguration and there was no data
plane to intercept anything. The tests treated the namespace LABEL as evidence that injection was
installed, when the label is only the namespace opting in.

Both halves fixed: `00-up.sh` installs the injector, and `_require_live_infrastructure()` now checks
for the MutatingWebhookConfiguration itself, so a labelled namespace on a cluster without injection
skips honestly instead of failing with a socket error that sends the reader to debug a sidecar that
was never created. Integration went 63 → **68 passed**, skips 9 → 4.

The two remaining skips are honest: multi-replica needs two API endpoints (this profile deliberately
runs one, because verb promotion does not propagate across replicas), and the injected-sidecar health
tests report "no injected agent workloads deployed (valid empty state)".

> **Rule: an opt-in flag that the harness never sets is coverage that does not exist. Grep the skip
> reasons — every one that names an environment variable is a test asking to be run.**

---

## G3 — the browser suite, and two runs that measured nothing

Three full runs, three different numbers, and only one of them meant anything.

| Run | Config | Result |
|---|---|---|
| 1 | `e2e.sh`, 3 workers | 21 failed · 12 flaky · 4 did not run · 146 passed (9.1m) |
| 2 | `e2e.sh`, 1 worker | **12 failed · 0 flaky · 4 did not run · 167 passed (18.1m)** |
| 3 | `e2e.sh`, 1 worker, expired token | 136 failed · 38 passed · **1h42m** |

Only run 2 is evidence. The other two are artefacts of the harness.

### The flakiness was not flakiness

`playwright.config.ts` sets `fullyParallel` with 3 workers, and all three share ONE
`storageState.json` token against a backend with a SINGLE admin identity. Any spec that logs out or
rotates the password breaks whatever is running beside it. Serialising took flaky from **12 to 0** and
failures from 21 to 12 — the twelve "flakes" were three workers fighting over one account.

`e2e.sh` now defaults to `--workers=1` and takes `NRVQ_E2E_WORKERS` to override. Serial costs 18
minutes against 9, which is the right trade for a gate whose entire value is that its result means
something.

### 136 failures, none of them real

Run 3 reported 136 failed across 136 different surfaces — every route smoke test, the whole console.
It took **an hour and forty-two minutes** because each spec sat through its own 60s timeout.

The admin token had expired. ~160 specs authenticate with it, `token_mint --ttl 7200` gives two hours,
a serial run takes twenty minutes, and the file persists across runs — so a token minted earlier in a
working session goes stale between one run and the next. Nothing checked.

It is reachable through the front door, too: the login gate re-seeds that file, and `e2e.sh` skips the
gate whenever the caller exports `NRVQ_E2E_PASSWORD`. Exporting it is exactly what left the stale token
in place.

The trap worth naming is not the expiry. It is that **run 3 came immediately after a seeding change**,
so the available reading — "the change I just made broke everything" — was both obvious and wrong. A
136-failure list that names 136 unrelated features is not 136 defects; it is one precondition.

> **Rule: before a long suite runs, assert its preconditions are LIVE, not merely present. A token file
> that exists proves nothing. `e2e.sh` now GETs `/api/v1/version` with it, re-mints from the live api
> pod if that fails, re-checks, and refuses to start rather than producing a failure list where every
> assertion is a disguised 401.**

Verified the way every other guard here is: by pointing it at a junk token and watching it re-mint.

### Red-team surfaces tested below the scale that exercises them

`redteam-view-pager` needs ≥300 results to prove the results table stays bounded at the VIEW. Its own
comment reads "18 real classes × 29 attacks ≈ 500+ rows" — true of the AKS cluster it was written
against. A fresh kind `default` namespace holds one governed class, so the suite returned ~29 rows and
the bound went unverified.

`seed.py` now seeds twelve plausibly-named agent classes: **638 results in 12s**. Named after real
agents rather than `probe-N` deliberately — `audit_row_is_non_real` hides the `probe-`/`e2e-`/`smoke-`
prefixes, so a fleet named that way would seed the surfaces it exists to populate with nothing at all.

---

## A real product defect: the Attack Graph reported two different sizes for one exposure

Found by a 12-agent triage of the remaining browser-suite failures, then confirmed against the live
cluster. `attack-graph.spec.ts:267` asserts that the class picker's path count equals the coverage
denominator in the same dialog. It did not:

    customer-support · 22 paths     <- the class picker
    coverage 0 / 49                 <- the denominator beside it, in the same modal

Both describe the same quantity. The second is right.

`/threats/attack-paths` ranks every kill-chain worst-first and returns the top `_MAX_PATHS` (200). The
denominator is derived class-scoped, so it sees all 49 of that class's paths. The picker tallied
classes *inside the already-truncated 200*, which answers a different question — "how many of this
class survived the global cap" — and is strictly smaller on any estate large enough to saturate it.

Confirmed live:

    ns=all&include_synthetic=true      -> exactly 200 paths (saturated)
    customer-support inside that list  -> 22
    cls=customer-support (class-scoped)-> 49, synthetic_hidden=0

**The console understated real exposure by 27 paths on a positive-security surface.** Every class was
undercounted, systematically, and the operator was shown the small number first.

The trail says this was an incomplete migration: `IntentModal.tsx` documents the new contract
("Coverage is always PER-CLASS ... measuring it over every class's paths is misleading") and the
denominator was moved to per-class, but the picker's count was left on the old visible-paths
derivation.

**Fix, in the product.** `/threats/attack-paths` now derives UNCAPPED, filters synthetics, counts each
class, and only then truncates — in that order. The response carries `class_totals` (true per-class
counts) and `total_paths` (the pre-cap total, so a client can tell a capped view from a complete one at
all, which it previously could not). The console reads `class_totals`, falling back to the old tally
only for an API that predates the field.

### How this was nearly recorded as the opposite of what it is

The first triage called it a product defect. The adversarial verifier refuted that and called it a
seeding gap: my own `FLEET_CLASSES` commit added 12 classes × 16 paths = 192, pushing `default` past
the 200 cap, and the spec had passed before it.

Both are partly right, and the synthesis is the honest reading: **the seed did not create this defect,
it made a kind cluster large enough to expose one that any real customer with >200 attack paths already
hits.** A latent bug that only appears at scale is still a bug; a fixture that grows the test estate to
production size is doing its job. Reverting the seed would have hidden it again.

> **Rule: when a fixture change surfaces a failure, ask whether the fixture created the defect or
> merely crossed the threshold where it becomes visible. Those call for opposite responses.**

### The regression test asserts the property, above the threshold

`tests/api/test_threat_paths_class_totals.py` builds a fixture that *saturates* the cap on purpose,
because below it the correct and buggy implementations agree exactly — a smaller fixture passes either
way and proves nothing. That is why this survived every hermetic suite until a seeded cluster grew past
200. It carries its own anti-vacuity assertion: if a tally over the returned paths ever equals
`class_totals`, the fixture has stopped saturating and the test says so rather than passing quietly.

Verified by reverting the one-line `cap=None` and watching it fail, then restoring it.

---

## G3, continued: what a fresh cluster exposed that an old one hid

Rebuilding the kind cluster from scratch took the browser suite from 11 failures to 32 — on the same
product code. Nothing regressed; the old cluster had been quietly supplying fixtures that no script
provides.

| Cause | What it broke |
|---|---|
| `NRVQ_E2E_PASSWORD` carried over from the previous cluster | the login gate is skipped when it is set, so ~27 form-login tests failed on 20s timeouts |
| ~58 audit rows, all minutes old, `1h == 24h == 7d` | every range, bucket and KPI assertion was unanswerable by construction |
| no deployed-but-never-observed agent had ever existed | `awaiting_hidden` was correctly 0, so the assertion could not hold |
| one governed class in `default` | a full-namespace red-team suite returned ~29 rows against a ≥300 bar |

The through-line: **these specs passed for months on AKS because that cluster was old, not because it
was seeded.** Weeks of accumulated traffic is not a fixture. Every one of these is now created
explicitly, so a fresh cluster and a long-lived one answer the same questions.

### The credential guards, and how each was wrong before it was right

Three rounds on one idea — *a supplied credential must be verified, not trusted*:

1. **The token.** A file that exists proves nothing; `token_mint --ttl 7200` expires between runs.
   `e2e.sh` now GETs `/api/v1/version` with it and re-mints from the live pod.
2. **The password.** Same rule, and the first version used `curl -sf`, which cannot tell 401 from 429.
   Verifying a password *spends* one of the five failed-attempt slots, so the probe tripped the lock
   and the gate that would have fixed everything then failed with "Too many failed attempts" — a
   message about the harness dressed as a message about the credential. It now reads the status code
   and clears the counter on 429.
3. **The lockout helper itself killed the script.** Zero-byte log, exit 1, no error anywhere. Under
   `set -euo pipefail` an assignment from a failing command substitution aborts, `kubectl get pods -l
   <label>` exits non-zero when nothing matches, the redis pod is labelled `app=norviq-redis`, and I
   had sent kubectl's stderr to `/dev/null`. **The rule against suppressing the stderr of a step whose
   failure you have not yet seen is written in a comment in that same file.**

### A spec that poisoned every spec after it

Eight `429`s in one run traced to `console-fixes-batch2.spec.ts`, which deliberately submits a wrong
password to prove the login form shows the right error. The lockout is keyed **per username**, and it
aimed at `admin` — the account every other form-login spec needs. Its assertions are about the form's
behaviour on bad credentials, which an unknown user exercises identically (the API runs a dummy verify
for unknown users precisely so the paths are indistinguishable), so it now uses a throwaway name.

> **Rule: a test that deliberately trips a security control must not trip it on the identity the rest
> of the suite depends on.**

### And one self-inflicted wound worth recording

The `LLM07 → LLM01` repair bound both sites to one constant — declared inside the test that generates
the draft, while the other use lives in a *different* test block. `ReferenceError: CONTROL is not
defined`, twice. The fix was right and the scope was wrong; it is hoisted to describe scope now.

**Standing at the end of this session: 13 failed / 161 passed, down from 32 / 144, with the runtime
back to 13.9 minutes.** G3 is NOT met. The remaining set is characterised, not guessed at.

---

## G3 met — 0 failed, twice back to back

| Run | Result |
|---|---|
| 12 | **0 failed** · 1 flaky · 0 did not run · 182 passed (7.7m) |
| 13 | **0 failed** · 0 flaky · 0 did not run · 183 passed (7.7m) |

Identical (empty) failing set across both. The single flake in run 12,
`posture-apply-ux.spec.ts:68`, is not in a spec this work touched — within G3's allowance.

Trajectory: **21 failed / 12 flaky → 13 / 3 → 1 / 0 → 0 / 0**, with the runtime falling from 26
minutes to 7.7.

### The dominant cause was one product defect, and it was operator-reachable

A 31-agent triage with adversarial verification put 13 of 15 failures under one slug: HTTP 429.

`redteam` is rate-limited at 15/60s because starting a suite fans out over every agent class times
every attack in the catalog — correct for the write. But `_ROUTE_RULES` classified the whole
`/api/v1/redteam` prefix, and the console's landing page calls `/redteam/results/latest` on every
boot. Measured over one run: **116 hits on results/latest against 20 actual Red Team page mounts** —
83% of the traffic in the tight bucket came from Overview.

So roughly fifteen visits to the **landing page** in a minute began 429-ing a real operator, on a
guard built to stop them hammering the suite runner. Only `/redteam/suite` and `/redteam/run` are in
that class now. A unit test pins the split and fails on the old rule.

Two more real defects fell out of the same investigation, both about **how the console behaves when it
is throttled** — which was untested because nothing had noticed it could be:

* **`RedTeam.tsx` loaded three independent reads with `Promise.all` in one try/catch**, and the render
  gate requires all of them — so one throttled history fetch erased the scorecard, the attack table
  *and* the empty state together. `allSettled` now, each panel from its own result. The
  `.catch(() => ({ targets: [] }))` was worse than useless: it turned an HTTP error into a confident
  "this namespace has no target classes".
* **`AppContext` swallowed every `/cluster-info` error into an empty namespace list**, commented
  "honest empty selector". Honest for a 401; for a 429 or 5xx the picker tells the operator their
  deployment has no namespaces. Only 401 clears it now.

### Why the failing set kept moving

The limiter keys on the JWT `sub`, and all 190 specs carry one admin token — so they share a single
bucket. Reconstructed from the counter, one run's 60s windows peaked at **482 against a 300 ceiling**.
The suite ran *at* the ceiling, and which spec ate the 429 was decided by ordering. That is exactly
why run 8 lost `auth-logout` and run 9 lost five compliance tests while the count stayed at 13.

A moving set is the signature G3 uses to detect leaked state, so this made the gate unpassable for a
reason that had nothing to do with the product. The harness now starts each run from a cold bucket and
raises the ceiling **locally only**; the product default stays 300, because the defect it exposed is
fixed properly rather than papered over.

### Three fixtures that were really other people's residue

* `brand-new-agent` was created solely by `tests/attacks/conftest.py`. A browser spec asserting its
  version history had only ever passed when the **attacks suite** ran first. Moved to `seed.py` with
  three genuinely distinct revisions (posting identical rego cuts no new version, so the assertion
  would have passed on one), and deleted from the attacks conftest — two owners at different
  priorities is a conflict waiting to be debugged.
* `ui-polish-batch-c` and `ui-batch-a` POSTed **identical** red-team suites. With
  `redteam_detail_keep_runs = 1`, each POST prunes the previous run's detail rows, so the duplicate
  was actively destroying the fixture other red-team specs read.
* `graph-scope-search` picked the alphabetically-first namespace, which is `agents` — real, created
  for sidecar injection, and holding zero attack paths. It now picks one that has kill-chains.

### And the last failure was a sleep

`console-fixes-batch2` asserted every graph node sits inside its cluster hull, after
`waitForTimeout(600)`. It reported "1/85 nodes fell outside their nearest hull", 259px out from a
radius of 141 — indistinguishable from a node rendered in the wrong place. It passed on retry.

The 600ms was calibrated against a smaller graph; the seeded estate reached ~85 nodes and the wait
expired mid-settle. It now polls for the transform signature to stop changing, and requires **two
consecutive** identical samples — the canvas reaches a quiet moment before its data lands and then
re-lays-out, so one match can catch that lull. The wait condition is stability, not the assertion:
waiting for "all nodes inside" would be circular.

> **Rule, earned three times this session: a fixed sleep is a threshold calibrated against whatever
> the estate happened to contain that day. Grow the data and it becomes a defect report.**

---

## EXIT STATE MET — all seven gates, one run

```
✓ G1 pytest: 1952 passed   ✓ G1 vitest: 759 passed   ✓ tsc  ✓ eslint  ✓ build
✓ G3 browser: 183 passed, 0 failed, 0 did not run
✓ G2 integration: 68 passed   ✓ G2 attacks: 101 passed   ✓ G2 attacks: 0 xfailed
✓ G4 @ concurrency 8 and 16: within budget, every scenario decided correctly
✓ G5: all 5 faults degraded correctly and legibly
✓ G6: 4 journeys, every persona proved a flip, no blockers, 7 findings filed
✓ G7: tree clean · chart renders both profiles · the workers-vs-memory guard still fires
       · gitleaks clean over main..HEAD · CI workflow present
```

### The last three failures were all the checker, not the product

G3 passed 0-failed twice standalone and then failed inside `exit-state.sh` three times running. Each
cause was a different way of measuring the wrong thing:

1. **The checker invoked playwright directly** instead of `scripts/e2e.sh`, skipping the exported
   `NRVQ_API_URL`, the reset and re-seed, the token liveness check, the lockout and rate-limit bucket
   clears, and the login gate. `e2e.sh` carries a comment saying precisely this, and the script written
   to enforce the gate ignored it.
2. **It read the absence of a "N failed" line as one failure.** Playwright prints no such line when
   there are none, and the default was `1` — so a run of 183 passed and nothing failed reported
   "? failed". A gate that treats missing bad news as bad news is as useless as one that treats it as
   good news. Absence now reads as zero, made safe by two guards that distinguish a crashed run: a
   zero exit from `e2e.sh` and a passed count clearing its floor.
3. **It ran L3 before L4**, when `EXIT-STATE.md`'s own G7 row says "L3 after L4". The attacks suite
   writes ~101 tests' worth of `framework=redteam` audit rows immediately beforehand, and
   `audit-filters-and-volume` counts rows. The document said which way round; the script disagreed
   with the document it exists to enforce.

### And then the gate failed on its own exhaust

With the order fixed, `audit-filters-and-volume` still failed: "unfiltered total must include the test
rows". `audit_log` had reached **83,128 rows** — chaos and the latency harness drive ~13,000 real
evaluate calls between them, every red-team suite adds hundreds, and the reset only ever cleared
throwaway *policies*. A spec looking for its own handful of rows cannot find them under eighty
thousand.

Decision volume is now part of the reset baseline: `TRUNCATE audit_log` before seeding, which is safe
here and only here because every row the suite depends on is re-created by the seeders immediately
after. What is destroyed is accumulation, not fixtures — and accumulation is exactly what makes one
run incomparable to the next. Every run now starts at 1h=22 / 24h=198 / 7d=1254.

> **The through-line of this whole gate: five separate times, a failure that looked like a product
> defect was the harness measuring something other than the product. The cluster running a published
> image, an expired token, a login lockout tripped by a neighbouring spec, a rate-limit bucket shared
> by 190 specs, and finally the checker's own ordering and parsing. Each one was indistinguishable
> from a real defect until the discriminating experiment was run — and in every case the experiment
> was cheap and the guess was expensive.**

---

## Reversing the builder-chrome decision, and moving two detail panels into dialogs

Both came from walking the live console. The second is the more interesting one, because the record was
already clear and wrong.

### The chrome decision is reversed

`IMPLEMENTATION-LOG.md` said *"The plan's Phase 5 lists builder chrome … **Decision: not built**"* and
`EXIT-STATE.md` listed it as out of scope. Of the eleven components the handoff specifies, only
`ScopeCell` and `ProvenanceBadge` were wired in. `Stepper.tsx` and `TokenInput.tsx` had been **built to
spec and left dead** — imported by nothing but their own tests.

Built now: the 54px top bar with a `namespace / class` breadcrumb, the stepper strip (wiring the
`Stepper` that already existed), a sheet-level footer action bar, and `RegoDrawer` as a 46px rail.

**The rail is the load-bearing part.** The compiled rego held half the sheet permanently, and the
allowed-tool row is specced `[name] [ScopeCell flex: 2 1 300px] [remove]` — at half width the ScopeCell
wrapped its four slots into a stack of fragments. A permanent reference pane was crowding out the one
control this whole redesign exists to make readable. Collapsed, the rail still carries the budget line
sideways, because those three caps are the reason an expert watches that pane at all: you lose the
source, not the signal.

**The footer is the other real fix.** `Run dry-run` and `Save & enforce` lived inside Step 3, inside
the *right-hand rego column*, below a code editor — so the primary CTA of the sheet was in the
reference pane, and expanding the editor pushed it out of view. A previous fix had made it `sticky` to
work around that, which is a good hint the placement was wrong.

Save's disabled reason is now **visible text** under the button via the existing
`InlineDisabledReason`, not a `title`: `.btn:disabled { pointer-events: none }` means a disabled button
can never show its tooltip, so every reason we put only in `title` was unreachable exactly when it was
needed. The footer's status line describes the STATE and the button's reason names the ACTION — the
first draft printed one sentence in both places, spending the two most-read spots in the sheet on the
same words.

### Two bugs in my own new component, both from the same root

`Monaco` sized `height: 100%` inside a block with no height of its own resolves to **zero**: the drawer
opened onto an empty pane with a scrollbar and nothing under it. And the authoring column, capped at
860px for a readable measure, sat left-aligned with ~500px of void where the rego used to be — which
reads as a pane failing to load. Both were only visible in a screenshot; both passed every test.

### Tools and MCP Servers

The detail panels rented a third of each page to something empty until a row was clicked, so the tables
ran cramped. They are dialogs now, over a blurred backdrop, with the row still highlighted behind.

What stays OUT of the dialog is the interesting part: the collision notes and the empty state. Those
answer questions you have **before** you know which row to click — "why does one name appear twice",
"why is this empty" — and behind a click, the reader has to already suspect the thing the note exists
to tell them. The tests that asserted them with no row selected were right to.

`Modal` gained `wide` (760px — a definition diff wraps into uselessness at 520; the injected
description in the drift case now reads on one line), `subtitle`, and **focus restore on close**. It
moved focus in and never gave it back, which was tolerable for two dialogs and hostile once opening one
is how you read a table row.

### The guard that was right and incomplete

The `podAnnotations` rollout lever went on api and engine only. This UI-only change then sailed
straight through the guard that exists to catch exactly it: the bundle was built, loaded into the node,
and the pod **serving the console** kept running the previous one — the redesign looked unshipped in
the browser while every gate reported success. All four first-party deployments carry it now, and
`00-up.sh` verifies all four.

> **Rule: a provenance guard that covers one component of four still reports "this cluster runs your
> code". Second time this class of bug cost a session; the first fix was correct and partial.**

### One test updated, and why it is not a weakening

`builder-scope-p1.spec.ts` reads the compiled rego through Monaco. With the drawer collapsed the editor
is not mounted, so the spec now opens the rail first — which is what a user does to read the rego. The
vitest suite's `renderSheet()` helper does the same, because nearly every test in it asserts on the
compiled preview and their premise is a sheet where that preview is on screen. The one test that
asserted the *old* 260px↔560px height toggle is rewritten for rail↔drawer, and now also asserts the
budget survives the collapse.

**Still not built: `ConditionPicker`.** Deferred deliberately — it changes the condition-editing model
rather than the layout, and `ConditionChip` alone exposes ~20 testids both e2e specs drive. Shipping it
alongside a layout restructure would make any regression unattributable.

---

## ConditionPicker — the last piece of the builder chrome

`ui/src/components/policies/ConditionPicker.tsx` replaces the two `<select>` elements that were the
only place a tool's own arguments were ever named.

A native select is the wrong instrument for this job in three ways that all mattered:

1. **It cannot show a REASON.** Non-addressable arguments were rendered as disabled `<option>`s with
   the reason appended to the label and repeated in a `title` — a tooltip on a disabled option, which
   no browser shows. The operator saw a greyed line and no way to learn why. This is the same defect
   as `.btn:disabled { pointer-events: none }` hiding a disabled button's tooltip, in a different
   control, and it had been sitting next to that one the whole time.
2. **It cannot be searched.** A tool with thirty arguments is a scroll.
3. **It collapses the moment you look away,** so the two groups — this tool's own arguments, and what
   the call carries or reaches — could never be seen side by side. That comparison is the entire
   lesson about which one to reach for.

Three groups, in an order that is itself the argument: **this tool's arguments** first (most specific
thing anyone can say, and until recently unsayable at all), **whole-call facts** second (broader, and
they hold wherever the value sits in the payload), **undeclared paths** last (reaching for it means
the schema did not describe what you want). Disabled options carry `aria-disabled` rather than
`disabled`, so a screen reader can still land on them and read the reason — `disabled` removes a node
from the tree, which is hiding by another name.

**What was NOT built, and why.** The prototype's capture-off band needs `params_available`, which is a
propose-side signal the builder does not receive. Rather than fabricate one, the picker states the
condition the builder actually knows: a tool with no declared schema says so, and a tool whose schema
declares no properties says that instead.

### The migration made one assertion possible that was not before

`BuilderSheet.test.tsx` asserted the disabled state of `<option>` elements. It could not assert the
REASON, because a `title` is not rendered text. The picker's version reads:

```ts
expect(anInteger).toHaveAttribute("aria-disabled", "true");
expect(anInteger.textContent).toMatch(/only text/i);
```

Eleven unit tests and six e2e steps moved from `selectOption` to a `pickCondition` helper. Both helpers
are **idempotent** — they open the picker only if it is not already open — because they get called
inside `waitFor`, and the trigger is replaced by the popover on first click, so an unconditional second
click reports "unable to find builder-condition-picker-open" and the retry loop blames a missing
element instead of the condition it was waiting on.

With this, `EXIT-STATE.md` has nothing left in its "explicitly not in scope" list for the builder.

---

## Reverted: the Visual Policy Builder UI

The builder chrome and `ConditionPicker` described in the two entries above are **reverted**.
`BuilderSheet.tsx`, `BuilderSheet.test.tsx`, `BuilderSteps.css` and `builder-scope-p1.spec.ts` are
restored byte-for-byte to `5362d42`; `RegoDrawer.tsx` and `ConditionPicker.tsx` are deleted.

**Why.** The old builder is the one carrying the full validated history — months of e2e runs, the
whole `BuilderSheet.test.tsx` suite written against it, and every gate that has ever passed on this
branch before the restructure. The new chrome passed its gates too, but it was hours old against a
surface whose value is that it is trusted to author enforcement. Trading a long validation record for
a nicer layout is the wrong trade on the one screen that decides what an agent may do.

**Scope, verified rather than asserted.** `git diff HEAD --name-only` after the revert lists six
files, all under `ui/src/components/policies/` or the builder's own spec. Nothing else moved:

| Kept | Where |
|---|---|
| Tools + MCP detail dialogs, blurred backdrop, full-width tables | `Tools.tsx`, `McpServers.tsx` |
| `Modal` gaining `wide`, `subtitle`, focus-restore | `common/Modal.tsx`, `index.css` |
| `podAnnotations` on all four deployments + the four-way rollout guard | `helm/`, `00-up.sh` |

The two builder commits touched only builder files plus docs, which is what made a clean revert
possible — worth noting as an argument for keeping a change confined to its own surface even when
you are confident in it.

**What the revert costs, stated plainly.** The real defect I found while walking through the new
picker is still live in the old builder: a `param_paths.<path>` clause addresses one named argument
but renders under a heading reading *"A fact the ENGINE derived about the call, not one named
argument."* That mislabel predates both builder commits. It is a small, self-contained fix to the
old builder if wanted, independent of any layout work.

---

## Keeping the builder's features while reverting its layout

The revert above went too far. It took the chrome — which was the point — but also took two things
that were product value rather than decoration, and it left a real defect in place.

Restored into the OLD layout, with no structural change to the sheet:

**`ConditionPicker`.** The two `<select>`s it replaces cannot show a disabled option's REASON. The
non-addressable arguments carried theirs in a `title` on a disabled `<option>`, which no browser
renders — so an operator saw a greyed line and no way to learn why `retries` or `attachments` could
not be scoped. It also cannot be searched, and it split the tool's own arguments from the whole-call
facts into two dropdowns that could never be compared, which is the one comparison that teaches the
difference between them.

**Save's blocked reason as visible text.** `.btn:disabled { pointer-events: none }` means a disabled
button never fires the hover that would show its tooltip, so a reason living only in `title` was
unreachable exactly when it was needed. Now rendered beneath the button via `InlineDisabledReason`.

### The defect the walkthrough surfaced

`param_paths.<path>` clauses are STORED as facts — that is how the compiler emits them — and the facts
pass rendered every non-negated fact under a heading reading *"A fact the ENGINE derived about the
call, not one named argument."* So a clause addressing exactly one named argument was filed under a
heading stating that it does not.

ARGUMENT vs WHOLE CALL is the distinction the scope panel exists to teach — an argument clause fails
when the caller omits that argument; a whole-call fact holds wherever the value sits in the payload.
Filing one under the other teaches it backwards. This predates every builder commit in this session;
it only became visible once the picker put the same two groups side by side.

Fixed by ordering the facts pass by what each clause addresses and emitting the heading at each group
boundary — one pass, so the row markup stays in one place, and `i` remains the clause's REAL index so
`removeFact(tool, i)` still removes what the operator clicked. That last point has its own test: the
display order is now a sort, so if it ever leaked into the index the wrong clause would be deleted
silently and the operator would be left enforcing something they believed they had removed.

`ScopeSection` gained a `data-testid` so the tests assert grouping by DOM order rather than by hunting
for copy in a `textContent` blob — the grouping is the guarantee, and it should not break every time a
label is reworded. Both tests were verified against the old behaviour: reintroducing the bug fails the
grouping test.

### What survived the revert untouched

Worth stating, because it was the question asked: `ScopeCell` and its four slots, the unscoped banner,
the mode-fork callout, the provenance badges and the refinements were all in the builder BEFORE the
chrome work, so the revert never touched them. The P1 fix — "a first-time operator must discover
argument scoping without being told it exists" — is intact.

---

## Walkthrough round 2 — the lookalike a proposed rule never mentioned

Found by reading the console rather than by any test: **Propose from traffic** offered
`send-s-nd-email`, a rule whose APPLIES TO band read *"calls to send_email"*. Its raw clause is

```
tool_name in ['sеnd_email']        # U+0435 CYRILLIC SMALL LETTER IE
```

The Tools page flags that exact tool with a red **Homoglyph** pill. This page — the one carrying
**Save as draft** and **Open in Visual Builder** — said nothing, and the two spellings are identical
in the console's font. The rule id was the only tell, and only because the slugifier dropped the
non-ASCII character.

### Why this is not a missing badge

The generated allowlist matches EVASION-NORMALIZED. `norviq/api/threat_intent.py` emits

```rego
in_allowlist { allow_skeletons[input.tool_name_normalized] }
```

and `skeleton()` folds Cyrillic е to Latin e — verified, not assumed:

```
skeleton('sеnd_email') == skeleton('send_email') == 'send_email'
```

So approving that rule grants the look-alike **and** the real ASCII tool. That folding is correct and
deliberate — a homoglyph must not dodge a DENY — but it means an operator's allow silently widened to
two names, on the surface where they click Save, with nothing on screen saying so.

The same defect shape this project has now hit eleven times: **one concept, two components, only one
of them holding the fact.** Tools computes `name_skeleton` from the registry; the rule card never
asked.

### The fix

Annotation attached in `predicateSentence()` — the ONE vocabulary both the rule card and the near-miss
card render through — rather than in either page, because the near-miss card quotes the same clause
back after a refusal and would otherwise have had the same blind spot.

- `lookalikeOf(value)` → `{ value, codepoints, masked }`. `masked` (`s·nd_email`) is the load-bearing
  field: `U+0435` alone says something is wrong, not *where*.
- Scoped to `IDENTIFIER_FIELDS = {tool_name, mcp.server}` — names the engine folds. A non-ASCII
  character in a `data_classes` term or a `param_paths.to` address is ordinary, and a warning that
  fires on ordinary values is one operators learn to click past.
- Attached in `done()` **and** on the un-humanised fall-through, so a raw predicate is annotated too —
  a raw label hides the codepoint every bit as well as prose does. That branch has its own test.
- `LookalikeNote` renders under the CLAUSE, not beside the rule id: a rule can name several tools and
  a card-level badge cannot say which one is the spoof.
- It states the CONSEQUENCE, which is the half an operator cannot derive: *"the rule grants the
  look-alike and the plain-ASCII tool of the same shape."*

Test literals are written `"s\u0435nd_email"`, never pasted. A pasted literal is a test that looks
like it asserts the ASCII case and silently asserts the other one — the same trap as the bug.

### A vacuous green found on the way out

`npx vitest run` reported **761 passed, 2 errors** at HEAD, and had for some time. The errors were
unhandled rejections from `AppContext.p1.test.tsx` / `AppContext.sticky.test.tsx`:

```
No "ApiError" export is defined on the "../api/client" mock
```

`AppContext.tsx:194` does `e instanceof ApiError` to tell a 429 from a real outage — the branch added
earlier this session when the Overview's rate-limit budget made `AppContext` report "no namespaces" on
a throttled read. With `ApiError` undefined, the catch handler threw a `TypeError` **before reaching
that branch**, and the test still passed, because *"posture stays UNKNOWN"* is also true when nothing
ran at all.

Fixed with `importOriginal` rather than a stub class: `instanceof` needs the same constructor
`client.ts` throws, so a hand-rolled `class ApiError {}` in the mock would have kept the test green and
still not exercised the branch.

**Rule.** A vitest "N errors" line under a green run is not cosmetic. An unhandled rejection inside a
`catch` means the assertion's subject was never computed, and every such test is asserting the
post-condition of code that did not execute.

Gate after both fixes: **86 files · 773 passed · 0 errors** (was 761 + 2 errors), tsc clean, eslint
clean, build clean.

### The harness measuring itself, again — a truncated seed reported as a range-selector bug

The browser suite came back **182 passed, 1 failed, 7 skipped**. The failure named
`range-selector-scope.spec.ts` — *"switching range on Overview actually refetches — 1h total ≠ 24h
total"*. The range selector was fine.

`/audit/stats` returned **total=36 for 1h, for 24h AND for 7d**. Identical across every window is not
a filtering bug, it is an empty history: the whole table held 3948 rows spanning eight minutes. The
seeder's `seed_backdate()` — 1232 rows spread over seven days, whose print line literally reads *"so
1h, 24h and 7d are different questions"* — had never run.

`seed.py` died earlier, in `seed_redteam`, on a `TimeoutError`. `POST /redteam/suite` evaluates the
corpus against every class in the namespace synchronously, and the step immediately above it seeds
twelve classes into `default` — 348 evaluations, each a real OPA call. The shared 30s `post()` timeout
was never sized for it. `main` aborted, and every fixture after that point silently went unwritten.

And `scripts/e2e.sh` **warned and carried on**:

```sh
|| echo "WARNING: seeding failed — specs asserting seeded data will fail" >&2
```

7.3 minutes later the run reported a defect in a surface that had nothing to do with it, because a
missing fixture surfaces wherever it is READ, not where it was missed.

**Three fixes, none of them to the spec.**

1. `post()` takes a per-call `timeout`; `seed_redteam` uses `REDTEAM_SUITE_TIMEOUT_S = 300`, sized
   from the observed ~90s run with headroom. The failure mode of being too low is not a slow seed but
   a truncated one.
2. `seed_redteam` treats a client timeout as a THIRD outcome, distinct from failure — the request was
   accepted and the server is still working — and *verifies* via `/redteam/results/latest` instead of
   assuming either way.
3. `e2e.sh` **aborts** on a nonzero seed, printing the last 20 lines of the seed log. `seed.py` already
   returned a count of failed steps; nothing was reading it.

**Rule.** A harness step that warns instead of failing converts its own breakage into a product
defect report, and hands it to you 7 minutes later wearing someone else's name. If a fixture is a
precondition, a missing fixture is a fatal error — the run that continues without it is not a weaker
signal, it is a misleading one.

This is the sixth time this session a failure that looked like a product defect turned out to be the
harness measuring something other than the product: a published image, an expired token, a stale
port-forward, a login lockout tripped by a neighbouring spec, a shared rate-limit bucket, the
checker's own ordering — and now a seed that stopped two thirds of the way through and said so only
on stderr.

After the fixes, the seeder reports `backdate INSERT 0 1232 spread over the last 7 days`, and
`/audit/stats` returns **22 / 198 / 1254** for 1h / 24h / 7d.

---

## G4 on AKS: the engine denies benign traffic when it is CPU-starved

Moved off kind onto the AKS cluster (`rg-opsai-dev-eastus-001/norviq`) to get a latency measurement
that is not competing with Docker Desktop and Chrome on a laptop. The measurement is worse, and the
reason is the finding.

### The numbers

Quiet cluster, nothing else running, measured INSIDE the api pod:

```
concurrency 8    p50 ~560-660ms   p95 1.8-3.6s
concurrency 16   p50 ~1.2-1.9s    p95 3.3-6.0s
                 benign: WRONG DECISION — expected allow, saw
                 ['block/evaluator_error', 'block/evaluator_fallback'] on 90/200 calls
```

kind, for comparison, held p50 ~190ms with a true p95 around 420-450ms against a 500ms budget.

### Why

| | |
|---|---|
| node pool | 2 × `Standard_A2_v2` — 2 vCPU / 4 GB **each**, for the whole stack |
| `vmss00002q` at rest | CPU 74%, **memory 101%** |
| `norviq-engine` CPU limit | **500m — half a core** |

Under concurrency 16 the engine cannot finish an evaluation inside its fail-closed deadline, so it
does exactly what it is built to do: it denies. **45% of benign calls were blocked.**

### The finding, stated as a product property

The product is not wrong here — failing closed is the correct behaviour and the alternative is
unthinkable. The finding is what that costs, and it is stronger than the docstring's "latency is an
availability property" suggests:

**Starve the engine of CPU and Norviq stops being a policy engine and becomes an outage.** There is no
intermediate degradation. Below some CPU floor the deny rate for LEGITIMATE traffic goes from ~0% to
45% at one step of concurrency.

Two consequences worth acting on, neither done here:

1. **Nothing tells the operator this is the cause.** The console shows an `engine errors` count (the
   Overview's amber band, "11 engine errors in 24h — fail-closed OPA-evaluation faults, not policy
   blocks") which is honest but not actionable. It does not say "your engine is CPU-starved and is
   denying real traffic". An operator reading a spike in blocked calls would go looking at their
   policies, which are fine.
2. **The chart ships a 500m engine limit** with no guidance tying it to expected concurrency. The
   render-time guard added earlier for `api.workers` × memory is the right shape of idea; the engine's
   CPU limit needs the equivalent.

### What was NOT done

The 500ms budget and the G4 gate are UNCHANGED. Fitting a threshold to undersized hardware would
convert a real capacity finding into a green check, which is the failure mode this whole exit-state
exists to prevent. G4 is recorded as **not measurable on `Standard_A2_v2`** — a statement about the
environment, not a pass.

### A methodology mistake worth recording

The first AKS G4 run was taken WHILE the browser suite was running against the same cluster, and the
browser suite's 4 failures were taken while the latency probe was firing 2,000 evaluations at the same
API. Both numbers were contaminated, in both directions, and the giveaway was `large-payload` showing
`allow,block` for a byte-identical payload.

This is the sixth time this branch has recorded a measurement that described something other than the
product — and the first where I caused it myself rather than inheriting it. The rule already written
here ("never suppress stderr on a step whose failure you have not yet seen") has a sibling: **never
start a measurement while another one is running against the same system.** Sequential or nothing.

---

## Release pass: the audit backlog, G1, and the live gate on kind (2026-08-05)

Ten agents fixed the 29 catalogued audit findings across five disjoint file groups, then eight more
built G1. Each group was fixed by one agent and then **refuted** by a second whose only instruction
was to prove the first wrong.

### The refutation pass is the entire value, and that is the finding

The fixers' own reports were confident, detailed, and wrong in four places — every one a defect of the
same severity as the finding it was closing:

| Introduced by | What it did |
|---|---|
| the finding-19 fix | CRITICAL fail-open in `compileConditionLine` |
| the finding-27 fix | HIGH bypass in `constraintExpr` |
| the finding-5 fix | HIGH fail-open in **both** rego copies |
| the finding-9 fix | bounded the new destination budget on RAW strings, so 70 spellings of one allowlisted host evict the real destination — finding 1's eviction rebuilt through a new door, under a docstring claiming padding could not starve it |
| the finding-8 fix | gated promotion on `verb == "unknown"`, but `classify_tool` falls back to agent-supplied params, so `{"query": "select 1"}` cancels an admin's `delete` promotion — a demotion primitive handed to the attacker in place of the one being closed |

**Rule: a fix is not evidence that a defect is closed. Only an adversary is.** Nothing on this branch
should land on a single agent's report that its own work is correct.

### Three tests were asserting nothing, in three different ways

1. `test_a_bracket_in_a_key_forges_an_index_too` — relaxed from an exact list to a membership check
   while being "fixed". Pinned nothing about minting.
2. `test_a_version_quad_is_not_an_ip_destination` — asserted a fail-open outright
   (`{"host": "999.1.1.1"} == []`), missing octal `0177.0.0.1` and bare IPv6 entirely.
3. The `itOpa.skip` version-skew gap — **the compiler was correct all along, in both modes.** The
   test's helper could not build the document its name claimed, so a `undefined` default silently
   swallowed the state under test. The skip was hiding a broken fixture, and the commit message that
   left it open asserted a compiler defect that did not exist.

I then hit the same class twice myself:

- `test_unclassified_denial_is_separately_identifiable` used `zzz_exfil` as unclassifiable gibberish.
  It now classifies as send/high, because "exfil" entered the egress lexicon — so the test kept its
  assertion and lost its meaning.
- I wrote a new test for `detail: "none"` with non-empty keys, then deleted it: **no server response
  can produce that state**, so it pinned nothing. Writing the test is not the same as the test being
  able to fail.

### G1 changed shape under contact

The plan was "persist the `param_paths` key-set". Two things only appeared once it ran:

- **Values ride in KEY positions.** `{"balances": {"<pan>": 25.0}}` wrote a PAN into the key-set on a
  default install whose value capture is deliberately OFF — a worse privacy posture than the opt-in
  field beside it. "Keys only" is not automatically "no values".
- **Observed ≠ constrainable.** `param_paths` carries STRING leaves only, so `amount: 25.0` is named
  but never derivable; under `default decision = "block"` a clause pinned on it refuses *every* call,
  and a key-only dry run cannot warn you because it blocks the sound predicates too. Hence
  `param_keys_pinnable`. **Showing an argument you cannot constrain is honest; offering it is a trap.**

### The recurring defect, hit again — and this time between two agents

The console gated its unpinnable note on `detail === "masked"` while the propose group, working
concurrently, made `pinnable` meaningful for key-only rows. Both were internally consistent; the union
hid `amount` on exactly the install the feature exists for. **Two components keyed differently on one
concept** — the twelfth instance on this branch, and the first produced by parallelism rather than
inherited. Disjoint file ownership prevents edit conflicts, not contract drift; only central assembly
catches that.

tsc then rejected my first fix's `!== "none"` guard as provably dead — the narrowing was already the
guarantee, and the clause was noise pretending to be a safeguard.

### Two gates could fail without saying why

- **G5** rendered `✗ G5:` with nothing after the colon whenever `chaos.py` exited non-zero without
  printing a `✗`, and its log was a `mktemp` already gone by the time anyone read the summary. A gate
  that fails silently is worse than one that does not run: nobody can tell a regression from a flake.
- **G4** reports p50 beside the breach now. p95 alone cannot separate "the enforcement path got
  slower" from "this host was busy" — opposite conclusions, identical summary line.

### What was NOT done, again

The 500ms budget is UNCHANGED. Three consecutive runs of identical code breached `sql-injection`,
then `benign`, then nothing, with p50 flat at ~200ms and every decision correct. Measured in-pod
against the real scenario payloads, the new argument capture costs **0.004–0.008 ms/call** against a
76–126 ms overshoot — five orders of magnitude too small to be the cause. G4 is recorded as **not
measurable on this host**, which is a statement about the environment, not a pass.

### Live state

The corrected baseline was **never in the cluster** until this pass: `rego_length` went 32063 → 38729
at version 14. The earlier fix landed on `comprehensive.rego`, and `webhook/presets/strict.rego` is
the copy that ships.

---

## MCP server registry (P3) + asset-graph node (6a) — live on kind, chatbot-lab

### What the plan predicted, and what only the cluster found

The plan said to verify "through the real MCP SDK client from the agent pod, not raw POSTs — the SSE
bug last night only reproduced with a spec-compliant client". That instruction earned its place four
more times. Everything below passed the full unit suite before it was deployed.

1. **`settings.namespace` does not exist.** The HTTP transport read
   `getattr(settings, "namespace", "")` for BOTH control-plane stores, so both addressed the control
   plane with an empty namespace on every deployment there has ever been. The `getattr` default is
   what hid it: a phantom read with a fallback looks like a deliberate optional and errors nowhere.
   Fixed at the source — the namespace comes from the attested identity, which is what the stdio
   transport was already doing.

2. **`api_url` and `policy_engine_url` are two env vars for one target.** Every deployment sets only
   `NRVQ_POLICY_ENGINE_URL`, so anything reading `api_url` fell back to the short name
   `http://norviq-api:8080` — which resolves only inside the API's own namespace. A sidecar anywhere
   else got "Name or service not known" from a proxy whose `/evaluate` calls were working perfectly,
   so the symptom named neither variable. `api_url` now follows `policy_engine_url` unless stated.

3. **The HTTP transport never reported anything to the control plane.** This is the big one.
   `ControlPlanePinStore.put()` only enqueues; `flush()` sends, and nothing on the streamable-HTTP
   path called it. On the transport the 2026-07-28 revision mandates and every real deployment uses,
   no MCP observation ever reached the control plane: the console's MCP Servers page was empty on
   every such install, the pin table stayed at zero, and cross-pod drift detection had nothing to
   compare against. Local Gate A worked throughout — which is exactly why it survived. The
   enforcement was real and the entire record of it was missing.

   Not findable by unit test as the suite was written: every test asserted what the firewall DECIDED,
   and none asserted that anybody was ever told. **The rule learned: for any control that produces a
   record, one test must assert the record, not the decision.**

4. **A refused discovery was recorded as `escalate`.** `apply_pep_denial` deliberately left escalate
   alone, on the reasoning that promoting it would change enforcement under cover of an
   audit-fidelity change. Correct for a decision the caller is about to act on — and a `pep_decision`
   is never one. It is only ever set on a REPORT of a refusal that already happened, and the return
   value on that path is discarded. So the carve-out did not preserve behaviour, it falsified the
   record: tools withheld, console saying a human was being asked.

5. **Every audit row and pin this transport wrote claimed `transport: "stdio"`** — the firewall's
   default, never overridden by the HTTP driver. A console filtering by transport read a constant.

### What the console itself showed

`rugpull` rendered "BLOCKED | BLOCKED" across Status and Registration. Two columns, one word, and the
operator deciding whether to unblock could not see that its definitions were clean — the fact that
decision turns on. Split into `observed_health` (knows nothing about decisions) and `health` (folds
the decision in, remains the sort key).

### Product decisions taken autonomously

- **A cold-start control-plane outage fails OPEN.** Before the first successful load nothing is
  enforced, so a proxy that starts while the API is unreachable does not enforce a `blocked` decision
  until it can read one. Failing closed was tried in another form and is documented in
  `HttpProxy._install_pin_store`: three proxies refused every call at Gate A for eleven hours and the
  failure was indistinguishable from a defence working. Logged loudly (NRVQ-MCP-5070); a load that
  fails AFTER a success keeps the last good copy, so an API restart cannot un-block a server.
- **An unrecognised status from a newer control plane degrades to `discovered`, not `blocked`.** A
  rolling upgrade must not black out discovery for every server the moment the API is a version ahead
  of the sidecars.
- **Registering defaults to read-only.** Registering says the integration is expected here, not that
  everything it offers may be invoked.
- **Unblock returns a server to UNREVIEWED, never to registered.** Withdrawing a refusal must not
  manufacture an approval nobody gave.
- **The graph node carries no pin or registration state.** Those live in the tables where an operator
  changes them; a copy would be a second answer that goes stale the moment somebody clicks Block.
- **The report-due rule is a catalog FINGERPRINT, not "Gate A rewrote the listing".** A persistently
  poisoned server is stripped on every list, so the rewrite rule handed the report rate to the server.

### The six-becomes-seven UI break points

The plan listed five places a new asset-graph node kind disappears. Working through them found two
more, both silent: `AssetGraphCanvas` has its OWN radius table separate from `NODE_RADIUS` (an
unlisted kind draws a circle of NaN), and `AssetEdge`'s type union had no `serves`. A third was in
`computeSets`: `s.types[kind]` for a kind with no chip is `undefined`, which is falsy — so any future
kind was hidden by default with no filter to turn it back on. That is why `namespace` had to be
special-cased there; the fix generalises it instead of adding a second special case.

### Live proof (chatbot-lab, kind)

The chatbot's LangChain agent was repointed at the two `norviq.mcp` firewalls and run:

- `malicious` — Gate A stripped 3 poisoned definitions (line_jumping, concealment + exfil_directive +
  hidden_marker, concealment) before they reached the model. 5 tools observed, 3 flagged critical/high.
- `rugpull` — blocked from the console; the decision reached a RUNNING proxy in ~24s and a re-list
  through the real MCP SDK client returned zero tools.
- Audit truth: `block | mcp_server_blocked | tools/list | rugpull`, with `transport: http`.
- Denial coalescing verified on the discovery path: 5 listings of a blocked server → 1 audit row.

## MCP baseline controls (P4) and the builder narrowing (P5)

### P4a — five controls ported from the template into the shipped preset

Live-verified through `/evaluate` on kind: drift → escalate `mcp_definition_drift`, never-scanned →
escalate `mcp_definition_never_scanned`, quarantined → block `mcp_tool_not_approved`, scanner-critical
→ block `mcp_definition_flagged`, healthy MCP call → allow, non-MCP call → allow.

### P4b — the registry-backed pair, and the trap the precedent left

`egress_allowlist.py` is a complete compiler with engine-side collection and **no router**: its only
importer is its own test. The MCP registry module ships with `_materialize_mcp_registry` wired into
every write path, and the test that asserts it comes before any of the rego assertions.

**A live finding worth keeping.** The first probe after deploying showed a READ through a REGISTERED
server blocking with `mcp_unregistered_server`. The generated module was correct — evaluated
standalone it returned `allow`. The block came from the **stale hand-written `__guardrail__`** left in
`chatbot-lab` by the earlier L2 campaign, whose `known_servers = {"rugpull"}` had never been updated.
That is precisely the failure mode P4 exists to end: a hand-maintained list in a copy-me template,
enforcing a stale answer with the weight of an operator guardrail.

Isolating the shipped control from the legacy one took constructing a case where the two DISAGREE:
`rugpull` is known-and-writable to the legacy guardrail and registered-read-only in the new registry.
Read → allow (both agree). Write → **block, `mcp_unapproved_write_server`** — a verdict only the
generated module can produce. The shipped control is live and its decision is the one that won.

### Product decisions taken autonomously

- **An empty registry is INERT**, the opposite of the egress module's discovery-first choice. An empty
  egress allowlist flags destinations and interrupts nothing; an empty server registry would flag
  every MCP call on a fresh install and the operator's first act would be to switch it off.
- **Unregistered AUDITS, unapproved-write BLOCKS.** Registration is housekeeping that lags reality;
  which servers may be written through is a decision already made.
- **Server ids are not case-folded**, unlike egress domains — a domain is case-insensitive by
  specification, a server id is an operator-chosen string the PEP reports verbatim.
- **`unknown` verb is not a write.** The classifier saying "I cannot tell" is not evidence.
- **P5 is a condition, not a fourth tier.** All three tiers are attested; `mcp.server` is
  PEP-reported. A tier selects which rego program runs, so a forgeable string must never be one. The
  narrowing is ANDed into EVERY condition row — a builder rule's rows are ORed, so appending a row
  would have WIDENED the rule to "…or any call through this server", the opposite of the promise.

### What is deliberately still open

Part 6b (attack-graph non-agent origin) is unstarted, as the plan sequenced it: it needs the
"which of the three attack-path surfaces is canonical" question settled first, and bundling it here
would have made that decision by accident.
