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
