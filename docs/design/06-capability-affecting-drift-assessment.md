# Capability-affecting contract drift — feasibility assessment

**Status:** assessment only, nothing implemented. **Spec:** `capability-affecting-v1.0.md` (frozen, read
as given). **Date:** 2026-08-17.

## Verdict

The mechanism is feasible and cheap: we already pin the entire consent surface the spec defines, at
approval time, in full text. A classifier at the drift point is a few hundred lines against data we
already hold, hooking a path that already exists.

**But the value proposition should be inverted from what "drift gate" implies.** The win available
here is *precision on a gate we already run* — today we refuse on **any** digest change, including the
one structural class the spec explicitly excludes and calls its largest bucket. Framed as "block less,
truthfully", this is a strong small piece of work. Framed as "detect capability-affecting
vulnerabilities", it will disappoint, and the reference material says so unambiguously.

The single most likely reason this fails is stated in §7 below. It is not latency and not false
positives — it is that **for a runtime MCP client, the rubric's baseline does not exist.**

---

## 1. Do we already store a tool contract at approval time?

**Yes, and it is sufficient to diff against.**

`mcp_tool_pins` (`norviq/api/db/models.py:422-449`), keyed `(namespace, server_id, tool_name)`, carries
`approved_digest`, `last_digest`, **`approved_canonical`**, **`last_canonical`**, `approved`,
`approved_by`, `approved_at`, `scan_severity`, `findings` (jsonb), `drift_count`, `transport`,
`first_seen_at`, `last_seen_at`.

The canonical form is `norviq/mcp/pins.py:76` over:

```python
_PINNED_FIELDS = ("name", "title", "description", "inputSchema", "outputSchema", "annotations")
```

That is the spec's consent surface — description prose, input schema, behavioural annotations —
**exactly**, plus `name`/`title`/`outputSchema`. Canonicalisation already normalises key order and
whitespace (`sort_keys`, pinned separators), so a server re-serialising its own catalog does not read
as a change. Nothing new needs to persist for a first slice.

Three findings worth acting on:

**We pin `outputSchema`, which the spec excludes by rule.** Part A: `output-schema-changed → No`, and
the spec notes it is *"the largest structural bucket; excluded by rule, not by omission."* So our
current binary gate fires hardest on the class the spec says should never gate. This is the clearest
immediate win and it needs no prose analysis at all.

**The in-process pin drops the prior text.** `ToolPin` (`pins.py:98-112`) carries `canonical` (the
approved definition) and `last_digest` — but not `last_canonical`, which only exists on the DB row. So
at the firewall hook a classifier can diff **approved vs served** in full text, but not
**prior-served vs served**. For a consent gate approved-vs-served is arguably the *correct* baseline
(see §7); for fidelity to the spec's wording it is not.

**For the console we would want the verdict persisted**, not just computed: a `drift_class` column plus
which tests fired, so the operator sees *why* a change was classified, the same way `findings` already
records what the scanner saw.

---

## 2. The six prose tests: mechanical, LLM, or unreliable

### Mechanically checkable today

**Test 4 — weakened or removed stated limit.** The most mechanical of the six by a distance, and the
best first candidate. The spec names the phrases: `read-only`, `does not modify`, `local only`,
`requires confirmation`, `sandboxed`. Removal is a set difference over normalised prose. Deterministic,
cheap, high precision, and — critically — it is the one test that survives the objection in §7, because
a limit that was *stated* can be observed to disappear.

**Test 1 — new or broadened action.** We have the lexicon. `norviq/engine/capability/source_registry.py`
defines `Verb` = READ / WRITE / DELETE / SEND with a consequence ordering and a token lexicon;
`classify_tool` (`:409`) applies it to tool *names*. Applying the same lexicon to prose yields
"verb set expanded" or "max consequence increased", which is a real implementation of test 1 —
and it handles the spec's carve-out (*"reworded synonyms of the same verb do not count"*) naturally,
since synonyms map to the same `Verb`. Residual: description prose often names verbs belonging to the
*domain* rather than the tool ("for users who delete records"), so expect noise.

### Wordlist-approximable, moderate precision

**Test 2 — widened target or scope.** The scope-universal list (*any / all / other / cross- / global /
arbitrary*) is literal and its appearance is checkable. The hard half is *"where a bounded scope
stood"* — that requires the prior prose to have expressed a bound. Approximable as "universal term
present in new, absent in old". Note `any` and `all` are extremely common English ("any errors", "all
results"), so this will be the noisiest of the five.

**Test 3 — new or expanded side effect.** A closed noun list (logging, retention, third-party sharing,
network egress, credential caching, state mutation) tested as new-term-present. Same shape as test 2,
somewhat better precision because the vocabulary is more specialised.

### Needs an LLM judge, or should be dropped

**Test 5 — redirected data flow or trust.** Host/URL extraction from prose is mechanical; *"whom the
tool trusts"* is not. `"processed locally" → "sent to an external API"` is detectable with a locality
wordlist, but the general case is a semantic judgement. This is the one test where an LLM judge earns
its cost — and see §5 for why that cost cannot sit on the discovery path.

### Test 6 — be blunt

**We already implement it, it is our most reliable prose control, and it should not be part of a drift
classifier at all.**

`norviq/mcp/scanner.py` carries `mcp_a_instruction_override`, `mcp_a_concealment`,
`mcp_a_exfil_directive`, `mcp_a_hidden_marker`, `mcp_a_line_jumping`, `mcp_a_authority_claim`,
`mcp_a_role_impersonation`, `mcp_a_invisible_characters` — eighteen rules in total. They fire live: on
the lab's malicious server they produce `mcp_a_concealment`, `mcp_a_exfil_directive`,
`mcp_a_hidden_marker` on the poisoned tool and `mcp_a_line_jumping` on the directive-carrying one.

The problem is categorical. **Test 6 is an absolute property of the current text, not a relational
property of a change.** A description that always said "always call this first" is exactly as poisoned
as one that just started saying it. Gating it on drift makes it strictly weaker: a server that ships
poisoned from birth never drifts, so a drift-conditioned test 6 misses it entirely — while our
existing Gate A scan catches it on first sight, which is what happened in the lab.

Folding test 6 into a drift classifier would be a regression dressed as a feature. Keep it where it is
and report it *alongside* a drift verdict, never *inside* one. It also does not need the prior text,
which is a tell that it does not belong in a differ.

### Unreliable either way

Test 2's *"where a bounded scope stood"* half and test 5's *trust* half. Both require the prior prose
to have stated a boundary. When it did not — which the exemplars say is the normal case — there is
nothing for any differ, mechanical or LLM, to observe disappearing. This is not a tooling limitation;
it is an absence of signal.

---

## 3. Where a drift gate would hook

Every hook already exists. Nothing new is plumbed.

| Step | Location |
|---|---|
| **Classify** | `norviq/mcp/pins.py::PinRegistry.check()`, the `existing.digest != digest` branch (~`:244-259`). Both texts are in hand here: `existing.canonical` and the freshly-computed `canonical`. |
| **Carry the verdict** | `PinVerdict` — add the class beside `status`/`record`. |
| **Act on it** | `norviq/mcp/firewall.py::_gate_a_tools_list()` (`:1070`) already consumes the verdict and decides withhold-vs-forward per tool. `_gate_a_discover()` (`:1548`) is the server-level twin. |
| **Call-path carry-over** | Already there: the catalog entry drives `_gate_b_tools_call`'s Gate-A short circuit and the `mcp_gate_a_{pin_status}` rule id. |
| **Expose to policy** | `_mcp_context()` (`firewall.py:496`) publishes `pin_status` as `input.mcp.pin_status`. A `drift_class` fact slots in beside it, and `input.mcp` is **already in the eval cache key** (`evaluator.py:1983-1985`), so decisions recompute when it changes. |
| **Record the refusal** | `_report_denial(...)` / `pep_decision="block"` — built and proven live this week, so a drift refusal produces a real audit row with a named rule instead of vanishing. |
| **Operator review** | `DefinitionDiff` in `ui/src/pages/McpServers.tsx:845` already renders approved-vs-served; approve adopts the served text (`norviq/api/routers/mcp.py:307`). |

Cost note: `PinStore`'s contract says *"Reads are on the DISCOVERY path only; the call path never
touches a store"* (`pins.py:118-119`). A prose diff at `tools/list` is therefore affordable. Anything
per-call is not, and is not needed.

---

## 4. What already overlaps — do not rebuild

- **Canonicalisation, digesting, pin lifecycle, TOFU/strict modes, drift counting** — `norviq/mcp/pins.py`.
- **Drift detection itself** — exists and is enforced; it is binary, which is the thing to improve.
- **Prose directive scanning** — `norviq/mcp/scanner.py`, 18 rules, shared by definition and response
  paths. Strictly better than test 6 as a drift test (§2).
- **Verb lexicon and consequence ordering** — `norviq/engine/capability/source_registry.py`.
- **Operator diff + approve/revoke + drift badge** — `McpServers.tsx`, `GET /mcp/servers`, `mcp.py`.
- **Policy surface for pin state** — `input.mcp.pin_status`, and the guardrail template already has
  `mcp_definition_drift` / `mcp_tool_not_approved` / `mcp_definition_flagged` rules proven live.
- **Audit for PEP-side refusals** — `pep_decision` on the evaluate contract.

**The only genuinely new component is the classifier function.** Everything it needs as input, and
everything that would consume its output, is already built.

---

## 5. Honest failure modes

**False positives on benign rewording.** Mitigated three ways before we write any code: the direction
rule excludes narrowing, the spec's tie-break defaults ambiguity to cosmetic, and our posture ships
controls on `monitor` first. The measured discipline from `norviq/redteam/benign.py` applies directly —
a corpus of realistic rewrites, and a rate, before anything gates.

**The dangerous inverse, which matters more.** A *cosmetic* verdict must still **record**. Today every
drift produces a `pin.drift` event and a `drift_count`. If classification becomes a reason to stop
recording, we trade a noisy signal for no signal, and the rug-pull evidence we currently have is lost.
Classify to decide whether to *block*; never to decide whether to *notice*.

**Latency.** Fine for the mechanical tests — discovery path, per tool, string work. **Not fine for an
LLM judge.** `tools/list` is the agent's startup path; a model call there adds seconds to every agent
cold start and puts an external dependency in front of the gate. If tests 1/5 want a judge it must run
out-of-band, with the gate defaulting to today's binary behaviour until the verdict lands — which
means the judge informs the *operator*, not the *block*.

**Contract changes mid-session.** Two distinct issues:

*Pre-existing and inherited:* a warm proxy forwards calls against its cached catalog until its next
mediated `tools/list`; `_on_catalog_changed` (`firewall.py:1053`) reacts to `notifications/*_changed`
but a server that simply answers differently without notifying is not observed until re-discovery. A
classifier neither worsens nor fixes this.

*New, and the spec does not address it:* **salami-slicing.** If the classifier ever diffs against the
*last-served* definition, an attacker walks the contract to anywhere in individually-cosmetic steps,
each one passing. The defence is to always diff against the **approved** baseline, never the last
served — which is what our pin already does (`check()` deliberately does not re-pin on drift, and the
comment says why: *"silently re-pinning would make the second call to a rug-pulled tool succeed"*).
This is a strong argument for keeping approved-as-baseline even though the spec says
immediately-prior-published, and it should be stated explicitly in any implementation.

---

## 6. What the reference material says about reach

Two independent reads converge, and neither is encouraging about detection.

**The four exemplars.** In all four the vulnerable and the correct implementation have **identical
contracts**. OpenNMS is the reductio: v1 enforces the guard and v2 does not, and they differ by one `!`
inside a method body — same name, same parameters, same description, same annotations. Three of the
four are defined by an *absence* (a missing `security:` key, a missing `session.rights` check, a
missing target-scope predicate), and an absence is only meaningful against a sibling implementation the
contract layer cannot see. The behavioural annotations actively mislead here: the CoopCycle cross-tenant
leak is a genuinely read-only, idempotent, non-destructive GET — every annotation correct and
reassuring, on the operation that dumps other tenants' data.

**The AuthzBench vocabulary.** Ten of twelve patterns require evidence a contract cannot carry — a
sibling's predicate (`read-scoped-write-unscoped`, `url-param-skips-sibling-gate`), a named
implementation primitive (`framework-authz-primitive-bypass`), wiring topology
(`split-router-auth-gap`), or an actor model (`state-machine-authz`, `agent-tool-authz`). The two that
are partially contract-visible fail on the distinguishing half: `scope-mass-assignment` needs the body
field to **override** the session scope, and the corpus tracks that exact gap as a first-class
false-positive trap (`writable-not-honored`, firing on 33 records).

**The precedent that sets the honest ceiling.** GraphQL SDL directive diffing is a genuine
contract-only signal — and it still requires a source-level confirmation step before promotion.
Contract-level analysis is admissible as a **lead generator, not an assertion.** That is the correct
framing for anything built here.

**One caveat to carry forward.** The pass that populated the AuthzBench pattern labels violated its own
rule that *"detection tactics are not patterns"* — roughly 22% of assignments took the label from how
the bug was found rather than what it was. A drift classifier is prone to precisely this conflation,
because "the description changed" and "the authority changed" are easy to merge. Whatever we emit must
name the *observed change*, not the *suspected consequence*.

---

## 7. The flag: what the rubric assumes that a runtime client does not have

This is the section to read first if the idea is going to be killed.

**1. "The immediately-prior published description" does not exist at runtime.** The spec judges each
change *"against the immediately-prior published description, per field"* — coherent for a corpus of 47
daily snapshots, where every intermediate state is on disk. A runtime MCP client has two things: the
contract it approved, and the contract it is being served now. It never saw the states in between, and
for tools it did not discover during a given window it saw nothing at all. **The corpus recurrence
figures (13.8% vs 2.8%, lift 4.8) are computed over a dense daily census; a gate observes a sparse,
session-dependent subsample. The lift does not transfer to the gate's hit rate, and should not be cited
as if it did.**

**2. Part A's decidability claim is the load-bearing one, and it is optimistic.** The spec asserts the
conditionals are *"decidable from the schema diff plus the param name/role, not from intent."* Two of
them are not:

- `added-required-param` / `required-set-expanded` — *"yes only if the param denotes a target or
  scope."* `resource_id`, `path`, `url` are recognisable; `q`, `ref`, `key`, `container`, `selector`,
  `scope` are not reliably. This is a semantic judgement about a name, dressed as a lookup.
- `removed-param` — *"yes only if the removed param was a scope/target **constraint**."* A contract
  states that a parameter exists, never that it *constrains*. Distinguishing a removed `tenant_id`
  filter from a removed `format` option requires knowing which one bounded the blast radius, and no
  MCP contract carries that. This is the same gap AuthzBench records as `writable-not-honored`.

**3. The through-line sentence does more work than the exemplars support.** §4 concludes: *"in every
case the schema stays plausible, and the boundary that failed lived in prose **or in an unstated
assumption**. That is precisely the bucket a deterministic schema differ marks cosmetic, which is why
the rubric in Part B is aimed there."* In all four exemplars it lived in the **unstated** half. The
spec is careful and explicit that §4 is pattern reference only — *"the authorization shape is what
transfers"*, and it claims no count from them — so this is not the spec overclaiming. But that one
sentence is the bridge from "the shape is real" to "prose analysis is where to aim", and the exemplars
carry the first clause, not the second. **A limit that was never stated cannot be observed to be
removed.** Test 4 is the only one of the six that escapes this, because it operates on limits that
*were* stated.

**4. Annotations are decidable but low-yield.** We pin `annotations`, so the guarantee-change (was
asserted read-only, now destructive → Yes) versus first-labeling (was unannotated, now annotated → No)
split is genuinely computable — a real strength of our pin design. But MCP annotations are advisory and
widely absent in practice, so most real events land in the first-labeling bucket and score No. Correct,
and rarely load-bearing.

---

## 8. Recommended minimal first slice

**Do not build the classifier as a gate. Build it as a measurement, and let a number decide.**

The fastest way to prove or kill this is to answer one question against traffic we can already
generate: **what fraction of observed drift is cosmetic?**

- If most drift is cosmetic — output-schema churn, rewording — then classification is a real precision
  win on a gate we already run, and it is worth shipping.
- If most drift is already capability-affecting, classification buys nothing over the binary gate and
  we should stop.

The slice, in order:

1. **A pure function.** `classify_drift(approved_canonical, served_canonical) -> (class, tests_fired)`
   in `norviq/mcp/`, with no gating and no callers in the enforcement path. Part A structural lookup
   plus **test 4 only**. Zero regex budget impact — this is Python, not rego.
2. **Record, do not act.** Call it from `PinRegistry.check()`'s drift branch, log the verdict, leave
   the returned status exactly as it is today. Nothing changes behaviour.
3. **Measure.** Run it over the `rugpull` lab server (which produces real drift on demand — verified
   this week: `fc7a0b45…` → `9b8c04ac…`) plus a synthetic corpus of contract edits covering each Part A
   kind and each test-4 phrase.
4. **Read the split.** Part A alone should answer it, because `output-schema-changed` is by the spec's
   own account the largest bucket and we currently gate on it.

Prose tests 1/2/3/5 wait for that number. Test 6 stays exactly where it is.

Estimated: the function and the recording are a day; the synthetic corpus is the real work, and it is
the same shape as `norviq/redteam/benign.py`, which now exists as a template.

---

## 9. What we would need that does not exist

**A labelled corpus of contract changes.** This is the biggest gap by a wide margin. We have none, and
without one every precision claim is unfalsifiable. The collaborator's 176,287-event corpus is pinned
and external. We would need either access to it, or a synthetic corpus built the way the benign corpus
was — realistic changes, each labelled with the class it should receive and *why*, so a
misclassification reads as a defect rather than a disagreement.

**A parameter-role signal.** Part A's conditionals need target/scope/data discrimination on a parameter
name. Nothing today infers it. The closest existing material is the argument-surface work
(`param_keys_pinnable`, `param_keys_ambiguous` in the evaluate payload) and the preset's
`sensitive_keys` / `destination_keys` sets — a starting vocabulary, not a solution.

**Prior-published history, if spec fidelity matters.** We hold approved and last-served. A chain would
need either a new table or an append-only column, and §5 argues we should *not* use it as the diff
baseline anyway.

**An out-of-band judge harness**, only if tests 1 and 5 are wanted: a queue, a latency budget off the
discovery path, and a way to attach a late verdict to an already-forwarded catalog. Non-trivial, and
worth deferring until step 8.4 says the mechanical tests are insufficient.

---

## Summary for the decision

Feasible, cheap, and hooks entirely into existing machinery — the contract we need is already pinned,
and it is exactly the surface the spec defines. Ship it as **precision on an existing gate**, measured
before it is trusted, starting with Part A and test 4.

Do not ship it as vulnerability detection. The exemplars and the pattern vocabulary both say the same
thing from different directions: the boundary that fails lives in the implementation, and the contract
of a vulnerable tool is character-identical to the contract of a correct one. A clean drift verdict must
never be presented as evidence of safety.
