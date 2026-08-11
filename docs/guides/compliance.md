<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Norviq Contributors -->

# Compliance & coverage

Norviq reports two different numbers about your posture, and they answer two different questions:

| Number | Question it answers | Where it comes from |
|---|---|---|
| **Coverage %** ("rules present") | For each MITRE ATLAS technique / OWASP LLM control, is a rule that would enforce it actually loaded for this namespace? | `norviq/api/routers/mitre.py::_compute_coverage` — the framework mapping cross-referenced with the Rego the loader holds |
| **Proven-blocking %** ("efficacy") | Of the attacks we can actually send, how many did the deployed posture stop? | `norviq/api/redteam_efficacy.py::compute_efficacy` — the last red-team suite run |

Neither is a claim that you are protected. Coverage says a rule exists; it says nothing about whether
the rule works, and the API labels itself accordingly (`"basis": "rules_present"`,
`mitre.py:308`). Proven-blocking says a specific corpus of attacks was stopped; it says nothing about
attacks that are not in the corpus, and — the part this page exists for — the corpus deliberately
cannot reach most of the catalogued MCP/tool attack surface. **A high score on either number is a
statement about a bounded denominator. [Section 3](#3-coverage-limits-what-the-numbers-do-not-cover)
states what those denominators exclude.**

In the console the two numbers live on two pages: **Compliance** (`/compliance`,
`ui/src/pages/Compliance.tsx`) for coverage, gaps, remediation and the evidence pack, and **Red Team**
(`/redteam`, `ui/src/pages/RedTeam.tsx`) for the suite, the scorecard, the three framework breakdowns
and the run history. Compliance carries an efficacy banner reading the last red-team run, and Red Team
carries a vector-coverage band reading this page's [section 3](#3-coverage-limits-what-the-numbers-do-not-cover);
each page states the other's caveat so neither can be read alone.

Compliance is driven by the global header time range (`ui/src/lib/routeMeta.ts`) — there is no in-page
range picker. Red Team results are per-run, not range-scoped.

If you have not read **[Concepts](../concepts.md)** and **[Writing Policies](writing-policies.md)**,
read those first — this guide assumes policy tiers, precedence, and enforcement modes.

---

## 1. Framework coverage

### 1.1 What is counted

Two frameworks are live and both run through the same machinery (`mitre.py:39`):

| Framework | Mapping file | Console / API id |
|---|---|---|
| MITRE ATLAS | `policies/mitre_mapping.json` | `atlas` |
| OWASP Top 10 for LLM Applications (2025) | `policies/owasp_llm_mapping.json` | `owasp` |

Each mapping entry declares a `scope` (`enforceable` or `out_of_scope`) and a list of `policies` —
the `rule_id` values that, if present in the loaded Rego, mean this control is enforced. Coverage is
computed per technique (`mitre.py:227-281`):

- `scope: out_of_scope` → status `out_of_scope`. Shown, **not** counted in the denominator. These are
  model-lifecycle and governance controls (training-data poisoning, model backdooring) that a
  tool-call PEP structurally cannot see, so counting them would manufacture a permanent failure.
- `scope: enforceable` and at least one mapped `rule_id` present in the loaded Rego → `enforced`.
- `scope: enforceable` and none present → `gap`.

`coverage_pct = round(enforced / enforceable_total * 100)` (`mitre.py:288`). Out-of-scope controls
never enter that fraction.

### 1.2 Presence is tested against executable Rego, not text

`_rule_is_present` (`mitre.py:190-216`) does **not** substring-match. `_rego_blob`
(`mitre.py:166-182`) first strips whole-line `#` comments, then presence requires the `rule_id` to
appear as a **quoted string literal** — either the bare id (`blocks["deny_sql_injection"]`) or a
colon-namespaced id whose last segment is the rule (`blocks["remediation:atlas:AML.T0049:deny_sql_injection"]`,
which is the shape the built-in remediation generator emits).

The reason is direct: a line reading `# TODO: reinstate deny_sql_injection` enforces nothing, and a
raw substring test would have marked the technique covered. Prose in a `reason` string cannot make a
technique read `enforced` either, because a sentence is not a literal equal to the id.

### 1.3 The structural ceiling — read this before quoting a percentage

Four enforceable controls in the shipped mappings have an **empty `policies` list**. There is no
`rule_id` to look for, so `_rule_is_present` can never match, so they can never read `enforced` — no
matter what policy you write:

| Framework | Control | `remediation` | Consequence |
|---|---|---|---|
| ATLAS | `AML.T0056` LLM Meta Prompt Extraction | `bespoke` | permanent `gap` |
| ATLAS | `AML.T0061` LLM Prompt Self-Replication | `bespoke` | permanent `gap` |
| OWASP | `LLM07:2025` System Prompt Leakage | `bespoke` | permanent `gap` |
| OWASP | `LLM10:2025` Unbounded Consumption | `rate` | permanent `gap` |

So the maximum coverage this product can report today is:

- **MITRE ATLAS: 8 / 10 enforceable = 80%**
- **OWASP LLM: 4 / 6 enforceable = 67%**

Verified by running `_rule_is_present` over the shipped `comprehensive.rego` against both mapping
files: a namespace loading that baseline reads exactly 80% / 67%, which is also the ceiling. **80% is
not "20% of ATLAS is unaddressed on your cluster" — it is the top of the scale.** Three of the four
are flagged `remediation: bespoke`, meaning the product will not fake a runtime rule for them — but
all four behave identically on "Generate enforcing policy", because the guard is
`_control_is_bespoke(info) or not usable` and an empty `policies` list yields no generatable rule, so
`LLM10:2025` takes the second branch. Each returns `status: "escalate"` with an explanation rather
than emitting a vacuous per-class deny-all (`mitre.py:637-645`), and each carries
`generatable: false` on the coverage payload (`mitre.py:242-244`), which is what keeps the console
from offering a Generate checkbox that only ever dead-ends (`Compliance.tsx:1126`).

`LLM10:2025` is the odd one out: it is not `bespoke`, its `remediation` hint reads `rate`, and
unbounded consumption is enforced at runtime — *partially* — by the stateful rate limiter rather than
by a Rego rule with a mapped `rule_id`. State the partiality when you cite it: the limiter throttles
allowed calls per identity at 60 per 60 s by default (`norviq/config.py:128-129`) and returns
`rate_limit_exceeded`, but read-like tools are **exempt by default**
(`evaluator_rate_limit_read_exempt: true`, `norviq/config.py:132-135` — the
`get_`/`read_`/`list_`/`query_`/`fetch_`/`describe_`/`view_`/`monitor_`/`poll_`/`report_`/`search_`
prefixes), a deliberate availability trade so a benign read spike is not denied. A read-only flood is
therefore not throttled at all under the shipped defaults. Because the mapping lists no `policies`,
none of this enforcement — throttled or exempt — is visible to the coverage computation either way.
The red-team corpus states the same limitation from the other side: `RL-001` expects `allow`, because
a single tool call cannot observe a flood (`attacks.py:84-86`).

One console wrinkle worth knowing before you screenshot the gap list: it chips **every**
non-generatable gap `BESPOKE` (`Compliance.tsx:1146`), so `LLM10:2025` is chipped `BESPOKE` even
though its mapping says `remediation: rate`. The chip means "cannot be auto-generated", not "the
mapping declares it bespoke".

### 1.4 `status` is not evidence — `proven` is

`status: "enforced"` is decided purely from the loaded Rego and never consults traffic. The payload
carries a separate `proven` field per technique (`blocked > 0`, `mitre.py:276`) and a `proven` roll-up
(`mitre.py:299`) counting how many enforced techniques actually acted on traffic in the selected
window. The gap between `enforced` and `proven` is the whole distance between "a rule is loaded" and
"the control demonstrably fired".

Two caveats, both real:

- **In monitor mode the gap is total.** Monitor mode is a *namespace posture*, not a field on a
  policy: `PUT /api/v1/settings?namespace=<ns>` with `{"enforcement_mode": "audit"}`, which the
  evaluator resolves to `posture["monitor"]` (`norviq/engine/evaluator.py:692`). It is a different
  knob from the per-policy `spec.enforcementMode` the CRD requires on every `NrvqPolicy`
  (`webhook/controller.go:929`) — setting *that* to `audit` does not put the namespace into monitor
  mode. Under the namespace posture, `_apply_posture` softens a would-block **or would-escalate** to
  an `audit` decision and rewrites the rule id to `monitor_would_block:<rule>`
  (`norviq/engine/evaluator.py:761-779`). Five rule ids stay hard regardless — `trust_frozen`,
  `policy_load_pending`, `evaluator_error`, `evaluator_invalid_payload`, `rate_limit_exceeded`
  (`_POSTURE_EXEMPT_RULES`, `evaluator.py:329-331`) — but none of them is a mapped `rule_id` in
  either framework mapping, so no technique is rescued by the exemption. The audit rows therefore
  match neither the `block`/`escalate` decision filter nor the mapped `rule_id`, so `blocked` is 0
  and `proven` is **false for every technique**, while `status` still reads `enforced`. That is
  correct behaviour, not a defect — but it means block evidence is structurally impossible in a
  monitor namespace, so any attestation sentence claiming such evidence would be false.
- **`proven` and `basis` are computed but not displayed.** `GET /api/v1/compliance/{framework}/coverage`
  returns both; the console's `MitreCoverage` type (`ui/src/api/client.ts:626-646`) declares neither,
  the Compliance page renders neither, and the evidence pack (`mitre.py:522-544`) omits both. To use
  them today, read the coverage endpoint directly.

### 1.5 "Blocked" here means blocked **or escalated**

`_activity_by_rule` (`mitre.py:120`) counts `block` **and** `escalate` for the Compliance surface,
because for an attestation the question is "did the control act on this call" — an escalated call did
not proceed unchallenged, and the shipped packs really do emit escalates (`comprehensive.rego`,
`webhook/presets/strict.rego`).

The Overview's "Blocked (Nh)" KPI counts `block` only (`norviq/api/routers/audit.py`). Over the same
namespace and window the two headline numbers can legitimately differ. This is a difference of unit,
not a bug; the Compliance surface labels its number "blocked or escalated".

### 1.6 Real traffic only

Both audit joins exclude synthetic/probe/eval identities (`norviq/api/synthetic.py::is_synthetic_identity`)
**and** every event tagged `framework="redteam"` (`mitre.py:112`, `mitre.py:154`). Red-team runs write
audit rows for evidence (`redteam.py:425-445`) but must never inflate an attestation, so
observed/blocked counts, and the per-technique "affected agent classes" chips, both drop them. The
number dropped is reported as `synthetic_excluded` so the console and the evidence pack can state the
exclusion rather than imply it.

### 1.7 Trend, evidence pack, remediation

**Trend.** `GET /api/v1/compliance/{framework}/trend` reads the persisted
`mitre_coverage_snapshots` table (`norviq/api/db/models.py:313-347`). There is no scheduler: a
coverage read upserts at most one row per `(namespace, framework, UTC hour)` (`mitre.py:362-392`),
serialized by a `pg_advisory_xact_lock` and backstopped by a partial unique index on the hour. The
series is empty until the first read and accumulates from there — no point is ever fabricated.
Snapshots older than `coverage_snapshot_retention_days` (default 30, `norviq/config.py:254`) are
pruned; only `kind='snapshot'` rows are pruned, `kind='export'` rows back the "last exported"
indicator.

**Evidence pack.** `GET /api/v1/compliance/{framework}/export?format=json|pdf` streams an
in-cluster pack (`mitre.py:495-561`) — per-control id, name, scope, status, mapped policies, enforcing
policies, observed/blocked, **per-rule** blocked counts, and affected classes, plus the
`synthetic_excluded` count. Nothing egresses; the pack is rendered from the same `_compute_coverage`
call the page uses. The export itself is recorded as a `kind='export'` snapshot row.

**Remediation.** A `gap` is `generatable` only when it is not `bespoke` **and** at least one of its
mapped rule ids has a runtime template (`remediation_generatable_rules`,
`norviq/api/threat_intent.py:578-585`; templates exist for `base64_decoded_threat`,
`cross_tenant_access`, `deny_shell_execution`, `deny_sql_injection`, `llm01_prompt_injection`,
`llm02_data_leakage`, `llm05_supply_chain`, `llm06_excessive_agency`). Generating produces a
**tighten-only dry-run draft**, never an enforcing policy, and it is persisted under a dedicated
overlay key `"<class>__remediation__"` rather than the class's own policy key — applying a draft is a
full-replace upsert, so writing it at the real key would destroy that class's enforcing policy
(`mitre.py:660-671`). Generate is admin-only and target-cluster-gated; it refuses a synthetic class
outright (`mitre.py:629-630`).

---

## 2. Red-team efficacy

### 2.1 What actually runs

`POST /api/v1/redteam/suite` (`redteam.py:103`, admin-only) evaluates **every attack in the corpus
against every real agent class seeded in the namespace**. Targets come from `_seeded_classes`
(`redteam.py:64-80`), which excludes reserved `__…__` keys and synthetic/probe identities; when a
namespace has no seeded class at all the suite falls back to a single identity `redteam-test`
(`redteam.py:34`).

The suite calls the in-process evaluator directly (`request.app.state.evaluator.evaluate`,
`redteam.py:162`) — not the HTTP `/evaluate` route. This matters for [section 3](#3-coverage-limits-what-the-numbers-do-not-cover):
the suite can adjudicate only what a **policy decides**. Each decision is also emitted to the audit
log tagged `framework="redteam"` so each result row's "Audit" link resolves to its own evidence
(`redteam.py:425-445`), and that tag is exactly what keeps those rows out of every real-traffic count.

Concurrency is bounded twice: a per-namespace lock (in-process dict plus a Redis `SET NX EX`, because
the chart ships `api.replicas: 2`, `helm/norviq/values.yaml:204`, and an in-process guard alone
measurably did not hold) returns
`409` with the in-flight `run_id`; a process-wide semaphore caps simultaneously executing suites at
`redteam_suite_global_concurrency` (default 3, `config.py:292`).

There is also a CLI path — `norviq redteam run|single|catalog` (`norviq/redteam/runner.py`) — which
drives `AttackSimulator` (`norviq/redteam/simulator.py`) over HTTP against
`POST /api/v1/evaluate`. It reports pass/fail by category and has **no** efficacy roll-up, no ATLAS /
OWASP / vector breakdown and no durable history; those exist only on the API/console path.

### 2.2 The corpus

34 attacks (`norviq/redteam/attacks.py:65-123`), each carrying an ATLAS technique id, an expected
decision, an expected `rule_id`, and — for the newest ones — an MCP vector id and a forged
`input.mcp` document:

| Category (enum) | Attacks | OWASP control derived? | Conditional? |
|---|---|---|---|
| `OWASP_LLM01` prompt injection | 3 | `LLM01:2025` | no |
| `OWASP_LLM02` data leakage | 5 | `LLM02:2025` | no |
| `OWASP_LLM05` supply chain | 2 | `LLM05:2025` | no |
| `OWASP_LLM06` excessive agency | 3 | `LLM06:2025` | no |
| `OWASP_LLM10` unbounded consumption | 1 | `LLM10:2025` | expects `allow` |
| `CROSS_TENANT` | 2 | — | no |
| `SQL_INJECTION` | 3 | — | no |
| `SHELL_INJECTION` | 2 | — | no |
| `TRUST_MANIPULATION` | 1 | — | no |
| `CHAIN_EXPLOIT` | 2 | — | one expects `allow` |
| `POLICY_BYPASS` | 2 | — | no |
| `SECTOR_POLICY` | 3 | — | **yes** — sector pack |
| `MCP_IDENTITY` | 3 | — | **yes** — MCP guardrail |
| `POLICY_COMPOSITION` | 2 | — | no |

The OWASP control id is derived by string surgery on the **enum name**, not the value:
`OWASP_LLM01` → `LLM01:2025` (`redteam_efficacy.py:50-58`). A category not starting with `OWASP_LLM`
returns `None` and carries only an ATLAS technique. This is why `attacks.py:29-32` carries an
explicit warning: naming a future category `OWASP_LLM*` when it is not that control would silently
fabricate an OWASP mapping.

### 2.3 How efficacy is computed

`compute_efficacy` (`redteam_efficacy.py:138-204`) walks the result rows and applies three filters
before anything reaches a denominator:

1. **Synthetic identities are dropped** (`:147`). Counted as `excluded_synthetic`.
2. **Rows whose expected decision is not `block` are set aside** (`:157-158`) as `non_enforcement`.
   `RL-001` (rate-limit flood) and `CE-002` (recursive planner intent) expect `allow` because neither
   is decidable in a single evaluation — the real control is the stateful rate limiter and the
   `chain_depth_limit` rule respectively. They are never counted as misses.
3. **Rows marked `applicable: false` are set aside** (`:162-164`) as `sector_not_enabled`.

What survives is the denominator. A row is `caught` when it actually blocked, `got_through` when it
expected a block and did not get one, and `proven_blocking_pct = round(caught / total * 100, 1)`
(`:106-109`).

### 2.4 `sector_not_enabled` and inapplicable attacks

Two attack categories are **conditional** (`redteam.py:511-513`): `SECTOR_POLICY` and `MCP_IDENTITY`.
Their enforcing rules are not part of any shipped baseline — they live in a sector pack
(`policies/sector/*`) or in the opt-in MCP guardrail template
(`policies/templates/mcp_integration_guardrail.rego`, default-off). `_attack_applicable`
(`redteam.py:516-525`) marks such an attack applicable only when its `expected_rule` appears in the
Rego loaded for that namespace:

| Attack | Expected rule | Enabled by |
|---|---|---|
| `FIN-001` SoD self-approval | `sod_violation` | pack `finance-money-movement` |
| `PHI-001` PHI export exfil | `phi_export_exfil_blocked` | pack `healthcare-phi` |
| `OT-001` OT control command | `ot_control_command_blocked` | pack `energy-ot` |
| `MCP-01/02/03` MCP identity | `mcp_unapproved_write_server`, `mcp_tool_not_approved` | MCP integration guardrail |

Verified: **no shipped baseline reads `input.mcp` at all** — zero references in `comprehensive.rego`
or any of `webhook/presets/{strict,moderate,permissive}.rego`. An MCP identity attack in a namespace
without the guardrail could never be blocked, and no operator action inside that namespace's policy
would fix it — reporting it as a miss would paint every default namespace red. So it is reported as
"not enabled here" (`RedTeam.tsx:419-425`), excluded from the denominator, and the console's
`gotThrough()` helper (`RedTeam.tsx:509-511`) is the single definition both the badge and the
"Got-through only" filter use, so the table and the scorecard cannot disagree.

`POLICY_COMPOSITION` (`MCP-04`/`MCP-05`) is deliberately **not** conditional: its expected rules are
baseline blocks that ship everywhere, so "did this class's own allowlist override a baseline
protection?" is always a fair question to ask.

Concretely, for a namespace running only the shipped `comprehensive.rego` baseline, one target class,
and every control holding:

```
overall            {total: 26, caught: 26, got_through: 0, proven_blocking_pct: 100.0}
non_enforcement    2      # RL-001, CE-002
sector_not_enabled 6      # FIN-001, PHI-001, OT-001, MCP-01, MCP-02, MCP-03
excluded_synthetic 0
```

**26, not 34.** Enable all three sector packs and the MCP guardrail and the denominator becomes 32.

### 2.5 The three breakdowns and their denominators

| Breakdown | Key | Denominator | Missing-key behaviour |
|---|---|---|---|
| `by_technique` | `attacks.py` `mitre_technique` (ATLAS id), display name resolved from `policies/mitre_mapping.json` | block-expected, applicable rows carrying that id | defaults to `"unknown"` — every attack is supposed to carry a technique, so that bucket is an alarm for a broken mapping (`redteam_efficacy.py:169-171`) |
| `by_owasp` | derived from the category enum name | block-expected, applicable rows whose category maps to an OWASP control | **skipped** when absent |
| `by_vector` | `attacks.py` `mcp_vector`, title from `vectors.py` | block-expected, applicable rows carrying a vector id | **skipped** when absent — the 29 attacks predating the dimension exercise *no* MCP vector, and bucketing them as "unknown" would assert they exercise an unidentified one (`redteam_efficacy.py:182-193`) |

Every denominator is per-row, so with N target classes each bucket's `total` is N × the attacks in it.

Two honest wrinkles in the ATLAS breakdown, both visible in the console today:

- **`AML.T0010` has no entry in `policies/mitre_mapping.json`.** The three `MCP_IDENTITY` attacks
  declare it, so when the guardrail is enabled the breakdown renders a row reading
  `AML.T0010 · AML.T0010` — the display name falls back to the raw id (`redteam_efficacy.py:67`). The
  technique also never appears on the Compliance page, which iterates the mapping file.
- **The id on an attack is the attack's own declaration, not a cross-check against the mapping's
  meaning.** Two ids currently carry attacks whose subject matter does not match the mapping's name
  for that id: `AML.T0048` ("External Harms", which the ATLAS mapping marks **out_of_scope**) is the
  corpus's catch-all and carries ten of the 34 — the prompt-injection, jailbreak, chain,
  policy-bypass and rate-limit attacks plus two sector attacks (`FIN-001`, `OT-001`) — while
  `AML.T0051` ("LLM Prompt Injection") carries the four destructive-tool attacks (`EA-001/2/3`,
  `TM-001`). Read the attack names in the results table, not the technique label, and do not
  reconcile a Red Team `AML.T0048` row against the Compliance page's `AML.T0048` row — they are not
  describing the same thing.

### 2.6 Durability and retention

Each run is persisted to `redteam_runs` (`models.py:350-372`) with its full result rows and its
efficacy blob, then two-tier retention runs for that namespace (`plan_retention`,
`redteam.py:200-236`):

| Tier | Config (`norviq/config.py:283-286`) | Default | Effect when exceeded |
|---|---|---|---|
| Detail | `redteam_detail_keep_runs` / `redteam_detail_keep_days` | 1 run / 7 days | `results` nulled, summary kept (`detail_pruned: true`) |
| Summary | `redteam_summary_keep_runs` / `redteam_summary_keep_days` | 20 runs / 30 days | row deleted |

The newest run per namespace is never pruned at either tier, so `/redteam/results/latest` always
returns full detail. This is why the vector-coverage denominators are **stored on the run** rather
than re-derived from rows (`vectors.py:259-267`, `redteam_efficacy.py:112-135`) — a block derived from
rows would silently vanish from every detail-pruned run while the rest of the summary survived.

---

## 3. Coverage limits — what the numbers do **not** cover

This is the section a compliance reader should read twice.

### 3.1 The MCP/tool vector catalog ships its own denominator

`norviq/redteam/vectors.py` promotes the attack surface enumerated in
`docs/design/MCP-TOOL-ATTACK-SURFACE.md` into code, and classifies each vector by whether this suite
can adjudicate it (`vectors.py:48-53`):

- **`EVALUATE`** — the outcome turns on a policy decision the engine renders, given facts that exist
  today. Scoreable here.
- **`PROXY`** — the outcome is produced by proxy code *before or instead of* `_evaluate`. Not
  scoreable here, **and not unprotected**.
- **`OUT_OF_SCOPE`** — not a per-call enforcement question at all (a PodSpec inventory question, a
  process-environment property, the absence of a call).

Every vector that is not `EVALUATE` **must** state a reason; the module refuses to import otherwise
(`vectors.py:236-251`), because an unmeasured vector with no stated reason is indistinguishable from
someone forgetting to classify it.

The counts, as shipped (`coverage_denominators`, `vectors.py:259-267`):

| | Count |
|---|---|
| Catalogued vectors | **39** |
| `EVALUATE`-reachable (this suite *can* score) | **4** |
| `PROXY`-only (decided before the policy engine) | **29** |
| `OUT_OF_SCOPE` | **6** |

By surface: 25 `mcp-protocol`, 9 `mcp-identity-transport`, 5 `tool-runtime`.

### 3.2 What a run actually exercises

`vector_coverage` (`redteam_efficacy.py:112-135`) ships those denominators with every run, plus
`exercised` (distinct vectors seen — surface coverage, not attack volume) and
`unexercised_reachable` (the `EVALUATE` vectors no attack touched). The console renders this as a
neutral band directly under the scorecard (`RedTeam.tsx:292-313`).

For the two realistic namespace shapes:

| Namespace | `exercised` | `unexercised_reachable` |
|---|---|---|
| Baseline only (no MCP guardrail) | **1 of 39** | `eval-cache-key-omits-mcp-context`, `mcp-server-identity-unattested`, `resources-read-uri-gate` |
| MCP guardrail loaded | **2 of 39** | `eval-cache-key-omits-mcp-context`, `resources-read-uri-gate` |

Read that against the scorecard. A run reporting **100% proven-blocking** on a namespace with the
guardrail loaded has exercised **2 of 39 catalogued MCP/tool vectors** — and that 100% is over
**29** block-expected attack×class rows for one target class (the 26 of
[2.4](#24-sector_not_enabled-and-inapplicable-attacks) plus `MCP-01/02/03`, which the guardrail makes
applicable). 32 is the ceiling, and only with all three sector packs enabled as well. Either way the
denominator is attack rows, not the vector catalog. The two numbers have nothing to do with each
other, and the coverage band exists precisely so the second cannot be read as the first.

The four `EVALUATE`-reachable vectors:

| Vector | Exercised by | Status |
|---|---|---|
| `mcp-server-identity-unattested` | `MCP-01/02/03` | scored when the guardrail is loaded |
| `base-allowlist-strips-baseline-floor` | `MCP-04/05` | always scored |
| `resources-read-uri-gate` | — | no attack exists; the proxy really does call `_evaluate("resources/read", …, surface="resources/read")` and refuse on a block (`norviq/mcp/firewall.py:865-883`), so what is missing is a **rule**, not a mechanism |
| `eval-cache-key-omits-mcp-context` | — | defect closed by adding the MCP document to the cache key; regression-tested at `tests/engine/test_cache_key_scope.py`, which is a stronger guard than a suite attack (a suite cannot express two evaluations resolving to one cached verdict) |

An unexercised entry stays listed until the corpus can express it. That is the intent: the list is a
standing statement of what has not been attacked, not a backlog that quietly empties itself.

### 3.3 A proxy-only vector is not a failure

29 of 39 vectors are `PROXY`. Most are **enforced**, several provably: in the live red/blue run recorded
in `docs/design/MCP-RED-BLUE-LOOP.md`, Gate A stripped tool-description poisoning and invisible
tag-character steganography, and the content-hash pin refused a tool whose definition changed after
approval. They are decided **before the policy engine**,
which is the one layer this suite can score. The recurring reasons, named once in `vectors.py:84-99`:

| Reason | Meaning | Example vectors |
|---|---|---|
| never evaluated | the proxy's dispatch forwards or refuses the method before any `/evaluate` call exists | `initialize` negotiation, `elicitation/create`, sampling egress, `notifications/message` |
| discovery plane | decided once at `tools/list` / `prompts/get` / `resources/list` against the pin registry and the definition scanner, not per call | rug-pull, tool-definition poisoning, TOFU first-sight window, mid-session tool addition |
| proxy structural | enforced structurally in the proxy before `/evaluate` | header parameter smuggling, JSON-RPC batch smuggling |
| transport | a session/connection-layer property that is not a fact in any call's policy input | TLS downgrade, upstream session hijack, Gate-A session keying |

Colouring these red would itself be a false claim. The correct place to prove a proxy behaviour is
`scripts/kind-e2e/mcp_red_team.py`, which drives a **live proxy with an ungoverned control** — the
only setup that can demonstrate a control that never reaches a policy.

Reclassifying a `PROXY` vector as `EVALUATE` to make the number look better would restore exactly the
overclaim the coverage block prevents. The only legitimate levers are writing more attacks against the
`EVALUATE` set, or moving a vector into policy reach. `tests/redteam/test_vectors.py` enforces this
mechanically: no attack may target a non-`EVALUATE` vector, or it would score a working control red
forever.

### 3.4 Other limits worth stating in an attestation

- **Monitor mode inverts the red-team score.** In a namespace whose posture is
  `enforcement_mode: audit` (the settings knob, not a policy's `spec.enforcementMode` — see
  [1.4](#14-status-is-not-evidence-proven-is)), a would-block returns `audit`
  (`evaluator.py:761-779`), so a block-expecting attack's `actual` never equals its `expected` and it
  reports `got_through`; proven-blocking reads 0%. That is the posture working as configured, not a
  policy gap. Run the suite against an enforcing namespace, or read the result as "monitor mode
  confirmed".
- **The applicability test is looser than the coverage test.** `_loaded_rego` (`redteam.py:491-502`)
  concatenates the namespace's Rego **without stripping comments**, and `_attack_applicable` does a
  plain substring check — unlike Compliance's quoted-literal test ([1.2](#12-presence-is-tested-against-executable-rego-not-text)).
  A commented-out mention of `sod_violation` would mark `FIN-001` applicable. It affects only whether
  an attack is scored, never a coverage percentage.
- **`excluded_synthetic` is almost always 0 on the console path**, because `_seeded_classes` already
  filters synthetic classes out of the target list before evaluation. It is belt-and-braces. It
  becomes non-zero only if you pass an explicit synthetic `target_agent` — in which case *every* row
  is excluded and the scorecard correctly reads 0% over a denominator of 0.
- **The fallback target is scored as if real.** `redteam-test` (`redteam.py:34`) matches no prefix in
  `SYNTHETIC_CLASS_PREFIXES` (`norviq/api/synthetic.py:29-42`) and is not in `SYNTHETIC_CLASS_EXACT`
  (`:45`), so a suite run in a namespace with no seeded agent classes produces a real-looking
  percentage measured against an identity that carries no policy of its own. Check the "N classes"
  summary on the scorecard before quoting a number.
- **`sector_not_enabled` and `non_enforcement` are returned but not displayed** as scorecard figures;
  only `excluded_synthetic` is (`RedTeam.tsx:271-273`). The per-row "— not enabled here" label is the
  only place the exclusion is visible in the console. Read them from
  `GET /api/v1/redteam/results/latest`.
- **Coverage is per namespace.** Both surfaces scope to the header's selected namespace; the "all"
  aggregate reads whatever cluster-wide run was newest. The console deliberately refuses to
  republish one namespace's efficacy as another's when a read fails, showing "efficacy is unknown"
  instead (`Compliance.tsx:172-226`) — "we could not ask" is not "we asked, and the answer is no".

---

## 4. How to read a score honestly

Before putting either number in front of an auditor:

1. **State the denominator.** "80% ATLAS coverage" means 8 of 10 *enforceable* techniques, with 5
   out-of-scope techniques excluded and 2 structurally unreachable. "100% proven-blocking" means N of
   N *block-expected, applicable* attack×class rows.
2. **Say which namespace and which window.** Coverage is range-scoped (observed/blocked change with
   the window); efficacy is a point-in-time run.
3. **Distinguish `enforced` from `proven`.** If the namespace is in monitor mode, say so — block
   evidence is structurally impossible there.
4. **Carry the vector-coverage band with the efficacy number.** `exercised / catalogued` and the
   `unexercised_reachable` list travel with the run for exactly this reason.
5. **Do not merge the two blocked-counts.** Compliance counts block+escalate; the Overview counts
   block only.
6. **Never present coverage as protection.** The API says `"basis": "rules_present"` in its own
   payload. A rule being loaded is not a rule being correct.

---

## 5. API reference

Coverage routes take `get_current_user`; generate is additionally admin + target-cluster gated. Every
red-team route is admin-only (`require_admin`).

| Endpoint | Purpose |
|---|---|
| `GET /api/v1/compliance/{framework}/coverage?namespace=&range=` | per-control coverage + headline; records a throttled trend snapshot |
| `GET /api/v1/compliance/{framework}/trend?range=` | persisted snapshot series (empty until the first read) |
| `GET /api/v1/compliance/{framework}/export?format=json\|pdf` | in-cluster evidence pack; records the export |
| `POST /api/v1/compliance/{framework}/generate` | one tighten-only dry-run remediation draft |
| `POST /api/v1/compliance/{framework}/generate-batch` | draft per (control × class); per-item results |
| `POST /api/v1/redteam/suite?target_agent=&target_namespace=` | run the suite; `409` if one is already running for the namespace |
| `POST /api/v1/redteam/run?attack_id=` | one attack against one identity |
| `GET /api/v1/redteam/catalog` | the corpus with resolved ATLAS/OWASP/vector mappings |
| `GET /api/v1/redteam/targets?namespace=` | real (non-synthetic) seeded classes |
| `GET /api/v1/redteam/results/latest?namespace=` | newest durable run + efficacy, or `{"has_run": false}` |
| `GET /api/v1/redteam/results?limit=&offset=&namespace=` | run history, summaries only |
| `GET /api/v1/redteam/results/{run_id}` | one run (`detail_pruned: true` when rows were retention-pruned) |

`framework` is `atlas` or `owasp`; anything else returns `404` naming the live set (`mitre.py:43-46`).
The legacy `/api/v1/mitre/*` routes remain as ATLAS-default aliases.

`range` accepts `1h`, `6h`, `24h`, `7d`, `30d` (`mitre.py:36`). An unrecognised token is never a
`400` — it silently falls back to the route's own default: 24h on `/coverage` and `/export`, 30d on
`/trend` (`_RANGE_HOURS.get(range, 720)`, `mitre.py:477`). The payload echoes the token you *sent*,
not the window that was used (`mitre.py:301`), so a typo is invisible in the response — check the
token against the five above before quoting a windowed number.

## 6. Configuration

| Key | Default | File |
|---|---|---|
| `coverage_snapshot_retention_days` | 30 | `norviq/config.py:254` |
| `redteam_detail_keep_runs` | 1 | `norviq/config.py:283` |
| `redteam_detail_keep_days` | 7 | `norviq/config.py:284` |
| `redteam_summary_keep_runs` | 20 | `norviq/config.py:285` |
| `redteam_summary_keep_days` | 30 | `norviq/config.py:286` |
| `redteam_history_page_size` | 20 | `norviq/config.py:287` |
| `redteam_suite_global_concurrency` | 3 | `norviq/config.py:292` |

## 7. Enabling the conditional controls

To move the six conditional attacks out of `sector_not_enabled` and into the scored denominator:

```bash
# The pack catalog, with per-namespace enabled state.
curl -s "$NORVIQ_API/api/v1/policy-packs?namespace=chatbot-prod" \
  -H "Authorization: Bearer $TOKEN"

# Enable a pack (admin-only, idempotent, audited). The pack ids that carry the three
# sector attacks' expected rules are finance-money-movement, healthcare-phi and energy-ot.
curl -X POST "$NORVIQ_API/api/v1/policy-packs/finance-money-movement/enable" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"namespace":"chatbot-prod"}'
```

Enabling a pack materializes its Rego as the namespace's `(ns, "__pack__")` policy through the normal
policy-create path and invalidates the namespace's evaluation cache, so the change takes effect
immediately (`norviq/api/routers/packs.py:50-72`). Packs are default-off: no `(ns, __pack__)` policy
exists until an admin enables one. A dry-run-only namespace rejects the apply.

For the MCP identity attacks, materialize the opt-in guardrail. It is a **template**, not a shipped
default — copy `policies/templates/mcp_integration_guardrail.rego`, edit the two `# >>> EDIT` blocks
(`writable_servers`, `blocking_scan_severity`), and load it for the namespace as the additive
`(ns, "__guardrail__")` target through the policy API. It defaults to `allow` and blocks specific
conditions, so a tool it says nothing about falls through to your baseline — pair it with a
deny-by-default perimeter (`policies/templates/tool-allowlist-perimeter.rego`) if you need to keep an
unknown tool out.

One trust note that belongs in any compliance narrative about MCP: `input.mcp` is **PEP-reported**,
exactly like `input.tool_name`. It is a policy input and never a trust input. `MCP-02` and `MCP-03`
exist to demonstrate this — `MCP-01` shows the write allowlist working, and `MCP-02` shows its limit
by claiming to *be* the allowlisted server, so the rule that refused `MCP-01` admits `MCP-02` on
the strength of an assertion the attacker made. A `by_vector` bucket for
`mcp-server-identity-unattested` that is below 100% is therefore not a flaky control; it is an
accurate measurement of a control keyed on a self-asserted field, and the pair is deliberate
(`attacks.py:109-112`). Identity comes from the caller's attested SVID and is never read from an MCP
message (`policies/templates/mcp_integration_guardrail.rego:32-35`).

---

## See also

- **[Writing Policies](writing-policies.md)** — the policy contract, overlays, precedence, enforcement modes
- **[Security model](../security-model.md)**
- **[Configuration](../configuration.md)** — the chart knobs behind the defaults above
- `docs/design/MCP-TOOL-ATTACK-SURFACE.md` — the prose enumeration `vectors.py` promotes into code
- `docs/design/MCP-RED-BLUE-LOOP.md` — live proxy red/blue results for the `PROXY` vectors
