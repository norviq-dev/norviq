<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Norviq Contributors -->

# Policy Cookbook

Complete, pasteable `NrvqPolicy` manifests for the jobs operators actually have: fence an agent class
to a fixed tool set, stop a sink verb, hold a change for a human, move a namespace's fallback,
gate on trust, gate on an MCP definition fact, and roll any of it out audit-only first.

**[Writing Policies](writing-policies.md) is the reference; this page is the recipes.** That guide
carries the Rego contract (§1), the complete list of facts a rule may read (§2), tighten-only overlays
(§4) and the dry-run/red-team loop (§6). This page does not restate any of it — where a recipe leans on
a fact, it cites the section rather than re-deriving the vocabulary. Every Rego block below was checked
against both validators that stand between you and enforcement (`webhook/controller.go:1030` and
`norviq/api/routers/policies.py:676`) and evaluated with `opa eval --v0-compatible` before being
written down.

Chart version throughout: **0.2.0**.

---

## 0. Read this before you paste: what a target actually keys to

A `NrvqPolicy` does not enforce where its `spec.target` says it does. It enforces at the **loader key**
the API derives from what the CRD controller POSTs, and the evaluator only ever looks up a fixed set of
keys. Getting this wrong produces the worst failure mode in the product: a CR that reaches
`Phase: Active`, shows up in `kubectl get nrvqpolicy`, and governs nothing.

The controller always sends `policy_name` = the CR's `metadata.name`
(`webhook/controller.go:925`), and `resolve_policy_key` (`norviq/api/routers/policies.py:727-741`)
prefers `agent_class`, then `policy_name`, then the workload `kind:name`, then `namespace:<ns>`. So
`policy_name` shadows the workload branch for anything that arrives from a CR.

| `spec.target` | Stored at loader key | Collected by the evaluator? |
|---|---|---|
| `agentClass: <class>`, CR in the namespace the agents run in | `<cr-namespace>:<class>` | **Yes** — `_append_policy(namespace, agent_class)`, `norviq/engine/evaluator.py:1941` |
| `namespace: <ns>` **plus** `clusterPriority`, CR in the release namespace | `<ns>:__baseline__` at priority `1` | **Yes** — `_append_policy(namespace, "__baseline__")`, `evaluator.py:1942`. Rewritten by `namespaceBaselineKey`, `webhook/controller.go:1008-1028` |
| `namespace: <ns>` alone (no `clusterPriority`) | `<ns>:<metadata.name>` | **No.** Nothing looks that key up |
| `kind` + `name` (workload) | `<cr-namespace>:<metadata.name>` | **No.** The workload tier the evaluator collects is `<ns>:deployment:<workload>` (`evaluator.py:1955-1961`), which the CRD path never mints |

Two consequences worth internalising:

- **An agent-class policy must live in the namespace where its agents run.** The controller keys the
  policy on the CR's OWN namespace (`payload.Namespace = namespace`, `webhook/controller.go:924`), and
  only the whole-namespace baseline case rewrites it. A CR in the release namespace targeting
  `agentClass: customer-support` in `chatbot-prod` is stored at `norviq:customer-support` and never
  matches a `chatbot-prod` caller — even though the controller's cross-namespace check
  (`validateTarget`, `webhook/controller.go:1076-1113`) happily admits it.
- **Workload (`kind` + `name`) targets are not reachable from a CR today.** The CRD accepts them, the
  controller validates them, the API stores them — under a key nothing reads. Use `agentClass` and give
  the workload its own class label, or apply the policy through `POST /api/v1/policies` without a
  `policy_name` (which is what mints `deployment:<name>`). That second route carries a precondition:
  the workload tier is only collected when the *caller* names its workload
  (`if workload:`, `evaluator.py:1955-1961`), and `AgentIdentity.workload` defaults to `""` and is
  populated by the sidecar/SDK from the Deployment name — never guessed from the pod
  (`norviq/sdk/core/events.py:22-25`). A caller that does not report one is governed by the class and
  namespace tiers only. This is a real product gap, not a documentation shortcut; §8 shows how to prove
  which key you actually landed on in ten seconds.

Every recipe below uses one of the two shapes that work.

### One scope, one policy — recipes do not stack

A loader key holds exactly one policy. `loader.create` upserts on `(namespace, agent_class)`
(`ON CONFLICT (namespace, agent_class) DO UPDATE`, `norviq/engine/policy_loader.py:164-179`), so two
CRs whose targets resolve to the same key do **not** layer: they overwrite each other, each sync bumps
the version, and which one is live is whichever the controller synced last — an ordering that is
re-rolled every time the webhook restarts. Two CRs both targeting `agentClass: payments-agent` in
`payments-prod` is the common form of this mistake; so is a second whole-namespace baseline landing on
a `__baseline__` the chart may already occupy for that namespace (§4).

To apply two of these recipes to one class, **merge them into one module** rather than applying two
CRs. With the partial-set idiom that is mechanical: concatenate the predicates, union the
`blocks`/`escalates` rules and the `reasons` map, and keep a single resolver tail. Nothing else
changes — that is what the idiom is for. If instead you want a rule that layers *on top of* a class's
own policy without replacing it, you want a tighten-only overlay (`__guardrail__`,
`<class>__remediation__`), and those are not authorable from a CR — see
[Writing Policies §4](writing-policies.md).

### The two validators disagree, and only one of them blocks you

`spec.rego` is checked twice. The controller parses it in-process (`validateRego`,
`webhook/controller.go:1030-1074`) and, if that passes, POSTs it to the API, which runs
`validate_rego_source` (`norviq/api/routers/policies.py:676-704`). Where they differ, the API is the
one that decides whether your policy ever enforces:

| Check | Controller (`validateRego`) | API (`validate_rego_source`) |
|---|---|---|
| Enforcement rule | any `decision` rule whose value is `"block"`/`"escalate"` — **including `default decision = "block"`** | a **complete** rule: `decision = "block" { … }` or `decision = "escalate" { … }`, or partial sets plus a resolver (`assert_decision_resolver`, `policies.py:565-607`) |
| `regex.*` / `re_match(` calls | **max 5** (`controller.go:1069-1072`) | max 25 (`policies.py:693-695`) |
| Line cap | 500 newlines after comment-strip | 500 **non-blank** lines after comment-strip |
| Forbidden builtins / cross-package `data.` | not checked | rejected (`_FORBIDDEN_REGO_TOKENS`, `policies.py:637-673`) |

A policy that satisfies the controller but not the API fails in the least visible way available: the CR
flips to `Phase: Error` with a `422`, `NRVQ-WHK-4025` appears in the webhook log, and the database keeps
serving whatever rego was there before. **Write a complete `decision = "block" { … }` rule, declare a
`default decision`, and stay under five regex calls.** The `default decision` line is not optional in
either validator — the controller refuses `policy must define default decision` (`hasDefaultDecision`,
`controller.go:1063-1065`) and the API refuses a resolver without one (`_DEFAULT_DECISION_RE`,
`policies.py:599-607`), both so that a rule which never matches cannot leave `decision` undefined and be
read as an allow. Those three cover the differences above; the API's forbidden-builtin and
cross-package-`data.` rejects are separate and no recipe here goes near them. Every recipe below
satisfies all of it.

> Two shipped templates currently violate this: `policies/templates/tool-allowlist-perimeter.rego` and
> `policies/templates/sql-allowlist-deny-by-default.rego` express their deny-by-default posture with
> `default decision = "block"` and no complete block rule. They pass `opa check`, pass the controller,
> and are refused `422 rego_source must include block or escalate decision` by the API. Do not paste
> them into `spec.rego` unchanged — add an explicit `decision = "block" { not allowed }` rule (Recipe 1
> shows the shape).

### Dry-run cannot exercise most of these recipes

`POST /api/v1/policies/dry-run` — and the `norviq policy dry-run` that wraps it — replays your
candidate against real recent audit records, and it is the right first move for any policy that keys
on `input.tool_name` or `input.tool_params`. But the replay builds its input by hand and **omits
`input.derived`, `input.mcp` and `input.direction`** ([Writing Policies §2.5](writing-policies.md)).

Recipes 2, 3, 4, 5 and 6 all gate their `decision` on exactly those facts — every recipe here except
1 and 7, which key on the tool name alone. A tighten-only rule that reads one of them hits an undefined
reference during a replay, so the rule does not fire and the response comes back `newly_blocked: 0` —
which reads as an all-clear and means "not exercised". That is the dangerous direction, so treat it as
no evidence at all.

What does exercise them: `POST /api/v1/evaluate` (the per-recipe probes below build a real
`ToolCallEvent`, so the full document is present) and the red-team suite,
`norviq redteam run --agent <class> --namespace <ns>`. Use dry-run to find out what a tool-name rule
would break, and `/evaluate` plus red-team to prove a `derived`- or `mcp`-gated rule actually fires.

### Fields the CRD accepts that nothing acts on

- **`spec.rules`** is documentation. The controller forwards it (`webhook/controller.go:964-965`) and
  the API model accepts it (`PolicyCreate.rules`, `policies.py:199`), and no code path reads it. It is
  a useful comment about which `rule_id`s you expect; it is not a filter, an allowlist, or a selector.
- **`spec.enforcementMode: escalate`** is stored and displayed but changes nothing at evaluation time.
  Only `audit` is special-cased (`_apply_policy_mode`, `norviq/engine/evaluator.py:721-759`); `escalate`
  and `block` take the same path. An `escalate` **decision** comes from your Rego, not from this field
  — see Recipe 3.
- **`status.blockCount24h` / `status.matchingWorkloads`** — the `Blocks-24h` column in
  `kubectl get nrvqpolicy` is hardcoded to `0` on every status write (`webhook/controller.go:799-805`).
  Read block counts from the audit log (§8), never from that column.

---

## 1. Fence an agent class to a fixed tool set

**What it does.** Deny-by-default: the `customer-support` class may call exactly the three listed
tools and nothing else. This is the only shape that holds against a name nobody has seen before — it is
registration-based, so `zzz_exfil`, `x1` and `do_thing` fail for not being listed, with no
classification required. Contrast a verb/intent rule (Recipe 2), which gates on what a call *does* and
can therefore be routed around by renaming.

The allowlist matches `input.tool_name` **exactly**, as the shipped template does. Under deny-by-default
that is already the confusable-safe shape: `sеarch_kb` with a Cyrillic `е`, or a `search_kb` carrying a
zero-width joiner, is a different string from `search_kb` and is denied for not being on the list.

**Do not add an `input.tool_name_normalized` arm to an allowlist.** That fact is the engine's confusable
*skeleton* of the name (`_build_input`, `norviq/engine/evaluator.py:941-943`), and folding is the
tightening direction only for a blocklist, where it collapses evasive spellings onto the name you
refused. On an allowlist it does the opposite — it collapses them onto the name you *approved*. Measured
against OPA with the engine's own `skeleton()`, which folds both variants above onto `search_kb`: adding
`allowed { allowed_tools[lower(input.tool_name_normalized)] }` turns each of them from a `block` into
`allow` / `tool_allowlisted`. `lower()` is left off for the same reason — case-folding widens the list
to spellings nobody registered, so `SEARCH_KB` is a block too.

```yaml
apiVersion: norviq.io/v1alpha1
kind: NrvqPolicy
metadata:
  name: support-tool-perimeter
  namespace: chatbot-prod          # MUST be the namespace the agents run in
spec:
  target:
    agentClass: customer-support   # matches the pod label norviq.io/agent-class
  enforcementMode: block
  priority: 200
  rego: |
    package norviq.cookbook.support_tool_perimeter

    # Deny-by-default: this class may call exactly the tools listed, and nothing else.
    default decision = "block"
    default rule_id = "tool_not_allowlisted"
    default reason = "tool is not on this agent class's approved list"

    allowed_tools = {
      "search_kb",
      "get_customer",
      "get_order",
    }

    # Exact name only. A confusable, zero-width or case variant of a listed
    # name is a DIFFERENT string and is denied for not being listed - see the
    # note above on why folding the name would widen this list, not tighten it.
    allowed { allowed_tools[input.tool_name] }

    decision = "allow" { allowed }
    rule_id = "tool_allowlisted" { allowed }
    reason = "tool is on this agent class's approved list" { allowed }

    # The complete block rule the API validator requires. `default decision = "block"`
    # alone is accepted by the controller and refused by the API — see §0.
    decision = "block" { not allowed }

    # An unlisted call whose verb is `unknown` is the one worth alerting on: someone
    # invoked a tool the classifier could not place, which is what probing looks like.
    rule_id = "tool_not_allowlisted_unclassified" {
      not allowed
      input.derived.verb == "unknown"
    }
    reason = "unlisted AND unclassified tool - the call's purpose could not be determined" {
      not allowed
      input.derived.verb == "unknown"
    }
```

**Do not author the list from memory.** Run the class audit-only first (Recipe 7), let the console show
the tools it actually calls, promote the legitimate ones, and only then switch to `block`. This is the
one recipe here that dry-run genuinely measures — its `decision` path reads only `input.tool_name`, and
the replay carries that verbatim from the audit row (`_opa_input_from_record`, `policies.py:934`) — so
run it before you enforce:

```bash
norviq policy dry-run -f policy.rego -n chatbot-prod -c customer-support
```

Read the result carefully. The CLI prints only `Records checked`, `Would block`, `Would allow` and
`Recommendation` (`norviq/cli/main.py:153-156`), and `Would block` is *every* call the candidate would
refuse, not the ones that are currently allowed. The number that tells you whether enforcing breaks
live traffic is `newly_blocked`, and it exists only in the endpoint's JSON — the CLI has no `--output
json` branch on this subcommand. Get it with `curl -s -X POST "$API/api/v1/policies/dry-run"` (same
body: `namespace`, `agent_class`, `rego_source`) and require `newly_blocked: 0` before you switch to
`block`. A non-zero count means the allowlist is not finished.

**Verify it took effect.**

```bash
kubectl get nrvqpolicy -n chatbot-prod support-tool-perimeter     # PHASE -> Active
norviq policy get chatbot-prod customer-support                   # the key it really landed on
curl -s -X POST "$API/api/v1/evaluate" -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{
    "tool_name": "zzz_exfil", "tool_params": {},
    "agent_identity": {"spiffe_id":"spiffe://norviq/ns/chatbot-prod/sa/support",
                       "namespace":"chatbot-prod","agent_class":"customer-support"}}'
# {"decision":"block","rule_id":"tool_not_allowlisted", ...}
```

`zzz_exfil` blocks on the default rule, not the `_unclassified` one: the classifier reads `exfil` as a
sink and returns `verb: "send"` (`classify_tool`, `norviq/engine/capability/source_registry.py:386`),
so `input.derived.verb == "unknown"` is false. That is the point of the recipe — it does not need the
verb to refuse the call. To see the `_unclassified` arm fire you need a name the classifier genuinely
cannot place; `x1` and `do_thing` both return `unknown`, and either yields
`{"decision":"block","rule_id":"tool_not_allowlisted_unclassified", ...}`.

---

## 2. Stop a sink verb, and pin where egress may go

**What it does.** Blocks outbound calls from the `data-analyst` class that go anywhere other than an
approved destination, blocks any outbound call carrying a credential, and escalates one carrying
regulated data.

It gates on `input.derived.verb`, `input.derived.destinations` and `input.derived.data_classes`
([Writing Policies §2.2](writing-policies.md) has the vocabulary and the caveats). Two reasons to reach
for them here rather than for tool names and a regex: `verb` is the same notion of "sink" the console
and the capability registry use, so a vendor-named egress tool (`invoke_send_pipeline`, `run_export`)
is covered without being enumerated; and because destinations and data classes arrive pre-extracted,
the policy needs no `regex.*` of its own and stays well inside the controller's five-call budget.

Under deny-by-default the **destination is the control**: "may email acme.com" needs no detector for
what is being sent, which is the gap a detector list can never close.

```yaml
apiVersion: norviq.io/v1alpha1
kind: NrvqPolicy
metadata:
  name: analyst-egress-scope
  namespace: analytics
spec:
  target:
    agentClass: data-analyst
  enforcementMode: block
  priority: 200
  rego: |
    package norviq.cookbook.analyst_egress

    # Partial-set + resolver idiom: several guards can fire on one call without a
    # complete-rule conflict, and each still carries its own rule_id and reason.
    default decision = "allow"
    default rule_id = "default_allow"
    default reason = "Allowed"

    # >>> EDIT: hosts and mail domains this class may send to.
    approved_destinations = {"acme.com", "mail.acme.com"}

    is_send { input.derived.verb == "send" }

    unapproved_host {
      is_send
      host := input.derived.destinations.hosts[_]
      not approved_destinations[host]
    }
    unapproved_recipient {
      is_send
      addr := input.derived.destinations.emails[_]
      parts := split(lower(addr), "@")
      not approved_destinations[parts[1]]
    }
    sends_secret {
      is_send
      input.derived.data_classes[_] == "secret"
    }
    sends_regulated {
      is_send
      class := input.derived.data_classes[_]
      class != "secret"
    }

    blocks["egress_unapproved_destination"] { unapproved_host }
    blocks["egress_unapproved_destination"] { unapproved_recipient }
    blocks["egress_carries_secret"] { sends_secret }
    escalates["egress_carries_regulated_data"] { sends_regulated }

    reasons = {
      "egress_unapproved_destination": "egress to a destination this agent class is not approved for",
      "egress_carries_secret": "a credential may not leave through an egress tool",
      "egress_carries_regulated_data": "regulated data (PII/PCI) in an outbound call - needs human review",
      "default_allow": "Allowed",
    }

    block_fired { blocks[_] }
    escalate_fired { escalates[_] }
    decision = "block" { block_fired }
    decision = "escalate" { escalate_fired; not block_fired }
    rule_id = sort([id | blocks[id]])[0] { block_fired }
    rule_id = sort([id | escalates[id]])[0] { escalate_fired; not block_fired }
    reason = reasons[rule_id]
```

**Why the partial-set idiom here and not in Recipe 1.** Two complete rules that bind the same name to
different values at the same time are a runtime `eval_conflict_error` in OPA. Recipe 1's branches are
mutually exclusive (`allowed` / `not allowed`), so complete rules are safe. Here three guards can fire
on one call, so `blocks[id]` / `escalates[id]` plus the canonical resolver is the shape that keeps
every fired rule carrying a correct `reason` — the same shape as the resolver tail in
`comprehensive.rego:765-817` and in every sector pack (`policies/sector/*/*.rego`, between their
`RESOLVER-BEGIN`/`RESOLVER-END` markers). Those two are supersets, not copies: both also carry an
`audits[id]` set and `audit_fired` arm, the packs bind `reason` per branch rather than once through
`rule_id`, and comprehensive.rego adds SQL-vs-shell attribution shadowing. The recipes here need none
of that, so they use the two-decision core of it.

**Known limits, stated plainly.** `derived.verb` is derived from the tool NAME (with an admin verb
promotion able to fill in an `unknown`, never to contradict the classifier —
`evaluator.py:1038-1058`). A caller who renames its sink to something unrecognisable gets
`verb == "unknown"`, and `is_send` is false, so this policy says nothing about it. That is why this
recipe is a scope, not a perimeter: pair it with Recipe 1 on the same class.

**Verify it took effect.**

```bash
curl -s -X POST "$API/api/v1/evaluate" -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{
    "tool_name": "send_email",
    "tool_params": {"to": "ops@evil.example", "body": "quarterly numbers"},
    "agent_identity": {"spiffe_id":"spiffe://norviq/ns/analytics/sa/analyst",
                       "namespace":"analytics","agent_class":"data-analyst"}}'
# {"decision":"block","rule_id":"egress_unapproved_destination", ...}
norviq audit list -n analytics -d block --range 1h
```

---

## 3. Hold a change for human review

**What it does.** Destructive changes, unclassified tools, and writes carrying regulated data are
returned as `escalate`; a small set of tools is refused outright.

**Understand what `escalate` is before you use it.** It is *not* a resumable approval queue — there is
no endpoint that later releases a held call. The tool is **not executed**: the SDK raises
`NorviqEscalateError` (`norviq/sdk/core/interceptor.py:113-115`), and the MCP proxy returns a tool
error whose text reads "held for human approval" and instructs the model not to retry
(`norviq/mcp/firewall.py:823-841`). What escalate buys you over a block is attribution and triage: the
decision is recorded with its own `rule_id` and shows up in the audit log as a distinct class of
outcome that a human is expected to act on out of band. Norviq's only true approval workflow is Gate A
for MCP *tool definitions* (`norviq/api/routers/mcp.py`), not per-call.

`escalate` is also the honest handling for `derived.verb == "unknown"`. Do not write
`decision = "allow" { input.derived.verb == "unknown" }`: classification keys on the tool name, which
the agent side controls, so that rule is a universal bypass for anything named unrecognisably.

```yaml
apiVersion: norviq.io/v1alpha1
kind: NrvqPolicy
metadata:
  name: crm-change-review
  namespace: sales-prod
spec:
  target:
    agentClass: crm-writer
  # Metadata only: `escalate` here changes nothing at evaluation time (§0). The
  # escalate DECISION below comes from the rego.
  enforcementMode: block
  priority: 200
  rego: |
    package norviq.cookbook.crm_change_review

    default decision = "allow"
    default rule_id = "default_allow"
    default reason = "Allowed"

    # >>> EDIT: actions this class may never take, whatever a reviewer would say.
    never_allowed = {"drop_table", "exec_shell", "spawn_pod"}

    # A destructive change: hold it for a human rather than refusing it outright.
    destructive { input.derived.verb == "delete" }

    # The classifier did not recognise this tool name. Escalate - never allow.
    unclassified { input.derived.verb == "unknown" }

    # A write whose payload carries regulated data is worth a second pair of eyes.
    regulated_write {
      input.derived.verb == "write"
      input.derived.data_classes[_]
    }

    blocks["crm_never_allowed_tool"] { never_allowed[lower(input.tool_name)] }
    escalates["crm_destructive_change"] { destructive }
    escalates["crm_unclassified_tool"] { unclassified }
    escalates["crm_regulated_write"] { regulated_write }

    reasons = {
      "crm_never_allowed_tool": "this tool is never permitted for the crm-writer class",
      "crm_destructive_change": "destructive change held for human review",
      "crm_unclassified_tool": "unclassified tool - the call's purpose could not be determined",
      "crm_regulated_write": "write carrying regulated data held for human review",
      "default_allow": "Allowed",
    }

    block_fired { blocks[_] }
    escalate_fired { escalates[_] }
    decision = "block" { block_fired }
    decision = "escalate" { escalate_fired; not block_fired }
    rule_id = sort([id | blocks[id]])[0] { block_fired }
    rule_id = sort([id | escalates[id]])[0] { escalate_fired; not block_fired }
    reason = reasons[rule_id]
```

**Verify it took effect.**

```bash
curl -s -X POST "$API/api/v1/evaluate" -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{
    "tool_name": "delete_record", "tool_params": {"id": "C-91"},
    "agent_identity": {"spiffe_id":"spiffe://norviq/ns/sales-prod/sa/crm",
                       "namespace":"sales-prod","agent_class":"crm-writer"}}'
# {"decision":"escalate","rule_id":"crm_destructive_change", ...}
norviq audit list -n sales-prod -d escalate --range 24h
```

---

## 4. Move a namespace's fallback floor

**What it does.** Replaces the policy every agent class in `chatbot-prod` falls back to when no
class-tier policy matches.

**This is the only namespace-wide shape that enforces**, and it has three non-obvious requirements
(`namespaceBaselineKey`, `webhook/controller.go:1008-1028`):

1. The CR must live in the **release namespace** — the controller's admin namespace, set by the chart
   to `.Release.Namespace` (`helm/norviq/templates/webhook-deployment.yaml:109-110`; default `norviq`
   if unset, `webhook/controller.go:217`). Anywhere else and `clusterPriority` is rejected with
   `NRVQ-WHK-4037`.
2. `spec.target` must carry `namespace` and **nothing else** — no `agentClass`, no `kind`/`name`. Add
   any of those and the rewrite does not fire and the policy lands at an unread key.
3. `spec.clusterPriority` must be present and in `500-1000`. It is an **authorization marker for the
   cross-namespace target, not the evaluation priority**: the controller then stores the policy at
   priority `1` (`baselineFallbackPriority`, `webhook/controller.go:998-1001`).

That priority is the point. A namespace baseline is a **fallback, not a floor**. Base-tier candidates
are resolved highest-priority-wins (`_resolve_precedence`, `norviq/engine/evaluator.py:2149-2158`), so
a class policy at the default `100` outranks the baseline at `1` outright — including when the class
policy allows and the baseline would have blocked. If you need something that can only ever tighten
regardless of priority, you need an overlay, and no overlay is reachable from a CR — the CRD's
`agentClass` pattern (`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`) forbids underscores. Which endpoint you use
depends on which overlay:

| Overlay | How to author it |
|---|---|
| `__guardrail__`, `<class>__remediation__` | `POST /api/v1/policies` with that `agent_class` |
| `__pack__` | `POST /api/v1/policy-packs/{id}/enable` |
| `__pack_override__`, `__pack_weaken__` | `PUT /api/v1/policy-packs/override` |

The pack scopes are **managed** — `POST /api/v1/policies` rejects all three by name with a `422`
naming the right endpoint (`policies.py:474-480`), because a direct write there is wiped the next time
any pack is toggled and skips the override route's OPA validation and admin gate. See
[Writing Policies §4](writing-policies.md).

**One namespace has exactly one `__baseline__` scope, and on most installs the chart already occupies
it.** With `baselineClusterPolicy.enabled: true` (the default, `helm/norviq/values.yaml:67-71`) the
chart renders one `baseline-cluster-guard-<ns>` CR per entry in `policyQuotaNamespaces`, each landing at
`<ns>:__baseline__` with the `strict` preset. Check before you assume: `policyQuotaNamespaces` is `[]`
by default (`values.yaml:17`), and the chart refuses to install with the baseline enabled and that list
empty rather than silently rendering zero baselines (`{{- fail }}`,
`helm/norviq/templates/baseline-cluster-policy.yaml:1-10`) — so the scope is occupied for exactly the
namespaces on that list, and not at all if the operator chose `baselineClusterPolicy.enabled: false`.
Where it *is* occupied, a second CR targeting the same namespace does not layer on top of it — both
write the same scope and the last controller sync wins, which after a webhook restart is not an ordering
you should depend on. Applying this recipe there is a **deliberate replacement**: remove or repoint the
chart's baseline for that namespace first.

```yaml
apiVersion: norviq.io/v1alpha1
kind: NrvqPolicy
metadata:
  name: chatbot-prod-baseline
  namespace: norviq                # the RELEASE namespace, not the tenant namespace
spec:
  target:
    namespace: chatbot-prod        # and nothing else
  enforcementMode: block
  clusterPriority: 900             # 500-1000, admin-only; stored priority becomes 1
  rego: |
    package norviq.cookbook.chatbot_prod_baseline

    # The fallback for every class in chatbot-prod that has no policy of its own.
    # Deliberately narrow: it refuses the destructive verbs and holds anything the
    # classifier could not place, and says nothing else - a class policy is where
    # per-class intent belongs.
    default decision = "allow"
    default rule_id = "default_allow"
    default reason = "Allowed"

    blocks["baseline_destructive_verb"] { input.derived.verb == "delete" }
    escalates["baseline_unclassified_tool"] { input.derived.verb == "unknown" }

    reasons = {
      "baseline_destructive_verb": "destructive tool call refused by the chatbot-prod baseline",
      "baseline_unclassified_tool": "unclassified tool - held for review by the chatbot-prod baseline",
      "default_allow": "Allowed",
    }

    block_fired { blocks[_] }
    escalate_fired { escalates[_] }
    decision = "block" { block_fired }
    decision = "escalate" { escalate_fired; not block_fired }
    rule_id = sort([id | blocks[id]])[0] { block_fired }
    rule_id = sort([id | escalates[id]])[0] { escalate_fired; not block_fired }
    reason = reasons[rule_id]
```

Swap `rego` for `preset: strict | moderate | permissive` if one of the shipped starters fits — the
preset files live in the webhook image at `/app/presets` (`webhook/Dockerfile:15,25`; source
`webhook/presets/*.rego`) and `rego` always wins if both are set (`webhook/controller.go:983-993`).
Because a preset's content lives in the image, a new release changes what an unchanged CR means; the
controller notices that via a content fingerprint and re-syncs (`policyContentDrifted`,
`webhook/controller.go:441-459`, logged as `NRVQ-WHK-4061`).

**Verify it took effect.**

```bash
norviq policy get chatbot-prod __baseline__          # NOT chatbot-prod-baseline
curl -s -H "Authorization: Bearer $TOKEN" \
  "$API/api/v1/policies/effective?namespace=chatbot-prod&agent_class=customer-support"
# layers[] lists every candidate scope with its priority and overlay flag — the
# baseline should appear as
# {"scope":"chatbot-prod:__baseline__","priority":1,"overlay":false}
```

`layers[]` is in `_collect_candidates` **collection** order (own class, then `__baseline__`, then
`__cluster__:__baseline__`, then the namespace and workload tiers, then overlays), not precedence
order. Its job is to answer "is my scope in the stack at all"; who wins is decided later from
`priority` and the `overlay` flag (§8, step 5).

If `norviq policy get chatbot-prod __baseline__` 404s but `kubectl get nrvqpolicy -n norviq` says
`Active`, one of the three requirements above is unmet and the policy landed at
`norviq:chatbot-prod-baseline` instead. Check with `norviq policy list`.

---

## 5. Gate on trust score

**What it does.** State-changing calls from the `payments-agent` class are refused below a hard trust
floor and held for review below a review floor. Reads are never gated.

**What the engine already does, so you do not restate it.** After every policy evaluation the engine
applies its own trust overrides (`_apply_trust_overrides`, `norviq/engine/evaluator.py:863-887`):
a `frozen` agent is hard-blocked with `rule_id: trust_frozen` regardless of what your policy said, and
a `low`-tier agent's **allow** is rewritten to `escalate_low_trust`. Tier boundaries are `high >= 0.7`,
`medium >= 0.4`, else `low`, moved together by a per-namespace `trust_threshold`
(`_categorize` / `_tiers`, `norviq/engine/trust/calculator.py:293-318`). So a rule that blocks frozen
agents is dead code, and a rule that escalates below 0.4 duplicates the engine. What a policy adds is
a **stricter, per-class threshold** and the ability to turn a low-trust allow into a hard block rather
than an escalate.

**The cost, so you can decide.** Reading `input.trust_score`, `input.trust_category` or
`input.agent.spiffe_id` makes this policy's decisions **non-cacheable**: the eval cache is keyed per
`(namespace, agent_class, tool+params+depth+workload+mcp)` and is shared between agents of a class, so
the engine detects those facts in the source and skips the cache write entirely
(`_PER_IDENTITY_FACTS` / `_depends_on_per_identity_facts`, `evaluator.py:1546-1575`). That is
deliberate — without it a low-trust agent would be served a high-trust agent's allow for the TTL — but
every call to this class pays a full OPA evaluation.

```yaml
apiVersion: norviq.io/v1alpha1
kind: NrvqPolicy
metadata:
  name: payments-trust-gate
  namespace: payments-prod
spec:
  target:
    agentClass: payments-agent
  enforcementMode: block
  priority: 300
  rego: |
    package norviq.cookbook.payments_trust_gate

    default decision = "allow"
    default rule_id = "default_allow"
    default reason = "Allowed"

    # >>> EDIT: `hard_floor` refuses outright; below `review_floor` the change is
    # held for a human. Reads are never gated here.
    hard_floor = 0.4
    review_floor = 0.8

    changes_state { input.derived.verb == "write" }
    changes_state { input.derived.verb == "delete" }
    changes_state { input.derived.verb == "send" }

    # Below the hard floor the engine's own override would only ESCALATE (and only
    # from an allow). For payment state this class refuses outright instead.
    blocks["payments_trust_below_hard_floor"] {
      changes_state
      input.trust_score < hard_floor
    }
    escalates["payments_trust_below_review_floor"] {
      changes_state
      input.trust_score < review_floor
      input.trust_score >= hard_floor
    }

    reasons = {
      "payments_trust_below_hard_floor": "agent trust is below the hard floor for payment state changes",
      "payments_trust_below_review_floor": "agent trust is below this class's review floor - change held for human review",
      "default_allow": "Allowed",
    }

    block_fired { blocks[_] }
    escalate_fired { escalates[_] }
    decision = "block" { block_fired }
    decision = "escalate" { escalate_fired; not block_fired }
    rule_id = sort([id | blocks[id]])[0] { block_fired }
    rule_id = sort([id | escalates[id]])[0] { escalate_fired; not block_fired }
    reason = reasons[rule_id]
```

**Verify it took effect.** Drive the score down rather than asserting it. The `/evaluate` request body
has a `trust_score` field, and the route strips it before building the event
(`model_dump(exclude={"trust_score"})`, `norviq/api/routers/evaluate.py:327`) — the score that reaches
Rego is the one the engine computes for the caller's SPIFFE ID.

`norviq agent reset-trust … --score 0.5` is the lever, but read what it does: for `0 < score < 1` it
sets a **tighten-only cap**, not an assignment. The engine uses `min(computed, cap)`
(`calculator.py:125-127`; `update_trust`, `norviq/api/routers/agents.py:426-430`), so `--score 0.5`
means "at most 0.5" and an agent whose behaviour already scores `0.3` stays at `0.3` and returns the
hard-floor **block**, not the review-floor escalate below. `--score 0` freezes instead (`trust_frozen`);
`--score 1.0` clears both the freeze and the cap. Read back the effective score with `norviq agent get`
before concluding anything about which arm fired.

```bash
norviq agent reset-trust spiffe://norviq/ns/payments-prod/sa/payments --score 0.5
norviq agent get spiffe://norviq/ns/payments-prod/sa/payments   # read the EFFECTIVE score first
curl -s -X POST "$API/api/v1/evaluate" -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{
    "tool_name": "post_payment", "tool_params": {"amount": "10.00"},
    "agent_identity": {"spiffe_id":"spiffe://norviq/ns/payments-prod/sa/payments",
                       "namespace":"payments-prod","agent_class":"payments-agent"}}'
# with an effective score in [0.4, 0.8):
# {"decision":"escalate","rule_id":"payments_trust_below_review_floor", ...}
```

(`post_payment` classifies as `verb: "send"`, so `changes_state` holds and the gate applies.)

---

## 6. Gate on an MCP definition fact

**What it does.** For the `ledger-broker` class, refuses MCP tools whose definition is quarantined,
absent from the Gate-A catalog entirely, or scanner-flagged at high/critical; escalates one that changed
after approval; and permits writes only through named servers. It does **not** refuse a `first_seen`
definition — see the pin-vocabulary note below before you rely on it as an approval gate.

It is deliberately a **different class** from Recipe 5 so the two manifests can be pasted side by side.
To give one class both gates, merge the two modules into one — see "One scope, one policy" in §0.

MCP traffic is already governed by every policy you have — the proxy maps MCP `arguments` onto
`tool_params` one-for-one, so a rule written for the SDK applies unchanged. What only a policy can add
is the Gate-A state the proxy computed at **discovery** and attached to the call as `input.mcp`
(`_mcp_context`, `norviq/mcp/firewall.py:495-543`). Because those values were computed once at
discovery and cached on the catalog entry, reading them per call costs a dict lookup — which is the
whole reason a definition-integrity gate can sit on the hot path at all.

[Writing Policies §2.3](writing-policies.md) is the field-by-field reference for `input.mcp` and
`input.direction`; the three facts this recipe turns on are `pin_status`, `scan_severity` and `server`.
The one worth repeating because the policy's shape depends on it: **`unknown` is not `none`.** A tool
with no catalog entry reports `pin_status: "unknown"` and `scan_severity: "unknown"` — Gate A never
looked at it — whereas `none` means it was scanned and came back clean. An allow whose only integrity
guard is `scan_severity in ["none","low"]` is therefore satisfied by a definition nobody ever vetted,
so this recipe refuses `unknown` explicitly rather than letting it fall through.

**What this recipe does not refuse: `first_seen`.** The pin vocabulary is `pinned`, `first_seen`,
`drift`, `quarantined` (`norviq/mcp/pins.py:70-73`) plus the `unknown` above, and which one a
never-before-seen definition gets depends on the proxy's pin mode. Under the default
`mcp_pin_mode: "tofu"` (`norviq/config.py:191`) first sight is pinned and allowed and reported as
`first_seen` (`norviq/api/routers/mcp.py:158,175`); only `strict` quarantines it until an operator
approves. So on a default install the rules below stop a *changed* or *withheld* definition, not a
brand-new one — trust-on-first-use is exactly what TOFU means. If this class must never call a
definition no human approved, either run the proxy with `mcp_pin_mode: strict`, or add a rule of its own
to the block set below rather than folding it into `unvetted` (whose reason, "no approved definition
exists", is wrong for a TOFU pin — one does exist, `approved_by: "tofu"`):

```rego
tofu_pinned { is_mcp; input.mcp.pin_status == "first_seen" }
blocks["mcp_definition_tofu_only"] { tofu_pinned }
# and in `reasons`:
#   "mcp_definition_tofu_only": "this MCP tool was pinned on first sight, not approved by a human",
```

```yaml
apiVersion: norviq.io/v1alpha1
kind: NrvqPolicy
metadata:
  name: ledger-mcp-gate
  namespace: payments-prod
spec:
  target:
    agentClass: ledger-broker
  enforcementMode: block
  priority: 250
  rego: |
    package norviq.cookbook.ledger_mcp_gate

    default decision = "allow"
    default rule_id = "default_allow"
    default reason = "Allowed"

    # >>> EDIT: MCP servers this class may WRITE through. Server ids are the
    # `--server-id` the proxy was started with.
    writable_servers = {"postgres-prod"}

    # >>> EDIT: the Gate-A scan severities that stop a definition being usable.
    blocking_scan_severity = {"high", "critical"}

    # Only govern calls that arrived over MCP: a non-MCP caller carries no
    # input.mcp, and this policy must not change its decision.
    is_mcp { input.mcp.server }

    quarantined { is_mcp; input.mcp.pin_status == "quarantined" }

    # "unknown" = Gate A never saw the definition. Not the same fact as "scanned
    # and clean" ("none"), and for payments it is not admissible.
    unvetted { is_mcp; input.mcp.pin_status == "unknown" }

    # The definition CHANGED after approval. Escalate rather than block: adopting a
    # changed definition is a legitimate operator action and the safe default is a
    # human on the diff, not a silently broken agent.
    drifted { is_mcp; input.mcp.pin_status == "drift" }

    flagged { is_mcp; blocking_scan_severity[input.mcp.scan_severity] }

    # The same tool NAME served by a different server is a different action against
    # a different system - what a tool-name policy cannot express at all. `unknown`
    # counts as a write here, deliberately tighter than the shipped template.
    unapproved_write {
      is_mcp
      not writable_servers[input.mcp.server]
      input.derived.verb != "read"
    }

    blocks["mcp_tool_not_approved"] { quarantined }
    blocks["mcp_definition_never_seen"] { unvetted }
    blocks["mcp_definition_flagged"] { flagged }
    blocks["mcp_unapproved_write_server"] { unapproved_write }
    escalates["mcp_definition_drift"] { drifted }

    reasons = {
      "mcp_tool_not_approved": "this MCP tool definition has not been approved",
      "mcp_definition_never_seen": "no approved definition exists for this MCP tool",
      "mcp_definition_flagged": "this MCP tool definition matched an instruction-injection pattern",
      "mcp_unapproved_write_server": "writes are not permitted through this MCP integration",
      "mcp_definition_drift": "this MCP tool definition changed after it was approved (possible rug pull)",
      "default_allow": "Allowed",
    }

    block_fired { blocks[_] }
    escalate_fired { escalates[_] }
    decision = "block" { block_fired }
    decision = "escalate" { escalate_fired; not block_fired }
    rule_id = sort([id | blocks[id]])[0] { block_fired }
    rule_id = sort([id | escalates[id]])[0] { escalate_fired; not block_fired }
    reason = reasons[rule_id]
```

**Trust boundary.** `input.mcp` is PEP-reported, exactly like `input.tool_name`. It is a **policy**
input and never a **trust** input: identity comes from the caller's attested SVID and is never read
from an MCP message. Do not use `input.mcp.server` to decide *who* is calling — only *what* they are
calling.

**This is a guardrail, not a perimeter.** It defaults to allow and blocks specific conditions, so an
MCP tool it says nothing about falls through to whatever else governs the class. Pair it with Recipe 1.
For the namespace-wide, operator-loaded variant see `policies/templates/mcp_integration_guardrail.rego`,
which also covers the `answer` plane (a credential in a reply to a server-composed
`resultType: "input_required"` question).

**Verify it took effect.** `input.mcp` is optional on `POST /api/v1/evaluate`, so you can drive each
branch without a live drifted server:

```bash
curl -s -X POST "$API/api/v1/evaluate" -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{
    "tool_name": "pg_query", "tool_params": {"sql": "select 1"},
    "agent_identity": {"spiffe_id":"spiffe://norviq/ns/payments-prod/sa/ledger",
                       "namespace":"payments-prod","agent_class":"ledger-broker"},
    "mcp": {"server":"postgres-prod","transport":"stdio","surface":"tools/call",
            "pin_status":"drift","scan_severity":"none","definition_seen":true}}'
# {"decision":"escalate","rule_id":"mcp_definition_drift", ...}
```

Then confirm the real pin state on the MCP Servers page, or `GET /api/v1/mcp/servers`.

---

## 7. Roll it out audit-only first

**What it does.** Applies a real policy that logs what it *would* have done instead of enforcing it.

[Writing Policies §5](writing-policies.md) covers the namespace-wide monitor switch; this is the
per-policy one. `spec.enforcementMode: audit` reaches the engine and is honoured — but only under
conditions worth knowing precisely (`_apply_policy_mode`, `norviq/engine/evaluator.py:721-759`):

- It softens a `block` or `escalate` to `audit` **only when this policy is the winning candidate**. If
  a different layer wins — the namespace baseline, a sector pack — that layer's decision stands at its
  own mode, and the call is still blocked.
- It applies to **base/floor candidates only**. Overlays carry no mode by construction
  (`_collect_candidates`, `evaluator.py:1968-2008`), because honouring an overlay's mode would let a
  tighten-only overlay weaken the policy it sits on.
- Softened decisions keep their identity: `decision` becomes `audit` and `rule_id` is prefixed
  `policy_audit_would_block:` (`evaluator.py:63`, `756-759`). The call **proceeds** — `audit` counts as
  allowed at the PEP (`PolicyDecision.is_allowed`, `norviq/sdk/core/decisions.py:35-37`).
- Five rule ids stay hard whatever the mode says: `trust_frozen`, `policy_load_pending`,
  `evaluator_error`, `evaluator_invalid_payload`, `rate_limit_exceeded`
  (`_POSTURE_EXEMPT_RULES`, `evaluator.py:329-331`). An admin trust freeze is an incident-response kill
  switch, and engine-health and rate-limit blocks are not policy decisions to monitor away.

```yaml
apiVersion: norviq.io/v1alpha1
kind: NrvqPolicy
metadata:
  name: support-tool-perimeter
  namespace: chatbot-prod
spec:
  target:
    agentClass: customer-support
  enforcementMode: audit           # <- the only change from Recipe 1
  priority: 200
  rego: |
    # ... identical to Recipe 1 ...
    package norviq.cookbook.support_tool_perimeter
    default decision = "block"
    default rule_id = "tool_not_allowlisted"
    default reason = "tool is not on this agent class's approved list"
    allowed_tools = {"search_kb", "get_customer", "get_order"}
    allowed { allowed_tools[input.tool_name] }
    decision = "allow" { allowed }
    rule_id = "tool_allowlisted" { allowed }
    reason = "tool is on this agent class's approved list" { allowed }
    decision = "block" { not allowed }
```

Flip to enforcing by changing the one field and re-applying; the controller re-syncs on the generation
bump (`shouldProcessUpdate`, `webhook/controller.go:1368-1378`).

**Verify it is observing and not enforcing.**

```bash
norviq audit list -n chatbot-prod -d audit --range 1h
# rule_id column shows policy_audit_would_block:tool_not_allowlisted
```

### The two other ways to not enforce, and when each is right

| Mechanism | Scope | Traffic | Use when |
|---|---|---|---|
| `spec.enforcementMode: audit` | one policy, only when it wins | live | trialling one new policy against real traffic |
| `PUT /api/v1/settings?namespace=<ns>` with `{"enforcement_mode":"audit"}` | every layer in the namespace | live | validating a batch of changes; `rule_id` prefix is `monitor_would_block:` (`_apply_posture`, `evaluator.py:761-779`) |
| `POST /api/v1/policies/dry-run` (wrapped by `norviq policy dry-run -f p.rego -n <ns> -c <class>`) | nothing — the policy is never stored | replay of up to 500 real audit records from the last 24h, **without** `derived`/`mcp`/`direction` (§0) | a tool-name or param-content rule, before you apply it; it is the only one that reports decision **flips** — but `newly_blocked` / `newly_allowed` are in the endpoint's JSON only, not in the CLI's four printed lines (Recipe 1) |

`PUT /api/v1/settings` also takes `{"apply_mode":"dry_run_only"}`, which makes the API refuse policy
*applies* for that namespace entirely — drafts and dry-runs still work. That is the harder gate for a
namespace that must never auto-enforce.

---

## 8. Troubleshooting: what "it did not work" actually means

Run these in order. Each one eliminates a distinct failure.

```bash
# 1. Did the CR reach the API at all?
kubectl get nrvqpolicy -n <ns>
kubectl describe nrvqpolicy -n <ns> <name>     # status.message — see below
```

`status.message` names the rejection **only for the checks the controller does itself** (bad rego, bad
target, bad `clusterPriority`, missing preset — it writes `err.Error()` verbatim). When the API is the
one that refused, `syncPolicy` returns `unexpected response status %d` (`controller.go:1499`) and that
is all the CR gets: the API's `detail` string never reaches `status.message`. Step 2 is where you read
it back.

`Phase: Active` means the last sync succeeded and nothing more. `Blocks-24h` is always `0` — it is
hardcoded, not measured (`webhook/controller.go:799-805`).

```bash
# 2. What did the controller say?
kubectl logs -n norviq deploy/norviq-webhook | grep NRVQ-WHK-40
```

| Code | Meaning |
|---|---|
| `NRVQ-WHK-4026` | synced successfully |
| `NRVQ-WHK-4025` | the sync to the API did not succeed — usually a non-2xx, whose code the status line carries (`422` is almost always the validator gap in §0); also covers a transport failure or an unbuildable payload |
| `NRVQ-WHK-4032` | rego rejected by the controller before it ever left the pod |
| `NRVQ-WHK-4029` | `spec.preset` names a file not in this image (`/app/presets`) |
| `NRVQ-WHK-4034` | cross-namespace target refused |
| `NRVQ-WHK-4037` | `clusterPriority` outside `500-1000`, or used outside the release namespace |
| `NRVQ-WHK-4059` | the 60s retry sweep is re-driving a policy stuck in `Error`/`Pending` |
| `NRVQ-WHK-4061` | a preset's content changed under an unchanged CR; re-syncing |

A failure the **controller** decided (bad rego, bad target, bad `clusterPriority`, missing preset) is
recorded against the CR's generation and *not* retried until the spec changes
(`markDeterministicFailure`, `webhook/controller.go:522-530`, called at `:575`, `:582`, `:589`, `:596`)
— one loud log line and then silence.

An **API** refusal is not marked that way. The sync runs in a goroutine and its failure path
(`controller.go:615-617`) only logs `NRVQ-WHK-4025` and writes `Phase: Error`, so the 60s sweep re-drives
it on every tick: expect `NRVQ-WHK-4059` followed by `NRVQ-WHK-4025` repeating forever, at 422 after 422,
with the old rego still enforcing throughout. Repetition here is a symptom, not progress — a `422` never
self-heals. Edit the CR.

```bash
# 3. Which key did it land on?  This is the §0 trap.
norviq policy list
norviq policy get <ns> <key>
```

If your policy is listed under `<ns>:<metadata.name>` rather than `<ns>:<agentClass>` or
`<ns>:__baseline__`, it is stored but unreachable. Re-read §0.

```bash
# 4. Which layers are in play for this caller at all?
curl -s -H "Authorization: Bearer $TOKEN" \
  "$API/api/v1/policies/effective?namespace=<ns>&agent_class=<class>"
```

This calls the same `_collect_candidates` enforcement uses (`policies.py:367-412`), so the *membership*
of `layers[]` cannot drift from real behaviour. If your scope is not in it, no amount of Rego will help.
It does not tell you who wins: `layers[]` comes back in collection order, and precedence is applied
afterwards by `_resolve_precedence` / `_resolve_with_packs` from each entry's `priority` and `overlay`
fields. Read those two fields, then step 5.

```bash
# 5. Is another layer winning?
```

Base tiers resolve highest-priority-wins, ties to most-restrictive (`_resolve_precedence`,
`evaluator.py:2149-2158`); overlays are then combined most-restrictive-wins and can only tighten
(`_resolve_with_packs`, `evaluator.py:2059-2082`). A class policy at `200` beats a namespace baseline at
`1` even when the baseline is stricter.

### Capacity limits you can hit

- **100 `NrvqPolicy` objects per namespace** when that namespace is listed in `policyQuotaNamespaces`
  (`helm/norviq/templates/resource-quota.yaml`). Exceeding it fails `kubectl apply`.
- **200 distinct policy scopes per namespace** at the API (`policy_scope_cap_per_namespace`,
  `policies.py:490-500`), answered with `429`. Only a genuinely new scope counts; updating an existing
  one never grows it.
- On a **fresh install**, `kubectl apply` of an `NrvqPolicy` can fail with
  `is forbidden: status unknown for quota: norviq-crd-quota` for up to ~4 minutes while Kubernetes'
  quota controller computes usage for the brand-new resource type. Re-apply; nothing is misconfigured.

---

## 9. Where to go next

- **[Writing Policies](writing-policies.md)** — the full Rego contract, the positive-security intent
  generator, tighten-only overlays, dry-run and the red-team suite.
- **`policies/templates/`** — `mcp_integration_guardrail.rego` and `tool_allowlist.rego` are the
  namespace-wide `__guardrail__` overlays these recipes' class-scoped versions are derived from. Load
  them through `POST /api/v1/policies`, not through a CR.
- **`policies/sector/<sector>/*.rego`** — finance, healthcare, government, energy, telecom, ecommerce,
  erp-crm, media-entertainment. Enable the matching pack (`POST /api/v1/policy-packs/{id}/enable`)
  before hand-writing a rule that already exists there.
- **`comprehensive.rego`** — the reference implementation of the partial-set + resolver idiom every
  multi-rule recipe here copies (resolver tail at `comprehensive.rego:765-817`).
- **[Configuration](../configuration.md)** — `baselineClusterPolicy`, `policyQuotaNamespaces`, and the
  install-blocking guards around them.
