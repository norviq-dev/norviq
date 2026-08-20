<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Norviq Contributors -->

# Governing MCP traffic

Model Context Protocol is a wire protocol for tool calls, and Norviq is a policy enforcement point
for tool calls — so the MCP surface is a **protocol adapter, not a second engine**. An
`mcp/tools/call` maps 1:1 onto the `ToolCallEvent` the SDK and the injected sidecar already produce
(`norviq/mcp/__init__.py:10-16`), reaches the same `POST /api/v1/evaluate`, and is adjudicated by the
same policy. A rule you wrote for a LangChain agent applies to an MCP tool of the same name with no
changes.

What MCP adds is a *definition* plane the SDK path does not have. An MCP server tells the model what
its tools are, in prose the model reads as authoritative, and it can change that prose after you
approved it. Norviq splits enforcement accordingly:

| | Gate A — discovery | Gate B — invocation |
|---|---|---|
| Runs on | `tools/list` and its siblings, prompt templates, notifications | `tools/call`, `resources/read`, `sampling/createMessage` |
| Frequency | a handful of times per session | every call |
| Cost | scan + hash + pin comparison | one `/evaluate` round trip |
| Decided by | the proxy, from config — **policy is never consulted** | policy, after five proxy-side checks |
| Nature | heuristic, evadable by construction | deterministic backstop |

Gate A never runs on the Gate B path: a `tools/call` costs one dict lookup against a catalog built at
discovery (`norviq/mcp/firewall.py:203-257`). That separation is the reason it is affordable to put
Gate-A state in front of every policy decision.

If you have not read [Writing Policies](writing-policies.md), do that first — everything in §5 below
assumes the Rego contract it describes.

---

## 1. Placement

There are two transports and one identity story.

**stdio.** A stdio MCP server is a *child process* of its client. There is no socket, so there is
nothing for a gateway to sit in front of; the only faithful interception point is to *be* the child
(`norviq/mcp/stdio.py:5-15`).

```bash
python -m norviq.mcp --server-id filesystem -- npx -y @modelcontextprotocol/server-filesystem /work
```

**Streamable HTTP.** Fronts a remote MCP endpoint. Still deployed as a sidecar in the agent's pod,
not as a shared gateway — a shared gateway would have to attest callers over the network, which is a
different and larger design (`norviq/mcp/http.py:22-26`).

```bash
python -m norviq.mcp --http --listen 127.0.0.1:9000 --upstream https://mcp.example.com/mcp
```

There is no `norviq-mcp` console script; `python -m norviq.mcp` is the entry point
(`norviq/mcp/__main__.py`). `--server-id` defaults to the basename of the upstream command on stdio
and to the literal `upstream` on HTTP — set it explicitly, because it keys the definition pins.
`--tool-name-prefix` is off by default and should stay off unless you run several servers whose
policies must tell two identically-named tools apart: prefixing breaks the 1:1 mapping onto
`input.tool_name`, so every existing rule written against the bare name stops matching.

**Identity comes from the SVID, never from an MCP message.** MCP carries no principal at all. The
proxy runs in the same pod, same uid and network namespace as the agent that spawned it, so its
SPIFFE SVID *is* that workload's identity — and `/api/v1/evaluate` re-binds every
enforcement-selecting field to the caller's own credential anyway, so a proxy that lied would have
its claim overwritten (`norviq/mcp/stdio.py:17-32`).

### In Kubernetes

Injection is annotation-driven and **off by default** (`helm/norviq/values.yaml:337-338`). Build and
push the proxy payload first, then enable it:

```bash
docker build -f scripts/mcp-proxy-payload.Dockerfile -t <registry>/norviq-mcp-payload:0.2.0 .

# Prove the frozen payload starts in the images your MCP servers actually use. The argument list is
# those TARGET images, not the payload — the script builds and copies the payload itself, then execs
# it with the mount read-only, the way an injected container does.
scripts/mcp-proxy-payload-verify.sh node:22-bookworm python:3.12-slim

helm upgrade norviq oci://ghcr.io/norviq-dev/charts/norviq --version 0.2.4 -n norviq \
  --set webhook.injection.enabled=true \
  --set webhook.injection.mcp.enabled=true \
  --set webhook.injection.mcp.proxyImage=<registry>/norviq-mcp-payload:0.2.0
```

```yaml
metadata:
  annotations:
    norviq.io/mcp-servers: "filesystem,github"      # containers whose command IS an MCP server
    norviq.io/mcp-server-id.github: "github-prod"   # optional stable pin id (default: container name)
```

The injector rewrites each named container's `command` to exec the proxy and adds an init container
that copies the proxy in, so the upstream image needs nothing installed
(`webhook/mcp_injector.go:163-168, 240-268`). `proxyImage` is **required with no fallback** — it must
carry the relocatable payload built by `scripts/mcp-proxy-payload.Dockerfile`; the engine image does
not (`webhook/mcp_injector.go:61-68`).

`mcp-proxy-payload-verify.sh` is no longer byte-identical to what the injector emits: it stages the
payload at the mount root and execs `/norviq/mcp/norviq-mcp`, while the injector copies into a `bin/`
subdirectory and execs `/norviq/mcp/bin/norviq-mcp` (`webhook/mcp_injector.go:44-45, 251-252`). It
still answers the question it exists for — does this frozen payload start under that image's libc —
but it does not verify the injected argv.

### The two labels the Helm flags do not grant

**Enabling MCP injection is not enough to get a pod injected.** The annotation is only read on a pod
the admission webhook actually routes, and routing is a separate opt-in:

- the namespace must carry `norviq-injection=enabled` — the `MutatingWebhookConfiguration`'s
  `namespaceSelector` (`helm/norviq/templates/webhook-config.yaml:50-57`);
- **and**, under the shipped default `gateOnlyAgentPods: true` (`helm/norviq/values.yaml:429`), the
  pod itself must carry `norviq.io/agent-class` — the `objectSelector`
  (`helm/norviq/templates/webhook-config.yaml:78-81`).

A pod missing either label is never sent to the injector, so its `norviq.io/mcp-servers` annotation is
never read, no proxy is wrapped around the MCP server, and that server runs ungoverned. This failure
is silent in the direction that matters: the pod starts normally and the annotation looks like it took
effect. `failurePolicy: Fail` does not cover it either — fail-closed applies to pods the webhook
routes, and an unlabelled pod is not one.

```bash
kubectl label ns <ns> norviq-injection=enabled
# and on the pod template, alongside the MCP annotations:
#   metadata:
#     labels:
#       norviq.io/agent-class: <class>

# After a rollout, check what is actually routed:
kubectl get pods -n <ns> -L norviq.io/agent-class     # a blank column is NOT injected
```

Two admission rules follow from "never leave a named server ungoverned", and both are **denials, not
skips** (`webhook/mcp_injector.go:89-130`):

- a name in `norviq.io/mcp-servers` that matches no container is a typo, and a typo that "worked" is
  the failure mode;
- a container with no explicit `command` cannot be wrapped, because its real argv is the image
  ENTRYPOINT and admission cannot see it.

Injection covers the **stdio** shape only. The injector emits no HTTP proxy form, so an agent that
dials a remote MCP endpoint with an in-process client library spawns nothing, has no container to
name, and gets no Gate A — deploy the `--http` driver yourself for that case.

---

## 2. Which method falls in which gate

Everything not named below is forwarded **byte-for-byte**, including future methods and vendor
extensions. Allowed messages are re-emitted from the original bytes rather than re-serialised, so key
order and anything the proxy does not model survive the hop (`norviq/mcp/protocol.py:103-127`).

### Gate B — invocation (an `/evaluate` round trip)

| Method | Direction | Gated when | Blocked how |
|---|---|---|---|
| `tools/call` | client → server | always (`firewall.py:414`) | MCP tool error (`result.isError`) for the Gate-A, schema and policy refusals; JSON-RPC error for the two malformed-input refusals (see below) |
| `resources/read` | client → server | `mcp_govern_resources` (default `true`, `firewall.py:416`) | JSON-RPC error `-32001` |
| `sampling/createMessage` | server → client | `mcp_govern_sampling` (default `true`, `firewall.py:434`) | JSON-RPC error `-32001`, returned to the **server** |
| any request carrying `params.inputResponses` | client → server | always (`firewall.py:410-413`) | JSON-RPC error `-32001` |

A `tools/call` refusal is deliberately shaped as `result.isError` rather than a JSON-RPC `error`:
several hosts treat a server-originated protocol error on a tool call as a session fault and tear the
connection down, so a targeted denial would become an outage. The block is still absolute — the
upstream server never sees the call — and the model reads "blocked by rule X" as tool output and can
route around it (`norviq/mcp/protocol.py:277-292`).

Two refusals on this same path are the exception and do travel as JSON-RPC errors: transport-header
smuggling answers `-32001` (`firewall.py:744-751`) and a `params.arguments` that is not an object
answers `-32600` (`firewall.py:758-762`). The reasoning above applies to those two no less than to a
policy block, so a host that tears the session down on a server-originated error will do so for them.
Read it as an inconsistency in the shipped code rather than as a deliberate distinction.

The last row is the **answer plane** (2026-07-28 Multi Round-Trip Requests). A server may answer a
call with `resultType: "input_required"` and a list of questions; the client retries with
`inputResponses` attached. That retry is data leaving the trust boundary in reply to a question the
*server* composed, so it is adjudicated as egress with `surface: "answer"` first, and then falls
through to the ordinary call gate — one message, two decisions.

### Gate A — discovery (scan, pin, rewrite; no `/evaluate`)

| Surface | Direction | Action on a finding |
|---|---|---|
| `tools/list` result | server → client | per tool: pass / sanitize / **strip** (`firewall.py:946-1064`) |
| `resources/list`, `resources/templates/list`, `prompts/list` results | server → client | per entry: keep or **withhold**; the rest of the list still passes (`firewall.py:1119-1248`) |
| `prompts/get` result | server → client | annotate; **replace** the messages at strip severity (`firewall.py:1080-1117`) |
| `elicitation/create` | server → client (request) | annotate; **refuse** at strip severity (`firewall.py:1269-1305`) |
| `server/discover` result | server → client | annotate only — never refused (`firewall.py:1424-1444`) |
| `notifications/message`, `notifications/progress` | server → client | annotate only (`firewall.py:1307-1331`) |
| `notifications/{tools,prompts,resources}/list_changed` | server → client | mark every catalog entry stale (`firewall.py:929-944`) |
| `notifications/*` carrying a `subscriptionId` + `content` | server → client | content guard (fence + DLP) (`firewall.py:449-451`) |
| `tools/call` result | server → client | content guard, then `structuredContent` DLP (`firewall.py:1334-1382`) |
| `resources/read` result | server → client | content guard only — the `structuredContent` pass is not run here (`firewall.py:1384-1386`) |
| `tools/call` result with `resultType: "input_required"` | server → client | scan the demand, annotate only (`firewall.py:1485-1513`) |

JSON-RPC **batches are refused in both directions** (`firewall.py:392-401`). MCP removed batching in
2025-06-18, and a proxy that forwarded an array it did not inspect would let a `tools/call` ride
inside it ungoverned. A message the proxy cannot classify or decode is dropped, not forwarded — on
both transports (`firewall.py:489-492`, `http.py:296-310`).

---

## 3. What the firewall does at discovery

### 3.1 The scanner

`norviq/mcp/scanner.py` matches a fixed rule table against a **confusable skeleton** of each string —
casefolded, combining marks and zero-width/format characters stripped — so homoglyph and
mark-stacking evasion collapses before the rules run. Invisible characters are checked separately on
the *raw* text, because the skeleton can never witness them (`scanner.py:257-266`).

| Rule | Severity | Fires on |
|---|---|---|
| `mcp_a_instruction_override` | critical | "ignore/disregard/forget previous instructions" |
| `mcp_a_concealment` | critical | "do not tell the user", any wording of the same shape |
| `mcp_a_exfil_directive` | critical | "send/include … to \<url\>" or "… as the \<x\> argument" |
| `mcp_a_credential_read` | critical | names a credential location (`.ssh/`, `.env`, `api_key`, `/var/run/secrets`, …) |
| `mcp_a_concealment_bare` | high | `silently`, `covertly`, `without the user` |
| `mcp_a_hidden_marker` | high | `<IMPORTANT>`, `[[SYSTEM]]`, `## instructions` |
| `mcp_a_tool_precondition` | high | asserts a precondition on *other* tools |
| `mcp_a_role_impersonation` | high | a line beginning `system:` / `assistant:` |
| `mcp_a_authority_claim` | medium | imperatives at the model ("you must", "always call this") |
| `mcp_a_invisible_characters` | high | zero-width / bidi / Unicode tag characters |
| `mcp_a_name_not_plain` | high | a tool name outside `[A-Za-z0-9_.-]` |
| `mcp_a_name_shadowing` | critical | a name that folds onto an already-registered tool |
| `mcp_a_unclassifiable_item` | high | a listing entry that is not an object |
| `mcp_a_oversized_field` | medium | a field past 16 KiB (truncated for analysis) |
| `mcp_a_scan_budget_exhausted` | medium | text the scanner meant to read went unread |
| `mcp_a_scan_truncated` | medium (low on a tool definition) | the structure walk hit a bound |
| `mcp_a_oversized_description` | low | a description past 2 KiB |

`mcp_a_credential_read` is **demoted to medium** on the `description`/`title` of a resource, template
or prompt entry, and only there: in a tool description "read `~/.ssh/id_rsa`" is the payload, but in a
catalogue entry's prose it is usually the subject ("How to configure your API key"). It keeps full
severity on `uri`/`uriTemplate`/`name`, where it is the address *of* a secret rather than prose about
one (`scanner.py:534-540`).

Every bound is **reported, never silent**. One `tools/list` response gets a shared 512 KiB scan budget
(`firewall.py:80`), one message 64 KiB (`scanner.py:212`), one field 16 KiB, and the structure walk
stops at 512 strings / 512 members per node / 12 levels deep. Exhausting any of them raises a finding
and sets `budget_exhausted`, and on `tools/list` a definition the budget could not read is **stripped
rather than sanitised** — a walk that stopped early must not produce the same report as a walk that
found nothing (`firewall.py:992-1000`).

### 3.2 Severity → action

`_action_for` (`firewall.py:1066-1078`) maps (scan severity, pin status) onto one of three actions:

| Action | What the model receives | Can the tool still be called? |
|---|---|---|
| `pass` | the definition unchanged | yes |
| `sanitize` | the tool, with its `description` replaced by a stub and `annotations` dropped | yes |
| `strip` | nothing — the entry is removed from `tools/list` | **no** (see §4) |

Defaults, both set in `norviq/config.py`:

- `mcp_scan_strip_severity: "high"` (line 203) — a definition scanning `high` or `critical` is removed.
- `mcp_scan_sanitize_severity: "medium"` (line 204) — a `medium` definition is listed with its prose withheld.

Two cases outrank severity entirely: a pin status of `drift` or `quarantined` is always `strip`,
because the *fact* of the change is the finding regardless of how innocent the new text scans; and a
budget-exhausted definition is `strip` for the reason above.

Sanitising leaves `inputSchema` in place, whose `description` and `default` values reach the model
exactly as prose does — which is why the threshold for withholding is set where it is, and why the
name-charset rule is graded `high`. A sanitised homoglyph twin is still listed, still visually
identical to its target, and still selectable (`scanner.py:433-439`).

### 3.3 Homoglyph and shadowing detection

Two independent mechanisms:

- **Charset** (`mcp_a_name_not_plain`, high): every real MCP server draws tool names from
  `[A-Za-z0-9_.-]`, so an out-of-charset character has no legitimate use and one attack use.
  Charset-based rather than skeleton-based on purpose, so it fires on confusables the fold table
  happens not to cover. Applied to `tools/list` names and to `prompts/list` names — a prompt is
  addressed by name — but **not** to `resources/list` names, which are display strings addressed by
  `uri` (`scanner.py:519-532`).
- **Cross-catalog collision** (`mcp_a_name_shadowing`, critical): `send_email` and `send_emaiI` fold
  to the same skeleton and are indistinguishable to a model reading a list. Only detectable with the
  whole catalog in hand, so it lives in the firewall rather than the scanner
  (`firewall.py:979-988, 1627-1632`).

**`server_id` is not folded.** Confusables cover tool names only, so `pоstgres-prod` (Cyrillic о) is a
distinct pin row from `postgres-prod` rather than a detected collision. It is resolved at
registration — the console marks non-ASCII names on both tool and server ids
(`ui/src/pages/McpServers.tsx:104-121`) — not at call time.

### 3.4 Content-hash pinning

The digest covers only the fields that can influence the model or the call —
`name`, `title`, `description`, `inputSchema`, `outputSchema`, `annotations`
(`norviq/mcp/pins.py:68`) — and deliberately excludes transport metadata and any `_meta`, so a server
bumping an unrelated field does not manufacture a false drift. A detector that cries wolf gets
disabled, which is worse than not having one. See §6 for the lifecycle.

### 3.5 Schema enforceability

At discovery the firewall records what its conformance checker *cannot* enforce about each declared
`inputSchema` (`firewall.py:583-634`): `$ref`, `anyOf`/`oneOf`/`allOf`, `if`/`then`, `patternProperties`
and friends are not evaluated, because resolving them means following references or running
server-supplied regexes — unbounded work on attacker-controlled input inside a fail-closed budget.
The result is published to policy as `mcp.schema_notes` and logged once at `NRVQ-MCP-5070`. Nothing is
checked against the arguments here; that happens at Gate B (§4).

### 3.6 Default posture at a glance

| Control | Setting (`config.py`) | Default | Notes |
|---|---|---|---|
| `tools/list` scan + pin | — | **always on** | not gated by `mcp_scan_responses` (`firewall.py:946-955`) |
| Scan server-returned content and non-tool discovery lists | `mcp_scan_responses` (207) | `true` | off skips `prompts/get`, the three item lists, `elicitation/create`, the free-text notifications and the result injection scan — but **not** the whole response path: `server/discover` (`firewall.py:1424-1444`) and the `input_required` demand scan (`firewall.py:1485-1513`) do not consult it, and masking is governed separately by `mcp_output_dlp_enabled` (`firewall.py:1518-1521`) |
| Content-hash pinning mode | `mcp_pin_mode` (191) | `tofu` | `strict` quarantines first sight |
| Pin durability | `mcp_pin_store` (192) | `memory` | the chart sets `control-plane` (`values.yaml:349`) |
| Strip threshold | `mcp_scan_strip_severity` (203) | `high` | |
| Sanitize threshold | `mcp_scan_sanitize_severity` (204) | `medium` | |
| Schema conformance at Gate B | `mcp_enforce_schema` (227) | `true` | enforces the *server's own* declaration |
| Output DLP on results | `mcp_output_dlp_enabled` (188) | `true` | defaults on here and off in the SDK — an MCP result is pasted straight into the model's context |
| Govern `resources/read` | `mcp_govern_resources` (217) | `true` | |
| Govern `sampling/createMessage` | `mcp_govern_sampling` (209) | `true` | |
| Allow tool params to set HTTP headers | `mcp_allow_tool_headers` (215) | **`false`** | opt-in; see §4 |

Every one of these is read from the **proxy process's own environment** (`NRVQ_MCP_*`, prefix set at
`config.py:49`), not from the control plane. `PUT /api/v1/settings` does not reach them and the
console cannot display them — which is why the MCP Servers page states the shipped default explicitly
rather than claiming to know your threshold (`ui/src/pages/McpServers.tsx:243-253`).

---

## 4. What the proxy enforces before policy is consulted

This is the distinction that determines what you can change with a rule. A `tools/call` passes five
proxy-side checks *before* `/evaluate` is reached (`firewall.py:735-842`; check 1 sits one level up,
in `on_client_message` at `firewall.py:392-401`), in this order:

| # | Check | Refuses when | Turned off by |
|---|---|---|---|
| 1 | JSON-RPC batch | the message is an array | nothing |
| 2 | Transport-header smuggling | any argument at any depth is named `x-mcp-header` | `mcp_allow_tool_headers=true` |
| 3 | Malformed `arguments` | `params.arguments` is present and not an object | nothing |
| 4 | **Gate-A carry-over** | the tool's pin status is `drift` or `quarantined`, **or** its discovery action was `strip` | nothing (change the thresholds, or approve the pin) |
| 5 | **Schema conformance** | a missing `required` argument, a wrong-typed value, or — when the server set `additionalProperties: false` — an argument the tool never declared | `mcp_enforce_schema=false` |
| 6 | Policy | `data.<package>.decision` is not an allow | this is where your rules live |

Check 5 runs before the evaluation on purpose. An argument the tool never declared is one no policy
mentions either, so evaluating first would produce an `allow` meaning "no rule objected to a field
nobody knew about" — true and useless. Refusing first keeps the allow honest: every argument that
reaches policy is one the server admits to. It is a **deliberate subset** of JSON Schema, not a
validator (`firewall.py:636-666`). It runs only when the tool has a catalog entry *and* that entry
carries a published `inputSchema` (`firewall.py:793`), so an observed-only tool and a tool the proxy
never scanned are both unaffected either way.

At discovery, **policy is not consulted at all**. Strip and sanitize are proxy decisions taken from
`mcp_scan_strip_severity` / `mcp_scan_sanitize_severity` in the microseconds before a `tools/list`
response is forwarded. There is no rule that un-strips a tool, and no rule that makes the firewall
withhold one it passed — those are configuration changes and pin approvals, not policy.

### The reachability consequence

Because check 4 fires before check 6, several `input.mcp` values **cannot be observed by a policy on
the ordinary `tools/call` path**:

- `pin_status == "drift"` and `pin_status == "quarantined"` — the call is already refused
  (`CatalogEntry.call_denied`, `firewall.py:248-257`).
- `scan_severity == "high"` and `scan_severity == "critical"` at the default strip threshold — the
  same short circuit, because those grades produce `action == "strip"`.

So the shipped guardrail's first three rules (§7) are **defence in depth for events that reach
`/evaluate` by a route other than the call gate** — the answer plane (which evaluates *before* the
call gate, `firewall.py:410-415`, so it does see a drifted tool's status), red-team traffic, which
synthesises its own MCP document, and any caller that reaches `/evaluate` directly. They are not the
mechanism that stops a drifted tool on the call path. The proxy is that mechanism.

To make a severity rule live on the call path, either lower what the policy blocks on (add `"medium"`
to `blocking_scan_severity`, which is reachable because a `medium` definition is sanitised and stays
callable), or raise `mcp_scan_strip_severity` to `critical` so a `high` definition reaches policy
instead of being withheld. Pick one deliberately; doing both means nothing is withheld and nothing is
blocked.

---

## 5. The facts `input.mcp` publishes

Built by `_mcp_context` (`firewall.py:495-543`) from values computed at discovery and cached, so
assembling it is a dict lookup plus a literal — that is what makes it affordable on every call. The
evaluator publishes it as `input.mcp`, and lifts `input.direction` out of it, for MCP callers only;
for every other caller `input.mcp` is `{}` and `input.direction` is `"call"`
(`norviq/engine/evaluator.py:967-984`).

| Fact | Values | Meaning |
|---|---|---|
| `mcp.server` | the `--server-id` string | which integration served this tool |
| `mcp.transport` | `stdio` \| `http` | see the caveat below |
| `mcp.surface` | `tools/call`, `resources/read`, `sampling/createMessage`, `answer` | which RPC produced this decision |
| `mcp.direction` | `call` \| `answer` | also lifted to `input.direction` |
| `mcp.pin_status` | `pinned`, `first_seen`, `drift`, `quarantined`, `unknown` | approval state of the definition |
| `mcp.scan_severity` | `none`, `low`, `medium`, `high`, `critical`, `unknown` | worst Gate-A finding on the definition |
| `mcp.definition_seen` | bool | whether this tool was in the catalog the proxy scanned |
| `mcp.catalog_stale` | bool | the server announced a change not yet re-read |
| `mcp.schema_enforced` | bool | a schema was declared **and** the checker could apply all of what it understands |
| `mcp.schema_closed` | bool | the server declared `additionalProperties: false` |
| `mcp.schema_notes` | list of strings | what conformance could not enforce, in plain words |
| `mcp.tool_digest` | 16 hex chars | first half of the definition digest; absent when there is no catalog entry |

`pin_status` and `scan_severity` report **`unknown`, not `none`**, for a tool with no catalog entry.
That is deliberate: `none` is what a definition that *was* scanned and came back clean carries, so
reporting it for a tool nobody looked at would spell "I never looked" exactly like "I looked and it
was fine". `unknown` is outside the severity vocabulary, so it satisfies no allow list and no
high/critical block — an operator who wants to admit unscanned tools must now say so
(`firewall.py:508-525`).

Two honest caveats about this table:

- **`catalog_stale` is `false` when there is no catalog entry** (`firewall.py:526`) — the signal is
  inverted for the most suspicious case. Use `definition_seen` for "was this ever scanned"; use
  `catalog_stale` only to mean "the entry I have may be out of date".
- **`transport` reports `stdio` on the HTTP driver.** `HttpProxy` constructs its `McpFirewall`
  without passing `transport=` (`http.py:173-179`), so the constructor default applies
  (`firewall.py:339`). The control-plane pin rows record the transport correctly
  (`pins.py:340-347`), so the console is right and the policy fact is not. Do not write a rule that
  branches on `input.mcp.transport` until this is fixed.

### Trust level

`input.mcp` is **PEP-reported, exactly like `input.tool_name` and `input.tool_params`**. It is a
policy input and never a trust input. A compromised proxy that can forge `mcp.pin_status` can equally
forge the tool name, or decline to report the call at all, and a caller that can reach `/evaluate` directly
can assert any of these fields. Identity stays bound to the caller's attested credential in the API
layer, and the authoritative pin state lives in the control plane's `mcp_tool_pins` table, never in
this document (`norviq/sdk/core/events.py:40-54`). **Do not use `input.mcp.server` to decide *who* is
calling — only *what* they are calling.**

### Writing a rule

Same v0 dialect and same contract as every other policy: a `default decision`, and a `rule_id` and
`reason` for every reachable decision. Gate `is_mcp` on `input.mcp.server` so the rule stays additive
and cannot change a non-MCP caller's decision.

```rego
package norviq.guardrail.mcp_unscanned

default decision = "allow"
default rule_id = "default_allow"
default reason = "Allowed"

is_mcp {
	input.mcp.server
}

# A call naming a tool that was NOT in the catalog the firewall scanned. Nothing shipped blocks this
# case, and it is the shape a poisoned-context attack produces: the model learned the name somewhere
# other than tools/list.
never_scanned {
	is_mcp
	not input.mcp.definition_seen
}

decision = "escalate" { never_scanned }
rule_id = "mcp_tool_never_scanned" { never_scanned }
reason = "this MCP tool was not in the catalog the firewall scanned at discovery" { never_scanned }
```

Other fragments worth knowing:

```rego
# First use of a tool this proxy has never pinned. Under the default `tofu` mode the proxy pins and
# allows it; `first_seen` is the only signal that it happened, and no shipped rule matches it.
first_use {
	is_mcp
	input.mcp.pin_status == "first_seen"
}

# The residual behind every per-argument constraint you write: the server did not close its argument
# set, so a caller may smuggle an argument the tool honours and your rule never mentions.
open_argument_surface {
	is_mcp
	not input.mcp.schema_closed
	input.derived.verb != "read"
}

# An allow arriving with schema notes attached is narrower than one without. The two must not be
# indistinguishable.
conformance_incomplete {
	is_mcp
	count(input.mcp.schema_notes) > 0
}
```

`input.derived.*` (verb, param values, param paths, data classes, normalised SQL) is available on the
MCP path exactly as it is everywhere else — see [Writing Policies §2](writing-policies.md).

---

## 6. The pin lifecycle

**Identity.** `pin_id = sha256(server_id + NUL + tool_name)[:32]` (`pins.py:92-94`); the approved
value is `sha256` over the canonical JSON of the six pinned fields (`pins.py:76-89`).

**First sight.** Under `tofu` (the default) the definition is pinned and allowed, and the *change* is
what gets enforced. Under `strict` it is quarantined until an operator approves it. TOFU is the
default because in a spike `strict` turns every new server into an approval workflow; `strict` is the
production-tenant posture. An unrecognised value for `NRVQ_MCP_PIN_MODE` is coerced to `strict`, so a
typo cannot silently disable the gate (`pins.py:211-215`).

**Drift.** When the served digest differs from the approved one, the pin is **not** updated:
`drift_count` is incremented, `last_digest` records what is being served now, approval stays with the
definition that was approved, and the tool is stripped from `tools/list` and refused at Gate A
(`pins.py:248-260`). Silently re-pinning would mean an attacker only has to absorb one blocked call.
The approved *canonical text* is retained specifically so the console can diff approved-versus-served
— the old definition cannot be re-fetched from a server that has already replaced it.

**Re-pinning.** `POST /api/v1/mcp/pins/approve` (admin) takes the digest **explicitly** and returns
`409` if it matches neither the approved nor the currently-served definition, so a server that changes
its definition again between the operator reading it and the click landing cannot get the new one
blessed by a click meant for the old one (`norviq/api/routers/mcp.py:284-306`). The console turns that
409 into a dialog naming all three digests rather than a generic failure
(`ui/src/pages/McpServers.tsx:407-421`).

**Revoke** withdraws approval; the tool is withheld until re-approved. **Forget**
(`DELETE /api/v1/mcp/servers/{namespace}/{server_id}`, admin, logged at `NRVQ-MCP-5045`) deletes every
pin for a server — the next `tools/list` re-pins whatever it serves at that moment, which is a
deliberate re-TOFU and destructive in the security-relevant direction.

### What survives a restart

| `mcp_pin_store` | Survives process restart | Shared across replicas | Notes |
|---|---|---|---|
| `memory` (default in `config.py:192`) | no | no | correct for a stdio proxy whose lifetime *is* the session; a restart is a free re-TOFU |
| `file` | yes | only if the path is shared storage | atomic write; a corrupt file **raises at construction** rather than degrading to "no pins" |
| `control-plane` | yes | yes | the chart's default (`values.yaml:349`); pins live in `mcp_tool_pins`, tenant-scoped, RBAC'd, audited, console-visible |

`memory` is **refused on the HTTP transport** — under a stateless protocol any request may land on any
instance, so a per-process store means replica A approves what replica B has never seen. The HTTP
driver upgrades it to `control-plane` and logs `NRVQ-MCP-5065` (`http.py:95-104`).

The control-plane store reads once at startup and then **re-reads on a timer**
(`mcp_pin_refresh_s`, default 30s, `config.py:200`). Without that refresh a running proxy holds its
startup copy for its whole lifetime, so an operator who revoked approval would see the console update
while the tool stayed listed and callable until the pod restarted (`pins.py:375-392`).

### Two verdicts, and the one that enforces is local

The verdict the proxy **acts on** is computed in-process by `PinRegistry.check` (`pins.py:221-260`),
comparing the served digest against approved digests that `ControlPlanePinStore.load()` pulled from
`GET /api/v1/mcp/pins` at startup and re-pulls on the refresh timer. So the approved digest *does*
reach the proxy: `_row_dict` ships `approved_digest` (`norviq/api/routers/mcp.py:95`) and the store
reads it into memory (`pins.py:432`).

The control plane computes its **own** verdict when the proxy reports a catalog to
`POST /api/v1/mcp/pins/observe` (`norviq/api/routers/mcp.py:154-203`). That report is sent *after*
the `tools/list` response has already been forwarded, as a background task, and its reply is never
read (`stdio.py:338-345`, `pins.py:470-476`) — so the server-side verdict is what the durable row and
the console show, not what stopped a call. The router's own module docstring
(`norviq/api/routers/mcp.py:16-22`) still describes this the other way round; the code above is
authoritative.

What does hold, and is the property that matters against a compromised proxy: **neither path adopts a
changed digest.** `observe` increments `drift_count` and leaves `approved_digest` untouched
(`norviq/api/routers/mcp.py:189-192`), and adoption is only `POST /mcp/pins/approve`, which is
admin-gated (`norviq/api/routers/mcp.py:294`). The residual is narrower than "cannot report a false
state" and worth naming: `observe` takes `mode` from the request **body**
(`norviq/api/routers/mcp.py:140`), so a proxy asserting `tofu` gets a *first-seen* tool auto-approved
in the control plane even where an operator configured `strict`. In a cluster that gap is closed at
admission — the injector requires a wrapped container's `NRVQ_MCP_PIN_MODE` to match the cluster
config (`webhook/mcp_injector.go:400-402`) — not by the API itself.

### Limits of pinning, stated plainly

- **Pin identity is the name.** Leaving `send_report` untouched and adding `send_report_v2` carrying
  the payload is not drift — it is a new tool with a fresh `first_seen` pin. `first_seen` matches no
  shipped rule; see the fragment in §5.
- **A control plane unreachable at startup degrades to per-process TOFU.** `load()` never raises; it
  sets `_degraded`, leaves the in-memory pins empty, and logs `NRVQ-MCP-5046`. For that window every
  tool reads `first_seen` and cross-pod drift detection is unavailable. Gate B is unaffected — every
  call is still evaluated and a fail-closed engine still blocks (`pins.py:403-424`).
- **The HTTP driver never reports observations.** `ControlPlanePinStore.flush()` is the only writer to
  `/mcp/pins/observe`, and only `stdio.py` calls it (`stdio.py:278-282, 343-345`); `http.py` has no
  such call. A server fronted with `--http` therefore loads approved pins but never appears in the
  console inventory, so there is nothing for approve/revoke to act on. Use the stdio placement where
  operator-visible approval matters.

---

## 7. Enabling the integration guardrail

`policies/templates/mcp_integration_guardrail.rego` is **opt-in and default-off**. Nothing about MCP
requires it: the proxy maps MCP `arguments` onto `tool_params` verbatim, so every rule you already
have applies. What it adds is the two facts only the proxy knows — `input.mcp` and `input.direction`.

Edit the two constants at the top first (`mcp_integration_guardrail.rego:40-46`):

```rego
writable_servers = {"postgres-prod", "mailer"}     # server ids that may be written through
blocking_scan_severity = {"high", "critical"}      # see the reachability note below
```

Then load it as the namespace's guardrail overlay:

```bash
norviq policy create \
  -f policies/templates/mcp_integration_guardrail.rego \
  -n chatbot-prod -c __guardrail__ --mode block
```

`__guardrail__` is a tighten-only overlay resolved as its own group and combined with the base-tier
winner by most-restrictive-wins — it can add a block to a permissive base, and can never turn a base
`block` into an `allow` ([Writing Policies §3](writing-policies.md)).

**There is one `__guardrail__` policy per namespace, and create is a full-replace upsert.** If that
namespace already carries a tool-allowlist guardrail, this load *replaces* it. Merge the two by hand
into one module rather than loading them in sequence.

The five rules, and when each is reachable:

| Rule | Decision | Reachable on the `tools/call` path? |
|---|---|---|
| `mcp_tool_not_approved` (`pin_status == "quarantined"`) | block | **no** — Gate A refuses first (§4) |
| `mcp_definition_drift` (`pin_status == "drift"`) | escalate | **no** — Gate A refuses first |
| `mcp_definition_flagged` (`scan_severity` in the set) | block | **not at defaults** — `high`/`critical` are stripped; add `"medium"` to the set, or raise `mcp_scan_strip_severity` |
| `mcp_unapproved_write_server` (`derived.verb` is neither `read` **nor** `unknown`, and the server is not in `writable_servers`) | block | **yes** |
| `mcp_answer_carries_secret` (`direction == "answer"` and a secret data class) | block | **yes** |

The fourth rule is the one a tool-name policy cannot express at all: the same tool *name* served by a
different MCP server is a different action against a different system. Note what it rests on —
`server_id` is chosen by the operator at injection time (the pod annotation, or `--server-id`), not
attested. It is a statement about your own deployment, and anyone who can create a pod in the
namespace can assert it. Note also what it deliberately excludes: `verb != "unknown"`
(`mcp_integration_guardrail.rego:133`), so a call the verb classifier cannot place — the shape an
unregistered or unusually-named tool produces — passes this rule rather than being blocked by it.

**This is a guardrail, not a perimeter.** It defaults to `allow` and blocks specific conditions, so a
tool it says nothing about falls through to your baseline. Pair it with a deny-by-default perimeter
(`policies/templates/tool-allowlist-perimeter.rego`), which is registration-based and therefore holds
against a name nobody has seen before.

`norviq redteam run --agent <class> --namespace <ns>` exercises three MCP identity attacks
(`MCP-01`–`MCP-03`, `norviq/redteam/attacks.py:113-115`). `MCP-01` is the one
`mcp_unapproved_write_server` blocks; `MCP-02` and `MCP-03` forge `input.mcp` fields and exist to
*measure* the residual described under Trust level in §5 — they are not expected to be closed by a
rule.

---

## 8. Console and API

The **MCP Servers** page (`/mcp` in the console) is the operator half of Gate A. It leads with a
server-level inventory — tools, drifted, awaiting approval, scanner findings, and a one-word `health`
roll-up where drift outranks a scan finding — then the per-tool definitions with the scanner's own
findings and evidence, an approved-versus-served diff, and Approve / Revoke / Quarantine-server /
Forget-server actions (`ui/src/pages/McpServers.tsx`). Without it the enforcement is real but
invisible: the agent quietly loses a tool and nobody knows why.

| Endpoint | Who | Purpose |
|---|---|---|
| `POST /api/v1/mcp/pins/observe` | the proxy (service credential) | report a catalog at discovery; the **server** computes the verdict |
| `GET /api/v1/mcp/pins` | any reader | every pinned tool the caller may see, with `status` and findings |
| `GET /api/v1/mcp/servers` | any reader | server-level roll-up with `health` |
| `POST /api/v1/mcp/pins/approve` | admin | adopt a named digest (409 on a digest nobody served) |
| `POST /api/v1/mcp/pins/revoke` | admin | withdraw approval |
| `DELETE /api/v1/mcp/servers/{ns}/{id}` | admin | forget every pin for a server (re-TOFU) |

The namespace on `observe` is bound to the **caller's credential**, not taken from the body, exactly
as `/evaluate` does — a service token scoped to one tenant cannot write another tenant's pins
(`norviq/api/routers/mcp.py:128-135`).

Structured logs use the `NRVQ-MCP-5xxx` range: `5020` Gate-A call denial, `5021` Gate-B block, `5031`
stripped, `5032` sanitised, `5035` output-DLP redaction, `5036` response injection flagged, `5041`
first pin, `5042` drift, `5043` approved, `5044` revoked, `5046` control plane unreachable, `5066`
schema violation, `5070` schema not fully enforceable. Latency is recorded as
`norviq_path_phase_ms{component="mcp"}` with phases `evaluate`, `call_total`, `gate_a_tools_list` and
`response_guard` (`norviq/telemetry/metrics.py:156-168`). These codes are not yet in
[Error Codes](../error-codes.md).

---

## 9. Configuration reference

All read from the **proxy process's** environment, prefix `NRVQ_`:

| Variable | Default | Effect |
|---|---|---|
| `NRVQ_MCP_PIN_MODE` | `tofu` | `tofu` pins on first sight; `strict` quarantines until approved; anything else → `strict` |
| `NRVQ_MCP_PIN_STORE` | `memory` | `memory` \| `file` \| `control-plane` (the chart sets `control-plane`) |
| `NRVQ_MCP_PIN_PATH` | `""` | file location when the store is `file` |
| `NRVQ_MCP_PIN_REFRESH_S` | `30` | how often a control-plane-backed proxy re-reads pins; `0` disables |
| `NRVQ_MCP_SCAN_STRIP_SEVERITY` | `high` | at/above this, a definition is removed from `tools/list` |
| `NRVQ_MCP_SCAN_SANITIZE_SEVERITY` | `medium` | at/above this, the description is replaced by a stub |
| `NRVQ_MCP_SCAN_RESPONSES` | `true` | scan server-returned content and the non-`tools/list` discovery surfaces |
| `NRVQ_MCP_ENFORCE_SCHEMA` | `true` | refuse a call that contradicts the tool's own `inputSchema` |
| `NRVQ_MCP_OUTPUT_DLP_ENABLED` | `true` | mask PAN/SSN in tool results and `structuredContent` |
| `NRVQ_MCP_GOVERN_RESOURCES` | `true` | evaluate `resources/read` against policy |
| `NRVQ_MCP_GOVERN_SAMPLING` | `true` | evaluate server-initiated `sampling/createMessage` |
| `NRVQ_MCP_ALLOW_TOOL_HEADERS` | `false` | permit tool parameters to set outbound HTTP headers |
| `NRVQ_MCP_MAX_PENDING_REQUESTS` | `4096` | per-direction cap on in-flight request-id bookkeeping |

Helm keys that set them on injected proxies: `webhook.injection.mcp.pinStore` and
`webhook.injection.mcp.pinMode` (`values.yaml:349-352`; wired at
`webhook/mcp_injector.go:206-215`). The injector's admission check *requires* a wrapped container's
`NRVQ_API_URL`, `NRVQ_MCP_PIN_STORE` and `NRVQ_MCP_PIN_MODE` to match the cluster config, so a pod
that swings its own Gate-A posture locally does not read as already-governed
(`webhook/mcp_injector.go:388-404`).

---

## 10. What this does not do

Gate A is a heuristic and is evadable by construction; Gate B is the deterministic backstop. Stated
individually:

- **The scanner catches shapes, not meanings.** A paraphrased instruction that avoids every pattern in
  the rule table scans `none` and is pinned. The product's own adversarial fixtures include a case
  labelled "EXPECTED TO EVADE Gate A", with the harness asserting that it does
  (`norviq/mcp/adversarial/servers.py:54-56`). Schema conformance (§4) is the deterministic half of that answer:
  a paraphrased instruction still has to produce a call carrying an argument the developer never
  declared.
- **Fencing is a request, not a control.** Flagged server-returned content is wrapped in
  `<untrusted-content>` with an instruction to treat it as data and delivered
  (`firewall.py:100-112`). That is the right default for data the agent asked for — silently returning
  nothing is indistinguishable from a broken tool — but a model that ignores the fence has defeated the
  ingest path.
- **Output DLP masks PAN and SSN only.** `mask_text` / `mask_structure_counted`
  (`norviq/engine/masking.py:14-16, 60-64`) match card-number and SSN shapes. An API key or a private
  key in a tool result is *not* redacted by this setting. Content past the 1 MiB per-response guard
  budget is fenced but neither scanned nor masked, and says so both to the model and in the log
  (`firewall.py:88-97, 1545-1589`).
- **The upstream server inherits the proxy's environment.** `asyncio.create_subprocess_exec` is called
  with no `env=` (`stdio.py:216-222`), so the wrapped MCP server process sees `NRVQ_API_TOKEN` and, under
  internal TLS, the client key material. A hostile stdio server package can read them at import time.
  Treat the MCP server image as being inside the trust boundary of the pod's Norviq credential, and
  prefer servers you build or vendor deliberately.
- **The HTTP driver relays request headers to the upstream.** `authorization` is not in `_HOP_HEADERS`
  (`http.py:55-58`), so a bearer token the agent holds reaches whatever `--upstream` names. It leaves
  before any JSON-RPC decision exists, so no gate applies to it. Norviq brokers no OAuth on the
  agent-to-server leg and has no grant inventory.
- **`resources/read` and `sampling/createMessage` are evaluated, but nothing shipped rules on them.**
  The mechanism is real — the proxy calls `_evaluate` with `surface: "resources/read"` /
  `"sampling/createMessage"` and honours a block — and no bundled policy or template contains a rule
  for either. That is a policy you write, not a control that is missing.
- **`--tool-name-prefix` double-prefixes on the answer plane.** `_gate_answer` prefixes the tool name
  and then calls `_evaluate`, which prefixes again (`firewall.py:1466-1470`, `firewall.py:545-557`).
  With the default empty prefix there is no effect; with a prefix set, answer-plane decisions carry a
  doubled `tool_name` and miss the catalog lookup. Leave the flag off until this is fixed.

---

## See also

- [Writing Policies](writing-policies.md) — the Rego contract, overlays, dry-run and red-team
- [Configuration](../configuration.md) — the Helm `values.yaml` reference
- [Security model](../security-model.md) — trust boundaries and the threat model
- [Error codes](../error-codes.md) — the `NRVQ-*` registry
