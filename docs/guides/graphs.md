<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Norviq Contributors -->

# Asset & Attack Graphs

Norviq builds two views on top of the same data. The **asset graph** is an inventory of what your
agents have actually touched: one node per agent identity, one per tool, one per data source, wired by
the calls the enforcement path recorded. The **attack graph** walks that inventory looking for chains
from an agent to something worth protecting, and joins each hop to its real allow/block history so you
can see which chains are open *today*.

The thing that makes either view worth acting on is provenance. A graph that mixes observed traffic
with assumed topology looks the same on screen but means something completely different — one is
evidence, the other is a diagram. This guide is explicit about which is which, edge type by edge type,
because the honest answer is that **agent→tool edges are observed and tool→data edges are declared from
a static map in the source tree**. Read [§1](#1-provenance-what-is-observed-and-what-is-declared)
before you use the graph to justify a control.

If you haven't read **[Concepts](../concepts.md)**, do that first — this guide assumes agent identity,
agent classes, enforcement modes and the decision model.

---

## 1. Provenance: what is observed, and what is declared

### 1.1 There is exactly one writer

The graph is written from the enforcement path and nowhere else. Every evaluated tool call queues
`_safe_record_graph` (`norviq/engine/evaluator.py:1417`), which calls
`AssetGraphBuilder.record_tool_call` with the SPIFFE id, tool name, decision, namespace and agent class
of the call that just happened (`norviq/engine/evaluator.py:1440-1456`). There is no importer, no
discovery scan, no CRD-driven inventory, and no seeding job: **a node exists because a call happened**.

That has a direct consequence. An agent that is deployed but has never made a tool call has no node in
the snapshot at all — it is synthesized separately from the policy and registry tables as a dimmed
"awaiting first tool call" node, which the API **hides unless you pass `?include_awaiting=true`**
(`graphs.py:436`, `graphs.py:480-486`; see [§11](#11-synthetic-and-awaiting-agents)). And a tool your
agent *can* call but never has is invisible. The asset graph is a record of exercise, not of grant.

### 1.2 The provenance table

| Element | Where it comes from | Observed or declared |
|---|---|---|
| `agent` node | `record_tool_call` on the first evaluated call for that SPIFFE id | **Observed** |
| `tool` node | `record_tool_call`, from `event.tool_name` | **Observed** |
| `data` node | `TOOL_DATA_MAP` in `norviq/engine/graph/asset_graph.py:35-44` — a static dict of 8 tool names → data URIs | **Declared** (hard-coded) |
| `calls` edge (agent→tool) | `_upsert_call_edge`, one per observed call | **Observed** |
| `accesses` edge (tool→data) | `_record_mapped_data` → `record_data_access`, driven by the same static map (`asset_graph.py:170-173`) | **Declared** (hard-coded) |
| `belongs_to` edge | Synthesized in the read model when one SPIFFE id hosts several agent classes (`norviq/api/routers/graphs.py:217-226`) | Structural |
| `delegates` edge | `record_delegation` exists (`asset_graph.py:175-182`) but **has no production caller** | Never present |
| Edge `decision_history` | Joined at read time from `audit_log`, grouped by `(agent_id, tool_name)` over the requested range (`graphs.py:130-161`) | **Observed** |
| Node `risk_level` (tools) | `TOOL_RISK_MAP` (`asset_graph.py:17-33`); unknown tools default to `medium` | **Declared** (static table) |
| Node `sensitivity` (data) | `add_data(..., sensitivity="medium")` default — **nothing ever passes another value** (`asset_graph.py:110`) | Constant |
| Node `trust_score` (agents) | `add_agent(..., trust_score=0.8)` default — **never updated after node creation** (`asset_graph.py:61`) | Constant |

### 1.3 The tool→data map is the load-bearing caveat

Data nodes and `accesses` edges are produced by exactly one thing: a lookup of the tool name in
`TOOL_DATA_MAP`. The shipped map covers eight tool names:

```python
# norviq/engine/graph/asset_graph.py:35-44
TOOL_DATA_MAP: dict[str, list[str]] = {
    "execute_sql":   ["postgresql/users", "postgresql/orders", "postgresql/payments"],
    "get_customer":  ["postgresql/customers"],
    "search_kb":     ["elasticsearch/knowledge_base"],
    "send_email":    ["smtp/outbound"],
    "read_file":     ["filesystem/uploads"],
    "get_order":     ["postgresql/orders"],
    "update_record": ["postgresql/users", "postgresql/orders"],
    "delete_record": ["postgresql/users", "postgresql/orders"],
}
```

So:

- If your agents call tools with these exact names, you get data nodes — **and the target URIs are the
  ones in that table, not your real databases**. `postgresql/users` is a label from the source tree; it
  is not evidence that the call reached a table called `users`.
- If your agents call anything else — `crm_lookup`, `aws_s3_delete`, `slack_post_message` — **no data
  node is created and no `accesses` edge exists**. Kill chains for those agents terminate at the tool
  (the walk treats a node with no outgoing edges as terminal, `norviq/api/routers/threats.py:240-242`),
  and the source-capability panel ([§8](#8-source-capability-and-defend)) has nothing to classify.
- Norviq has no mechanism today for declaring your own tool→data topology. There is no CRD field, no
  Helm key and no API for it. The map is edited in the source tree or not at all.

**What to take from the graph, then.** The agent→tool layer, its call counts and its decision history
are real evidence about your estate and can be used to justify a policy. The tool→data layer is a
demonstration topology: treat a data node as a *category label for the tool's sink class*, not as a
verified reachability claim about your infrastructure. Where a chain's severity depends on its data
terminal ([§6.3](#63-severity)), that severity inherits the same caveat.

---

## 2. Nodes

Three node types (`NodeType` in `norviq/engine/graph/models.py:12-17`), keyed as follows:

| Type | Node id | Display name | Properties written at creation |
|---|---|---|---|
| `agent` | the SPIFFE id, e.g. `spiffe://norviq/ns/support-bot/sa/support-sa` | `agent_class`, else the last SVID segment | `agent_class`, `agent_classes[]`, `trust_score` (0.8), `trust_category` |
| `tool` | `tool:<tool_name>` | the tool name | `risk_level` (from `TOOL_RISK_MAP`, default `medium`), `call_count` |
| `data` | `data:<data_uri>` | the data URI, e.g. `postgresql/orders` | `data_type` (`database`), `sensitivity` (`medium`) |

Agent nodes are keyed by **SPIFFE id**, not by agent class. One service account running two agent
classes is one node in the builder; the read model expands it into a parent identity node plus one
sub-node per class, joined by `belongs_to` edges, so distinct chatbots never silently collapse into one
dot (`norviq/api/routers/graphs.py:192-227`). The layout that avoids this entirely — one namespace or
service account per chatbot — is in
**[docs/onboarding-asset-graph.md](../onboarding-asset-graph.md)**.

Two node properties look like signal and are not:

- **`trust_score` is pinned at `0.8`.** `add_agent` takes a `trust_score` parameter with a default of
  `0.8` (`asset_graph.py:61`) and its only production caller — `_ensure_tool_call_nodes` — never passes
  one (`asset_graph.py:132-139`). Nothing rewrites it afterwards. The live per-agent trust score exists, but
  it lives in the trust engine and cache, not on the graph node. Every "Min trust" figure on the Attack
  Graph inspector therefore reads `0.80`, and the graph's own low-trust analytics
  (`find_critical_paths`'s `min_trust < 0.4` filter, `get_summary`'s `low_trust_agents`, both in
  `norviq/engine/graph/attack_graph.py`) can never fire.
- **`sensitivity` is pinned at `medium`.** `add_data` accepts a sensitivity but only ever runs through
  `record_data_access`'s default. `AttackGraphEngine.compute_blast_radius`'s `critical_data` list
  (`engine/graph/attack_graph.py:36`) is consequently always empty. The console does not rely on this
  field — its kill chains treat *every* data node as sensitive
  (`threats.py:179-183`) — but any tooling you write against `sensitivity` will read a constant.

---

## 3. Edges

| Type | Direction | Written by | Properties |
|---|---|---|---|
| `calls` | agent → tool | `_upsert_call_edge` (`asset_graph.py:144-163`) | `call_count`, `last_decision`, `last_timestamp`, plus `decision_history` added at read time |
| `accesses` | tool → data | `record_data_access` (`asset_graph.py:184-195`), only via the static map | `access_type` (always `"read"`), plus `verb` added at read time |
| `belongs_to` | class sub-node → identity | read model only (`graphs.py:217-226`) | `namespace` |
| `delegates` | agent → agent | no production caller | — |

The `weight` field on the API response is always `1.0`: `GraphEdge` defaults it and nothing sets it
(`models.py:55`, `graphs.py:260`). Volume lives in `properties.call_count` and, more usefully, in
`properties.decision_history`.

`accesses` edges are written once and never updated (`asset_graph.py:192-193` returns early if the edge
exists), so their `access_type` says nothing about the operation. The real operation is resolved at read
time from the capability registry and attached as `properties.verb`
(`graphs.py:367-368`) — see [§8](#8-source-capability-and-defend).

### Decision history is joined, not stored

The builder's `last_decision` is one value. The counts an operator reads come from a separate query
against `audit_log`, grouped by `(agent_id, tool_name)` over the selected range
(`graphs.py:130-161`):

```sql
SELECT agent_id, tool_name,
    COUNT(*) FILTER (WHERE decision = 'allow')    AS allow_count,
    COUNT(*) FILTER (WHERE decision = 'block')    AS block_count,
    COUNT(*) FILTER (WHERE decision = 'escalate') AS escalate_count,
    COUNT(*) FILTER (WHERE decision = 'audit')    AS would_block_count
FROM audit_log
WHERE namespace = :ns AND timestamp_utc >= :since
GROUP BY agent_id, tool_name
```

`audit_log.agent_id` is the SPIFFE id (`norviq/api/audit_hub.py:63`), which is why the join lands on the
`calls` edge's source. The `audit` bucket is a **Monitor-mode would-block**: the evaluator softens
`block`/`escalate` to `audit` when a namespace is in Monitor mode, so surfacing it as `would_block` is
what stops a Monitor namespace's graph from looking inert.

Two consequences worth knowing:

- The window matters. Ranges are `1h`, `6h`, `24h`, `7d`, `30d` (`RANGE_HOURS`, `graphs.py:30`);
  anything else silently falls back to 24h. A node persists in the snapshot forever, so an edge whose
  traffic is all older than the window renders with zero counts — present in the topology, silent in
  the history.
- Counts are per **identity**, not per class. Two agent classes on one service account share one
  `calls` edge and therefore one set of counts.

---

## 4. Persistence, snapshots and restore

`GraphStore` (`norviq/engine/graph/store.py`) writes both a cache copy and a database row on every save:

- **Redis**: key `graph:<namespace>`, TTL **300 s** (`store.py:47`).
- **PostgreSQL**: a new row in `asset_graph` — `namespace`, `node_count`, `edge_count`, `graph_json`
  (JSONB), `built_at` (`norviq/api/db/models.py:222-232`).

A row is written **per evaluated tool call**, because `_safe_record_graph` saves after each record. Every
reader takes only the newest row per namespace (`DISTINCT ON (namespace) … ORDER BY namespace, built_at
DESC`, `graphs.py:80-83`), so the older rows are history for restore and debugging, and they are what the
retention sweep prunes ([§13](#13-retention-and-pruning)).

Snapshots are also what survives a restart. On the first record for a namespace after process start,
`_restore_graph` loads the persisted snapshot into the live in-memory builder
(`evaluator.py:1422-1438`). Without it, a pod restart would begin from an empty graph and the next save
would overwrite the accumulated snapshot with a single call — the graph would silently lose everything
built before the restart.

Saving also invalidates the per-namespace analysis cache (`store.py:39-42`), which is what keeps the
cached analyses in [§5.3](#53-the-graph-analysis-family) consistent with the graph they were computed
from.

### Removing a node

The graph is append-only apart from LRU eviction, so two admin paths exist to take a node out:

```bash
# Explicit housekeeping: drop a decommissioned tool or a junk identity + its incident edges.
curl -X DELETE -H "Authorization: Bearer $TOKEN" \
  "$NORVIQ_API/api/v1/asset-graph/node?namespace=support-bot&node_id=tool:legacy_export"
```

Deregistering an agent (`DELETE /api/v1/agents/{spiffe_id}`) prunes the same way
(`norviq/api/routers/agents.py:516`). Both go through one implementation
(`norviq/api/graph_maintenance.py`) so the two cannot drift into different notions of "removed", and
both report whether a node was *actually* removed rather than assuming success. The removal operates on
the live builder and re-saves, so every graph surface reflects it immediately.

---

## 5. Reach

"Reach" means three different computations in three places. They agree in spirit and differ in detail.

### 5.1 Asset Graph inspector (client-side)

Selecting a node runs a BFS over the loaded view model
(`ui/src/components/asset-graph/model.ts:278-296`). Direction depends on the node kind: an agent or tool
traces **downstream** ("what can this reach"), a data node traces **upstream** ("who can reach me").
`belongs_to` edges are skipped — they are structural and must not inflate a blast radius. The inspector
labels the number "Blast radius" for agents and tools and "Exposure" for data
(`ui/src/components/asset-graph/AssetNodeDetail.tsx:137-155`).

### 5.2 Kill-chain blast radius (server-side)

Each kill chain carries a `blast` count and up to eight named `reach[]` assets. `_reachable`
(`threats.py:186-196`) is a forward DFS from the chain's source agent over all non-`belongs_to` edges;
agent nodes are excluded, and so is the chain's own target — the target is the compromise premise, not
part of its own blast radius (`threats.py:367-380`). Each asset is flagged `s=1` when
`_node_sensitive` holds: **every data node is sensitive**, and a tool is sensitive when its
`risk_level` is `high` or `critical` (`threats.py:179-183`).

### 5.3 The graph-analysis family

`norviq/api/routers/graph.py` exposes a separate, cached analysis API over the same snapshot, under
`/api/v1/graph`:

| Endpoint | Returns |
|---|---|
| `GET /api/v1/graph/` | the raw snapshot (`nodes`, `edges`) |
| `GET /api/v1/graph/summary` | node/edge/agent/tool/data counts, critical tools, low-trust agents, cycle flag |
| `GET /api/v1/graph/blast-radius/{agent_id}` | reachable agents/tools/data, bounded paths to data, aggregate risk |
| `GET /api/v1/graph/attack-paths?source=&target=` | simple paths between two nodes (cutoff 6, up to 5) |
| `GET /api/v1/graph/critical-paths` | paths whose `min_trust < 0.4` |
| `GET /api/v1/graph/chokepoints` | tools with both agent callers and data targets, ranked by data fan-out |
| `GET /api/v1/graph/analysis` | the full report |

Results are memoized per `(namespace, graph-version, analysis, params)` where the version is a content
hash of the snapshot (`store.py:18-20`), so they invalidate automatically when the graph changes.

Be aware of two things before you build on these. **No console surface consumes them** — the Asset
Graph page reads `/api/v1/asset-graph` and the Attack Graph page reads `/api/v1/threats/attack-paths`;
these are API-only. And the constants in [§2](#2-nodes) propagate: `critical-paths` returns an empty
list (nothing has `min_trust < 0.4`), `summary.low_trust_agents` is always `0`, `blast-radius`'s
`critical_data` is always empty, and every `path_risk` carries the same constant `1.0 − 0.8` trust
factor. The **reachability sets** those endpoints return — reachable agents/tools/data, and
`chokepoints`' agent and data fan-out per tool — are real, and are what these routes are good for.

---

## 6. Kill chains — what the console Attack Graph computes

`GET /api/v1/threats/attack-paths` (`norviq/api/routers/threats.py:564`) is what the Attack Graph screen
renders. It derives chains **live** from the newest asset-graph snapshot joined to audit history; it
does not read the `attack_paths` table (that is a separate implementation — see
[§7](#7-the-precomputed-attack_paths-table)).

```bash
curl -H "Authorization: Bearer $TOKEN" \
  "$NORVIQ_API/api/v1/threats/attack-paths?ns=all&range=24h&cls=all"
```

### 6.1 The walk

Sources are agent nodes with a real `agent_class` that are neither the shared identity parent nor an
awaiting placeholder (`_is_source_agent`, `threats.py:170-176`). From each source, `_walk_paths`
(`threats.py:208-259`) does a depth-bounded DFS:

| Bound | Value | Why |
|---|---|---|
| `_MAX_DEPTH` | 4 | chain length ceiling |
| `_MAX_CHAINS_PER_CHOKEPOINT` | 3 | per-chokepoint fan-out, so `execute_sql` reaching many tables cannot crowd out a sibling `delete_record` |
| `_MAX_CHOKEPOINTS_PER_AGENT` | 16 | distinct first-hop tools per agent — but **every** `high`/`critical`-risk chokepoint is kept and only the low-risk tail is truncated |
| `_MAX_PATHS` | 200 | global cap, applied **after** ranking, so the least severe chains are the ones dropped |

The response reports `total_paths` (pre-cap) and `class_totals` (per-class counts computed before
truncation), so the console can tell you it is holding a partial list rather than silently under-count a
class.

A chain terminates on a data node, or on any node with no outgoing edges. On an estate whose tools are
not in `TOOL_DATA_MAP`, that means chains are `agent → tool`, one hop.

### 6.2 Status — derived from audit history, not from evaluation

Per hop, `_build_path` (`threats.py:280-294`) reads the joined counts and resolves a decision:

| Hop decision | Condition |
|---|---|
| `would_block` | `would_block > 0` and `block == 0` — a policy covers this hop but the namespace logs instead of enforcing |
| `block` | `block > 0` and `allow == 0` |
| `mixed` | `block > 0` and `allow > 0` |
| `allow` | otherwise |

The chain status then follows (`threats.py:386-398`):

| Status | Meaning | Verdict text |
|---|---|---|
| `blocked` | some hop is a hard block with no allows | "Policy blocks the chokepoint … — path neutralized." |
| `blocked` (Monitor) | some hop is a Monitor would-block with no allows | "Monitor mode: … would be blocked (logged, not enforced) — switch to Block to enforce." |
| `exploitable` | **every** hop has allowed traffic | "Every hop has allowed traffic — … is reachable end-to-end." |
| `unsimulated` | at least one hop has no allowed traffic and nothing blocked it | "No end-to-end traffic yet — simulate to confirm reachability." |

This is history, not a policy evaluation: nothing is called, and a policy you applied five minutes ago
does not change a status derived from yesterday's traffic. That lag is exactly what `governed_by`
([§6.5](#65-the-governed_by-flag--a-defense-is-applied)) and **Simulate** ([§9](#9-simulate)) exist to
cover.

One gap to know: `escalate` decisions are counted by the join but **not used** by the hop decision —
`_dec_from_counts` only looks at `allow` and `block` (`threats.py:120-125`). A hop whose entire history
is escalations renders as `allow` with "Allowed · 0 calls", and the chain lands in `unsimulated`. The
Asset Graph's own verdict function does fold escalations into `mixed`
(`ui/src/components/asset-graph/model.ts:83-105`), so the two surfaces can disagree about an
escalate-only edge.

### 6.3 Severity

```python
# norviq/api/routers/threats.py:382-384
tgt_sens = 1.0 if _node_sensitive(tgt_node) else 0.4
risk = min(1.0, (1.0 - trust) * 0.5 + tgt_sens * 0.35 + (0.15 if chokepoint else 0.0))
sev  = _severity_from(risk)   # >=0.75 critical, >=0.5 high, >=0.25 medium, else low
```

Because `trust` is the constant `0.8` ([§2](#2-nodes)) and `chokepoint` is always non-empty (it falls
back to the target's name, `threats.py:364-365`), this reduces on a real estate to exactly two outcomes:

| Terminal | `tgt_sens` | risk | severity |
|---|---|---|---|
| data node, or a tool whose `risk_level` is `high`/`critical` | 1.0 | `0.60` | **high** |
| any other tool | 0.4 | `0.39` | **medium** |

So the severity chips are a two-valued signal today, and the **Critical** / **Low** severity filters
match nothing. Rank by status first (`exploitable` before `unsimulated` before `blocked`) and use blast
radius and the chokepoint's verb for the finer ordering; the server already sorts that way
(`_STATUS_ORDER`, then severity, then `-blast`, `threats.py:549-552`).

### 6.4 Chokepoint, MITRE and fix

- **Chokepoint** is the last tool node on the chain (`threats.py:287-288`). It is the single name a
  policy has to constrain to neutralize the chain, which is why the intent builder and the "Defend"
  action both target it.
- **MITRE** is a best-effort ATLAS descriptor from the chokepoint's name — an exact table of 14 tools,
  then a verb-prefix fallback (`mitre_for_tool`, `norviq/api/threat_intent.py:847-863`). Read tools map
  to the tactic string `Reconnaissance · read/search — no specific ATLAS technique` rather than a
  fabricated technique id.
- **Fix** is a one-line recommendation derived from the chokepoint's verb (`recommended_fix`,
  `threat_intent.py:812-822`): egress tools get "deny external egress", mutating verbs get "constrain to
  read-only", reads get "scope to the agent's namespace", everything else gets "restrict to the declared
  intent (default-deny)".

### 6.5 The governed_by flag — "a defense is applied"

Because status is audit-derived, a chain can still read `exploitable` immediately after you apply a
policy. `_governing_policies` (`threats.py:426-518`) reads the newest policy per `(namespace,
agent_class)`, keeps only intent-compiled (`package norviq.intent.*`) and capability-remediation
(`package norviq.remediation.capability.*`) policies, and answers whether that policy actually **denies
this chain's chokepoint**:

- a capability policy is a verb forward-guard → `governed_by = "capability"`;
- an intent policy is default-deny, so a chokepoint **not** in its allowlist is denied →
  `governed_by = "intent"`; an allowlisted mutating tool is denied only when Read-only is on;
- an intent that does not scope by tool name at all (empty `# nrvq:intent-tools` marker) claims
  **nothing** — it is deliberately not reported as the thing defending the chokepoint.

The inspector renders this as a teal shield note: *"An applied intent policy already denies `X` for this
class. This status reflects past traffic — Simulate to confirm."*

---

## 7. The precomputed `attack_paths` table

There is a second, older attack-path implementation: `norviq/engine/attack_graph.py`, triggered by
`POST /api/v1/attack-paths/compute` (admin-only) and read by `GET /api/v1/attack-paths`. It walks the
same snapshot with its own DFS (depth ≤ 4, terminal = data node or a name in `DANGEROUS_TOOLS`,
`engine/attack_graph.py:268-303`), deletes the namespace's existing rows, and inserts the new ones into
`attack_paths` (`norviq/api/db/models.py:299-310`).

| | Console kill chains | Precomputed `attack_paths` |
|---|---|---|
| Endpoint | `GET /api/v1/threats/attack-paths` | `GET /api/v1/attack-paths`, `POST /api/v1/attack-paths/compute` |
| Source of truth | live derivation from snapshot + `audit_log` | rows in the `attack_paths` table |
| Hop verdict | observed decision counts | a real `evaluator.evaluate()` per tool hop |
| Storage | none | one row per path, replaced per compute |
| Console surface | Attack Graph page | **none** |

Two things follow, and both matter if you are scripting against the API.

**The console's "Recompute" button does not refresh what the console shows.** It POSTs to
`/attack-paths/compute` (`ui/src/pages/AttackGraph.tsx:347`) and then refetches
`/threats/attack-paths`. The compute writes `attack_paths` rows; the refetch reads a live derivation. The
refetch does pick up any newer asset-graph snapshot, but the count the button reports ("Recomputed 12
attack paths") is a count of rows on a surface the page does not display.

**The precompute's policy attribution is not currently usable.** `_evaluate_step` builds its simulated
event with `agent["properties"].get("spiffe_id", "")` (`engine/attack_graph.py:361-367`), but
`add_agent` never writes a `spiffe_id` property — the SPIFFE id is the node *key*, not a property
(`asset_graph.py:69-81`). The evaluator therefore fails SPIFFE validation
(`evaluator.py:2290-2293`) and returns the named fail-closed decision `invalid_spiffe_identity`
(`evaluator.py:2172-2179`). Every **tool** step therefore comes back `would_block` — data steps are never
policy-evaluated at all (`_evaluate_step` returns `no_policy` for a non-tool node,
`engine/attack_graph.py:353-354`) — and because a path's first hop is always a tool, every stored path
has `blocked_by_policy = true` and a risk score of `0.3 − 0.3 (+0.2)` → severity `low`
(`engine/attack_graph.py:393-433`). The topology in those rows is real; the policy verdict and severity
are not. Use `/threats/attack-paths` for anything you act on.

(The one silver lining: because validation fails before `_persist_behavior`, the precompute does **not**
write audit rows or graph edges. Simulate does — see [§9](#9-simulate).)

---

## 8. Source capability and Defend

For data nodes whose URI resolves to a known source type, the asset-graph response attaches a
capability posture (`_attach_source_capability`, `graphs.py:306-399`). Source types come from
`source_type_of` — the part before `://` or the first `/` — against a registry of `elasticsearch`,
`postgresql`, `smtp`, `webhook`, `s3`, `filesystem` plus aliases (`postgres`, `es`, `opensearch`,
`mail`, `gcs`, `minio`, …) in `norviq/engine/capability/source_registry.py:183-201`.

Each source exposes verbs — `read`, `write`, `delete`, `send` — and each verb is classified by joining
three signals:

| Signal | Derived from |
|---|---|
| **granted** | an `accesses` edge exists from a tool with that verb (declared — see [§1.3](#13-the-tooldata-map-is-the-load-bearing-caveat)) |
| **observed** | the tool's incoming `calls` edges have `allow + block + escalate > 0` (observed) |
| **defended** | those `calls` edges have `block + escalate > 0` — a rule acted on it at least once (observed) |

Note the attribution: the signal lives on the **agent→tool** edge, because that is the edge that carries
decision history, and it is mapped onto the source through the `accesses` edge (`graphs.py:329-368`).

The resulting statuses (`CapabilityStatus`, `source_registry.py:51-58`):

| Status | Meaning | What it should prompt |
|---|---|---|
| `undefended` | observed in traffic, no policy has ever acted on it | Author a rule. This is the live gap. |
| `dormant_grant` | reachable but never exercised | Least-privilege cleanup — remove the grant or scope it before it is used. |
| `defended` | observed and a policy acted on it | Nothing; keep it that way. |
| `latent` | the source exposes it, nothing grants or observes it | Informational. |
| `not_exposed` | this source class has no such verb | — |

**Defend** turns the worst open finding into a policy draft. The inspector's button calls
`POST /api/v1/capability/defend` (`threats.py:869-993`) — **admin only** (`require_admin`,
`threats.py:881`) — which:

1. resolves target verbs — explicit, else every mutating verb the source exposes (i.e. "make read-only");
2. resolves the **concrete tool names** for the class that reach that source with those verbs
   (`_tools_reaching_source`, `threats.py:846-866`) — necessary because OPA input has no source field;
3. adds forward-guard name fragments so the policy also catches unobserved or renamed destructive tools;
4. compiles the Rego through the evaluator's isolated dry-run key to prove it compiles;
5. persists a **draft** in `intent_drafts` with `source_framework='capability'`, and returns a deep link
   to `/policies/catalog?intent_draft=<id>`.

A draft never enforces. `intent_drafts` is a dedicated table the evaluator's `_collect_candidates` never
queries; enforcement happens only when an admin reviews and applies the Rego through the gated Policies
flow. The draft's priority mirrors the namespace baseline so an applied draft stays tighten-only.

---

## 9. Simulate

**Simulate (preview)** in the Attack Graph inspector answers a different question from the status chip:
*given the policies loaded right now, what happens if this chain is walked?*

What it does (`ui/src/pages/AttackGraph.tsx:279-326`):

1. Builds an identity `spiffe://norviq/ns/<ns>/sa/<cls>`, `namespace = <ns>`, `agent_class = <cls>`.
2. Collects the chain's **tool** hops (falling back to the chokepoint or target if there are none).
3. `POST /api/v1/evaluate` for each, with `tool_params: {}` and `framework: "attack-graph"`, stopping at
   the first hard block.
4. Classifies the outcome:

| Result | Condition | Label |
|---|---|---|
| Enforced block | any hop returns `block` whose `rule_id` is **not** `no_policy_loaded` | "Blocked by an authored policy" |
| Monitor would-block | any hop returns `audit` | "Would be blocked — this namespace is in Monitor mode (evaluated, not enforced)" |
| Fail-closed only | a hop returns `block` with `rule_id = "no_policy_loaded"` | "Blocked only by the fail-closed default — no policy is loaded for this namespace. Author a policy to control it intentionally." |
| Gap | everything allowed | "Simulation found a policy gap — no policy covers this path" |

Only the first two count as *covered*. The fail-closed default is deliberately not reported as a block
by policy — it is the absence of a policy, and treating it as coverage is how a namespace ends up
looking governed when nobody authored anything.

Three limits to hold on to:

- **Simulate does not enforce, but it is not side-effect free.** `POST /api/v1/evaluate` runs the real
  evaluator, which persists behaviour on every evaluation that completes (`evaluator.py:470`,
  `evaluator.py:572` — the fail-closed timeout/invalid-identity paths return before it): an audit row is
  written, trust state is updated, and `_safe_record_graph` records the call into the asset graph. Since
  the synthetic id uses the **agent class** in the `sa/` segment while a real workload uses its
  **service account**, simulating usually mints a *new* agent node and a new `calls` edge in the graph
  for that namespace. Simulated rows carry `framework="attack-graph"`, which is how you filter them out
  of the audit log.
- **Parameters are empty.** `tool_params: {}` means any rule that depends on argument content — a SQL
  allowlist, a destination check, a `param_paths` predicate — will not fire. Simulate proves *tool-level*
  coverage, not argument-level coverage.
- **It is per hop, not per chain.** Each hop is evaluated independently; there is no session, no call
  depth accumulation, and no ordering effect between hops.

### What-if is not Simulate

Clicking a hop toggles a **what-if** block (`AttackGraph.tsx:267-276`). That is purely local and
hypothetical: it recolors the hop, rewrites the verdict in amber ("… WOULD neutralize this path …"),
and enables **Draft blocking policy**. It deliberately does **not** move the headline `BLOCKED` stat or
re-order the list, because folding a hypothetical into the real numbers made a what-if look like an
enforced block (`AttackGraph.tsx:194-201`).

---

## 10. Namespace scoping

Every graph read resolves the caller's effective namespace set server-side
(`_resolve_namespaces`, `graphs.py:44-71`):

| Caller | `namespace=all` | `namespace=team-a` | `namespace=team-a,team-b` |
|---|---|---|---|
| `admin`, or a `*` namespace claim, or `role=service` with no claim | unrestricted (every namespace) | that namespace | both |
| non-admin with claim `team-a` | **just `team-a`** | `team-a` | **403** |
| non-admin with **no** claim | **403** | 403 | 403 |

A scoped viewer asking for "all" gets exactly its own namespace — never everyone else's — and naming a
namespace outside its claim is refused fail-closed with `NRVQ-API-7052`. `/api/v1/threats/attack-paths`
reuses the same helper, and `/api/v1/graph/*` uses the equivalent `scoped_namespace`
(`norviq/api/auth.py:265-284`).

Two conventions in the responses:

- **`all` is a console sentinel, not a namespace.** Along with `__cluster__` it is excluded from
  snapshot reads (`_RESERVED_NAMESPACES`, `graphs.py:37`), and the managed policy scopes `__baseline__`
  and `__pack__` are excluded from the deployed-agent derivation (`_RESERVED_AGENT_CLASSES`,
  `graphs.py:35`) so a namespace's baseline row never renders as a phantom agent.
- **Multi-namespace responses qualify ids.** When more than one namespace is in scope, node ids become
  `"<ns>::<id>"` so ids that repeat across namespaces (`tool:search_kb`) do not collide
  (`graphs.py:176-177`). A single named namespace keeps the plain id shape. Every node carries
  `properties.namespace` either way, which is what drives per-namespace clustering and coloring.

---

## 11. Synthetic and awaiting agents

Two classes of node are hidden by default, independently.

**Synthetic / probe identities.** One shared classifier (`is_synthetic_identity`,
`norviq/api/synthetic.py:63-85`) marks e2e, probe, policy-tester, smoke, canary and eval identities by an
anchored class-name convention — `allowlist-probe`, `e2e-`, `probe-`, `evtrace-`, `effecttest`, `smoke-`,
`canary-`, `policy-tester-`, `wave<N>e2e…`, plus the exact names `policy-tester` / `scorer`
(`synthetic.py:29-48`). It checks an explicit `norviq.io/synthetic=true` node property first
(`synthetic.py:71-74`), but **nothing in the product writes that property onto a graph node** —
`add_agent` only ever writes `agent_class`, `agent_classes`, `trust_score`, `trust_category`
(`asset_graph.py:69-81`) — so on the graphs the name convention is the only branch that fires today.
A red-team identity is therefore hidden only when its class matches one of those prefixes; the
`framework='redteam'` exclusion is a separate SQL predicate for audit rows (`audit_row_is_non_real`,
`synthetic.py:94-103`) and does not filter the graphs. Hidden agents take their edges with
them, and any tool/data node left orphaned is dropped too so no lone dots linger
(`graphs.py:281-303`). The response reports `synthetic_hidden`, which drives the *"N test/probe agents
hidden — Show"* chip. `?include_synthetic=true` brings them back. The Attack Graph applies the same
classifier to chain sources.

**Awaiting agents.** An agent that is deployed — it has a row in `policies` or `agent_registry` — but has
produced no observed traffic is synthesized as a dimmed node with `properties.awaiting = true`
(`_deployed_classes` + `_awaiting_nodes`, `graphs.py:102-127, 267-278`). This covers both the namespace
that has other traffic and the namespace that has none at all. Hidden by default;
`?include_awaiting=true` reveals them, reported as `awaiting_hidden`.

An agent that stays dimmed after a rollout is not reaching Norviq at all — check sidecar injection and
the API URL. Remember that injection under the shipped default requires **both** the namespace label
`norviq-injection=enabled` **and** the per-pod label `norviq.io/agent-class`: the chart ships
`webhook.injection.gateOnlyAgentPods: true` (`helm/norviq/values.yaml:429`), which renders the
`namespaceSelector` on `norviq-injection In [enabled]` *and* an `objectSelector` on
`norviq.io/agent-class Exists` (`helm/norviq/templates/webhook-config.yaml:50-54, 78-81`). A pod missing
the pod label is never routed to the webhook, so it starts un-injected and ungoverned, and will never
appear on either graph.

---

## 12. Tool classification lifecycle

A tool's **verb** (`read` / `write` / `delete` / `send`) is what lets a kill chain say a hop is
destructive rather than generically "reaches", and it is resolved in a fixed order
(`threats.py:304-345`):

1. **Promoted override** — an admin-confirmed verb in `tool_verb_overrides`; shown as `learned`.
2. **Registry classification** — the source-specific `verb_of_tool` for a tool→data hop, else the
   source-agnostic `classify_tool` name/token classifier; shown as `registry`.
3. **Observation** — still unclassified: the hop shows `observing · delete 12/14`, from the last **7
   days** of audit rows whose params revealed the operation (`_verb_evidence`, `threats.py:1190-1219`).

Promotion is admin-gated (`POST /api/v1/threats/tool-verbs/promote`). Risk follows the canonical
verb→risk map so a promotion cannot under-declare, and the suggested verb is the **most destructive**
verb the evidence showed, not the most frequent — a tool observed doing four reads and two deletes is a
delete tool for authorization purposes (`_top_verb`, `threats.py:1225-1241`). Promotion also re-seeds
the evaluator's in-process map, so `input.derived.verb` reports the promoted verb on the very next call
rather than after a restart. `DELETE /api/v1/threats/tool-verbs` demotes it back to observation.

---

## 13. Retention and pruning

| Bound | Default | Where | Effect |
|---|---|---|---|
| In-memory nodes per namespace | `5000` | `settings.graph_max_nodes` (`norviq/config.py:424`) | LRU eviction by last-touched tick once the cap is exceeded (`asset_graph.py:268-280`) |
| Snapshot rows kept per namespace | `10` | `config.retention.graphSnapshotKeepPerNamespace` (`norviq/config.py:258`) | Hourly sweep deletes older rows; `0` keeps all |
| Redis snapshot copy | `300 s` | `store.py:47` | Falls back to the newest DB row on miss |
| Agent registry entries | `90 d` after `last_seen` | `config.retention.agentRegistryRetentionDays` | Stops decommissioned agents lingering as phantom "awaiting" nodes |
| Retention sweep interval | `3600 s` | `settings.audit_retention_prune_interval_s` (`norviq/config.py:251`) — **no Helm key**, see below | One loop sweeps every retention-managed table |

The `asset_graph` prune keeps the newest N per namespace **and always keeps any row referenced by
`attack_paths`** — the foreign key has no cascade, and deleting a referenced row would break those paths'
provenance (`norviq/api/audit_retention.py:152-172`). None of the retention-managed tables is read by the
enforcement path, so pruning can never change a decision.

Two gaps worth planning around:

- **`attack_paths` itself is not retention-managed.** Rows are only removed by the next compute for the
  same namespace, which deletes and reinserts (`engine/attack_graph.py:94-106`). A namespace that is
  computed once and then goes quiet keeps its rows indefinitely.
- **`graph_max_nodes` has no Helm key, and neither does the sweep interval.** The chart renders named env
  vars for `graphSnapshotKeepPerNamespace` and `agentRegistryRetentionDays`
  (`helm/norviq/templates/configmap.yaml:94-95`) but none for these two, so set them with
  `config.extraEnv`, which the ConfigMap template renders verbatim
  (`helm/norviq/templates/configmap.yaml:34-36`). Settings take the `NRVQ_` prefix
  (`norviq/config.py:49`):

```yaml
# values.yaml — raise the per-namespace graph node cap
config:
  extraEnv:
    NRVQ_GRAPH_MAX_NODES: "20000"
    NRVQ_AUDIT_RETENTION_PRUNE_INTERVAL_S: "3600"
  retention:
    graphSnapshotKeepPerNamespace: 10
```

```bash
helm upgrade norviq oci://ghcr.io/norviq-dev/charts/norviq --version 0.2.2 -n norviq -f values.yaml
```

Eviction is silent and LRU by touch order, so a namespace that exceeds the cap loses its coldest nodes —
which are, by construction, the agents and tools nobody has exercised recently. If you run more than a
few thousand distinct tool names or identities in one namespace, raise the cap rather than let it trim.

---

## 14. Reading the console

### Asset Graph (`/asset-graph`)

Opens on whatever the console's namespace scope already is — `?ns=` in the URL, else the identity-scoped
`nrvq_namespace` in localStorage, else **All namespaces**
(`initialNamespace`, `ui/src/store/AppContext.tsx:94-105`) — with each namespace clustered and colored.
The Namespace dropdown drives the
server-side scope (and is the global console scope); Range drives the API `range` parameter; type, risk,
agent-class, search and "blocked only" filter client-side. Clicking an agent focuses its subgraph;
clicking any node opens the inspector with its blast radius (or, for a data node, its exposure) and the
source-capability panel. The stat strip is Namespaces · Nodes · Tools · Data · High risk · Blocked; the
**Data** cell turns red and reads "N write/delete-open" when N data sources have a **worst open verb**
of `write`, `delete` or `send` — a dormant read grant deliberately does not light it — and **High risk**
and **Blocked** double as filters.

What the canvas does and does not distinguish: an **enforced blocked** edge is drawn in red with its own
arrowhead; every other verdict — `allow`, `mixed`, and Monitor `would_block` — is drawn identically
(`ui/src/components/asset-graph/AssetGraphCanvas.tsx:433-450`). The model computes all four verdicts
(`model.ts:83-105`) and the inspector uses them, but the canvas has not yet been branched on them, so a
Monitor-mode namespace's coverage is **under-reported on the canvas**. Read the edge in the inspector
before concluding an edge is ungoverned. The **Blocked** stat counts *edges*, not paths — only
agent→tool `calls` edges can be blocked, since `accesses` edges carry no decision history — and it and
the "blocked only" filter both count enforced blocks only, so the two always agree.

### Attack Graph (`/threats/graph`)

Three columns inside one panel — ranked path list, kill-chain canvas, inspector — over a clickable stat
strip (Critical paths, High, Chokepoints, Max blast radius, Exploitable, Blocked). The strip's
`Chokepoints` uses the server's definition (`path.tool`), the same one the inspector chips. Selection and
filters are reflected in the URL (`?path,ns,cls,status,sev,range`), so a triage view is shareable.

Canvas key: agent / tool / data node colors, a red diamond for a sensitive blast-radius satellite, and
per-hop edge colors — green allowed, amber partial, **amber dashed** Monitor would-block, **red dashed**
blocked. A hop also carries its resolved operation and, for an unclassified tool, its observation state
(`observing · delete 12/14`). Node names are attacker-supplied text, so a homoglyph lookalike
(`exеcute_sql` with a Cyrillic `е`) is flagged in amber with the masked position and codepoints.

### What each finding should prompt

| What you see | What it means | Do this |
|---|---|---|
| `EXPLOITABLE` chain | every hop has allowed traffic in the window | Open the inspector, read the chokepoint and the recommended fix, then **Define `<class>`'s intended behaviour** to generate a default-deny draft. |
| `EXPLOITABLE` **with** a teal shield note | a policy is applied but status is derived from pre-apply traffic | **Simulate** to confirm the defense holds now. Do not author a second policy. |
| `NOT SIMULATED` chain | topology exists, no end-to-end allowed traffic | **Simulate**. If it comes back "policy gap", author before that traffic arrives. |
| `BLOCKED` with the Monitor verdict | a policy covers the chokepoint but the namespace only logs | Switch the namespace to Block mode. This is a coverage decision, not a policy gap. |
| Simulate → "Blocked only by the fail-closed default" | no policy is loaded for the namespace | Author an explicit policy. Fail-closed is a safety net, not a control you can evidence. |
| Simulate → "policy gap" | no rule addresses the chain | Draft from the what-if, or define the class's intended behaviour. |
| Capability finding `UNDEFENDED` | a verb is observed on a source and nothing has ever acted on it | **Defend** → review the draft in Policies → apply. |
| Capability finding `DORMANT_GRANT` | reachable, never exercised | Remove or scope the grant now, while nothing depends on it. |
| Hop showing `observing · <verb> n/m` | the tool's verb is unproven | Review the evidence in the tool-verbs panel and **promote** it, so verb-gated policies stop seeing `unknown`. |
| A dimmed "awaiting" agent that never lights up | deployed but not reaching Norviq | Check the pod carries `norviq.io/agent-class` **and** the namespace carries `norviq-injection=enabled`; then check the sidecar's API URL. |
| A chain whose target is a `postgresql/...` node | a **declared** sink from the static map, not a verified table | Treat the severity as indicative. Confirm the real sink before citing it as evidence. |

---

## 15. Limits, in one place

Everything below is a property of the shipped code, not a caveat about your deployment:

1. `accesses` edges and every data node come from a hard-coded 8-entry map; there is no way to declare
   your own tool→data topology ([§1.3](#13-the-tooldata-map-is-the-load-bearing-caveat)).
2. Graph `trust_score` is a constant `0.8` and `sensitivity` a constant `medium`, so kill-chain severity
   is two-valued (`high`/`medium`) and the `/graph/critical-paths` analysis is always empty
   ([§2](#2-nodes), [§6.3](#63-severity)).
3. `escalate` history does not colour a kill-chain hop, though it does colour an asset-graph edge
   ([§6.2](#62-status--derived-from-audit-history-not-from-evaluation)).
4. Monitor-mode `would_block` edges are computed but not yet drawn distinctly on the Asset Graph canvas
   ([§14](#14-reading-the-console)).
5. `POST /api/v1/attack-paths/compute` writes a table no console surface reads, and its per-step policy
   verdicts are unusable ([§7](#7-the-precomputed-attack_paths-table)).
6. Simulate writes audit rows and can add an agent node/edge to the graph; it evaluates with empty
   `tool_params` ([§9](#9-simulate)).
7. `delegates` edges are modelled but never written, so agent→agent delegation does not appear on either
   graph ([§3](#3-edges)).
8. `attack_paths` rows are not retention-managed ([§13](#13-retention-and-pruning)).

---

## See also

- **[Concepts](../concepts.md)** — agent identity, policy tiers, enforcement modes, trust score.
- **[Asset Graph onboarding](../onboarding-asset-graph.md)** — namespace/service-account layout so each
  chatbot maps to its own node.
- **[Writing policies](writing-policies.md)** — the Rego contract behind the drafts the graph generates.
- **[Compliance & coverage](compliance.md)** — where the MITRE ATLAS mapping on a chain's chip feeds the
  coverage view.
- **[Configuration](../configuration.md)** — the Helm reference, including the retention keys in
  [§13](#13-retention-and-pruning).
