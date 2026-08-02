# 05 — Data contracts

Real payloads, at `f41c77f`. **Design against these, not invented data.** Every example below is either
copied from a test fixture or modelled on the repo's own realistic scenario
(`norviq/mcp/adversarial/chatbot.py`, namespace `agents`, servers github/postgres/slack/filesystem).

---

## 1. `GET /api/v1/tools` — the tool registry

`norviq/api/routers/tools.py`. Returns a **bare JSON array**. No envelope, no `total`, **no pagination**.

**Query:** `namespace` (omit or `all` = every readable namespace) · `range` ∈ `24h|7d|30d|90d`
(default `30d`; governs the **observed** tier only).
**Auth:** any authenticated user. Tenant-scoped by token.

### Field reference

| Field | Type | Null when |
|---|---|---|
| `name` | string | never |
| `name_skeleton` | string | never — server-computed; **differs from `name` only for homoglyph/zero-width names**, which is a security signal |
| `source` | `"mcp_declared"` \| `"observed"` | never |
| `namespace` | string | never |
| `server_id` | string \| null | null when observed |
| `pin_status` | `"pinned"` \| `"drift"` \| `"quarantined"` \| null | null when observed |
| `scan_severity` | `"none"\|"low"\|"medium"\|"high"\|"critical"` \| null | null when observed |
| `description` | string \| null | null when observed **or withheld** |
| `description_withheld` | boolean | never |
| `input_schema` | object \| null | null when observed, truncated, unparseable, or absent |
| `schema_available` | boolean | never |
| `last_seen_at` | ISO8601 \| null | null when observed |

### Realistic response — 14 rows, both tiers, one drifted

```json
[
  {"name":"list_directory","name_skeleton":"list_directory","source":"mcp_declared","namespace":"agents","server_id":"filesystem","pin_status":"pinned","scan_severity":"none","description":"Lists a directory in the runbook volume.","description_withheld":false,"input_schema":{"type":"object","properties":{"path":{"type":"string"}}},"schema_available":true,"last_seen_at":"2026-08-02T09:14:07.412881+00:00"},
  {"name":"read_file","name_skeleton":"read_file","source":"mcp_declared","namespace":"agents","server_id":"filesystem","pin_status":"pinned","scan_severity":"none","description":"Reads a UTF-8 file from the mounted runbook volume.","description_withheld":false,"input_schema":{"type":"object","properties":{"path":{"type":"string"}}},"schema_available":true,"last_seen_at":"2026-08-02T09:14:07.412881+00:00"},
  {"name":"add_issue_comment","name_skeleton":"add_issue_comment","source":"mcp_declared","namespace":"agents","server_id":"github","pin_status":"pinned","scan_severity":"none","description":"Adds a comment to an existing issue.","description_withheld":false,"input_schema":{"type":"object","properties":{"number":{"type":"integer"},"body":{"type":"string"}}},"schema_available":true,"last_seen_at":"2026-08-02T09:14:06.881204+00:00"},
  {"name":"create_issue","name_skeleton":"create_issue","source":"mcp_declared","namespace":"agents","server_id":"github","pin_status":"pinned","scan_severity":"none","description":"Opens a new issue in a repository.","description_withheld":false,"input_schema":{"type":"object","properties":{"title":{"type":"string"},"body":{"type":"string"}}},"schema_available":true,"last_seen_at":"2026-08-02T09:14:06.881204+00:00"},
  {"name":"get_issue","name_skeleton":"get_issue","source":"mcp_declared","namespace":"agents","server_id":"github","pin_status":"pinned","scan_severity":"none","description":"Fetches one issue with its comments.","description_withheld":false,"input_schema":{"type":"object","properties":{"number":{"type":"integer"}}},"schema_available":true,"last_seen_at":"2026-08-02T09:14:06.881204+00:00"},
  {"name":"search_issues","name_skeleton":"search_issues","source":"mcp_declared","namespace":"agents","server_id":"github","pin_status":"pinned","scan_severity":"none","description":"Searches issues in the connected repositories.","description_withheld":false,"input_schema":{"type":"object","properties":{"query":{"type":"string","description":"GitHub issue search syntax"}}},"schema_available":true,"last_seen_at":"2026-08-02T09:14:06.881204+00:00"},
  {"name":"describe_table","name_skeleton":"describe_table","source":"mcp_declared","namespace":"agents","server_id":"postgres","pin_status":"pinned","scan_severity":"none","description":"Returns the column definitions for a table.","description_withheld":false,"input_schema":{"type":"object","properties":{"table":{"type":"string"}}},"schema_available":true,"last_seen_at":"2026-08-02T09:14:07.104553+00:00"},
  {"name":"execute_sql","name_skeleton":"execute_sql","source":"mcp_declared","namespace":"agents","server_id":"postgres","pin_status":"pinned","scan_severity":"none","description":"Executes arbitrary SQL, including writes and DDL.","description_withheld":false,"input_schema":{"type":"object","properties":{"sql":{"type":"string"}}},"schema_available":true,"last_seen_at":"2026-08-02T09:14:07.104553+00:00"},
  {"name":"run_query","name_skeleton":"run_query","source":"mcp_declared","namespace":"agents","server_id":"postgres","pin_status":"pinned","scan_severity":"none","description":"Runs a read-only SQL query against the support replica.","description_withheld":false,"input_schema":{"type":"object","properties":{"sql":{"type":"string","description":"a SELECT statement"}}},"schema_available":true,"last_seen_at":"2026-08-02T09:14:07.104553+00:00"},
  {"name":"post_message","name_skeleton":"post_message","source":"mcp_declared","namespace":"agents","server_id":"slack","pin_status":"drift","scan_severity":"critical","description":null,"description_withheld":true,"input_schema":{"type":"object","properties":{"channel":{"type":"string"},"text":{"type":"string"}}},"schema_available":true,"last_seen_at":"2026-08-02T09:31:52.006119+00:00"},
  {"name":"read_thread","name_skeleton":"read_thread","source":"mcp_declared","namespace":"agents","server_id":"slack","pin_status":"pinned","scan_severity":"none","description":"Reads a thread's messages.","description_withheld":false,"input_schema":{"type":"object","properties":{"channel":{"type":"string"},"ts":{"type":"string"}}},"schema_available":true,"last_seen_at":"2026-08-02T09:31:52.006119+00:00"},
  {"name":"send_dm","name_skeleton":"send_dm","source":"mcp_declared","namespace":"agents","server_id":"slack","pin_status":"pinned","scan_severity":"none","description":"Sends a direct message to a user by email address.","description_withheld":false,"input_schema":{"type":"object","properties":{"to":{"type":"string","description":"recipient email"},"text":{"type":"string"}}},"schema_available":true,"last_seen_at":"2026-08-02T09:31:52.006119+00:00"},
  {"name":"vector_search","name_skeleton":"vector_search","source":"observed","namespace":"agents","server_id":null,"pin_status":null,"scan_severity":null,"description":null,"description_withheld":false,"input_schema":null,"schema_available":false,"last_seen_at":null},
  {"name":"http_get","name_skeleton":"http_get","source":"observed","namespace":"agents","server_id":null,"pin_status":null,"scan_severity":null,"description":null,"description_withheld":false,"input_schema":null,"schema_available":false,"last_seen_at":null}
]
```

Note row 10 (`post_message`): **drifted, critical severity, description withheld.** That is the rug-pull
scenario, and it is the row a design should be judged on.

### The truncated-schema row — design for it

```json
{"name":"bulk_export","source":"mcp_declared","server_id":"warehouse","pin_status":"pinned",
 "scan_severity":"none","description":null,"description_withheld":false,
 "input_schema":null,"schema_available":false,"last_seen_at":"2026-08-02T09:14:07Z"}
```

Declared and pinned, but **unscopeable**. Cause: the proxy stores the definition as a bare 8 KiB slice,
and because JSON keys serialise alphabetically, `description` comes before `inputSchema` — a long
description evicts the schema. Frequent, not exotic.

### Live sample from the running cluster (namespace `analytics`)

```json
[{"name":"execute_sql","name_skeleton":"execute_sql","source":"observed","namespace":"analytics","server_id":null,"pin_status":null,"scan_severity":null,"description":null,"description_withheld":false,"input_schema":null,"schema_available":false,"last_seen_at":null},
 {"name":"search_kb","...":"observed"},{"name":"send_email","...":"observed"},{"name":"http_get","...":"observed"}]
```

i.e. a real deployment with **no MCP servers**: four observed tools, zero declared. This is the common
state.

## 2. Argument paths — `ui/src/lib/toolSchema.ts`

`schemaPaths(input_schema)` turns a JSON Schema into the paths a policy can address.

```ts
interface SchemaPath {
  path: string;          // dotted, no prefix, e.g. "filters.customer"
  type: string;          // "string"|"integer"|"number"|"boolean"|"array"|"object"|"unknown"
  addressable: boolean;
  note?: string;         // reason or caveat — always display
  enumValues?: string[];
  required: boolean;
}
```

Outcomes, with **exact** note copy:

| Input | `addressable` | `note` |
|---|---|---|
| `{"type":"string"}` | `true` | — (carries `enumValues` if declared) |
| `{"type":"object", properties:{…}}` | *not emitted* | recursed into; only leaves appear |
| `{"type":"integer"\|"number"\|"boolean"}` | `false` | `"integer arguments never appear in param_paths — only text does"` |
| `{"type":"array"}` | `false` | `"list arguments are indexed at runtime (…[0], …[1]) — scope by a seen path, or use “any parameter value”"` |
| `{"$ref"\|"oneOf"\|"anyOf"\|"allOf"}` | `false` | `"shape depends on a reference or union the builder cannot resolve"` |
| name with a space, `/`, `@`, `:` … | `false` | `"argument name uses characters a policy field cannot contain"` |
| no `type` declared | **`true`** | `"no declared type — matches only if the value arrives as text"` |
| `{"type":["string","null"]}` | `true` | treated as string |

Bounds: depth ≤ 12, ≤ 256 paths.

**A schema exercising every branch** (from the test suite — use it as your mock fixture):

```json
{"type":"object","required":["to"],
 "properties":{
   "to":          {"type":"string"},
   "retries":     {"type":"integer"},
   "attachments": {"type":"array","items":{"type":"string"}},
   "filters":     {"type":"object","properties":{"customer":{"type":"string"}}}}}
```

→ `to *` (addressable, required) · `retries` (disabled, "only text") · `attachments` (disabled, "indexed
at runtime") · `filters.customer` (addressable, nested).

## 3. `GET /api/v1/mcp/servers`

Roll-up, one row per server: `server_id` · `namespace` · `transport` · `tools` (count) · `status`
(`ok|drift|quarantined|flagged`) · `drifted` (count) · `flagged` (count) · `last_seen_at`.

## 4. `GET /api/v1/mcp/pins`

One row per pinned tool. Query: `namespace`, `server_id`, `status`.

`namespace` · `server_id` · `tool_name` · `approved_digest` · `last_digest` · `approved` (bool) ·
`approved_by` · `approved_at` · `scan_severity` · `findings[]` · `drift_count` · `transport` ·
`first_seen_at` · `last_seen_at` · `status` · `approved_canonical` · `last_canonical`

- `status` is **derived**, not stored: drift outranks quarantine. `last_digest !== approved_digest` →
  `drift`; else `!approved` → `quarantined`; else `pinned`.
- Digests are 64-char sha256; the UI shows `[:12]`.
- ⚠️ `approved_canonical` / `last_canonical` contain the **pre-sanitize** definition text.

### Writes
- `POST /mcp/pins/approve` `{namespace, server_id, tool_name, digest}` — **admin**. **409** if the digest
  matches neither the approved nor the currently-served one: *"digest does not match the approved or the
  currently-served definition; re-read the pin and approve the digest you actually reviewed"*.
- `POST /mcp/pins/revoke` `{namespace, server_id, tool_name}` — **admin**.
- `DELETE /mcp/servers/{namespace}/{server_id}` — **admin**, returns `{namespace, server_id, removed:n}`.
  **No UI exists for this.**

## 5. Scan findings

Each finding: `rule` · `severity` · `field` (JSON path into the definition, e.g. `inputSchema.properties.q.description`)
· `detail` · `evidence` (≤ 200 chars, the matched text — **currently never rendered**).

Severity: `none|low|medium|high|critical`. At default settings, `high` and above causes the tool to be
**stripped from the model's tool list entirely**; `medium` causes its description to be replaced by a stub.

**A tool can therefore exist in the pins table, carry findings, and be invisible to the agent.** A design
should be able to express that.

## 6. Addressable policy fields — what a scope editor presents

From `norviq/engine/intent/schema.py`, mirrored in `ui/src/lib/builderCompile.ts`.

**Scalar** (ops: `equals`, `in`, `matches`, `notMatches`) — `verb` · `tool_kind` · `sql_normalized` ·
`direction` · `mcp.server` · `mcp.pin_status` · `mcp.scan_severity` · **`param_paths.<dotted.path>`**
(validated by pattern, not enumerated — the path is whatever the tool's own arguments are).

**Collection** (ops: `subsetOf`, `noneOf`, `anyOf`, `maxCount`) — `data_classes` · `sql_tables` ·
`sql_statements` · `param_values` · `destinations.emails` · `destinations.urls` · `destinations.hosts` ·
`destinations.schemes`.

**Numeric** (ops: `max`, `min`) — `param_bytes` · `call_depth` · `trust_score`.

### UI labels and verbs currently in use

| Field | Label |
|---|---|
| `data_classes` | data it carries |
| `sql_tables` | SQL tables |
| `param_values` | any parameter value |
| `destinations.emails` | recipient addresses |
| `destinations.urls` | destination URLs |
| `destinations.hosts` | destination hosts |
| `destinations.schemes` | URL schemes |
| `param_bytes` | payload size (bytes) |
| `call_depth` | call depth |
| `trust_score` | agent trust score |
| `verb` | operation verb |
| `mcp.pin_status` | MCP pin status |
| `param_paths.X` | **argument X** |

| Operator | Verb |
|---|---|
| `noneOf` | must not include |
| `subsetOf` | must be within |
| `anyOf` | must include one of |
| `maxCount` | at most (count) |
| `max` / `min` | at most / at least |
| `equals` | is exactly |
| `in` | is one of |
| `matches` / `notMatches` | matches regex / does NOT match regex |

Selected hints: `data_classes` → *"secret, pci, pii — matched wherever in the payload it sits, not just
one argument"*; `destinations.emails` → *"every address found anywhere in the call, so it cannot be moved
to another field"*; `param_bytes` → *"a volume guard, e.g. 65536"*.

**Budget:** only `matches`/`notMatches` spend the server's **25-regex-op cap**. Every set operation is
free. The builder shows this live as `0 / 25 regex ops`. *(A design could make cheap operators the
obvious default.)*

## 7. Identity and the collision case

The durable key is the composite **`(namespace, server_id, tool_name)`**.

At enforcement time the engine receives only the **bare `tool_name`** — server prefixing exists
(`--tool-name-prefix`) but is **off by default**, deliberately, because it breaks every policy written
against the plain name. So a rule naming `read_file` governs `read_file` on *every* server.

Disambiguation is available as policy data — the proxy sends an `input.mcp` block per call carrying
`{server, transport, pin_status, scan_severity, tool_digest, …}` — which is what the `mcp.server`
addressable field reads.

**Never key a UI row on `tool_name` alone.** The MCP page does today, and it produces duplicate React
keys plus a selection highlight that never matches.

## 8. Limits, caps and volumes

| | |
|---|---|
| Pagination | **none** on `/tools`, `/mcp/pins`, `/mcp/servers` |
| Sorting | **none** in `DataTable` |
| Filtering | substring match over `JSON.stringify(row)` |
| Stored definition | 8 KiB bare slice per tool |
| Scanned field | 16 KiB; a description over 2 KiB raises a `low` finding |
| Argument walk | depth 12, 256 paths |
| Column widths | namespace / server_id / tool_name are `varchar(255)`; digests 64 |
| Typical servers | 3–8 per namespace (4 in the repo fixture) |
| Typical declared tools | 10–40 (12 in the fixture) |
| Typical observed tools | 5–30 per namespace; unbounded in a large estate |
