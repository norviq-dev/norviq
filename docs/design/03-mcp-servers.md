# 03 — MCP Servers

**Status:** exists and is the **healthiest** of the four surfaces. `ui/src/pages/McpServers.tsx` (426
lines), route `/mcp`, nav group `MONITORING`, icon `Plug2`.
**Priority:** 4 of 4 — it needs elevation and de-duplication against the new Tools page, not a rebuild.

---

## 1. What it is

MCP (Model Context Protocol) servers are the integrations an agent calls tools *through* — GitHub,
Postgres, Slack, a filesystem. Norviq's proxy sits in front of them and intercepts the `tools/list`
handshake ("Gate A"), scanning every tool **definition** for prompt-injection and pinning it by content
hash.

This page is the control plane for that: **which integrations exist, and is each tool's definition still
the one we approved?**

The threat it exists to catch is a **rug pull**: a server serves a benign definition, gets approved, then
later serves a malicious one. The pin makes that change visible and refuses the call until an operator
adopts it.

## 2. Current structure — keep this, it works

**PageHead**
- Title `MCP Servers`
- Subtitle: *"Model Context Protocol integrations, and the approval state of every tool definition they serve"*
- Action: `Refresh` (`RefreshCw`, `btn btn-outline`)

**Five stat tiles** (`data-testid="mcp-totals"`, 5-col grid → 2-col at tablet):
`Servers` · `Tool definitions` · `Drifted` (`#FF3B5C` when > 0) · `Awaiting approval` (`#FFB020` when
> 0) · `Scanner findings` (`#FFB020` when > 0)

**Servers table** — columns: Server (mono) · Namespace · Transport · Tools · Status · Drifted · Flagged ·
Last seen. Clicking a row filters the table below; sub-copy switches to *"Filtered to {server} — click
the row again to clear"*.

**Tool definitions table** — Tool · Server · Pin · Scan · Approved (`digest[:12]`) · Served
(`digest[:12]`, red when drifted) · Drifts · Approved by.
Panel sub: *"Pinned by content hash. A definition that changes after approval is a rug pull, and the
tool is withheld from the model."*

**Detail panel** (`data-testid="mcp-detail"`), title `{server_id} / {tool_name}`, with status-specific copy:

| Status | Copy |
|---|---|
| drift | "This server is serving a definition that DIFFERS from the one approved. Calls to this tool are refused until an operator adopts the change." |
| quarantined | "Not approved. The tool is withheld from the model and calls to it are refused." |
| pinned | "Approved. The served definition matches the approved one." |

Actions: `Approve served definition` (primary, `CheckCircle2`) when not pinned · `Revoke` (destructive,
`XCircle`) when approved. **Both are admin-only** — the API enforces it; the UI does not gate the button,
so a viewer gets a 403 toast.

**Findings table**: `Rule | Severity | Field | Why it fired`.
**Definition diff**: two `<pre class="json">` blocks — `Approved definition` and `Definition served now`
(heading turns red and gains `(CHANGED)` on drift).

## 3. Vocabularies

**Pin status** — the read APIs emit three: `pinned` · `drift` · `quarantined`. Two more exist elsewhere:
`first_seen` (observe verdict) and `unknown` (sent to the engine when no definition was seen). A picker
offering pin status should list all five.

**Server health** — exactly four, with current labels and icons:

| Value | Label | Tone | Icon |
|---|---|---|---|
| `drift` | "definition changed" | `--block` | `ShieldAlert` |
| `quarantined` | "awaiting approval" | `--escalate` | `AlertTriangle` |
| `flagged` | "scanner findings" | `--escalate` | `AlertTriangle` |
| `ok` | "healthy" | `--allow` | `ShieldCheck` |

**Scan severity** — `none` · `low` · `medium` · `high` · `critical`. Rendered uppercase in a pill, except
`none` which renders as the muted word **`clean`**. critical/high → `--block`, none → `--allow`, else
`--escalate`.

**Pin mode** — `tofu` (trust on first use; auto-approves, `approved_by = "tofu"`) or `strict`
(quarantines until approved). Default `tofu`.

## 4. Problems to fix

### 4a. Two bugs on the collision case
Two servers can legitimately serve the same tool name.

1. The tool table uses **`rowKey="tool_name"`** → duplicate React keys.
2. `selectedKey` is built as `` `${server_id}/${tool_name}` `` but `DataTable` compares it against
   `row[rowKey]` (the bare tool name) → **the selected row is never highlighted.** Selection works;
   only the highlight is broken.

### 4b. Scan findings are under-used
`findings` is the richest security data on the page and gets four plain columns. **`evidence` — which
carries the actual matched text — is never rendered at all.** For a prompt-injection finding that is the
most important field.

*(Care: evidence is attacker-authored text. It should be rendered as inert, clearly-quoted data — never
in a way that could be mistaken for UI copy. Same doctrine as withheld descriptions in brief 01.)*

### 4c. The diff is not a diff
Approved vs served are two `<pre>` blocks side by side. For the page's central threat — *what changed?* —
that is the weakest possible presentation. A real diff with changed lines marked would make a rug pull
obvious in a second instead of a minute.

### 4d. Overlap with the new Tools page
Both list tool definitions. They must not become two answers to one question.

*(Opinion — proposed division:)*
- **Tools** = *"what tools exist and what can I do with them"* — inventory and policy-authoring, both
  tiers, argument-level detail.
- **MCP Servers** = *"are my integrations healthy and are their definitions still trustworthy"* —
  approval, drift, scanner findings, per-server health.

Cross-link both ways. A tool row on `/mcp` should link to its Tools entry; a declared tool on `/tools`
should link to its pin.

### 4e. No "forget server" UI
`DELETE /api/v1/mcp/servers/{ns}/{server_id}` exists and works. The walkthrough docs reference deleting a
server's pins "in the console"; **no such control exists.** Either add it (destructive, confirm) or fix
the docs.

### 4f. Approve can 409
`POST /mcp/pins/approve` returns **409** with: *"digest does not match the approved or the
currently-served definition; re-read the pin and approve the digest you actually reviewed"*. This fires
when the server changed its definition again between render and click — exactly the rug-pull race the
design should make legible. Today it is a raw-JSON toast.

## 5. Data

`GET /api/v1/mcp/servers` — roll-up per server: `server_id, namespace, transport, tools, status, drifted,
flagged, last_seen_at`.
`GET /api/v1/mcp/pins` — one row per pinned tool: `namespace, server_id, tool_name, approved_digest,
last_digest, approved, approved_by, approved_at, scan_severity, findings[], drift_count, transport,
first_seen_at, last_seen_at, status, approved_canonical, last_canonical`.

⚠️ `approved_canonical` / `last_canonical` contain the **pre-sanitize** definition text — including any
injection payload the firewall stripped. The diff view renders them today. Any redesign must decide
deliberately how to present attacker-controlled text; see brief 01 §4.

No pagination on either endpoint. Both are namespace-scoped by the caller's token.

## 6. Empty state — the default

*"No MCP servers observed yet"* — *"A server appears here the first time an agent runs a `tools/list`
through the Norviq MCP proxy. Point the host's server command at `python -m norviq.mcp -- <server
command>` to start governing it."*

This is good copy. **Keep its spirit**: the empty state is the most-viewed state, since MCP injection
ships off by default.

## 7. Required components

| Component | Exists? |
|---|---|
| `PageHead`, `Panel`, `StatTile`, `DataTable`, `KitButton`, `.pill` | ✅ |
| **Side-by-side / unified diff** | ❌ new |
| **Evidence display** (inert, quoted, attacker-authored) | ❌ new |
| **Destructive confirm** for forget-server | ❌ new |
| Stable composite row keys | ❌ component fix |

## 8. Acceptance criteria

1. Two servers serving one tool name render correctly and selectably.
2. "What changed?" on a drifted definition is answerable at a glance.
3. Scan findings surface their evidence, safely.
4. The division of labour with the Tools page is obvious, and both cross-link.
5. Admin-only actions are visibly admin-only rather than failing on click.
6. The empty state still teaches how to onboard a server.
