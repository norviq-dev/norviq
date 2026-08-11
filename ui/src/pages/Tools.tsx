// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// Tools — what Norviq knows about in this namespace, and HOW WELL it knows each one.
//
// The second half of that sentence is the page. A tool Norviq has a declared definition for can have its
// arguments scoped by policy; a tool it has merely seen in traffic can only be allowed or denied by name.
// That difference decides what security an operator can actually express, and until this page existed it
// was visible nowhere — the registry was consumed only by the builder's autocomplete and its warning.
//
// THE RULE THAT GOVERNS THE LAYOUT: declared and observed are TWO PANELS, never one table with a Source
// column. The bug this endpoint was built to retire was a UI that flattened sources of different strength
// into one set and then treated the union as proof a tool existed — it suggested names that could not
// exist and suppressed its own warning for exactly those names. A single sorted table would reintroduce
// the same invitation to read them as equivalent.
//
// A THIRD STATE is common and easy to miss: declared, pinned, and STILL unscopeable, because the stored
// definition is an 8 KiB slice and `sort_keys` puts `description` ahead of `inputSchema`, so a long
// description evicts the schema. That is not an error path; it is a Tuesday.

import { useCallback, useMemo, useState } from "react";
import { AlertTriangle, ExternalLink, Info, RefreshCw } from "lucide-react";
import { Link } from "react-router-dom";
import { fetchTools, type ToolRegistryEntry } from "../api/client";
import { ArgumentTree } from "../components/common/ArgumentTree";
import { BrandLoader } from "../components/common/BrandLoader";
import { KitButton } from "../components/common/KitButton";
import { Modal } from "../components/common/Modal";
import { PageHead } from "../components/common/PageHead";
import { Panel } from "../components/common/Panel";
import { ProvenanceBadge } from "../components/common/ProvenanceBadge";
import { ScopeabilityBadge } from "../components/common/ScopeabilityBadge";
import { SegmentedControl } from "../components/common/SegmentedControl";
import { StatTile } from "../components/common/StatTile";
import { useApi } from "../hooks/useApi";
import type { BuilderGraph } from "../lib/builderGraph";
import { schemaPaths } from "../lib/toolSchema";
import { useApp } from "../store/AppContext";

/**
 * The handoff into the Visual Policy Builder, with this tool already allowed.
 *
 * This screen used to send `state={{ scopeTool, fromTools }}` — keys NOTHING read. The tool name was
 * dropped in transit and the operator landed on the Policy Catalog's raw rego editor with an empty
 * buffer, which is not "the reverse direction of the P1 fix", it is a dead link that returns 200.
 * `builderGraph` is the channel `/intents` already uses and `PolicyCatalog` already consumes.
 *
 * ALLOWLIST MODE, deliberately. "Scope this tool" means constraining what this tool may do, and a
 * grant only exists under deny-by-default — tighten-only has no allowed-tool list to hang a
 * ScopeCell on. The operator arrives with the tool listed, its scope row reading "Any arguments ·
 * unrestricted", and the Narrow it button one click away.
 *
 * The agent class is left EMPTY on purpose. It is the one thing this page cannot know — a tool is
 * not owned by a class — and inventing one would produce a policy targeting an agent that may not
 * exist. The builder already gates Save on it and says so in words ("Set an agent class first."),
 * which is the correct place for that prompt.
 */
function scopeHandoffGraph(toolName: string): BuilderGraph {
  return {
    schemaVersion: 1,
    scope: { kind: "class", agentClass: "" },
    mode: "allowlist",
    rules: [],
    defaults: { decision: "block", reason: "No builder rule matched" },
    allowlist: {
      tools: [toolName],
      refinements: { readonly: false, egress: false, scope: false, rate: false },
      grants: []
    }
  };
}

/** Exactly the windows `GET /api/v1/tools` accepts. See D4 in the implementation log for why the page
 *  carries its own control instead of using the global header selector, which offers 1h/6h. */
const RANGES = [
  { value: "24h" as const, label: "24h" },
  { value: "7d" as const, label: "7d" },
  { value: "30d" as const, label: "30d" },
  { value: "90d" as const, label: "90d" }
];
type Range = (typeof RANGES)[number]["value"];

/** A row needs a human look when the scanner condemned it OR its name is not what it appears to be. */
export function isFlagged(t: ToolRegistryEntry): boolean {
  const severe = t.scan_severity === "high" || t.scan_severity === "critical";
  return severe || t.name_skeleton.toLowerCase() !== t.name.toLowerCase();
}

/**
 * WHAT THIS PAGE MAY AND MAY NOT SAY ABOUT "withheld".
 *
 * `description_withheld` is a SERVER-side measurement: `tools.py::_description_is_withheld` compares
 * `scan_severity` against this deployment's real `mcp_scan_sanitize_severity`/`mcp_scan_strip_severity`
 * and the row ships the answer. It is a fact about the DESCRIPTION TEXT and nothing else — at the
 * shipped defaults it is true from MEDIUM up, while the tool itself is only stripped from HIGH up.
 *
 * The row pill used to read "Withheld" off that flag, in red, next to the tool name. On MCP Servers
 * the same word is `withheldReason` — pin drifted, pin never approved, or a scanner grade at or above
 * the strip threshold — i.e. THE TOOL IS OFF. So at MEDIUM, Tools shouted "Withheld" over a tool MCP
 * Servers correctly called "Approved. The served definition matches the approved one", and at HIGH,
 * where the tool really had been stripped, Tools said only that its description was hidden and still
 * offered "Scope this tool in a policy". One word, two definitions, wrong in both directions.
 *
 * The rule adopted here: the description flag gets its own words, and the word "Withheld" is reserved
 * for THE TOOL being off — the same three reasons `McpServers.tsx::withheldReason` counts, in the same
 * order, so the two pages give one answer to "can the model still call this".
 *
 * WHY THE PREDICATE IS RESTATED RATHER THAN IMPORTED: `/tools` does not serve the strip judgement (see
 * `_declared_row`, tools.py:103-137 — `pin_status` and `scan_severity`, no scanner action), and the two
 * pages are separately code-split routes (App.tsx:22-23), so importing McpServers here would pull its
 * module into the /tools chunk. `Tools.test.tsx` therefore asserts the two implementations agree by
 * running the SAME fixture through `withheldReason` — if either drifts, that test goes red. The real
 * repair is the server shipping the scanner's action alongside `description_withheld`, at which point
 * both of these should be deleted in favour of reading it.
 *
 * The threshold caveat travels with the claim: this console is not told which `mcp_scan_strip_severity`
 * a cluster runs, so the scanner branch is stated as the default and labelled as such, exactly as
 * McpServers does. A guess rendered as a measurement, in the direction that stops the operator looking,
 * is the failure this page exists to avoid.
 */
function scannerCondemned(t: ToolRegistryEntry): boolean {
  return t.scan_severity === "high" || t.scan_severity === "critical";
}

/** True when THE TOOL — not merely its description — is withheld from the model. Mirrors
 *  `McpServers.tsx::withheldReason() !== null`; only declared rows have a pin to judge. */
export function toolIsWithheld(t: ToolRegistryEntry): boolean {
  if (t.source !== "mcp_declared") return false;
  return t.pin_status !== "pinned" || scannerCondemned(t);
}

/** What an operator loses by having no definition for this tool. Specific beats generic. */
function costsYou(name: string): string {
  if (/^http|fetch|request|curl/i.test(name)) return "Destination hosts cannot be restricted";
  if (/sql|query|select/i.test(name)) return "Cannot restrict which statements or tables it touches";
  if (/mail|email|dm|message|notify|send/i.test(name)) return "Cannot restrict recipients";
  if (/search|vector|kb|lookup/i.test(name)) return "Query text cannot be inspected";
  if (/file|read|write|path/i.test(name)) return "Cannot restrict which paths it reaches";
  return "Arguments cannot be constrained — only the name can be matched";
}

function argCount(t: ToolRegistryEntry): string {
  if (!t.schema_available || !t.input_schema) return "—";
  const paths = schemaPaths(t.input_schema);
  return `${paths.filter((p) => p.addressable).length} of ${paths.length}`;
}

export function Tools() {
  const { namespace } = useApp();
  const ns = namespace || "all";
  const [range, setRange] = useState<Range>("30d");
  const [selected, setSelected] = useState<string | null>(null);

  const loader = useCallback(() => fetchTools(ns, range), [ns, range]);
  const { data, error, loading, refetch } = useApi<ToolRegistryEntry[]>(loader, [ns, range], {
    cacheKey: `tools:${ns}:${range}`,
    staleTimeMs: 5000
  });

  const rows = useMemo(() => data ?? [], [data]);
  const declared = useMemo(() => rows.filter((t) => t.source === "mcp_declared"), [rows]);
  const observed = useMemo(() => rows.filter((t) => t.source === "observed"), [rows]);

  /**
   * Names served by more than one DISTINCT server. The API returns a row per pin and nothing merges
   * them, and a policy naming the tool governs every one of them because the engine only ever sees
   * the bare name.
   *
   * DISTINCT is the whole correctness of this block. A pin's identity is `(namespace, server_id,
   * tool_name)` — `McpToolPin`'s primary key — so ONE server pinned in two namespaces returns two
   * rows carrying the SAME `server_id`. Bucketing rows and testing `length > 1` reported that as two
   * servers publishing one name, which is the shadowing/impersonation signal this note exists to
   * raise, and then prescribed `mcp.server` as the remedy — which cannot separate two namespaces.
   * A `Set` makes the count the number of servers rather than the number of rows.
   */
  const collisions = useMemo(() => {
    const byName = new Map<string, Set<string>>();
    for (const t of declared) {
      const set = byName.get(t.name) ?? new Set<string>();
      if (t.server_id) set.add(t.server_id);
      byName.set(t.name, set);
    }
    return new Map(
      [...byName]
        .filter(([, servers]) => servers.size > 1)
        .map(([name, servers]) => [name, [...servers].sort()] as [string, string[]])
    );
  }, [declared]);

  /** Whether the view spans more than one namespace — true on the default "All namespaces" scope. Two
   *  declared rows differing only by namespace are otherwise character-for-character identical. */
  const multiNamespace = useMemo(() => new Set(declared.map((t) => t.namespace)).size > 1, [declared]);

  const rowKey = (t: ToolRegistryEntry) => `${t.namespace}/${t.server_id ?? "-"}/${t.name}`;
  const current = rows.find((t) => rowKey(t) === selected) ?? null;

  if (loading) {
    return (
      <div className="page-enter stack">
        <PageHead title="Tools" subtitle="Every tool Norviq knows about in this namespace, and how it knows about it." />
        <Panel>
          <div style={{ display: "grid", placeItems: "center", padding: 40, gap: 12 }} data-testid="tools-loading">
            <BrandLoader />
            <div className="muted" style={{ fontSize: 12.5 }}>Reading the tool registry…</div>
          </div>
        </Panel>
      </div>
    );
  }

  // A failed read is NOT an empty registry, and the difference is the whole point of the distinction.
  // "We could not check" must never render as "there is nothing here" — an operator who reads absence as
  // an all-clear will conclude a namespace has no tools when in fact nothing was asked.
  if (error) {
    return (
      <div className="page-enter stack">
        <PageHead
          title="Tools"
          subtitle="Every tool Norviq knows about in this namespace, and how it knows about it."
          actions={<KitButton variant="outline" icon={RefreshCw} onClick={refetch}>Retry</KitButton>}
        />
        <Panel data-testid="tools-error">
          <div style={{ display: "flex", gap: 12, alignItems: "flex-start" }}>
            <AlertTriangle size={18} style={{ color: "var(--block)", flex: "none", marginTop: 2 }} />
            <div>
              <div style={{ fontSize: 15, fontWeight: 600, marginBottom: 5 }}>Couldn&rsquo;t read the tool registry</div>
              <p className="muted" style={{ fontSize: 12.5, lineHeight: 1.6, margin: 0 }}>
                Not the same as &ldquo;there are none&rdquo;. Treat any absence as unknown, not an all-clear —
                policies already written keep enforcing, and a tool can still be named in a new one.
              </p>
              <div className="mono" style={{ fontSize: 11.5, color: "var(--text-faint)", marginTop: 8 }}>{error}</div>
            </div>
          </div>
        </Panel>
      </div>
    );
  }

  return (
    <div className="page-enter stack">
      <PageHead
        title="Tools"
        subtitle="Every tool Norviq knows about in this namespace, and how it knows about it."
        actions={
          <div style={{ display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
            <SegmentedControl
              options={RANGES}
              value={range}
              onChange={setRange}
              ariaLabel="Observed window"
              data-testid="tools-range"
            />
            <span className="muted" style={{ fontSize: 11.5 }}>observed window</span>
            <KitButton variant="outline" icon={RefreshCw} onClick={refetch}>Refresh</KitButton>
          </div>
        }
      />

      <div className="grid grid-cols-2 md:grid-cols-5 gap-5" data-testid="tools-totals">
        <StatTile label="Tools known" value={rows.length} />
        <StatTile label="Declared" value={declared.length} />
        <StatTile
          label="Scopeable"
          value={declared.filter((t) => t.schema_available).length}
          color={declared.some((t) => t.schema_available) ? "var(--allow)" : undefined}
        />
        <StatTile
          label="Observed only"
          value={observed.length}
          color={observed.length ? "var(--escalate)" : undefined}
        />
        <StatTile
          label="Flagged"
          value={rows.filter(isFlagged).length}
          color={rows.some(isFlagged) ? "var(--block)" : undefined}
        />
      </div>

      {/* FULL WIDTH. The detail used to occupy a third of the page and stood empty until a row was
          clicked, so the two tables — the thing you actually came to read — ran at 620px with their
          argument counts and timestamps crushed against each other. Detail is a modal now, which is
          also the honest shape for it: reading one tool is a drill-in, not a persistent companion. */}
      <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
        <DeclaredPanel
          rows={declared}
          collisions={collisions}
          showNamespace={multiNamespace}
          selected={selected}
          onSelect={(t) => setSelected(rowKey(t) === selected ? null : rowKey(t))}
          rowKey={rowKey}
        />
        <ObservedPanel
          rows={observed}
          selected={selected}
          onSelect={(t) => setSelected(rowKey(t) === selected ? null : rowKey(t))}
          rowKey={rowKey}
        />
        {/* Both of these stay OUT of the modal, deliberately. They are answers to questions you have
            before you know which row to click: "why does one name appear twice" and "why is this
            empty". Putting them behind a click would mean the reader has to already suspect the thing
            the note exists to tell them. */}
        {collisions.size > 0 && <CollisionNote collisions={collisions} />}
        <NothingSelected empty={rows.length === 0} />
      </div>

      {/* Rendered AFTER the tables and outside every <Panel>: `.panel` sets `backdrop-filter`, which
          makes it a containing block for `position: fixed` and would trap the dialog under the page
          chrome. Three other call sites in this codebase carry the same warning. */}
      {current && (
        <Modal
          wide
          data-testid="tool-detail"
          title={
            <span className="mono" style={{ fontSize: 15 }}>
              {current.server_id ? `${current.server_id} / ` : ""}
              {current.name}
            </span>
          }
          onClose={() => setSelected(null)}
        >
          <ToolDetail tool={current} />
        </Modal>
      )}
    </div>
  );
}

// --- panels -------------------------------------------------------------------------------------------

interface TableProps {
  rows: ToolRegistryEntry[];
  selected: string | null;
  onSelect: (t: ToolRegistryEntry) => void;
  rowKey: (t: ToolRegistryEntry) => string;
}

function CountPill({ n, tone, label }: { n: number; tone: string; label: string }) {
  return (
    <span className="pill" style={{ background: `${tone}15`, color: tone, borderColor: `${tone}30` }}>
      {n} · {label}
    </span>
  );
}

function DeclaredPanel({
  rows,
  collisions,
  showNamespace,
  selected,
  onSelect,
  rowKey
}: TableProps & { collisions: Map<string, string[]>; showNamespace: boolean }) {
  // Only when the view actually spans namespaces. On a single-namespace scope the column would be one
  // repeated value taking width from the digest/argument columns; on "All namespaces" its absence
  // leaves two rows for the same server, pinned twice, byte-identical on screen.
  const template = showNamespace ? DECLARED_TEMPLATE_NS : DECLARED_TEMPLATE;
  const cols = showNamespace
    ? ["Tool", "Scope", "Namespace", "Server", "Pin", "Scan", "Arguments", "Last seen"]
    : ["Tool", "Scope", "Server", "Pin", "Scan", "Arguments", "Last seen"];
  return (
    <Panel
      data-testid="tools-declared"
      title={
        <span style={{ display: "inline-flex", alignItems: "center", gap: 8 }}>
          Declared{" "}
          {/* "N · schema-backed" labelled EVERY declared row schema-backed, and this file's own header
              spends a paragraph on the third state where that is false: declared, pinned, and still
              unscopeable because a long description evicted `inputSchema` from the 8 KiB canonical
              slice. On the seeded estate the panel said "5 · schema-backed" three inches under a
              "Scopeable 4" tile computed from `schema_available` — one quantity, two definitions, the
              louder one wrong. The count of the panel is still the row count; the qualifier now counts
              what it claims to, off the same predicate as the tile. */}
          <CountPill
            n={rows.length}
            tone="#2ddab8"
            label={`${rows.filter((t) => t.schema_available).length} schema-backed`}
          />
        </span>
      }
      // The old line — "…and an operator approved it" — was false of the panel's own contents.
      // `/tools` emits a `mcp_declared` row for EVERY `McpToolPin` (tools.py:182), and a pin written
      // on a first `tools/list` in strict mode has `approved=False` (mcp.py:157-165). So a definition
      // no human has ever looked at was filed in the strong tier under a sentence saying a human had.
      // Publication and approval are two facts; the panel is keyed on the first and shows the second
      // per row.
      sub="An MCP server published a definition. Approval is per row — a drifted or unapproved pin is withheld from the model. Arguments can be scoped where a schema survived."
    >
      {rows.length === 0 ? (
        <div className="muted" style={{ fontSize: 12.5, lineHeight: 1.6 }} data-testid="tools-declared-empty">
          Nothing published in this namespace yet, so no tool here can be scoped by argument. A server
          appears the first time an agent runs a <span className="mono">tools/list</span> through the proxy.
        </div>
      ) : (
        <div style={{ overflowX: "auto" }}>
          <div style={{ minWidth: showNamespace ? 944 : 840 }}>
            <HeadRow cols={cols} template={template} />
            {rows.map((t) => (
              <button
                key={rowKey(t)}
                type="button"
                data-testid={`tool-row-${t.server_id}-${t.name}`}
                // The testid omits the namespace for continuity with every existing caller; this
                // carries the full pin identity so two rows that differ only by namespace are still
                // separately addressable.
                data-rowkey={rowKey(t)}
                onClick={() => onSelect(t)}
                aria-pressed={rowKey(t) === selected}
                style={rowStyle(rowKey(t) === selected, template)}
              >
                <span className="mono" style={{ display: "inline-flex", alignItems: "center", gap: 6, minWidth: 0 }}>
                  <span style={{ overflow: "hidden", textOverflow: "ellipsis" }}>{t.name}</span>
                  {t.name_skeleton.toLowerCase() !== t.name.toLowerCase() && (
                    <AlertTriangle
                      size={13}
                      style={{ color: "var(--block)", flex: "none" }}
                      aria-label={`Name differs from its evasion-normalised skeleton ${t.name_skeleton}`}
                    />
                  )}
                  {/* The COUNT, never a literal. Three servers publishing one name reported as "2
                      servers" tells an operator sizing the blast radius that the set is closed at
                      two, so they verify two rows and stop. */}
                  {collisions.has(t.name) && (
                    <MiniPill hex="#ffb020">{collisions.get(t.name)!.length} servers</MiniPill>
                  )}
                  {/* "Withheld" alone read as the tool being off, which is a different predicate on a
                      different page — see the note above `scannerCondemned`. This pill says only what
                      the flag means, and amber rather than red because a sanitised description is not
                      the capability being gone. */}
                  {t.description_withheld && (
                    <MiniPill hex="#ffb020" data-testid="tool-pill-description-withheld">
                      Description withheld
                    </MiniPill>
                  )}
                  {toolIsWithheld(t) && (
                    <MiniPill hex="#ff3b5c" data-testid="tool-pill-withheld">
                      Withheld
                    </MiniPill>
                  )}
                </span>
                <span><ScopeabilityBadge source="mcp_declared" schemaAvailable={t.schema_available} /></span>
                {showNamespace && <span className="mono muted">{t.namespace}</span>}
                <span className="mono muted">{t.server_id ?? "—"}</span>
                <span><PinPill status={t.pin_status} /></span>
                <span><ScanPill severity={t.scan_severity} /></span>
                <span className="muted">{argCount(t)}</span>
                <span className="mono muted">{t.last_seen_at ? new Date(t.last_seen_at).toLocaleString() : "—"}</span>
              </button>
            ))}
          </div>
        </div>
      )}
    </Panel>
  );
}

function ObservedPanel({ rows, selected, onSelect, rowKey }: TableProps) {
  return (
    <Panel
      data-testid="tools-observed"
      title={
        <span style={{ display: "inline-flex", alignItems: "center", gap: 8 }}>
          Observed only <CountPill n={rows.length} tone="#ffb020" label="name only" />
        </span>
      }
      sub="No definition — allow or deny by name only."
    >
      {rows.length === 0 ? (
        <div className="muted" style={{ fontSize: 12.5 }} data-testid="tools-observed-empty">
          No undeclared tool has been called in this window.
        </div>
      ) : (
        <div style={{ overflowX: "auto" }}>
          <div style={{ minWidth: 670 }}>
            <HeadRow cols={["Tool", "Scope", "What this costs you", ""]} template="minmax(150px,1.5fr) 116px minmax(190px,1.6fr) 130px" />
            {rows.map((t) => (
              <button
                key={rowKey(t)}
                type="button"
                data-testid={`tool-row-observed-${t.name}`}
                onClick={() => onSelect(t)}
                aria-pressed={rowKey(t) === selected}
                style={rowStyle(rowKey(t) === selected, "minmax(150px,1.5fr) 116px minmax(190px,1.6fr) 130px")}
              >
                <span className="mono" style={{ display: "inline-flex", alignItems: "center", gap: 6 }}>
                  {t.name}
                  {t.name_skeleton.toLowerCase() !== t.name.toLowerCase() && <MiniPill hex="#ff3b5c">Homoglyph</MiniPill>}
                </span>
                <span><ScopeabilityBadge source="observed" schemaAvailable={false} /></span>
                <span className="muted">{costsYou(t.name)}</span>
                <span className="muted" style={{ fontSize: 12 }}>View in Audit Log →</span>
              </button>
            ))}
          </div>
        </div>
      )}
    </Panel>
  );
}

// --- detail -------------------------------------------------------------------------------------------

/**
 * The body of the tool dialog.
 *
 * No Panel and no `data-testid` of its own: the `Modal` that hosts it carries `tool-detail`, and the
 * name is already the dialog's title. Two nested cards and the name printed twice is what you get if
 * a side panel is dropped into a dialog unchanged.
 */
function ToolDetail({ tool }: { tool: ToolRegistryEntry }) {
  const declared = tool.source === "mcp_declared";
  return (
    <>
      <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginBottom: 12 }}>
        <ProvenanceBadge source={tool.source} />
        <ScopeabilityBadge source={tool.source} schemaAvailable={tool.schema_available} />
        {tool.pin_status && <PinPill status={tool.pin_status} />}
      </div>

      {/* FIRST, above the description and the argument tree.
          `ProvenanceBadge`'s teal "Declared" carries the title "An MCP server published this definition
          and an operator approved it", and this dialog used to say nothing that contradicted it — so a
          vendor definition nobody had ever reviewed read as human-blessed, with its argument tree
          presented as "Arguments a policy can address" and a Scope CTA under it. The amber `quarantined`
          PinPill was the only dissent, and a status word does not outrank a sentence.
          The words match MCP Servers' `withheldReason` branch for branch, deliberately. */}
      {toolIsWithheld(tool) && (
        <Callout tone="#ff3b5c" title="Withheld from the model" data-testid="tool-withheld">
          {tool.pin_status === "drift" && (
            <div>
              This server is serving a definition that <strong>differs from the approved one</strong>, so the
              proxy strips this tool from every <span className="mono">tools/list</span> and calls to it are
              refused. Nothing below has been reviewed against what is being served now.
            </div>
          )}
          {tool.pin_status !== "drift" && tool.pin_status !== "pinned" && (
            <div>
              <strong>No operator has approved this definition.</strong> The proxy strips this tool from every{" "}
              <span className="mono">tools/list</span> and calls to it are refused. The description and
              arguments below are the server&rsquo;s own text, published by it and not yet reviewed.
            </div>
          )}
          {scannerCondemned(tool) && (
            <div style={{ marginTop: tool.pin_status !== "pinned" ? 6 : 0 }}>
              The definition scanner graded this tool {String(tool.scan_severity).toUpperCase()}. At the
              default <span className="mono">mcp_scan_strip_severity</span> (high) a grade this high strips the
              tool whatever the pin says.{" "}
              {/* Stated as the default, not as a reading of this cluster: no endpoint serves
                  `mcp_scan_strip_severity` to the console. McpServers carries the same caveat. */}
              <span style={{ color: "var(--text-muted)" }}>
                This console is not told which threshold this cluster runs, so if it was raised the tool is
                still being handed to the model and the grade is the only fact here.
              </span>
            </div>
          )}
          <div style={{ marginTop: 6 }}>
            <Link to="/mcp" style={{ color: "#ff3b5c" }}>
              Review its pin on MCP Servers →
            </Link>
          </div>
        </Callout>
      )}

      {tool.description_withheld ? (
        // The stored definition holds the PRE-sanitize text — the payload the firewall stripped before
        // the model saw it. Showing the fact of withholding is the whole affordance; showing the text
        // would put the attack in front of the operator instead of the model.
        <Callout tone="#ffb020" title="Description withheld" data-testid="tool-description-withheld">
          The definition scanner condemned this tool&rsquo;s <strong>description</strong>, so the description
          is not shown here and was not passed to the model. This says nothing about whether the tool
          itself is still callable — the sanitize threshold is lower than the strip threshold. Review the
          finding on MCP Servers.
        </Callout>
      ) : (
        tool.description && (
          <p className="muted" style={{ fontSize: 12.5, lineHeight: 1.6, margin: "0 0 12px" }}>{tool.description}</p>
        )
      )}

      {declared && !tool.schema_available && (
        <Callout tone="#ffb020" title="Declared, but unscopeable">
          {/* "Approved definition" was the same false claim the panel subtitle made — this panel holds
              never-approved pins too. The pin state is on the badge row above and in its own callout. */}
          Declared definition, no argument schema — a long description evicted it from the 8&nbsp;KiB slice.
          Allow or deny by name, or hand-write a path you know. The registry informs, never restricts.
        </Callout>
      )}

      {!declared && (
        <Callout tone="#ffb020" title="What that costs you">
          {costsYou(tool.name)}. Whole-call facts still work; per-argument scoping does not. Route it through
          the MCP proxy to get a definition.
        </Callout>
      )}

      {declared && tool.schema_available && (
        <>
          <div style={{ fontSize: 11, fontWeight: 600, letterSpacing: ".07em", textTransform: "uppercase", color: "var(--text-secondary)", margin: "14px 0 4px" }}>
            Arguments a policy can address
          </div>
          <div className="muted" style={{ fontSize: 12, marginBottom: 8 }}>
            Unusable ones are shown, never hidden.
            {/* TWO unpinned states, and they are opposites about where this tree came from — one
                sentence for both was wrong for one of them.
                `_declared_row` reads `approved_canonical`, never `last_canonical`. On a NEVER-APPROVED
                pin those are the same string (mcp.py:157-165 writes both at first sight with
                `approved=False`), so the tree really is the server's own unreviewed text. On a DRIFTED
                pin they are not: the tree is the pinned baseline, and what the server is serving now is
                something else — so "no operator has approved these paths, the server chose them"
                contradicted the drift callout six lines above, which had just said the tree is what was
                approved and the SERVED definition is the unknown one.
                Neither branch says "an operator approved this": `_status_of` (mcp.py:112-118) returns
                `drift` before it looks at `approved`, so a first-sighting that later changed reports
                drift with `approved=False` — and `/tools` ships `pin_status` without `approved`, so this
                page cannot tell those apart and must not claim to. */}
            {tool.pin_status === "drift" && (
              <span data-testid="tool-args-stale" style={{ color: "var(--escalate)" }}>
                {" "}
                These paths come from the pinned definition, not from the one this server is serving now —
                the two differ, which is why the tool is withheld.
              </span>
            )}
            {tool.pin_status !== "pinned" && tool.pin_status !== "drift" && (
              <span data-testid="tool-args-unreviewed" style={{ color: "var(--escalate)" }}>
                {" "}
                These paths come from a definition no operator has approved — the server chose them.
              </span>
            )}
          </div>
          <ArgumentTree schema={tool.input_schema} suppressDescriptions={tool.description_withheld} />
        </>
      )}

      <div style={{ display: "flex", flexDirection: "column", gap: 8, marginTop: 14 }}>
        {/* The reverse direction of the P1 fix: the operator arrives at a tool and leaves with a policy
            that narrows it, rather than discovering scoping by accident inside the builder. */}
        <Link
          to="/policies/catalog"
          state={{ builderGraph: scopeHandoffGraph(tool.name), fromTools: true }}
          data-testid="tool-detail-scope-cta"
          className="btn btn-primary"
          style={{ textDecoration: "none", justifyContent: "center" }}
        >
          Scope this tool in a policy →
        </Link>
        {/* NOT suppressed: deny-by-default requires authoring rules for tools nobody has approved, and
            gating the CTA on pin state would make the registry restrict rather than inform — the thing
            ProvenanceBadge's header forbids. It gets a visible caveat instead, because the schema the
            builder would seed from is the server's, not a reviewed one. */}
        {toolIsWithheld(tool) && (
          <div
            data-testid="tool-scope-cta-caveat"
            className="muted"
            style={{ fontSize: 12, lineHeight: 1.55, marginTop: -2 }}
          >
            You can still write it — a policy may name any tool. But this one is withheld from the model
            for the reason stated above, so the rule will not be exercised until that is resolved on MCP
            Servers.
          </div>
        )}
        {tool.server_id && (
          <Link to="/mcp" className="btn btn-outline" style={{ textDecoration: "none", justifyContent: "center" }}>
            <ExternalLink size={14} /> View its pin on MCP Servers
          </Link>
        )}
      </div>
    </>
  );
}

/**
 * Always rendered, in the page body — never inside the dialog.
 *
 * With no tools at all it is the page's whole explanation, and there is no row to click that could
 * reveal it. With tools present it is one line telling you a row is clickable, which is exactly the
 * thing a modal cannot advertise about itself.
 */
function NothingSelected({ empty }: { empty: boolean }) {
  if (!empty) {
    return (
      <div
        data-testid="tool-detail-empty"
        className="muted"
        style={{ fontSize: 12.5, lineHeight: 1.6, padding: "0 2px" }}
      >
        Select a tool to see how well Norviq knows it, and which of its arguments a policy can address.
      </div>
    );
  }
  return (
    <Panel data-testid="tool-detail-empty">
      <div className="muted" style={{ fontSize: 12.5, lineHeight: 1.6 }}>
        Norviq doesn&rsquo;t know about any tools here yet. Tools arrive two ways, and they are not
        equivalent: declared through the MCP proxy with a schema, so arguments can be scoped — or merely
        observed in a real call, which proves the name exists and nothing more.
      </div>
      <div className="muted" style={{ fontSize: 12.5, marginTop: 10 }}>
        You needn&rsquo;t wait for either — a policy can name a tool nobody has called.
      </div>
    </Panel>
  );
}

/**
 * One line per colliding NAME, each carrying its own server count.
 *
 * The count and the word "both" were both string literals, so three servers publishing `search` read
 * as two — and "both" asserts the set is closed at two, which is exactly the number an operator
 * sizing the blast radius of a policy would go on to verify before stopping. The title said "two"
 * for the same reason.
 */
function CollisionNote({ collisions }: { collisions: Map<string, string[]> }) {
  const entries = [...collisions.entries()];
  const allTwo = entries.every(([, servers]) => servers.length === 2);
  return (
    <Panel
      title={allTwo ? "One name, two servers" : "One name, several servers"}
      sub="Not a duplicate — the key is (namespace, server_id, tool_name)."
      data-testid="tools-collision"
    >
      <div className="muted" style={{ fontSize: 12.5, lineHeight: 1.6 }}>
        {entries.map(([name, servers]) => (
          <div key={name} style={{ marginBottom: entries.length > 1 ? 6 : 0 }}>
            A policy naming <span className="mono" style={{ color: "var(--text-primary)" }}>{name}</span> governs{" "}
            <strong style={{ color: "var(--text-primary)" }}>
              {servers.length === 2 ? "both" : `all ${servers.length}`}
            </strong>{" "}
            (<span className="mono">{servers.join(", ")}</span>) — the engine sees the bare name. Add{" "}
            <span className="mono">mcp.server</span> to separate them.
          </div>
        ))}
      </div>
    </Panel>
  );
}

// --- small shared bits --------------------------------------------------------------------------------

const DECLARED_TEMPLATE = "minmax(160px,1.5fr) 116px 104px 92px 84px 92px 108px";
/** Same, with a Namespace column ahead of Server — used only when the view spans namespaces. */
const DECLARED_TEMPLATE_NS = "minmax(160px,1.5fr) 116px 104px 104px 92px 84px 92px 108px";

function HeadRow({ cols, template = DECLARED_TEMPLATE }: { cols: string[]; template?: string }) {
  return (
    <div
      style={{
        display: "grid",
        gridTemplateColumns: template,
        gap: 12,
        padding: "0 18px 8px",
        fontSize: 11,
        fontWeight: 500,
        color: "var(--text-secondary)"
      }}
    >
      {cols.map((c, i) => (
        <span key={`${c}-${i}`}>{c}</span>
      ))}
    </div>
  );
}

function rowStyle(selected: boolean, template = DECLARED_TEMPLATE) {
  return {
    display: "grid",
    // `minmax()` rather than a bare `fr`: with `fr`, each row is its own grid and the columns resolve to
    // per-row min-content once the table overflows, so the rows visibly stop lining up.
    gridTemplateColumns: template,
    gap: 12,
    alignItems: "center",
    width: "100%",
    padding: "9px 18px",
    borderTop: "1px solid var(--border)",
    borderLeft: selected ? "2px solid var(--accent)" : "2px solid transparent",
    background: selected ? "var(--bg-surface-hover)" : "transparent",
    fontSize: 13,
    textAlign: "left" as const,
    color: "var(--text-primary)",
    cursor: "pointer",
    fontFamily: "inherit"
  };
}

function MiniPill({
  hex,
  children,
  "data-testid": testId
}: {
  hex: string;
  children: React.ReactNode;
  "data-testid"?: string;
}) {
  return (
    <span
      data-testid={testId}
      style={{
        flex: "none",
        fontSize: 10,
        fontWeight: 600,
        padding: "2px 6px",
        borderRadius: 4,
        background: `${hex}15`,
        color: hex,
        border: `1px solid ${hex}30`
      }}
    >
      {children}
    </span>
  );
}

function PinPill({ status }: { status: string | null }) {
  if (!status) return <span className="muted">—</span>;
  const hex = status === "drift" ? "#ff3b5c" : status === "quarantined" ? "#ffb020" : "#00e5a0";
  return (
    <span className="pill" style={{ background: `${hex}15`, color: hex, borderColor: `${hex}30` }}>
      {status}
    </span>
  );
}

function ScanPill({ severity }: { severity: string | null }) {
  if (!severity) return <span className="muted">—</span>;
  // `none` as the muted word "clean" rather than a green pill: a clean scan is the expected case, and
  // giving it the same visual weight as a critical finding flattens the thing the column exists to show.
  if (severity === "none") return <span className="muted">clean</span>;
  const hex = severity === "critical" || severity === "high" ? "#ff3b5c" : "#ffb020";
  return (
    <span className="pill" style={{ background: `${hex}15`, color: hex, borderColor: `${hex}30` }}>
      {severity}
    </span>
  );
}

function Callout({
  tone,
  title,
  children,
  "data-testid": testId
}: {
  tone: string;
  title: string;
  children: React.ReactNode;
  "data-testid"?: string;
}) {
  return (
    <div data-testid={testId} style={{ padding: 12, borderRadius: 10, border: `1px solid ${tone}30`, background: `${tone}15`, marginBottom: 12 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 7, fontSize: 13, fontWeight: 600, color: tone, marginBottom: 5 }}>
        <Info size={14} /> {title}
      </div>
      <div className="muted" style={{ fontSize: 12.5, lineHeight: 1.55 }}>{children}</div>
    </div>
  );
}
