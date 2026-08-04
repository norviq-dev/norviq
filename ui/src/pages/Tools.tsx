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
import { schemaPaths } from "../lib/toolSchema";
import { useApp } from "../store/AppContext";

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

  /** Names served by more than one server. The API returns both rows; nothing merges them, and a policy
   *  naming the tool governs BOTH because the engine only ever sees the bare name. */
  const collisions = useMemo(() => {
    const byName = new Map<string, string[]>();
    for (const t of declared) {
      const list = byName.get(t.name) ?? [];
      if (t.server_id) list.push(t.server_id);
      byName.set(t.name, list);
    }
    return new Map([...byName].filter(([, servers]) => servers.length > 1));
  }, [declared]);

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
        {collisions.size > 0 && <CollisionNote names={[...collisions.keys()]} />}
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

function DeclaredPanel({ rows, collisions, selected, onSelect, rowKey }: TableProps & { collisions: Map<string, string[]> }) {
  return (
    <Panel
      data-testid="tools-declared"
      title={
        <span style={{ display: "inline-flex", alignItems: "center", gap: 8 }}>
          Declared <CountPill n={rows.length} tone="#2ddab8" label="schema-backed" />
        </span>
      }
      sub="An MCP server published a definition and an operator approved it. Arguments can be scoped."
    >
      {rows.length === 0 ? (
        <div className="muted" style={{ fontSize: 12.5, lineHeight: 1.6 }} data-testid="tools-declared-empty">
          Nothing published in this namespace yet, so no tool here can be scoped by argument. A server
          appears the first time an agent runs a <span className="mono">tools/list</span> through the proxy.
        </div>
      ) : (
        <div style={{ overflowX: "auto" }}>
          <div style={{ minWidth: 840 }}>
            <HeadRow cols={["Tool", "Scope", "Server", "Pin", "Scan", "Arguments", "Last seen"]} />
            {rows.map((t) => (
              <button
                key={rowKey(t)}
                type="button"
                data-testid={`tool-row-${t.server_id}-${t.name}`}
                onClick={() => onSelect(t)}
                aria-pressed={rowKey(t) === selected}
                style={rowStyle(rowKey(t) === selected)}
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
                  {collisions.has(t.name) && <MiniPill hex="#ffb020">2 servers</MiniPill>}
                  {t.description_withheld && <MiniPill hex="#ff3b5c">Withheld</MiniPill>}
                </span>
                <span><ScopeabilityBadge source="mcp_declared" schemaAvailable={t.schema_available} /></span>
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

      {tool.description_withheld ? (
        // The stored definition holds the PRE-sanitize text — the payload the firewall stripped before
        // the model saw it. Showing the fact of withholding is the whole affordance; showing the text
        // would put the attack in front of the operator instead of the model.
        <Callout tone="#ff3b5c" title="Description withheld">
          The definition scanner condemned this tool&rsquo;s description, so it is not shown here and was
          withheld from the model. Review the finding on MCP Servers.
        </Callout>
      ) : (
        tool.description && (
          <p className="muted" style={{ fontSize: 12.5, lineHeight: 1.6, margin: "0 0 12px" }}>{tool.description}</p>
        )
      )}

      {declared && !tool.schema_available && (
        <Callout tone="#ffb020" title="Declared, but unscopeable">
          Approved definition, no argument schema — a long description evicted it from the 8&nbsp;KiB slice.
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
          </div>
          <ArgumentTree schema={tool.input_schema} suppressDescriptions={tool.description_withheld} />
        </>
      )}

      <div style={{ display: "flex", flexDirection: "column", gap: 8, marginTop: 14 }}>
        {/* The reverse direction of the P1 fix: the operator arrives at a tool and leaves with a policy
            that narrows it, rather than discovering scoping by accident inside the builder. */}
        <Link
          to="/policies/catalog"
          state={{ scopeTool: tool.name, fromTools: true }}
          data-testid="tool-detail-scope-cta"
          className="btn btn-primary"
          style={{ textDecoration: "none", justifyContent: "center" }}
        >
          Scope this tool in a policy →
        </Link>
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

function CollisionNote({ names }: { names: string[] }) {
  return (
    <Panel title="One name, two servers" sub="Not a duplicate — the key is (namespace, server_id, tool_name)." data-testid="tools-collision">
      <div className="muted" style={{ fontSize: 12.5, lineHeight: 1.6 }}>
        A policy naming <span className="mono" style={{ color: "var(--text-primary)" }}>{names.join(", ")}</span> governs{" "}
        <strong style={{ color: "var(--text-primary)" }}>both</strong> — the engine sees the bare name. Add{" "}
        <span className="mono">mcp.server</span> to separate them.
      </div>
    </Panel>
  );
}

// --- small shared bits --------------------------------------------------------------------------------

const DECLARED_TEMPLATE = "minmax(160px,1.5fr) 116px 104px 92px 84px 92px 108px";

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

function MiniPill({ hex, children }: { hex: string; children: React.ReactNode }) {
  return (
    <span
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

function Callout({ tone, title, children }: { tone: string; title: string; children: React.ReactNode }) {
  return (
    <div style={{ padding: 12, borderRadius: 10, border: `1px solid ${tone}30`, background: `${tone}15`, marginBottom: 12 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 7, fontSize: 13, fontWeight: 600, color: tone, marginBottom: 5 }}>
        <Info size={14} /> {title}
      </div>
      <div className="muted" style={{ fontSize: 12.5, lineHeight: 1.55 }}>{children}</div>
    </div>
  );
}
