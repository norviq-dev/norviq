// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// MCP Servers — the inventory of Model Context Protocol servers the agent estate talks to, and the
// approval state of every tool DEFINITION they serve.
//
// This is the console half of Gate A. The proxy withholds a poisoned or drifted definition from the
// model in the microseconds before it forwards `tools/list`; this screen is where the operator finds
// out that happened, sees exactly what changed, and decides whether to adopt the new definition.
// Without it the enforcement is real but invisible — the agent quietly loses a tool and nobody knows
// why, which is how a security control gets switched off.
//
// The SERVER list leads because it answers the first question a chatbot operator asks — "which MCP
// integrations are live, and is any of them misbehaving?" — before any per-tool detail.

import { CSSProperties, useCallback, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { AlertTriangle, CheckCircle2, Info, RefreshCw, ShieldAlert, ShieldCheck, Trash2, XCircle } from "lucide-react";
import { ApiError, apiGet, apiSend, fetchMe } from "../api/client";
import { Column, DataTable } from "../components/common/DataTable";
import { DefinitionDiff } from "../components/common/DefinitionDiff";
import { DestructiveConfirm } from "../components/common/DestructiveConfirm";
import { EvidenceBlock } from "../components/common/EvidenceBlock";
import { InlineDisabledReason } from "../components/common/InlineDisabledReason";
import { Modal } from "../components/common/Modal";
import { PageHead } from "../components/common/PageHead";
import { Panel } from "../components/common/Panel";
import { StatTile } from "../components/common/StatTile";
import { useToast } from "../components/common/Toast";
import { useApi } from "../hooks/useApi";
import { type Lookalike, lookalikeOf } from "../lib/predicateSentence";
import { useApp } from "../store/AppContext";

export type McpServerRow = {
  namespace: string;
  server_id: string;
  transport: string;
  tools: number;
  drifted: number;
  quarantined: number;
  flagged: number;
  worst_severity: string;
  health: string;
  first_seen_at: string | null;
  last_seen_at: string | null;
  [key: string]: unknown;
};

export type McpFinding = { rule: string; severity: string; field: string; evidence: string; detail: string };

export type McpPinRow = {
  namespace: string;
  server_id: string;
  tool_name: string;
  approved_digest: string;
  last_digest: string;
  approved: boolean;
  approved_by: string;
  approved_at: string | null;
  scan_severity: string;
  findings: McpFinding[];
  drift_count: number;
  status: string;
  approved_canonical: string;
  last_canonical: string;
  [key: string]: unknown;
};

/**
 * A pin's identity is COMPOSITE. Two servers may serve one tool name — `read_file` from `filesystem`
 * and from `runbooks` are different definitions, scanned and approved independently. Keying a row on
 * `tool_name` alone produced duplicate React keys and made selection unreachable; the engine, which
 * sees only the bare name, governs both with one policy. Both facts are surfaced below.
 */
export function pinKey(p: Pick<McpPinRow, "namespace" | "server_id" | "tool_name">): string {
  return `${p.namespace}/${p.server_id}/${p.tool_name}`;
}

// Reuses the DecisionBadge colour language so severity reads the same way it does everywhere else in
// the console: red = enforced against, amber = needs a human, green = fine.
const TONE: Record<string, CSSProperties> = {
  bad: { background: "#FF3B5C15", color: "#FF3B5C", borderColor: "#FF3B5C30" },
  warn: { background: "#FFB02015", color: "#FFB020", borderColor: "#FFB02030" },
  ok: { background: "#00E5A015", color: "#00E5A0", borderColor: "#00E5A030" },
  neutral: { background: "#7C5CFC15", color: "#7C5CFC", borderColor: "#7C5CFC30" }
};

const HEALTH_META: Record<string, { label: string; tone: string; icon: typeof ShieldCheck }> = {
  drift: { label: "definition changed", tone: "bad", icon: ShieldAlert },
  quarantined: { label: "awaiting approval", tone: "warn", icon: AlertTriangle },
  flagged: { label: "scanner findings", tone: "warn", icon: AlertTriangle },
  ok: { label: "healthy", tone: "ok", icon: ShieldCheck }
};

const STATUS_TONE: Record<string, string> = { drift: "bad", quarantined: "warn", pinned: "ok" };

function Pill({ text, tone, label }: { text: string; tone: string; label?: string }) {
  return (
    <span className="pill" style={TONE[tone] ?? TONE.neutral} aria-label={label}>
      {text}
    </span>
  );
}

/**
 * A name on this page is not the name it appears to be.
 *
 * THIS is the screen with the Approve button, so it is the screen where a lookalike becomes a
 * decision. A second server publishing `reаd_file` (Cyrillic а, U+0430) renders pixel-identical to the
 * `read_file` an operator already trusts, earns a "Withheld" pill that reads as "a normal tool
 * awaiting approval", and sits beside "Approve served definition".
 *
 * The detector is the console's existing one — `lookalikeOf` — reused rather than reinvented. What is
 * deliberately NOT done here is fold the collision buckets on a skeleton: `ui/src/lib/skeleton.ts`
 * says in its own header that it ports neither the cross-script confusables table nor Cf/Cc
 * stripping, so a browser-derived skeleton does NOT fold Cyrillic а to Latin a and would disagree
 * with the engine. `/mcp/pins` (`_row_dict`, mcp.py:90-109) ships no `name_skeleton` the way `/tools`
 * does. So this page states the fact it can measure exactly — these codepoints are not ASCII, and
 * here is where they sit — and never guesses which ASCII name the engine would fold them onto.
 */
function lookalikesOfPin(p: Pick<McpPinRow, "tool_name" | "server_id">): Lookalike[] {
  return [lookalikeOf(p.tool_name), lookalikeOf(p.server_id)].filter((l): l is Lookalike => l !== null);
}

/** The row mark. Visible text, never a `title` — a pill is not hoverable on touch and `.btn:disabled`
 *  taught this codebase that a tooltip is not a place to keep a security fact. */
function LookalikePill({ l }: { l: Lookalike }) {
  return (
    <Pill
      text="Lookalike"
      tone="bad"
      label={`Not the ASCII name it resembles: ${l.masked} carries ${l.codepoints.join(", ")}`}
    />
  );
}

/**
 * A tool name or server id printed inside the console's own prose, marked if it is not what it looks
 * like.
 *
 * The collision note names servers — it has to, or an operator cannot tell which definitions a policy
 * would govern. But `server_id` and `tool_name` are strings an MCP server chose, and printing
 * `governs both (filesystem, runbоoks)` in the product's own sentence is the product vouching for a
 * name it did not author. That is the exact failure the row pills exist to prevent, one paragraph
 * lower down the same panel, so the note uses the same mark.
 */
function MarkedName({ value }: { value: string }) {
  const l = lookalikeOf(value);
  return (
    <>
      <span className="mono" style={{ color: "var(--text-secondary)" }}>{value}</span>
      {l && (
        <>
          {" "}
          <LookalikePill l={l} />
        </>
      )}
    </>
  );
}

/**
 * WHY THIS PAGE DOES NOT RENDER THE SHARED `LookalikeNote`.
 *
 * `components/common/LookalikeNote` closes with "…so the rule grants the look-alike AND the
 * plain-ASCII tool of the same shape. Confirm you meant both before saving." That sentence is true on
 * the five authoring surfaces that render it (BuilderSheet ×2, RuleCard, NearMissCard, IntentModal) —
 * each has a rule and a Save. This dialog has neither: its controls are "Show full definitions" and
 * "Approve served definition", and approving pins one server's definition rather than writing any
 * allowlist. `Intents.tsx::ArgLookalikeNote` set the precedent and the reason — reusing the other
 * note's copy "would be a misstatement of what the engine does, which this codebase treats as worse
 * than no copy".
 *
 * So: same detector, same visual language, same `masked`-carries-`codepoints` line, and the
 * consequence restated for the control that is actually on this screen. The allowlist fact survives
 * because it is what makes approving consequential HERE — the engine matches
 * `allow_skeletons[input.tool_name_normalized]` and `norviq/engine/confusables.py::skeleton` folds
 * Cyrillic а to Latin a (verified: `skeleton("reаd_file") == "read_file"`), so this tool needs no
 * rule of its own to become reachable under a policy written for the name it imitates.
 */
function PinLookalikeNote({ lookalikes }: { lookalikes: Lookalike[] }) {
  if (lookalikes.length === 0) return null;
  return (
    <div
      data-testid="mcp-lookalike"
      style={{
        marginTop: 5,
        marginBottom: 14,
        padding: "7px 9px",
        borderRadius: 8,
        border: "1px solid #ff3b5c30",
        background: "#ff3b5c12",
        fontSize: 12,
        lineHeight: 1.5,
        color: "var(--text-secondary)"
      }}
    >
      <span
        className="pill"
        style={{ background: "#ff3b5c15", color: "#ff3b5c", borderColor: "#ff3b5c30", marginRight: 7 }}
      >
        Lookalike name
      </span>
      {lookalikes.map((l) => (
        <span key={l.value} style={{ display: "block", marginTop: 5 }}>
          <code className="mono" style={{ fontSize: 12 }}>
            {l.masked}
          </code>{" "}
          carries {l.codepoints.join(", ")} where an ASCII letter appears to be.
        </span>
      ))}
      <span style={{ display: "block", marginTop: 5 }}>
        Approving hands this name to the model as a callable tool. The engine matches tool allowlists
        evasion-normalised, so a policy written for the plain-ASCII tool of the same shape already grants
        this one — it does not need a rule of its own to be reachable. Check it against the server you
        expected to serve that name first: an identical-looking name from a second server is
        impersonation, not a duplicate.
      </span>
    </div>
  );
}

function severityTone(sev: string): string {
  return sev === "critical" || sev === "high" ? "bad" : sev === "none" ? "ok" : "warn";
}

/**
 * WHY the proxy is withholding this definition from the model, or `null` when it is not withholding it.
 *
 * THREE reasons, not two. The pin status accounts for only the first two: `norviq/mcp/firewall.py`
 * `_action_for` strips a tool whenever the scanner's grade reaches `mcp_scan_strip_severity` (default
 * `high`) REGARDLESS of pin status, so a tool can be approved, undrifted, and still absent from every
 * `tools/list`.
 *
 * This function is the single source of that judgement. It exists because the row badge and the
 * detail dialog used to decide it separately — the badge on all three reasons, the subtitle on pin
 * status alone — so a row badged "Withheld" opened a dialog that led with "Approved. The served
 * definition matches the approved one." Two opposite claims about one tool, on the surface built to
 * catch rug pulls, with the dialog winning because it is the detail view.
 */
export type WithheldReason = "drift" | "quarantined" | "scan";

/**
 * The DEFAULT strip threshold, and the reason the scanner branch may not speak in the indicative.
 *
 * `mcp_scan_strip_severity` is a setting (norviq/config.py), and nothing serves it to this console:
 * `/mcp/pins` returns `scan_severity` and `/settings` carries no `mcp_scan_*` field at all. So this
 * comparison is not a reading of the deployment — it is the shipped default, and on a cluster that
 * raised the threshold to `critical` a HIGH-graded tool is still handed to the model. Telling that
 * operator the tool is "withheld from the model and the model cannot call it" is a guess rendered as
 * a measurement, in the direction that stops them looking.
 */
const DEFAULT_STRIP_SEVERITY = "high";

export function withheldReason(p: McpPinRow): WithheldReason | null {
  if (p.status === "drift") return "drift";
  if (p.status !== "pinned") return "quarantined";
  if (p.scan_severity === "critical" || p.scan_severity === "high") return "scan";
  return null;
}

/** A definition withheld from the model is the tool being *off*, which the pin status alone does not
 *  say. `Withheld` next to the name is the operator-facing consequence of all three reasons above. */
function isWithheld(p: McpPinRow): boolean {
  return withheldReason(p) !== null;
}

/** The dialog's lead sentence. Keyed on {@link withheldReason}, never on `status` alone. */
function detailSubtitle(p: McpPinRow): string {
  switch (withheldReason(p)) {
    case "drift":
      return "This server is serving a definition that DIFFERS from the one approved. Calls to this tool are refused until an operator adopts the change.";
    case "quarantined":
      return "Not approved. The tool is withheld from the model and calls to it are refused.";
    case "scan":
      // "so the proxy strips this tool" was stated as fact. It is a fact only at the DEFAULT
      // threshold, which is all this console has — see DEFAULT_STRIP_SEVERITY.
      return `Approved, and the scanner graded it ${String(
        p.scan_severity
      ).toUpperCase()}. The served definition matches the approved one, but at the default mcp_scan_strip_severity (${DEFAULT_STRIP_SEVERITY}) a grade this high strips the tool from every tools/list, whatever the pin says.`;
    default:
      return "Approved. The served definition matches the approved one.";
  }
}

/** What the operator was shown, so approve can name the digest they actually reviewed. */
function reviewedDigest(p: McpPinRow): string {
  return p.last_digest || p.approved_digest;
}

type Conflict = { row: McpPinRow; reviewed: string; approved: string; servedNow: string | null; detail: string };

export function McpServers() {
  const { selectedNamespace } = useApp();
  const toast = useToast();
  const ns = selectedNamespace || "all";
  const [selectedServer, setSelectedServer] = useState<string | null>(null);
  const [selectedPin, setSelectedPin] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [conflict, setConflict] = useState<Conflict | null>(null);
  const [forgetting, setForgetting] = useState<McpServerRow | null>(null);

  const loadServers = useCallback(
    () => apiGet<McpServerRow[]>(`/api/v1/mcp/servers?namespace=${encodeURIComponent(ns)}`),
    [ns]
  );
  const loadPins = useCallback(
    () => apiGet<McpPinRow[]>(`/api/v1/mcp/pins?namespace=${encodeURIComponent(ns)}`),
    [ns]
  );

  const servers = useApi<McpServerRow[]>(loadServers, [ns], { cacheKey: `mcp-servers:${ns}`, staleTimeMs: 5000 });
  const pins = useApi<McpPinRow[]>(loadPins, [ns], { cacheKey: `mcp-pins:${ns}`, staleTimeMs: 5000 });
  // Approve, revoke and forget are all admin-gated server-side. Asking the server who we are lets the
  // console say WHY a control is unavailable instead of showing a grey button with no explanation.
  const me = useApi(() => fetchMe(), []);
  // Blocked only when we POSITIVELY know the caller is not an admin. An unreachable `/api/v1/me` is
  // not evidence of anything: treating it as "viewer" turns an unrelated endpoint being down into a
  // permanently dead Approve button with no way to find out why. The real gate is `require_admin`
  // server-side, so being permissive here costs at worst an honest 403.
  const notAdmin = Boolean(me.data) && me.data?.role !== "admin";

  const serverRows = useMemo(() => servers.data ?? [], [servers.data]);
  const allPins = useMemo(() => pins.data ?? [], [pins.data]);
  const pinRows = useMemo(
    () => allPins.filter((p) => !selectedServer || p.server_id === selectedServer),
    [allPins, selectedServer]
  );

  // Re-derived from the live list every render rather than held as an object: after a refetch the
  // held copy would be a stale snapshot, and the detail panel would keep showing the digest that was
  // true before the operator clicked Refresh — which is precisely the state this page exists to
  // prevent anyone acting on.
  const selectedTool = useMemo(
    () => (selectedPin ? (allPins.find((p) => pinKey(p) === selectedPin) ?? null) : null),
    [allPins, selectedPin]
  );

  /**
   * Every tool name served by more than one DISTINCT server, each carrying its own server set.
   *
   * The count and the servers are both carried, and both are rendered, because the note used to be a
   * single block of literals — "Two … rows are two definitions on two servers … governs both" —
   * indexed at `collisions[0]`. Three servers publishing `read_file` therefore read as two, a second
   * colliding name was never mentioned at all, and no server was named. An operator sizing the blast
   * radius of a policy naming `read_file` reads "the set is closed at two", verifies two definitions
   * and stops, leaving a third un-reviewed. The Tools page was already fixed for exactly this
   * (Tools.tsx `CollisionNote`); this page is the same estate and must not disagree with it about how
   * many servers publish one name.
   *
   * `Set` rather than a row count, for the reason Tools states: a pin's identity is `(namespace,
   * server_id, tool_name)`, so ONE server pinned in two namespaces yields two rows with the same
   * `server_id` and is not a collision.
   */
  const collisions = useMemo(() => {
    const byName = new Map<string, Set<string>>();
    for (const p of allPins) {
      const set = byName.get(p.tool_name) ?? new Set<string>();
      set.add(p.server_id);
      byName.set(p.tool_name, set);
    }
    return [...byName.entries()]
      .filter(([, servers_]) => servers_.size > 1)
      .map(([name, servers_]) => [name, [...servers_].sort()] as [string, string[]]);
  }, [allPins]);

  const totals = useMemo(() => {
    const t = { servers: serverRows.length, tools: 0, drifted: 0, quarantined: 0, flagged: 0 };
    for (const s of serverRows) {
      t.tools += s.tools;
      t.drifted += s.drifted;
      t.quarantined += s.quarantined;
      t.flagged += s.flagged;
    }
    return t;
  }, [serverRows]);

  const refresh = useCallback(() => {
    void servers.refetch();
    void pins.refetch();
  }, [servers, pins]);

  const act = useCallback(
    async (row: McpPinRow, action: "approve" | "revoke") => {
      setBusy(true);
      const reviewed = reviewedDigest(row);
      try {
        // Approve names the SERVED digest explicitly. The API refuses a digest it has not seen, so a
        // server that changes its definition again between this screen rendering and the click
        // landing gets a 409 rather than an accidental blessing.
        const body =
          action === "approve"
            ? { namespace: row.namespace, server_id: row.server_id, tool_name: row.tool_name, digest: reviewed }
            : { namespace: row.namespace, server_id: row.server_id, tool_name: row.tool_name };
        await apiSend<McpPinRow>(`/api/v1/mcp/pins/${action}`, "POST", body);
        toast.push({
          kind: "success",
          message: action === "approve" ? `Approved ${row.tool_name}` : `Revoked ${row.tool_name}`,
          detail:
            action === "approve"
              ? "The served definition is now the approved one; the tool is visible to the model again."
              : "The tool is withheld from the model and calls to it are refused until it is re-approved."
        });
        setSelectedPin(null);
        refresh();
      } catch (err) {
        // 409 is not an error to report — it is the rug pull happening while the operator reads. It
        // gets a dialog naming all three digests, because "your approval failed" without them leaves
        // the operator to guess whether they mis-clicked or are being attacked.
        if (err instanceof ApiError && err.status === 409) {
          const fresh = await apiGet<McpPinRow[]>(`/api/v1/mcp/pins?namespace=${encodeURIComponent(ns)}`).catch(
            () => null
          );
          const now = fresh?.find((p) => pinKey(p) === pinKey(row)) ?? null;
          setConflict({
            row,
            reviewed,
            approved: row.approved_digest,
            servedNow: now ? now.last_digest : null,
            detail: err.message
          });
          refresh();
        } else {
          toast.push({
            kind: "error",
            message: `Could not ${action} ${row.tool_name}`,
            detail: (err as Error).message
          });
        }
      } finally {
        setBusy(false);
      }
    },
    [ns, refresh, toast]
  );

  /**
   * Withdraw approval from every tool a server serves.
   *
   * The escape hatch when a server has changed its definition more than once in a sitting: rather
   * than adjudicate each tool while the ground moves, withhold the lot and investigate. Reversible —
   * re-approving is one click per tool — which is why it does not need type-to-confirm, and why the
   * button names the blast radius instead.
   */
  const quarantineServer = useCallback(
    async (server: string) => {
      const victims = allPins.filter((p) => p.server_id === server && p.approved);
      setBusy(true);
      let done = 0;
      for (const p of victims) {
        try {
          await apiSend<McpPinRow>("/api/v1/mcp/pins/revoke", "POST", {
            namespace: p.namespace,
            server_id: p.server_id,
            tool_name: p.tool_name
          });
          done++;
        } catch {
          // Keep going: a partial quarantine still reduces exposure, and the count reports honestly.
        }
      }
      setBusy(false);
      setConflict(null);
      toast.push({
        kind: done === victims.length ? "success" : "error",
        message: `Withheld ${done} of ${victims.length} ${server} tools`,
        detail:
          done === victims.length
            ? "Every tool this server serves is now refused until an operator re-approves it individually."
            : "Some revocations failed — re-run, or revoke the remaining tools individually."
      });
      refresh();
    },
    [allPins, refresh, toast]
  );

  const forgetServer = useCallback(
    async (server: McpServerRow) => {
      setBusy(true);
      try {
        const res = await apiSend<{ removed: number }>(
          `/api/v1/mcp/servers/${encodeURIComponent(server.namespace)}/${encodeURIComponent(server.server_id)}`,
          "DELETE"
        );
        toast.push({
          kind: "success",
          message: `Forgot ${server.server_id}`,
          detail: `${res.removed} pin${res.removed === 1 ? "" : "s"} deleted. If the server reappears, its next definition is pinned afresh.`
        });
        setForgetting(null);
        setSelectedServer(null);
        setSelectedPin(null);
        refresh();
      } catch (err) {
        toast.push({ kind: "error", message: `Could not forget ${server.server_id}`, detail: (err as Error).message });
      } finally {
        setBusy(false);
      }
    },
    [refresh, toast]
  );

  const serverColumns: Array<Column<McpServerRow>> = [
    {
      key: "server_id",
      title: "Server",
      render: (v, row) => {
        const l = lookalikeOf(row.server_id);
        return (
          <span style={{ display: "inline-flex", alignItems: "center", gap: 7 }}>
            <span className="mono">{String(v)}</span>
            {l && <LookalikePill l={l} />}
          </span>
        );
      }
    },
    { key: "namespace", title: "Namespace", render: (v) => <span className="muted">{String(v)}</span> },
    { key: "transport", title: "Transport", render: (v) => <span className="mono muted">{String(v)}</span> },
    { key: "tools", title: "Tools" },
    {
      key: "health",
      title: "Status",
      render: (v) => {
        const meta = HEALTH_META[String(v)] ?? HEALTH_META.ok;
        const Icon = meta.icon;
        return (
          <span className="pill" style={{ ...TONE[meta.tone], display: "inline-flex", alignItems: "center", gap: 5 }}>
            <Icon size={12} /> {meta.label}
          </span>
        );
      }
    },
    {
      key: "drifted",
      title: "Drifted",
      render: (v) => (Number(v) > 0 ? <Pill text={String(v)} tone="bad" /> : <span className="muted">0</span>)
    },
    {
      key: "flagged",
      title: "Flagged",
      render: (v) => (Number(v) > 0 ? <Pill text={String(v)} tone="warn" /> : <span className="muted">0</span>)
    },
    {
      key: "last_seen_at",
      title: "Last seen",
      render: (v) => <span className="mono muted">{v ? new Date(String(v)).toLocaleString() : "—"}</span>
    }
  ];

  const pinColumns: Array<Column<McpPinRow>> = [
    {
      key: "tool_name",
      title: "Tool",
      render: (v, row) => {
        const l = lookalikeOf(row.tool_name);
        return (
          <span style={{ display: "inline-flex", alignItems: "center", gap: 7 }}>
            <span className="mono">{String(v)}</span>
            {l && <LookalikePill l={l} />}
            {isWithheld(row) && <Pill text="Withheld" tone="bad" />}
          </span>
        );
      }
    },
    {
      key: "server_id",
      title: "Server",
      render: (v, row) => {
        const l = lookalikeOf(row.server_id);
        return (
          <span style={{ display: "inline-flex", alignItems: "center", gap: 7 }}>
            <span className="mono muted">{String(v)}</span>
            {l && <LookalikePill l={l} />}
          </span>
        );
      }
    },
    {
      key: "status",
      title: "Pin",
      render: (v) => <Pill text={String(v).toUpperCase()} tone={STATUS_TONE[String(v)] ?? "neutral"} />
    },
    {
      key: "scan_severity",
      title: "Scan",
      render: (v) =>
        String(v) === "none" ? (
          <span className="muted">clean</span>
        ) : (
          <Pill text={String(v).toUpperCase()} tone={severityTone(String(v))} />
        )
    },
    {
      key: "approved_digest",
      title: "Approved",
      render: (v) => <span className="mono muted">{String(v).slice(0, 12) || "—"}</span>
    },
    {
      key: "last_digest",
      title: "Served",
      render: (v, row) => (
        <span className="mono" style={row.status === "drift" ? { color: "#FF3B5C" } : { opacity: 0.7 }}>
          {String(v).slice(0, 12) || "—"}
        </span>
      )
    },
    {
      key: "drift_count",
      title: "Drifts",
      render: (v) => (Number(v) > 0 ? <Pill text={String(v)} tone="bad" /> : <span className="muted">0</span>)
    },
    { key: "approved_by", title: "Approved by", render: (v) => <span className="muted">{String(v) || "—"}</span> }
  ];

  const loading = servers.loading || pins.loading;
  const error = servers.error || pins.error;
  const selectedServerRow = serverRows.find((s) => s.server_id === selectedServer) ?? null;
  const approveReason = notAdmin ? "Needs admin — you are a viewer." : undefined;

  return (
    <div className="stack page-enter">
      <PageHead
        title="MCP Servers"
        subtitle="Model Context Protocol integrations, and the approval state of every tool definition they serve"
        actions={
          <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
            <Link className="btn btn-outline" to="/tools" data-testid="mcp-to-tools">
              What can I do with these tools? →
            </Link>
            <button type="button" className="btn btn-outline" onClick={refresh} disabled={loading}>
              <RefreshCw size={14} /> Refresh
            </button>
          </div>
        }
      />

      <div className="grid grid-cols-5 lg:grid-cols-5 md:grid-cols-2 gap-5" data-testid="mcp-totals">
        <StatTile label="Servers" value={totals.servers} />
        <StatTile label="Tool definitions" value={totals.tools} />
        <StatTile label="Drifted" value={totals.drifted} color={totals.drifted ? "#FF3B5C" : undefined} />
        <StatTile label="Awaiting approval" value={totals.quarantined} color={totals.quarantined ? "#FFB020" : undefined} />
        <StatTile label="Scanner findings" value={totals.flagged} color={totals.flagged ? "#FFB020" : undefined} />
      </div>

      {error && (
        <Panel title="Couldn't read pin state" data-testid="mcp-error">
          {/* Silence must never read as an all-clear. An operator who takes a failed fetch for "no
              drift" concludes the estate is healthy at exactly the moment nobody checked. */}
          <div style={{ fontSize: 13, lineHeight: 1.6, color: "var(--text-secondary)" }}>
            Not the same as “no drift”. Approval state is unknown right now — enforcement is unaffected, and pinned
            tools keep refusing changed definitions.
          </div>
          <div className="mono" style={{ marginTop: 10, fontSize: 12, color: "var(--text-muted)" }}>
            {String(error)}
          </div>
          <button type="button" className="btn btn-outline" style={{ marginTop: 12 }} onClick={refresh}>
            <RefreshCw size={14} /> Retry
          </button>
        </Panel>
      )}

      {!error && !loading && serverRows.length === 0 && (
        <Panel title="No MCP servers observed yet" data-testid="mcp-empty">
          <div className="muted" style={{ lineHeight: 1.65 }}>
            A server appears here the first time an agent runs a <span className="mono">tools/list</span> through the
            Norviq MCP proxy. Point the host&apos;s server command at{" "}
            <span className="mono">python -m norviq.mcp -- &lt;server command&gt;</span> to start governing it.
            <div style={{ marginTop: 10 }}>
              MCP inspection ships off by default, so an empty inventory usually means a fresh install rather than a
              problem. Enforcement does not depend on it — <Link to="/policies/catalog">write policies now →</Link>
            </div>
          </div>
        </Panel>
      )}

      {serverRows.length > 0 && (
        <Panel
          title="Servers"
          sub={
            selectedServer
              ? `Filtered to ${selectedServer} — click the row again to clear`
              : "Click a server to filter the tool definitions below"
          }
          action={
            selectedServerRow && (
              <button
                type="button"
                className="btn btn-ghost btn-sm revoke"
                onClick={() => setForgetting(selectedServerRow)}
                data-testid="mcp-forget-open"
              >
                <Trash2 size={14} /> Forget {selectedServerRow.server_id}…
              </button>
            )
          }
        >
          <DataTable<McpServerRow>
            columns={serverColumns}
            rows={serverRows}
            rowKey={(r) => `${r.namespace}/${r.server_id}`}
            selectedKey={selectedServerRow ? `${selectedServerRow.namespace}/${selectedServerRow.server_id}` : null}
            onRowClick={(row) => setSelectedServer((cur) => (cur === row.server_id ? null : row.server_id))}
            placeholder="Filter servers…"
          />
          <div className="muted" style={{ fontSize: 12, marginTop: 10 }}>
            Pins outlive the server until forgotten — a server that stops responding keeps enforcing the definition it
            last had approved.
          </div>
        </Panel>
      )}

      {/* FULL WIDTH, detail in a dialog. The previous side-by-side layout was itself a fix for a worse
          one — stacked, the detail opened a screen below the row that opened it and the click read as
          a dead control. Side by side solved that and cost the table a third of the page, which is
          where the digests, the drift column and the scan verdict all live. A dialog keeps the
          proximity (it opens over the row, with the row still highlighted behind it) without renting
          space that stands empty until something is selected. */}
      {pinRows.length > 0 && (
        <Panel
          title="Tool definitions"
          sub="Pinned by content hash. A definition that changes after approval is a rug pull, and the tool is withheld from the model — as is one the scanner grades high or critical, whatever its pin says."
        >
          <DataTable<McpPinRow>
            columns={pinColumns}
            rows={pinRows}
            rowKey={pinKey}
            selectedKey={selectedPin}
            onRowClick={(row) => setSelectedPin((cur) => (cur === pinKey(row) ? null : pinKey(row)))}
            placeholder="Filter tools…"
          />
          {collisions.length > 0 && (
            <div
              data-testid="mcp-collision"
              style={{ display: "flex", gap: 8, alignItems: "flex-start", marginTop: 12 }}
            >
              <Info size={14} style={{ flex: "none", marginTop: 2, color: "var(--escalate)" }} />
              <span style={{ fontSize: 12.5, lineHeight: 1.55, color: "var(--text-muted)" }}>
                Rows are keyed on{" "}
                <span className="mono" style={{ color: "var(--text-secondary)" }}>(namespace, server_id, tool_name)</span>,
                so these are separate definitions rather than duplicates. The engine sees only the bare name.
                {/* Both the name and every server id are strings a server chose. `MarkedName` is why
                    they are not simply interpolated: naming the servers is the whole point of the
                    note, and an unmarked `runbоoks` inside the console's own sentence reads as a
                    second legitimate server rather than the impersonation the row pill calls it. */}
                {collisions.map(([name, servers_]) => (
                  <span key={name} style={{ display: "block", marginTop: 5 }}>
                    A policy naming <MarkedName value={name} /> governs{" "}
                    <strong style={{ color: "var(--text-secondary)", fontWeight: 600 }}>
                      {servers_.length === 2 ? "both" : `all ${servers_.length}`}
                    </strong>{" "}
                    (
                    {servers_.map((s, i) => (
                      <span key={s}>
                        {i > 0 && ", "}
                        <MarkedName value={s} />
                      </span>
                    ))}
                    ).
                  </span>
                ))}
              </span>
            </div>
          )}
        </Panel>
      )}

      {/* AFTER the tables in the DOM, and outside every <Panel>. `.panel` sets `backdrop-filter`,
          which makes it a containing block for `position: fixed` and would pin the dialog under the
          page chrome. DOM order also matters to the tests that reach a server row by index.

          Suppressed while a conflict is open: two stacked Modals both register a document-level
          Escape listener, so one keypress would dismiss both and drop the operator back to a table
          having silently closed the 409 they needed to read. */}
      {selectedTool && !conflict && (
        <Modal
          wide
          data-testid="mcp-detail"
          onClose={() => setSelectedPin(null)}
          title={
            <span className="mono" style={{ fontSize: 15 }}>
              {selectedTool.server_id} / {selectedTool.tool_name}
            </span>
          }
          subtitle={detailSubtitle(selectedTool)}
        >
          {/* FIRST in the body, above the diff and above Approve. The operator is about to decide
              whether this definition is the one they think it is, and the name in the title is the
              only thing they have to go on — `notes / reаd_file` and `filesystem / read_file` are the
              same pixels. Reuses the console's own detector and note rather than a second mechanism. */}
          <PinLookalikeNote lookalikes={lookalikesOfPin(selectedTool)} />

          {/* The badge's own sentence, in the view that outranks it. A scanner grade at or above
              `mcp_scan_strip_severity` strips the tool whatever the pin says, so this has to name
              what would CLEAR it — otherwise the only control on offer is Revoke, which is the
              opposite of what the operator wants. */}
          {isWithheld(selectedTool) && (
            <div
              data-testid="mcp-withheld-note"
              style={{
                display: "flex",
                gap: 9,
                alignItems: "flex-start",
                padding: "10px 12px",
                borderRadius: 10,
                marginBottom: 14,
                border: "1px solid #FF3B5C30",
                background: "#FF3B5C15"
              }}
            >
              <ShieldAlert size={15} style={{ flex: "none", marginTop: 2, color: "var(--block)" }} />
              <div style={{ fontSize: 12.5, lineHeight: 1.6, color: "var(--text-secondary)" }}>
                <div style={{ fontWeight: 600, color: "var(--block)", marginBottom: 3 }}>
                  Withheld from the model
                </div>
                {withheldReason(selectedTool) === "drift" &&
                  "The served definition differs from the approved one, so the proxy strips this tool from every tools/list. Adopting the served definition below clears it."}
                {withheldReason(selectedTool) === "quarantined" &&
                  "This definition has never been approved, so the proxy strips this tool from every tools/list. Approving the served definition below clears it."}
                {withheldReason(selectedTool) === "scan" && (
                  <>
                    The definition scanner graded this tool {String(selectedTool.scan_severity).toUpperCase()}. At the
                    default <span className="mono">mcp_scan_strip_severity</span> ({DEFAULT_STRIP_SEVERITY}) the proxy
                    strips it from every <span className="mono">tools/list</span> whatever the pin says. Approving the
                    definition does not clear it: fix the definition upstream, or raise{" "}
                    <span className="mono">mcp_scan_strip_severity</span> above {String(selectedTool.scan_severity)}.
                    <div style={{ marginTop: 5, color: "var(--text-muted)" }}>
                      This console is not told which threshold this cluster runs — no endpoint serves{" "}
                      <span className="mono">mcp_scan_strip_severity</span> — so if it was raised, this tool is still
                      being handed to the model and the grade above is the only fact here.
                    </div>
                  </>
                )}
                {withheldReason(selectedTool) !== "scan" &&
                  (selectedTool.scan_severity === "critical" || selectedTool.scan_severity === "high") && (
                    <div style={{ marginTop: 5 }}>
                      The scanner also graded it {String(selectedTool.scan_severity).toUpperCase()}, so approving the
                      served definition will NOT make this tool visible again on its own — that grade strips it
                      independently of the pin.
                    </div>
                  )}
              </div>
            </div>
          )}

          <DefinitionDiff
            approved={selectedTool.approved_canonical}
            served={selectedTool.last_canonical}
            approvedDigest={selectedTool.approved_digest}
            servedDigest={selectedTool.last_digest}
          />

          {selectedTool.findings.length > 0 && (
            <div style={{ marginTop: 18 }}>
              <div
                style={{
                  fontSize: 11,
                  fontWeight: 600,
                  letterSpacing: "0.08em",
                  textTransform: "uppercase",
                  color: "var(--text-secondary)",
                  marginBottom: 8
                }}
              >
                Scanner findings
              </div>
              <div style={{ border: "1px solid var(--border)", borderRadius: 12, overflow: "hidden" }}>
                {selectedTool.findings.map((f, i) => (
                  <div key={`${f.rule}-${i}`} data-testid={`mcp-finding-${f.rule}`}>
                    <div style={{ padding: "11px 12px", background: "var(--bg-elevated)" }}>
                      <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap", marginBottom: 6 }}>
                        <Pill text={f.severity.toUpperCase()} tone={severityTone(f.severity)} />
                        <span className="mono" style={{ fontSize: 12.5 }}>
                          {f.rule}
                        </span>
                      </div>
                      <div style={{ fontSize: 12.5, lineHeight: 1.55, color: "var(--text-secondary)" }}>{f.detail}</div>
                    </div>
                    {/* The sentence that fired the rule. Withheld from the model, shown here — the
                        operator is being asked to judge this exact text. */}
                    <EvidenceBlock evidence={f.evidence} field={f.field} data-testid={`mcp-evidence-${f.rule}`} />
                  </div>
                ))}
              </div>
            </div>
          )}

          <div style={{ display: "flex", flexDirection: "column", gap: 8, alignItems: "flex-start", marginTop: 18 }}>
            {selectedTool.status !== "pinned" && (
              <InlineDisabledReason reason={approveReason} tone="muted" align="start" data-testid="mcp-approve-gate">
                <button
                  type="button"
                  className="btn btn-primary"
                  disabled={busy || notAdmin}
                  onClick={() => void act(selectedTool, "approve")}
                  data-testid="mcp-approve"
                >
                  <CheckCircle2 size={14} /> Approve served definition
                </button>
              </InlineDisabledReason>
            )}
            {selectedTool.approved && (
              <InlineDisabledReason reason={approveReason} tone="muted" align="start" data-testid="mcp-revoke-gate">
                <button
                  type="button"
                  className="btn btn-destructive"
                  disabled={busy || notAdmin}
                  onClick={() => void act(selectedTool, "revoke")}
                  data-testid="mcp-revoke"
                >
                  <XCircle size={14} /> Revoke
                </button>
              </InlineDisabledReason>
            )}
            {/* The other half of the operator's question. This page says whether the definition can be
                trusted; Tools says what the definition lets the agent do, and how to narrow it. */}
            <Link className="btn btn-outline" to="/tools" data-testid="mcp-detail-tools-link">
              See this tool&apos;s arguments on Tools →
            </Link>
          </div>
        </Modal>
      )}

      {conflict && (
        <Modal
          danger
          data-testid="mcp-conflict"
          title={
            <>
              <XCircle size={19} style={{ color: "var(--block)" }} />
              The definition changed again while you were reading it
            </>
          }
          onClose={() => setConflict(null)}
          actions={
            <>
              <button type="button" className="btn btn-ghost" onClick={() => setConflict(null)}>
                Close
              </button>
              <button
                type="button"
                className="btn btn-outline"
                onClick={() => {
                  setConflict(null);
                  refresh();
                }}
                data-testid="mcp-conflict-reread"
              >
                Re-read the pin
              </button>
              <button
                type="button"
                className="btn btn-destructive"
                disabled={busy || notAdmin}
                onClick={() => void quarantineServer(conflict.row.server_id)}
                data-testid="mcp-conflict-quarantine"
              >
                Withhold all {allPins.filter((p) => p.server_id === conflict.row.server_id && p.approved).length}{" "}
                {conflict.row.server_id} tools
              </button>
            </>
          }
        >
          <p style={{ margin: "0 0 14px", fontSize: 13, lineHeight: 1.6, color: "var(--text-secondary)" }}>
            Your digest matches neither the approved nor the served definition.{" "}
            <span style={{ color: "var(--text-primary)" }}>The rug pull, live</span> — the server swapped between this
            screen rendering and your click landing.
          </p>
          <div className="mono" style={{ display: "flex", flexDirection: "column", gap: 6, marginBottom: 16, fontSize: 12 }}>
            {[
              { label: "you reviewed", value: conflict.reviewed, tone: "primary" },
              { label: "approved", value: conflict.approved || "(none)", tone: "secondary" },
              { label: "served now", value: conflict.servedNow ?? "could not re-read", tone: "danger" }
            ].map((r) => (
              <div
                key={r.label}
                style={{
                  display: "flex",
                  gap: 10,
                  padding: "8px 11px",
                  borderRadius: 9,
                  background: r.tone === "danger" ? "#ff3b5c15" : "var(--bg-elevated)",
                  border: r.tone === "danger" ? "1px solid #ff3b5c30" : "1px solid transparent"
                }}
              >
                <span style={{ flex: "none", width: 96, color: "var(--text-muted)" }}>{r.label}</span>
                <span
                  data-testid={`mcp-conflict-${r.label.replace(/\s+/g, "-")}`}
                  style={{
                    overflowWrap: "anywhere",
                    color:
                      r.tone === "danger"
                        ? "var(--block)"
                        : r.tone === "primary"
                          ? "var(--text-primary)"
                          : "var(--text-secondary)"
                  }}
                >
                  {r.value}
                </span>
              </div>
            ))}
          </div>
          <p style={{ margin: "0 0 4px", fontSize: 12.5, lineHeight: 1.6, color: "var(--text-muted)" }}>
            Nothing was approved. Re-read the pin — or treat three definitions in one session as the answer.
          </p>
        </Modal>
      )}

      {forgetting && (
        <DestructiveConfirm
          title={
            <>
              Forget <span className="mono">{forgetting.server_id}</span>?
            </>
          }
          confirmWord={forgetting.server_id}
          confirmLabel="Forget server"
          allowed={!notAdmin}
          busy={busy}
          onCancel={() => setForgetting(null)}
          onConfirm={() => void forgetServer(forgetting)}
          data-testid="mcp-forget"
          consequence={
            <>
              If it reappears under the default <span className="mono" style={{ color: "var(--text-primary)" }}>tofu</span>{" "}
              pin mode,{" "}
              <strong style={{ color: "var(--escalate)", fontWeight: 600 }}>
                the drifted definition would be auto-approved on sight.
              </strong>{" "}
              Forgetting a server to clear an alarm is one step from adopting the change that raised it.
            </>
          }
        >
          Deletes{" "}
          <strong style={{ color: "var(--text-primary)", fontWeight: 600 }}>
            {allPins.filter((p) => p.server_id === forgetting.server_id).length} pin
            {allPins.filter((p) => p.server_id === forgetting.server_id).length === 1 ? "" : "s"}
          </strong>
          , their drift history and their findings. Policies are unchanged and keep enforcing.
        </DestructiveConfirm>
      )}
    </div>
  );
}
