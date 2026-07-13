// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// Asset Graph inspector (design_handoff_assetgraph): floating panel with blast-radius (or exposure
// for data nodes), trust bar, risk / tool-call cards, ns/class/cluster chips, SPIFFE identity, the
// per-edge connection list with decision dots, and a View-in-Audit-Log action. Flips to the left
// when the selected node sits on the right half of the canvas.

import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { DECISION_COLORS, NODE_COLORS, RISK_COLORS, timeAgo } from "../../lib/d3-helpers";
import { defendCapability } from "../../api/client";
import { useToast } from "../common/Toast";
import type { CapabilityFinding } from "./types";
import type { ViewEdge, ViewModel, ViewNode } from "./model";

interface Props {
  node: ViewNode;
  model: ViewModel;
  reach: Set<string>;
  cluster?: string;
  side: "left" | "right";
  onClose: () => void;
}

const cardStyle: React.CSSProperties = { padding: "11px 12px", background: "var(--bg-graph-card)", border: "1px solid var(--graph-border-soft)", borderRadius: 10 };
const chipStyle: React.CSSProperties = {
  display: "inline-flex", alignItems: "center", gap: 6, fontSize: 11, color: "#b8c2d6",
  background: "var(--bg-graph-card)", border: "1px solid var(--graph-border-soft)", borderRadius: 999, padding: "4px 10px"
};
const sectionLabel: React.CSSProperties = { fontSize: 11, fontWeight: 600, letterSpacing: "0.04em", color: "#a0a0a0", textTransform: "uppercase" };

// CAP-1: per-verb status presentation. Open statuses (undefended/dormant) are the finding; defended is
// reassurance; latent is muted (the source could do it but nothing grants/observes it).
const STATUS_META: Record<string, { label: string; color: string; bg: string }> = {
  undefended: { label: "UNDEFENDED", color: "#FF3B5C", bg: "rgba(255,59,92,0.12)" },
  dormant_grant: { label: "DORMANT GRANT", color: "#FFB020", bg: "rgba(255,176,32,0.12)" },
  defended: { label: "DEFENDED", color: "#00e5a0", bg: "rgba(0,229,160,0.10)" },
  latent: { label: "LATENT", color: "#8a93a6", bg: "rgba(138,147,166,0.10)" },
  not_exposed: { label: "—", color: "#6e6e6e", bg: "transparent" }
};
const VERB_LABEL: Record<string, string> = { read: "READ", write: "WRITE", delete: "DELETE", send: "SEND", unknown: "?" };

export function AssetNodeDetail({ node, model, reach, cluster, side, onClose }: Props) {
  const kindColor = NODE_COLORS[node.kind];
  const byId = new Map(model.nodes.map((n) => [n.id, n]));
  const reachNodes = [...reach].filter((id) => id !== node.id).map((id) => byId.get(id)).filter(Boolean) as ViewNode[];
  const isData = node.kind === "data";
  const dataN = reachNodes.filter((n) => n.kind === "data").length;
  const toolN = reachNodes.filter((n) => n.kind === "tool").length;
  const agentN = reachNodes.filter((n) => n.kind === "agent").length;
  const blastMain = isData ? agentN + toolN : dataN;
  const blastColor = blastMain > 0 ? "#FFB020" : "#6e6e6e";
  // CAP-1: the source's verb-capability posture (data nodes with a registry-known source type).
  const cap = node.capability;
  const worst = cap?.worst ?? null;
  const toast = useToast();
  const navigate = useNavigate();
  const [defending, setDefending] = useState(false);

  // CAP→POLICY: the class to defend for an open finding (the first agent-class exercising the verb).
  const defendClass = (f: CapabilityFinding | null): string | null => f?.agent_classes?.[0] ?? null;

  // Generate a DRY-RUN policy draft that blocks this verb on the source for the class, then hand off to
  // the Policies inbox (never auto-enforces). A read finding's defense is "make the class read-only"
  // (block all mutating verbs → verbs:[]); a mutating verb blocks just that verb.
  async function onDefend(f: CapabilityFinding) {
    const cls = defendClass(f);
    if (!cap?.source_type || !cls || defending) return;
    const verbs = f.verb === "read" ? [] : [f.verb];
    setDefending(true);
    try {
      const res = await defendCapability(node.ns, cls, cap.source_type, verbs);
      const guardVerbs = (res.forward_guard_verbs ?? verbs).join("/");
      // The policy blocks by verb-name PATTERN (forward guard for tools not seen yet) plus any concrete
      // tools observed today — so it's a real defense even when nothing is observed.
      const tools = res.blocked_tools.length
        ? `blocks ${res.blocked_tools.length} observed tool${res.blocked_tools.length === 1 ? "" : "s"} + any future ${guardVerbs} tool`
        : `blocks any ${guardVerbs} tool by name (forward guard — none observed yet)`;
      toast.push({
        kind: res.valid ? "success" : "warning",
        message: `Draft created — ${res.read_only ? `${cls} → read-only` : `block ${verbs.join("/")} for ${cls}`}`,
        detail: `${tools}. Dry-run only — review and apply in Policies (nothing enforces yet).`,
        actionLabel: "Review in Policies →",
        onAction: () => navigate(res.deeplink)
      });
    } catch (e) {
      toast.push({ kind: "error", message: "Could not create defense draft", detail: e instanceof Error ? e.message : String(e) });
    } finally {
      setDefending(false);
    }
  }
  const trust = node.trust;
  const trustLabel = trust === undefined ? "" : trust >= 0.75 ? "High" : trust >= 0.5 ? "Medium" : "Low";
  const trustColor = trust === undefined ? "#a0a0a0" : trust >= 0.75 ? DECISION_COLORS.allow : trust >= 0.5 ? DECISION_COLORS.mixed : DECISION_COLORS.blocked;
  const conns = model.edges
    .filter((e): e is ViewEdge => e.type !== "belongs_to" && (e.s === node.id || e.t === node.id))
    .map((e) => {
      const other = byId.get(e.s === node.id ? e.t : e.s);
      return {
        name: other?.name ?? "",
        verdict: e.verdict,
        dot: e.verdict === "blocked" ? DECISION_COLORS.blocked : "#a0a0a0",
        detail: `${e.allow} allow · ${e.block} block`
      };
    });

  return (
    <div
      role="complementary"
      aria-label="Node inspector"
      style={{
        position: "absolute", top: 16, bottom: 16, width: 316,
        left: side === "left" ? 16 : "auto", right: side === "left" ? "auto" : 16,
        background: "rgba(20,20,20,0.94)", backdropFilter: "blur(16px)", border: "1px solid var(--graph-border)",
        borderRadius: 13, boxShadow: "0 24px 60px -20px rgba(0,0,0,0.7)",
        display: "flex", flexDirection: "column", overflow: "hidden", zIndex: 7
      }}
    >
      <div style={{ display: "flex", alignItems: "flex-start", gap: 10, padding: "16px 16px 14px", borderBottom: "1px solid var(--graph-border-soft)" }}>
        <span style={{ width: 12, height: 12, borderRadius: "50%", background: kindColor, marginTop: 5, flex: "none", boxShadow: `0 0 10px ${kindColor}` }} />
        <div style={{ minWidth: 0, flex: 1 }}>
          <div style={{ fontSize: 10, fontWeight: 700, letterSpacing: "0.1em", color: kindColor, textTransform: "uppercase" }}>
            {node.kind}{node.ns ? ` · ${node.ns}` : ""}
          </div>
          <div style={{ fontSize: 15, fontWeight: 700, marginTop: 3, wordBreak: "break-word", lineHeight: 1.25 }}>{node.name}</div>
        </div>
        <button
          type="button" onClick={onClose} aria-label="Close inspector"
          style={{ flex: "none", width: 26, height: 26, display: "flex", alignItems: "center", justifyContent: "center", background: "transparent", border: "1px solid var(--graph-border)", borderRadius: 7, color: "#a0a0a0", cursor: "pointer" }}
        >
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M18 6 6 18M6 6l12 12" /></svg>
        </button>
      </div>

      <div style={{ padding: 16, overflow: "auto", flex: 1 }}>
        {/* blast radius / exposure */}
        <div style={{ display: "flex", alignItems: "center", gap: 13, padding: "13px 14px", marginBottom: 16, background: "linear-gradient(180deg, rgba(255,176,32,0.07), rgba(255,176,32,0.02))", border: "1px solid #2a2418", borderRadius: 11 }}>
          <div style={{ fontSize: 30, fontWeight: 700, lineHeight: 1, letterSpacing: "-0.02em", color: blastColor, fontVariantNumeric: "tabular-nums" }}>{blastMain}</div>
          <div>
            <div style={{ fontSize: 11, fontWeight: 700, letterSpacing: "0.05em", color: blastColor, textTransform: "uppercase" }}>
              {isData ? "Exposure" : "Blast radius"}
            </div>
            <div style={{ fontSize: 11.5, color: "#a0a0a0", marginTop: 2, lineHeight: 1.35 }}>
              {node.awaiting
                ? "awaiting first tool call — no traffic yet"
                : isData
                  ? worst
                    ? `principals can reach this data · worst reachable verb: ${VERB_LABEL[worst.verb]}`
                    : "principals can reach this data"
                  : toolN > 0
                    ? `data sources across ${toolN} tools`
                    : "data sources in blast radius"}
            </div>
          </div>
        </div>

        {/* CAP-1: source capability — what verbs THIS source exposes, and which are open. The single
            highest-value block for a data node: turns "an agent reaches this" into "write/delete here
            is undefended / a dormant grant". Only rendered for registry-known sources (ES/Postgres). */}
        {isData && cap && (
          <div style={{ marginBottom: 16 }}>
            <div style={{ display: "flex", alignItems: "baseline", justifyContent: "space-between", marginBottom: 8 }}>
              <span style={sectionLabel}>Source capability</span>
              <span style={{ fontSize: 10.5, fontWeight: 700, letterSpacing: "0.04em", color: "#8a93a6", textTransform: "uppercase" }}>
                {cap.source_class.replace("_", " ")} · {cap.source_display}
              </span>
            </div>
            {worst && (
              <div style={{ padding: "9px 11px", marginBottom: 8, borderRadius: 9, background: STATUS_META[worst.status].bg, border: `1px solid ${STATUS_META[worst.status].color}55` }}>
                <div style={{ display: "flex", alignItems: "center", gap: 9 }}>
                  <span style={{ width: 8, height: 8, borderRadius: 2, background: RISK_COLORS[worst.risk], flex: "none" }} />
                  <div style={{ minWidth: 0, flex: 1 }}>
                    <div style={{ fontSize: 12, fontWeight: 700, color: STATUS_META[worst.status].color }}>
                      {STATUS_META[worst.status].label} · {VERB_LABEL[worst.verb]}
                    </div>
                    {worst.recommendation && (
                      <div style={{ fontSize: 11, color: "#c3cad6", marginTop: 2, lineHeight: 1.35 }}>{worst.recommendation}</div>
                    )}
                  </div>
                </div>
                {/* CAP→POLICY: one-click defense — generates a dry-run policy draft for the class exercising
                    the verb, landing in the Policies inbox (never auto-enforces). */}
                {cap?.source_type && defendClass(worst) && (
                  <button
                    type="button"
                    data-testid="cap-defend"
                    disabled={defending}
                    onClick={() => onDefend(worst)}
                    style={{
                      marginTop: 9, width: "100%", height: 32, display: "flex", alignItems: "center", justifyContent: "center", gap: 7,
                      borderRadius: 8, border: "none", cursor: defending ? "default" : "pointer",
                      background: STATUS_META[worst.status].color, color: "#0d0d0d", fontFamily: "inherit", fontSize: 12, fontWeight: 700,
                      opacity: defending ? 0.6 : 1
                    }}
                  >
                    {defending
                      ? "Generating draft…"
                      : worst.verb === "read"
                        ? `Defend: make ${defendClass(worst)} read-only →`
                        : `Defend: block ${VERB_LABEL[worst.verb]} for ${defendClass(worst)} →`}
                  </button>
                )}
              </div>
            )}
            <div style={{ display: "flex", flexDirection: "column", gap: 5 }}>
              {cap.findings.map((f) => {
                const meta = STATUS_META[f.status] ?? STATUS_META.not_exposed;
                return (
                  <div key={f.verb} style={{ display: "flex", alignItems: "center", gap: 9, padding: "7px 10px", background: "var(--bg-graph-card)", border: "1px solid var(--graph-border-soft)", borderRadius: 8 }}>
                    <span style={{ width: 7, height: 7, borderRadius: 2, background: RISK_COLORS[f.risk], flex: "none" }} title={`${f.risk} risk`} />
                    <span style={{ fontSize: 11.5, fontWeight: 700, color: "#d3dae6", width: 52, flex: "none" }}>{VERB_LABEL[f.verb]}</span>
                    <span style={{ minWidth: 0, flex: 1, fontSize: 11, color: "#9aa7bd", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
                      {f.label}{f.technique ? ` · ${f.technique}` : ""}
                    </span>
                    <span style={{ fontSize: 9.5, fontWeight: 700, letterSpacing: "0.03em", color: meta.color, background: meta.bg, padding: "2px 6px", borderRadius: 5, flex: "none" }}>{meta.label}</span>
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {trust !== undefined && (
          <div style={{ marginBottom: 16 }}>
            <div style={{ display: "flex", alignItems: "baseline", justifyContent: "space-between", marginBottom: 7 }}>
              <span style={sectionLabel}>Trust score</span>
              <span style={{ fontSize: 13, fontWeight: 700, color: trustColor }}>{trust.toFixed(2)} · {trustLabel}</span>
            </div>
            <div style={{ height: 7, borderRadius: 999, background: "var(--bg-graph-card)", overflow: "hidden" }}>
              <div style={{ height: "100%", width: `${Math.round(trust * 100)}%`, background: trustColor }} />
            </div>
          </div>
        )}

        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8, marginBottom: 16 }}>
          <div style={cardStyle}>
            <div style={{ fontSize: 10.5, color: "#a0a0a0", textTransform: "uppercase", letterSpacing: "0.04em" }}>Risk</div>
            <div style={{ display: "flex", alignItems: "center", gap: 6, marginTop: 6 }}>
              <span style={{ width: 8, height: 8, borderRadius: 2, background: RISK_COLORS[node.risk] }} />
              <span style={{ fontSize: 14, fontWeight: 700, color: RISK_COLORS[node.risk], textTransform: "capitalize" }}>{node.risk}</span>
            </div>
          </div>
          <div style={cardStyle}>
            <div style={{ fontSize: 10.5, color: "#a0a0a0", textTransform: "uppercase", letterSpacing: "0.04em" }}>Tool calls</div>
            <div style={{ fontSize: 14, fontWeight: 700, marginTop: 6, fontVariantNumeric: "tabular-nums" }}>{node.calls.toLocaleString()}</div>
          </div>
        </div>

        <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginBottom: 16 }}>
          {node.ns && <span style={chipStyle}><span style={{ color: "#a0a0a0" }}>ns</span>{node.ns}</span>}
          {node.agentClass && <span style={chipStyle}><span style={{ color: "#a0a0a0" }}>class</span>{node.agentClass}</span>}
          {cluster && <span style={chipStyle}><span style={{ color: "#a0a0a0" }}>cluster</span>{cluster}</span>}
          {node.awaiting && <span style={{ ...chipStyle, color: "#f3d18b", borderColor: "#4a3a10" }}>awaiting first call</span>}
        </div>

        {node.spiffe && (
          <div style={{ marginBottom: 16 }}>
            <div style={{ ...sectionLabel, marginBottom: 6 }}>SPIFFE identity</div>
            <div style={{ padding: "9px 11px", background: "var(--bg-graph-card)", border: "1px solid var(--graph-border-soft)", borderRadius: 9, fontFamily: "ui-monospace, monospace", fontSize: 11, color: "#b8c2d6", wordBreak: "break-all", lineHeight: 1.5 }}>
              {node.spiffe}
            </div>
          </div>
        )}

        <div style={{ ...sectionLabel, marginBottom: 8 }}>Connections · {conns.length}</div>
        <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
          {conns.map((ce, i) => (
            <div key={i} style={{ display: "flex", alignItems: "center", gap: 9, padding: "9px 11px", background: "var(--bg-graph-card)", border: "1px solid var(--graph-border-soft)", borderRadius: 9 }}>
              <span style={{ width: 8, height: 8, borderRadius: "50%", background: ce.dot, flex: "none" }} />
              <div style={{ minWidth: 0, flex: 1 }}>
                <div style={{ fontSize: 12.5, color: "#d3dae6", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{ce.name}</div>
                <div style={{ fontSize: 10.5, color: "#a0a0a0", marginTop: 1 }}>{ce.detail}</div>
              </div>
              <span style={{ fontSize: 10, fontWeight: 700, letterSpacing: "0.05em", color: ce.dot, textTransform: "uppercase" }}>{ce.verdict}</span>
            </div>
          ))}
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: 7, marginTop: 16, fontSize: 11.5, color: "#a0a0a0" }}>
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><circle cx="12" cy="12" r="9" /><path d="M12 7v5l3 2" /></svg>
          Last seen {node.lastSeen ? timeAgo(node.lastSeen) : "—"}
        </div>
      </div>

      {node.spiffe && (
        <div style={{ padding: "12px 16px", borderTop: "1px solid var(--graph-border-soft)" }}>
          <Link
            // Carry the agent's SPIFFE (server-side substring filter) AND its namespace, so Audit Log
            // lands on the right namespace pre-filtered to this agent (not the global 'default' scope).
            to={`/audit?agent=${encodeURIComponent(node.spiffe)}${node.ns ? `&namespace=${encodeURIComponent(node.ns)}` : ""}`}
            style={{
              width: "100%", height: 38, display: "flex", alignItems: "center", justifyContent: "center", gap: 8,
              borderRadius: 9, background: "#00e5a0", color: "#04241a", fontFamily: "inherit", fontSize: 13,
              fontWeight: 700, textDecoration: "none", boxSizing: "border-box"
            }}
          >
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M22 12h-4l-3 9L9 3l-3 9H2" /></svg>
            View in Audit Log
          </Link>
        </div>
      )}
    </div>
  );
}
