// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// Intents — what an agent class is FOR. Everything it does not state is denied.
//
// This screen exists because deny-by-default is easy to ship and hard to adopt. A policy that
// refuses everything it was not told about will refuse something legitimate on day one, and if the
// operator cannot see WHICH call and WHY, the policy gets switched off. So the screen is built
// around the diff, not the editor: propose a candidate from traffic the class actually produced,
// replay it against that traffic, and put the would-block list — each with the rule that came
// closest and the single clause that failed — in front of the operator BEFORE anything is saved.
//
// Nothing here enforces. "Save as draft" writes to the drafts table the evaluator never reads;
// applying stays the gated Policies flow, so there is exactly one place where enforcement begins.

import { useCallback, useMemo, useState } from "react";
import { AlertTriangle, CheckCircle2, FileText, PencilLine, Play, Wand2 } from "lucide-react";
import { useNavigate } from "react-router-dom";
import { apiSend } from "../api/client";
import { Column, DataTable } from "../components/common/DataTable";
import { KitButton } from "../components/common/KitButton";
import { PageHead } from "../components/common/PageHead";
import { Panel } from "../components/common/Panel";
import { StatTile } from "../components/common/StatTile";
import { useToast } from "../components/common/Toast";
import { useApp } from "../store/AppContext";
import { intentToBuilderGraph, type IntentLike } from "../lib/intentToGraph";
import type { BuilderGraph } from "../lib/builderGraph";

export type IntentRule = {
  id: string;
  server?: string;
  match?: Record<string, unknown>;
  require?: Record<string, unknown>;
};

export type Intent = { name: string; class: string; call?: IntentRule[] };

export type ProposeResponse = { intent: Intent; sampled: number; params_available: boolean };

export type BlockedCall = { index: number; tool_name: string; reason: string; [key: string]: unknown };

export type DryRunResponse = {
  total: number;
  would_allow: number;
  would_block: number;
  coverage: Record<string, number>;
  unused_rules: string[];
  blocked: BlockedCall[];
  params_available?: boolean;
};

/** Render a predicate map as the sentence an operator reads, not as JSON. */
function describePredicates(rule: IntentRule): string[] {
  const out: string[] = [];
  if (rule.server) out.push(`integration is ${rule.server}`);
  const walk = (block?: Record<string, unknown>) => {
    Object.entries(block ?? {}).forEach(([field, spec]) => {
      if (typeof spec === "string") {
        out.push(`${field} is ${spec}`);
        return;
      }
      Object.entries((spec ?? {}) as Record<string, unknown>).forEach(([op, value]) => {
        const rendered = Array.isArray(value) ? value.join(", ") : String(value);
        out.push(`${field} ${op} ${rendered}`);
      });
    });
  };
  walk(rule.match);
  walk(rule.require);
  return out;
}

export function Intents() {
  const { namespace } = useApp();
  const { push } = useToast();
  const navigate = useNavigate();
  const [agentClass, setAgentClass] = useState("");
  const [busy, setBusy] = useState<string | null>(null);
  const [proposal, setProposal] = useState<ProposeResponse | null>(null);
  const [report, setReport] = useState<DryRunResponse | null>(null);
  const [savedDraft, setSavedDraft] = useState<string | null>(null);

  const ns = namespace || "all";

  // Convert eagerly so the button can state, BEFORE it is pressed, whether the handoff would lose a
  // restriction. `dropped` non-empty means the resulting graph would be MORE PERMISSIVE than the
  // intent that was just dry-run and approved — so the button refuses rather than warning. A warning
  // that can be clicked through is how the permissive version gets saved.
  const handoff = useMemo(
    () =>
      proposal?.intent
        ? intentToBuilderGraph(proposal.intent as IntentLike, agentClass)
        : { graph: null as BuilderGraph | null, dropped: [] as string[] },
    [proposal, agentClass]
  );

  const openInBuilder = useCallback(() => {
    if (!handoff.graph) return;
    if (handoff.dropped.length) {
      push({
        kind: "error",
        message: `This intent cannot be edited in the builder without weakening it: ${handoff.dropped[0]}${
          handoff.dropped.length > 1 ? ` (+${handoff.dropped.length - 1} more)` : ""
        }`
      });
      return;
    }
    // The builder owns authoring and the gated save; nothing here enforces. Carrying the graph in
    // router state (not a query string) keeps a policy body out of browser history and access logs.
    // `/policies/catalog`, NOT `/policies`. App.tsx routes `/policies` through
    // `<Navigate to="/policies/catalog" replace />`, and a redirect does not carry router state — so
    // targeting the shorthand delivered the operator to the catalog with `location.state` null and the
    // builder never opened. Found only by walking the flow in a browser: the unit tests covered the
    // converter and the seeding separately and rendered BuilderSheet directly, so nothing exercised
    // navigate -> redirect -> catalog. Deep-link to the real route.
    navigate("/policies/catalog", { state: { builderGraph: handoff.graph, fromIntent: proposal?.intent?.name ?? "" } });
  }, [handoff, navigate, proposal, push]);

  const reset = () => {
    setReport(null);
    setSavedDraft(null);
  };

  const propose = useCallback(async () => {
    if (!agentClass.trim()) return;
    setBusy("propose");
    reset();
    try {
      const res = await apiSend<ProposeResponse>("/api/v1/intents/propose", "POST", {
        ns,
        cls: agentClass.trim(),
        name: `${agentClass.trim()}-intent`.toLowerCase().replace(/[^a-z0-9-]+/g, "-").slice(0, 63)
      });
      setProposal(res);
      push({ kind: "success", message: `Proposed ${res.intent.call?.length ?? 0} rules from ${res.sampled} calls` });
    } catch (err) {
      setProposal(null);
      push({ kind: "error", message: (err as Error).message || "Could not propose an intent" });
    } finally {
      setBusy(null);
    }
  }, [agentClass, ns, push]);

  const dryRun = useCallback(async () => {
    if (!proposal) return;
    setBusy("dryrun");
    try {
      const res = await apiSend<DryRunResponse>("/api/v1/intents/dry-run", "POST", {
        ns,
        cls: proposal.intent.class,
        intent: proposal.intent
      });
      setReport(res);
    } catch (err) {
      push({ kind: "error", message: (err as Error).message || "Dry run failed" });
    } finally {
      setBusy(null);
    }
  }, [proposal, ns, push]);

  const saveDraft = useCallback(async () => {
    if (!proposal) return;
    setBusy("draft");
    try {
      const res = await apiSend<{ draft_id: string }>("/api/v1/intents/drafts", "POST", {
        // A draft is stored against ONE namespace; "All namespaces" is a view, not a target.
        ns,
        cls: proposal.intent.class,
        intent: proposal.intent
      });
      setSavedDraft(res.draft_id);
      push({ kind: "success", message: "Saved as a non-enforcing draft — apply it from Policy Catalog" });
    } catch (err) {
      push({ kind: "error", message: (err as Error).message || "Could not save the draft" });
    } finally {
      setBusy(null);
    }
  }, [proposal, ns, push]);

  const blockedColumns: Column<BlockedCall>[] = useMemo(
    () => [
      { key: "tool_name", title: "Tool", thStyle: { width: "18%" } },
      {
        key: "reason",
        title: "Why it would be denied",
        // The near-miss explainer — "closest send-send-email met 3/4, failed: <clause>" — is the most
        // useful sentence on the page and it contains raw regexes, so it needs the mono face. It also
        // needs to WRAP: `.tbl td` is `white-space: nowrap`, which put the one string an operator has
        // to read behind a horizontal scrollbar.
        render: (value) => (
          <span className="mono" style={{ fontSize: 12, whiteSpace: "normal", display: "inline-block" }}>
            {String(value)}
          </span>
        ),
        tdStyle: { whiteSpace: "normal" }
      }
    ],
    []
  );

  const rules = proposal?.intent.call ?? [];

  return (
    // `page-enter stack` is what every other page uses: the fade-in plus a 16px gap between panels.
    // This file previously said `page`, which is not a defined class — so the panels below sat flush
    // against each other with no rhythm. Several classes here were in the same state; see the header.
    <div className="page-enter stack">
      <PageHead
        // Matches the sidebar entry. The two disagreed ("Intents" here, "Propose from traffic" in the
        // nav), which left the page looking like a different destination from the one just clicked.
        title="Propose from traffic"
        subtitle="What each agent class is FOR. Anything an intent does not state is denied."
      />

      <Panel
        title="Start from what it actually did"
        sub="An allowlist written from memory is both too wide and missing the one tool that matters."
      >
        <div style={{ display: "flex", gap: 10, flexWrap: "wrap", alignItems: "flex-end" }}>
          <label style={{ display: "flex", flexDirection: "column", gap: 6, minWidth: 240 }}>
            <span className="field-label">Agent class</span>
            <input
              className="input"
              placeholder="support-bot"
              value={agentClass}
              aria-label="Agent class"
              onChange={(e) => {
                setAgentClass(e.target.value);
                setProposal(null);
                reset();
              }}
            />
          </label>
          <KitButton icon={Wand2} onClick={propose} disabled={!agentClass.trim() || busy !== null}>
            {busy === "propose" ? "Proposing…" : "Propose intent"}
          </KitButton>
        </div>
      </Panel>

      {proposal && (
        <>
          {proposal.params_available === false && (
            <Panel data-testid="params-warning">
              <div style={{ display: "flex", gap: 10, alignItems: "flex-start" }}>
                <AlertTriangle size={16} style={{ color: "var(--escalate)", flex: "none", marginTop: 2 }} />
                <div>
                  <strong>Proposed from tool names only.</strong> The audit log for this class carries no
                  call parameters, so this proposal cannot constrain recipients, data classes or SQL
                  tables. Enable parameter capture, or supply sample calls, before relying on a
                  destination-level rule.
                </div>
              </div>
            </Panel>
          )}

          {/* `stat-row` was undefined, so these stacked vertically instead of forming a KPI row. The
              rest of the app uses a Tailwind grid for exactly this (see McpServers' five tiles). */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-5">
            <StatTile label="Rules" value={rules.length} />
            <StatTile label="Calls sampled" value={proposal.sampled} />
            {report && <StatTile label="Would allow" value={report.would_allow} color="var(--allow)" />}
            {report && (
              <StatTile label="Would block" value={report.would_block} color={report.would_block ? "var(--block)" : undefined} />
            )}
          </div>

          <Panel
            title="Proposed intent"
            sub="Every rule is an ALLOW. There is no deny list — deny is the absence of a match."
            action={
              <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
                <KitButton variant="secondary" icon={Play} onClick={dryRun} disabled={busy !== null}>
                  {busy === "dryrun" ? "Replaying…" : "Dry run"}
                </KitButton>
                <KitButton
                  variant="secondary"
                  icon={FileText}
                  onClick={saveDraft}
                  disabled={busy !== null || !report || ns === "all"}
                >
                  {busy === "draft" ? "Saving…" : "Save as draft"}
                </KitButton>
                {/* The handoff. This screen proposes from RECORDED TRAFFIC and replays it — the two
                    things the builder structurally cannot do. Editing belongs in the builder, so
                    this hands the proposal over rather than growing a second editor here. */}
                <KitButton
                  variant="secondary"
                  icon={PencilLine}
                  data-testid="open-in-builder"
                  onClick={openInBuilder}
                  disabled={busy !== null || !proposal || ns === "all"}
                >
                  Open in Visual Builder
                </KitButton>
              </div>
            }
          >
            {/* WHY AN ACTION IS UNAVAILABLE, as text. These were `title` tooltips on the buttons, which
                could never be read: `.btn:disabled` sets `pointer-events: none`, so a disabled button
                never receives the hover that would show its own explanation. */}
            {ns === "all" && (
              <div className="muted" style={{ fontSize: 12, marginBottom: 10 }} data-testid="ns-blocker">
                Pick a single namespace to save a draft or hand this to the builder — both are stored
                against one namespace, not all.
              </div>
            )}
            {/* The handoff REFUSES rather than warns when a restriction cannot be carried across, because
                a warning that can be clicked through is how the weaker policy gets saved. That is right,
                but it used to be invisible until you clicked: the button looked enabled and the reasons
                arrived in a corner toast showing only the first. Stating it up front, in full, is the
                same protection without the dead end. */}
            {handoff.dropped.length > 0 && (
              <div
                data-testid="handoff-blocked"
                role="status"
                style={{
                  fontSize: 12,
                  marginBottom: 10,
                  padding: "8px 10px",
                  borderRadius: 8,
                  border: "1px solid #FFB02030",
                  background: "#FFB02015",
                  color: "var(--escalate)"
                }}
              >
                <strong>This proposal cannot be edited in the builder without weakening it.</strong>
                <ul style={{ margin: "6px 0 0", paddingLeft: 18 }}>
                  {handoff.dropped.map((d) => (
                    <li key={d}>{d}</li>
                  ))}
                </ul>
              </div>
            )}
            {!report && (
              <div className="muted" style={{ fontSize: 12 }} data-testid="dryrun-hint">
                Dry run this against recorded traffic before saving — the draft is only worth having once
                you know what it would have refused.
              </div>
            )}
            <ul style={{ listStyle: "none", margin: "12px 0 0", padding: 0, display: "flex", flexDirection: "column", gap: 10 }}>
              {rules.map((rule) => (
                <li
                  key={rule.id}
                  data-testid={`rule-${rule.id}`}
                  style={{ borderTop: "1px solid var(--border)", paddingTop: 10 }}
                >
                  <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
                    <code className="mono">{rule.id}</code>
                    {/* `.badge` is not a class in this app — these rendered as plain text, so a green
                        "covered" and an amber "matched nothing" were indistinguishable. `.pill` is the
                        real primitive, and it carries the colour that makes the two mean something. */}
                    {report?.unused_rules?.includes(rule.id) && (
                      <span
                        className="pill"
                        title="No recorded call matched this rule"
                        style={{ background: "#FFB02015", color: "#FFB020", borderColor: "#FFB02030" }}
                      >
                        matched nothing
                      </span>
                    )}
                    {typeof report?.coverage?.[rule.id] === "number" && !report.unused_rules.includes(rule.id) && (
                      <span
                        className="pill"
                        style={{ background: "#00E5A015", color: "#00E5A0", borderColor: "#00E5A030" }}
                      >
                        {report.coverage[rule.id]} calls
                      </span>
                    )}
                  </div>
                  <div className="muted" style={{ fontSize: 12, marginTop: 4 }}>
                    {describePredicates(rule).join(" · ")}
                  </div>
                </li>
              ))}
            </ul>
          </Panel>
        </>
      )}

      {report && (
        <Panel
          title={report.would_block ? "What this would have refused" : "Nothing legitimate would break"}
          sub={
            report.would_block
              ? "Each row names the rule that came closest and the single clause that failed — tighten the rule, or accept the denial."
              : "Every recorded call is covered by a rule. That is the point at which this is safe to draft."
          }
        >
          {report.would_block === 0 ? (
            <div style={{ display: "flex", gap: 10, alignItems: "center" }} data-testid="no-blocks">
              <CheckCircle2 size={16} /> {report.total} recorded calls replayed, none refused.
            </div>
          ) : (
            <DataTable<BlockedCall>
              rows={report.blocked}
              columns={blockedColumns}
              rowKey="index"
            />
          )}
        </Panel>
      )}

      {savedDraft && (
        <Panel data-testid="draft-saved">
          <div style={{ display: "flex", gap: 10, alignItems: "flex-start" }}>
            <FileText size={16} style={{ flex: "none", marginTop: 2 }} />
            <div>
              Draft <code>{savedDraft}</code> saved and <strong>not enforcing</strong>. Review and apply it
              from Policy Catalog — that is the only place enforcement begins.
            </div>
          </div>
        </Panel>
      )}
    </div>
  );
}

export default Intents;
