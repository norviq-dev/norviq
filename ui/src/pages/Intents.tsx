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
import { apiSend, fetchMe } from "../api/client";
import { InlineDisabledReason } from "../components/common/InlineDisabledReason";
import { KitButton } from "../components/common/KitButton";
import { NearMissCard, type BlockedCallDetail } from "../components/common/NearMissCard";
import { PageHead } from "../components/common/PageHead";
import { Panel } from "../components/common/Panel";
import { RuleCard } from "../components/common/RuleCard";
import { StatTile } from "../components/common/StatTile";
import { useToast } from "../components/common/Toast";
import { useApi } from "../hooks/useApi";
import { useApp } from "../store/AppContext";
import { commonTerms, predicateSentence } from "../lib/predicateSentence";
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

/** The near miss, decomposed by the API so the clause list can reconcile with `met M of N`. The
 *  optional fields are absent when the reason could not be decomposed; the card then shows the raw
 *  sentence rather than a tick-list that contradicts its own heading. */
export type BlockedCall = BlockedCallDetail & { [key: string]: unknown };

export type DryRunResponse = {
  total: number;
  would_allow: number;
  would_block: number;
  coverage: Record<string, number>;
  unused_rules: string[];
  blocked: BlockedCall[];
  params_available?: boolean;
};

/**
 * Group identical refusals.
 *
 * The dry run replays every recorded call, so 1,241 `run_query` calls refused for one reason produce
 * 1,241 rows. The operator has ONE decision to make there, not 1,241 — and a list that long buries
 * the single `execute_sql` refusal that is actually interesting.
 */
export function groupBlocked(blocked: BlockedCall[]): Array<{ call: BlockedCall; occurrences: number }> {
  const groups = new Map<string, { call: BlockedCall; occurrences: number }>();
  for (const b of blocked) {
    const key = [b.tool_name, b.closest_rule ?? "", (b.failed ?? []).join("|"), b.reason].join("\u241F");
    const existing = groups.get(key);
    if (existing) existing.occurrences += 1;
    else groups.set(key, { call: b, occurrences: 1 });
  }
  return [...groups.values()].sort((a, b) => b.occurrences - a.occurrences);
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
  // Saving a draft is admin-only server-side (`require_admin` in the intents router). Asking who we
  // are lets the button say WHY rather than going grey for an unstated reason.
  const me = useApi(() => fetchMe(), []);
  // Blocked only when we POSITIVELY know the caller is not an admin. An unreachable `/api/v1/me` is
  // not evidence of anything, and treating it as "viewer" made an unrelated endpoint being down
  // present as a permanently dead button with no way to find out why. The real gate is server-side
  // (`require_admin`), so the worst case of being permissive here is an honest 403.
  const notAdmin = Boolean(me.data) && me.data?.role !== "admin";

  // Convert eagerly so the button can state, BEFORE it is pressed, whether the handoff would lose a
  // restriction. `dropped` non-empty means the resulting graph would be MORE PERMISSIVE than the
  // intent that was just dry-run and approved — so the button refuses rather than warning. A warning
  // that can be clicked through is how the permissive version gets saved.
  // Keyed on the PROPOSAL's class, never the input box. Typing in the box after proposing used to
  // re-seed the builder graph with a class the rules were not proposed from — a policy scoped to an
  // agent class that never made those calls.
  const handoff = useMemo(
    () =>
      proposal?.intent
        ? intentToBuilderGraph(proposal.intent as IntentLike, proposal.intent.class)
        : { graph: null as BuilderGraph | null, dropped: [] as string[] },
    [proposal]
  );

  /** The box has been edited since this proposal was made, so the two no longer describe one class. */
  const stale = Boolean(proposal && agentClass.trim() && proposal.intent.class !== agentClass.trim());

  const openInBuilder = useCallback(() => {
    // Belt and braces: the button is disabled when a restriction would be lost, but the refusal
    // stays here too. A guard that lives only in a `disabled` attribute is one keyboard shortcut or
    // one refactor away from being gone, and what it protects is the weaker policy being saved.
    if (!handoff.graph || handoff.dropped.length) return;
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

  const rules = proposal?.intent.call ?? [];
  // Clauses every rule repeats, stated once above the set instead of on each card. The proposer
  // attaches `data_classes noneOf ['secret']` to everything it emits, so repeating it buries the
  // clauses that actually differ — which is what an operator comparing rules is reading for.
  const hoisted = useMemo(() => commonTerms(rules), [rules]);
  const grouped = useMemo(() => (report ? groupBlocked(report.blocked) : []), [report]);

  const draftBlocker = ns === "all"
    ? "Pick a single namespace — a draft is stored against one, not all."
    : !report
      ? "Dry run it first. A draft is only worth having once you know what it would refuse."
      : notAdmin
        ? "Needs admin — you are a viewer."
        : undefined;

  const builderBlocker = ns === "all"
    ? "Pick a single namespace — the builder saves against one."
    : handoff.dropped.length > 0
      ? `${handoff.dropped.length} restriction${handoff.dropped.length === 1 ? "" : "s"} cannot be carried across, listed above.`
      : undefined;

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
              // Editing the box no longer DESTROYS the proposal. It used to clear it on every
              // keystroke, so correcting a typo threw away a dry run that had just taken a minute
              // over 1,284 replayed calls. The proposal names its own class; when the two diverge
              // the page says so and offers to propose again.
              onChange={(e) => setAgentClass(e.target.value)}
            />
          </label>
          <KitButton icon={Wand2} onClick={propose} disabled={!agentClass.trim() || busy !== null}>
            {busy === "propose" ? "Proposing…" : "Propose intent"}
          </KitButton>
        </div>
      </Panel>

      {stale && (
        <Panel data-testid="proposal-stale">
          <div style={{ display: "flex", gap: 10, alignItems: "flex-start" }}>
            <AlertTriangle size={16} style={{ color: "var(--escalate)", flex: "none", marginTop: 2 }} />
            <div style={{ fontSize: 13, lineHeight: 1.6 }}>
              This proposal is for <code className="mono">{proposal?.intent.class}</code>, not{" "}
              <code className="mono">{agentClass.trim()}</code>. It is still shown because a dry run over
              recorded traffic is not cheap to redo — but propose again before saving anything.
            </div>
          </div>
        </Panel>
      )}

      {proposal && (
        <>
          {proposal.params_available === false && (
            // A PRIMARY state, not a footnote. With no recorded arguments this proposal can only name
            // tools, and every argument-level affordance below is suppressed rather than shown empty —
            // an empty ALLOWED IF band would read as "nothing is required here", when the truth is
            // "nothing could be checked".
            <Panel data-testid="params-warning" title="Proposed from tool names only">
              <div style={{ display: "flex", gap: 10, alignItems: "flex-start" }}>
                <AlertTriangle size={16} style={{ color: "var(--escalate)", flex: "none", marginTop: 2 }} />
                <div style={{ fontSize: 13, lineHeight: 1.65 }}>
                  No call arguments were recorded for this class, so these rules can only name tools and
                  the operation they perform — not recipients, data classes or SQL tables. A rule here
                  grants a tool outright.
                  <div style={{ marginTop: 8, color: "var(--text-secondary)" }}>
                    Enable parameter capture, or supply sample calls, before relying on a
                    destination-level rule.
                  </div>
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
              <div style={{ display: "flex", gap: 10, flexWrap: "wrap", alignItems: "flex-start" }}>
                <KitButton variant="secondary" icon={Play} onClick={dryRun} disabled={busy !== null}>
                  {busy === "dryrun" ? "Replaying…" : "Dry run"}
                </KitButton>
                {/* WHY AN ACTION IS UNAVAILABLE, as text beside the control. These were `title`
                    tooltips: `.btn:disabled` sets `pointer-events: none`, so a disabled button never
                    receives the hover that would show its own explanation. */}
                <InlineDisabledReason reason={draftBlocker} tone={notAdmin ? "muted" : "escalate"} data-testid="draft-gate">
                  <KitButton
                    variant="secondary"
                    icon={FileText}
                    onClick={saveDraft}
                    data-testid="save-draft"
                    disabled={busy !== null || Boolean(draftBlocker)}
                  >
                    {busy === "draft" ? "Saving…" : "Save as draft"}
                  </KitButton>
                </InlineDisabledReason>
                {/* The handoff. This screen proposes from RECORDED TRAFFIC and replays it — the two
                    things the builder structurally cannot do. Editing belongs in the builder, so
                    this hands the proposal over rather than growing a second editor here.

                    DISABLED when a restriction would be lost. The banner below has said so since
                    9ecd610, but the button stayed live: clicking it fired a toast showing only the
                    first reason and went nowhere, so the page both refused and looked broken. */}
                <InlineDisabledReason
                  reason={builderBlocker}
                  tone={handoff.dropped.length > 0 ? "block" : "escalate"}
                  data-testid="builder-gate"
                >
                  <KitButton
                    variant="secondary"
                    icon={PencilLine}
                    data-testid="open-in-builder"
                    onClick={openInBuilder}
                    disabled={busy !== null || !proposal || Boolean(builderBlocker)}
                  >
                    Open in Visual Builder
                  </KitButton>
                </InlineDisabledReason>
              </div>
            }
          >
            {/* The handoff REFUSES rather than warns when a restriction cannot be carried across,
                because a warning that can be clicked through is how the weaker policy gets saved.
                Naming each lost restriction is what makes the refusal actionable — the operator can
                re-add them by hand in the builder, or keep the stronger intent as a draft. */}
            {handoff.dropped.length > 0 && (
              <div
                data-testid="handoff-blocked"
                role="status"
                style={{
                  fontSize: 12.5,
                  lineHeight: 1.6,
                  marginBottom: 12,
                  padding: "10px 12px",
                  borderRadius: 10,
                  border: "1px solid #FFB02030",
                  background: "#FFB02015",
                  color: "var(--text-secondary)"
                }}
              >
                <strong style={{ color: "var(--escalate)" }}>
                  This proposal cannot be opened in the builder.
                </strong>{" "}
                {handoff.dropped.length === 1 ? "One restriction has" : `${handoff.dropped.length} restrictions have`}{" "}
                no allowlist equivalent.
                <ul style={{ margin: "6px 0 0", paddingLeft: 18 }}>
                  {handoff.dropped.map((d) => (
                    <li key={d}>{d}</li>
                  ))}
                </ul>
                <div style={{ marginTop: 6, color: "var(--text-muted)" }}>
                  Save it as a draft and apply it from Policy Catalog, or re-add these by hand in the builder.
                </div>
              </div>
            )}
            {!report && (
              <div className="muted" style={{ fontSize: 12, marginBottom: 10 }} data-testid="dryrun-hint">
                Dry run this against recorded traffic before saving — the draft is only worth having once
                you know what it would have refused.
              </div>
            )}
            {hoisted.length > 0 && (
              <div
                data-testid="hoisted-clauses"
                style={{
                  fontSize: 12.5,
                  lineHeight: 1.6,
                  padding: "9px 11px",
                  borderRadius: 10,
                  background: "var(--bg-elevated)",
                  color: "var(--text-secondary)",
                  marginBottom: 10
                }}
              >
                <span style={{ fontWeight: 600, color: "var(--text-primary)" }}>Applied to every rule:</span>{" "}
                {hoisted.map((t) => predicateSentence(t).prose).join("; ")} — stated once here instead of repeated
                on all {rules.length}.
              </div>
            )}
            <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
              {rules.map((rule) => (
                <RuleCard
                  key={rule.id}
                  rule={rule}
                  calls={report ? (report.coverage?.[rule.id] ?? 0) : null}
                  unused={Boolean(report?.unused_rules?.includes(rule.id))}
                  hoisted={hoisted.map((t) => t.raw)}
                />
              ))}
            </div>
          </Panel>
        </>
      )}

      {report && (
        <Panel
          title={report.would_block ? "What this would have refused" : "Nothing legitimate would break"}
          sub={
            report.would_block
              ? "The closest rule and the clause that failed — tighten the rule, or accept the denial."
              : "Every recorded call is covered by a rule. That is the point at which this is safe to draft."
          }
        >
          {report.would_block === 0 ? (
            <div style={{ display: "flex", gap: 10, alignItems: "center" }} data-testid="no-blocks">
              <CheckCircle2 size={16} /> {report.total} recorded calls replayed, none refused.
            </div>
          ) : (
            <div data-testid="near-misses">
              {/* Grouped: replaying 1,284 calls produces one row per call, and 1,241 identical
                  `run_query` refusals bury the single interesting one. The operator has one decision
                  per distinct reason, not one per call. */}
              {grouped.map(({ call, occurrences }) => (
                <NearMissCard key={call.index} call={call} occurrences={occurrences} />
              ))}
            </div>
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
