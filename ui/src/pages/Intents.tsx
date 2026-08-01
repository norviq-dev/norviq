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
import { AlertTriangle, CheckCircle2, FileText, Play, Wand2 } from "lucide-react";
import { apiSend } from "../api/client";
import { Column, DataTable } from "../components/common/DataTable";
import { PageHead } from "../components/common/PageHead";
import { Panel } from "../components/common/Panel";
import { StatTile } from "../components/common/StatTile";
import { useToast } from "../components/common/Toast";
import { useApp } from "../store/AppContext";

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
  const [agentClass, setAgentClass] = useState("");
  const [busy, setBusy] = useState<string | null>(null);
  const [proposal, setProposal] = useState<ProposeResponse | null>(null);
  const [report, setReport] = useState<DryRunResponse | null>(null);
  const [savedDraft, setSavedDraft] = useState<string | null>(null);

  const ns = namespace || "all";

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
        render: (value) => <span className="mono-sm">{String(value)}</span>
      }
    ],
    []
  );

  const rules = proposal?.intent.call ?? [];

  return (
    <div className="page">
      <PageHead
        title="Intents"
        subtitle="What each agent class is FOR. Anything an intent does not state is denied."
      />

      <Panel
        title="Propose from traffic"
        sub="Start from what the class actually did, not from memory — an allowlist written from memory is both too wide and missing the one tool that matters."
      >
        <div className="row gap-8 wrap items-end">
          <label className="field">
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
          <button className="btn primary" onClick={propose} disabled={!agentClass.trim() || busy !== null}>
            <Wand2 size={14} /> {busy === "propose" ? "Proposing…" : "Propose intent"}
          </button>
        </div>
      </Panel>

      {proposal && (
        <>
          {proposal.params_available === false && (
            <Panel data-testid="params-warning">
              <div className="row gap-8 items-center">
                <AlertTriangle size={16} />
                <div>
                  <strong>Proposed from tool names only.</strong> The audit log for this class carries no
                  call parameters, so this proposal cannot constrain recipients, data classes or SQL
                  tables. Enable parameter capture, or supply sample calls, before relying on a
                  destination-level rule.
                </div>
              </div>
            </Panel>
          )}

          <div className="stat-row">
            <StatTile label="Rules" value={rules.length} />
            <StatTile label="Calls sampled" value={proposal.sampled} />
            {report && <StatTile label="Would allow" value={report.would_allow} />}
            {report && (
              <StatTile label="Would block" value={report.would_block} color={report.would_block ? "#FF3B5C" : undefined} />
            )}
          </div>

          <Panel
            title="Proposed intent"
            sub="Every rule is an ALLOW. There is no deny list — deny is the absence of a match."
            action={
              <div className="row gap-8">
                <button className="btn" onClick={dryRun} disabled={busy !== null}>
                  <Play size={14} /> {busy === "dryrun" ? "Replaying…" : "Dry run"}
                </button>
                <button
                  className="btn"
                  onClick={saveDraft}
                  disabled={busy !== null || !report || ns === "all"}
                  title={
                    ns === "all"
                      ? "Pick a single namespace — a draft is stored against one, not all"
                      : !report
                        ? "Dry run it first"
                        : undefined
                  }
                >
                  <FileText size={14} /> Save as draft
                </button>
              </div>
            }
          >
            {!report && (
              <div className="muted small" data-testid="dryrun-hint">
                Dry run this against recorded traffic before saving — the draft is only worth having once
                you know what it would have refused.
              </div>
            )}
            <ul className="rule-list">
              {rules.map((rule) => (
                <li key={rule.id} data-testid={`rule-${rule.id}`}>
                  <code>{rule.id}</code>
                  {report?.unused_rules?.includes(rule.id) && (
                    <span className="badge warn" title="No recorded call matched this rule">
                      matched nothing
                    </span>
                  )}
                  {typeof report?.coverage?.[rule.id] === "number" && !report.unused_rules.includes(rule.id) && (
                    <span className="badge ok">{report.coverage[rule.id]} calls</span>
                  )}
                  <div className="muted small">{describePredicates(rule).join(" · ")}</div>
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
            <div className="row gap-8 items-center" data-testid="no-blocks">
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
          <div className="row gap-8 items-center">
            <FileText size={16} />
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
