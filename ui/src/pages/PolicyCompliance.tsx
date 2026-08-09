import { useMemo, useState } from "react";
import { Link } from "react-router-dom";

import {
  fetchBaselineControls,
  fetchCompliancePrincipals,
  fetchPolicyCompliance,
  fetchPolicyList,
  fetchPolicySource,
  type CompliancePrincipal,
  type PolicyListRow
} from "../api/client";
import { DataTable } from "../components/common/DataTable";
import { DonutChart } from "../components/common/DonutChart";
import { PageHead } from "../components/common/PageHead";
import { Panel } from "../components/common/Panel";
import { StatTile } from "../components/common/StatTile";
import { useApi } from "../hooks/useApi";
import { useApp } from "../store/AppContext";

// Scopes the product owns. They are real policies and they really enforce, but they are not something
// the customer authored, so they do not belong in a view whose whole subject is "your own policies".
// `<class>__remediation__` is the per-class overlay the compliance flow itself writes.
const RESERVED = new Set(["__baseline__", "__controls__", "__pack__", "__pack_override__", "__pack_weaken__", "__guardrail__"]);
// baseline_router._CONTROLS_PRIORITY — the tier the shipped detectors are materialised at.
const CONTROLS_TIER_PRIORITY = 2;

const isReserved = (agentClass: string) => RESERVED.has(agentClass) || agentClass.endsWith("__remediation__");

// Every rule id a policy DEFINES. /policy-compliance is keyed by rule_id and knows nothing about which
// policy owns it, so this regex is the join. It matches the partial-set heads the whole codebase uses
// (`blocks["x"] {`), which is also what the baseline compiler and the Visual Builder emit.
const HEAD_RE = /^\s*(?:blocks|escalates|audits)\[\s*"([A-Za-z0-9_.:-]+)"\s*\]/gm;

export function ruleIdsIn(rego: string): string[] {
  const out = new Set<string>();
  for (const m of rego.matchAll(HEAD_RE)) {
    // The never-firing sentinel the baseline compiler emits so an all-monitor module still compiles.
    if (m[1] !== "__never__") out.add(m[1]);
  }
  return [...out];
}

type PolicyRow = {
  key: string;
  name: string;
  agentClass: string;
  scope: string;
  mode: string;
  version: number | null;
  /** null === we could not read this policy's rego, so we do NOT know its rules. Never 0. */
  ruleIds: string[] | null;
  nonCompliant: string[];
  totalPrincipals: number;
  /** null === not computable (unreadable rego, or no principals to measure against). */
  compliancePct: number | null;
  priority: number;
  /** Base tiers resolve by HIGHEST PRIORITY OUTRIGHT, so a class policy above the controls tier
   *  means the shipped controls do not run for that class at all. Proven on a live cluster. */
  masksBaseline: boolean;
  calls: number;
  state: "Compliant" | "Non-compliant" | "Not evaluated" | "Unknown";
};

const STATE_COLOR: Record<PolicyRow["state"], string> = {
  Compliant: "var(--allow, #00E5A0)",
  "Non-compliant": "var(--block, #FF3B5C)",
  "Not evaluated": "var(--text-muted)",
  Unknown: "var(--escalate, #FFB020)"
};

/** Azure renders "0% (0 out of 4)". Same shape, plus an explicit unknown — a percentage we cannot
 *  compute must read as unknown, never as 100%. */
function ComplianceBar({ pct, compliant, total }: { pct: number | null; compliant: number; total: number }) {
  if (pct === null) {
    return <span style={{ fontSize: 12, color: "var(--text-muted)" }}>—</span>;
  }
  const colour = pct === 100 ? "var(--allow, #00E5A0)" : pct >= 50 ? "var(--escalate, #FFB020)" : "var(--block, #FF3B5C)";
  return (
    <div style={{ minWidth: 150 }}>
      <div style={{ fontSize: 12 }}>
        {pct}% <span style={{ color: "var(--text-muted)" }}>({compliant} out of {total})</span>
      </div>
      <div style={{ height: 4, background: "var(--border)", borderRadius: 2, marginTop: 4, overflow: "hidden" }}>
        <div style={{ width: `${pct}%`, height: "100%", background: colour }} />
      </div>
    </div>
  );
}

export function PolicyCompliance() {
  // `routeMeta.isTimeScoped` already returns true for /compliance/*, so the GLOBAL header range
  // selector drives this page. Adding an in-page picker gave two range controls on one screen that
  // did not agree — the header said 24h while the page said 7d.
  const { namespace, timeRange } = useApp();
  const range = timeRange;
  const [selected, setSelected] = useState<string | null>(null);

  const compliance = useApi(() => fetchPolicyCompliance(namespace, range), [namespace, range], {
    cacheKey: `pc:compliance:${namespace}:${range}`,
    staleTimeMs: 30_000
  });
  const principals = useApi(() => fetchCompliancePrincipals(namespace), [namespace], {
    cacheKey: `pc:principals:${namespace}`,
    staleTimeMs: 30_000
  });
  // Policies plus their rego, in one loader: the rule_id -> policy join needs the source, and a policy
  // whose source will not load must stay DISTINGUISHABLE from one with no rules (ruleIds: null).
  const policies = useApi(
    async () => {
      const list = (await fetchPolicyList(namespace)).filter((p) => p.agent_class && !isReserved(p.agent_class));
      return Promise.all(
        list.map(async (p: PolicyListRow) => {
          let ruleIds: string[] | null = null;
          try {
            // Fetch by the row's OWN namespace. Under "All namespaces" the list spans namespaces, and
            // asking for <selected>/<class> 404s for every row that lives somewhere else — which
            // renders the whole page Unknown for a reason that is our bug, not the customer's.
            const src = await fetchPolicySource(p.namespace ?? namespace, p.agent_class as string);
            ruleIds = ruleIdsIn(src.rego_source ?? "");
          } catch {
            ruleIds = null;
          }
          return { policy: p, ruleIds };
        })
      );
    },
    [namespace],
    { cacheKey: `pc:policies:${namespace}`, staleTimeMs: 30_000 }
  );

  // The DENOMINATOR. Synthetic identities are real rows but they are not a customer workload, so
  // counting them would move a compliance number that no operator can act on.
  const realPrincipals = useMemo(() => {
    const seen = new Set<string>();
    for (const p of (principals.data ?? []) as CompliancePrincipal[]) {
      if (p.synthetic) continue;
      if (p.agent_class) seen.add(p.agent_class);
    }
    return seen;
  }, [principals.data]);

  const byRule = useMemo(() => {
    const m = new Map<string, { count: number; classes: string[] }>();
    for (const c of compliance.data?.controls ?? []) {
      m.set(c.control_id, { count: c.count, classes: c.agent_classes.map((a) => a.name) });
    }
    return m;
  }, [compliance.data]);

  // A failed compliance fetch reads EXACTLY like a clean one: no rows means no offenders means 100%.
  // Caught by its own test — the degraded banner said "unknown" while the headline said 100% compliant,
  // which is the single most dangerous thing this page could render. If the evidence feed is
  // unreadable, no percentage on this page is knowable, regardless of what the other two loaders did.
  const evidenceUnreadable = Boolean(compliance.error) || !compliance.data;

  const rows: PolicyRow[] = useMemo(() => {
    const total = realPrincipals.size;
    return (policies.data ?? []).map(({ policy, ruleIds }) => {
      const agentClass = policy.agent_class as string;
      const offenders = new Set<string>();
      let calls = 0;
      if (ruleIds) {
        for (const id of ruleIds) {
          const hit = byRule.get(id);
          if (!hit) continue;
          calls += hit.count;
          // Only principals we are counting in the denominator can be counted in the numerator, or a
          // synthetic offender would push compliance below 0 out of N.
          for (const cls of hit.classes) if (realPrincipals.has(cls)) offenders.add(cls);
        }
      }
      const nonCompliant = [...offenders].sort();
      let state: PolicyRow["state"];
      let compliancePct: number | null;
      if (!ruleIds || evidenceUnreadable) {
        state = "Unknown";
        compliancePct = null;
      } else if (total === 0) {
        // No workload to measure against. "100% compliant out of nothing" is the exact lie this avoids.
        state = "Not evaluated";
        compliancePct = null;
      } else {
        compliancePct = Math.round(((total - nonCompliant.length) / total) * 100);
        state = nonCompliant.length === 0 ? "Compliant" : "Non-compliant";
      }
      // The controls tier is priority 2 (baseline_router._CONTROLS_PRIORITY). Anything above it wins
      // outright, so the shipped controls never run for this class.
      const priority = policy.priority ?? 100;
      return {
        key: agentClass,
        name: policy.policy_name || agentClass,
        agentClass,
        // The ROW's namespace, never the selected one. Under "All namespaces" the list returns
        // policies from every namespace, so stamping the current selection onto each row labelled a
        // policy with a namespace it does not live in — and the detail fetch then 404s, which is how
        // this surfaced: a row that claimed chatbot-prod, and a 404 fetching chatbot-prod/<class>.
        scope: `${policy.namespace ?? namespace} / ${agentClass}`,
        mode: policy.enforcement_mode ?? "—",
        version: policy.current_version ?? null,
        ruleIds,
        nonCompliant,
        totalPrincipals: total,
        compliancePct,
        priority,
        masksBaseline: priority > CONTROLS_TIER_PRIORITY,
        calls,
        state
      };
    });
  }, [policies.data, byRule, realPrincipals, namespace, evidenceUnreadable]);

  const maskingRows = rows.filter((r) => r.masksBaseline);
  const measurable = rows.filter((r) => r.compliancePct !== null);
  const nonCompliantRows = rows.filter((r) => r.state === "Non-compliant");
  // Overall = principals clean across EVERY policy, matching Azure's resource-level roll-up.
  const offendersOverall = useMemo(() => {
    const s = new Set<string>();
    for (const r of rows) for (const c of r.nonCompliant) s.add(c);
    return s;
  }, [rows]);
  const totalPrincipals = realPrincipals.size;
  const compliantPrincipals = Math.max(0, totalPrincipals - offendersOverall.size);
  const overallPct =
    evidenceUnreadable || totalPrincipals === 0
      ? null
      : Math.round((compliantPrincipals / totalPrincipals) * 100);

  const scanned = compliance.data?.scanned ?? null;
  const unreadable = compliance.error || principals.error || policies.error;
  const loading = compliance.loading || principals.loading || policies.loading;

  const selectedRow = rows.find((r) => r.key === selected) ?? null;

  // What a class policy is switching OFF. The controls tier sits at priority 2 and base tiers resolve
  // by highest priority OUTRIGHT, so any class policy above it takes the whole shipped detector set
  // out of play for that class.
  const controls = useApi(() => fetchBaselineControls(namespace), [namespace], {
    cacheKey: `pc:controls:${namespace}`,
    staleTimeMs: 30_000
  });
  const activeControlCount = (controls.data?.controls ?? []).filter((c) => c.effect !== "off").length;
  const enforcingControlCount = (controls.data?.controls ?? []).filter((c) => c.effect === "deny").length;

  return (
    <div className="page-enter stack">
      <PageHead
        title="Policy Compliance"
        subtitle={
          <>
            Showing: <b>{namespace}</b> · policies you authored · last {range}
          </>
        }
      />

      {/* A surface we could not READ is not a compliant surface. */}
      {unreadable && (
        <div
          data-testid="pc-unreadable"
          style={{
            padding: "10px 14px",
            marginBottom: 16,
            background: "rgba(255,176,32,0.08)",
            border: "1px solid #4a3a1a",
            borderRadius: 10,
            fontSize: 12,
            color: "var(--escalate, #FFB020)"
          }}
        >
          Compliance could not be read in full — figures below are <b>unknown, not &ldquo;compliant&rdquo;</b>.{" "}
          <span style={{ color: "var(--text-muted)" }}>{String(unreadable)}</span>
        </div>
      )}

      {/* ---- Azure's four summary tiles ---- */}
      <div className="grid-kit g4">
        <Panel pad>
          <div style={{ fontSize: 12, color: "var(--text-muted)" }}>Overall resource compliance</div>
          <div data-testid="pc-overall" data-pct={overallPct ?? "unknown"} style={{ fontSize: 34, fontWeight: 600, marginTop: 4 }}>
            {overallPct === null ? "—" : `${overallPct}%`}
          </div>
          {/* The subline must agree with the headline. It read "53 out of 53" under a "—" while the
              evidence feed was unreadable, which is a stronger claim than the number it sits beneath. */}
          <div style={{ fontSize: 11, color: "var(--text-muted)" }}>
            {evidenceUnreadable
              ? "compliance evidence unavailable"
              : totalPrincipals === 0
                ? "no agent classes seen yet"
                : `${compliantPrincipals} out of ${totalPrincipals}`}
          </div>
        </Panel>

        {/* DonutChart renders its OWN Panel and defaults its title to "Trust Distribution" — wrapping
            it gave two nested panels with two competing headings, and the chart announced itself as a
            different metric on a compliance page. Let it own the panel, and name it. */}
        {totalPrincipals === 0 ? (
          <Panel pad title="Resources by compliance state">
            <div data-testid="pc-donut-empty" style={{ fontSize: 12, color: "var(--text-muted)" }}>
              No agent classes have run yet.
            </div>
          </Panel>
        ) : (
          <DonutChart
            title="Resources by compliance state"
            data={[
              { name: "Compliant", value: compliantPrincipals },
              { name: "Non-compliant", value: offendersOverall.size }
            ]}
          />
        )}

        <StatTile
          label="Non-compliant policies"
          value={`${nonCompliantRows.length}`}
          sub={`out of ${rows.length}`}
          color={nonCompliantRows.length > 0 ? "var(--block, #FF3B5C)" : undefined}
        />

        {/* The honesty number: zero non-compliant out of ZERO traffic is idle, not clean. */}
        <StatTile
          label="Calls examined"
          value={scanned === null ? "—" : scanned.toLocaleString()}
          sub={scanned === 0 ? "no real traffic in this window" : `over the last ${range}`}
        />
      </div>

      {/* The finding this page exists to surface, proven live: same SSN payload, `r2-support` (which
          has a class policy) ALLOWED it while a class with no policy was BLOCKED by pii_detection.
          Base tiers resolve by highest priority OUTRIGHT, so writing one class policy switches the
          whole shipped detector set off for that class — and until now nothing said so anywhere. */}
      {maskingRows.length > 0 && activeControlCount > 0 && (
        <div
          data-testid="pc-baseline-masked"
          style={{
            padding: "10px 14px",
            border: "1px solid #4a3a1a",
            background: "rgba(255,176,32,0.08)",
            borderRadius: 10,
            fontSize: 12,
            color: "var(--escalate)"
          }}
        >
          <b>
            {maskingRows.length} {maskingRows.length === 1 ? "policy supersedes" : "policies supersede"} the shipped
            baseline controls
          </b>{" "}
          <span style={{ color: "var(--text-secondary)" }}>
            — {maskingRows.map((r) => r.agentClass).join(", ")}. Base tiers resolve by highest priority outright, so
            the {activeControlCount} active control{activeControlCount === 1 ? "" : "s"}
            {enforcingControlCount > 0 ? ` (${enforcingControlCount} enforcing)` : ""} on Target Settings do not run
            for {maskingRows.length === 1 ? "that class" : "those classes"} at all. Anything you still need must be
            written into the policy itself.
          </span>{" "}
          <Link to="/policies/targets">Review controls</Link>
        </div>
      )}

      {/* ---- Per-policy compliance ---- */}
      <Panel
        title="Policy compliance"
        sub="One row per policy you authored. Resource compliance counts agent classes, not calls — a class is non-compliant for a policy if any of that policy's rules flagged it."
        style={{ marginBottom: 16 }}
      >
        {loading && !rows.length ? (
          <div data-testid="pc-loading" style={{ fontSize: 13, color: "var(--text-muted)" }}>
            Loading compliance…
          </div>
        ) : rows.length === 0 ? (
          <div data-testid="pc-empty" style={{ fontSize: 13, color: "var(--text-muted)" }}>
            No policies of your own in <b>{namespace}</b>. The shipped baseline controls are governed on{" "}
            <Link to="/policies/targets">Target Settings</Link>.
          </div>
        ) : (
          <DataTable
            rowKey="key"
            selectedKey={selected}
            onRowClick={(r) => {
              const key = (r as unknown as PolicyRow).key;
              setSelected(key === selected ? null : key);
            }}
            rows={rows as unknown as Array<Record<string, unknown>>}
            columns={[
              {
                key: "name",
                title: "Name",
                render: (_v, r) => (
                  <span data-testid={`pc-row-${(r as unknown as PolicyRow).key}`}>
                    {(r as unknown as PolicyRow).name}
                    {(r as unknown as PolicyRow).version !== null && (
                      <span style={{ color: "var(--text-muted)", marginLeft: 6, fontSize: 11 }}>
                        v{(r as unknown as PolicyRow).version}
                      </span>
                    )}
                    {(r as unknown as PolicyRow).masksBaseline && activeControlCount > 0 && (
                      <span
                        data-testid={`pc-masks-${(r as unknown as PolicyRow).key}`}
                        title="Base tiers resolve by highest priority outright, so the shipped controls do not run for this class."
                        style={{ color: "var(--escalate)", marginLeft: 8, fontSize: 10, whiteSpace: "nowrap" }}
                      >
                        supersedes baseline
                      </span>
                    )}
                  </span>
                )
              },
              { key: "scope", title: "Scope" },
              {
                key: "mode",
                title: "Mode",
                render: (_v, r) => <code style={{ fontSize: 11 }}>{(r as unknown as PolicyRow).mode}</code>
              },
              {
                key: "state",
                title: "Compliance state",
                render: (_v, r) => {
                  const row = r as unknown as PolicyRow;
                  return (
                    <span data-testid={`pc-state-${row.key}`} style={{ color: STATE_COLOR[row.state], fontSize: 12 }}>
                      {row.state}
                    </span>
                  );
                }
              },
              {
                key: "compliancePct",
                title: "Resource compliance",
                render: (_v, r) => {
                  const row = r as unknown as PolicyRow;
                  return (
                    <span data-testid={`pc-pct-${row.key}`} data-pct={row.compliancePct ?? "unknown"}>
                      <ComplianceBar
                        pct={row.compliancePct}
                        compliant={row.totalPrincipals - row.nonCompliant.length}
                        total={row.totalPrincipals}
                      />
                    </span>
                  );
                }
              },
              {
                key: "nonCompliant",
                title: "Non-compliant resources",
                render: (_v, r) => {
                  const row = r as unknown as PolicyRow;
                  return <span style={{ fontSize: 12 }}>{row.ruleIds === null ? "—" : row.nonCompliant.length}</span>;
                }
              }
            ]}
          />
        )}
      </Panel>

      {/* ---- Remediation (Azure's "Policies to remediate") ---- */}
      <Panel
        title="Remediation"
        sub="What to do about each non-compliant policy. Nothing here changes enforcement on its own."
        style={{ marginBottom: 16 }}
      >
        {nonCompliantRows.length === 0 ? (
          <div data-testid="pc-remediation-empty" style={{ fontSize: 13, color: "var(--text-muted)" }}>
            {rows.length === 0
              ? "No policies to remediate."
              : // "Nothing to remediate" is a CLEARANCE, and it must not be issued while any policy's
                // state is still unknown. Caught in the browser: mid-load every row read Unknown while
                // this line already said "every policy is compliant" — an all-clear over data that had
                // not arrived, which is exactly the reading an operator would stop at.
                loading || evidenceUnreadable || rows.some((r) => r.state === "Unknown")
                ? "Compliance is not fully known yet — this is not an all-clear."
                : totalPrincipals === 0
                  ? "No agent classes have run yet, so nothing has been evaluated."
                  : "Nothing to remediate — every policy is compliant across all agent classes."}
          </div>
        ) : (
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            {nonCompliantRows.map((r) => (
              <div
                key={r.key}
                data-testid={`pc-remediate-${r.key}`}
                style={{ border: "1px solid var(--border)", borderRadius: 8, padding: "10px 12px" }}
              >
                <div style={{ display: "flex", justifyContent: "space-between", gap: 12, flexWrap: "wrap" }}>
                  <div style={{ minWidth: 0 }}>
                    <div style={{ fontSize: 13, fontWeight: 600 }}>{r.name}</div>
                    <div style={{ fontSize: 12, color: "var(--text-secondary)", marginTop: 2 }}>
                      {r.nonCompliant.length} of {r.totalPrincipals} agent class
                      {r.totalPrincipals === 1 ? "" : "es"} non-compliant · {r.calls.toLocaleString()} call
                      {r.calls === 1 ? "" : "s"} flagged
                    </div>
                    <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 4 }}>
                      {r.nonCompliant.join(", ")}
                    </div>
                    <div style={{ fontSize: 11, color: "var(--escalate, #FFB020)", marginTop: 6, maxWidth: 620 }}>
                      {r.mode === "block"
                        ? "This policy is enforcing, so these calls were refused. Remediate the workload, or add an exception if the traffic is legitimate."
                        : "This policy is in audit, so these calls PROCEEDED and were only recorded. Promote it to block in Policy Catalog once the count above looks right."}
                    </div>
                  </div>
                  <div style={{ display: "flex", gap: 8, alignItems: "flex-start", flexShrink: 0 }}>
                    <Link className="btn btn-outline" to={`/policies/catalog?ns=${encodeURIComponent(namespace)}`}>
                      Open policy
                    </Link>
                    <Link className="btn btn-outline" to={`/audit?ns=${encodeURIComponent(namespace)}`}>
                      View in Audit Log
                    </Link>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </Panel>

      {/* ---- Evidence: a REDIRECT, not a second Audit Log ----
           A 25-row table here was a worse copy of a page that already does filtering, tailing,
           export and redteam separation. Deep-link into the real one instead, pre-filtered to the
           exact class and rule, so the operator lands on the evidence rather than on a search box. */}
      <Panel
        title="Evidence"
        sub="Every decision behind these numbers lives in the Audit Log. These links open it already filtered."
      >
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
          <Link
            className="btn btn-outline"
            data-testid="pc-evidence-all"
            to={`/audit?ns=${encodeURIComponent(namespace)}&range=${encodeURIComponent(range)}`}
          >
            All decisions in {namespace}
          </Link>
          {selectedRow ? (
            <>
              <Link
                className="btn btn-outline"
                data-testid="pc-evidence-class"
                to={`/audit?ns=${encodeURIComponent(namespace)}&range=${encodeURIComponent(range)}&agent=${encodeURIComponent(selectedRow.agentClass)}`}
              >
                {selectedRow.agentClass} only
              </Link>
              {(selectedRow.ruleIds ?? []).map((id) => (
                <Link
                  key={id}
                  className="btn btn-outline"
                  data-testid={`pc-evidence-rule-${id}`}
                  to={`/audit?ns=${encodeURIComponent(namespace)}&range=${encodeURIComponent(range)}&rule=${encodeURIComponent(id)}`}
                >
                  rule: {id}
                </Link>
              ))}
            </>
          ) : (
            <span style={{ fontSize: 12, color: "var(--text-muted)", alignSelf: "center" }}>
              Select a policy above for per-class and per-rule links.
            </span>
          )}
        </div>
      </Panel>
    </div>
  );
}

export default PolicyCompliance;
