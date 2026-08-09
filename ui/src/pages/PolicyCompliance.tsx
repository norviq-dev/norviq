import { useMemo, useState } from "react";
import { Link } from "react-router-dom";

import {
  fetchBaselineControls,
  fetchCompliancePrincipals,
  fetchPolicyCompliance,
  fetchPolicyList,
  fetchPolicySource,
  fetchVolume,
  type CompliancePrincipal,
  type PolicyListRow
} from "../api/client";
import { DataTable } from "../components/common/DataTable";
import { DonutChart } from "../components/common/DonutChart";
import { ScoreGauge } from "../components/common/ScoreGauge";
import { VolumeChart } from "../components/charts/VolumeChart";
import { PageHead } from "../components/common/PageHead";
import { Panel } from "../components/common/Panel";
import { useApi } from "../hooks/useApi";
import { useApp } from "../store/AppContext";

// Scopes the product owns. They are real policies and they really enforce, but they are not something
// the customer authored, so they do not belong in a view whose whole subject is "your own policies".
// `<class>__remediation__` is the per-class overlay the compliance flow itself writes.
const RESERVED = new Set(["__baseline__", "__controls__", "__pack__", "__pack_override__", "__pack_weaken__", "__guardrail__"]);
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
  namespace: string;
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
      const priority = policy.priority ?? 100;
      return {
        key: agentClass,
        name: policy.policy_name || agentClass,
        agentClass,
        // The ROW's namespace, never the selected one. Under "All namespaces" the list returns
        // policies from every namespace, so stamping the current selection onto each row labelled a
        // policy with a namespace it does not live in — and the detail fetch then 404s, which is how
        // this surfaced: a row that claimed chatbot-prod, and a 404 fetching chatbot-prod/<class>.
        namespace: policy.namespace ?? namespace,
        scope: `${policy.namespace ?? namespace} / ${agentClass}`,
        mode: policy.enforcement_mode ?? "—",
        version: policy.current_version ?? null,
        ruleIds,
        nonCompliant,
        totalPrincipals: total,
        compliancePct,
        priority,
        calls,
        state
      };
    });
  }, [policies.data, byRule, realPrincipals, namespace, evidenceUnreadable]);

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
  // Calls examined deserves a shape, not just a number: the same window, split allow vs block, is
  // what tells an operator whether 9,000 calls is steady traffic or one spike.
  const volume = useApi(() => fetchVolume(range, namespace), [namespace, range], {
    cacheKey: `pc:volume:${namespace}:${range}`,
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
        {/* Every card carries a visual. A card that is only a number is a number that could have been
            a sentence, and four of them in a row read as a form rather than a dashboard. */}
        {overallPct === null ? (
          <Panel pad title="Overall resource compliance">
            <div data-testid="pc-overall" data-pct="unknown" style={{ fontSize: 34, fontWeight: 600 }}>
              —
            </div>
            <div style={{ fontSize: 11, color: "var(--text-muted)" }}>
              {evidenceUnreadable
                ? "compliance evidence unavailable"
                : "no agent classes seen yet"}
            </div>
          </Panel>
        ) : (
          <div data-testid="pc-overall" data-pct={overallPct}>
            <ScoreGauge
              score={overallPct}
              title="Overall resource compliance"
              sub={`${compliantPrincipals} out of ${totalPrincipals} agent classes`}
            />
          </div>
        )}

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

        {rows.length === 0 ? (
          <Panel pad title="Policies by state">
            <div data-testid="pc-policy-donut-empty" style={{ fontSize: 12, color: "var(--text-muted)" }}>
              No policies of your own here.
            </div>
          </Panel>
        ) : (
          <div data-testid="pc-policy-donut" data-noncompliant={nonCompliantRows.length} data-total={rows.length}>
            <DonutChart
              title="Policies by state"
              data={[
                { name: "Compliant", value: rows.filter((r) => r.state === "Compliant").length },
                { name: "Non-compliant", value: nonCompliantRows.length },
                { name: "Not evaluated", value: rows.filter((r) => r.state !== "Compliant" && r.state !== "Non-compliant").length }
              ]}
            />
          </div>
        )}

        {/* Calls examined — the honesty number, now with the shape of the traffic behind it. */}
        {(volume.data ?? []).length > 0 ? (
          <div data-testid="pc-volume" data-scanned={scanned ?? "unknown"}>
            <VolumeChart
              title={scanned === null ? "Calls examined — unknown" : `Calls examined · ${scanned.toLocaleString()}`}
              data={volume.data ?? []}
              labels={["Allowed", "Blocked"]}
            />
          </div>
        ) : (
          <Panel pad title="Calls examined">
            <div data-testid="pc-scanned" data-scanned={scanned ?? "unknown"} style={{ fontSize: 34, fontWeight: 600 }}>
              {scanned === null ? "—" : scanned.toLocaleString()}
            </div>
            <div style={{ fontSize: 11, color: "var(--text-muted)" }}>
              {scanned === 0 ? "no real traffic in this window" : `over the last ${range}`}
            </div>
          </Panel>
        )}
      </div>

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

      {/* ---- Remediation — Azure's "Policies to remediate" columns ----
           Policy definition | Assignment | Resources to remediate | Scope. The analogy holds because
           each column has a real referent here: the rego rule is the definition, the (namespace,
           agent_class) row is the assignment, the agent classes are the resources, and the scope is
           where the row is written. What Azure has and this does NOT is a remediation TASK — nothing
           on this page mutates anything, and the copy says so rather than implying a fix button. */}
      <Panel
        title="Remediation"
        sub="Non-compliant policies and what each one needs. Nothing here changes enforcement on its own."
      >
        {nonCompliantRows.length === 0 ? (
          <div data-testid="pc-remediation-empty" style={{ fontSize: 13, color: "var(--text-muted)" }}>
            {rows.length === 0
              ? "No policies to remediate."
              : loading || evidenceUnreadable || rows.some((r) => r.state === "Unknown")
                ? "Compliance is not fully known yet — this is not an all-clear."
                : totalPrincipals === 0
                  ? "No agent classes have run yet, so nothing has been evaluated."
                  : "Nothing to remediate — every policy is compliant across all agent classes."}
          </div>
        ) : (
          <DataTable
            rowKey="key"
            rows={nonCompliantRows as unknown as Array<Record<string, unknown>>}
            columns={[
              {
                key: "name",
                title: "Policy definition",
                render: (_v, r) => {
                  const row = r as unknown as PolicyRow;
                  return (
                    <div data-testid={`pc-remediate-${row.key}`}>
                      <div style={{ fontSize: 13 }}>{row.name}</div>
                      <div style={{ fontSize: 11, color: "var(--text-muted)" }}>
                        {(row.ruleIds ?? []).length} rule{(row.ruleIds ?? []).length === 1 ? "" : "s"}
                        {row.ruleIds?.length ? ` · ${row.ruleIds.join(", ")}` : ""}
                      </div>
                    </div>
                  );
                }
              },
              {
                key: "mode",
                title: "Assignment",
                render: (_v, r) => {
                  const row = r as unknown as PolicyRow;
                  return (
                    <div>
                      <code style={{ fontSize: 11 }}>{row.agentClass}</code>
                      <div style={{ fontSize: 11, color: "var(--text-muted)" }}>
                        v{row.version} · {row.mode} · priority {row.priority}
                      </div>
                    </div>
                  );
                }
              },
              {
                key: "nonCompliant",
                title: "Resources to remediate",
                render: (_v, r) => {
                  const row = r as unknown as PolicyRow;
                  return (
                    <div>
                      <div style={{ fontSize: 13 }}>
                        {row.nonCompliant.length} of {row.totalPrincipals}
                      </div>
                      <div style={{ fontSize: 11, color: "var(--text-muted)" }}>
                        {row.nonCompliant.join(", ")} · {row.calls.toLocaleString()} call
                        {row.calls === 1 ? "" : "s"} flagged
                      </div>
                    </div>
                  );
                }
              },
              { key: "scope", title: "Scope", render: (v) => <code style={{ fontSize: 11 }}>{String(v)}</code> },
              {
                key: "state",
                title: "",
                render: (_v, r) => {
                  const row = r as unknown as PolicyRow;
                  return (
                    <div style={{ display: "flex", gap: 6, justifyContent: "flex-end" }}>
                      <Link
                        className="btn btn-outline"
                        data-testid={`pc-open-policy-${row.key}`}
                        to={`/policies/catalog?ns=${encodeURIComponent(row.namespace)}&agent_class=${encodeURIComponent(row.agentClass)}`}
                      >
                        Open policy
                      </Link>
                      <Link
                        className="btn btn-outline"
                        data-testid={`pc-open-audit-${row.key}`}
                        to={`/audit?ns=${encodeURIComponent(row.namespace)}&range=${encodeURIComponent(range)}&agent=${encodeURIComponent(row.agentClass)}`}
                      >
                        View in Audit Log
                      </Link>
                    </div>
                  );
                }
              }
            ]}
          />
        )}
        {nonCompliantRows.length > 0 && (
          <div style={{ fontSize: 11, color: "var(--escalate)", marginTop: 10, maxWidth: 720 }}>
            {nonCompliantRows.some((r) => r.mode !== "block")
              ? "A policy in audit RECORDED these calls and let them through — promote it in Policy Catalog once the counts look right."
              : "These policies are enforcing, so the calls above were refused. Remediate the workload, or add an exception if the traffic is legitimate."}
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
