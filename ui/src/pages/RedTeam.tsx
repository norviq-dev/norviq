// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// Red Team view (TESTING). Runs the attack suite against the deployed posture and shows the REAL,
// durable efficacy: a proven-blocking scorecard, per-attack results, a per-ATLAS-technique / per-OWASP
// breakdown, run history, and a link to the Audit evidence. Everything comes from the backend
// (/redteam/results/*, /redteam/suite) — no fabricated numbers, and an honest empty state before the first run.

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { AlertTriangle, CheckCircle2, ChevronLeft, ChevronRight, Loader2, PlayCircle, ShieldAlert, XCircle } from "lucide-react";
import {
  fetchRedteamHistory,
  fetchRedteamLatest,
  fetchRedteamTargets,
  runRedteamSuite,
  type RedteamLatest,
  type RedteamRunSummary
} from "../api/client";
import { DecisionBadge, type Decision } from "../components/common/DecisionBadge";
import { KitButton } from "../components/common/KitButton";
import { PageHead } from "../components/common/PageHead";
import { Panel } from "../components/common/Panel";
import { timeAgo } from "../lib/d3-helpers";
import { useApp } from "../store/AppContext";

const ACCENT = "#2ddab8";
const DANGER = "#ff3b5c";

const thStyle: React.CSSProperties = { textAlign: "left", padding: "8px 10px", borderBottom: "1px solid var(--border)", color: "var(--text-muted)", fontWeight: 600, whiteSpace: "nowrap" };
const tdStyle: React.CSSProperties = { padding: "8px 10px", borderBottom: "1px solid var(--border)", verticalAlign: "top" };

const PAGE_SIZE = 50; // Bound mounted result rows regardless of run size (avoids thousands of inline SVGs)

const RedTeam = () => {
  const { namespace } = useApp();
  const [latest, setLatest] = useState<RedteamLatest | null>(null);
  const [history, setHistory] = useState<RedteamRunSummary[]>([]);
  const [targets, setTargets] = useState<string[]>([]);
  const [target, setTarget] = useState<string>(""); // "" = all real classes in the namespace
  const [loading, setLoading] = useState(true);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [page, setPage] = useState(0);
  const [failedOnly, setFailedOnly] = useState(false);
  const [targetsOpen, setTargetsOpen] = useState(false); // B: expandable target-class list (collapsed default)
  // Synchronous one-submit guard. `disabled` only takes effect after a re-render, so a rapid double-click
  // can fire twice before React repaints — this ref blocks the second call in the SAME tick (exactly one POST).
  const inFlightRef = useRef(false);

  const targetNs = namespace === "all" ? "default" : namespace;

  const load = useCallback(async () => {
    setLoading(true);
    // allSettled, NOT all. These three reads are independent, and with `Promise.all` in one
    // try/catch a single failure erased the two that had loaded fine — one throttled history fetch
    // blanked the scorecard, the attack table AND the empty state together, because the render gate
    // below requires every piece at once. A partial outage should cost you the part that failed.
    //
    // The `.catch(() => ({ targets: [] }))` on targets was worse than useless: it turned an HTTP
    // error into "this namespace has no target classes", which is a confident, wrong answer.
    const [l, h, t] = await Promise.allSettled([
      // Scope efficacy + history to the selected namespace so the scorecard/table match the
      // scope the page displays (not whatever cluster-wide run was newest).
      fetchRedteamLatest(namespace),
      fetchRedteamHistory(15, namespace),
      fetchRedteamTargets(targetNs)
    ]);
    if (l.status === "fulfilled") setLatest(l.value);
    if (h.status === "fulfilled") setHistory(h.value.runs ?? []);
    if (t.status === "fulfilled") setTargets(t.value.targets ?? []);
    // Report only what actually failed, and name it — "Failed to load red-team results" gave no clue
    // which of three calls broke, and appeared even when two of them had succeeded.
    const failed = [
      l.status === "rejected" ? "efficacy" : null,
      h.status === "rejected" ? "history" : null,
      t.status === "rejected" ? "target classes" : null
    ].filter(Boolean);
    setError(failed.length ? `Could not load ${failed.join(", ")}. The rest of this page is current.` : null);
    setLoading(false);
  }, [targetNs, namespace]);

  useEffect(() => {
    void load();
  }, [load]);

  // Whenever the displayed run changes (new run, or detail was pruned server-side), snap back to page 0 so
  // the pager can never point past the end of a smaller/scoped result set.
  useEffect(() => {
    setPage(0);
    setFailedOnly(false);
  }, [latest?.run_id]);

  const runSuite = async () => {
    if (inFlightRef.current) return; // Block a duplicate submit in the same tick → exactly one POST
    inFlightRef.current = true;
    setRunning(true);
    setError(null);
    setPage(0);
    try {
      await runRedteamSuite(target || undefined, targetNs);
      await load();
    } catch (e) {
      // A 409 means another run for this namespace is already in flight — surface it, don't double-run.
      const msg = e instanceof Error ? e.message : "Suite run failed";
      setError(/already running/i.test(msg) ? "A red-team suite is already running for this namespace." : msg);
    } finally {
      inFlightRef.current = false;
      setRunning(false);
    }
  };

  const runBtn = (
    <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
      <select
        className="input"
        value={target}
        onChange={(e) => setTarget(e.target.value)}
        disabled={running}
        aria-label="Target agent class"
        data-testid="redteam-target"
        style={{ fontSize: 12.5, padding: "6px 8px", maxWidth: 220 }}
      >
        <option value="">All classes{targets.length ? ` (${targets.length})` : ""}</option>
        {targets.map((c) => (
          <option key={c} value={c}>{c}</option>
        ))}
      </select>
      <KitButton
        variant="primary"
        icon={running ? undefined : PlayCircle}
        onClick={runSuite}
        disabled={running}
        aria-busy={running}
        data-testid="redteam-run"
      >
        {running && <Loader2 size={15} style={{ animation: "akSpin 0.8s linear infinite" }} />}
        {running ? "Running…" : `Run suite · ${target || targetNs}`}
      </KitButton>
    </div>
  );

  const eff = latest?.efficacy;
  const overall = eff?.overall;
  // Optional by design. Retention keeps the `efficacy` blob of older runs verbatim, and runs written
  // before this dimension shipped have neither key — the page must render those without throwing
  // rather than assume every stored run has the newest shape.
  const cov = eff?.vector_coverage;

  // Scope the table to the SELECTED RUN's results (from results/latest), then filter + paginate so the
  // number of MOUNTED rows stays bounded (≤ PAGE_SIZE) no matter how large the run is.
  const allRows = latest?.results ?? [];
  const rows = useMemo(() => (failedOnly ? allRows.filter(gotThrough) : allRows), [allRows, failedOnly]);
  const pageCount = Math.max(1, Math.ceil(rows.length / PAGE_SIZE));
  const safePage = Math.min(page, pageCount - 1);
  const pageRows = rows.slice(safePage * PAGE_SIZE, safePage * PAGE_SIZE + PAGE_SIZE);

  return (
    <div className="page-enter">
      <PageHead
        title="Red Team"
        subtitle="Attack-suite efficacy — how much of the known attack corpus is proven-blocking on the deployed posture"
        actions={runBtn}
      />

      {error && (
        <Panel style={{ marginBottom: 16, borderColor: "#ff3b5c55" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8, color: "#ff6b81" }} data-testid="redteam-error">
            <AlertTriangle size={16} /> {error}
          </div>
        </Panel>
      )}

      {loading && !latest && (
        <Panel data-testid="redteam-loading">
          <div className="panel-sub">Loading red-team results…</div>
        </Panel>
      )}

      {!loading && latest && !latest.has_run && (
        <Panel data-testid="redteam-empty">
          <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 12, padding: "28px 16px", textAlign: "center" }}>
            <ShieldAlert size={30} style={{ color: ACCENT }} />
            <div style={{ fontSize: 15, fontWeight: 600 }}>No red-team run yet</div>
            <div className="panel-sub" style={{ maxWidth: 460 }}>
              This posture has not been efficacy-tested. Run the attack suite to measure how much of the known
              attack corpus is proven-blocking — the results and per-technique breakdown appear here and feed the
              Compliance &amp; Overview "proven-blocking" evidence.
            </div>
            <div style={{ marginTop: 4 }}>{runBtn}</div>
          </div>
        </Panel>
      )}

      {!loading && latest?.has_run && overall && eff && (
        <>
          <Panel data-testid="redteam-scorecard" style={{ marginBottom: 16 }}>
            {/* Primary metric on the left · a grouped, evenly-spaced secondary-metric cluster in the middle
                (breathing room + clear separation) · the run summary on the right. Wraps cleanly at narrow widths. */}
            <div style={{ display: "flex", flexWrap: "wrap", gap: 20, alignItems: "center", justifyContent: "space-between" }}>
              <div style={{ flex: "0 0 auto" }}>
                <div className="panel-sub">Proven-blocking (last run)</div>
                <div style={{ fontSize: 40, fontWeight: 700, color: ACCENT, lineHeight: 1.1 }} data-testid="redteam-proven-pct">
                  {overall.proven_blocking_pct}%
                </div>
                <div className="panel-sub" style={{ marginTop: 2 }}>
                  {overall.caught}/{overall.total} block-expected attacks caught
                </div>
              </div>
              <div
                data-testid="redteam-metric-cluster"
                style={{
                  // Unboxed — the metrics keep their grid + spacing but drop the --bg-surface/--border panel
                  // (reads lighter), and the group is nudged slightly RIGHT so the left primary "N%" has room.
                  display: "grid",
                  gridTemplateColumns: "repeat(auto-fit, minmax(96px, 1fr))",
                  gap: "14px 26px",
                  alignItems: "center",
                  padding: "4px 0",
                  marginLeft: 32,
                  flex: "1 1 340px",
                  minWidth: 0,
                }}
              >
                <Stat label="Caught" value={overall.caught} color={ACCENT} icon={CheckCircle2} />
                <Stat
                  label="Got through"
                  value={overall.got_through}
                  color={overall.got_through > 0 ? DANGER : "var(--text-secondary)"}
                  icon={overall.got_through > 0 ? XCircle : CheckCircle2}
                  testid="redteam-gotthrough"
                />
                <Stat label="Suite pass-rate" value={`${latest.pass_rate}%`} />
                <Stat label="Attacks × classes" value={latest.total ?? 0} />
              </div>
              <div style={{ textAlign: "right", flex: "0 0 auto" }}>
                {/* B: a concise count + timestamp, not the full comma-separated class list (wall-of-text on a
                    real cluster). The names are available on demand via the collapsed "N classes ▾" toggle;
                    the class selector + the per-row Class column already expose them inline. */}
                {(() => {
                  const n = (latest.targets ?? []).length;
                  const noun = `${n} class${n === 1 ? "" : "es"}`;
                  return (
                    <>
                      <div className="panel-sub" data-testid="redteam-targets-summary">
                        {noun} · ran {latest.created_at ? timeAgo(latest.created_at) : "—"}
                      </div>
                      {n > 0 && (
                        <button
                          type="button"
                          data-testid="redteam-targets-toggle"
                          aria-expanded={targetsOpen}
                          onClick={() => setTargetsOpen((v) => !v)}
                          style={{ background: "none", border: "none", color: "var(--accent)", cursor: "pointer", fontSize: 12, padding: 0 }}
                        >
                          {targetsOpen ? "Hide classes ▴" : `${noun} ▾`}
                        </button>
                      )}
                      {targetsOpen && (
                        <div
                          className="panel-sub mono"
                          data-testid="redteam-targets-list"
                          style={{ maxWidth: 320, whiteSpace: "normal", wordBreak: "break-word", marginTop: 3 }}
                        >
                          {(latest.targets ?? []).join(", ")}
                        </div>
                      )}
                    </>
                  );
                })()}
                {(eff.excluded_synthetic ?? 0) > 0 && (
                  <div className="panel-sub">{eff.excluded_synthetic} synthetic rows excluded</div>
                )}
              </div>
            </div>
            {overall.got_through > 0 && (
              <div style={{ marginTop: 12, padding: "9px 12px", borderRadius: 8, background: "#ff3b5c12", border: "1px solid #ff3b5c33", color: "#ff8fa0", fontSize: 12.5 }} data-testid="redteam-gap-warning">
                {overall.got_through} attack{overall.got_through === 1 ? "" : "s"} expected a block but got through — inspect the failing rows below and harden the policy.
              </div>
            )}
            {/*
              What this score does NOT cover. A sibling of the gap warning and deliberately OUTSIDE
              `redteam-metric-cluster`: three specs pairwise-check that no two direct children of that
              grid overlap at 1440 AND 720 wide, so a fifth stat there is prohibited.

              This band is the honest half of the dimension. Without it, a scorecard reading 100%
              across two MCP vectors is indistinguishable from full MCP coverage while thirty
              catalogued vectors went untouched. Neutral styling, never alarm: proxy-only vectors are
              mostly ENFORCED — Gate A stripping, the content-hash pin — just not by the layer this
              suite can score, and colouring them red would be its own false claim.
            */}
            {cov && (
              <div
                data-testid="redteam-mcp-coverage"
                style={{ marginTop: 12, padding: "9px 12px", borderRadius: 8, background: "var(--bg-surface)", border: "1px solid var(--border)", color: "var(--text-secondary)", fontSize: 12.5, lineHeight: 1.6 }}
              >
                <strong style={{ color: "var(--text-primary)" }}>{cov.exercised} of {cov.catalogued}</strong>{" "}
                catalogued MCP/tool vectors exercised by this run
                {cov.proxy_only > 0 && <> · <strong style={{ color: "var(--text-primary)" }}>{cov.proxy_only}</strong> are proxy-enforced and <strong>not measured here</strong></>}
                {cov.out_of_scope > 0 && <> · {cov.out_of_scope} out of scope for a per-call suite</>}
                <div style={{ marginTop: 6, color: "var(--text-muted)" }}>
                  A proxy-only vector is not a failure — it is decided at Gate A or in the pin registry,
                  before any policy is consulted, so this suite has nothing to score.{" "}
                  {(cov.unexercised_reachable ?? []).length > 0 && (
                    <>Reachable but not yet attacked:{" "}
                      <span className="mono" data-testid="redteam-mcp-unexercised">
                        {(cov.unexercised_reachable ?? []).join(", ")}
                      </span>.
                    </>
                  )}
                </div>
              </div>
            )}
          </Panel>

          {/*
            Three taxonomies now share this Panel, so the title is no longer "By MITRE ATLAS
            technique". Kept as ONE panel with the original testid deliberately: `RedTeam.test.tsx`
            scopes both the ATLAS and OWASP row lookups inside `redteam-by-technique`, and
            `redteam-runstate-list.spec.ts` asserts it is visible. Each table also gets its own row
            testid, because `redteam-breakdown-row` alone cannot say WHICH taxonomy a row came from —
            already ambiguous with two, worse with three.
          */}
          <Panel title="Framework breakdown" sub="Caught vs got-through per ATLAS technique, OWASP LLM control and MCP/tool vector" data-testid="redteam-by-technique" style={{ marginBottom: 16 }}>
            <BreakdownTable rowTestId="redteam-breakdown-atlas" rows={(eff.by_technique ?? []).map((t) => ({ id: t.technique_id, name: t.technique_name, ...t }))} />
            {(eff.by_owasp ?? []).length > 0 && (
              <div style={{ marginTop: 18 }}>
                <div className="section-label" style={{ marginBottom: 8 }}>By OWASP LLM control</div>
                <BreakdownTable rowTestId="redteam-breakdown-owasp" rows={(eff.by_owasp ?? []).map((o) => ({ id: o.control_id, name: o.control_name, ...o }))} />
              </div>
            )}
            {(eff.by_vector ?? []).length > 0 && (
              <div style={{ marginTop: 18 }} data-testid="redteam-by-vector">
                <div className="section-label" style={{ marginBottom: 8 }}>By MCP / tool vector</div>
                <BreakdownTable rowTestId="redteam-breakdown-vector" rows={(eff.by_vector ?? []).map((v) => ({ id: v.vector_id, name: v.vector_title, ...v }))} />
              </div>
            )}
          </Panel>

          <Panel
            title="Attack results"
            sub={`${rows.length} result${rows.length === 1 ? "" : "s"} in the last run (${(latest.targets ?? []).length} target class${(latest.targets ?? []).length === 1 ? "" : "es"})`}
            data-testid="redteam-attacks"
            style={{ marginBottom: 16 }}
            action={
              <label style={{ display: "inline-flex", alignItems: "center", gap: 6, fontSize: 12.5, cursor: "pointer" }} data-testid="redteam-failed-filter">
                <input
                  type="checkbox"
                  checked={failedOnly}
                  onChange={(e) => { setFailedOnly(e.target.checked); setPage(0); }}
                />
                Got-through only{overall.got_through ? ` (${overall.got_through})` : ""}
              </label>
            }
          >
            <div style={{ overflowX: "auto" }}>
              <table className="tbl" style={{ width: "100%", fontSize: 12.5 }}>
                <thead>
                  <tr>
                    <th style={thStyle}>Attack</th>
                    <th style={thStyle}>Class</th>
                    {/* One "Frameworks" column of mapped chips scales to N frameworks. */}
                    <th style={thStyle}>Frameworks</th>
                    <th style={thStyle}>Expected</th>
                    <th style={thStyle}>Actual</th>
                    <th style={thStyle}>Result</th>
                    <th style={thStyle}>Evidence</th>
                  </tr>
                </thead>
                <tbody>
                  {pageRows.length === 0 ? (
                    <tr><td style={tdStyle} colSpan={7}><span className="panel-sub">No matching results.</span></td></tr>
                  ) : (
                    pageRows.map((r, i) => (
                      <tr key={`${r.attack_id}-${r.agent_class ?? ""}-${safePage}-${i}`} data-testid="redteam-attack-row">
                        <td style={tdStyle}>
                          <div style={{ fontWeight: 600 }}>{r.attack_name}</div>
                          <div className="mono panel-sub">{r.attack_id}</div>
                        </td>
                        <td style={tdStyle} className="mono">{r.agent_class ?? "—"}</td>
                        {/* Real mapped chips (from the same mapping), one per framework, N-scalable. */}
                        <td style={tdStyle} data-testid="redteam-frameworks">
                          <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
                            {r.atlas_technique && (
                              <span className="mono" data-testid="fw-chip-atlas" title={r.atlas_technique_name}
                                style={{ fontSize: 11, padding: "1px 6px", borderRadius: 5, border: "1px solid var(--border)", color: "var(--text-secondary)" }}>
                                {r.atlas_technique}
                              </span>
                            )}
                            {r.owasp_control && (
                              <span className="mono" data-testid="fw-chip-owasp"
                                style={{ fontSize: 11, padding: "1px 6px", borderRadius: 5, border: "1px solid var(--border)", color: "var(--text-secondary)" }}>
                                {r.owasp_control}
                              </span>
                            )}
                            {/*
                              A chip, not a column: `graph-redteam-ux.spec.ts` asserts there is exactly
                              one "Frameworks" columnheader and that "ATLAS"/"OWASP" headers do not
                              exist, so the table is deliberately closed to new columns. Kebab vector
                              ids are long, so the chip shows a truncated label with the full id in the
                              tooltip rather than wrapping the row.
                            */}
                            {r.mcp_vector && (
                              <span className="mono" data-testid="fw-chip-mcp" title={r.mcp_vector_title ?? r.mcp_vector}
                                style={{ fontSize: 11, padding: "1px 6px", borderRadius: 5, border: "1px solid var(--border)", color: "var(--text-secondary)", maxWidth: 190, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                                {r.mcp_vector}
                              </span>
                            )}
                            {!r.atlas_technique && !r.owasp_control && !r.mcp_vector && <span className="mono panel-sub">—</span>}
                          </div>
                        </td>
                        <td style={tdStyle} className="mono">{r.expected}</td>
                        <td style={tdStyle}><DecisionBadge decision={(r.actual as Decision) ?? "allow"} /></td>
                        <td style={{ ...tdStyle, whiteSpace: "nowrap" }}>
                          {r.passed ? (
                            <span style={{ color: ACCENT, display: "inline-flex", alignItems: "center", gap: 4 }}>
                              <CheckCircle2 size={14} /> caught
                            </span>
                          ) : !gotThrough(r) ? (
                            // A conditional attack whose enforcing rule isn't loaded — a sector pack, or
                            // the opt-in MCP integration guardrail. Out of scope, not a real miss. Shares
                            // `gotThrough` with the filter so the two cannot drift apart again.
                            <span style={{ color: "var(--text-muted)", display: "inline-flex", alignItems: "center", gap: 4 }} title="This attack targets a sector pack or an opt-in guardrail that is not enabled for this namespace — not a policy gap.">
                              — not enabled here
                            </span>
                          ) : (
                            <span style={{ color: DANGER, display: "inline-flex", alignItems: "center", gap: 4 }} data-testid="redteam-row-failed">
                              <XCircle size={14} /> got through
                            </span>
                          )}
                        </td>
                        <td style={tdStyle}>
                          <Link
                            to={`/audit?rule=${encodeURIComponent(r.rule_id)}&framework=redteam`}
                            title="Audit rows for this rule, scoped to red-team traffic"
                            style={{ color: ACCENT }}
                          >
                            Audit
                          </Link>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
            {/* Pagination keeps mounted rows ≤ PAGE_SIZE regardless of result size. */}
            {pageCount > 1 && (
              <div style={{ display: "flex", alignItems: "center", justifyContent: "flex-end", gap: 12, marginTop: 10 }} data-testid="redteam-pager">
                <span className="panel-sub">
                  {safePage * PAGE_SIZE + 1}–{Math.min((safePage + 1) * PAGE_SIZE, rows.length)} of {rows.length}
                </span>
                <KitButton variant="outline" size="sm" icon={ChevronLeft} onClick={() => setPage((p) => Math.max(0, p - 1))} disabled={safePage === 0} data-testid="redteam-prev">Prev</KitButton>
                <span className="panel-sub" data-testid="redteam-page-indicator">Page {safePage + 1} / {pageCount}</span>
                <KitButton variant="outline" size="sm" icon={ChevronRight} onClick={() => setPage((p) => Math.min(pageCount - 1, p + 1))} disabled={safePage >= pageCount - 1} data-testid="redteam-next">Next</KitButton>
              </div>
            )}
          </Panel>

          <Panel title="Run history" sub="Recent red-team runs (durable)" data-testid="redteam-history">
            {history.length === 0 ? (
              <div className="panel-sub">No prior runs.</div>
            ) : (
              <div style={{ overflowX: "auto" }}>
                <table className="tbl" style={{ width: "100%", fontSize: 12.5 }}>
                  <thead>
                    <tr>
                      <th style={thStyle}>When</th>
                      <th style={thStyle}>Classes</th>
                      <th style={thStyle}>Proven-blocking</th>
                      <th style={thStyle}>Caught / Got-through</th>
                      <th style={thStyle}>Suite pass-rate</th>
                    </tr>
                  </thead>
                  <tbody>
                    {history.map((h) => (
                      <tr key={h.run_id} data-testid="redteam-history-row">
                        <td style={tdStyle}>{timeAgo(h.created_at)}</td>
                        <td style={tdStyle} className="mono" title={(h.targets ?? []).join(", ")}>{(h.targets ?? []).length}</td>
                        <td style={tdStyle}><b style={{ color: ACCENT }}>{h.proven_blocking_pct}%</b></td>
                        <td style={tdStyle} className="mono">{h.caught} / {h.got_through}</td>
                        <td style={tdStyle} className="mono">{h.pass_rate}%</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Panel>
        </>
      )}
    </div>
  );
};

/**
 * ONE notion of "got through", used by the filter AND by the row badge.
 *
 * These had drifted: the filter was `!passed`, while the badge renders "— pack not enabled" instead of
 * "got through" whenever `applicable === false`, and `compute_efficacy` skips those rows entirely
 * rather than counting them as misses. So "got-through only" listed rows that the very same table
 * labelled as not-a-miss, and the count disagreed with the scorecard above it.
 *
 * An attack is a miss only if it expected a block, did not get one, AND its enforcing rule was
 * actually loaded. A sector pack or the opt-in MCP guardrail that nobody installed is a control that
 * was never there — not a policy gap, and listing it as one sends an operator hunting a hole that does
 * not exist. Surfaced by the MCP identity attacks, which are guardrail-conditional by design.
 */
function gotThrough(r: { passed?: boolean; applicable?: boolean }): boolean {
  return !r.passed && r.applicable !== false;
}

function Stat({ label, value, color, icon: Icon, testid }: { label: string; value: React.ReactNode; color?: string; icon?: typeof CheckCircle2; testid?: string }) {
  return (
    <div data-testid={testid}>
      <div className="panel-sub" style={{ display: "flex", alignItems: "center", gap: 5 }}>
        {Icon && <Icon size={13} style={{ color: color ?? "var(--text-muted)" }} />} {label}
      </div>
      <div style={{ fontSize: 22, fontWeight: 700, color: color ?? "var(--text-primary)" }}>{value}</div>
    </div>
  );
}

function BreakdownTable({ rows, rowTestId }: { rows: Array<{ id: string; name: string; total: number; caught: number; got_through: number; proven_blocking_pct: number }>; rowTestId?: string }) {
  if (rows.length === 0) return <div className="panel-sub">No block-expected attacks in this run.</div>;
  return (
    <div style={{ overflowX: "auto" }}>
      <table className="tbl" style={{ width: "100%", fontSize: 12.5 }}>
        <thead>
          <tr>
            <th style={thStyle}>Control</th>
            <th style={thStyle}>Caught</th>
            <th style={thStyle}>Got through</th>
            <th style={thStyle}>Proven-blocking</th>
          </tr>
        </thead>
        <tbody>
          {/* The shared testid is KEPT — `redteam-view.spec.ts` counts it across all taxonomies — and
              `data-taxonomy` is additive, so a test can now say WHICH table it meant. Three
              taxonomies share this component and `redteam-breakdown-row` alone cannot tell them
              apart. */}
          {rows.map((r) => (
            <tr key={r.id} data-testid="redteam-breakdown-row" data-taxonomy={rowTestId}>
              <td style={tdStyle}><span className="mono">{r.id}</span> · {r.name}</td>
              <td style={tdStyle}>{r.caught}</td>
              <td style={{ ...tdStyle, color: r.got_through > 0 ? DANGER : undefined }}>{r.got_through}</td>
              <td style={tdStyle}><b style={{ color: r.proven_blocking_pct === 100 ? ACCENT : "var(--text-primary)" }}>{r.proven_blocking_pct}%</b></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default RedTeam;
