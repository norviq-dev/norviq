// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// Compliance / AI-attack-framework coverage page.
//
// ABSOLUTE RULE — NO MOCK DATA. Every number, chip, evidence row and export on this page is derived
// from a live backend response (fetchMitreCoverage / mitreExportPath / generateMitrePolicy). There is
// no hardcoded technique list, no fabricated count, and no fake export. MITRE ATLAS and OWASP LLM Top 10 (2025) are BOTH live frameworks — each drives its own card
// (overview) and the whole detail view (when selected) off its OWN backend coverage, fetched with the
// SAME client methods and a trailing `framework` argument. Every OTHER framework renders as an inert
// "coming soon" roadmap row with NO coverage numbers.
//
// Coverage % = coverage_pct (enforced / enforceable). OUT-OF-SCOPE controls are shown but NOT counted
// in the denominator — they sit outside a runtime PEP and are never a failure.

import { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  apiUrl,
  fetchMitreCoverage,
  fetchRedteamLatest,
  generateMitrePolicy,
  generateMitrePolicyBatch,
  mitreExportPath,
  type ComplianceFramework,
  type GenerateResult,
  type MitreCoverage,
  type MitreTechnique,
  type RedteamLatest
} from "../api/client";
import { getToken } from "../auth/session";
import { useApi } from "../hooks/useApi";
import { useApp } from "../store/AppContext";
import { FrameworkEmblem } from "../components/compliance/FrameworkEmblem";

// ---- canonical decision / status colors (NO blue anywhere) --------------------------------------
const ACCENT = "var(--accent)"; // teal #2ddab8
const ENFORCED = "#00e5a0"; // green
const GAP = "#ffb020"; // amber
const OOS_TEXT = "#9a9aa2"; // neutral grey (label)
const OOS_TRACK = "#33333a"; // neutral grey (bar/track)
const OOS_DOT = "#3a3a40";
const MUTED = "#8b8d93";
const FAINT = "#5c5e66";

// Compliance is driven by the GLOBAL header time-range (routeMeta timeScoped:true) — so the window widens to
// the full header set (1h/6h/24h/7d/30d). No in-page picker; the header is the single source of truth.
type Range = "1h" | "6h" | "24h" | "7d" | "30d";
type StatusFilter = "all" | "gap" | "enforced" | "oos";

const ST = {
  enforced: { label: "ENFORCED", color: ENFORCED, bg: "#00e5a015", border: "#00e5a033", dot: ENFORCED },
  gap: { label: "GAP", color: GAP, bg: "#ffb02015", border: "#ffb02033", dot: GAP },
  out_of_scope: { label: "OUT OF SCOPE", color: OOS_TEXT, bg: "#26262a", border: OOS_TRACK, dot: OOS_DOT }
} as const;

// ---- LIVE frameworks — both fetch real coverage via fetchMitreCoverage(ns, range, id). -----------
// title/tagline/blurb are static framing copy; every NUMBER on the card comes from the API response
// for that framework (never hardcoded). The API also returns `framework` as a display name.
const LIVE_FRAMEWORKS: Array<{
  id: ComplianceFramework;
  fallbackName: string;
  tagline: string;
  subtitle: string;
  blurb: string;
}> = [
  {
    id: "atlas",
    fallbackName: "MITRE ATLAS",
    tagline: "Runtime attack techniques · strong fit",
    subtitle: "Adversarial Threat Landscape for AI Systems · framework",
    blurb:
      "Adversarial Threat Landscape for AI Systems. Norviq enforces the ATLAS techniques that manifest as agent tool-calls, evidenced by live policy decisions."
  },
  {
    id: "owasp",
    fallbackName: "OWASP LLM Top 10 (2025)",
    tagline: "Agent-runtime LLM risks · best fit",
    subtitle: "OWASP Top 10 for LLM Applications (2025) · framework",
    blurb:
      "The OWASP Top 10 for LLM Applications. Norviq enforces the LLM risks that manifest as agent tool-calls (prompt injection, excessive agency, insecure output handling), evidenced by live policy decisions."
  }
];

// Roadmap frameworks — inert, NO coverage numbers, clearly "coming soon". OWASP LLM Top 10 (2025) is
// NOT here anymore — it went live. OWASP Agentic uses the "owasp" mark; nist/iso/eu their own marks.
const ROADMAP: Array<{ id: string; emblem: string; title: string; tagline: string; badge: string; evidence: boolean }> = [
  { id: "owasp-agentic", emblem: "owasp", title: "OWASP Agentic Top 10", tagline: "Agent-runtime · best fit", badge: "UPCOMING", evidence: false },
  { id: "nist", emblem: "nist", title: "NIST AI RMF", tagline: "Governance · controls contributed (no score)", badge: "UPCOMING · EVIDENCE", evidence: true },
  { id: "iso", emblem: "iso", title: "ISO/IEC 42001", tagline: "Governance · controls contributed (no score)", badge: "UPCOMING · EVIDENCE", evidence: true },
  { id: "eu", emblem: "eu", title: "EU AI Act", tagline: "Regulatory · evidence sliver (no score)", badge: "UPCOMING · EVIDENCE", evidence: true }
];

const RANGE_LABEL: Record<Range, string> = { "1h": "1h", "6h": "6h", "24h": "24h", "7d": "7d", "30d": "30d" };

function fmt(n: number | undefined | null): string {
  return (n ?? 0).toLocaleString("en-US");
}

function frameworkName(fw: ComplianceFramework, data: MitreCoverage | null): string {
  // The coverage response's `framework` field is the machine id ("atlas"|"owasp"), NOT a display name —
  // so prefer the canonical human name from meta; fall back to the id only if the framework is unknown.
  const meta = LIVE_FRAMEWORKS.find((f) => f.id === fw);
  return meta?.fallbackName || (data?.framework ?? fw).toUpperCase();
}

// ------------------------------------------------------------------------------------------------
// Donut ring geometry (enforced green + gap amber over the enforceable subset), mirrors the mockup.
// ------------------------------------------------------------------------------------------------
function ringDash(coveragePct: number): { green: string; greenOff: number; amber: string; amberOff: number } {
  const green = Math.max(0, Math.min(100, Math.round(coveragePct)));
  return {
    green: `${green} ${100 - green}`,
    greenOff: 25,
    amber: `${100 - green} ${green}`,
    amberOff: -(green - 25)
  };
}

function Donut({ size, coveragePct }: { size: number; coveragePct: number }) {
  const r = ringDash(coveragePct);
  const label = `${Math.round(coveragePct)}%`;
  return (
    <svg width={size} height={size} viewBox="0 0 42 42" role="img" aria-label={`${label} of enforceable enforced`}>
      <circle cx="21" cy="21" r="15.9" fill="none" stroke="#1c1c1f" strokeWidth="5" />
      <circle cx="21" cy="21" r="15.9" fill="none" stroke={ENFORCED} strokeWidth="5" strokeDasharray={r.green} strokeDashoffset={r.greenOff} transform="rotate(-90 21 21)" strokeLinecap="round" />
      <circle cx="21" cy="21" r="15.9" fill="none" stroke={GAP} strokeWidth="5" strokeDasharray={r.amber} strokeDashoffset={r.amberOff} transform="rotate(-90 21 21)" />
      <text x="21" y="24.4" textAnchor="middle" fontSize="9.5" fontWeight={800} fill="#ededf0" fontFamily="Outfit, system-ui, sans-serif">
        {label}
      </text>
    </svg>
  );
}

// ------------------------------------------------------------------------------------------------
// Authenticated evidence-pack download (mirrors AssetGraph's authenticated fetch): fetch(apiUrl(path))
// with a Bearer token → blob → object-URL download. No secret leaks into a plain href. The `framework`
// arg picks which framework's pack the backend renders.
// ------------------------------------------------------------------------------------------------
async function downloadEvidencePack(
  namespace: string | undefined,
  range: Range,
  format: "json" | "pdf",
  framework: ComplianceFramework
): Promise<void> {
  const path = mitreExportPath(namespace, range, format, framework);
  const token = getToken();
  const res = await fetch(apiUrl(path), { headers: token ? { Authorization: `Bearer ${token}` } : {} });
  if (!res.ok) throw new Error(`Export failed: ${res.status}`);
  const blob = await res.blob();
  const objectUrl = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = objectUrl;
  a.download = `${framework}-evidence-${namespace ?? "all"}-${range}.${format}`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(objectUrl);
}

function techStatus(t: MitreTechnique): keyof typeof ST {
  return t.status; // "enforced" | "gap" | "out_of_scope" — from the API, never inferred client-side
}

// Efficacy overlay. When a Red Team run exists it shows the REAL proven-blocking %; before any run it
// keeps the honest "not efficacy-tested" caption with a call to action. Coverage (rules present) ≠ efficacy.
function ComplianceEfficacyBanner({ efficacy, onView }: { efficacy?: RedteamLatest; onView: () => void }) {
  const hasRun = !!efficacy?.has_run;
  const pct = hasRun ? efficacy!.efficacy?.overall.proven_blocking_pct : undefined;
  const overall = efficacy?.efficacy?.overall;
  return (
    <div
      data-testid="compliance-efficacy-banner"
      style={{
        display: "flex", alignItems: "center", gap: 12, padding: "11px 15px", marginBottom: 16,
        background: hasRun ? "rgba(45,218,184,0.07)" : "rgba(255,255,255,0.03)",
        border: `1px solid ${hasRun ? "#2ddab840" : "var(--border)"}`, borderRadius: 10
      }}
    >
      <span style={{ fontSize: 12.5, color: "var(--text-secondary)" }}>
        Coverage above shows <b>rules present</b>.{" "}
        {hasRun ? (
          <span data-testid="compliance-proven-blocking">
            Efficacy: <b style={{ color: "#2ddab8" }}>{pct}% proven-blocking</b> on the last Red Team run
            {overall ? ` (${overall.caught}/${overall.total} block-expected attacks caught)` : ""}.
          </span>
        ) : (
          <span data-testid="compliance-not-tested">
            This posture is <b>not efficacy-tested</b> — run the Red Team suite to prove blocking.
          </span>
        )}
      </span>
      <button
        onClick={onView}
        className="link-btn"
        style={{ marginLeft: "auto", background: "none", border: "none", color: "#2ddab8", cursor: "pointer", fontSize: 12.5, fontWeight: 600 }}
      >
        {hasRun ? "View Red Team →" : "Run Red Team suite →"}
      </button>
    </div>
  );
}

// ================================================================================================
export function Compliance() {
  const navigate = useNavigate();
  const { namespace, timeRange } = useApp();

  const [view, setView] = useState<"overview" | "detail">("overview");
  const [tab, setTab] = useState<"frameworks" | "custom">("frameworks");
  // The range is the GLOBAL header time-range (reactive) — no local state, no in-page picker. Changing the
  // header chip refetches coverage/evidence (keyed on `range` below), on BOTH the overview cards and the detail.
  const range: Range = timeRange;
  // The framework the DETAIL view is bound to (switcher-driven). Overview always shows both live cards.
  const [framework, setFramework] = useState<ComplianceFramework>("atlas");
  const [treeQuery, setTreeQuery] = useState("");
  const [treeFilter, setTreeFilter] = useState<StatusFilter>("all");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [scopeOpen, setScopeOpen] = useState(false);
  const [fwMenuOpen, setFwMenuOpen] = useState(false);
  const [drafted, setDrafted] = useState<Record<string, boolean>>({});
  const [toast, setToast] = useState<{ msg: string; link?: string } | null>(null);
  // Multi-select: the set of GAP technique_ids checked for batch generation + the class-scope mode
  // for that batch ("affected" = each control's top affected class · "all" = every real affected class · a
  // specific class name).
  const [selectedGaps, setSelectedGaps] = useState<Set<string>>(new Set());
  const [genClassMode, setGenClassMode] = useState<string>("affected");
  // Non-draft outcomes of the last batch generate (escalate / no class / error) — rendered as a
  // dismissible panel with the FULL per-control server message, so a zero-draft batch can't pass silently.
  const [batchOutcome, setBatchOutcome] = useState<GenerateResult[] | null>(null);

  // `drafted` and `selectedGaps` are session hints keyed only by technique_id — with no
  // namespace/framework component. Without this, a draft made in ns-A/atlas would wrongly disable
  // "Generate" for the same technique id in ns-B (or in owasp), and a batch-generate could fire the ids
  // selected while viewing ns-A/atlas against a different scope. Reset both whenever the scope changes.
  useEffect(() => {
    setDrafted({});
    setSelectedGaps(new Set());
    setBatchOutcome(null);
    // Revert the batch class-scope to the safe default on any scope change too. A specific class
    // picked in ns-A (from ns-A's affected classes) won't exist in ns-B; left stale, the controlled <select>
    // holds an off-list value and onGenerateBatch submits it verbatim → a zero-draft "no_affected_classes"
    // batch in ns-B. Resetting here matches how drafted/selectedGaps/batchOutcome are already cleared.
    setGenClassMode("affected");
  }, [namespace, framework]);

  // ---- REAL data. Both live frameworks fetch their OWN coverage — the overview renders TWO cards,
  // each off its own response; the detail view reads the coverage for the SELECTED framework. ------
  const atlasCoverage = useApi<MitreCoverage>(() => fetchMitreCoverage(namespace, range, "atlas"), [namespace, range], {
    cacheKey: `mitre-coverage:atlas:${namespace}:${range}`,
    staleTimeMs: 30_000
  });
  const owaspCoverage = useApi<MitreCoverage>(() => fetchMitreCoverage(namespace, range, "owasp"), [namespace, range], {
    cacheKey: `mitre-coverage:owasp:${namespace}:${range}`,
    staleTimeMs: 30_000
  });
  // The last Red Team run's efficacy. Coverage answers "which controls have rules"; efficacy answers
  // "how many are PROVEN-blocking". We surface it as a banner that coexists with the header range selector.
  // Scope efficacy to the selected namespace so "N% proven-blocking" describes THIS scope's last
  // run, not whatever cluster-wide run was newest. Cache key includes the namespace so scopes don't share.
  const efficacy = useApi<RedteamLatest>(() => fetchRedteamLatest(namespace), [namespace], {
    cacheKey: `compliance-redteam-latest:${namespace}`,
    staleTimeMs: 30_000
  });
  const covByFw: Record<ComplianceFramework, ReturnType<typeof useApi<MitreCoverage>>> = {
    atlas: atlasCoverage,
    owasp: owaspCoverage
  };

  // The detail view's active framework selects which coverage drives it.
  const activeCoverage = covByFw[framework];
  const data = activeCoverage.data;
  // Degraded when the selected framework's coverage errored (detail) — or, on overview, when either did.
  const apiDegraded =
    view === "detail" ? !!activeCoverage.error : !!atlasCoverage.error && !!owaspCoverage.error;

  const techniques = useMemo<MitreTechnique[]>(() => data?.techniques ?? [], [data]);
  const selected = useMemo(
    () => techniques.find((t) => t.technique_id === selectedId) ?? null,
    [techniques, selectedId]
  );

  function showToast(msg: string, link?: string) {
    setToast({ msg, link });
    window.setTimeout(() => setToast((cur) => (cur && cur.msg === msg ? null : cur)), 3500);
  }

  // ---- open detail for a framework; jump to first gap. -------------------------------------------
  function openDetail(fw: ComplianceFramework, startFilter: StatusFilter = "all") {
    setFramework(fw);
    const techs = covByFw[fw].data?.techniques ?? [];
    const first =
      startFilter === "gap"
        ? techs.find((t) => t.status === "gap")
        : techs.find((t) => t.status === "enforced") ?? techs[0];
    setSelectedId(first?.technique_id ?? techs[0]?.technique_id ?? null);
    setTreeFilter(startFilter);
    setTreeQuery("");
    setView("detail");
  }

  // Switch the detail view to another live framework: re-seed the selected technique off the new
  // framework's coverage (its OWN technique list), reset filters.
  function switchFramework(fw: ComplianceFramework) {
    setFramework(fw);
    setFwMenuOpen(false);
    const techs = covByFw[fw].data?.techniques ?? [];
    const first = techs.find((t) => t.status === "enforced") ?? techs[0];
    setSelectedId(first?.technique_id ?? null);
    setTreeFilter("all");
    setTreeQuery("");
  }

  // ---- export (authenticated blob download), then refetch coverage so "last exported" updates. ---
  async function onExport(fw: ComplianceFramework) {
    try {
      await downloadEvidencePack(namespace, range, "json", fw);
      showToast("Audit-evidence pack exported (JSON)");
      void covByFw[fw].refetch();
    } catch (e) {
      showToast(e instanceof Error ? e.message : "Export failed");
    }
  }

  // ---- gap remediation: create a NON-enforcing dry-run draft (for the SELECTED framework), then
  //      deep-link to Policies. -----------------------------------------------------------------
  async function onGenerate(t: MitreTechnique) {
    // Don't force a "default" class — pass the control's top affected class if we have one, else let the
    // backend derive the real active class (or honestly report there's nothing to remediate).
    const cls = t.affected_classes?.[0]?.class;
    try {
      const res = await generateMitrePolicy(t.technique_id, namespace ?? "default", cls, framework);
      if (res.status === "no_affected_classes") {
        showToast("No affected agent classes in range — nothing to remediate yet.");
        return;
      }
      if (res.status === "escalate") {
        showToast(res.message ?? "This control can't be auto-generated — the risk doesn't show up in tool-call traffic, so it needs a manual (configuration/process) control.");
        return;
      }
      setDrafted((d) => ({ ...d, [t.technique_id]: true }));
      showToast(`Draft for ${res.control_name ?? t.name} · scoped to ${res.cls} · pending in Policies`, res.deeplink);
    } catch (e) {
      showToast(e instanceof Error ? e.message : "Draft failed");
    }
  }

  function toggleGapSelect(techniqueId: string) {
    setSelectedGaps((prev) => {
      const next = new Set(prev);
      if (next.has(techniqueId)) next.delete(techniqueId);
      else next.add(techniqueId);
      return next;
    });
  }

  // Multi-select: generate one CONTROL-SPECIFIC draft per (selected control × class) in ONE batch
  // call, honouring the class-scope mode. Marks each drafted control + surfaces a rollup toast that deep-links
  // to the first draft (all land in the Policy Catalog inbox).
  // `ids` is the caller-supplied set of controls to generate — the DetailView passes only the
  // currently-VISIBLE generatable gaps (selected ∩ visible), never hidden selections the user can't see.
  async function onGenerateBatch(ids: string[]) {
    if (!ids.length) return;
    try {
      const res = await generateMitrePolicyBatch(ids, namespace ?? "default", genClassMode, framework);
      const drafts = res.results.filter((r) => r.status === "draft");
      setDrafted((d) => {
        const next = { ...d };
        for (const r of drafts) next[r.technique_id] = true;
        return next;
      });
      setSelectedGaps(new Set());
      const firstLink = drafts.find((r) => r.deeplink)?.deeplink;
      // A 3.5s toast is NOT enough for a partial/zero outcome — the per-control escalation
      // reasons were dropped and "pending in Policies" was claimed even when nothing was created.
      // Every non-draft outcome now lands in a DISMISSIBLE panel (sticky, full server message);
      // the toast only carries the honest rollup.
      const nonDraft = res.results.filter((r) => r.status !== "draft");
      setBatchOutcome(nonDraft.length ? nonDraft : null);
      const escalated = nonDraft.filter((r) => r.status === "escalate").length;
      const noClass = nonDraft.filter((r) => r.status === "no_affected_classes").length;
      const failed = nonDraft.filter((r) => r.status === "error").length;
      const parts = [`${res.drafts_created} draft${res.drafts_created === 1 ? "" : "s"} created`];
      if (escalated) parts.push(`${escalated} need${escalated === 1 ? "s" : ""} a bespoke rule`);
      if (noClass) parts.push(`${noClass} with no affected class`);
      if (failed) parts.push(`${failed} failed`);
      showToast(
        res.drafts_created > 0 ? `${parts.join(" · ")} · drafts pending in Policies` : parts.join(" · "),
        res.drafts_created > 0 ? firstLink : undefined
      );
    } catch (e) {
      showToast(e instanceof Error ? e.message : "Batch generate failed");
    }
  }

  const overviewLoading = (atlasCoverage.loading && !atlasCoverage.data) || (owaspCoverage.loading && !owaspCoverage.data);
  const detailLoading = activeCoverage.loading && !data;

  return (
    <div className="page-enter" style={{ color: "#ededf0", fontFamily: "'Outfit', system-ui, sans-serif" }}>
      {/* DEGRADED BANNER — bound to the real coverage fetch error state. */}
      {apiDegraded && (
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 10,
            padding: "10px 14px",
            marginBottom: 16,
            background: "rgba(255,176,32,0.08)",
            border: "1px solid #4a3a1a",
            borderRadius: 10
          }}
        >
          <span style={{ fontSize: 12.5, fontWeight: 600, color: "#ffcf82" }}>
            API unavailable. Coverage could not be loaded.
          </span>
          <span style={{ marginLeft: "auto", display: "inline-flex", alignItems: "center", gap: 6, fontSize: 11, color: "#b89148" }}>
            <span style={{ width: 7, height: 7, borderRadius: "50%", background: GAP }} />
            Status: Degraded
          </span>
        </div>
      )}

      {/* Proven-blocking efficacy overlay from the last Red Team run — coverage is "rules present",
          this is the honest "how much is PROVEN blocking". Coexists with the header range selector. */}
      <ComplianceEfficacyBanner efficacy={efficacy.data ?? undefined} onView={() => navigate("/redteam")} />

      {view === "overview" ? (
        <OverviewView
          tab={tab}
          setTab={setTab}
          scopeOpen={scopeOpen}
          setScopeOpen={setScopeOpen}
          covByFw={covByFw}
          loading={overviewLoading}
          range={range}
          onOpen={(fw) => openDetail(fw, "all")}
          onGaps={(fw) => openDetail(fw, "gap")}
          onExport={onExport}
        />
      ) : (
        <DetailView
          framework={framework}
          data={data}
          loading={detailLoading}
          range={range}
          namespace={namespace}
          techniques={techniques}
          selected={selected}
          setSelectedId={setSelectedId}
          treeQuery={treeQuery}
          setTreeQuery={setTreeQuery}
          treeFilter={treeFilter}
          setTreeFilter={setTreeFilter}
          fwMenuOpen={fwMenuOpen}
          setFwMenuOpen={setFwMenuOpen}
          onSwitchFramework={switchFramework}
          drafted={drafted}
          onBack={() => setView("overview")}
          onGaps={() => openDetail(framework, "gap")}
          onExport={() => onExport(framework)}
          onGenerate={onGenerate}
          selectedGaps={selectedGaps}
          onToggleGapSelect={toggleGapSelect}
          onClearGapSelect={() => setSelectedGaps(new Set())}
          genClassMode={genClassMode}
          setGenClassMode={setGenClassMode}
          onGenerateBatch={onGenerateBatch}
          batchOutcome={batchOutcome}
          onDismissBatchOutcome={() => setBatchOutcome(null)}
          onOpenRule={(ruleId) => navigate(`/audit?rule=${encodeURIComponent(ruleId)}&range=${range}`)}
          onOpenClass={(cls) => navigate(`/agents?class=${encodeURIComponent(cls)}`)}
        />
      )}

      {/* TOAST */}
      {toast && (
        <div
          style={{
            position: "fixed",
            bottom: 22,
            right: 22,
            zIndex: 90,
            display: "flex",
            alignItems: "center",
            gap: 10,
            padding: "12px 16px",
            background: "#171717",
            border: "1px solid #2ddab866",
            borderRadius: 11,
            boxShadow: "0 16px 40px -14px rgba(0,0,0,0.7)",
            maxWidth: 360
          }}
        >
          <span style={{ fontSize: 12.5, fontWeight: 600, color: "#ededf0" }}>{toast.msg}</span>
          {toast.link && (
            <button
              type="button"
              onClick={() => {
                const path = toast.link!.startsWith("/") ? toast.link! : `/${toast.link!}`;
                setToast(null);
                navigate(path);
              }}
              style={{ marginLeft: 4, background: "transparent", border: "none", color: ACCENT, fontFamily: "inherit", fontSize: 12.5, fontWeight: 700, cursor: "pointer" }}
            >
              Open →
            </button>
          )}
        </div>
      )}
    </div>
  );
}

// ================================================================================================
// OVERVIEW
// ================================================================================================
type CoverageApi = ReturnType<typeof useApi<MitreCoverage>>;
function OverviewView({
  tab,
  setTab,
  scopeOpen,
  setScopeOpen,
  covByFw,
  loading,
  range,
  onOpen,
  onGaps,
  onExport
}: {
  tab: "frameworks" | "custom";
  setTab: (t: "frameworks" | "custom") => void;
  scopeOpen: boolean;
  setScopeOpen: (v: boolean) => void;
  covByFw: Record<ComplianceFramework, CoverageApi>;
  loading: boolean;
  range: Range;
  onOpen: (fw: ComplianceFramework) => void;
  onGaps: (fw: ComplianceFramework) => void;
  onExport: (fw: ComplianceFramework) => void;
}) {
  return (
    <div>
      <div style={{ fontSize: 21, fontWeight: 700 }}>Compliance</div>
      <div style={{ fontSize: 12.5, color: MUTED, marginTop: 4 }}>
        Runtime-control coverage of AI-attack frameworks · in-cluster agent workloads
      </div>

      {/* scope note */}
      <div style={{ marginTop: 16, background: "rgba(45,218,184,0.05)", border: "1px solid #143a35", borderRadius: 11, padding: "12px 16px" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <div style={{ flex: 1, minWidth: 0, fontSize: 12, color: "#9fc4bd", lineHeight: 1.5 }}>
            <b style={{ color: "#d7f2ec" }}>Runtime-control coverage.</b> Coverage is measured over the{" "}
            <b style={{ color: "#cfe8e3" }}>enforceable subset</b> — runtime tool-call controls. Model-lifecycle &amp;
            governance controls are out of scope, not failures.
          </div>
          <button
            type="button"
            onClick={() => setScopeOpen(!scopeOpen)}
            style={{ flex: "none", background: "transparent", border: "none", padding: 0, fontFamily: "inherit", fontSize: 11.5, fontWeight: 600, color: ACCENT, cursor: "pointer", whiteSpace: "nowrap" }}
          >
            {scopeOpen ? "Less" : "Learn more"}
          </button>
        </div>
        {scopeOpen && (
          <div style={{ marginTop: 10, paddingTop: 10, borderTop: "1px solid #143a35", fontSize: 12, color: "#9fc4bd", lineHeight: 1.6 }}>
            Norviq is a policy-enforcement point for agent tool-calls — it covers the framework controls about{" "}
            <b style={{ color: "#cfe8e3" }}>what an agent may do at runtime</b>. Model-lifecycle controls (poisoning,
            theft, supply-chain) and governance process are <b style={{ color: "#cfe8e3" }}>out of scope</b> and shown as
            such, never as failures. Coverage % is of the enforceable subset, evidenced by live policy decisions.
          </div>
        )}
      </div>

      {/* tabs */}
      <div style={{ display: "flex", gap: 24, marginTop: 20, borderBottom: "1px solid #1c1c1c" }}>
        {([
          { key: "frameworks" as const, label: "Frameworks", soon: false },
          { key: "custom" as const, label: "Custom", soon: true }
        ]).map((t) => (
          <div
            key={t.key}
            onClick={() => setTab(t.key)}
            style={{
              display: "flex",
              alignItems: "center",
              gap: 7,
              fontSize: 13,
              fontWeight: 600,
              color: tab === t.key ? "#ededf0" : MUTED,
              padding: "0 0 12px",
              cursor: "pointer",
              borderBottom: `2px solid ${tab === t.key ? ACCENT : "transparent"}`
            }}
          >
            {t.label}
            {t.soon && (
              <span style={{ fontSize: 9, fontWeight: 800, letterSpacing: "0.05em", color: "#7a7a82", background: "#1e1e22", border: "1px solid #2a2a2e", borderRadius: 999, padding: "2px 7px" }}>
                SOON
              </span>
            )}
          </div>
        ))}
      </div>

      {tab === "frameworks" ? (
        <>
          {/* ACTIVE FRAMEWORKS — ATLAS + OWASP, each off its OWN live coverage. */}
          <div style={{ display: "flex", flexDirection: "column", gap: 16, marginTop: 20 }}>
            {loading ? (
              <div style={{ color: MUTED, fontSize: 13, padding: "20px 0" }}>Loading coverage…</div>
            ) : (
              LIVE_FRAMEWORKS.map((meta) => (
                <FrameworkOverviewCard
                  key={meta.id}
                  meta={meta}
                  data={covByFw[meta.id].data}
                  range={range}
                  onOpen={() => onOpen(meta.id)}
                  onGaps={() => onGaps(meta.id)}
                  onExport={() => onExport(meta.id)}
                />
              ))
            )}
          </div>

          {/* ROADMAP — inert, no coverage numbers. */}
          <div style={{ fontSize: 10.5, fontWeight: 800, letterSpacing: "0.08em", textTransform: "uppercase", color: FAINT, margin: "24px 0 10px" }}>
            Roadmap · frameworks in progress
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            {ROADMAP.map((f) => (
              <div key={f.id} style={{ display: "flex", alignItems: "center", gap: 13, background: "#171717", border: "1px solid #26262a", borderRadius: 11, padding: "13px 16px" }}>
                <span style={{ flex: "none", color: MUTED, display: "inline-flex" }}>
                  <FrameworkEmblem framework={f.emblem} size={26} />
                </span>
                <div style={{ minWidth: 0 }}>
                  <div style={{ fontSize: 13.5, fontWeight: 600, color: "#d6d6da" }}>{f.title}</div>
                  <div style={{ fontSize: 11.5, color: "#7a7a82", marginTop: 1 }}>{f.tagline}</div>
                </div>
                <span
                  style={{
                    marginLeft: "auto",
                    flex: "none",
                    fontSize: 9.5,
                    fontWeight: 800,
                    letterSpacing: "0.04em",
                    padding: "3px 9px",
                    borderRadius: 999,
                    background: f.evidence ? "#2a230d" : "#26262a",
                    color: f.evidence ? "#f2d488" : "#9a9aa2"
                  }}
                >
                  {f.badge}
                </span>
              </div>
            ))}
          </div>
        </>
      ) : (
        <div style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", gap: 14, padding: "90px 20px", textAlign: "center" }}>
          <div style={{ fontSize: 16, fontWeight: 700 }}>Custom frameworks — coming soon</div>
          <div style={{ fontSize: 12.5, color: MUTED, maxWidth: 400, lineHeight: 1.6 }}>
            Map your own control set to Norviq's enforcing policies and generate a live evidence pack. Available once the
            first frameworks ship.
          </div>
        </div>
      )}
    </div>
  );
}

function FrameworkOverviewCard({
  meta,
  data,
  range,
  onOpen,
  onGaps,
  onExport
}: {
  meta: (typeof LIVE_FRAMEWORKS)[number];
  data: MitreCoverage | null;
  range: Range;
  onOpen: () => void;
  onGaps: () => void;
  onExport: () => void;
}) {
  const name = frameworkName(meta.id, data);
  if (!data) {
    return (
      <div style={{ background: "#171717", border: "1px solid #26262a", borderRadius: 14, padding: "20px 22px", color: MUTED, fontSize: 13, display: "flex", alignItems: "center", gap: 10 }}>
        <span style={{ flex: "none", color: MUTED, display: "inline-flex" }}>
          <FrameworkEmblem framework={meta.id} size={22} />
        </span>
        No {name} coverage available.
      </div>
    );
  }
  const enforceable = data.enforceable_total || 0;
  const enforced = data.enforced ?? 0;
  const gap = data.gap ?? 0;
  const oos = data.oos ?? 0;
  const total = enforceable + oos || 1;
  const pct = data.coverage_pct ?? 0;
  const gapLabel = `${gap} ${gap === 1 ? "gap" : "gaps"} →`;

  return (
    <div style={{ background: "#171717", border: "1px solid #143a35", borderRadius: 14, boxShadow: "0 0 0 1px #2ddab81f", overflow: "hidden" }}>
      <div style={{ display: "flex", flexWrap: "wrap", gap: 22, padding: "20px 22px" }}>
        <div style={{ flex: 1, minWidth: 300 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
            {/* per-framework emblem (currentColor-tinted teal) next to the title */}
            <span style={{ flex: "none", color: ACCENT, display: "inline-flex" }}>
              <FrameworkEmblem framework={meta.id} size={30} />
            </span>
            <div style={{ minWidth: 0 }}>
              <div style={{ fontSize: 10.5, fontWeight: 700, color: ACCENT }}>{meta.tagline}</div>
              <div style={{ fontSize: 17, fontWeight: 700, marginTop: 1 }}>{name}</div>
            </div>
            <span style={{ marginLeft: "auto", flex: "none", fontSize: 9.5, fontWeight: 800, letterSpacing: "0.04em", padding: "3px 9px", borderRadius: 999, background: "#0d2a1c", color: "#6ee7b7" }}>
              ENFORCED
            </span>
          </div>
          <div style={{ fontSize: 12.5, color: MUTED, lineHeight: 1.55, margin: "12px 0 14px", maxWidth: 560 }}>
            {meta.blurb} Coverage is measured over the {enforceable} enforceable technique
            {enforceable === 1 ? "" : "s"} — the {oos} out-of-scope technique{oos === 1 ? "" : "s"} are not counted.
          </div>
          <div style={{ display: "flex", height: 7, borderRadius: 999, background: "#1c1c1f", overflow: "hidden", marginBottom: 8, maxWidth: 560 }}>
            <span style={{ display: "block", height: "100%", width: `${Math.round((enforced / total) * 100)}%`, background: ENFORCED }} />
            <span style={{ display: "block", height: "100%", width: `${Math.round((gap / total) * 100)}%`, background: GAP }} />
            <span style={{ display: "block", height: "100%", width: `${Math.round((oos / total) * 100)}%`, background: OOS_TRACK }} />
          </div>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 14, fontSize: 11.5, color: MUTED }}>
            <span><b style={{ color: ENFORCED }}>{enforced}</b> enforced</span>
            <span><b style={{ color: GAP }}>{gap}</b> gap</span>
            <span><b style={{ color: OOS_TEXT }}>{oos}</b> out-of-scope</span>
            <span style={{ color: FAINT }}>·</span>
            <span><b style={{ color: "#ededf0" }}>{fmt(data.blocked)}</b> blocked · {RANGE_LABEL[range]}</span>
          </div>
        </div>

        <div style={{ display: "flex", flexDirection: "column", justifyContent: "space-between", gap: 14, flex: "none", minWidth: 200 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
            <Donut size={76} coveragePct={pct} />
            <button
              type="button"
              onClick={onGaps}
              style={{ display: "flex", alignItems: "center", gap: 7, padding: "8px 11px", border: "1px solid #4a3a1a", borderRadius: 9, background: "rgba(255,176,32,0.08)", color: "#f6c667", fontFamily: "inherit", fontSize: 12, fontWeight: 700, cursor: "pointer", whiteSpace: "nowrap" }}
            >
              <span style={{ width: 8, height: 8, borderRadius: "50%", background: GAP }} />
              {gapLabel}
            </button>
          </div>
          <button
            type="button"
            onClick={onOpen}
            style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 8, height: 36, padding: "0 16px", border: "none", borderRadius: 9, background: "linear-gradient(180deg, #5ae8cc, #2ddab8)", color: "#04211d", fontFamily: "inherit", fontSize: 13, fontWeight: 700, cursor: "pointer" }}
          >
            Open coverage detail →
          </button>
        </div>
      </div>
      <div style={{ display: "flex", flexWrap: "wrap", alignItems: "center", gap: 12, padding: "12px 22px", borderTop: "1px solid #26262a", background: "#131313" }}>
        <span style={{ fontSize: 12.5, color: "#cdd0d6" }}>Audit-evidence pack — per-control policies, block counts &amp; timestamps</span>
        <span style={{ fontSize: 11.5, color: FAINT }}>
          {data.last_exported ? `Last exported ${data.last_exported}` : "Not exported yet"}
        </span>
        <button
          type="button"
          onClick={onExport}
          style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 7, height: 32, padding: "0 13px", border: "1px solid #2ddab866", borderRadius: 8, background: "rgba(45,218,184,0.1)", color: ACCENT, fontFamily: "inherit", fontSize: 12, fontWeight: 700, cursor: "pointer" }}
        >
          Export
        </button>
      </div>
    </div>
  );
}

// ================================================================================================
// DETAIL
// ================================================================================================
function DetailView(props: {
  framework: ComplianceFramework;
  data: MitreCoverage | null;
  loading: boolean;
  range: Range;
  namespace: string;
  techniques: MitreTechnique[];
  selected: MitreTechnique | null;
  setSelectedId: (id: string | null) => void;
  treeQuery: string;
  setTreeQuery: (v: string) => void;
  treeFilter: StatusFilter;
  setTreeFilter: (v: StatusFilter) => void;
  fwMenuOpen: boolean;
  setFwMenuOpen: (v: boolean) => void;
  onSwitchFramework: (fw: ComplianceFramework) => void;
  drafted: Record<string, boolean>;
  onBack: () => void;
  onGaps: () => void;
  onExport: () => void;
  onGenerate: (t: MitreTechnique) => void;
  selectedGaps: Set<string>;
  onToggleGapSelect: (techniqueId: string) => void;
  onClearGapSelect: () => void;
  genClassMode: string;
  setGenClassMode: (v: string) => void;
  onGenerateBatch: (ids: string[]) => void;
  batchOutcome: GenerateResult[] | null;
  onDismissBatchOutcome: () => void;
  onOpenRule: (ruleId: string) => void;
  onOpenClass: (cls: string) => void;
}) {
  const {
    framework,
    data,
    loading,
    range,
    techniques,
    selected,
    setSelectedId,
    treeQuery,
    setTreeQuery,
    treeFilter,
    setTreeFilter,
    fwMenuOpen,
    setFwMenuOpen,
    onSwitchFramework,
    drafted,
    onBack,
    onGaps,
    onExport,
    onGenerate,
    selectedGaps,
    onToggleGapSelect,
    onClearGapSelect,
    genClassMode,
    setGenClassMode,
    onGenerateBatch,
    batchOutcome,
    onDismissBatchOutcome,
    onOpenRule,
    onOpenClass
  } = props;

  const enforced = data?.enforced ?? 0;
  const gap = data?.gap ?? 0;
  const oos = data?.oos ?? 0;
  const enforceable = data?.enforceable_total ?? 0;
  const pct = data?.coverage_pct ?? 0;
  const total = techniques.length;
  const fwName = frameworkName(framework, data);
  const fwMeta = LIVE_FRAMEWORKS.find((f) => f.id === framework);

  // filtered tree grouped by STATUS (P3 deviation from the design): the design groups by ATLAS tactic,
  // but our coverage mapping carries NO tactic field — so we group by status (Gaps/Enforced/OOS) and do
  // NOT invent tactics.
  const q = treeQuery.trim().toLowerCase();
  const matchesQuery = (t: MitreTechnique) =>
    !q || t.name.toLowerCase().includes(q) || t.technique_id.toLowerCase().includes(q);
  const matchesFilter = (t: MitreTechnique) => {
    if (treeFilter === "all") return true;
    if (treeFilter === "enforced") return t.status === "enforced";
    if (treeFilter === "gap") return t.status === "gap";
    if (treeFilter === "oos") return t.status === "out_of_scope";
    return true;
  };
  const visible = techniques.filter((t) => matchesQuery(t) && matchesFilter(t));

  const groups: Array<{ label: string; oos?: boolean; techs: MitreTechnique[] }> = [];
  const enfList = visible.filter((t) => t.status === "enforced");
  const gapList = visible
    .filter((t) => t.status === "gap")
    .sort((a, b) => prioRank(a.priority) - prioRank(b.priority));
  const oosList = visible.filter((t) => t.status === "out_of_scope");
  if (treeFilter === "gap") {
    if (gapList.length) groups.push({ label: "Gaps · worst first", techs: gapList });
  } else {
    if (gapList.length) groups.push({ label: "Gaps · worst first", techs: gapList });
    if (enfList.length) groups.push({ label: "Enforced", techs: enfList });
    if (oosList.length) groups.push({ label: "Out of scope · not a runtime control", oos: true, techs: oosList });
  }
  const treeEmpty = groups.every((g) => g.techs.length === 0);

  // Multi-select: only GENERATABLE gap techniques are selectable (a bespoke gap escalates on
  // generate → never gets a checkbox). The real (non-synthetic) affected classes across the visible techniques
  // populate the "specific class" options in the class-scope picker.
  const gapIdSet = new Set(gapList.filter((t) => t.generatable).map((t) => t.technique_id));
  const selectedGapIds = [...selectedGaps].filter((id) => gapIdSet.has(id));
  const realClassOptions = [...new Set(
    techniques.flatMap((t) => (t.affected_classes ?? []).map((c) => c.class)).filter(Boolean)
  )].sort();

  const filterSegs: Array<{ key: StatusFilter; label: string }> = [
    { key: "all", label: `All ${total}` },
    { key: "gap", label: `Gaps ${gap}` },
    { key: "enforced", label: `Enforced ${enforced}` },
    { key: "oos", label: `OOS ${oos}` }
  ];

  return (
    <div>
      {fwMenuOpen && <div onClick={() => setFwMenuOpen(false)} style={{ position: "fixed", inset: 0, zIndex: 45 }} />}

      {/* breadcrumb + framework switcher (ATLAS + OWASP are BOTH live) */}
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 14 }}>
        <span onClick={onBack} style={{ fontSize: 12.5, color: ACCENT, cursor: "pointer" }}>
          ← Compliance
        </span>
        <span style={{ fontSize: 12.5, color: FAINT }}>/</span>
        <div style={{ position: "relative" }}>
          <button
            type="button"
            onClick={() => setFwMenuOpen(!fwMenuOpen)}
            style={{ display: "flex", alignItems: "center", gap: 8, height: 30, padding: "0 11px", border: "1px solid #2a2a2e", borderRadius: 8, background: "#171717", color: "#ededf0", fontFamily: "inherit", fontSize: 12.5, fontWeight: 600, cursor: "pointer" }}
          >
            <span style={{ flex: "none", color: ACCENT, display: "inline-flex" }}>
              <FrameworkEmblem framework={framework} size={16} />
            </span>
            {fwName} ▾
          </button>
          {fwMenuOpen && (
            <div style={{ position: "absolute", top: 36, left: 0, zIndex: 50, width: 300, background: "#171717", border: "1px solid #2a2a2e", borderRadius: 10, padding: 6, boxShadow: "0 16px 40px -14px rgba(0,0,0,0.72)" }}>
              {/* Both ATLAS and OWASP are LIVE — selectable, no "SOON". */}
              {LIVE_FRAMEWORKS.map((f) => {
                const on = f.id === framework;
                return (
                  <button
                    key={f.id}
                    type="button"
                    onClick={() => onSwitchFramework(f.id)}
                    style={{ display: "flex", alignItems: "center", gap: 8, width: "100%", padding: "8px 10px", border: "none", borderRadius: 7, background: on ? "#132320" : "transparent", color: "#ededf0", fontFamily: "inherit", fontSize: 12.5, fontWeight: 600, cursor: "pointer", textAlign: "left" }}
                  >
                    <span style={{ flex: "none", color: on ? ACCENT : MUTED, display: "inline-flex" }}>
                      <FrameworkEmblem framework={f.id} size={16} />
                    </span>
                    <span style={{ flex: 1, minWidth: 0 }}>{frameworkName(f.id, on ? data : null)}</span>
                    {on && <span style={{ color: ACCENT }}>✓</span>}
                  </button>
                );
              })}
              <div style={{ height: 1, background: "#26262a", margin: "5px 4px" }} />
              {ROADMAP.map((f) => (
                <div
                  key={f.id}
                  style={{ display: "flex", alignItems: "center", gap: 8, width: "100%", padding: "8px 10px", borderRadius: 7, color: "#7a7a82", fontSize: 12.5, fontWeight: 600, textAlign: "left" }}
                >
                  <span style={{ flex: "none", color: FAINT, display: "inline-flex" }}>
                    <FrameworkEmblem framework={f.emblem} size={16} />
                  </span>
                  <span style={{ flex: 1, minWidth: 0 }}>{f.title}</span>
                  <span style={{ fontSize: 9, fontWeight: 800, letterSpacing: "0.05em", color: "#7a7a82", background: "#1e1e22", border: "1px solid #2a2a2e", borderRadius: 999, padding: "2px 7px" }}>
                    SOON
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* HERO */}
      <div style={{ display: "flex", flexWrap: "wrap", gap: 22, alignItems: "center", background: "#171717", border: "1px solid #26262a", borderRadius: 14, padding: "18px 22px" }}>
        <div style={{ flexBasis: "100%", display: "flex", alignItems: "center", gap: 13, paddingBottom: 16, borderBottom: "1px solid #26262a" }}>
          <span style={{ flex: "none", color: ACCENT, display: "inline-flex" }}>
            <FrameworkEmblem framework={framework} size={34} />
          </span>
          <div style={{ minWidth: 0 }}>
            <div style={{ fontSize: 17, fontWeight: 700, letterSpacing: "0.01em" }}>{fwName}</div>
            <div style={{ fontSize: 11.5, color: MUTED, marginTop: 1 }}>{fwMeta?.subtitle ?? "framework"}</div>
          </div>
          {/* The range is driven by the GLOBAL header selector (no duplicate in-page picker). The header
              shows the current window (RANGE_LABEL[range]) so the detail still reads it. */}
          <div style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 12, flex: "none" }}>
            <span style={{ fontSize: 10.5, color: MUTED }}>range · <b style={{ color: ACCENT }}>{RANGE_LABEL[range]}</b></span>
            <span style={{ fontSize: 9.5, fontWeight: 800, letterSpacing: "0.04em", padding: "4px 10px", borderRadius: 999, background: "#0d2a1c", color: "#6ee7b7" }}>
              ENFORCED
            </span>
          </div>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: 16, flex: "none" }}>
          <Donut size={98} coveragePct={pct} />
          <div style={{ display: "flex", flexDirection: "column", gap: 6, fontSize: 11.5, color: MUTED }}>
            <span style={{ display: "flex", alignItems: "center", gap: 7 }}>
              <span style={{ width: 10, height: 10, borderRadius: 3, background: ENFORCED }} />
              Enforced · {enforced}
            </span>
            <button
              type="button"
              onClick={onGaps}
              style={{ display: "flex", alignItems: "center", gap: 7, background: "transparent", border: "none", padding: 0, margin: 0, fontFamily: "inherit", fontSize: 11.5, color: "#f6c667", cursor: "pointer" }}
            >
              <span style={{ width: 10, height: 10, borderRadius: 3, background: GAP }} />
              Gap · {gap} →
            </button>
            <span style={{ display: "flex", alignItems: "center", gap: 7 }}>
              <span style={{ width: 10, height: 10, borderRadius: 3, background: OOS_TRACK }} />
              Out-of-scope · {oos} <span style={{ color: FAINT }}>(not counted)</span>
            </span>
          </div>
        </div>

        <div style={{ flex: 1, minWidth: 260, fontSize: 12.5, color: MUTED, lineHeight: 1.6 }}>
          Coverage is measured over the {enforceable} enforceable technique{enforceable === 1 ? "" : "s"} (those that
          appear as agent tool-calls) — {enforced} enforced, {gap} gap{gap === 1 ? "" : "s"}. The {oos} out-of-scope
          technique{oos === 1 ? "" : "s"} sit outside a runtime PEP and are not counted as failures. Every enforced
          technique is backed by a live policy and block evidence.
        </div>

        <div style={{ display: "flex", flexDirection: "column", gap: 12, flex: "none" }}>
          <div style={{ display: "flex", gap: 22 }}>
            <div style={{ fontSize: 11, color: MUTED }}>
              <b style={{ display: "block", fontSize: 19, fontWeight: 800, color: "#ededf0" }}>{fmt(data?.blocked)}</b>
              blocked · {RANGE_LABEL[range]}
            </div>
            <div style={{ fontSize: 11, color: MUTED }}>
              <b style={{ display: "block", fontSize: 19, fontWeight: 800, color: "#ededf0" }}>{fmt(data?.agent_classes)}</b>
              agent classes
            </div>
          </div>
          <button
            type="button"
            onClick={onExport}
            style={{ display: "flex", alignItems: "center", gap: 8, height: 34, padding: "0 13px", border: "1px solid #2ddab866", borderRadius: 9, background: "rgba(45,218,184,0.1)", color: ACCENT, fontFamily: "inherit", fontSize: 12, fontWeight: 700, cursor: "pointer", whiteSpace: "nowrap" }}
          >
            Export audit-evidence pack
          </button>
          <div style={{ fontSize: 10.5, color: FAINT, textAlign: "right" }}>
            {data?.last_exported ? `Last exported ${data.last_exported}` : "Not exported yet"}
          </div>
          {/* The pack is real-traffic only — state how many synthetic/
              simulated + red-team events were excluded, so it can't be read as understating enforcement. */}
          {!!data?.synthetic_excluded && data.synthetic_excluded > 0 && (
            <div data-testid="evidence-synthetic-excluded" style={{ fontSize: 10.5, color: FAINT, textAlign: "right", maxWidth: 220 }}>
              Real traffic only · {fmt(data.synthetic_excluded)} synthetic/simulated event{data.synthetic_excluded === 1 ? "" : "s"} excluded
            </div>
          )}
        </div>
      </div>

      {/* TREE + DETAIL PANEL */}
      <div style={{ display: "grid", gridTemplateColumns: "300px 1fr", gap: 16, marginTop: 16, alignItems: "start" }}>
        {/* TREE */}
        <div style={{ background: "#171717", border: "1px solid #26262a", borderRadius: 14, display: "flex", flexDirection: "column", maxHeight: 640 }}>
          <div style={{ padding: "12px 12px 10px", borderBottom: "1px solid #26262a" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8, height: 34, padding: "0 11px", border: "1px solid #2a2a2e", borderRadius: 8, background: "#131313" }}>
              <input
                type="text"
                value={treeQuery}
                onChange={(e) => setTreeQuery(e.target.value)}
                placeholder="Search techniques…"
                aria-label="Search techniques"
                style={{ flex: 1, minWidth: 0, background: "transparent", border: "none", color: "#ededf0", fontSize: 12.5, outline: "none", fontFamily: "inherit" }}
              />
            </div>
            <div style={{ display: "flex", gap: 5, marginTop: 9 }}>
              {filterSegs.map((seg) => {
                const on = treeFilter === seg.key;
                return (
                  <button
                    key={seg.key}
                    type="button"
                    onClick={() => setTreeFilter(seg.key)}
                    style={{ flex: 1, height: 27, padding: "0 4px", border: `1px solid ${on ? "#2ddab866" : "#2a2a2e"}`, borderRadius: 7, background: on ? "#0e2a28" : "transparent", color: on ? ACCENT : MUTED, fontFamily: "inherit", fontSize: 10.5, fontWeight: 700, cursor: "pointer", whiteSpace: "nowrap" }}
                  >
                    {seg.label}
                  </button>
                );
              })}
            </div>
          </div>
          <div style={{ flex: 1, overflow: "auto", padding: "6px 0" }}>
            {loading ? (
              <div style={{ padding: "30px 18px", textAlign: "center", fontSize: 12, color: FAINT }}>Loading…</div>
            ) : treeEmpty ? (
              <div style={{ padding: "30px 18px", textAlign: "center", fontSize: 12, color: FAINT }}>No controls match.</div>
            ) : (
              groups.map((g) => (
                <div key={g.label}>
                  <div style={{ fontSize: 10.5, fontWeight: 800, letterSpacing: "0.05em", textTransform: "uppercase", color: g.oos ? FAINT : "#6e6e76", padding: "12px 16px 6px" }}>
                    {g.label}
                  </div>
                  {g.techs.map((t) => {
                    const on = selected?.technique_id === t.technique_id;
                    const isGap = t.status === "gap";
                    return (
                      <div
                        key={t.technique_id}
                        onClick={() => setSelectedId(t.technique_id)}
                        style={{ display: "flex", alignItems: "center", gap: 9, padding: "9px 16px", fontSize: 13, color: "#ededf0", cursor: "pointer", background: on ? "#132320" : "transparent", boxShadow: on ? "inset 3px 0 0 #2ddab8" : "none" }}
                      >
                        {/* Only GENERATABLE gaps get a checkbox. A bespoke gap (no runtime rule)
                            would only escalate, so it is shown but not selectable for auto-generation. */}
                        {isGap && t.generatable ? (
                          <input
                            type="checkbox"
                            aria-label={`Select ${t.name} for remediation`}
                            data-testid={`gap-select-${t.technique_id}`}
                            checked={selectedGaps.has(t.technique_id)}
                            onClick={(e) => e.stopPropagation()}
                            onChange={() => onToggleGapSelect(t.technique_id)}
                            style={{ flex: "none", width: 13, height: 13, accentColor: "#2ddab8", cursor: "pointer" }}
                          />
                        ) : (
                          <span style={{ width: 13, flex: "none" }} />
                        )}
                        <span style={{ width: 9, height: 9, borderRadius: "50%", flex: "none", background: ST[techStatus(t)].dot }} />
                        <span style={{ flex: 1, minWidth: 0 }}>{t.name}</span>
                        {t.status === "gap" && t.priority && (
                          <span style={{ flex: "none", fontSize: 8.5, fontWeight: 800, letterSpacing: "0.04em", color: prioColor(t.priority), border: `1px solid ${prioColor(t.priority)}`, borderRadius: 4, padding: "1px 5px" }}>
                            {t.priority === "high" ? "HIGH" : t.priority === "medium" ? "MED" : "LOW"}
                          </span>
                        )}
                        {isGap && !t.generatable && (
                          <span
                            title="No runtime-detectable signal — enforce this via configuration or process, not a tool-call policy. It can't be auto-generated."
                            style={{ flex: "none", fontSize: 8.5, fontWeight: 800, letterSpacing: "0.04em", color: "var(--escalate)", border: "1px solid var(--escalate)", borderRadius: 4, padding: "1px 5px" }}
                          >
                            BESPOKE
                          </span>
                        )}
                      </div>
                    );
                  })}
                </div>
              ))
            )}
          </div>

          {/* Multi-select action bar — visible once ≥1 gap is checked. The class-scope picker
              governs how each selected control is scoped (its top affected class · all affected classes · a
              specific class); "Generate for selected" fans out one control-specific draft per (control × class). */}
          {selectedGapIds.length > 0 && (
            <div
              data-testid="gap-batch-bar"
              style={{ borderTop: "1px solid #26262a", padding: "10px 14px", display: "flex", flexWrap: "wrap", alignItems: "center", gap: 8, background: "#141414" }}
            >
              <span data-testid="gap-batch-count" style={{ fontSize: 12, fontWeight: 700, color: "#ededf0" }}>
                {selectedGapIds.length} selected
              </span>
              <button
                type="button"
                onClick={onClearGapSelect}
                style={{ fontSize: 11, color: MUTED, background: "transparent", border: "none", cursor: "pointer", textDecoration: "underline" }}
              >
                clear
              </button>
              <select
                aria-label="Agent class scope for generation"
                data-testid="gap-batch-classmode"
                value={genClassMode}
                onChange={(e) => setGenClassMode(e.target.value)}
                style={{ marginLeft: "auto", fontSize: 11.5, padding: "5px 8px", borderRadius: 7, background: "#0d0d0d", color: "#ededf0", border: "1px solid #2a2a2e", cursor: "pointer", maxWidth: 200 }}
              >
                <option value="affected">This affected class</option>
                <option value="all">All affected classes</option>
                {realClassOptions.map((c) => (
                  <option key={c} value={c}>{c}</option>
                ))}
              </select>
              <button
                type="button"
                data-testid="gap-batch-generate"
                onClick={() => onGenerateBatch(selectedGapIds)}
                style={{ fontSize: 11.5, fontWeight: 700, padding: "6px 12px", borderRadius: 7, background: "linear-gradient(180deg, #2ddab8, #22c4a4)", color: "#0d0d0d", border: "none", cursor: "pointer" }}
              >
                Generate for selected
              </button>
            </div>
          )}

          {/* Non-draft outcomes of the last batch — sticky until dismissed, full server reason per
              control. A "0 drafts created" batch previously vanished into a 3.5s toast with the
              escalation message dropped; the operator believed the gap was remediated. */}
          {batchOutcome && batchOutcome.length > 0 && (
            <div
              data-testid="gap-batch-outcome"
              style={{ borderTop: "1px solid #26262a", padding: "10px 14px", background: "#141414" }}
            >
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 6 }}>
                <span style={{ fontSize: 11.5, fontWeight: 700, letterSpacing: 0.3, color: "var(--escalate)" }}>
                  NOT AUTO-REMEDIATED · {batchOutcome.length} control{batchOutcome.length === 1 ? "" : "s"}
                </span>
                <button
                  type="button"
                  aria-label="Dismiss batch outcome"
                  onClick={onDismissBatchOutcome}
                  style={{ background: "transparent", border: "none", color: MUTED, cursor: "pointer", fontSize: 13 }}
                >
                  ✕
                </button>
              </div>
              {batchOutcome.map((r) => (
                <div key={r.technique_id} style={{ padding: "6px 0", borderTop: "1px solid #1d1d20" }}>
                  <div style={{ fontSize: 12, fontWeight: 600, color: "#ededf0" }}>
                    {r.technique_id}
                    {r.control_name ? ` · ${r.control_name}` : ""}
                    <span style={{ marginLeft: 8, fontSize: 10.5, fontWeight: 700, color: r.status === "error" ? "var(--block)" : "var(--escalate)" }}>
                      {r.status === "escalate" ? "NEEDS MANUAL CONTROL" : r.status === "no_affected_classes" ? "NO AFFECTED CLASS" : "FAILED"}
                    </span>
                  </div>
                  {r.message && (
                    <div style={{ fontSize: 11.5, color: MUTED, marginTop: 2, whiteSpace: "pre-wrap" }}>{r.message}</div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>

        {/* DETAIL PANEL */}
        <div style={{ background: "#171717", border: "1px solid #26262a", borderRadius: 14, padding: "20px 22px" }}>
          {selected ? (
            <TechniqueDetail
              t={selected}
              range={range}
              drafted={!!drafted[selected.technique_id]}
              onGenerate={onGenerate}
              onOpenRule={onOpenRule}
              onOpenClass={onOpenClass}
            />
          ) : (
            <div style={{ color: MUTED, fontSize: 13 }}>Select a technique to see its detail.</div>
          )}
        </div>
      </div>
    </div>
  );
}

function TechniqueDetail({
  t,
  range,
  drafted,
  onGenerate,
  onOpenRule,
  onOpenClass
}: {
  t: MitreTechnique;
  range: Range;
  drafted: boolean;
  onGenerate: (t: MitreTechnique) => void;
  onOpenRule: (ruleId: string) => void;
  onOpenClass: (cls: string) => void;
}) {
  const st = ST[techStatus(t)];
  const isOos = t.status === "out_of_scope";
  const isGap = t.status === "gap";
  const isEnforceable = t.status !== "out_of_scope";
  // Evidence rows: the technique's covered_policies (rules actually loaded/active) carry the block evidence.
  const evidence = t.covered_policies ?? [];
  const chips = t.affected_classes ?? [];

  return (
    <>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12 }}>
        <div style={{ fontSize: 17, fontWeight: 700 }}>{t.name}</div>
        <div style={{ display: "flex", alignItems: "center", gap: 7, flex: "none" }}>
          {isGap && t.priority && (
            <span style={{ fontSize: 10, fontWeight: 800, letterSpacing: "0.04em", padding: "3px 9px", borderRadius: 999, color: prioColor(t.priority), border: `1px solid ${prioColor(t.priority)}` }}>
              {t.priority === "high" ? "HIGH PRIORITY" : t.priority === "medium" ? "MED PRIORITY" : "LOW PRIORITY"}
            </span>
          )}
          <span style={{ fontSize: 11, fontWeight: 800, letterSpacing: "0.04em", padding: "3px 10px", borderRadius: 999, background: st.bg, color: st.color, border: `1px solid ${st.border}` }}>
            {st.label}
          </span>
        </div>
      </div>
      <div style={{ fontFamily: "ui-monospace, 'JetBrains Mono', monospace", fontSize: 12, color: MUTED, margin: "5px 0 14px" }}>
        {t.technique_id}
      </div>
      {t.description && <div style={{ fontSize: 13, color: "#a2a2aa", lineHeight: 1.6 }}>{t.description}</div>}

      {/* "also satisfies" note (from the API `also` field). */}
      {t.also && (
        <div style={{ marginTop: 12, display: "flex", alignItems: "center", gap: 8, padding: "8px 12px", background: "rgba(45,218,184,0.06)", border: "1px solid #143a35", borderRadius: 9, fontSize: 11.5, color: "#9fc4bd" }}>
          Same enforcing rule also satisfies <b style={{ color: "#cfe8e3" }}>{t.also}</b>
        </div>
      )}

      {/* out-of-scope note. */}
      {isOos && (
        <div style={{ marginTop: 16, padding: "13px 15px", background: "#17171a", border: "1px solid #2a2a2e", borderRadius: 10, fontSize: 12.5, color: "#a2a2aa", lineHeight: 1.6 }}>
          <b style={{ color: "#d6d6da" }}>Not a runtime-PEP control.</b> This control targets the model lifecycle or model
          behaviour (training, supply-chain, output truthfulness), not agent tool-calls at runtime — so it sits outside
          Norviq's enforcement layer. Shown for completeness; <b style={{ color: "#d6d6da" }}>not counted as a gap or a
          failure</b>. Pair Norviq with model-supply-chain and training-time controls to address it.
        </div>
      )}

      {isEnforceable && (
        <>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", margin: "18px 0 9px" }}>
            <div style={{ fontSize: 10.5, fontWeight: 800, letterSpacing: "0.05em", textTransform: "uppercase", color: FAINT }}>
              Enforcing policies &amp; live evidence
            </div>
            {evidence.length > 0 && <span style={{ fontSize: 10.5, color: FAINT }}>click a row to open in Audit Log</span>}
          </div>
          {evidence.length > 0 ? (
            <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
              {evidence.map((rule) => {
                // Render THIS rule's own blocked count, not the technique-wide `t.blocked` total.
                // `t.blocked` sums over every covered policy, so a technique enforced by >1 rule repeated the
                // same total on each row and over-attributed all blocks to each rule. Consume the per-rule
                // `blocked_by_rule` map shipped by the backend; if it is momentarily absent, a single-rule
                // technique's total IS that rule's count (safe fallback), a multi-rule one shows 0 rather
                // than the misleading total.
                const ruleBlocked =
                  t.blocked_by_rule?.[rule] ?? (evidence.length === 1 ? (t.blocked ?? 0) : 0);
                return (
                  <div
                    key={rule}
                    onClick={() => onOpenRule(rule)}
                    style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12, background: "#131316", border: "1px solid #2a2a2e", borderRadius: 9, padding: "10px 13px", cursor: "pointer" }}
                  >
                    <span style={{ fontFamily: "ui-monospace, monospace", fontSize: 12, color: "#d6d6da", minWidth: 0, overflowWrap: "anywhere" }}>
                      {rule}
                    </span>
                    <span style={{ display: "flex", alignItems: "center", gap: 7, whiteSpace: "nowrap" }}>
                      <span style={{ fontSize: 11.5, fontWeight: 600, color: ruleBlocked > 0 ? ENFORCED : "#6e6e76" }}>
                        {fmt(ruleBlocked)} blocked · {RANGE_LABEL[range]}
                      </span>
                      <span style={{ color: "#5f5f67" }}>↗</span>
                    </span>
                  </div>
                );
              })}
            </div>
          ) : (
            <div style={{ padding: "12px 14px", background: "#17171a", border: "1px solid #2a2a2e", borderRadius: 9, fontSize: 12.5, color: "#a2a2aa", lineHeight: 1.55 }}>
              No enforcing policy maps to this control yet for these agent classes.
            </div>
          )}

          <div style={{ fontSize: 10.5, fontWeight: 800, letterSpacing: "0.05em", textTransform: "uppercase", color: FAINT, margin: "18px 0 9px" }}>
            Affected agent classes
          </div>
          {chips.length > 0 ? (
            <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
              {chips.map((c) => (
                <span
                  key={c.class}
                  onClick={() => onOpenClass(c.class)}
                  style={{ fontSize: 10.5, fontFamily: "ui-monospace, monospace", color: MUTED, border: "1px solid #2a2a2e", borderRadius: 999, padding: "3px 10px", cursor: "pointer" }}
                >
                  {c.class}
                </span>
              ))}
            </div>
          ) : (
            <div style={{ fontSize: 12, color: FAINT }}>No affected agent classes in range.</div>
          )}

          {isGap && (
            <>
              <div style={{ fontSize: 10.5, fontWeight: 800, letterSpacing: "0.05em", textTransform: "uppercase", color: FAINT, margin: "18px 0 9px" }}>
                Remediation
              </div>
              {t.generatable ? (
                <>
                  <button
                    type="button"
                    onClick={() => !drafted && onGenerate(t)}
                    disabled={drafted}
                    style={{
                      display: "inline-flex",
                      alignItems: "center",
                      gap: 8,
                      height: 36,
                      padding: "0 15px",
                      border: drafted ? "1px solid #1f4635" : "1px solid transparent",
                      borderRadius: 9,
                      background: drafted ? "transparent" : "linear-gradient(180deg, #5ae8cc, #2ddab8)",
                      color: drafted ? "#6ee7b7" : "#04211d",
                      fontFamily: "inherit",
                      fontSize: 13,
                      fontWeight: 700,
                      cursor: drafted ? "default" : "pointer"
                    }}
                  >
                    {drafted ? "✓ Draft created · pending in Policies" : "Generate enforcing policy"}
                  </button>
                  <div style={{ fontSize: 11.5, color: MUTED, marginTop: 9, lineHeight: 1.5 }}>
                    Creates a <b style={{ color: "#d6d6da" }}>tighten-only dry-run draft</b> in Policies that denies this
                    control for the affected agent classes — review &amp; apply from Policies.
                  </div>
                </>
              ) : (
                <div style={{ padding: "12px 14px", background: "#1a1712", border: "1px solid #3a2f1a", borderRadius: 9, fontSize: 12.5, color: "var(--escalate)", lineHeight: 1.55 }}>
                  <b>Needs a manual control.</b> This risk doesn&apos;t show up in agent tool-call traffic, so no
                  runtime policy can detect or block it — there is nothing for a generated rule to match. Address
                  it in configuration or process (secret management, access reviews, prompt hardening), and track
                  it outside runtime enforcement.
                </div>
              )}
            </>
          )}
        </>
      )}
    </>
  );
}

function prioRank(p: MitreTechnique["priority"]): number {
  if (p === "high") return 0;
  if (p === "medium") return 1;
  if (p === "low") return 2;
  return 3;
}
function prioColor(p: MitreTechnique["priority"]): string {
  return p === "high" ? "#ff8a5c" : "#f6c667";
}

export default Compliance;
