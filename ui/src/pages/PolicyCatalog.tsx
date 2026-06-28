import Editor from "@monaco-editor/react";
import {
  AlertCircle,
  ArrowUpCircle,
  Check,
  ChevronDown,
  ChevronUp,
  Copy,
  FileCode,
  Info,
  Play,
  Plus,
  Radar,
  RotateCcw,
  TriangleAlert,
  X
} from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { apiGet, apiSend, applyPolicy, dryRunPolicy } from "../api/client";
import { CategoryCoverage } from "../components/common/CategoryCoverage";
import { DecisionBadge, type Decision } from "../components/common/DecisionBadge";
import { KitButton } from "../components/common/KitButton";
import { PageHead } from "../components/common/PageHead";
import { Panel } from "../components/common/Panel";
import { useApi } from "../hooks/useApi";
import { fmtDateTime } from "../lib/format";
import { useApp } from "../store/AppContext";

type TargetType = "workload" | "class" | "namespace";

type Policy = {
  id?: string;
  target_type?: TargetType;
  target?: string;
  namespace?: string;
  agent_class?: string;
  current_version?: number;
  rego_length?: number;
  mode?: "block" | "audit" | "escalate";
  matches?: number;
};

type PolicyDetail = {
  namespace?: string;
  agent_class?: string;
  rego_source?: string;
  version?: number;
};

type PolicyVersion = {
  version: number;
  saved_by?: string;
  saved_at: string;
};

type Deployment = {
  name: string;
  namespace: string;
  agent_class: string;
  replicas?: number;
};

type DryRunResult = {
  total_records_checked?: number;
  would_block?: number;
  would_allow?: number;
  block_rate_pct?: number;
  recommendation?: string;
};

const PRIORITY: Record<TargetType, { rank: number; label: string; color: string }> = {
  workload: { rank: 1, label: "highest", color: "#00e5a0" },
  class: { rank: 2, label: "medium", color: "#2ddab8" },
  namespace: { rank: 3, label: "lowest", color: "#a0a0a0" }
};

const TIERS: Array<{ type: TargetType; title: string; sub: string }> = [
  { type: "workload", title: "Workload Policies", sub: "Specific deployments · highest priority" },
  { type: "class", title: "Agent-Class Policies", sub: "Groups of agents by label · medium priority" },
  { type: "namespace", title: "Namespace Policies", sub: "Catch-all fallback · lowest priority" }
];

const MODE_DECISION: Record<NonNullable<Policy["mode"]>, Decision> = {
  block: "block",
  audit: "audit",
  escalate: "escalate"
};

const FALLBACK_DEPLOYMENTS: Deployment[] = [
  { name: "smartsales-agent", namespace: "chatbot-prod", agent_class: "customer-support" },
  { name: "navigator-chatbot", namespace: "chatbot-prod", agent_class: "customer-support" },
  { name: "ledger-summarizer", namespace: "payments", agent_class: "summarizer" },
  { name: "copilot-reviewer", namespace: "platform", agent_class: "code-assistant" },
  { name: "etl-loader", namespace: "analytics", agent_class: "data-loader" },
  { name: "shift-scheduler", namespace: "platform", agent_class: "scheduler" },
  { name: "weekly-report-gen", namespace: "analytics", agent_class: "report-gen" },
  { name: "triage-bot", namespace: "support", agent_class: "support-bot" }
];

/**
 * Defense-in-depth: the API now returns target_type, but default it to "class" when an
 * agent_class is set and the field is absent — so the catalog never drops a class policy
 * (the seeded default:customer-support) into "no policies configured".
 */
function withTargetType(list: Policy[]): Policy[] {
  return list.map((p) => ({
    ...p,
    target_type: p.target_type ?? (p.agent_class ? "class" : p.target_type)
  }));
}

function PriorityBars({ tier }: { tier: TargetType }) {
  const p = PRIORITY[tier];
  return (
    <span style={{ display: "inline-flex", gap: 3, alignItems: "flex-end", height: 14 }}>
      {[1, 2, 3].map((r) => (
        <i
          key={r}
          style={{
            width: 4,
            borderRadius: 1,
            height: [14, 11, 8][r - 1],
            background: p.rank === r ? p.color : "var(--text-muted)",
            display: "inline-block"
          }}
        />
      ))}
    </span>
  );
}

function PriorityBadge({ tier }: { tier: TargetType }) {
  const p = PRIORITY[tier];
  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        gap: 8,
        marginTop: 14,
        paddingTop: 12,
        borderTop: "1px solid var(--border)",
        fontSize: 12
      }}
    >
      <PriorityBars tier={tier} />
      <span style={{ color: p.color, fontWeight: 600 }}>
        {tier === "class" ? "Agent-class" : tier === "workload" ? "Workload" : "Namespace"} policy
      </span>
      <span className="muted">· {p.label} priority</span>
    </div>
  );
}

function RadioPill({
  active,
  label,
  onClick
}: {
  active: boolean;
  label: string;
  onClick: () => void;
}) {
  return (
    <button
      className={`tab-kit${active ? " active" : ""}`}
      onClick={onClick}
      style={{ display: "inline-flex", alignItems: "center", gap: 7, textTransform: "capitalize" }}
    >
      <span
        style={{
          width: 12,
          height: 12,
          borderRadius: 99,
          border: `1.5px solid ${active ? "var(--accent)" : "var(--text-muted)"}`,
          position: "relative",
          display: "inline-block"
        }}
      >
        {active && (
          <span
            style={{ position: "absolute", inset: 2, borderRadius: 99, background: "var(--accent)" }}
          />
        )}
      </span>
      {label}
    </button>
  );
}

function PolicyTarget({
  policy,
  deployments
}: {
  policy: Policy;
  deployments: Deployment[];
}) {
  const initial = policy.target_type ?? "class";
  const [mode, setMode] = useState<TargetType>(initial);
  const [agentClass, setAgentClass] = useState(policy.agent_class ?? "customer-support");

  useEffect(() => {
    setMode(policy.target_type ?? "class");
    if (policy.agent_class) setAgentClass(policy.agent_class);
  }, [policy]);

  const matches = deployments.filter((d) => d.agent_class === agentClass);

  return (
    <div>
      <div className="section-label">Target by</div>
      <div className="tabs-kit" style={{ marginBottom: 16 }}>
        <RadioPill active={mode === "class"} label="Agent Class" onClick={() => setMode("class")} />
        <RadioPill active={mode === "workload"} label="Workload" onClick={() => setMode("workload")} />
        <RadioPill active={mode === "namespace"} label="Namespace" onClick={() => setMode("namespace")} />
      </div>

      {mode === "class" && (
        <div>
          <div className="field-row">
            <label className="field-label">Agent Class · recommended</label>
            <div className="input select-trigger">
              <span>{agentClass}</span>
              <ChevronDown />
            </div>
          </div>
          <div className="panel-sub" style={{ marginBottom: 8 }}>
            Applies to all deployments labeled
          </div>
          <span
            style={{
              fontFamily: "var(--font-mono)",
              fontSize: 12,
              color: "#00e5a0",
              background: "#00e5a012",
              border: "1px solid #00e5a028",
              borderRadius: 6,
              padding: "6px 10px",
              display: "inline-block"
            }}
          >
            norviq.io/agent-class={agentClass}
          </span>
          <div style={{ marginTop: 14 }}>
            <div
              className="muted"
              style={{ fontSize: 11, display: "flex", alignItems: "center", gap: 6 }}
            >
              <Radar size={13} /> Matching deployments · auto-discovered
            </div>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 8, marginTop: 10 }}>
              {matches.length === 0 ? (
                <span className="muted" style={{ fontSize: 12 }}>
                  No deployments labeled with this agent-class.
                </span>
              ) : (
                matches.map((d) => (
                  <span
                    key={d.name}
                    style={{
                      display: "inline-flex",
                      alignItems: "center",
                      gap: 6,
                      fontFamily: "var(--font-mono)",
                      fontSize: 12,
                      background: "var(--bg-surface)",
                      border: "1px solid var(--border)",
                      borderRadius: 99,
                      padding: "4px 11px"
                    }}
                  >
                    <span
                      style={{
                        width: 6,
                        height: 6,
                        borderRadius: 99,
                        background: "#00e5a0",
                        boxShadow: "0 0 6px #00e5a0"
                      }}
                    />
                    {d.name}
                  </span>
                ))
              )}
            </div>
          </div>
          <PriorityBadge tier="class" />
        </div>
      )}

      {mode === "workload" && (
        <div>
          <div className="field-row">
            <label className="field-label">Kind</label>
            <div className="input select-trigger">
              <span>Deployment</span>
              <ChevronDown />
            </div>
          </div>
          <div className="field-row">
            <label className="field-label">Name</label>
            <input className="input" defaultValue={policy.target ?? "smartsales-agent"} />
          </div>
          <div className="field-row">
            <label className="field-label">Namespace</label>
            <div className="input select-trigger">
              <span>{policy.namespace ?? "chatbot-prod"}</span>
              <ChevronDown />
            </div>
          </div>
          <div
            style={{
              fontSize: 12,
              color: "var(--text-secondary)",
              display: "flex",
              alignItems: "center",
              gap: 7,
              marginTop: 4
            }}
          >
            <ArrowUpCircle size={14} style={{ color: "#2ddab8" }} />
            Overrides any agent-class policy for this workload
          </div>
          <PriorityBadge tier="workload" />
        </div>
      )}

      {mode === "namespace" && (
        <div>
          <div className="field-row">
            <label className="field-label">Namespace</label>
            <div className="input select-trigger">
              <span>{policy.namespace ?? "chatbot-prod"}</span>
              <ChevronDown />
            </div>
          </div>
          <div
            style={{
              display: "flex",
              gap: 10,
              alignItems: "flex-start",
              background: "#ffb02010",
              border: "1px solid #ffb02030",
              borderRadius: "var(--radius-md)",
              padding: "11px 13px",
              marginTop: 6
            }}
          >
            <TriangleAlert size={16} style={{ color: "#ffb020", flex: "none", marginTop: 1 }} />
            <p style={{ margin: 0, fontSize: 12.5, lineHeight: 1.5, color: "#ffcf7a" }}>
              Applies to <strong>ALL</strong> norviq-enabled workloads in this namespace. Use
              agent-class for precision.
            </p>
          </div>
          <PriorityBadge tier="namespace" />
        </div>
      )}
    </div>
  );
}

function PolicySheet({
  policy,
  deployments,
  onClose,
  onApply
}: {
  policy: Policy;
  deployments: Deployment[];
  onClose: () => void;
  onApply: (mode: Policy["mode"]) => void;
}) {
  const [enforcement, setEnforcement] = useState<NonNullable<Policy["mode"]>>(policy.mode ?? "block");
  const [paramsOpen, setParamsOpen] = useState(false);
  const [dryRun, setDryRun] = useState(false);

  const yamlPreview = `apiVersion: norviq.io/v1
kind: NrvqPolicy
spec:
  targetType: ${policy.target_type ?? "class"}
  target: ${policy.target ?? policy.agent_class ?? ""}
  enforcement: ${enforcement}
  rateLimit: 10
  keywords: [secret, token, password]`;

  return (
    <>
      <div className="sheet-overlay" onClick={onClose} />
      <div className="sheet-kit">
        <div className="sheet-head">
          <div>
            <div className="sheet-title">Configure Policy</div>
            <div className="panel-sub mono" style={{ marginTop: 3 }}>
              {policy.target ?? policy.agent_class ?? "new"} · v{policy.current_version ?? 1}
            </div>
          </div>
          <button className="icon-btn" onClick={onClose}>
            <X size={18} />
          </button>
        </div>

        <PolicyTarget policy={policy} deployments={deployments} />

        <div className="section-label" style={{ marginTop: 20 }}>
          Enforcement Mode
        </div>
        <div className="tabs-kit" style={{ display: "flex", marginBottom: 6 }}>
          {(["block", "audit", "escalate"] as const).map((m) => (
            <RadioPill
              key={m}
              active={enforcement === m}
              label={m}
              onClick={() => setEnforcement(m)}
            />
          ))}
        </div>

        <div
          className="section-label collapse-head"
          style={{ marginTop: 18 }}
          onClick={() => setParamsOpen((v) => !v)}
        >
          <span>Custom Parameters</span>
          {paramsOpen ? <ChevronUp size={15} /> : <ChevronDown size={15} />}
        </div>
        {paramsOpen && (
          <div style={{ marginTop: 8 }}>
            <div className="field-row">
              <label className="field-label">Rate limit (calls/min)</label>
              <input className="input mono" defaultValue="10" />
            </div>
            <div className="field-row">
              <label className="field-label">Block keywords</label>
              <input className="input mono" defaultValue="secret,token,password" />
            </div>
            <div className="field-row">
              <label className="field-label">Trust threshold override</label>
              <input className="input mono" defaultValue="0.7" />
            </div>
          </div>
        )}

        <div className="section-label" style={{ marginTop: 18 }}>
          Generated YAML
        </div>
        <div className="editor" style={{ marginBottom: 10 }}>
          <div className="editor-head">
            <FileCode size={14} /> NrvqPolicy
            <span style={{ marginLeft: "auto", color: "var(--text-muted)" }}>read-only</span>
          </div>
          <div className="editor-body">
            <div className="editor-code" style={{ paddingLeft: 16 }}>
              <pre style={{ margin: 0, fontFamily: "var(--font-mono)" }}>{yamlPreview}</pre>
            </div>
          </div>
        </div>

        {dryRun && (
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: 8,
              fontSize: 12.5,
              color: "#ffb020",
              background: "#ffb02010",
              border: "1px solid #ffb02030",
              borderRadius: "var(--radius-md)",
              padding: "9px 12px",
              marginBottom: 10
            }}
          >
            <Info size={14} /> Would have blocked{" "}
            <strong style={{ color: "#ffcf7a" }}>23 calls</strong> in the last 24h.
          </div>
        )}

        <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
          <KitButton variant="primary" icon={Check} onClick={() => onApply(enforcement)}>
            Apply
          </KitButton>
          <KitButton variant="outline" icon={Play} onClick={() => setDryRun(true)}>
            Dry-Run
          </KitButton>
          <KitButton variant="outline" icon={Copy} onClick={() => navigator.clipboard.writeText(yamlPreview)}>
            Copy YAML
          </KitButton>
          <KitButton variant="ghost" onClick={onClose}>
            Cancel
          </KitButton>
        </div>
      </div>
    </>
  );
}

export function PolicyCatalog() {
  const { namespace } = useApp();
  const outlineTealButtonStyle = {
    background: "transparent",
    border: "1px solid #2DDAB8",
    color: "#2DDAB8"
  } as const;
  // Land on the editor so the seeded class policy opens with Monaco + Dry-Run immediately
  // (the Catalog tab remains a click away for the grouped tier view).
  const [tab, setTab] = useState<"catalog" | "editor" | "versions">("editor");
  const [selected, setSelected] = useState<Policy | null>(null);
  const [restoreV, setRestoreV] = useState<number | null>(null);
  const [activeFile, setActiveFile] = useState<string | null>(null);
  const [regoDraft, setRegoDraft] = useState("");
  const [editorStatus, setEditorStatus] = useState<"saved" | "unsaved" | `syntax:${number}`>("saved");
  const [dryRunResult, setDryRunResult] = useState<DryRunResult | null>(null);
  const [dryRunLoading, setDryRunLoading] = useState(false);

  const policies = useApi<Policy[]>(
    () => apiGet<Policy[]>(`/api/v1/policies?namespace=${encodeURIComponent(namespace)}`).then(withTargetType),
    [namespace],
    {
      cacheKey: `policy-catalog:${namespace}`,
      staleTimeMs: Number.MAX_SAFE_INTEGER
    }
  );
  const deployments = useApi<Deployment[]>(
    () =>
      apiGet<Deployment[]>(`/api/v1/deployments?namespace=${encodeURIComponent(namespace)}`).catch(
        () => FALLBACK_DEPLOYMENTS
      ),
    [namespace]
  );

  const editorPolicy = useMemo(() => {
    const list = policies.data ?? [];
    if (activeFile) return list.find((p) => (p.target ?? p.agent_class) === activeFile);
    return list.find((p) => p.target_type === "class") ?? list[0];
  }, [policies.data, activeFile]);

  const detail = useApi<PolicyDetail>(
    () =>
      editorPolicy?.namespace && editorPolicy?.agent_class
        ? apiGet(
            `/api/v1/policies/${encodeURIComponent(editorPolicy.namespace)}/${encodeURIComponent(
              editorPolicy.agent_class
            )}?namespace=${encodeURIComponent(namespace)}`
          )
        : Promise.resolve({ rego_source: "" }),
    [editorPolicy?.namespace, editorPolicy?.agent_class, namespace]
  );

  const versions = useApi<PolicyVersion[]>(
    () =>
      editorPolicy?.namespace && editorPolicy?.agent_class
        ? apiGet(
            `/api/v1/policies/${encodeURIComponent(editorPolicy.namespace)}/${encodeURIComponent(
              editorPolicy.agent_class
            )}/versions?namespace=${encodeURIComponent(namespace)}`
          )
        : Promise.resolve([]),
    [editorPolicy?.namespace, editorPolicy?.agent_class, namespace]
  );

  const refreshPolicies = async () => {
    try {
      const next = withTargetType(await apiGet<Policy[]>(`/api/v1/policies?namespace=${encodeURIComponent(namespace)}`));
      policies.setData(next);
    } catch {
      // ignore
    }
  };

  const onApply = async (mode: Policy["mode"]) => {
    if (!selected) return;
    try {
      const targetType = selected.target_type === "class" ? "agent_class" : selected.target_type ?? "agent_class";
      await applyPolicy(selected.namespace ?? namespace, selected.agent_class ?? "", {
        target_type: targetType,
        target_namespace: selected.namespace ?? namespace,
        target_name: selected.target,
        target_kind: selected.target_type === "workload" ? "Deployment" : undefined,
        enforcement_mode: mode ?? "block"
      });
      await refreshPolicies();
    } finally {
      setSelected(null);
    }
  };

  const editorFiles = (policies.data ?? []).filter((p) => p.target_type === "class");
  const activePolicyName = activeFile ?? editorFiles[0]?.target ?? editorFiles[0]?.agent_class ?? null;

  useEffect(() => {
    setRegoDraft(detail.data?.rego_source ?? "");
    setEditorStatus("saved");
    setDryRunResult(null);
  }, [editorPolicy?.id, detail.data?.rego_source]);

  const saveEditorPolicy = async () => {
    if (!editorPolicy?.namespace || !editorPolicy?.agent_class) return;
    await apiSend("/api/v1/policies", "POST", {
      namespace: editorPolicy.namespace,
      agent_class: editorPolicy.agent_class,
      rego_source: regoDraft,
      enforcement_mode: editorPolicy.mode ?? "audit"
    });
    setEditorStatus("saved");
    await refreshPolicies();
  };

  const runDryRun = async () => {
    if (!editorPolicy?.namespace || !editorPolicy?.agent_class) return;
    setDryRunLoading(true);
    try {
      const result = await dryRunPolicy({
        namespace: editorPolicy.namespace,
        agent_class: editorPolicy.agent_class,
        rego_source: regoDraft || detail.data?.rego_source || ""
      });
      setDryRunResult(result);
    } catch {
      setDryRunResult({
        total_records_checked: 0,
        would_block: 0,
        would_allow: 0,
        block_rate_pct: 0,
        recommendation: "Unable to evaluate right now"
      });
    } finally {
      setDryRunLoading(false);
    }
  };

  return (
    <div className="page-enter">
      <PageHead
        title="Policy Catalog"
        subtitle={`Showing: ${namespace}`}
        actions={
          <KitButton
            variant="ghost"
            icon={Plus}
            style={outlineTealButtonStyle}
            onMouseEnter={(e) => (e.currentTarget.style.background = "#2DDAB815")}
            onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
            onClick={() =>
              setSelected({
                target_type: "class",
                target: "customer-support",
                agent_class: "customer-support",
                current_version: 1,
                mode: "block"
              })
            }
          >
            New Policy
          </KitButton>
        }
      />

      <div className="stack">
        <CategoryCoverage />

        <div className="tabs-kit" style={{ alignSelf: "flex-start" }}>
          {(["catalog", "editor", "versions"] as const).map((t) => (
            <button
              key={t}
              className={`tab-kit${tab === t ? " active" : ""}`}
              onClick={() => setTab(t)}
            >
              {t[0].toUpperCase() + t.slice(1)}
            </button>
          ))}
        </div>

        {tab === "catalog" && (
          <div className="stack">
            {TIERS.map((tier) => {
              const items = (policies.data ?? []).filter((p) => p.target_type === tier.type);
              return (
                <Panel
                  key={tier.type}
                  title={tier.title}
                  sub={tier.sub}
                  action={<PriorityBars tier={tier.type} />}
                >
                  {items.length === 0 ? (
                    <div className="muted" style={{ fontSize: 13, padding: "12px 0" }}>
                      No {tier.type} policies configured.
                    </div>
                  ) : (
                    <div className="grid-kit g3">
                      {items.map((p) => (
                        <button
                          key={p.id ?? `${p.namespace}-${p.agent_class}`}
                          className="policy-item"
                          onClick={() => {
                            setActiveFile(p.target ?? p.agent_class ?? null);
                            setTab("editor");
                          }}
                        >
                          <div
                            style={{
                              display: "flex",
                              justifyContent: "space-between",
                              alignItems: "center",
                              gap: 8
                            }}
                          >
                            <span className="policy-name mono">
                              {p.target ?? p.agent_class ?? "—"}
                            </span>
                            {p.mode && <DecisionBadge decision={MODE_DECISION[p.mode]} />}
                          </div>
                          <div className="policy-meta">
                            v{p.current_version ?? 1} ·{" "}
                            {(p.rego_length ?? 0).toLocaleString()} chars ·{" "}
                            {p.matches ?? 0} match{p.matches === 1 ? "" : "es"}
                          </div>
                        </button>
                      ))}
                    </div>
                  )}
                </Panel>
              );
            })}
          </div>
        )}

        {tab === "editor" && (
          <Panel pad>
            <div
              style={{
                display: "flex",
                gap: 0,
                border: "1px solid var(--border)",
                borderRadius: "var(--radius-md)",
                overflow: "hidden"
              }}
            >
              <div
                style={{
                  width: 220,
                  flex: "none",
                  background: "var(--bg-surface)",
                  borderRight: "1px solid var(--border)",
                  padding: 8
                }}
              >
                <div className="section-label" style={{ padding: "4px 8px" }}>
                  Policies
                </div>
                {editorFiles.length === 0 && (
                  <div className="muted" style={{ fontSize: 12, padding: 8 }}>
                    No class policies
                  </div>
                )}
                {editorFiles.map((p) => {
                  const name = p.target ?? p.agent_class ?? "policy";
                  const isActive = activePolicyName === name;
                  return (
                    <button
                      key={p.id ?? name}
                      role="row"
                      className={`sb-link${isActive ? " active" : ""}`}
                      onClick={() => setActiveFile(name)}
                      style={{ fontSize: 12.5 }}
                    >
                      <FileCode size={14} />
                      <span className="mono" style={{ fontSize: 12 }}>
                        {name}.rego
                      </span>
                    </button>
                  );
                })}
              </div>
              <div style={{ flex: 1, minWidth: 0, display: "flex", flexDirection: "column" }}>
                <div className="editor" style={{ borderRadius: 0, border: "none", height: 400 }}>
                  <div className="editor-head">
                    <FileCode size={14} /> {(activeFile ?? editorPolicy?.target ?? "policy") + ".rego"}
                    <span style={{ marginLeft: "auto", color: "var(--text-muted)" }}>Rego · OPA</span>
                  </div>
                  <Editor
                    defaultLanguage="rego"
                    theme="vs-dark"
                    height="350px"
                    value={regoDraft || "# Select a policy from the list"}
                    onChange={(value) => {
                      setRegoDraft(value ?? "");
                      setEditorStatus("unsaved");
                    }}
                    onValidate={(markers) => {
                      if (markers.length > 0) {
                        setEditorStatus(`syntax:${markers[0].startLineNumber}`);
                      } else {
                        setEditorStatus("unsaved");
                      }
                    }}
                    options={{ minimap: { enabled: false }, fontSize: 12.5 }}
                  />
                </div>
                <div
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: 12,
                    padding: "10px 14px",
                    borderTop: "1px solid var(--border)",
                    background: "var(--bg-surface)"
                  }}
                >
                  <span
                    style={{
                      color:
                        editorStatus === "saved"
                          ? "#00e5a0"
                          : editorStatus.startsWith("syntax:")
                          ? "#ff3b5c"
                          : "#ffb020",
                      fontSize: 12.5,
                      display: "inline-flex",
                      alignItems: "center",
                      gap: 6
                    }}
                  >
                    {editorStatus === "saved" && (
                      <>
                        <Check size={14} /> Saved ✓
                      </>
                    )}
                    {editorStatus === "unsaved" && (
                      <>
                        <Info size={14} /> Unsaved changes
                      </>
                    )}
                    {editorStatus.startsWith("syntax:") && (
                      <>
                        <AlertCircle size={14} /> Syntax error on line {editorStatus.split(":")[1]}
                      </>
                    )}
                  </span>
                  <div style={{ flex: 1 }} />
                  <KitButton
                    variant="ghost"
                    size="sm"
                    icon={Check}
                    style={outlineTealButtonStyle}
                    onMouseEnter={(e) => (e.currentTarget.style.background = "#2DDAB815")}
                    onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
                    onClick={saveEditorPolicy}
                  >
                    Save
                  </KitButton>
                  <KitButton variant="outline" size="sm" icon={Play} onClick={runDryRun}>
                    {dryRunLoading ? "Dry-Running..." : "Dry-Run"}
                  </KitButton>
                  <KitButton
                    variant="outline"
                    size="sm"
                    icon={Check}
                    onClick={() => {
                      if (editorPolicy) setSelected(editorPolicy);
                    }}
                  >
                    Apply
                  </KitButton>
                </div>
                {dryRunResult != null && (
                  <div
                    style={{
                      padding: "10px 14px",
                      borderTop: "1px solid var(--border)",
                      fontSize: 12.5
                    }}
                  >
                    <div style={{ fontWeight: 600, marginBottom: 6 }}>Dry-Run Results</div>
                    <div>Records checked: {(dryRunResult.total_records_checked ?? 0).toLocaleString()}</div>
                    <div>
                      Would block: {dryRunResult.would_block ?? 0} ({dryRunResult.block_rate_pct ?? 0}%)
                    </div>
                    <div>Would allow: {(dryRunResult.would_allow ?? 0).toLocaleString()}</div>
                    <div style={{ marginTop: 6 }}>Recommendation: {dryRunResult.recommendation ?? "n/a"}</div>
                  </div>
                )}
              </div>
            </div>
          </Panel>
        )}

        {tab === "versions" && (
          <Panel
            title="Version History"
            sub={`${editorPolicy?.target ?? editorPolicy?.agent_class ?? "—"} · ${
              editorPolicy?.target_type ?? "class"
            }`}
            style={{ paddingBottom: 6 }}
          >
            <div style={{ overflowX: "auto" }}>
              <table className="tbl">
                <thead>
                  <tr>
                    <th>Version</th>
                    <th>Saved By</th>
                    <th>Saved At</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {(versions.data ?? []).map((v, i) => (
                    <tr key={v.version} style={{ cursor: "default" }}>
                      <td>
                        <span className="mono">v{v.version}</span>
                        {i === 0 && (
                          <span
                            className="pill"
                            style={{ marginLeft: 8, color: "#00e5a0", borderColor: "#00e5a040" }}
                          >
                            current
                          </span>
                        )}
                      </td>
                      <td className="mono muted">{v.saved_by ?? "system"}</td>
                      <td className="muted">{fmtDateTime(v.saved_at)}</td>
                      <td>
                        <div style={{ display: "flex", gap: 8 }}>
                          <KitButton
                            variant="outline"
                            size="sm"
                            icon={FileCode}
                            onClick={() => {
                              setTab("editor");
                              setActiveFile(editorPolicy?.target ?? editorPolicy?.agent_class ?? null);
                            }}
                          >
                            Load in Editor
                          </KitButton>
                          {i !== 0 && (
                            <KitButton
                              variant="outline"
                              size="sm"
                              icon={RotateCcw}
                              onClick={() => setRestoreV(v.version)}
                            >
                              Restore
                            </KitButton>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {(versions.data ?? []).length === 0 && (
                <div className="muted" style={{ fontSize: 13, padding: "16px 14px" }}>
                  No version history available.
                </div>
              )}
            </div>
          </Panel>
        )}
      </div>

      {selected && (
        <PolicySheet
          policy={selected}
          deployments={deployments.data ?? FALLBACK_DEPLOYMENTS}
          onClose={() => setSelected(null)}
          onApply={onApply}
        />
      )}

      {restoreV != null && (
        <>
          <div className="sheet-overlay" onClick={() => setRestoreV(null)} />
          <div className="confirm-modal">
            <div className="sheet-title">Restore version v{restoreV}?</div>
            <p
              style={{
                fontSize: 13,
                color: "var(--text-secondary)",
                lineHeight: 1.5,
                margin: "10px 0 18px"
              }}
            >
              This rolls the active policy back to v{restoreV}. The current version is preserved in
              history.
            </p>
            <div style={{ display: "flex", justifyContent: "flex-end", gap: 8 }}>
              <KitButton variant="ghost" onClick={() => setRestoreV(null)}>
                Cancel
              </KitButton>
              <KitButton
                variant="primary"
                icon={RotateCcw}
                onClick={async () => {
                  if (editorPolicy?.namespace && editorPolicy?.agent_class) {
                    try {
                      await apiSend(
                        `/api/v1/policies/${encodeURIComponent(editorPolicy.namespace)}/${encodeURIComponent(
                          editorPolicy.agent_class
                        )}/rollback`,
                        "POST",
                        { target_version: restoreV }
                      );
                    } catch {
                      // ignore
                    }
                  }
                  setRestoreV(null);
                }}
              >
                Confirm Restore
              </KitButton>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
