import { Check, ArrowRight } from "lucide-react";
import { ReactNode, useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { fetchRetentionSettings, fetchSettings, saveSettings, type RetentionSettings } from "../api/client";
import { KitButton } from "../components/common/KitButton";
import { PageHead } from "../components/common/PageHead";
import { Panel } from "../components/common/Panel";
import { useApp } from "../store/AppContext";

function SettingsSection({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div style={{ marginBottom: 8 }}>
      <div
        style={{
          fontSize: 10,
          fontWeight: 600,
          letterSpacing: "0.08em",
          color: "#666666",
          textTransform: "uppercase",
          marginBottom: 10
        }}
      >
        {label}
      </div>
      {children}
    </div>
  );
}

// Read-only value formatters for the Data-retention card: 0/negative means the limit is disabled.
const FOREVER = "keep forever / disabled";
const fmtDays = (n: number) => (n > 0 ? `${n} day${n === 1 ? "" : "s"}` : FOREVER);
const fmtHours = (n: number) => (n > 0 ? `${n} hour${n === 1 ? "" : "s"}` : FOREVER);
const fmtRuns = (n: number) => (n > 0 ? `last ${n} run${n === 1 ? "" : "s"}` : FOREVER);

function RetentionRow({ label, value }: { label: string; value: string }) {
  return (
    <Field label={label}>
      <span className="mono" style={{ fontSize: 13, color: "var(--text-primary)" }}>{value}</span>
    </Field>
  );
}

function Field({
  label,
  hint,
  children
}: {
  label: string;
  hint?: string;
  children: ReactNode;
}) {
  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        gap: 20,
        padding: "12px 0",
        borderBottom: "1px solid var(--border)"
      }}
    >
      <div>
        <div style={{ fontSize: 13.5, color: "var(--text-primary)" }}>{label}</div>
        {hint && <div style={{ fontSize: 12, color: "var(--text-secondary)", marginTop: 2 }}>{hint}</div>}
      </div>
      <div style={{ flex: "none" }}>{children}</div>
    </div>
  );
}

export function Settings() {
  const { namespace } = useApp();
  const navigate = useNavigate();
  // GOV-IA (product decision): namespace-keyed GOVERNANCE (Block⇄Monitor enforcement + Live⇄Frozen change
  // control) lives ONLY in Target Settings now — the duplicate toggles here mutated the same server object
  // from two places. This page keeps the per-namespace TUNING defaults (trust/penalty/rate/sector) and
  // links to Target Settings for governance.
  const [trustThreshold, setTrustThreshold] = useState("");
  const [rateLimit, setRateLimit] = useState("");
  const [sector, setSector] = useState("");
  const [loading, setLoading] = useState(true);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // Cluster-wide retention limits (read-only). null = not loaded / fetch failed → the card is hidden.
  const [retention, setRetention] = useState<RetentionSettings | null>(null);
  const outlineTealButtonStyle = {
    background: "transparent",
    border: "1px solid #2DDAB8",
    color: "#2DDAB8"
  } as const;

  // Load the REAL effective settings (config defaults + persisted overrides) for the namespace.
  useEffect(() => {
    let active = true;
    setLoading(true);
    fetchSettings(namespace)
      .then((s) => {
        if (!active) return;
        setTrustThreshold(String(s.trust_threshold));
        setRateLimit(String(s.rate_limit));
        setSector(s.sector ?? "");
        setError(null);
      })
      .catch(() => active && setError("Could not load settings"))
      .finally(() => active && setLoading(false));
    return () => {
      active = false;
    };
  }, [namespace]);

  // Retention limits are cluster-wide (not per-namespace) — fetch once; on failure keep the card hidden.
  useEffect(() => {
    let active = true;
    fetchRetentionSettings()
      .then((r) => active && setRetention(r))
      .catch(() => active && setRetention(null));
    return () => {
      active = false;
    };
  }, []);

  // SET-VALIDATE (audit #14): reject non-numeric / out-of-range tuning values client-side instead of
  // shipping NaN to the server. trust threshold is 0..1; rate limit is a non-negative int.
  const validateTuning = (): string | null => {
    const t = Number(trustThreshold);
    const r = Number(rateLimit);
    if (!Number.isFinite(t) || t < 0 || t > 1) return "Trust Threshold must be a number between 0 and 1.";
    if (!Number.isInteger(r) || r < 0) return "Rate Limit must be a non-negative whole number.";
    return null;
  };

  const onSave = async () => {
    setError(null);
    const invalid = validateTuning();
    if (invalid) {
      setError(invalid);
      return;
    }
    try {
      await saveSettings(namespace, {
        trust_threshold: Number(trustThreshold),
        rate_limit: Number(rateLimit),
        sector
      });
      setSaved(true);
      setTimeout(() => setSaved(false), 2500);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Save failed");
    }
  };

  return (
    <div className="page-enter" style={{ maxWidth: 760, position: "relative", paddingBottom: 72 }}>
      <PageHead title="Settings" />
      <div className="stack">
        <Panel pad>
          <SettingsSection label="Tuning defaults">
            {/* GOV-IA: governance (enforcement mode + change control) is per-namespace and owned by Target
                Settings — this callout is the one pointer, replacing the duplicate toggles. */}
            <button
              type="button"
              onClick={() => navigate("/policies/targets")}
              style={{
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                width: "100%",
                gap: 12,
                padding: "12px 14px",
                marginBottom: 8,
                background: "var(--bg-surface-hover)",
                border: "1px solid var(--border)",
                borderRadius: 10,
                cursor: "pointer",
                textAlign: "left",
                fontFamily: "inherit"
              }}
            >
              <span>
                <span style={{ fontSize: 13.5, color: "var(--text-primary)", fontWeight: 600 }}>
                  Governance (enforcement mode, change control)
                </span>
                <span style={{ display: "block", fontSize: 12, color: "var(--text-secondary)", marginTop: 2 }}>
                  Block ⇄ Monitor and Live ⇄ Frozen are per-namespace — managed in Target Settings.
                </span>
              </span>
              <span style={{ display: "inline-flex", alignItems: "center", gap: 6, color: "var(--accent)", fontSize: 12.5, fontWeight: 600, whiteSpace: "nowrap" }}>
                Target Settings <ArrowRight size={14} />
              </span>
            </button>
            <Field label="Trust Threshold" hint="Score below this triggers escalation">
              <input
                className="input mono"
                value={trustThreshold}
                onChange={(e) => setTrustThreshold(e.target.value)}
                style={{ width: 90, textAlign: "right" }}
              />
            </Field>
            <Field label="Rate Limit" hint="Max tool calls per agent per minute">
              <input
                className="input mono"
                value={rateLimit}
                onChange={(e) => setRateLimit(e.target.value)}
                style={{ width: 90, textAlign: "right" }}
              />
            </Field>
            <Field label="Sector" hint="Suggests matching starter Policy Packs">
              <select
                className="input"
                value={sector}
                onChange={(e) => setSector(e.target.value)}
                style={{ width: 160 }}
              >
                <option value="">None</option>
                {["Energy", "Finance", "Healthcare", "Government", "Telecom", "ERP/CRM", "Media/Entertainment", "E-commerce"].map((s) => (
                  <option key={s} value={s}>
                    {s}
                  </option>
                ))}
              </select>
            </Field>
          </SettingsSection>
        </Panel>

        {/* Read-only, cluster-wide data-retention limits. Hidden entirely when the fetch fails. */}
        {retention && (
          <Panel pad>
            <SettingsSection label="Data retention">
              <RetentionRow label="Audit log" value={fmtDays(retention.audit_retention_days)} />
              <RetentionRow label="Coverage snapshots" value={fmtDays(retention.coverage_snapshot_retention_days)} />
              <RetentionRow
                label="Asset-graph snapshots"
                value={
                  retention.graph_snapshot_keep_per_namespace > 0
                    ? `newest ${retention.graph_snapshot_keep_per_namespace} per namespace`
                    : FOREVER
                }
              />
              <RetentionRow label="Agent registry" value={fmtDays(retention.agent_registry_retention_days)} />
              <RetentionRow
                label="API keys"
                value={
                  retention.api_key_default_ttl_days > 0
                    ? `new keys expire after ${retention.api_key_default_ttl_days} days`
                    : FOREVER
                }
              />
              <RetentionRow label="Policy drafts" value={fmtDays(retention.draft_ttl_days)} />
              <RetentionRow label="Test policy drafts" value={fmtHours(retention.draft_ttl_test_hours)} />
              <RetentionRow
                label="Draft cap"
                value={
                  retention.draft_cap_per_namespace > 0
                    ? `max ${retention.draft_cap_per_namespace} per namespace`
                    : FOREVER
                }
              />
              <RetentionRow
                label="Policy versions kept"
                value={
                  retention.policy_version_keep_count > 0
                    ? `newest ${retention.policy_version_keep_count}`
                    : FOREVER
                }
              />
              <RetentionRow label="Policy versions age limit" value={fmtDays(retention.policy_version_keep_days)} />
              <RetentionRow label="Red-team run details" value={fmtRuns(retention.redteam_detail_keep_runs)} />
              <RetentionRow label="Red-team run details age limit" value={fmtDays(retention.redteam_detail_keep_days)} />
              <RetentionRow label="Red-team summaries" value={fmtRuns(retention.redteam_summary_keep_runs)} />
              <RetentionRow label="Red-team summaries age limit" value={fmtDays(retention.redteam_summary_keep_days)} />
              <div style={{ fontSize: 12, color: "var(--text-secondary)", marginTop: 10 }}>
                Adjust via Helm values (config.*) — 0 disables a limit (keep forever).
              </div>
            </SettingsSection>
          </Panel>
        )}
      </div>

      <div
        style={{
          marginTop: 16,
          padding: "4px 0 12px",
          display: "flex",
          alignItems: "center",
          justifyContent: "flex-end",
          gap: 12
        }}
      >
        {saved && (
          <span role="status" style={{ fontSize: 13, color: "#00e5a0", display: "flex", alignItems: "center", gap: 6 }}>
            <Check size={14} /> Settings saved
          </span>
        )}
        {error && <span style={{ fontSize: 13, color: "var(--block)" }}>{error}</span>}
        <span style={{ fontSize: 12, color: "var(--text-secondary)" }}>
          {loading ? "Loading…" : `Persisted server-side for namespace "${namespace}"`}
        </span>
        <KitButton
          variant="ghost"
          icon={Check}
          onClick={onSave}
          style={outlineTealButtonStyle}
          onMouseEnter={(e) => (e.currentTarget.style.background = "#2DDAB815")}
          onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
        >
          {saved ? "Saved" : "Save Changes"}
        </KitButton>
      </div>
    </div>
  );
}
