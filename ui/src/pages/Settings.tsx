import { Check, ArrowRight } from "lucide-react";
import { ReactNode, useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { fetchSettings, saveSettings } from "../api/client";
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
  // GOV-IA (San decision a): namespace-keyed GOVERNANCE (Block⇄Monitor enforcement + Live⇄Frozen change
  // control) lives ONLY in Target Settings now — the duplicate toggles here mutated the same server object
  // from two places. This page keeps the per-namespace TUNING defaults (trust/penalty/rate/sector) and
  // links to Target Settings for governance.
  const [trustThreshold, setTrustThreshold] = useState("");
  const [violationPenalty, setViolationPenalty] = useState("");
  const [rateLimit, setRateLimit] = useState("");
  const [sector, setSector] = useState("");
  const [loading, setLoading] = useState(true);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState<string | null>(null);
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
        setViolationPenalty(String(s.violation_penalty));
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

  // SET-VALIDATE (audit #14): reject non-numeric / out-of-range tuning values client-side instead of
  // shipping NaN to the server. trust threshold + violation penalty are 0..1; rate limit is a non-negative int.
  const validateTuning = (): string | null => {
    const t = Number(trustThreshold);
    const v = Number(violationPenalty);
    const r = Number(rateLimit);
    if (!Number.isFinite(t) || t < 0 || t > 1) return "Trust Threshold must be a number between 0 and 1.";
    if (!Number.isFinite(v) || v < 0 || v > 1) return "Violation Penalty must be a number between 0 and 1.";
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
        violation_penalty: Number(violationPenalty),
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
            <Field label="Violation Penalty" hint="Trust deducted per blocked call">
              <input
                className="input mono"
                value={violationPenalty}
                onChange={(e) => setViolationPenalty(e.target.value)}
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
