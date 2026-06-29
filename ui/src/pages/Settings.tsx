import { Check } from "lucide-react";
import { ReactNode, useEffect, useState } from "react";
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
  const [mode, setMode] = useState<"block" | "audit">("block");
  const [trustThreshold, setTrustThreshold] = useState("");
  const [violationPenalty, setViolationPenalty] = useState("");
  const [rateLimit, setRateLimit] = useState("");
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
        setMode(s.enforcement_mode);
        setTrustThreshold(String(s.trust_threshold));
        setViolationPenalty(String(s.violation_penalty));
        setRateLimit(String(s.rate_limit));
        setError(null);
      })
      .catch(() => active && setError("Could not load settings"))
      .finally(() => active && setLoading(false));
    return () => {
      active = false;
    };
  }, [namespace]);

  const onSave = async () => {
    setError(null);
    try {
      await saveSettings(namespace, {
        enforcement_mode: mode,
        trust_threshold: Number(trustThreshold),
        violation_penalty: Number(violationPenalty),
        rate_limit: Number(rateLimit)
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
          <SettingsSection label="General">
            <Field label="Enforcement Mode" hint="Default action when a policy matches">
              <div className="tabs-kit">
                {(["block", "audit"] as const).map((m) => (
                  <button
                    key={m}
                    className={`tab-kit${mode === m ? " active" : ""}`}
                    onClick={() => setMode(m)}
                    style={{ textTransform: "capitalize" }}
                  >
                    {m}
                  </button>
                ))}
              </div>
            </Field>
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
