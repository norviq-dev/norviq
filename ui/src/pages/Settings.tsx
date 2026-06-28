import { Check } from "lucide-react";
import { ReactNode, useState } from "react";
import { KitButton } from "../components/common/KitButton";
import { PageHead } from "../components/common/PageHead";
import { Panel } from "../components/common/Panel";

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

const SETTINGS_KEY = "nrvq_settings";

type StoredSettings = {
  mode: "block" | "audit";
  trustThreshold: string;
  violationPenalty: string;
  rateLimit: string;
};

function loadSettings(): StoredSettings {
  const fallback: StoredSettings = { mode: "block", trustThreshold: "0.7", violationPenalty: "0.05", rateLimit: "60" };
  try {
    const raw = localStorage.getItem(SETTINGS_KEY);
    return raw ? { ...fallback, ...(JSON.parse(raw) as Partial<StoredSettings>) } : fallback;
  } catch {
    return fallback;
  }
}

export function Settings() {
  const initial = loadSettings();
  const [mode, setMode] = useState<"block" | "audit">(initial.mode);
  const [trustThreshold, setTrustThreshold] = useState(initial.trustThreshold);
  const [violationPenalty, setViolationPenalty] = useState(initial.violationPenalty);
  const [rateLimit, setRateLimit] = useState(initial.rateLimit);
  const [saved, setSaved] = useState(false);
  const outlineTealButtonStyle = {
    background: "transparent",
    border: "1px solid #2DDAB8",
    color: "#2DDAB8"
  } as const;

  // No settings API yet — persist locally so the form round-trips and the action confirms (MVP).
  const onSave = () => {
    localStorage.setItem(SETTINGS_KEY, JSON.stringify({ mode, trustThreshold, violationPenalty, rateLimit }));
    setSaved(true);
    setTimeout(() => setSaved(false), 2500);
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
        <span
          title="Saved in this browser only — there is no server-side settings store yet."
          style={{ fontSize: 12, color: "var(--text-secondary)" }}
        >
          Saved locally (no server settings store yet)
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
