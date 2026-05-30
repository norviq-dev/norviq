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

export function Settings() {
  const [mode, setMode] = useState<"block" | "audit">("block");
  const outlineTealButtonStyle = {
    background: "transparent",
    border: "1px solid #2DDAB8",
    color: "#2DDAB8"
  } as const;

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
              <input className="input mono" defaultValue="0.7" style={{ width: 90, textAlign: "right" }} />
            </Field>
            <Field label="Violation Penalty" hint="Trust deducted per blocked call">
              <input className="input mono" defaultValue="0.05" style={{ width: 90, textAlign: "right" }} />
            </Field>
            <Field label="Rate Limit" hint="Max tool calls per agent per minute">
              <input className="input mono" defaultValue="60" style={{ width: 90, textAlign: "right" }} />
            </Field>
          </SettingsSection>
        </Panel>
      </div>

      <div
        style={{
          marginTop: 16,
          padding: "4px 0 12px",
          display: "flex",
          justifyContent: "flex-end"
        }}
      >
        <KitButton
          variant="ghost"
          icon={Check}
          style={outlineTealButtonStyle}
          onMouseEnter={(e) => (e.currentTarget.style.background = "#2DDAB815")}
          onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
        >
          Save Changes
        </KitButton>
      </div>
    </div>
  );
}
