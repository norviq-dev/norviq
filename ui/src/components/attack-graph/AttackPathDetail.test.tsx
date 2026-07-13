import { fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import { AttackPathDetail } from "./AttackPathDetail";
import type { ThreatPath } from "./types";

const path: ThreatPath = {
  id: "p2", sev: "high", src: "billing-runner", tgt: "postgresql/ledger", ns: "payments", cls: "payments",
  mitre: "T1041 · Exfiltration", hops: 2, trust: 0.61, blast: 4, status: "exploitable", tool: "issue_refund",
  reach: [{ n: "tax-records", s: 1 }],
  steps: [
    { from: "billing-runner", to: "issue_refund", verb: "calls", dec: "mixed", kind: "tool", deny: 6, allow: 68 },
    { from: "issue_refund", to: "postgresql/ledger", verb: "reaches", dec: "allow", kind: "data", deny: 0, allow: 512 }
  ],
  verdict: "No step fully blocked — path is EXPLOITABLE.",
  fix: "Scope issue_refund: cap refund amount and restrict to ns payments."
};

function renderDetail(over: Partial<React.ComponentProps<typeof AttackPathDetail>> = {}) {
  return render(
    // AG-DRAFT-01: the confirmation deep-links via useNavigate, so the inspector needs a Router context.
    <MemoryRouter>
      <AttackPathDetail
        path={path}
        status="exploitable"
        whatIfIndex={-1}
        simResult={null}
        simulating={false}
        drafted={false}
        onToggleWhatIf={vi.fn()}
        onDefineIntent={vi.fn()}
        onSimulate={vi.fn()}
        onDraft={vi.fn()}
        {...over}
      />
    </MemoryRouter>
  );
}

describe("AttackPathDetail (inspector)", () => {
  it("renders severity, MITRE, blast, verdict, and the recommended fix", () => {
    renderDetail();
    expect(screen.getByText(/MITRE T1041/)).toBeInTheDocument();
    expect(screen.getByText(/RECOMMENDED FIX/)).toBeInTheDocument();
    expect(screen.getByText(/EXPLOITABLE/)).toBeInTheDocument();
  });

  it("'Define intended behaviour' opens the intent flow", () => {
    const onDefineIntent = vi.fn();
    renderDetail({ onDefineIntent });
    fireEvent.click(screen.getByRole("button", { name: /define .*intended behaviour/i }));
    expect(onDefineIntent).toHaveBeenCalled();
  });

  it("shows the Draft blocking policy button only when a what-if is active", () => {
    const { rerender } = renderDetail();
    expect(screen.queryByRole("button", { name: /draft blocking policy/i })).not.toBeInTheDocument();
    rerender(
      <MemoryRouter>
        <AttackPathDetail
          path={path} status="blocked" whatIfIndex={0} simResult={null} simulating={false} drafted={false}
          onToggleWhatIf={vi.fn()} onDefineIntent={vi.fn()} onSimulate={vi.fn()} onDraft={vi.fn()}
        />
      </MemoryRouter>
    );
    expect(screen.getByRole("button", { name: /draft blocking policy/i })).toBeInTheDocument();
  });
});
