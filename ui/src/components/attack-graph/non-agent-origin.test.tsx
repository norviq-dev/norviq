// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// A kill-chain that starts at an MCP server rather than an agent (Part 6b).
//
// Every failure guarded here is a QUIET one. The canvas hardcoded the source as `kind: "agent"`, and
// `drawIcon`'s else-branch draws the DATA CYLINDER for any kind it does not recognise — so the one
// node whose kind carries the finding was both the most likely to be mislabelled and the least likely
// to look wrong. On the detail panel the failure is worse than cosmetic: the actions there are scoped
// by agent class, and a path with no class would either create a policy scoped to the empty string or
// mint a SPIFFE id ending in `/sa/`.

import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import { AttackPathDetail } from "./AttackPathDetail";
import { buildScope } from "./AttackGraphCanvas";
import type { ThreatPath } from "./types";

const STEPS: ThreatPath["steps"] = [
  { from: "reporting-kb", to: "read_file", verb: "serves", dec: "allow", kind: "tool", deny: 0, allow: 0 },
  { from: "read_file", to: "pg/customers", verb: "reaches", dec: "allow", kind: "data", deny: 0, allow: 0 }
];

const MCP_PATH: ThreatPath = {
  id: "p-mcp", sev: "critical", src: "reporting-kb", tgt: "pg/customers", ns: "agents",
  src_kind: "mcp_server", cls: null, mitre: "T1005", hops: 2, trust: null, blast: 1,
  status: "unsimulated", tool: "read_file", reach: [{ n: "pg/customers", s: 1 }], steps: STEPS,
  verdict: "Reachable by construction: this MCP server serves 'read_file'.", fix: "Register or block the server.",
  governed_by: "n/a"
};

const AGENT_PATH: ThreatPath = {
  ...MCP_PATH, id: "p-agent", src: "support-agent", src_kind: "agent", cls: "support-agent",
  trust: 0.42, governed_by: "", verdict: "Every hop has allowed traffic.", status: "exploitable"
};

function renderDetail(path: ThreatPath) {
  return render(
    <MemoryRouter>
      <AttackPathDetail
        path={path} status={path.status} whatIfIndex={-1} simResult={null} simulating={false}
        drafted={false} onToggleWhatIf={vi.fn()} onDefineIntent={vi.fn()}
        onSimulate={vi.fn()} onDraft={vi.fn()}
      />
    </MemoryRouter>
  );
}

describe("the detail panel does not offer agent-class actions for a non-agent origin", () => {
  it("replaces the intent button with what DOES govern the path", () => {
    // Not a disabled button. An intent policy for a non-agent origin is not a thing that exists and
    // is temporarily unavailable — it is a category error, and the panel should still end in an
    // action the operator can take.
    renderDetail(MCP_PATH);
    expect(screen.queryByText(/intended behaviour/i)).toBeNull();
    const note = screen.getByTestId("attack-path-non-agent-note");
    expect(note).toHaveTextContent(/starts at an MCP server, not an agent/i);
    expect(note).toHaveTextContent(/MCP Servers/);
  });

  it("still offers it for an agent origin", () => {
    renderDetail(AGENT_PATH);
    expect(screen.getByText(/support-agent's intended behaviour/i)).toBeInTheDocument();
    expect(screen.queryByTestId("attack-path-non-agent-note")).toBeNull();
  });

  it("says 'not an agent' instead of a trust number", () => {
    // The server used to fabricate 0.8 here, which renders GREEN. Rendering the null as 0 would be the
    // opposite lie — a frozen-agent red on something that has no score at all.
    renderDetail(MCP_PATH);
    expect(screen.getByTestId("attack-path-trust")).toHaveTextContent("not an agent");
    expect(screen.getByText("Origin")).toBeInTheDocument();
  });

  it("still shows a real trust score for an agent", () => {
    renderDetail(AGENT_PATH);
    expect(screen.getByTestId("attack-path-trust")).toHaveTextContent("0.42");
    expect(screen.getByText("Min trust")).toBeInTheDocument();
  });
});

describe("the canvas reads the origin kind rather than assuming", () => {
  it("scopes an MCP-origin node as an mcp server, in readable words", () => {
    // buildScope defaulted to "agent" for any node that never appears as a step target — true by
    // construction until an MCP server could be a source. The LABEL is asserted too: `kindLabel` is
    // the wire word, and "mcp_server" reads as an identifier rather than a thing in the estate.
    const card = buildScope("reporting-kb", [MCP_PATH]);
    expect(card?.kindLabel).toBe("mcp server");
    expect(card?.kindColor).toBeTruthy();
  });

  it("still scopes an agent source as an agent", () => {
    expect(buildScope("support-agent", [AGENT_PATH])?.kindLabel).toBe("agent");
  });

  it("scopes a step target by the step's own kind, unchanged", () => {
    expect(buildScope("read_file", [MCP_PATH])?.kindLabel).toBe("tool");
    expect(buildScope("pg/customers", [MCP_PATH])?.kindLabel).toBe("data");
  });
});

describe("backwards compatibility with a payload that predates src_kind", () => {
  it("treats a path with no src_kind as an agent path", () => {
    // The field is optional on the wire and defaulted server-side, so a stored fixture or an older
    // API must keep behaving exactly as it did.
    const legacy = { ...AGENT_PATH } as ThreatPath;
    delete (legacy as { src_kind?: string }).src_kind;
    renderDetail(legacy);
    expect(screen.getByText(/support-agent's intended behaviour/i)).toBeInTheDocument();
    expect(buildScope("support-agent", [legacy])?.kindLabel).toBe("agent");
  });
});
