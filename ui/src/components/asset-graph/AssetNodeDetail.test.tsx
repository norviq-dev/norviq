// SPDX-License-Identifier: Apache-2.0
// Redesigned inspector: blast radius from the reach set, trust bar, risk/calls cards, chips,
// SPIFFE identity, per-edge connections with allow/block counts, and the Audit Log deep-link.
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import { AssetNodeDetail } from "./AssetNodeDetail";
import { buildModel } from "./model";
import type { AssetEdge, AssetNode } from "./types";
import { ToastProvider } from "../common/Toast";
import * as client from "../../api/client";

const NODES: AssetNode[] = [
  {
    id: "agent-1", type: "agent", name: "customer-support",
    properties: { namespace: "studioai", agent_class: "customer-support", spiffe_id: "spiffe://norviq/ns/studioai/sa/customer-support", trust_score: 0.85 }
  },
  { id: "tool:send_email", type: "tool", name: "send_email", properties: { namespace: "studioai", risk_level: "high" } },
  { id: "data:smtp", type: "data", name: "smtp/outbound", properties: { namespace: "studioai" } }
];
const EDGES: AssetEdge[] = [
  { source: "agent-1", target: "tool:send_email", type: "calls", weight: 1, properties: { decision_history: { allow: 118, block: 24, escalate: 0 } } },
  { source: "tool:send_email", target: "data:smtp", type: "accesses", weight: 1, properties: {} }
];

describe("AssetNodeDetail (inspector redesign)", () => {
  const model = buildModel(NODES, EDGES);
  const agent = model.nodes.find((n) => n.id === "agent-1")!;
  const reach = new Set(["agent-1", "tool:send_email", "data:smtp"]);

  function renderIt(onClose = vi.fn()) {
    render(
      <MemoryRouter>
        <ToastProvider>
          <AssetNodeDetail node={agent} model={model} reach={reach} cluster="aks-dev" side="right" onClose={onClose} />
        </ToastProvider>
      </MemoryRouter>
    );
    return onClose;
  }

  it("renders name, blast radius, trust, and chips", () => {
    renderIt();
    // name appears as the title AND the class chip
    expect(screen.getAllByText("customer-support").length).toBeGreaterThanOrEqual(2);
    expect(screen.getByText(/blast radius/i)).toBeInTheDocument();
    expect(screen.getByText("1")).toBeInTheDocument(); // 1 data source in reach
    expect(screen.getByText(/0\.85/)).toBeInTheDocument();
    expect(screen.getByText("studioai")).toBeInTheDocument();
    expect(screen.getByText("aks-dev")).toBeInTheDocument();
  });

  it("lists connections with allow/block counts and verdict", () => {
    renderIt();
    expect(screen.getByText(/connections · 1/i)).toBeInTheDocument();
    expect(screen.getByText("118 allow · 24 block")).toBeInTheDocument();
    expect(screen.getByText("mixed")).toBeInTheDocument();
  });

  it("deep-links to the audit log by SPIFFE id and closes", () => {
    const onClose = renderIt();
    const link = screen.getByRole("link", { name: /view in audit log/i });
    expect(link.getAttribute("href")).toContain(encodeURIComponent("spiffe://norviq/ns/studioai/sa/customer-support"));
    fireEvent.click(screen.getByRole("button", { name: /close inspector/i }));
    expect(onClose).toHaveBeenCalled();
  });

  // A data node carrying a source-capability payload renders the verb surface + worst open verb.
  it("renders the source capability surface on a data node", () => {
    const dataNode = model.nodes.find((n) => n.id === "data:smtp")!;
    dataNode.capability = {
      source_class: "datastore",
      source_display: "Elasticsearch",
      worst: {
        verb: "write", risk: "high", technique: "AML.T0018", label: "write / index (knowledge poisoning)",
        status: "undefended", granted: true, observed: true, defended: false,
        recommendation: "block writes to the retrieval index — Elasticsearch"
      },
      findings: [
        { verb: "write", risk: "high", technique: "AML.T0018", label: "write / index (knowledge poisoning)", status: "undefended", granted: true, observed: true, defended: false, recommendation: "block writes to the retrieval index — Elasticsearch" },
        { verb: "delete", risk: "critical", technique: "AML.T0048", label: "delete / drop (availability)", status: "dormant_grant", granted: true, observed: false, defended: false, recommendation: "grant is unused — revoke delete on Elasticsearch (least privilege)" },
        { verb: "read", risk: "low", technique: null, label: "read / search", status: "defended", granted: true, observed: true, defended: true, recommendation: "" }
      ]
    };
    render(
      <MemoryRouter>
        <ToastProvider>
          <AssetNodeDetail node={dataNode} model={model} reach={new Set(["data:smtp"])} side="left" onClose={vi.fn()} />
        </ToastProvider>
      </MemoryRouter>
    );
    // section + source class/display
    expect(screen.getByText(/source capability/i)).toBeInTheDocument();
    expect(screen.getByText(/datastore · Elasticsearch/i)).toBeInTheDocument();
    // worst open verb surfaced with its recommendation
    expect(screen.getByText(/UNDEFENDED · WRITE/i)).toBeInTheDocument();
    expect(screen.getByText(/block writes to the retrieval index/i)).toBeInTheDocument();
    // per-verb rows: dormant delete + its real ATLAS id, and the read row present
    expect(screen.getByText(/AML\.T0048/)).toBeInTheDocument();
    expect(screen.getAllByText("DORMANT GRANT").length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText("DEFENDED")).toBeInTheDocument();
  });

  // CAP→POLICY: the worst open finding offers a one-click defense that calls the API + surfaces a toast
  // with a "Review in Policies" hand-off (never auto-enforces).
  it("defends an undefended verb → creates a draft and offers the Policies hand-off", async () => {
    const spy = vi.spyOn(client, "defendCapability").mockResolvedValue({
      draft_id: "dcap123", deeplink: "/policies/catalog?intent_draft=dcap123",
      ns: "studioai", cls: "report-gen", source_type: "elasticsearch", verbs: ["write"],
      blocked_tools: ["index_kb"], read_only: false, valid: true, errors: []
    });
    const dataNode = model.nodes.find((n) => n.id === "data:smtp")!;
    dataNode.ns = "studioai";
    dataNode.capability = {
      source_type: "elasticsearch", source_class: "datastore", source_display: "Elasticsearch",
      worst: {
        verb: "write", risk: "high", technique: "AML.T0018", label: "write / index (knowledge poisoning)",
        status: "undefended", granted: true, observed: true, defended: false,
        recommendation: "block writes to the retrieval index", agent_classes: ["report-gen"]
      },
      findings: [
        { verb: "write", risk: "high", technique: "AML.T0018", label: "write / index", status: "undefended", granted: true, observed: true, defended: false, recommendation: "block writes", agent_classes: ["report-gen"] }
      ]
    };
    render(
      <MemoryRouter>
        <ToastProvider>
          <AssetNodeDetail node={dataNode} model={model} reach={new Set(["data:smtp"])} side="left" onClose={vi.fn()} />
        </ToastProvider>
      </MemoryRouter>
    );
    const btn = screen.getByTestId("cap-defend");
    expect(btn).toHaveTextContent(/Defend: block WRITE for report-gen/i);
    fireEvent.click(btn);
    await waitFor(() => expect(spy).toHaveBeenCalledWith("studioai", "report-gen", "elasticsearch", ["write"]));
    // success toast with the hand-off action (draft is dry-run; nothing enforces)
    await waitFor(() => expect(screen.getByText(/Draft created/i)).toBeInTheDocument());
    expect(screen.getByText(/Review in Policies/i)).toBeInTheDocument();
    spy.mockRestore();
  });
});
