// SPDX-License-Identifier: Apache-2.0
// The resolution hierarchy renders GET /policies/effective VERBATIM — same order, scopes, priorities, overlay
// flags — never re-derived. Plus the reserved static Mode column, the presence template, and (fleet on) the cluster
// dimension.
import type { ReactNode } from "react";
import { render, screen, waitFor, within } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { PolicyHierarchy } from "./PolicyHierarchy";
import { clearApiCache } from "../hooks/useApi";

const mockApp = { servedCluster: "kind-nrvq", scopeCluster: "kind-nrvq" };
vi.mock("../store/AppContext", () => ({ useApp: () => mockApp }));
const fleet = { enabled: false };
vi.mock("../api/fleet", () => ({ get fleetEnabled() { return fleet.enabled; } }));

const server = setupServer();
beforeAll(() => server.listen({ onUnhandledRequest: "bypass" }));
beforeEach(() => { fleet.enabled = false; });
afterEach(() => { server.resetHandlers(); clearApiCache(); });
afterAll(() => server.close());

// The authoritative stack the evaluator returns (order matters — highest priority first).
const LAYERS = [
  { scope: "default:customer-support", label: "agent-class policy", priority: 700, overlay: false },
  { scope: "default:__pack_override__", label: "pack override (overlay)", priority: 500, overlay: true },
  { scope: "default:__pack__", label: "sector pack (overlay)", priority: 400, overlay: true },
  { scope: "default:__baseline__", label: "namespace baseline", priority: 100, overlay: false },
  { scope: "__cluster__:__baseline__", label: "cluster baseline (comprehensive)", priority: 100, overlay: false }
];

function handlers(layers: unknown[] = LAYERS, enforcementMode: "block" | "audit" = "block") {
  server.use(
    http.get("/api/v1/policies", () => HttpResponse.json([{ agent_class: "customer-support", target_type: "class" }])),
    http.get("/api/v1/policies/effective", () => HttpResponse.json({ namespace: "default", agent_class: "customer-support", layers, note: "overlay layers are tighten-only" })),
    // CATHIER-MODE-01: the Mode column now reflects the effective per-ns posture from GET /settings.
    http.get("/api/v1/settings", () => HttpResponse.json({ enforcement_mode: enforcementMode, apply_mode: "enforce" }))
  );
}

describe("PolicyHierarchy", () => {
  it("renders /policies/effective VERBATIM — order, scope, priority, overlay flag", async () => {
    handlers();
    render(<PolicyHierarchy namespace="default" />);
    await waitFor(() => expect(screen.getAllByTestId("policy-hierarchy-row").length).toBe(LAYERS.length));
    const rows = screen.getAllByTestId("policy-hierarchy-row");
    // rows are in the SAME order as the API (no client re-sort)
    LAYERS.forEach((l, i) => {
      const row = within(rows[i]);
      expect(row.getByTestId("policy-hierarchy-scope")).toHaveTextContent(l.scope);
      expect(row.getByTestId("policy-hierarchy-priority")).toHaveTextContent(String(l.priority));
      // overlay rows carry the tighten-only marker; base rows do not
      if (l.overlay) expect(row.getByTestId("policy-hierarchy-overlay")).toHaveTextContent(/tighten-only/i);
      else expect(row.queryByTestId("policy-hierarchy-overlay")).toBeNull();
    });
  });

  // CATHIER-MODE-01: the Mode column now reflects the effective per-ns posture (Block / Monitor) from /settings,
  // agreeing with the Governance card — no longer the wired-to-nothing static "Enforce".
  it("Mode column shows 'Block' for a block-mode namespace", async () => {
    handlers(LAYERS, "block");
    render(<PolicyHierarchy namespace="default" />);
    await waitFor(() => expect(screen.getAllByTestId("policy-hierarchy-row").length).toBe(LAYERS.length));
    const modes = screen.getAllByTestId("policy-hierarchy-mode");
    expect(modes.length).toBe(LAYERS.length);
    modes.forEach((m) => { expect(m).toHaveTextContent("Block"); expect(m).not.toHaveTextContent("Enforce"); });
  });

  it("Mode column shows 'Monitor' when the namespace is in audit mode (never the raw 'audit')", async () => {
    handlers(LAYERS, "audit");
    render(<PolicyHierarchy namespace="default" />);
    await waitFor(() => expect(screen.getAllByTestId("policy-hierarchy-row").length).toBe(LAYERS.length));
    const modes = screen.getAllByTestId("policy-hierarchy-mode");
    modes.forEach((m) => { expect(m).toHaveTextContent("Monitor"); expect(m).not.toHaveTextContent(/audit/i); });
  });

  it("presence template marks in-force slots ✓ (pack, override, ns-baseline, cluster-baseline, class) and empty slots ○", async () => {
    handlers();
    render(<PolicyHierarchy namespace="default" />);
    await waitFor(() => expect(screen.getByTestId("policy-hierarchy-slot-pack")).toHaveAttribute("data-present", "1"));
    expect(screen.getByTestId("policy-hierarchy-slot-override")).toHaveAttribute("data-present", "1");
    expect(screen.getByTestId("policy-hierarchy-slot-ns-baseline")).toHaveAttribute("data-present", "1");
    expect(screen.getByTestId("policy-hierarchy-slot-cluster-baseline")).toHaveAttribute("data-present", "1");
    expect(screen.getByTestId("policy-hierarchy-slot-class")).toHaveAttribute("data-present", "1");
    // no workload/guardrail layer present → empty slot
    expect(screen.getByTestId("policy-hierarchy-slot-workload")).toHaveAttribute("data-present", "0");
    expect(screen.getByTestId("policy-hierarchy-slot-guardrail")).toHaveAttribute("data-present", "0");
  });

  it("baseline-only class shows just the base layers (no overlay rows)", async () => {
    handlers([{ scope: "__cluster__:__baseline__", label: "cluster baseline (comprehensive)", priority: 100, overlay: false }]);
    render(<PolicyHierarchy namespace="default" />);
    await waitFor(() => expect(screen.getAllByTestId("policy-hierarchy-row").length).toBe(1));
    expect(screen.queryByTestId("policy-hierarchy-overlay")).toBeNull();
    expect(screen.getByTestId("policy-hierarchy-slot-pack")).toHaveAttribute("data-present", "0");
  });

  it("cluster dimension: single-cluster shows the served cluster; the fleet cluster slot is hidden", async () => {
    handlers();
    render(<PolicyHierarchy namespace="default" />);
    await waitFor(() => expect(screen.getByTestId("policy-hierarchy-cluster")).toHaveTextContent("kind-nrvq"));
    expect(screen.queryByTestId("policy-hierarchy-slot-cluster")).toBeNull(); // fleetOnly slot hidden when fleet off
  });

  it("FLEET ON: the cluster slot appears and the cluster header shows the scope cluster", async () => {
    fleet.enabled = true;
    mockApp.scopeCluster = "All clusters";
    handlers();
    render(<PolicyHierarchy namespace="default" />);
    await waitFor(() => expect(screen.getByTestId("policy-hierarchy-slot-cluster")).toBeInTheDocument());
    expect(screen.getByTestId("policy-hierarchy-cluster")).toHaveTextContent("All clusters");
    mockApp.scopeCluster = "kind-nrvq";
  });

  // SEED-DURABNS-01 (user-reported): a pack-only namespace has a `__pack__` overlay row but NO agent-class
  // policy. The overlay is correctly excluded from the class picker (it's a LAYER), but that left the picker
  // empty and the hierarchy rendered nothing — hiding a pack that IS enforcing. The fix offers a namespace-wide
  // "*" view so the enforcing overlays still show.
  it("SEED-DURABNS-01: a pack-only namespace still shows its enforcing pack overlay (namespace-wide view)", async () => {
    const packLayers = [{ scope: "durab-ns:__pack__", label: "sector pack (overlay)", priority: 800, overlay: true }];
    server.use(
      // pack-only ns: /policies returns ONLY the __pack__ overlay row (no class policy)
      http.get("/api/v1/policies", () => HttpResponse.json([{ agent_class: "__pack__", target_type: "class" }])),
      // the ns-wide overlays resolve for ANY class (packs apply namespace-wide) — the fix queries with "*"
      http.get("/api/v1/policies/effective", () =>
        HttpResponse.json({ namespace: "durab-ns", agent_class: "*", layers: packLayers, note: "overlay layers are tighten-only" })),
      http.get("/api/v1/settings", () => HttpResponse.json({ enforcement_mode: "block", apply_mode: "enforce" }))
    );
    render(<PolicyHierarchy namespace="durab-ns" />);
    // the picker offers the namespace-wide view (NOT a dead-end empty "(no agent-class policies)")
    await waitFor(() =>
      expect(screen.getByRole("option", { name: /All classes · namespace overlays/i })).toBeInTheDocument());
    expect(screen.queryByRole("option", { name: /no agent-class policies/i })).toBeNull();
    // and the enforcing pack overlay actually RENDERS (the bug: the whole hierarchy was empty)
    await waitFor(() => expect(screen.getAllByTestId("policy-hierarchy-row").length).toBe(packLayers.length));
    expect(screen.getByTestId("policy-hierarchy-scope")).toHaveTextContent("durab-ns:__pack__");
    expect(screen.getByTestId("policy-hierarchy-overlay")).toHaveTextContent(/tighten-only/i);
  });
});
