// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors

/**
 * The Tools page — and specifically the properties that, if lost, put the old bug back.
 *
 * The fixture below mirrors what `scripts/kind-e2e/seed.py` actually puts on the kind cluster, so a
 * failure here and a failure in the browser suite describe the same defect rather than two unrelated
 * ones. Same tool names, same server ids, same awkward states.
 */

import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { BuilderGraph } from "../lib/builderGraph";
import { Tools, isFlagged } from "./Tools";
import { AppProvider } from "../store/AppContext";
import { ToastProvider } from "../components/common/Toast";
import { clearApiCache } from "../hooks/useApi";
import * as client from "../api/client";
import type { ToolRegistryEntry } from "../api/client";

/**
 * A stand-in for the Policy Catalog that reports the router STATE it was handed.
 *
 * `state` is a react-router prop, not an HTML attribute — it never reaches the DOM, so a test that
 * asserts `href` cannot observe the handoff payload at all. That is exactly how a `state` object
 * whose keys nothing read shipped here and stayed green. Reading it off the React fiber does not work
 * either: the anchor's props carry href/onClick, not `state`.
 *
 * So this FOLLOWS the link the way an operator does, and asserts on the location that results —
 * which is also the thing PolicyCatalog itself reads (`useLocation().state.builderGraph`).
 */
function CatalogProbe() {
  const loc = useLocation();
  return <pre data-testid="catalog-handoff-state">{JSON.stringify(loc.state ?? null)}</pre>;
}

function entry(over: Partial<ToolRegistryEntry> & { name: string }): ToolRegistryEntry {
  return {
    name_skeleton: over.name,
    source: "mcp_declared",
    namespace: "analytics",
    server_id: "slack",
    pin_status: "pinned",
    scan_severity: "none",
    description: null,
    description_withheld: false,
    input_schema: null,
    schema_available: false,
    last_seen_at: "2026-08-02T09:31:52.006119+00:00",
    ...over
  } as ToolRegistryEntry;
}

/** Byte-for-byte the seeder's `SEND_DM_SCHEMA` — all four schemaPaths outcomes in one object. */
const SEND_DM_SCHEMA = {
  type: "object",
  required: ["to"],
  properties: {
    to: { type: "string", description: "recipient email" },
    filters: { type: "object", properties: { customer: { type: "string" } } },
    retries: { type: "integer" },
    attachments: { type: "array", items: { type: "string" } }
  }
};

const FIXTURE: ToolRegistryEntry[] = [
  entry({ name: "send_dm", input_schema: SEND_DM_SCHEMA, schema_available: true, description: "Sends a direct message." }),
  entry({ name: "post_message", scan_severity: "critical", pin_status: "drift", description_withheld: true,
          input_schema: { type: "object", properties: { channel: { type: "string" } } }, schema_available: true }),
  entry({ name: "bulk_export", server_id: "warehouse", schema_available: false, input_schema: null }),
  entry({ name: "read_file", server_id: "filesystem", schema_available: true,
          input_schema: { type: "object", properties: { path: { type: "string" } } } }),
  entry({ name: "read_file", server_id: "runbooks", schema_available: true,
          input_schema: { type: "object", properties: { slug: { type: "string" } } } }),
  entry({ name: "http_get", source: "observed", server_id: null, pin_status: null, scan_severity: null,
          schema_available: false, input_schema: null, last_seen_at: null }),
  // Cyrillic 'е' — the skeleton the server computes folds it back to ASCII.
  entry({ name: "sеnd_email", name_skeleton: "send_email", source: "observed", server_id: null,
          pin_status: null, scan_severity: null, schema_available: false, input_schema: null, last_seen_at: null })
];

function renderTools(rows: ToolRegistryEntry[] = FIXTURE) {
  vi.spyOn(client, "fetchTools").mockResolvedValue(rows);
  return render(
    <MemoryRouter>
      <AppProvider>
        <ToastProvider>
          <Tools />
        </ToastProvider>
      </AppProvider>
    </MemoryRouter>
  );
}

/** As above, but with a real /policies/catalog route so the handoff can actually be followed. */
function renderToolsRouted(rows: ToolRegistryEntry[] = FIXTURE) {
  vi.spyOn(client, "fetchTools").mockResolvedValue(rows);
  return render(
    <MemoryRouter initialEntries={["/tools"]}>
      <AppProvider>
        <ToastProvider>
          <Routes>
            <Route path="/tools" element={<Tools />} />
            <Route path="/policies/catalog" element={<CatalogProbe />} />
          </Routes>
        </ToastProvider>
      </AppProvider>
    </MemoryRouter>
  );
}

describe("Tools page", () => {
  beforeEach(() => {
    clearApiCache();
    vi.restoreAllMocks();
  });

  it("keeps declared and observed in SEPARATE panels — never one table", async () => {
    // The acceptance criterion, and the whole reason the endpoint tags each row with its source. A
    // single sorted table invites reading the two tiers as equivalent, which is the bug that shipped.
    renderTools();
    const declared = await screen.findByTestId("tools-declared");
    const observed = screen.getByTestId("tools-observed");

    expect(within(declared).getByTestId("tool-row-slack-send_dm")).toBeInTheDocument();
    expect(within(declared).queryByTestId("tool-row-observed-http_get")).not.toBeInTheDocument();
    expect(within(observed).getByTestId("tool-row-observed-http_get")).toBeInTheDocument();
    expect(within(observed).queryByTestId("tool-row-slack-send_dm")).not.toBeInTheDocument();
  });

  it("answers 'can I scope this?' without a click", async () => {
    renderTools();
    await screen.findByTestId("tools-declared");
    expect(within(screen.getByTestId("tool-row-slack-send_dm")).getByText("Scopeable")).toBeInTheDocument();
    // Declared and pinned, yet unscopeable — the 8 KiB slice ate its schema. A distinct third state.
    expect(within(screen.getByTestId("tool-row-warehouse-bulk_export")).getByText("No schema")).toBeInTheDocument();
    expect(within(screen.getByTestId("tool-row-observed-http_get")).getByText("Name only")).toBeInTheDocument();
  });

  it("counts a homoglyph as flagged, not just a bad scan", async () => {
    // The tile answers "how many rows need a human?" A name that is not what it appears to be is
    // exactly such a row. Counting only scanner severity would flag it in the table and deny it in the
    // headline, which teaches operators to distrust the headline.
    expect(isFlagged(FIXTURE.find((t) => t.name === "post_message")!)).toBe(true);
    expect(isFlagged(FIXTURE.find((t) => t.name === "sеnd_email")!)).toBe(true);
    expect(isFlagged(FIXTURE.find((t) => t.name === "send_dm")!)).toBe(false);

    renderTools();
    await screen.findByTestId("tools-totals");
    // Scoped to its own tile: "Observed only" is also 2 here, so a bare getByText("2") is ambiguous and
    // would pass or fail for reasons unrelated to what this test is about.
    const flaggedTile = screen.getByText("Flagged").parentElement!;
    expect(within(flaggedTile).getByText("2")).toBeInTheDocument();
  });

  it("shows both rows when two servers serve one tool name, and says a policy governs both", async () => {
    // The API returns both; nothing merges them. A row keyed on tool_name alone breaks here.
    renderTools();
    await screen.findByTestId("tools-declared");
    expect(screen.getByTestId("tool-row-filesystem-read_file")).toBeInTheDocument();
    expect(screen.getByTestId("tool-row-runbooks-read_file")).toBeInTheDocument();
    expect(screen.getByTestId("tools-collision")).toHaveTextContent(/governs\s*both/i);
  });

  it("never renders a withheld description, and says why it is missing", async () => {
    // The stored definition holds the PRE-sanitize text — the payload the firewall kept from the model.
    const user = userEvent.setup();
    renderTools();
    await screen.findByTestId("tools-declared");
    await user.click(screen.getByTestId("tool-row-slack-post_message"));
    const detail = await screen.findByTestId("tool-detail");
    expect(detail).toHaveTextContent(/Description withheld/i);
    expect(detail).not.toHaveTextContent(/always call before replying/i);
  });

  it("opens the argument tree for a scopeable tool, unusable arguments included", async () => {
    const user = userEvent.setup();
    renderTools();
    await screen.findByTestId("tools-declared");
    await user.click(screen.getByTestId("tool-row-slack-send_dm"));

    await screen.findByTestId("argument-tree");
    expect(screen.getByTestId("argument-row-to")).toBeInTheDocument();
    expect(screen.getByTestId("argument-row-filters.customer")).toBeInTheDocument();
    expect(screen.getByTestId("argument-row-retries")).toHaveTextContent(/only text does/i);
    expect(screen.getByTestId("argument-row-attachments")).toHaveTextContent(/indexed at runtime/i);
  });

  it("offers the reverse handoff into the builder, carrying the tool", async () => {
    // The other direction of the P1 fix: arrive at a tool, leave with a policy that narrows it, rather
    // than discovering scoping by accident inside the builder.
    //
    // ASSERT THE PAYLOAD, NOT THE href. This test used to check only
    // `toHaveAttribute("href", "/policies/catalog")`, which is structurally incapable of observing the
    // handoff: the whole BuilderGraph travels in react-router STATE and never appears in the anchor's
    // href. That is exactly how the previous `state={{ scopeTool, fromTools }}` — keys nothing read —
    // shipped and stayed green. PolicyCatalog fails silently on a bad payload
    // (`?.builderGraph ?? null` then `if (!handoffGraph) return;`), so the operator just gets the raw
    // editor. The e2e sibling was blind the same way and has been rewritten too.
    const user = userEvent.setup();
    renderToolsRouted();
    await screen.findByTestId("tools-declared");
    await user.click(screen.getByTestId("tool-row-slack-send_dm"));

    const cta = await screen.findByTestId("tool-detail-scope-cta");
    expect(cta).toHaveAttribute("href", "/policies/catalog");
    await user.click(cta);

    // Arrived — and carrying the payload PolicyCatalog actually reads.
    const state = JSON.parse((await screen.findByTestId("catalog-handoff-state")).textContent ?? "null");
    const graph = state?.builderGraph as BuilderGraph | undefined;
    expect(graph, "the handoff must carry a builderGraph — the key PolicyCatalog reads").toBeDefined();
    expect(graph!.mode).toBe("allowlist"); // a grant only exists under deny-by-default
    expect(graph!.allowlist?.tools).toEqual(["send_dm"]);
    // The class is deliberately blank: a tool is not owned by one, and inventing it would target an
    // agent that may not exist. The builder gates Save on it in words.
    expect(graph!.scope).toEqual({ kind: "class", agentClass: "" });
  });

  it("explains what an observed tool costs you, specifically", async () => {
    const user = userEvent.setup();
    renderTools();
    await screen.findByTestId("tools-observed");
    expect(screen.getByTestId("tool-row-observed-http_get")).toHaveTextContent(/Destination hosts cannot be restricted/i);
    await user.click(screen.getByTestId("tool-row-observed-http_get"));
    expect(await screen.findByTestId("tool-detail")).toHaveTextContent(/per-argument scoping does not/i);
  });

  it("distinguishes a failed read from an empty registry", async () => {
    // "We could not check" must never render as "there is nothing here". An operator reading absence as
    // an all-clear concludes a namespace has no tools when in fact nothing was asked.
    vi.spyOn(client, "fetchTools").mockRejectedValue(new Error("503 · pin store unreachable"));
    render(
      <MemoryRouter><AppProvider><ToastProvider><Tools /></ToastProvider></AppProvider></MemoryRouter>
    );
    const err = await screen.findByTestId("tools-error");
    expect(err).toHaveTextContent(/not the same as .there are none./i);
    expect(screen.queryByTestId("tools-declared")).not.toBeInTheDocument();
  });

  it("teaches how to populate both tiers when the registry is genuinely empty", async () => {
    renderTools([]);
    await waitFor(() => expect(screen.getByTestId("tools-declared-empty")).toBeInTheDocument());
    expect(screen.getByTestId("tool-detail-empty")).toHaveTextContent(/they are not equivalent/i);
    // Deny-by-default means you can write the rule before the tool ever appears.
    expect(screen.getByTestId("tool-detail-empty")).toHaveTextContent(/a policy can name a tool nobody has called/i);
  });

  it("offers only the windows the API accepts", async () => {
    // The global header selector offers 1h/6h, which this endpoint cannot serve — honouring them would
    // mean silently widening a window the operator asked to narrow.
    renderTools();
    const range = await screen.findByTestId("tools-range");
    expect(within(range).getByText("24h")).toBeInTheDocument();
    expect(within(range).getByText("90d")).toBeInTheDocument();
    expect(within(range).queryByText("1h")).not.toBeInTheDocument();
    expect(within(range).queryByText("6h")).not.toBeInTheDocument();
  });

  it("refetches when the window changes", async () => {
    const user = userEvent.setup();
    renderTools();
    await screen.findByTestId("tools-declared");
    const spy = vi.mocked(client.fetchTools);
    spy.mockClear();
    await user.click(within(screen.getByTestId("tools-range")).getByText("7d"));
    await waitFor(() => expect(spy).toHaveBeenCalledWith(expect.anything(), "7d"));
  });
});
