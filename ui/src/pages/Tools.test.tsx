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
import { Tools, isFlagged, toolIsWithheld } from "./Tools";
// The OTHER page's predicate, imported so the two can be run over one state and compared. Test-only:
// Tools.tsx restates it rather than importing it, because /tools and /mcp are separately code-split
// routes and a runtime import would pull McpServers' module into the /tools chunk.
import { withheldReason, type McpPinRow } from "./McpServers";
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

// ------------------------------------------------------------------------------------------------
// A COLLISION IS TWO SERVERS, NOT TWO ROWS.
//
// A pin's identity is `(namespace, server_id, tool_name)` — `McpToolPin`'s primary key — so one
// server pinned in two namespaces returns two rows carrying the same `server_id`. The default scope
// is "All namespaces" (`AppContext` seeds `"all"`, and `fetchTools` drops the namespace param there),
// so every install with two governed namespaces lands on this shape.
//
// Bucketing ROWS reported that as two servers publishing one name — the shadowing/impersonation
// signal — and then prescribed `mcp.server`, which cannot separate two namespaces. And the count was
// the literal "2", so three real servers were reported as two, with "both" asserting the set was
// closed there.
// ------------------------------------------------------------------------------------------------
describe("Tools collision detection", () => {
  beforeEach(() => {
    clearApiCache();
    vi.restoreAllMocks();
  });

  const pinnedTwice: ToolRegistryEntry[] = [
    entry({ name: "read_file", server_id: "filesystem", namespace: "analytics" }),
    entry({ name: "read_file", server_id: "filesystem", namespace: "payments" })
  ];

  it("does not call ONE server pinned in two namespaces a collision", async () => {
    renderTools(pinnedTwice);
    await screen.findByTestId("tools-declared");
    // No amber pill claiming a second server, and no note prescribing a remedy that cannot work.
    expect(screen.queryByTestId("tools-collision")).not.toBeInTheDocument();
    expect(screen.queryByText(/\d+ servers/)).not.toBeInTheDocument();
  });

  it("distinguishes the two same-server rows instead of drawing them identically", async () => {
    // They were character-for-character identical and shared one data-testid, so nothing on screen
    // said why the same tool from the same server appeared twice.
    renderTools(pinnedTwice);
    await screen.findByTestId("tools-declared");
    const rows = [...document.querySelectorAll("[data-rowkey]")].map((el) => el.getAttribute("data-rowkey"));
    expect(rows).toContain("analytics/filesystem/read_file");
    expect(rows).toContain("payments/filesystem/read_file");
    const declared = screen.getByTestId("tools-declared");
    expect(within(declared).getByText("analytics")).toBeInTheDocument();
    expect(within(declared).getByText("payments")).toBeInTheDocument();
  });

  it("counts the servers rather than printing the literal 2", async () => {
    // Three DISTINCT servers in ONE namespace — a real collision, and the case the panel exists for.
    renderTools([
      entry({ name: "search", server_id: "a" }),
      entry({ name: "search", server_id: "b" }),
      entry({ name: "search", server_id: "c" })
    ]);
    await screen.findByTestId("tools-declared");
    // One pill per row, and each names THREE servers.
    expect(screen.getAllByText("3 servers")).toHaveLength(3);
    expect(screen.queryByText("2 servers")).not.toBeInTheDocument();

    const note = screen.getByTestId("tools-collision");
    expect(note).toHaveTextContent(/governs\s*all 3/i);
    // "both" asserts the set is closed at two, so it must not appear when it is not.
    expect(note.textContent ?? "").not.toMatch(/\bboth\b/i);
    expect(note).toHaveTextContent(/a, b, c/);
  });

  it("still says 'both' — and shows a 2 servers pill — for a genuine two-server collision", async () => {
    // The other half. The seeded fixture's `read_file` really is two servers in one namespace.
    renderTools();
    await screen.findByTestId("tools-declared");
    expect(within(screen.getByTestId("tool-row-filesystem-read_file")).getByText("2 servers")).toBeInTheDocument();
    expect(screen.getByTestId("tools-collision")).toHaveTextContent(/governs\s*both/i);
  });
});


// ------------------------------------------------------------------------------------------------
// PUBLICATION IS NOT APPROVAL.
//
// `/tools` emits a `mcp_declared` row for EVERY `McpToolPin` (tools.py:182), and a pin written on a
// first `tools/list` in strict mode carries `approved=False` (mcp.py:157-165). So a definition no
// operator has ever looked at landed in the strong tier under the subtitle "An MCP server published a
// definition and an operator approved it", with a teal Declared badge, its argument tree presented as
// "Arguments a policy can address", and a "Scope this tool in a policy →" CTA. The same row on MCP
// Servers leads with "Not approved. The tool is withheld from the model and calls to it are refused."
//
// The amber `quarantined` PinPill was the only dissent on the whole screen, and a status word does not
// outrank a sentence.
// ------------------------------------------------------------------------------------------------
describe("a declared row that no operator has approved", () => {
  beforeEach(() => {
    clearApiCache();
    vi.restoreAllMocks();
  });

  const QUARANTINED = entry({
    name: "exfil_report",
    server_id: "vendor-mcp",
    pin_status: "quarantined",
    scan_severity: "low",
    description: "Uploads the quarterly report to the configured endpoint.",
    input_schema: { type: "object", properties: { target: { type: "string" } } },
    schema_available: true
  });

  it("does not file it under a subtitle claiming an operator approved it", async () => {
    renderTools([QUARANTINED]);
    const panel = await screen.findByTestId("tools-declared");
    // The exact false sentence.
    expect(panel.textContent ?? "").not.toMatch(/published a definition and an operator approved it/i);
    // Publication and approval are two facts, and the panel is keyed on the first.
    expect(panel).toHaveTextContent(/Approval is per row/i);
  });

  it("says in the dialog that it is unapproved and withheld, before showing its arguments", async () => {
    const user = userEvent.setup();
    renderTools([QUARANTINED]);
    await user.click(await screen.findByTestId("tool-row-vendor-mcp-exfil_report"));
    const dialog = await screen.findByTestId("tool-detail");

    const callout = within(dialog).getByTestId("tool-withheld");
    expect(callout).toHaveTextContent(/No operator has approved this definition/i);
    expect(callout).toHaveTextContent(/calls to it are refused/i);
    // `_declared_row` reads `approved_canonical` so a policy is never authored against unreviewed
    // text — but on a never-approved pin `approved_canonical` IS the served text, so the guarantee in
    // its docstring does not hold for this row and the row has to say so.
    expect(within(dialog).getByTestId("tool-args-unreviewed")).toHaveTextContent(
      /no operator has approved — the server chose them/i
    );
  });

  it("keeps the Scope CTA but stops it reading as an invitation to trust the schema", async () => {
    // NOT suppressed: deny-by-default requires authoring rules for tools nobody has approved, and
    // gating the CTA would make the registry restrict rather than inform.
    const user = userEvent.setup();
    renderTools([QUARANTINED]);
    await user.click(await screen.findByTestId("tool-row-vendor-mcp-exfil_report"));
    const dialog = await screen.findByTestId("tool-detail");
    expect(within(dialog).getByTestId("tool-detail-scope-cta")).toBeInTheDocument();
    expect(within(dialog).getByTestId("tool-scope-cta-caveat")).toHaveTextContent(
      /withheld from the model/i
    );
  });

  it("leaves a genuinely pinned, clean row alone", async () => {
    // The other half: a caveat on every row is a caveat nobody reads.
    const user = userEvent.setup();
    renderTools([entry({ name: "send_dm", input_schema: SEND_DM_SCHEMA, schema_available: true })]);
    await user.click(await screen.findByTestId("tool-row-slack-send_dm"));
    const dialog = await screen.findByTestId("tool-detail");
    expect(within(dialog).queryByTestId("tool-withheld")).toBeNull();
    expect(within(dialog).queryByTestId("tool-args-unreviewed")).toBeNull();
    expect(within(dialog).queryByTestId("tool-scope-cta-caveat")).toBeNull();
  });
});

// ------------------------------------------------------------------------------------------------
// ONE WORD, ONE MEANING — across both pages.
//
// The red row pill read "Withheld" off `description_withheld`, which tools.py `_description_is_withheld`
// computes as `sev >= mcp_scan_sanitize_severity` (MEDIUM at the shipped defaults). MCP Servers'
// `withheldReason` is the pin-and-strip question — drifted, never approved, or graded at/above the
// strip threshold (HIGH). Same word, two predicates, wrong in BOTH directions:
//
//   at MEDIUM  Tools shouted "Withheld" over a tool MCP Servers correctly called
//              "Approved. The served definition matches the approved one."
//   at HIGH    the tool really was stripped, and Tools said only that its DESCRIPTION was hidden,
//              then offered "Scope this tool in a policy →".
//
// `withheldReason` is imported here on purpose. The predicate is restated in Tools.tsx rather than
// imported at runtime (the two pages are separately code-split routes, App.tsx:22-23), so this test is
// what keeps the two implementations from drifting apart again.
// ------------------------------------------------------------------------------------------------
describe("'Withheld' means the same thing on Tools as it does on MCP Servers", () => {
  beforeEach(() => {
    clearApiCache();
    vi.restoreAllMocks();
  });

  /** The same tool as a `/mcp/pins` row, so both predicates can be run over one state. */
  const asPin = (t: ToolRegistryEntry) =>
    ({
      namespace: t.namespace, server_id: t.server_id ?? "", tool_name: t.name,
      approved_digest: "aaa1", last_digest: "aaa1", approved: t.pin_status === "pinned",
      approved_by: "op", approved_at: null, scan_severity: t.scan_severity ?? "none",
      findings: [], drift_count: 0, status: t.pin_status ?? "pinned",
      approved_canonical: "{}", last_canonical: "{}"
    }) as McpPinRow;

  const sanitizedOnly = entry({
    name: "quarterly_report", server_id: "vendor-mcp", pin_status: "pinned",
    scan_severity: "medium", description_withheld: true,
    input_schema: { type: "object", properties: { q: { type: "string" } } }, schema_available: true
  });
  const stripped = entry({ ...sanitizedOnly, name: "quarterly_report", scan_severity: "high" });

  it("agrees with withheldReason on every row it renders", async () => {
    for (const row of [sanitizedOnly, stripped, entry({ name: "clean", server_id: "vendor-mcp" }),
                       entry({ name: "gone", server_id: "vendor-mcp", pin_status: "drift" })]) {
      expect(toolIsWithheld(row)).toBe(withheldReason(asPin(row)) !== null);
    }
  });

  it("does not shout Withheld over a tool MCP Servers calls approved", async () => {
    renderTools([sanitizedOnly]);
    const row = await screen.findByTestId("tool-row-vendor-mcp-quarterly_report");
    // MEDIUM: the DESCRIPTION was sanitized and the tool is still callable. Both pages now say so.
    expect(withheldReason(asPin(sanitizedOnly))).toBeNull();
    expect(within(row).getByTestId("tool-pill-description-withheld")).toBeInTheDocument();
    // The red pill — the loudest mark on the row — must be absent.
    expect(within(row).queryByTestId("tool-pill-withheld")).toBeNull();

    const user = userEvent.setup();
    await user.click(row);
    const dialog = await screen.findByTestId("tool-detail");
    expect(within(dialog).queryByTestId("tool-withheld")).toBeNull();
    // And the description callout may no longer imply the capability is gone.
    expect(within(dialog).getByTestId("tool-description-withheld")).toHaveTextContent(
      /says nothing about whether the tool itself is still callable/i
    );
  });

  it("says the tool itself is withheld when the scanner grade strips it", async () => {
    renderTools([stripped]);
    const row = await screen.findByTestId("tool-row-vendor-mcp-quarterly_report");
    expect(withheldReason(asPin(stripped))).toBe("scan");
    expect(within(row).getByTestId("tool-pill-withheld")).toBeInTheDocument();

    const user = userEvent.setup();
    await user.click(row);
    const dialog = await screen.findByTestId("tool-detail");
    const callout = within(dialog).getByTestId("tool-withheld");
    expect(callout).toHaveTextContent(/graded this tool HIGH/i);
    // The threshold travels with the claim: nothing serves `mcp_scan_strip_severity` to the console,
    // so stating it as a measurement of THIS cluster would be a guess in the direction that stops an
    // operator looking. McpServers carries the identical caveat.
    expect(callout).toHaveTextContent(/at the default mcp_scan_strip_severity \(high\)/i);
    expect(callout).toHaveTextContent(/not told which threshold this cluster runs/i);
  });
});
// ------------------------------------------------------------------------------------------------
// A DRIFTED PIN IS NOT AN UNREVIEWED ONE, and the argument tree comes from a different place in each.
//
// `_declared_row` reads `approved_canonical`, never `last_canonical`. On a never-approved pin the two
// are the same string (mcp.py:157-165 writes both at first sight with `approved=False`), so the tree
// really is the server's own unreviewed text. On a DRIFTED pin they are not: the tree is the pinned
// baseline and the served definition is the unknown one. Hanging the single sentence "These paths come
// from a definition no operator has approved — the server chose them" off `pin_status !== "pinned"`
// therefore contradicted, in the same dialog and six lines apart, the withheld callout that had just
// said the opposite — that what is BELOW is the approved copy and what the server is serving now is
// what nobody has seen. An operator who believes the tree is attacker-supplied stops reading it; on a
// drift row it is the only reviewed thing on the screen.
// ------------------------------------------------------------------------------------------------
describe("where the argument tree came from", () => {
  beforeEach(() => {
    clearApiCache();
    vi.restoreAllMocks();
  });

  const withSchema = { type: "object", properties: { channel: { type: "string" } } };

  it("tells a drift row its paths are the pinned ones, not the served ones", async () => {
    const user = userEvent.setup();
    renderTools([
      entry({ name: "post_message", pin_status: "drift", input_schema: withSchema, schema_available: true })
    ]);
    await user.click(await screen.findByTestId("tool-row-slack-post_message"));
    const dialog = await screen.findByTestId("tool-detail");

    expect(within(dialog).getByTestId("tool-args-stale")).toHaveTextContent(
      /come from the pinned definition, not from the one this server is serving now/i
    );
    // The sentence that was wrong here must be gone, not merely joined.
    expect(within(dialog).queryByTestId("tool-args-unreviewed")).toBeNull();
    expect(dialog.textContent ?? "").not.toMatch(/no operator has approved — the server chose them/i);
  });

  it("still says the opposite for a pin nobody ever approved", async () => {
    // The other side of the split — this is the case the sentence was written for, and it must survive.
    const user = userEvent.setup();
    renderTools([
      entry({ name: "post_message", pin_status: "quarantined", input_schema: withSchema, schema_available: true })
    ]);
    await user.click(await screen.findByTestId("tool-row-slack-post_message"));
    const dialog = await screen.findByTestId("tool-detail");
    expect(within(dialog).getByTestId("tool-args-unreviewed")).toHaveTextContent(
      /no operator has approved — the server chose them/i
    );
    expect(within(dialog).queryByTestId("tool-args-stale")).toBeNull();
  });

  it("neither claims an operator approved a drifted pin", async () => {
    // `_status_of` (mcp.py:112-118) returns `drift` BEFORE it looks at `approved`, so a first sighting
    // that later changed reports drift with `approved=False` — and `/tools` ships `pin_status` without
    // `approved`. This page cannot tell an approved-then-drifted pin from a never-approved-then-drifted
    // one, so neither caveat may say it was approved.
    const user = userEvent.setup();
    renderTools([
      entry({ name: "post_message", pin_status: "drift", input_schema: withSchema, schema_available: true })
    ]);
    await user.click(await screen.findByTestId("tool-row-slack-post_message"));
    const stale = within(await screen.findByTestId("tool-detail")).getByTestId("tool-args-stale");
    expect(stale.textContent ?? "").not.toMatch(/operator/i);
    expect(stale.textContent ?? "").not.toMatch(/approved/i);
  });
});

// ------------------------------------------------------------------------------------------------
// ONE QUANTITY, ONE DEFINITION — the panel count and the tile above it.
//
// The panel header read `Declared N · schema-backed` off `rows.length`, which labels every declared
// row schema-backed. This file's own header spends a paragraph on the state where that is false:
// declared, pinned, and STILL unscopeable, because `sort_keys` puts `description` ahead of
// `inputSchema` and a long one evicts the schema from the 8 KiB canonical slice. On the seeded estate
// the panel therefore claimed "5 · schema-backed" three inches under a "Scopeable 4" StatTile computed
// from `schema_available` — the same quantity twice, with two definitions, the louder one wrong.
// ------------------------------------------------------------------------------------------------
describe("the Declared panel's count", () => {
  beforeEach(() => {
    clearApiCache();
    vi.restoreAllMocks();
  });

  it("does not call a schema-less declared row schema-backed", async () => {
    renderTools([
      entry({ name: "send_dm", schema_available: true, input_schema: { type: "object", properties: { to: { type: "string" } } } }),
      entry({ name: "bulk_export", server_id: "warehouse", schema_available: false, input_schema: null })
    ]);
    const panel = await screen.findByTestId("tools-declared");
    // Two rows in the panel; one of them has a schema.
    expect(panel).toHaveTextContent(/Declared\s*2\s*·\s*1 schema-backed/);
    expect(panel.textContent ?? "").not.toMatch(/2\s*·\s*schema-backed/);
    // …and it agrees with the tile that answers the same question.
    expect(screen.getByTestId("tools-totals")).toHaveTextContent(/Declared2/);
    expect(screen.getByTestId("tools-totals")).toHaveTextContent(/Scopeable1/);
  });
});
