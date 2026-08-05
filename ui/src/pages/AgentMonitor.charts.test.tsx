// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// The per-agent drill-down charts, asserted on the ECharts OPTION rather than on pixels — the series
// names, the values and the axis are the whole claim these panels make, and none of them reach the
// DOM. A separate file from AgentMonitor.test.tsx because it stubs the chart interop point, and that
// file's first test is a #130 guard that wants the real one.
//
// TWO DEFECTS, ONE SCREEN:
//
//  1. A panel titled "Trust History · 24h" plotted ALLOW and BLOCK COUNTS under the legend labels
//     ["Trust", "Risk"], discarding the `trust_score` the same payload carries. An agent that merely
//     got busier showed "Trust" climbing 40 → 120 on the very day its real average trust fell
//     0.90 → 0.42 — contradicting the "Current trust 0.42" row in the panel beside it, on the same
//     screen, while an operator decided whether to freeze it.
//
//  2. "Tool Usage" labelled its bars "100%" and "50%" for 10 and 5 calls — a share of the busiest
//     tool — under a caption reading "bar length = call volume". Percentages that sum to 150, with
//     the real counts nowhere on screen to contradict the reading that read_file is all of this
//     agent's traffic (it is 67%).

import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { MemoryRouter } from "react-router-dom";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

const captured = vi.hoisted(() => [] as Array<Record<string, unknown>>);
// The option is recorded for the value assertions, AND a marker node is rendered so a test can ask
// the separate question "is a chart on screen RIGHT NOW". `captured` accumulates across the whole
// render lifecycle — a chart drawn during the loading pass and then replaced by an error state is
// still in it — so it cannot answer that one.
vi.mock("../components/common/EChart", () => ({
  default: ({ option }: { option: Record<string, unknown> }) => {
    captured.push(option);
    const series = (option.series as Array<{ type?: string }> | undefined) ?? [];
    const kind =
      series.length === 2 && series[0]?.type === "line"
        ? "volume"
        : series.length === 1 && series[0]?.type === "bar"
          ? "bars"
          : "other";
    return <div data-testid={`echart-${kind}`} />;
  }
}));

import { AgentMonitor } from "./AgentMonitor";
import { AppProvider } from "../store/AppContext";
import { clearApiCache } from "../hooks/useApi";

const AGENT = {
  spiffe_id: "spiffe://norviq/ns/default/sa/deploy-bot",
  namespace: "default",
  agent_class: "deploy-bot",
  last_seen: new Date().toISOString(),
  score: 0.42,
  category: "low",
  violation_count: 3,
  signals: {},
  dominant_signal: "",
  recommendation: "review"
};

/** The exact `TrustHistoryPoint` shape client.ts declares and agents.py returns. */
type HistoryPoint = { time: string; allow: number; block: number; trust_score: number | null };
type UsageRow = { tool: string; count: number; blocked: number; risk: string };

const HISTORY: HistoryPoint[] = [
  { time: "2026-08-03", allow: 40, block: 1, trust_score: 0.9 },
  { time: "2026-08-04", allow: 120, block: 9, trust_score: 0.42 }
];

/** The exact shape `/agents/{id}/tool-usage` returns. */
const USAGE: UsageRow[] = [
  { tool: "read_file", count: 10, blocked: 0, risk: "low" },
  { tool: "send_email", count: 5, blocked: 2, risk: "high" }
];

const server = setupServer();
beforeAll(() => server.listen({ onUnhandledRequest: "bypass" }));
afterEach(() => {
  server.resetHandlers();
  clearApiCache();
});
afterAll(() => server.close());

beforeEach(() => {
  captured.length = 0;
});

function serve(history: HistoryPoint[] | "error" = HISTORY, usage: UsageRow[] = USAGE) {
  server.use(
    http.get("/api/v1/agents", () => HttpResponse.json([AGENT])),
    http.get("*/trust-history", () =>
      history === "error" ? new HttpResponse(null, { status: 503 }) : HttpResponse.json(history)
    ),
    http.get("*/tool-usage", () => HttpResponse.json(usage))
  );
}

/** Mount and open the drill-down for the single agent. */
async function openAgent() {
  render(
    <MemoryRouter>
      <AppProvider>
        <AgentMonitor />
      </AppProvider>
    </MemoryRouter>
  );
  const cell = await screen.findByText("deploy-bot");
  fireEvent.click(cell.closest("tr")!);
}

/** The last option whose series look like the two-line volume chart. */
function volumeOption() {
  return [...captured].reverse().find((o) => {
    const s = o.series as Array<{ type?: string }> | undefined;
    return Array.isArray(s) && s.length === 2 && s[0]?.type === "line";
  });
}

/** The last option whose series look like the horizontal category bars. */
function barsOption() {
  return [...captured].reverse().find((o) => {
    const s = o.series as Array<{ type?: string }> | undefined;
    return Array.isArray(s) && s.length === 1 && s[0]?.type === "bar";
  });
}

describe("the trust panel plots trust, not decision counts", () => {
  it("never labels a call count 'Trust'", async () => {
    serve();
    await openAgent();

    await waitFor(() => expect(volumeOption()).toBeDefined());
    const series = volumeOption()!.series as Array<{ name: string; data: number[] }>;
    // The counts are still plotted — under the names they actually are.
    expect(series.map((s) => s.name)).toEqual(["Allowed", "Blocked"]);
    expect(series[0].data).toEqual([40, 120]);
    expect(series[1].data).toEqual([1, 9]);
    // And no panel claims those counts are a trust history.
    expect(screen.queryByText(/Trust History/i)).toBeNull();
    expect(screen.getByText(/Decision volume/i)).toBeInTheDocument();
  });

  it("plots the trust_score the payload carries, which used to be dropped on the floor", async () => {
    serve();
    await openAgent();

    const panel = await screen.findByTestId("agent-trust-history");
    // 0.90 → 0.42: falling, on the day the discarded series showed "Trust" climbing 40 → 120.
    const trend = await screen.findByTestId("agent-trust-trend");
    expect(trend).toHaveTextContent("0.90");
    expect(trend).toHaveTextContent("0.42");
    expect(panel).toHaveTextContent(/2 measured buckets/i);
  });

  it("draws an unmeasured bucket as a break, never as a trust of zero", async () => {
    // `trust_score` is null when no decision in the bucket carried one. On a 0–1 axis a plotted zero
    // is the worst score there is and reads as an agent that collapsed.
    serve([
      { time: "2026-08-03", allow: 40, block: 1, trust_score: 0.9 },
      { time: "2026-08-04", allow: 5, block: 0, trust_score: null },
      { time: "2026-08-05", allow: 120, block: 9, trust_score: 0.88 }
    ]);
    await openAgent();

    const gaps = await screen.findByTestId("agent-trust-gaps");
    expect(gaps).toHaveTextContent(/1 bucket recorded no trust score/i);
    expect(gaps).toHaveTextContent(/not as zero/i);
    // Two runs of contiguous measured buckets → the line is genuinely broken, not bridged.
    expect(screen.getByTestId("agent-trust-history").querySelectorAll("polyline, circle")).toHaveLength(2);
  });

  it("says a failed read is a failed read, not a flat score", async () => {
    serve("error");
    await openAgent();
    const panel = await screen.findByTestId("agent-trust-history");
    await waitFor(() => expect(panel).toHaveTextContent(/Couldn’t read this agent’s trust history/i));
    expect(panel).toHaveTextContent(/nothing was measured/i);
    expect(panel.querySelector("polyline")).toBeNull();
  });
});

describe("Tool Usage says what its bars measure", () => {
  it("puts the raw call count on screen and captions the bar as a share of the busiest tool", async () => {
    serve();
    await openAgent();

    await waitFor(() => expect(barsOption()).toBeDefined());
    const opt = barsOption()!;
    const categories = (opt.yAxis as { data: string[] }).data;
    // REWRITTEN (adversarial pass). The first fix put the count INSIDE the category label
    // (`read_file · 10 calls`). That is a product-authored measurement concatenated into an
    // attacker-controlled string — see the `forges a call count` test below — so the axis carries the
    // bare name and the counts are printed beside it, in their own elements.
    expect(categories).toEqual(["read_file", "send_email"]);

    // The counts the "100% / 50%" labels used to hide. 10 and 5, not 100 and 50.
    const counts = screen.getByTestId("agent-tool-call-counts");
    expect(counts).toHaveTextContent(/read_file\s*10 calls/);
    expect(counts).toHaveTextContent(/send_email\s*5 calls/);

    // The caption must not claim the bar length is call volume — it is a share of the busiest tool,
    // which is why the two bars read 100% and 50% for 10 and 5 calls.
    const usage = screen.getByText(/colour = tool risk tier/i);
    expect(usage).toHaveTextContent(/share of the busiest tool/i);
    expect(usage.textContent ?? "").not.toMatch(/bar length = call volume/i);
  });

  it("singularises a one-call tool", async () => {
    serve(HISTORY, [{ tool: "shell_exec", count: 1, blocked: 1, risk: "critical" }]);
    await openAgent();
    await waitFor(() => expect(barsOption()).toBeDefined());
    expect((barsOption()!.yAxis as { data: string[] }).data).toEqual(["shell_exec"]);
    expect(await screen.findByTestId("agent-tool-call-counts")).toHaveTextContent(/shell_exec\s*1 call\b/);
  });

  it("never lets a tool NAME forge a call count in the console's own voice", async () => {
    // `tool` is whatever an MCP server called its tool. Folding the count into the same text node
    // made `read_file · 4000 calls` render as `read_file · 4000 calls · 2 calls` — one undifferentiated
    // ECharts axis label (and the same string verbatim in the tooltip), in which a number this console
    // never computed is indistinguishable from one it did. The name may appear; a count it did not
    // measure may not appear as though it did.
    serve(HISTORY, [
      { tool: "read_file · 4000 calls", count: 2, blocked: 0, risk: "low" },
      { tool: "send_email", count: 1, blocked: 0, risk: "high" }
    ]);
    await openAgent();
    await waitFor(() => expect(barsOption()).toBeDefined());

    const categories = (barsOption()!.yAxis as { data: string[] }).data;
    // The name is rendered exactly as served — never appended to. Under the concatenating version
    // this read `read_file · 4000 calls · 2 calls`, in which "4000 calls" is indistinguishable from
    // the console's own "2 calls".
    expect(categories).toEqual(["read_file · 4000 calls", "send_email"]);

    // And the counts the console DID measure sit in their own elements, not spliced into the name.
    const counts = screen.getByTestId("agent-tool-call-counts");
    expect(counts).toHaveTextContent(/2 calls/);
    expect(counts).toHaveTextContent(/1 call\b/);
  });

  it("says a failed tool-usage read is a failed read, not an agent that called nothing", async () => {
    // CategoryBars has no error state: handed `[]` it draws a complete, empty chart — the picture of
    // "measured, and this agent touched no tool", which is the reading that argues against freezing it.
    server.use(
      http.get("/api/v1/agents", () => HttpResponse.json([AGENT])),
      http.get("*/trust-history", () => HttpResponse.json(HISTORY)),
      http.get("*/tool-usage", () => new HttpResponse(null, { status: 503 }))
    );
    await openAgent();

    const panel = await screen.findByTestId("agent-tool-usage-error");
    expect(panel).toHaveTextContent(/Couldn’t read this agent’s tool usage/i);
    expect(panel).toHaveTextContent(/would read as “measured, and there was no activity”/i);
    // No bar chart is drawn from a read that failed.
    expect(screen.queryByTestId("echart-bars")).toBeNull();
    expect(screen.queryByTestId("agent-tool-call-counts")).toBeNull();
  });

  it("distinguishes a genuinely idle agent from an unreadable one", async () => {
    // The other half. An empty 200 IS an observation, and it must be stated rather than drawn as a
    // blank chart that could equally mean the read failed.
    serve(HISTORY, []);
    await openAgent();
    const panel = await screen.findByTestId("agent-tool-usage");
    await waitFor(() => expect(panel).toHaveTextContent(/No tool call by this agent was recorded/i));
    expect(screen.queryByTestId("agent-tool-usage-error")).toBeNull();
  });
});

describe("one failed request may not render as an error beside a drawn chart", () => {
  it("does not draw a Decision volume chart from the read that just failed", async () => {
    // `Decision volume` and `Trust` are fed by ONE request. Splitting the old panel in two left the
    // volume half error-blind, so a 503 rendered "Couldn’t read this agent’s trust history" next to a
    // complete, empty allow/block chart — the console contradicting itself about a single fetch, with
    // the chart (the thing an operator reads first) saying the agent was quiet.
    serve("error");
    await openAgent();

    const panel = await screen.findByTestId("agent-decision-volume-error");
    expect(panel).toHaveTextContent(/Couldn’t read this agent’s decision volume/i);
    // Its sibling from the SAME request says the same thing…
    expect(screen.getByTestId("agent-trust-history")).toHaveTextContent(/Couldn’t read/i);
    // …and the empty two-series line chart is gone from the screen, not merely relabelled.
    expect(screen.queryByTestId("echart-volume")).toBeNull();
    expect(panel).toHaveTextContent(/Decision volume · 24h/); // the panel keeps its title and its slot
  });
});
