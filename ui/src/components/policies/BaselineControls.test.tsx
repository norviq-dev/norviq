// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors

/**
 * Baseline controls — the surface where a customer turns a shipped detector into an enforced block.
 *
 * The assertions here are mostly about the two ways this screen could lie: showing "nothing is
 * enforcing" when it simply could not READ the controls, and sending a partial map on save (the
 * endpoint replaces a namespace's set wholesale, so a partial body silently resets every control the
 * operator did not touch).
 */

import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { BaselineControls } from "./BaselineControls";
import * as client from "../../api/client";
import { clearApiCache } from "../../hooks/useApi";
import { AppProvider } from "../../store/AppContext";

/** `useMutationScope` reads the app-wide namespace scope, so the component needs the real provider —
 *  a stub would let a scope-gating regression through, which is the thing that hook exists to stop.
 *
 *  The route carries `?ns=`, which is the first rule in AppContext's namespace precedence. Without it
 *  the provider resolves to the "all" aggregate and every control renders disabled — correctly, since
 *  a namespace-scoped write must never target the phantom aggregate scope. `test_aggregate_scope_...`
 *  below asserts that refusal on purpose. */
function renderPanel(props: { namespace: string; isAdmin: boolean }, scope = "chatbot-prod") {
  return render(
    <MemoryRouter initialEntries={[`/policies/targets?ns=${scope}`]}>
      <AppProvider>
        <BaselineControls {...props} />
      </AppProvider>
    </MemoryRouter>,
  );
}

const CONTROLS = {
  namespace: "chatbot-prod",
  preset: "strict",
  default_effect: "monitor" as const,
  effects: ["off", "monitor", "deny"] as const,
  counts: { off: 0, monitor: 2, deny: 0 },
  controls: [
    {
      id: "deny_shell_execution",
      title: "Shell / command execution",
      description: "Catches shell metacharacters in tool parameters.",
      caveat: "trips on roughly 1 in 8 ordinary alphanumeric identifiers",
      effect: "monitor" as const,
      default_effect: "monitor" as const,
    },
    {
      id: "pii_detection",
      title: "PII egress",
      description: "Catches personal data leaving via a tool call.",
      caveat: "",
      effect: "monitor" as const,
      default_effect: "monitor" as const,
    },
  ],
};

beforeEach(() => {
  clearApiCache();
  vi.restoreAllMocks();
});

function mockFetch(data: unknown = CONTROLS) {
  return vi.spyOn(client, "fetchBaselineControls").mockResolvedValue(data as never);
}

function mockCompliance(controls: unknown[], scanned = 1200) {
  return vi.spyOn(client, "fetchPolicyCompliance").mockResolvedValue({
    namespace: "chatbot-prod", range: "7d", scanned, excluded_synthetic: 0, controls,
  } as never);
}

describe("baseline controls", () => {
  it("renders one row per control with its current effect", async () => {
    mockFetch();
    renderPanel({ namespace: "chatbot-prod", isAdmin: true });
    const row = await screen.findByTestId("baseline-control-deny_shell_execution");
    expect(row).toHaveAttribute("data-effect", "monitor");
    expect(await screen.findByTestId("baseline-control-pii_detection")).toBeInTheDocument();
  });

  it("marks the controls that carry a limitation, and only those", async () => {
    // This test asserted the OPPOSITE until the page was read in situ: the caveat was a paragraph on
    // every affected row, and twenty-one rows of prose is what made the panel unreadable. The prose
    // moved to the docs; the MARKER did not, because a control having a limitation is what an
    // operator needs at the moment they click Enforce.
    //
    // The label is deliberately not "false positive" — see the component. Eleven controls carry a
    // caveat and only two of them are about false positives.
    mockFetch();
    renderPanel({ namespace: "chatbot-prod", isAdmin: true });
    const caveat = await screen.findByTestId("baseline-caveat-deny_shell_execution");
    // The text is still REACHABLE — the marker carries it — so the fact was moved, not deleted.
    expect(caveat.getAttribute("title")).toContain("1 in 8");
    expect(caveat.getAttribute("aria-label")).toMatch(/limitation/i);
    expect(caveat.getAttribute("aria-label")).not.toMatch(/false.positive/i);
    // A control with no known false-positive mode must not be marked.
    expect(screen.queryByTestId("baseline-caveat-pii_detection")).toBeNull();
  });

  it("puts no description prose on a control row", async () => {
    // The change the operator asked for, stated as a property rather than as an absence of markup:
    // a row carries its heading and its measured impact, and nothing that belongs in the docs.
    mockFetch();
    renderPanel({ namespace: "chatbot-prod", isAdmin: true });
    const row = await screen.findByTestId("baseline-control-deny_shell_execution");
    expect(row.textContent).toContain("Shell / command execution");   // the heading stays
    expect(row.textContent).not.toContain("Catches shell metacharacters");  // the description does not
  });

  it("gives every section one docs link instead of a paragraph per control", async () => {
    mockFetch();
    renderPanel({ namespace: "chatbot-prod", isAdmin: true });
    const tool = await screen.findByTestId("baseline-surface-tool");
    const links = [...tool.querySelectorAll("a")].filter((a) => /docs/i.test(a.textContent ?? ""));
    expect(links).toHaveLength(1);
  });

  it("reports an unreadable control set as unknown, never as 'nothing enforcing'", async () => {
    vi.spyOn(client, "fetchBaselineControls").mockRejectedValue(new Error("503 upstream"));
    renderPanel({ namespace: "chatbot-prod", isAdmin: true });
    const err = await screen.findByTestId("baseline-unreadable");
    expect(err.textContent).toContain("unknown");
    expect(screen.queryByTestId("baseline-counts")).toBeNull();
  });

  it("keeps Save disabled until something actually changes", async () => {
    mockFetch();
    renderPanel({ namespace: "chatbot-prod", isAdmin: true });
    const save = await screen.findByTestId("baseline-save");
    expect(save).toBeDisabled();

    await userEvent.click(await screen.findByTestId("baseline-deny_shell_execution-deny"));
    await waitFor(() => expect(save).toBeEnabled());
    expect(screen.getByTestId("baseline-dirty-deny_shell_execution")).toBeInTheDocument();
  });

  it("sends the FULL control map on save, not just the edits", async () => {
    // The endpoint replaces a namespace's set wholesale. A partial body would quietly reset every
    // control the operator did not touch back to the default.
    mockFetch();
    const save = vi.spyOn(client, "saveBaselineControls").mockResolvedValue({
      namespace: "chatbot-prod", preset: "strict",
      effects: { deny_shell_execution: "deny", pii_detection: "monitor" },
      enforcing: ["deny_shell_execution"], disabled: [],
    } as never);

    renderPanel({ namespace: "chatbot-prod", isAdmin: true });
    await userEvent.click(await screen.findByTestId("baseline-deny_shell_execution-deny"));
    await userEvent.click(screen.getByTestId("baseline-save"));

    await waitFor(() => expect(save).toHaveBeenCalledTimes(1));
    expect(save.mock.calls[0][1]).toEqual({
      deny_shell_execution: "deny",
      pii_detection: "monitor", // untouched, but still sent
    });
  });

  it("says plainly when nothing is enforcing after a save", async () => {
    mockFetch();
    vi.spyOn(client, "saveBaselineControls").mockResolvedValue({
      namespace: "chatbot-prod", preset: "strict",
      effects: {}, enforcing: [], disabled: ["deny_shell_execution"],
    } as never);

    renderPanel({ namespace: "chatbot-prod", isAdmin: true });
    await userEvent.click(await screen.findByTestId("baseline-deny_shell_execution-off"));
    await userEvent.click(screen.getByTestId("baseline-save"));

    const msg = await screen.findByTestId("baseline-msg");
    expect(msg.textContent).toContain("nothing is enforcing");
  });

  it("is read-only for a non-admin", async () => {
    mockFetch();
    renderPanel({ namespace: "chatbot-prod", isAdmin: false });
    expect(await screen.findByTestId("baseline-deny_shell_execution-deny")).toBeDisabled();
    expect(screen.getByTestId("baseline-save")).toBeDisabled();
  });

  it("shows what promoting a control would have cost, on the control's own row", async () => {
    // "Promote this to Enforce" is a question about what will break. Answering it two screens away
    // means it does not get answered.
    mockFetch();
    mockCompliance([{
      control_id: "deny_shell_execution", count: 1432,
      agent_classes: [{ name: "cmp-support", count: 1400 }, { name: "cmp-finance", count: 32 }],
      tools: [{ name: "get_order", count: 1200 }], namespaces: ["chatbot-prod"],
      first_seen: null, last_seen: null, samples: [],
    }, {
      // The quiet-but-reported case. It still carries agent_classes, so rendering it produced the
      // sentence "0 would have been blocked · 2 classes" — which is not merely noisy, it is false.
      control_id: "pii_detection", count: 0,
      agent_classes: [{ name: "cmp-support", count: 0 }, { name: "cmp-finance", count: 0 }],
      tools: [], namespaces: ["chatbot-prod"],
      first_seen: null, last_seen: null, samples: [],
    }]);
    renderPanel({ namespace: "chatbot-prod", isAdmin: true });
    const impact = await screen.findByTestId("baseline-impact-deny_shell_execution");
    expect(impact.textContent).toContain("1,432");
    expect(impact.textContent).toContain("2 classes");
    expect(impact.textContent).toContain("get_order");
    // A quiet control gets no line at all — "0 calls" on every row trains people to stop reading it.
    // pii_detection is PRESENT AT ZERO in the payload — the shape the live endpoint actually returns,
    // and the one the old `impact.has(id)` guard rendered as "0 would have been blocked · 2 classes".
    // An ABSENT control would satisfy this assertion for the wrong reason, which is what the first
    // version of this test did, so it could not fail when the guard was removed.
    expect(screen.queryByTestId("baseline-impact-pii_detection")).toBeNull();
  });

  it("surfaces non-compliance from the customer's OWN policies, not just the shipped controls", async () => {
    // The gap this closes: /policy-compliance returns every rule that flagged traffic, but the panel
    // only read it through `impact.get(c.id)` while iterating the shipped controls, so a rule from
    // a policy the customer wrote was fetched and silently discarded. That removed the entire point of
    // trialling a custom policy in audit mode — it records what it WOULD have blocked and the console
    // showed none of it. Found on a live cluster: a custom egress rule caught a real exfiltration,
    // the API reported count=1, and there was nowhere in the UI to see it.
    mockFetch();
    mockCompliance([
      {
        control_id: "deny_shell_execution", count: 1432,
        agent_classes: [{ name: "cmp-support", count: 1432 }],
        tools: [{ name: "get_order", count: 1200 }], namespaces: ["chatbot-prod"],
        first_seen: null, last_seen: null, samples: [],
      },
      {
        control_id: "customer_data_to_untrusted_recipient", count: 3,
        agent_classes: [{ name: "r2-support", count: 3 }],
        tools: [{ name: "send_email", count: 3 }], namespaces: ["chatbot-prod"],
        first_seen: null, last_seen: null, samples: [],
      },
    ]);
    renderPanel({ namespace: "chatbot-prod", isAdmin: true });

    const custom = await screen.findByTestId("custom-rule-customer_data_to_untrusted_recipient");
    expect(custom.textContent).toContain("3 calls would have been blocked");
    expect(custom.textContent).toContain("send_email");

    // A shipped control keeps rendering on its OWN row and must not be duplicated into this section —
    // the two lists answer different questions and share one response.
    expect(screen.queryByTestId("custom-rule-deny_shell_execution")).toBeNull();
    expect(await screen.findByTestId("baseline-impact-deny_shell_execution")).toBeInTheDocument();
  });

  it("hides the custom-rule section entirely when only shipped controls flagged traffic", async () => {
    // An empty "Your own policies" heading reads as a broken feature, not as "you have none".
    mockFetch();
    mockCompliance([{
      control_id: "pii_detection", count: 7,
      agent_classes: [{ name: "cmp-support", count: 7 }],
      tools: [{ name: "send_email", count: 7 }], namespaces: ["chatbot-prod"],
      first_seen: null, last_seen: null, samples: [],
    }]);
    renderPanel({ namespace: "chatbot-prod", isAdmin: true });
    await screen.findByTestId("baseline-impact-pii_detection");
    expect(screen.queryByTestId("custom-rule-compliance")).toBeNull();
  });

  it("distinguishes 'compliant' from 'nothing has happened here yet'", async () => {
    // Zero non-compliant out of ZERO traffic is idle; out of 40,000 it is compliant. Rendering an
    // idle namespace as a clean bill of health is the exact lie `scanned` exists to prevent.
    mockFetch();
    mockCompliance([], 0);
    renderPanel({ namespace: "chatbot-prod", isAdmin: true });
    const scanned = await screen.findByTestId("baseline-scanned");
    expect(scanned).toHaveAttribute("data-scanned", "0");
    expect(scanned.textContent).toContain("nothing measured yet");
  });

  it("refuses to write when the aggregate 'all namespaces' scope is selected", async () => {
    // A namespace-scoped write under the aggregate stores a row literally namespaced "all", which
    // enforces nothing — a concrete namespace's read never sees it. The control must be inert, not
    // optimistic.
    mockFetch();
    renderPanel({ namespace: "all", isAdmin: true }, "all");
    expect(await screen.findByTestId("baseline-deny_shell_execution-deny")).toBeDisabled();
    expect(screen.getByTestId("baseline-save")).toBeDisabled();
  });
});

describe("grouping by plane", () => {
  const mixed = {
    namespace: "default",
    preset: "strict",
    default_effect: "monitor" as const,
    effects: ["off", "monitor", "deny"] as const,
    counts: { off: 0, monitor: 1, deny: 2 },
    controls: [
      {
        id: "mcp_definition_flagged",
        title: "Poisoned tool definition",
        description: "Withholds a tool whose description scanned as an injection.",
        caveat: "",
        effect: "deny" as const,
        default_effect: "deny" as const,
        plane: "discovery" as const,
      },
      {
        id: "deny_shell_execution",
        title: "Shell / command execution",
        description: "Catches shell metacharacters in tool parameters.",
        caveat: "",
        effect: "deny" as const,
        default_effect: "deny" as const,
        plane: "call" as const,
      },
      {
        id: "mcp_a_dangerous_scheme",
        title: "Executable URL scheme in a result",
        description: "Fences a tool result carrying javascript: or data:text/html.",
        caveat: "",
        effect: "monitor" as const,
        default_effect: "monitor" as const,
        plane: "response" as const,
      },
    ],
  };

  it("renders one section per plane that has controls, in call order", async () => {
    mockFetch(mixed);
    renderPanel({ namespace: "default", isAdmin: true });

    await screen.findByTestId("baseline-plane-discovery");
    const planes = ["discovery", "call", "response"].map((k) =>
      screen.getByTestId(`baseline-plane-${k}`),
    );
    // A call travels discovery -> call -> response, and the sections must read in that order or the
    // grouping stops explaining the architecture it was chosen to mirror.
    expect(planes[0].compareDocumentPosition(planes[1]) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(planes[1].compareDocumentPosition(planes[2]) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  });

  it("puts each control under its OWN plane", async () => {
    mockFetch(mixed);
    renderPanel({ namespace: "default", isAdmin: true });

    const discovery = await screen.findByTestId("baseline-plane-discovery");
    expect(discovery).toContainElement(screen.getByTestId("baseline-control-mcp_definition_flagged"));
    expect(discovery).not.toContainElement(screen.getByTestId("baseline-control-deny_shell_execution"));
  });

  it("renders no empty section for a plane with no controls", async () => {
    // Until the MCP controls land every control is `call`; an empty "Discovery" heading would tell an
    // operator a layer exists that they cannot configure.
    mockFetch({ ...mixed, controls: [mixed.controls[1]] });
    renderPanel({ namespace: "default", isAdmin: true });

    await screen.findByTestId("baseline-plane-call");
    expect(screen.queryByTestId("baseline-plane-discovery")).toBeNull();
    expect(screen.queryByTestId("baseline-plane-response")).toBeNull();
  });

  it("falls back to the call plane for a server that predates the field", async () => {
    mockFetch({ ...mixed, controls: mixed.controls.map(({ plane: _p, ...rest }) => rest) });
    renderPanel({ namespace: "default", isAdmin: true });

    const call = await screen.findByTestId("baseline-plane-call");
    expect(call).toContainElement(screen.getByTestId("baseline-control-mcp_definition_flagged"));
  });
});



describe("Enforce does not mean one thing", () => {
  const withEnforcedAs = (enforced_as: string) => ({
    ...CONTROLS,
    controls: [{ ...CONTROLS.controls[0], enforced_as }],
  });

  it("does not promise a block in the intro", async () => {
    // The intro said "Enforce blocks it" for all 21 controls while each row's own consequence text
    // said otherwise for the escalate/audit ones — two contradictory sentences on one screen.
    mockFetch();
    renderPanel({ namespace: "chatbot-prod", isAdmin: true });
    const intro = await screen.findByTestId("baseline-intro");
    expect(intro.textContent).not.toMatch(/Enforce<\/b> blocks it|Enforce blocks it/);
    expect(intro.textContent).toMatch(/each row says exactly how/i);
  });

  it("words the impact line from enforced_as, not as an unconditional block", async () => {
    mockFetch(withEnforcedAs("escalate"));
    mockCompliance([{
      control_id: "deny_shell_execution", count: 412,
      agent_classes: [], tools: [], namespaces: ["chatbot-prod"],
      first_seen: null, last_seen: null, samples: [],
    }]);
    renderPanel({ namespace: "chatbot-prod", isAdmin: true });
    const impact = await screen.findByTestId("baseline-impact-deny_shell_execution");
    expect(impact.textContent).toMatch(/held for approval/i);
    expect(impact.textContent).not.toMatch(/would have been blocked/i);
  });

  it("still says blocked for a control that really blocks", async () => {
    mockFetch(withEnforcedAs("block"));
    mockCompliance([{
      control_id: "deny_shell_execution", count: 412,
      agent_classes: [], tools: [], namespaces: ["chatbot-prod"],
      first_seen: null, last_seen: null, samples: [],
    }]);
    renderPanel({ namespace: "chatbot-prod", isAdmin: true });
    const impact = await screen.findByTestId("baseline-impact-deny_shell_execution");
    expect(impact.textContent).toMatch(/would have been blocked/i);
  });
});
