// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// A GRANT is the one place a lookalike name costs the most.
//
// `sеnd_email` (U+0435 CYRILLIC SMALL LETTER IE in third position) is pixel-identical to `send_email`
// in the console's font. In the allowlist step it rendered as an ordinary row — "Observed · Any
// arguments · unrestricted", with a provenance badge asserting it was seen in real traffic — and the
// impact line read "Allows every call to sеnd_email, with any arguments." Nothing in the sheet said
// the name is not what it looks like, so an operator clicking Save & enforce on a deny-by-default
// policy believes they granted the tool they read.
//
// The same happens with no typing at all: Tools' "Scope this tool in a policy →" hands the observed
// name straight in via `seedGraph`, so a row the Tools page had just flagged red arrived here with
// the flag dropped in transit.
//
// The repo already owns the DETECTOR — `lookalikeOf` (lib/predicateSentence.ts), used by IntentModal,
// RuleCard, NearMissCard and Intents. This suite pins the BUILDER onto that same detector rather than
// a second one keyed differently.
//
// WHAT CHANGED IN THIS FILE, AND WHY (the two rewritten assertions below).
// It first asserted the shared `LookalikeNote`'s sentence: "the engine matches this allowlist
// evasion-normalised, so the rule grants the look-alike AND the plain-ASCII tool of the same shape."
// That sentence is true where LookalikeNote ships — its own header cites `norviq/api/threat_intent.py`,
// the SERVER generator, whose `skeleton()` folds Cyrillic е to Latin e — and false here. This sheet
// compiles in the BROWSER (`compileGraph`) and saves that rego verbatim (`rego_source: compiled.rego`),
// and `ui/src/lib/skeleton.ts` documents that it deliberately omits the cross-script confusables table.
// Compiling this exact graph emits:
//     allow_names     := {"sеnd_email"}   allow_skeletons := {"sеnd_email"}
// while the engine sends `input.tool_name_normalized = skeleton_py(tool) = "send_email"` — equal to
// neither. The ASCII tool matches nothing and stays denied; the grant is ONE name wide, not two.
// So the assertions now demand the sheet's own verified consequence AND forbid the old claim. Nothing
// was relaxed: this file asserts strictly more than it did (see `refuses to claim the ASCII twin…`).
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { BuilderSheet } from "./BuilderSheet";
import { lookalikeOf } from "../../lib/predicateSentence";
import { compileGraph } from "../../lib/builderCompile";
import { skeleton } from "../../lib/skeleton";
import type { BuilderGraph } from "../../lib/builderGraph";

vi.mock("@monaco-editor/react", () => ({
  default: ({ value }: { value?: string }) => <textarea data-testid="monaco-editor" readOnly value={value} />
}));

/** Cyrillic е — built from the codepoint so no editor or linter can normalise it away silently. */
const TWIN = `sеnd_email`;
const REAL = "send_email";

function registryEntry(name: string) {
  return {
    name,
    name_skeleton: REAL, // the server folds both names to the same skeleton — that is the whole point
    source: "observed" as const,
    namespace: "default",
    server_id: null,
    pin_status: null,
    scan_severity: null,
    description: null,
    description_withheld: false,
    input_schema: null,
    schema_available: false,
    last_seen_at: "2026-08-01T00:00:00Z"
  };
}

const server = setupServer(
  http.get("/api/v1/agents", () => HttpResponse.json([])),
  http.get("/api/v1/tools", () => HttpResponse.json([registryEntry(REAL), registryEntry(TWIN)]))
);
beforeAll(() => server.listen({ onUnhandledRequest: "bypass" }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

/** Exactly the shape Tools.tsx's `scopeHandoffGraph` produces for "Scope this tool in a policy →". */
const HANDOFF: BuilderGraph = {
  schemaVersion: 1,
  scope: { kind: "class", agentClass: "customer-support" },
  mode: "allowlist",
  rules: [],
  defaults: { decision: "block", reason: "Not in the intended tool set" },
  allowlist: { tools: [TWIN], refinements: { readonly: false, scope: false, rate: false, egress: false } }
} as unknown as BuilderGraph;

function renderSeeded(graph: BuilderGraph = HANDOFF) {
  return render(<BuilderSheet namespace="default" onClose={() => {}} seedGraph={graph} />);
}

describe("the detector this file relies on", () => {
  it("flags the twin and leaves the ASCII name alone", () => {
    expect(lookalikeOf(REAL)).toBeNull();
    expect(lookalikeOf(TWIN)).toEqual({ value: TWIN, codepoints: ["U+0435"], masked: "s·nd_email" });
  });
});

describe("an allowlist row for a lookalike tool name is marked", () => {
  it("hangs a lookalike note under the seeded row", async () => {
    renderSeeded();
    const row = await screen.findByTestId(`builder-allowlist-tool-row-${TWIN}`);

    // FAIL-ON-BUG: pre-fix the row rendered the impostor with a provenance badge and nothing else.
    const note = await within(row).findByTestId(`builder-lookalike-${TWIN}`);
    expect(note).toHaveTextContent("Lookalike name");
    expect(note).toHaveTextContent("s·nd_email"); // the POSITION, not just the codepoint
    expect(note).toHaveTextContent("U+0435");
    // The consequence, which is the part that decides whether the operator saves. See this file's
    // header for the compiled rego it was checked against.
    expect(note).toHaveTextContent(/grants exactly this name/i);
    expect(note).toHaveTextContent(/is not granted here/i);
  });

  it("refuses to claim the ASCII twin is granted too — this sheet's compiler does not fold it", async () => {
    // The shared LookalikeNote's sentence, rendered here, would tell the operator their allow had
    // widened to two names. `allow_names`/`allow_skeletons` both carry the Cyrillic literal, and the
    // engine's `input.tool_name_normalized` is always the folded ASCII form, so it matches neither.
    renderSeeded();
    const note = await within(
      await screen.findByTestId(`builder-allowlist-tool-row-${TWIN}`)
    ).findByTestId(`builder-lookalike-${TWIN}`);
    expect(note).not.toHaveTextContent(/grants the look-alike/i);
    expect(note).not.toHaveTextContent(/Confirm you meant both before saving/i);
  });

  it("emits rego in which the ASCII tool matches nothing — the claim above, against the compiler", async () => {
    // The assertion the copy rests on, checked at the source rather than restated. `skeleton()` here
    // is the BROWSER mirror the builder compiles with; `norviq/engine/confusables.py` is what the
    // engine runs, and only the latter folds U+0435.
    const { rego } = compileGraph(HANDOFF, "default");
    expect(rego).toContain(`allow_names := {"${TWIN}"}`);
    expect(rego).toContain(`allow_skeletons := {"${TWIN}"}`);
    expect(skeleton(TWIN)).toBe(TWIN); // the browser does NOT fold it…
    expect(rego).not.toContain(`"${REAL}"`); // …so no set in this policy contains the ASCII name
  });

  it("marks a name the operator types in, not only a seeded one", async () => {
    render(<BuilderSheet namespace="default" onClose={() => {}} />);
    fireEvent.click(await screen.findByTestId("builder-mode-allowlist"));
    const input = await screen.findByTestId("builder-allowlist-tool-input");
    fireEvent.change(input, { target: { value: TWIN } });
    fireEvent.click(screen.getByTestId("builder-allowlist-tool-add"));

    const row = await screen.findByTestId(`builder-allowlist-tool-row-${TWIN}`);
    expect(await within(row).findByTestId(`builder-lookalike-${TWIN}`)).toBeInTheDocument();
  });

  it("leaves an ordinary ASCII tool completely unmarked", async () => {
    // A registry with no twin in it at all — a warning that fires on every screen is a warning
    // nobody reads, and the ASCII case is almost every case.
    server.use(http.get("/api/v1/tools", () => HttpResponse.json([registryEntry(REAL)])));
    renderSeeded({
      ...HANDOFF,
      allowlist: { ...HANDOFF.allowlist!, tools: [REAL] }
    });
    const row = await screen.findByTestId(`builder-allowlist-tool-row-${REAL}`);
    expect(within(row).queryByTestId(`builder-lookalike-${REAL}`)).toBeNull();
    await waitFor(() => expect(screen.queryByTestId("builder-lookalike-suggestions")).toBeNull());
    expect(screen.queryByText(/Lookalike name/i)).toBeNull();
  });
});

describe("the suggestion list cannot offer the twin as if it were the real tool", () => {
  it("does not put a non-ASCII name into the bare datalist", async () => {
    renderSeeded();
    await waitFor(() => {
      const options = [...document.querySelectorAll("#builder-known-tools option")].map((o) =>
        o.getAttribute("value")
      );
      expect(options).toContain(REAL);
      // FAIL-ON-BUG: pre-fix the datalist offered `send_email` and `sеnd_email` as two entries that
      // are indistinguishable on screen, and a datalist option cannot carry a badge to tell them apart.
      expect(options).not.toContain(TWIN);
    });
  });

  it("still surfaces the twin, in a list that can say what it is", async () => {
    renderSeeded();
    // Not hidden — hiding an observed name would be its own lie ("this tool does not exist"). It is
    // moved somewhere a marking can travel with it.
    const withheld = await screen.findByTestId("builder-lookalike-suggestions");
    expect(withheld).toHaveTextContent("s·nd_email");
    expect(withheld).toHaveTextContent("U+0435");
  });
});
