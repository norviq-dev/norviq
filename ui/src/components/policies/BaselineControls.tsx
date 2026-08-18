// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// Baseline controls — the shipped detectors, each set to Off / Monitor / Enforce for one namespace.
//
// A preset used to be all-or-nothing, which meant the only way to stop a noisy control dropping
// legitimate traffic was to turn the whole baseline off. Every control ships on Monitor: it evaluates
// and records a non-compliant call without interrupting it, and the operator promotes the ones they
// want to Enforce once they can see what that would cost.
//
// The rows carry HEADINGS ONLY. Each control used to render its description and, where it had one, a
// paragraph of false-positive caveat — twenty-one rows of prose, which is what made the panel
// unreadable in situ and buried the one thing the page is for: the tri-state. The explanations moved
// to the docs, one link per section.
//
// What did NOT move is the SIGNAL that a caveat exists. Two of these controls have false-positive
// modes that will bite a real support desk, and the moment somebody clicks Enforce is the moment
// that matters — so an escalate-coloured marker stays on the row, carrying the text, pointing at the
// docs for the rest.

import { useEffect, useMemo, useState } from "react";
import {
  fetchBaselineControls,
  fetchPolicyCompliance,
  saveBaselineControls,
  type BaselineControl,
  type BaselineEffect,
  type ControlPlane,
  type ControlSurface,
} from "../../api/client";
import { Panel } from "../common/Panel";
import { invalidateApiCache, useApi } from "../../hooks/useApi";
import { useMutationScope } from "../../hooks/useMutationScope";

/** Wire value -> what an operator actually calls it. "deny" is shown as Enforce; "audit" is avoided
 *  entirely here because it already means a DECISION elsewhere in the console (and the Audit Log). */
// The three planes, in the order a call travels through them. A control's plane comes from the
// server (`BaselineControl.plane`) so the console and the engine cannot disagree about it; `planeOf`
// only supplies the fallback for a server that predates the field.
//
// TWO AXES, and which one is the HEADING changed after an operator read the page.
//
// `surface` (tool / MCP) is the top level, because that is the question somebody arrives with — "what
// do my MCP integrations enforce" — and grouping by plane alone split the five MCP controls across
// two sections with sixteen tool controls wedged in between. `plane` survives as the SUBGROUP: it is
// a real property and the reason a discovery control cannot read call arguments.
//
// A subgroup header is only drawn when a surface actually spans more than one plane, so the tool
// section (all sixteen on the call plane) does not gain a heading that says nothing.
const SURFACES: { key: ControlSurface; title: string; docs: string }[] = [
  { key: "tool", title: "Tool calls", docs: "/docs/controls#tool" },
  { key: "mcp", title: "MCP integrations", docs: "/docs/controls#mcp" },
];

const PLANES: { key: ControlPlane; title: string }[] = [
  { key: "discovery", title: "Discovery" },
  { key: "call", title: "Call" },
  { key: "response", title: "Response" },
];

function planeOf(c: BaselineControl): ControlPlane {
  return c.plane ?? "call";
}

/** Falls back to `tool`, where 16 of the 21 belong, so a pre-`surface` API still renders a sane page
 *  rather than an empty MCP section or an unsectioned list. */
function surfaceOf(c: BaselineControl): ControlSurface {
  return c.surface ?? "tool";
}

const LABELS: Record<BaselineEffect, string> = {
  off: "Off",
  monitor: "Monitor",
  deny: "Enforce",
};

/** What ENFORCING does, which is not always "block".
 *
 *  A control the preset registers as `escalates[...]` still escalates when the operator sets it to
 *  `deny` — the compiler preserves the head's severity. One sentence for every row made the two MCP
 *  controls that hold a call for a human advertise a hard denial, so an operator would either expect
 *  an outage that never comes or decline to enforce a control that would not have broken anything. */
const ENFORCED_AS_COPY: Record<string, string> = {
  block: "call is blocked",
  escalate: "call is held for approval",
  audit: "recorded, call proceeds",
};

/** What THIS control's current effect actually does. Only `deny` varies by control. */
function consequenceOf(control: { enforced_as?: string }, effect: BaselineEffect): string {
  if (effect !== "deny") return CONSEQUENCE[effect];
  return ENFORCED_AS_COPY[control.enforced_as ?? "block"] ?? CONSEQUENCE.deny;
}

const CONSEQUENCE: Record<BaselineEffect, string> = {
  off: "not evaluated",
  monitor: "recorded, call proceeds",
  deny: "call is blocked",
};

export function BaselineControls({ namespace, isAdmin }: { namespace: string; isAdmin: boolean }) {
  const controls = useApi(() => fetchBaselineControls(namespace), [namespace], {
    cacheKey: `baseline-controls:${namespace}`,
    staleTimeMs: 15_000,
  });
  // Blast radius, rendered against the control it belongs to. "Promote this to Enforce" is a question
  // about what will break, and answering it two screens away means it does not get answered.
  const compliance = useApi(() => fetchPolicyCompliance(namespace, "7d"), [namespace], {
    cacheKey: `baseline-compliance:${namespace}`,
    staleTimeMs: 30_000,
  });
  const { canMutate, blockedReason } = useMutationScope();

  // Pending edits, keyed by control id. Empty === "showing exactly what the server reports", which is
  // what makes the dirty check below honest rather than a guess.
  const [pending, setPending] = useState<Record<string, BaselineEffect>>({});
  const [saving, setSaving] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);

  // Drop pending edits when the namespace changes. Without this, switching namespaces would carry
  // one namespace's unsaved intent onto another's controls and save it there.
  useEffect(() => {
    setPending({});
    setMsg(null);
  }, [namespace]);

  const rows = controls.data?.controls ?? [];
  const effectFor = (id: string, server: BaselineEffect): BaselineEffect => pending[id] ?? server;
  const dirty = useMemo(
    () => rows.some((c) => effectFor(c.id, c.effect) !== c.effect),
    [rows, pending],
  );

  const counts = useMemo(() => {
    const out: Record<BaselineEffect, number> = { off: 0, monitor: 0, deny: 0 };
    for (const c of rows) out[effectFor(c.id, c.effect)] += 1;
    return out;
  }, [rows, pending]);

  const impact = useMemo(() => {
    const out = new Map<string, { count: number; classes: number; topTool: string }>();
    for (const c of compliance.data?.controls ?? []) {
      // `count > 0`, NOT merely "the endpoint mentioned this control". /policy-compliance returns a
      // row for every control it evaluated, including the quiet ones at count 0, so keying on presence
      // put "0 would have been blocked · 7d · 2 classes" on eleven of sixteen rows — noise, and
      // self-contradictory noise at that (zero blocks, two classes). Seen only on the live console:
      // the unit mock omitted quiet controls entirely, so `has()` and "flagged something" happened to
      // coincide there and the test could not tell the two apart.
      if (c.count <= 0) continue;
      out.set(c.control_id, {
        count: c.count,
        classes: c.agent_classes.length,
        topTool: c.tools[0]?.name ?? "",
      });
    }
    return out;
  }, [compliance.data]);
  // Distinguishes "compliant" from "nothing has happened here yet". Rendering an idle namespace as a
  // clean bill of health is the exact lie this number exists to prevent.
  const scanned = compliance.data?.scanned ?? null;

  // Non-compliance from the customer's OWN policies, which has nowhere else to go.
  //
  // /policy-compliance returns every rule that flagged traffic, but this component only ever read it
  // through `impact.get(c.id)` while iterating the shipped controls — so a rule from a policy the
  // customer wrote was fetched, stored in the map, and never looked up. That silently removed the
  // whole point of trialling a custom policy in monitor mode: it records what it WOULD have blocked,
  // and the console showed none of it. Same data, same request, just rendered.
  const customRows = useMemo(() => {
    const baseline = new Set(rows.map((c) => c.id));
    return (compliance.data?.controls ?? [])
      // `count > 0` for the same reason as the impact map above, which was fixed first and left this
      // one behind: /policy-compliance reports every control it evaluated, quiet ones at zero, so
      // without it a customer's own rule that flagged NOTHING is listed under a heading that says
      // these rules flagged real traffic.
      .filter((c) => !baseline.has(c.control_id) && c.count > 0)
      .map((c) => ({
        id: c.control_id,
        count: c.count,
        classes: c.agent_classes.length,
        topTool: c.tools[0]?.name ?? "",
      }));
  }, [compliance.data, rows]);

  const save = async () => {
    if (!canMutate) {
      setMsg(blockedReason);
      return;
    }
    setSaving(true);
    setMsg(null);
    try {
      // Send the FULL map, not just the edits: the endpoint replaces a namespace's control set
      // wholesale, so a partial body would silently reset every control the user did not touch.
      const effects: Record<string, BaselineEffect> = {};
      for (const c of rows) effects[c.id] = effectFor(c.id, c.effect);
      const result = await saveBaselineControls(namespace, effects);
      // The baseline governs every agent class in the namespace, so anything showing a resolved
      // policy is now stale.
      for (const p of ["baseline-controls:", "effective:", "hier-posture:", "policy-settings:"]) {
        invalidateApiCache(p);
      }
      setPending({});
      await controls.refetch();
      setMsg(
        result.enforcing.length
          ? `Saved — ${result.enforcing.length} control${result.enforcing.length === 1 ? "" : "s"} now enforcing`
          : "Saved — nothing is enforcing; all traffic proceeds and non-compliance is recorded",
      );
    } catch (e) {
      setMsg(`Failed: ${(e instanceof Error ? e.message : String(e)).replace(/^Error:\s*/, "")}`);
    } finally {
      setSaving(false);
    }
  };

  return (
    <Panel title="Baseline controls">
      <div data-testid="baseline-intro" style={{ fontSize: 12, color: "var(--text-secondary)", marginBottom: 10 }}>
        The shipped detectors, one row each. <b>Monitor</b> evaluates the call, records it as
        non-compliant and lets it through. <b>Enforce</b> blocks it. Nothing is blocked until you say so.
      </div>

      {controls.loading && <div data-testid="baseline-loading" style={{ fontSize: 13, color: "var(--text-muted)" }}>Loading controls…</div>}

      {/* A control set we could not READ is not a control set. Never render an empty table as "all clear". */}
      {!controls.loading && controls.error && (
        <div data-testid="baseline-unreadable" style={{ fontSize: 12, color: "var(--escalate)" }}>
          Baseline controls could not be read — <b>unknown, not &ldquo;none enforcing&rdquo;</b>.
          <span style={{ color: "var(--text-muted)" }}> {controls.error}</span>
        </div>
      )}

      {!controls.loading && !controls.error && rows.length > 0 && (
        <>
          <div data-testid="baseline-counts" style={{ display: "flex", gap: 14, fontSize: 12, marginBottom: 10, flexWrap: "wrap" }}>
            <span style={{ color: "var(--block, #ff5c7c)" }}>{counts.deny} enforcing</span>
            <span style={{ color: "var(--text-secondary)" }}>{counts.monitor} monitoring</span>
            <span style={{ color: "var(--text-muted)" }}>{counts.off} off</span>
            {scanned !== null && (
              <span data-testid="baseline-scanned" data-scanned={scanned} style={{ color: "var(--text-muted)" }}>
                {scanned === 0
                  ? "· no traffic in the last 7d — nothing measured yet"
                  : `· ${scanned.toLocaleString()} calls examined over 7d`}
              </span>
            )}
          </div>

          {SURFACES.filter((sf) => rows.some((c) => surfaceOf(c) === sf.key)).map((sf) => {
            const inSurface = rows.filter((c) => surfaceOf(c) === sf.key);
            const planes = PLANES.filter((pl) => inSurface.some((c) => planeOf(c) === pl.key));
            return (
            <section key={sf.key} data-testid={`baseline-surface-${sf.key}`} style={{ marginBottom: 22 }}>
              <div style={{ display: "flex", alignItems: "baseline", gap: 8, marginBottom: 8 }}>
                <h4 style={{ margin: 0, fontSize: 13, color: "var(--text)" }}>{sf.title}</h4>
                <span style={{ fontSize: 11.5, color: "var(--text-muted)" }}>{inSurface.length}</span>
                {/* The prose that used to sit under every row lives in the docs now. One link per
                    section, rather than a paragraph per control, is the whole point of the change. */}
                <a href={sf.docs} style={{ fontSize: 11.5, color: "var(--accent)", marginLeft: "auto" }}>
                  Docs →
                </a>
              </div>

              {planes.map((pl) => (
                <div key={pl.key} data-testid={`baseline-plane-${pl.key}`} style={{ marginBottom: 10 }}>
                  {planes.length > 1 && (
                    <div style={{ fontSize: 10.5, letterSpacing: "0.06em", textTransform: "uppercase",
                                  color: "var(--text-muted)", margin: "8px 0 6px" }}>
                      {pl.title}
                    </div>
                  )}
                  <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                  {inSurface.filter((c) => planeOf(c) === pl.key).map((c) => {
              const current = effectFor(c.id, c.effect);
              const changed = current !== c.effect;
              return (
                <div
                  key={c.id}
                  data-testid={`baseline-control-${c.id}`}
                  data-effect={current}
                  style={{
                    // GRID, not flex. The row was a flex whose text column had no track to sit in, so
                    // a long description simply grew past the toggles and rendered UNDER them —
                    // measured at 226px of overlap on a 1440px viewport. `minmax(0, 1fr)` gives the
                    // text a column that cannot exceed its share, and `auto` sizes the controls to
                    // their content, so the two can never intersect at any width.
                    display: "grid", gridTemplateColumns: "minmax(0, 1fr) auto",
                    columnGap: 16, alignItems: "center",
                    padding: "9px 12px", border: "1px solid var(--border)", borderRadius: 8,
                  }}
                >
                  <div style={{ minWidth: 0 }}>
                    <div style={{ fontSize: 13, fontWeight: 600, display: "flex", alignItems: "center", gap: 7 }}>
                      {/* WRAPS, never truncates. `nowrap` + ellipsis kept the row to one line, which
                          looks tidier right up until the viewport narrows: at tablet width it turned
                          the control names into "Prompt injecti…" and "Destructive & …", and the
                          second of those is not a shortened name, it is a different claim. The
                          controls column is `auto`, so it holds its size and the text column is the
                          one that gives — a wrapped title costs a line of height, a truncated one
                          costs the meaning. */}
                      <span style={{ minWidth: 0, overflowWrap: "anywhere" }}>{c.title}</span>
                      {/* The caveat TEXT is gone from the row; the fact that one exists is not — it is
                          what an operator needs at the moment they click Enforce, and they will not
                          go and read the docs at that moment.

                          NEUTRAL, and deliberately so. This was first built as an escalate-coloured
                          "!" labelled "has a known false-positive mode", which reading the live copy
                          showed to be false for most of them: of the eleven caveats, only two are
                          false-positive warnings. The rest are false-NEGATIVE gaps (`pii_detection`
                          matches US SSN shapes and nothing else), matching semantics (`ssrf_metadata`
                          keys on the destination, not the tool name), or a precondition that can make
                          the control inert (`mcp_tool_not_approved` fires only in strict pin mode).
                          A red "!" over "this control is narrower than its name" is an alarm about
                          the wrong thing, so the marker claims only what is true of all eleven: there
                          is a limitation here, and it is worth reading before you rely on it. */}
                      {c.caveat && (
                        <span
                          data-testid={`baseline-caveat-${c.id}`}
                          title={c.caveat}
                          aria-label="this control has a limitation — read it before relying on it"
                          style={{ fontSize: 10, color: "var(--text-muted)", border: "1px solid var(--border)",
                                   borderRadius: 4, padding: "0 4px", flex: "none", cursor: "help" }}
                        >
                          i
                        </span>
                      )}
                      {changed && (
                        <span data-testid={`baseline-dirty-${c.id}`} style={{ fontSize: 11, color: "var(--accent)", flex: "none" }}>
                          unsaved
                        </span>
                      )}
                    </div>
                    {/* What promoting this control would actually have cost over the last 7 days.
                        Kept while the prose went, because it is MEASURED DATA about this estate, not
                        an explanation — it is the number the decision turns on. Only rendered when
                        the control HAS flagged something: a "0 calls" line on every quiet control is
                        noise that trains people to stop reading the row. */}
                    {impact.has(c.id) && (
                      <div data-testid={`baseline-impact-${c.id}`} style={{ fontSize: 11, color: "var(--text-secondary)", marginTop: 2 }}>
                        <b>{impact.get(c.id)!.count.toLocaleString()}</b> would have been blocked · 7d
                        {impact.get(c.id)!.classes > 0 && ` · ${impact.get(c.id)!.classes} class${impact.get(c.id)!.classes === 1 ? "" : "es"}`}
                        {impact.get(c.id)!.topTool && ` · ${impact.get(c.id)!.topTool}`}
                      </div>
                    )}
                  </div>
                  <div style={{ display: "flex", alignItems: "center", gap: 10, justifySelf: "end" }}>
                    <div style={{ fontSize: 11, color: "var(--text-muted)", textAlign: "right", whiteSpace: "nowrap" }}>
                      {consequenceOf(c, current)}
                    </div>
                    <div className="tabs-kit" style={{ display: "flex", flex: "none" }}>
                      {(["off", "monitor", "deny"] as const).map((eff) => (
                        <button
                          key={eff}
                          data-testid={`baseline-${c.id}-${eff}`}
                          className={`tab-kit${current === eff ? " active" : ""}`}
                          disabled={!isAdmin || saving || !canMutate}
                          title={blockedReason ?? consequenceOf(c, eff)}
                          onClick={() => setPending((p) => ({ ...p, [c.id]: eff }))}
                        >
                          {LABELS[eff]}
                        </button>
                      ))}
                    </div>
                  </div>
                </div>
              );
                  })}
                  </div>
                </div>
              ))}
            </section>
            );
          })}

          <div style={{ marginTop: 12, display: "flex", alignItems: "center", gap: 12 }}>
            <button
              data-testid="baseline-save"
              className="btn btn-primary"
              disabled={!isAdmin || !dirty || saving || !canMutate}
              title={blockedReason ?? undefined}
              onClick={save}
            >
              {saving ? "Saving…" : "Save controls"}
            </button>
            {msg && <span data-testid="baseline-msg" style={{ fontSize: 12, color: "var(--text-secondary)" }}>{msg}</span>}
            {!isAdmin && (
              <span style={{ fontSize: 11, color: "var(--text-muted)" }}>Read-only — an admin can change these.</span>
            )}
          </div>

          {customRows.length > 0 && (
            <div data-testid="custom-rule-compliance" style={{ marginTop: 20, paddingTop: 14, borderTop: "1px solid var(--border)" }}>
              <div style={{ fontSize: 13, fontWeight: 600 }}>Your own policies</div>
              <div style={{ fontSize: 12, color: "var(--text-secondary)", marginTop: 2, marginBottom: 10, maxWidth: 620 }}>
                Rules from policies you wrote that flagged real traffic without stopping it — because the
                policy is in <b>audit</b> mode, or this namespace is in Monitor. Set the mode on the policy
                itself in Policy Catalog; the toggles above only govern the shipped controls.
              </div>
              <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                {customRows.map((c) => (
                  <div
                    key={c.id}
                    data-testid={`custom-rule-${c.id}`}
                    style={{
                      // GRID, for the same reason as the control row above — this row was left on the
                      // old flex when that one was converted. `c.id` is a CUSTOMER-authored rule id
                      // (snake_case, no break opportunities, arbitrarily long) with no flex and no
                      // minWidth, beside a variable-length sentence pinned by `flexShrink: 0`. With
                      // negative free space `space-between` degrades to `flex-start` and the sentence
                      // is laid out past the card's edge — and since `.content` is `overflow-x:
                      // hidden`, it is silently CLIPPED rather than visibly spilling.
                      display: "grid", gridTemplateColumns: "minmax(0, 1fr) auto",
                      columnGap: 12, alignItems: "baseline",
                      padding: "8px 12px", border: "1px solid var(--border)", borderRadius: 8,
                    }}
                  >
                    <code style={{ fontSize: 12, minWidth: 0, overflowWrap: "anywhere" }}>{c.id}</code>
                    <div style={{ fontSize: 11, color: "var(--text-secondary)", justifySelf: "end", textAlign: "right" }}>
                      <b>{c.count.toLocaleString()}</b> call{c.count === 1 ? "" : "s"} would have been blocked
                      {c.classes > 0 && ` — ${c.classes} agent class${c.classes === 1 ? "" : "es"}`}
                      {c.topTool && `, mostly ${c.topTool}`}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </>
      )}
    </Panel>
  );
}

export default BaselineControls;
