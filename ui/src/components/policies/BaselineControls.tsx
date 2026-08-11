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
// That cost is the reason `caveat` is rendered inline and in the escalate colour rather than tucked
// behind a tooltip: the moment someone clicks Enforce is exactly the moment they will not go and read
// the docs, and two of these controls have false-positive modes that will bite a real support desk.

import { useEffect, useMemo, useState } from "react";
import {
  fetchBaselineControls,
  fetchPolicyCompliance,
  saveBaselineControls,
  type BaselineEffect,
} from "../../api/client";
import { Panel } from "../common/Panel";
import { invalidateApiCache, useApi } from "../../hooks/useApi";
import { useMutationScope } from "../../hooks/useMutationScope";

/** Wire value -> what an operator actually calls it. "deny" is shown as Enforce; "audit" is avoided
 *  entirely here because it already means a DECISION elsewhere in the console (and the Audit Log). */
const LABELS: Record<BaselineEffect, string> = {
  off: "Off",
  monitor: "Monitor",
  deny: "Enforce",
};

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
  // through `impact.get(c.id)` while iterating the 14 shipped controls — so a rule from a policy the
  // customer wrote was fetched, stored in the map, and never looked up. That silently removed the
  // whole point of trialling a custom policy in monitor mode: it records what it WOULD have blocked,
  // and the console showed none of it. Same data, same request, just rendered.
  const customRows = useMemo(() => {
    const baseline = new Set(rows.map((c) => c.id));
    return (compliance.data?.controls ?? [])
      .filter((c) => !baseline.has(c.control_id))
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

          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            {rows.map((c) => {
              const current = effectFor(c.id, c.effect);
              const changed = current !== c.effect;
              return (
                <div
                  key={c.id}
                  data-testid={`baseline-control-${c.id}`}
                  data-effect={current}
                  style={{
                    display: "flex", gap: 12, alignItems: "flex-start", justifyContent: "space-between",
                    padding: "10px 12px", border: "1px solid var(--border)", borderRadius: 8,
                  }}
                >
                  <div style={{ minWidth: 0 }}>
                    <div style={{ fontSize: 13, fontWeight: 600 }}>
                      {c.title}
                      {changed && (
                        <span data-testid={`baseline-dirty-${c.id}`} style={{ fontSize: 11, color: "var(--accent)", marginLeft: 8 }}>
                          unsaved
                        </span>
                      )}
                    </div>
                    <div style={{ fontSize: 12, color: "var(--text-secondary)", marginTop: 2 }}>{c.description}</div>
                    {c.caveat && (
                      <div data-testid={`baseline-caveat-${c.id}`} style={{ fontSize: 11, color: "var(--escalate)", marginTop: 4, maxWidth: 560 }}>
                        {c.caveat}
                      </div>
                    )}
                    {/* What promoting this control would actually have cost over the last 7 days.
                        Only rendered when the control HAS flagged something — a "0 calls" line on
                        every quiet control is noise that trains people to stop reading this row. */}
                    {impact.has(c.id) && (
                      <div data-testid={`baseline-impact-${c.id}`} style={{ fontSize: 11, color: "var(--text-secondary)", marginTop: 4 }}>
                        <b>{impact.get(c.id)!.count.toLocaleString()}</b> call
                        {impact.get(c.id)!.count === 1 ? "" : "s"} in the last 7d would have been blocked
                        {impact.get(c.id)!.classes > 0 && ` — ${impact.get(c.id)!.classes} agent class${impact.get(c.id)!.classes === 1 ? "" : "es"}`}
                        {impact.get(c.id)!.topTool && `, mostly ${impact.get(c.id)!.topTool}`}
                      </div>
                    )}
                  </div>
                  <div style={{ flexShrink: 0, textAlign: "right" }}>
                    <div className="tabs-kit" style={{ display: "flex" }}>
                      {(["off", "monitor", "deny"] as const).map((eff) => (
                        <button
                          key={eff}
                          data-testid={`baseline-${c.id}-${eff}`}
                          className={`tab-kit${current === eff ? " active" : ""}`}
                          disabled={!isAdmin || saving || !canMutate}
                          title={blockedReason ?? CONSEQUENCE[eff]}
                          onClick={() => setPending((p) => ({ ...p, [c.id]: eff }))}
                        >
                          {LABELS[eff]}
                        </button>
                      ))}
                    </div>
                    <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 3 }}>{CONSEQUENCE[current]}</div>
                  </div>
                </div>
              );
            })}
          </div>

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
                      display: "flex", gap: 12, alignItems: "baseline", justifyContent: "space-between",
                      padding: "8px 12px", border: "1px solid var(--border)", borderRadius: 8,
                    }}
                  >
                    <code style={{ fontSize: 12 }}>{c.id}</code>
                    <div style={{ fontSize: 11, color: "var(--text-secondary)", flexShrink: 0 }}>
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
