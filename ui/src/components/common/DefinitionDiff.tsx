// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors

/**
 * What changed between the approved definition and the one being served right now.
 *
 * WHY A DIFF AND NOT TWO PANES. The operator's question at a drift is not "what are these two
 * documents?" — it is "what did the server change?". Two `<pre>` blocks make that a manual
 * character-by-character comparison of two ~8 KiB JSON documents, which is how a one-line
 * `x-priority: "always call before replying"` gets approved by a tired human. A tool definition is
 * mostly unchanged at a rug pull; the changed part is the whole story and belongs on screen alone.
 *
 * WHY THE PAYLOAD IS SHOWN HERE AND WITHHELD ON /tools. The stored canonical is the PRE-sanitize
 * text, so a diff can contain the injection the proxy kept from the model. Tools is a browsing
 * surface — it withholds, because nobody there asked to see an attack. This is an ADJUDICATION
 * surface: the operator is being asked to approve or refuse this exact text, and cannot answer
 * without reading it. The mitigation is framing, not concealment — the payload is inert here
 * because the model never reads this page, and the labels say so.
 */

import { useMemo, useState } from "react";

export type DiffLine = { kind: "same" | "add" | "del"; text: string };

/** Pretty-print JSON so the diff runs over semantic lines rather than one 8 KiB string. Canonical
 *  text that does not parse (a truncated 8 KiB slice does not) is diffed as-is — still useful. */
function toLines(canonical: string): string[] {
  if (!canonical) return [];
  try {
    return JSON.stringify(JSON.parse(canonical), null, 2).split("\n");
  } catch {
    return canonical.split("\n");
  }
}

/**
 * Longest-common-subsequence line diff.
 *
 * Bounded deliberately: definitions are capped at 8 KiB by the pin store, so the quadratic table is
 * at most a few hundred squared. Above the cap we fall back to "everything replaced", which is
 * honest — a document that large has no readable diff anyway.
 */
export function diffLines(a: string[], b: string[]): DiffLine[] {
  const MAX = 400;
  if (a.length > MAX || b.length > MAX) {
    return [...a.map((t) => ({ kind: "del" as const, text: t })), ...b.map((t) => ({ kind: "add" as const, text: t }))];
  }
  const n = a.length;
  const m = b.length;
  // lcs[i][j] = length of the longest common subsequence of a[i:] and b[j:]
  const lcs: number[][] = Array.from({ length: n + 1 }, () => new Array<number>(m + 1).fill(0));
  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      lcs[i][j] = a[i] === b[j] ? lcs[i + 1][j + 1] + 1 : Math.max(lcs[i + 1][j], lcs[i][j + 1]);
    }
  }
  const out: DiffLine[] = [];
  let i = 0;
  let j = 0;
  while (i < n && j < m) {
    if (a[i] === b[j]) {
      out.push({ kind: "same", text: a[i] });
      i++;
      j++;
    } else if (lcs[i + 1][j] >= lcs[i][j + 1]) {
      out.push({ kind: "del", text: a[i] });
      i++;
    } else {
      out.push({ kind: "add", text: b[j] });
      j++;
    }
  }
  while (i < n) out.push({ kind: "del", text: a[i++] });
  while (j < m) out.push({ kind: "add", text: b[j++] });
  return out;
}

/**
 * Drop runs of unchanged lines far from any change, the way `diff -U2` does.
 *
 * Without this, a two-line change inside a 300-line schema renders 300 lines and the change is again
 * something the operator has to hunt for — which is the defect this component exists to fix.
 */
export function collapseContext(lines: DiffLine[], context = 2): Array<DiffLine | { kind: "gap"; text: string }> {
  const keep = new Set<number>();
  lines.forEach((l, idx) => {
    if (l.kind === "same") return;
    for (let k = Math.max(0, idx - context); k <= Math.min(lines.length - 1, idx + context); k++) keep.add(k);
  });
  if (keep.size === 0) return [];
  const out: Array<DiffLine | { kind: "gap"; text: string }> = [];
  let hidden = 0;
  lines.forEach((l, idx) => {
    if (keep.has(idx)) {
      if (hidden > 0) {
        out.push({ kind: "gap", text: `${hidden} unchanged line${hidden === 1 ? "" : "s"}` });
        hidden = 0;
      }
      out.push(l);
    } else {
      hidden++;
    }
  });
  if (hidden > 0) out.push({ kind: "gap", text: `${hidden} unchanged line${hidden === 1 ? "" : "s"}` });
  return out;
}

const ROW: Record<string, { bg?: string; color: string; sign: string }> = {
  same: { color: "var(--text-faint)", sign: "  " },
  del: { bg: "#ff3b5c15", color: "var(--block)", sign: "- " },
  add: { bg: "#00e5a015", color: "var(--allow)", sign: "+ " }
};

export interface DefinitionDiffProps {
  approved: string;
  served: string;
  approvedDigest?: string;
  servedDigest?: string;
  "data-testid"?: string;
}

export function DefinitionDiff({
  approved,
  served,
  approvedDigest,
  servedDigest,
  "data-testid": testId = "definition-diff"
}: DefinitionDiffProps) {
  const [showFull, setShowFull] = useState(false);
  const { rows, added, removed } = useMemo(() => {
    const all = diffLines(toLines(approved), toLines(served));
    return {
      rows: collapseContext(all),
      added: all.filter((l) => l.kind === "add").length,
      removed: all.filter((l) => l.kind === "del").length
    };
  }, [approved, served]);

  // THE DIGESTS OUTRANK THE TEXT. `approvedDigest`/`servedDigest` are taken over the WHOLE canonical
  // definition (mcp/pins.py `definition_digest`); `approved`/`served` are the bounded slice the proxy
  // kept (`canonical_definition(tool)[:_CANONICAL_MAX]` in mcp/firewall.py) — truncated with no marker,
  // and `sort_keys` puts `description` ahead of `inputSchema`, so a padded description pushes a schema
  // change out of BOTH stored copies. They then arrive byte-identical while the digests differ, and the
  // digests are what the drift verdict is derived from (api/routers/mcp.py `_status_of`).
  //
  // So when the digests disagree and this component has nothing to show, the honest report is "the
  // change is outside the copy we hold" — never the two reassuring sentences below, which would state
  // an equality nobody checked on the one screen whose next button adopts the change.
  const digestsDiffer = Boolean(approvedDigest && servedDigest && approvedDigest !== servedDigest);
  if (digestsDiffer && (!served || rows.length === 0)) {
    return (
      <div data-testid={testId} style={{ fontSize: 12.5, lineHeight: 1.6 }}>
        <div data-testid="diff-unshowable" style={{ color: "var(--escalate)", fontWeight: 600, marginBottom: 4 }}>
          The change cannot be shown here.
        </div>
        <div style={{ color: "var(--text-secondary)" }}>
          {served
            ? `The stored copies of the approved and served definitions are identical, but their digests
               are not — so what changed lies outside the truncated copy this console holds.`
            : `A definition with a different digest has been served, but no copy of it was stored, so
               there is nothing to compare it against.`}{" "}
          This is <b>not</b> evidence that nothing changed. Do not adopt this definition on the strength
          of an empty diff — read what the server is serving now at its source first.
        </div>
        <div className="mono" style={{ marginTop: 6, fontSize: 11.5, color: "var(--text-muted)" }}>
          {approvedDigest?.slice(0, 8)} → {servedDigest?.slice(0, 8)}
        </div>
      </div>
    );
  }

  // THE OTHER SIDE OF THE SAME COIN: no stored copy of the APPROVED definition.
  //
  // `canonical` is optional on the observe payload (api/routers/mcp.py `canonical: str = ""`) and is
  // stored verbatim into `approved_canonical` at first pin, so a pin can hold an approved DIGEST with
  // no approved text. An empty string is unambiguous here — `canonical_definition` (mcp/pins.py)
  // json.dumps a dict, so its shortest possible output is `{}`, never "".
  //
  // Diffing against a missing baseline turns every line of the served definition into an ADD and puts
  // "0 removed" under it: a count of a document that was never stored, presented as a measurement. On
  // an unchanged pin (digests equal) it is worse than imprecise — the screen fills with a green "What
  // changed" for a tool that did not change. Show the served text, and say what it is.
  if (served && !approved) {
    const known =
      approvedDigest && servedDigest
        ? approvedDigest === servedDigest
          ? `Its digest still matches the approved digest, so the definition has not changed since it was approved.`
          : `Its digest does not match the approved one, so it HAS changed — but with no approved copy stored, nothing here can show what changed.`
        : `No digest pair was recorded either, so nothing about this definition has been compared.`;
    return (
      <div data-testid={testId} style={{ fontSize: 12.5, lineHeight: 1.6 }}>
        <div data-testid="diff-no-baseline" style={{ color: "var(--escalate)", fontWeight: 600, marginBottom: 4 }}>
          No copy of the approved definition was stored, so this is not a comparison.
        </div>
        <div style={{ color: "var(--text-secondary)" }}>
          Everything below is the definition being served now, in full — not a change the server made.{" "}
          {known}
        </div>
        {approvedDigest && servedDigest ? (
          <div className="mono" style={{ marginTop: 6, fontSize: 11.5, color: "var(--text-muted)" }}>
            {approvedDigest.slice(0, 8)} → {servedDigest.slice(0, 8)}
          </div>
        ) : null}
        <pre className="json" data-testid="served-definition" style={{ marginTop: 8 }}>
          {toLines(served).join("\n")}
        </pre>
      </div>
    );
  }

  // No served definition at all is NOT "no change" — it means nothing has been observed since the
  // approval, and saying "matches" there would assert something we never checked.
  if (!served) {
    return (
      <div data-testid={testId} className="muted" style={{ fontSize: 12.5, lineHeight: 1.6 }}>
        No definition has been served since this pin was approved, so there is nothing to compare. The
        approved definition is still what the model is allowed to see.
      </div>
    );
  }

  if (rows.length === 0) {
    return (
      <div data-testid={testId} className="muted" style={{ fontSize: 12.5, lineHeight: 1.6 }}>
        The served definition matches the approved one exactly — no fields added, removed or altered.
      </div>
    );
  }

  return (
    <div data-testid={testId}>
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8, flexWrap: "wrap" }}>
        <span
          style={{
            fontSize: 11,
            fontWeight: 600,
            letterSpacing: "0.08em",
            textTransform: "uppercase",
            color: "var(--text-secondary)"
          }}
        >
          What changed
        </span>
        {approvedDigest && servedDigest ? (
          <span className="mono" style={{ fontSize: 11.5, color: "var(--text-muted)" }}>
            {approvedDigest.slice(0, 8)} → {servedDigest.slice(0, 8)}
          </span>
        ) : null}
      </div>

      <div
        style={{
          border: "1px solid var(--border)",
          borderRadius: 10,
          background: "var(--bg-void)",
          overflow: "hidden"
        }}
      >
        <div style={{ overflowX: "auto" }}>
          <div className="mono" style={{ minWidth: 340, fontSize: 12, lineHeight: 1.75 }}>
            {rows.map((l, idx) =>
              l.kind === "gap" ? (
                <div
                  key={idx}
                  data-testid="diff-gap"
                  style={{
                    padding: "2px 10px",
                    color: "var(--text-muted)",
                    background: "var(--bg-surface)",
                    fontSize: 11
                  }}
                >
                  ⋯ {l.text}
                </div>
              ) : (
                <div
                  key={idx}
                  data-testid={`diff-${l.kind}`}
                  style={{ padding: "2px 10px", background: ROW[l.kind].bg, color: ROW[l.kind].color }}
                >
                  {ROW[l.kind].sign}
                  {l.text}
                </div>
              )
            )}
          </div>
        </div>
        <div
          style={{
            padding: "8px 10px",
            borderTop: "1px solid var(--border)",
            display: "flex",
            gap: 12,
            flexWrap: "wrap",
            alignItems: "center",
            fontSize: 11.5,
            color: "var(--text-muted)"
          }}
        >
          <span style={{ color: "var(--block)" }} data-testid="diff-removed-count">
            {removed} removed
          </span>
          <span style={{ color: "var(--allow)" }} data-testid="diff-added-count">
            {added} added
          </span>
          <button
            type="button"
            className="linklike"
            data-testid="diff-toggle-full"
            onClick={() => setShowFull((v) => !v)}
          >
            {showFull ? "Hide full definitions" : "Show full definitions"}
          </button>
        </div>
      </div>

      {showFull && (
        <div className="grid grid-cols-2 md:grid-cols-1 gap-5" style={{ marginTop: 14 }}>
          <div>
            <div className="page-sub">Approved definition</div>
            <pre className="json" data-testid="approved-definition">
              {toLines(approved).join("\n") || "(none recorded)"}
            </pre>
          </div>
          <div>
            <div className="page-sub" style={{ color: "var(--block)" }}>
              Definition served now
            </div>
            <pre className="json" data-testid="served-definition">
              {toLines(served).join("\n") || "(none recorded)"}
            </pre>
          </div>
        </div>
      )}
    </div>
  );
}
