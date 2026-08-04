// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors

/**
 * The compiled policy, as a drawer that is a 46px rail by default.
 *
 * WHY IT COLLAPSES. The rego is reference, not the work. It used to hold half the sheet permanently,
 * which cost the authoring column the room its most important row needs: the allowed-tool row is
 * specced `[name] [ScopeCell flex: 2 1 300px] [remove]`, and at half width the ScopeCell — the whole
 * point of this redesign, the thing that tells an operator a tool is unrestricted and offers to narrow
 * it — wrapped its four slots into a stack of fragments. A permanent reference pane was crowding out
 * the control it exists to describe.
 *
 * WHY THE RAIL STILL CARRIES THE BUDGET. Collapsing a pane usually means losing what it told you. The
 * three caps (65,536 bytes / 500 lines / 25 regex ops) are the one thing an expert watches while
 * authoring, and they are the reason to look at the pane at all — so the rail keeps them readable
 * sideways. Someone who collapses the drawer loses the source, not the signal.
 */

import Editor from "@monaco-editor/react";
import { ChevronLeft, ChevronRight } from "lucide-react";
import type { CSSProperties } from "react";

export interface RegoStats {
  bytes: number;
  lines: number;
  regexOps: number;
}

export interface RegoDrawerProps {
  rego: string;
  stats: RegoStats;
  errors: { message: string }[];
  expanded: boolean;
  onToggle: () => void;
  /** Monaco language registration, passed straight through to `beforeMount`. */
  beforeMount?: Parameters<typeof Editor>[0]["beforeMount"];
}

const OVER = "var(--block)";

/** `1.3 KB · 1/25 regex` — the rail has room for two facts, so it carries the two that bite first. */
function railBudget(stats: RegoStats): string {
  const kb = stats.bytes >= 1024 ? `${(stats.bytes / 1024).toFixed(1)} KB` : `${stats.bytes} B`;
  return `${kb} · ${stats.regexOps}/25 regex`;
}

const VERTICAL: CSSProperties = {
  writingMode: "vertical-rl",
  // Without this the text reads top-to-bottom rotated the wrong way for a left-hand rail.
  transform: "rotate(180deg)"
};

export function RegoDrawer({ rego, stats, errors, expanded, onToggle, beforeMount }: RegoDrawerProps) {
  const over = stats.bytes > 65536 || stats.lines > 500 || stats.regexOps > 25;

  if (!expanded) {
    return (
      <button
        type="button"
        data-testid="builder-editor-expand-toggle"
        aria-expanded={false}
        aria-label="Show the compiled rego"
        data-expanded={false}
        onClick={onToggle}
        // The WHOLE rail is the target. A 46px strip with a 22px button inside it is a strip that
        // looks clickable and mostly is not.
        style={{
          flex: "none",
          width: 46,
          border: "none",
          borderLeft: "1px solid var(--border)",
          background: "var(--bg-sidebar)",
          color: "var(--text-secondary)",
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          gap: 14,
          padding: "14px 0",
          cursor: "pointer"
        }}
      >
        <ChevronLeft size={16} aria-hidden />
        <span
          style={{
            ...VERTICAL,
            fontSize: 11.5,
            fontWeight: 600,
            letterSpacing: "0.1em",
            textTransform: "uppercase"
          }}
        >
          Compiled Rego
        </span>
        <span
          className="mono"
          data-testid="builder-stats"
          style={{ ...VERTICAL, fontSize: 11, color: over ? OVER : "var(--text-faint)" }}
        >
          {railBudget(stats)}
        </span>
      </button>
    );
  }

  return (
    <div
      className="vpb-rego-pane"
      style={{
        flex: "0 1 420px",
        minWidth: 300,
        borderLeft: "1px solid var(--border)",
        background: "var(--bg-sidebar)",
        display: "flex",
        flexDirection: "column",
        minHeight: 0
      }}
    >
      <div
        style={{
          flex: "none",
          display: "flex",
          alignItems: "center",
          gap: 8,
          padding: "12px 16px",
          borderBottom: "1px solid var(--border)"
        }}
      >
        <span
          style={{
            fontSize: 11,
            fontWeight: 600,
            letterSpacing: "0.08em",
            textTransform: "uppercase",
            color: "var(--text-secondary)"
          }}
        >
          Compiled Rego
        </span>
        <span style={{ fontSize: 11.5, color: "var(--text-faint)" }}>live · read-only</span>
        <span style={{ flex: 1 }} />
        <button
          type="button"
          data-testid="builder-editor-expand-toggle"
          className="icon-btn"
          aria-expanded
          aria-label="Hide the compiled rego"
          data-expanded
          style={{ width: 28, height: 28 }}
          onClick={onToggle}
        >
          <ChevronRight size={15} />
        </button>
      </div>

      {/* A COLUMN, not a scrolling block. Monaco is sized by its container, and `height: 100%` inside a
          block with no height of its own resolves to zero — the drawer opened onto an empty pane with
          a scrollbar and nothing under it. The editor takes the slack; the error band keeps its own
          height beneath. */}
      <div
        style={{
          flex: 1,
          minHeight: 0,
          display: "flex",
          flexDirection: "column",
          gap: 10,
          padding: "14px 16px"
        }}
      >
        <div className="editor" data-testid="builder-editor-container" data-expanded style={{ flex: 1, minHeight: 220 }}>
          <Editor
            defaultLanguage="rego"
            beforeMount={beforeMount}
            theme="vs-dark"
            height="100%"
            value={rego || "# Fix the errors below to generate rego"}
            options={{ readOnly: true, minimap: { enabled: false }, fontSize: 12 }}
          />
        </div>

        {errors.length > 0 && (
          <div
            data-testid="builder-errors"
            role="alert"
            style={{
              fontSize: 12,
              color: "var(--block)",
              background: "#ff3b5c15",
              border: "1px solid #ff3b5c30",
              borderRadius: 8,
              padding: "8px 10px",
              flex: "none",
              maxHeight: 90,
              overflowY: "auto"
            }}
          >
            {errors.map((e, i) => (
              <div key={i}>{e.message}</div>
            ))}
          </div>
        )}
      </div>

      <div
        data-testid="builder-stats"
        className="mono"
        style={{
          flex: "none",
          display: "flex",
          gap: 14,
          flexWrap: "wrap",
          padding: "12px 16px",
          borderTop: "1px solid var(--border)",
          fontSize: 11.5,
          color: "var(--text-faint)"
        }}
      >
        <span style={{ color: stats.bytes > 65536 ? OVER : undefined }}>
          {stats.bytes.toLocaleString()} / 65,536 bytes
        </span>
        <span style={{ color: stats.lines > 500 ? OVER : undefined }}>{stats.lines} / 500 lines</span>
        <span style={{ color: stats.regexOps > 25 ? OVER : undefined }}>{stats.regexOps} / 25 regex ops</span>
      </div>
    </div>
  );
}
