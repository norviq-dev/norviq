// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// The "something is wrong right now" surface.
//
// A governance product failing is not self-announcing. When the engine is unreachable the sidecars
// quietly fail closed and every agent's tool calls stop working — the operator's first signal is
// someone complaining the bot "got dumber". With a fail-open posture it is worse: tool calls are
// forwarded UNGOVERNED and nothing visibly changes at all. Either way the console looked healthy.
//
// This banner rides above every page and reports only what the backend can prove from decisions the
// data plane actually recorded, so it never claims an outage it cannot substantiate. It is dismissible
// per-issue, but a dismissal is keyed to the issue AND its last-seen time — a recurrence re-raises it
// rather than staying hidden, because a silenced enforcement outage is exactly the failure this exists
// to prevent.

import { useEffect, useState } from "react";
import { fetchSystemHealth, type SystemIssue } from "../../api/client";

const POLL_MS = 30_000;

function IssueRow({ issue, onDismiss }: { issue: SystemIssue; onDismiss: () => void }) {
  const accent = issue.severity === "critical" ? "var(--danger)" : "var(--warning)";
  return (
    <div
      role="alert"
      style={{
        display: "flex",
        alignItems: "flex-start",
        gap: 12,
        padding: "10px 16px",
        background: "var(--bg-elevated)",
        borderBottom: "1px solid var(--border)",
        borderLeft: `3px solid ${accent}`,
        fontSize: 13,
        lineHeight: 1.6,
      }}
    >
      <span aria-hidden style={{ color: accent, fontSize: 15, lineHeight: "22px" }}>
        ●
      </span>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ color: "var(--text-primary)", fontWeight: 600 }}>{issue.title}</div>
        <div style={{ color: "var(--text-secondary)", marginTop: 2 }}>{issue.detail}</div>
        <div style={{ color: "var(--text-muted)", marginTop: 4, fontSize: 12 }}>
          <span className="mono">{issue.affected_calls}</span> tool call
          {issue.affected_calls === 1 ? "" : "s"} affected in the last {issue.window_minutes} min
          {issue.namespaces.length > 0 && (
            <>
              {" · "}
              <span className="mono">{issue.namespaces.join(", ")}</span>
            </>
          )}
        </div>
        <div style={{ color: "var(--text-muted)", marginTop: 4, fontSize: 12 }}>{issue.remediation}</div>
      </div>
      <button
        type="button"
        onClick={onDismiss}
        aria-label={`Dismiss: ${issue.title}`}
        title="Dismiss until this happens again"
        style={{
          background: "none",
          border: "none",
          color: "var(--text-muted)",
          cursor: "pointer",
          fontSize: 16,
          lineHeight: 1,
          padding: 4,
        }}
      >
        ×
      </button>
    </div>
  );
}

export function SystemHealthBanner() {
  const [issues, setIssues] = useState<SystemIssue[]>([]);
  // Keyed by `${id}@${last_seen}` so dismissing hides THIS occurrence, not the whole class of issue.
  const [dismissed, setDismissed] = useState<Set<string>>(new Set());

  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      try {
        const health = await fetchSystemHealth();
        if (!cancelled) setIssues(health.issues ?? []);
      } catch {
        // A failure to FETCH health is not itself evidence of an incident — the console may simply be
        // unauthenticated or mid-reload. Staying silent beats crying wolf on every transient blip.
      }
    };
    void load();
    const timer = window.setInterval(() => void load(), POLL_MS);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, []);

  const visible = issues.filter((i) => !dismissed.has(`${i.id}@${i.last_seen ?? ""}`));
  if (visible.length === 0) return null;

  return (
    <div data-testid="system-health-banner">
      {visible.map((issue) => (
        <IssueRow
          key={issue.id}
          issue={issue}
          onDismiss={() =>
            setDismissed((prev) => new Set(prev).add(`${issue.id}@${issue.last_seen ?? ""}`))
          }
        />
      ))}
    </div>
  );
}
