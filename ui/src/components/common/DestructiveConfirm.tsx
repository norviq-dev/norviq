// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors

/**
 * Type-to-confirm for an action that cannot be undone.
 *
 * The prototype's version was decorative — an input beside a button that was never gated on it. That
 * is worse than no confirmation at all: it teaches the operator that the ceremony is theatre, so the
 * one time it matters they will click through it. Here the button is genuinely unreachable until the
 * typed text matches, and `InlineDisabledReason` says which of the two blockers is in the way, since
 * "you are not an admin" and "you have not typed the name" are otherwise the same grey button.
 *
 * The consequence line is the point of the dialog, not the confirmation. Forgetting an MCP server
 * under the default `tofu` mode means the next `tools/list` re-pins whatever the server serves at
 * that moment — so forgetting a DRIFTED server auto-approves the drift. An operator reaching for
 * "forget" to clean up an alarm is one click from adopting the attack.
 */

import { useState } from "react";
import { InlineDisabledReason } from "./InlineDisabledReason";
import { Modal } from "./Modal";

export interface DestructiveConfirmProps {
  title: React.ReactNode;
  /** What the action does, in plain terms. */
  children: React.ReactNode;
  /** The consequence the operator is most likely not to have thought of. Rendered in an amber band. */
  consequence?: React.ReactNode;
  /** The exact string that must be typed. Usually the name of the thing being destroyed. */
  confirmWord: string;
  confirmLabel: string;
  onConfirm: () => void;
  onCancel: () => void;
  /** False when the caller is not an admin — the control stays unreachable and says so. */
  allowed?: boolean;
  busy?: boolean;
  "data-testid"?: string;
}

export function DestructiveConfirm({
  title,
  children,
  consequence,
  confirmWord,
  confirmLabel,
  onConfirm,
  onCancel,
  allowed = true,
  busy = false,
  "data-testid": testId = "destructive-confirm"
}: DestructiveConfirmProps) {
  const [typed, setTyped] = useState("");
  const matches = typed.trim() === confirmWord;
  const blocked = !allowed ? "Needs admin — you are a viewer." : !matches ? `Type ${confirmWord} to enable.` : undefined;

  return (
    <Modal
      title={title}
      onClose={onCancel}
      danger
      data-testid={testId}
      actions={
        <>
          <button type="button" className="btn btn-ghost" onClick={onCancel} data-testid={`${testId}-cancel`}>
            Cancel
          </button>
          <InlineDisabledReason reason={blocked} tone={allowed ? "escalate" : "muted"} data-testid={`${testId}-gate`}>
            <button
              type="button"
              className="btn btn-destructive"
              disabled={!allowed || !matches || busy}
              onClick={onConfirm}
              data-testid={`${testId}-submit`}
            >
              {busy ? "Working…" : confirmLabel}
            </button>
          </InlineDisabledReason>
        </>
      }
    >
      <div style={{ fontSize: 13, lineHeight: 1.6, color: "var(--text-secondary)", marginBottom: 12 }}>{children}</div>
      {consequence ? (
        <div
          data-testid={`${testId}-consequence`}
          style={{
            padding: "11px 12px",
            borderRadius: 10,
            border: "1px solid #ffb02030",
            background: "#ffb02015",
            fontSize: 12.5,
            lineHeight: 1.55,
            color: "var(--text-secondary)",
            marginBottom: 14
          }}
        >
          {consequence}
        </div>
      ) : null}
      <label style={{ display: "block", fontSize: 12, color: "var(--text-secondary)", marginBottom: 6 }}>
        Type <span className="mono" style={{ color: "var(--text-primary)" }}>{confirmWord}</span> to confirm
        <input
          className="input mono"
          style={{ width: "100%", marginTop: 6, marginBottom: 16 }}
          placeholder={confirmWord}
          value={typed}
          onChange={(e) => setTyped(e.target.value)}
          data-testid={`${testId}-input`}
          autoComplete="off"
          spellCheck={false}
        />
      </label>
    </Modal>
  );
}
