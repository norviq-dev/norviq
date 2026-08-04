// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors

/**
 * The dialog primitive both MCP dialogs sit on.
 *
 * Small on purpose. It carries only the things that are wrong when hand-rolled: the ARIA wiring, a
 * working Escape, a backdrop that does not swallow clicks meant for the card, and focus moved into
 * the dialog on open. A modal an operator cannot dismiss from the keyboard is a modal that traps
 * them mid-incident.
 */

import { ReactNode, useEffect, useId, useRef } from "react";

export interface ModalProps {
  title: ReactNode;
  onClose: () => void;
  children: ReactNode;
  /** Footer controls, right-aligned. */
  actions?: ReactNode;
  /** Red-bordered card for a destructive or alarming dialog. */
  danger?: boolean;
  /**
   * A wider card for content that is a READING surface rather than a question.
   *
   * The default 520px suits a confirm dialog. It does not suit a unified definition diff or a nested
   * argument tree — both wrap into unreadability at that width, and both are the whole point of the
   * dialog they appear in.
   */
  wide?: boolean;
  /** A line under the title. Use it for status the reader needs before the body makes sense. */
  subtitle?: ReactNode;
  "data-testid"?: string;
}

export function Modal({
  title,
  onClose,
  children,
  actions,
  danger,
  wide,
  subtitle,
  "data-testid": testId
}: ModalProps) {
  const titleId = useId();
  const card = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    document.addEventListener("keydown", onKey);
    // Remember where focus came from BEFORE moving it, so it can go back on close. Without this every
    // dismissal drops a keyboard user at the top of the document — tolerable for the two dialogs this
    // started with, actively hostile now that opening one is the normal way to read a table row.
    const opener = document.activeElement as HTMLElement | null;
    // Move focus in, preferring the first input so a type-to-confirm dialog is immediately usable.
    const first = card.current?.querySelector<HTMLElement>("input, textarea, button");
    first?.focus();
    return () => {
      document.removeEventListener("keydown", onKey);
      // Only if the opener is still in the document — a row that was removed while the dialog was open
      // cannot take focus back, and calling focus() on a detached node silently sends it to <body>.
      if (opener && document.contains(opener)) opener.focus();
    };
  }, [onClose]);

  return (
    <div
      className="modal-backdrop"
      // Clicking the backdrop dismisses; clicking the card must not. Comparing target to
      // currentTarget is what distinguishes them — a bare onClick here closes on every inner click.
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div
        ref={card}
        className={`modal-card${danger ? " danger" : ""}${wide ? " wide" : ""}`}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        data-testid={testId}
      >
        <div className="modal-title" id={titleId}>
          {title}
        </div>
        {subtitle ? <div className="modal-subtitle">{subtitle}</div> : null}
        {children}
        {actions ? <div className="modal-actions">{actions}</div> : null}
      </div>
    </div>
  );
}
