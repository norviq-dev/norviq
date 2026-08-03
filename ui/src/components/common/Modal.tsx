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
  "data-testid"?: string;
}

export function Modal({ title, onClose, children, actions, danger, "data-testid": testId }: ModalProps) {
  const titleId = useId();
  const card = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    document.addEventListener("keydown", onKey);
    // Move focus in, preferring the first input so a type-to-confirm dialog is immediately usable.
    const first = card.current?.querySelector<HTMLElement>("input, textarea, button");
    first?.focus();
    return () => document.removeEventListener("keydown", onKey);
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
        className={`modal-card${danger ? " danger" : ""}`}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        data-testid={testId}
      >
        <div className="modal-title" id={titleId}>
          {title}
        </div>
        {children}
        {actions ? <div className="modal-actions">{actions}</div> : null}
      </div>
    </div>
  );
}
