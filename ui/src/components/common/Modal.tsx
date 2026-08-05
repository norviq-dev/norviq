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

import { ReactNode, RefObject, useEffect, useId, useRef } from "react";

/**
 * The dialogs currently open.
 *
 * Every Modal listens on `document`, so before this existed one Escape reached EVERY open dialog's
 * handler and closed the whole stack: an operator backing out of a stacked type-to-confirm also lost
 * the definition they were mid-review of underneath it, with nothing on screen to say the second
 * dialog had taken the first one with it. Call sites papered over it one pair at a time (McpServers
 * suppresses its detail dialog while the 409 conflict is up, and does not for the forget confirm);
 * the guard belongs here, once, for every pair that will ever be stacked.
 *
 * WHICH ONE IS ON TOP IS ASKED OF THE DOM, NOT OF MOUNT ORDER. Every backdrop is `z-index: 60`
 * (index.css), so the dialog the operator sees on top is exactly the one later in document order.
 * Mount order is NOT that: React runs a child's effect BEFORE its parent's, so a Modal rendered
 * inside another Modal's children registered first, and the dialog UNDERNEATH then claimed to be
 * topmost — one Escape closed the covered dialog the operator could not see and left the one they
 * were answering on screen. `compareDocumentPosition` answers for both shapes at once: a sibling
 * mounted later and a dialog nested inside this one are both FOLLOWING this card.
 */
const stack: Array<RefObject<HTMLDivElement>> = [];

const FOCUSABLE =
  'a[href], button:not([disabled]), input:not([disabled]), textarea:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])';

/**
 * What "move focus in, preferring a text entry" has to mean, enumerated positively.
 *
 * `input` on its own is not a text field. `type="checkbox"` and `type="radio"` are controls Space
 * TOGGLES, and `type="submit" | "button" | "reset" | "image"` are buttons Space and Enter FIRE — so
 * a bare `input` selector re-arms, one attribute later, the exact keypress this dialog must not arm:
 * a dialog whose first control fires under the operator's next keystroke is not a dialog they decided
 * anything in. Anything not named here is a control, and controls fall through to the card.
 */
const TEXT_ENTRY = [
  "textarea:not([disabled])",
  "input:not([type]):not([disabled])",
  'input[type="text"]:not([disabled])',
  'input[type="search"]:not([disabled])',
  'input[type="email"]:not([disabled])',
  'input[type="url"]:not([disabled])',
  'input[type="tel"]:not([disabled])',
  'input[type="password"]:not([disabled])',
  'input[type="number"]:not([disabled])'
].join(", ");

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
  // The latest onClose, without making it a dependency of the effect below. Every call site passes an
  // inline arrow, so a re-render of the page behind the dialog produced a new identity and re-ran the
  // whole effect — re-capturing the "opener" (by then the dialog's own control) and yanking focus back
  // to the top of the card mid-read. (The open-dialog registry below does not depend on this: it is
  // ordered by the DOM, so a re-run that removed and re-added this card would order the same either
  // way. Mount-once is here for the focus, which would not.)
  const onCloseRef = useRef(onClose);
  onCloseRef.current = onClose;

  useEffect(() => {
    stack.push(card);
    // Topmost = no other open dialog paints over this card. `DOCUMENT_POSITION_FOLLOWING` is set both
    // for a later sibling and for a node CONTAINED by this one, which is what puts a nested dialog on
    // top rather than underneath. The stack holds the REFS, not the elements they held at mount, so a
    // remounted card can never be compared as a detached node.
    const topmost = () => {
      const mine = card.current;
      if (!mine) return false;
      return !stack.some((other) => {
        const el = other !== card ? other.current : null;
        return el !== null && document.contains(el) &&
          Boolean(mine.compareDocumentPosition(el) & Node.DOCUMENT_POSITION_FOLLOWING);
      });
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        if (!topmost()) return; // the dialog on top owns this keypress; one Escape closes ONE dialog
        onCloseRef.current();
        return;
      }
      // FOCUS TRAP. `aria-modal="true"` tells a screen reader that everything behind this card does
      // not exist; without a trap, Tab walked straight out to it — three Shift+Tabs from the MCP tool
      // dialog reached "Forget <server>…" behind the backdrop, and Enter there stacked a second dialog
      // on top of the one still being read. A promise the tab order breaks is worse than no promise.
      if (e.key === "Tab" && topmost() && card.current) {
        const nodes = [...card.current.querySelectorAll<HTMLElement>(FOCUSABLE)];
        if (nodes.length === 0) {
          e.preventDefault();
          card.current.focus();
          return;
        }
        const first = nodes[0];
        const last = nodes[nodes.length - 1];
        const active = document.activeElement;
        // The CARD counts as outside for this purpose. It is where focus starts on open, and
        // `contains()` is true of the node itself — so treating it as inside let the very first
        // Shift+Tab walk backwards past the backdrop to the page's own controls, which is the exact
        // hop this trap exists to stop.
        if (!card.current.contains(active) || active === card.current) {
          e.preventDefault();
          (e.shiftKey ? last : first).focus();
        } else if (e.shiftKey && active === first) {
          e.preventDefault();
          last.focus();
        } else if (!e.shiftKey && active === last) {
          e.preventDefault();
          first.focus();
        }
      }
    };
    document.addEventListener("keydown", onKey);
    // Remember where focus came from BEFORE moving it, so it can go back on close. Without this every
    // dismissal drops a keyboard user at the top of the document — tolerable for the two dialogs this
    // started with, actively hostile now that opening one is the normal way to read a table row.
    const opener = document.activeElement as HTMLElement | null;
    // Move focus in, preferring a text entry so a type-to-confirm dialog is immediately usable — and
    // otherwise the CARD, never a control.
    //
    // `querySelector("input, textarea, button")` did not do that: a comma selector returns the first
    // node in DOCUMENT ORDER matching ANY branch, not the first input, so a dialog with no input
    // handed focus to its first button. On the MCP tool dialog that button is the destructive
    // "Revoke" (an approved, undrifted pin renders no diff toggle and no Approve), and one Space —
    // the natural key for scrolling a card that is `max-height: calc(100vh - 48px); overflow-y: auto`
    // — withheld the tool from the model with no confirmation step and a green success toast. A
    // dialog that arms a destructive action under the operator's next keypress is not a dialog they
    // decided anything in. Focusing the card announces the title, keeps Space a scroll key, and still
    // leaves the controls one Tab away.
    const entry = card.current?.querySelector<HTMLElement>(TEXT_ENTRY);
    (entry ?? card.current)?.focus();
    return () => {
      document.removeEventListener("keydown", onKey);
      const i = stack.indexOf(card);
      if (i >= 0) stack.splice(i, 1);
      // Only if the opener is still in the document — a row that was removed while the dialog was open
      // cannot take focus back, and calling focus() on a detached node silently sends it to <body>.
      if (opener && document.contains(opener)) opener.focus();
    };
  }, []);

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
        // Programmatically focusable, never a tab stop: it is where focus goes on open when the dialog
        // has no text entry, so the card scrolls under Space instead of a control firing under it.
        tabIndex={-1}
        style={{ outline: "none" }}
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
