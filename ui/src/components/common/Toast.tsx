// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// The ONE feedback surface for async outcomes. Convention: no fetch
// result may be silently dropped — every mutation surfaces success/partial/failure here (or in a
// dedicated in-context panel), and error/warning toasts are STICKY until dismissed so a failed
// or partial outcome can't expire unseen.
import { createContext, ReactNode, useCallback, useContext, useMemo, useRef, useState } from "react";

export type ToastKind = "success" | "error" | "warning" | "info";

export type ToastInput = {
  kind: ToastKind;
  message: string;
  /** Optional second line — full server detail (e.g. an escalation reason). Never truncated. */
  detail?: string;
  /** Optional action rendered as a button (e.g. "Open draft →"). */
  actionLabel?: string;
  onAction?: () => void;
  /** Sticky toasts stay until dismissed. Defaults: error/warning sticky, success/info auto-dismiss. */
  sticky?: boolean;
};

type ToastItem = ToastInput & { id: number };

type ToastContextValue = {
  push: (toast: ToastInput) => number;
  dismiss: (id: number) => void;
};

const ToastContext = createContext<ToastContextValue | null>(null);

const KIND_COLOR: Record<ToastKind, string> = {
  success: "var(--allow)",
  error: "var(--block)",
  warning: "var(--escalate)",
  info: "var(--audit)"
};

const AUTO_DISMISS_MS = 6000;

export function ToastProvider({ children }: { children: ReactNode }) {
  const [items, setItems] = useState<ToastItem[]>([]);
  const nextId = useRef(1);

  const dismiss = useCallback((id: number) => {
    setItems((cur) => cur.filter((t) => t.id !== id));
  }, []);

  const push = useCallback(
    (toast: ToastInput) => {
      const id = nextId.current++;
      const sticky = toast.sticky ?? (toast.kind === "error" || toast.kind === "warning");
      setItems((cur) => [...cur, { ...toast, sticky, id }]);
      if (!sticky) window.setTimeout(() => dismiss(id), AUTO_DISMISS_MS);
      return id;
    },
    [dismiss]
  );

  const value = useMemo(() => ({ push, dismiss }), [push, dismiss]);

  return (
    <ToastContext.Provider value={value}>
      {children}
      {items.length > 0 && (
        <div
          data-testid="toast-stack"
          style={{
            position: "fixed",
            bottom: 22,
            right: 22,
            zIndex: 200,
            display: "flex",
            flexDirection: "column",
            gap: 10,
            maxWidth: 420
          }}
        >
          {items.map((t) => (
            <div
              key={t.id}
              data-testid={`toast-${t.kind}`}
              role={t.kind === "error" ? "alert" : "status"}
              style={{
                display: "flex",
                alignItems: "flex-start",
                gap: 10,
                padding: "12px 14px",
                background: "var(--bg-surface)",
                border: `1px solid ${KIND_COLOR[t.kind]}`,
                borderRadius: 11,
                boxShadow: "0 16px 40px -14px rgba(0,0,0,0.7)"
              }}
            >
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ fontSize: 12.5, fontWeight: 600, color: "var(--text-primary)" }}>{t.message}</div>
                {t.detail && (
                  <div style={{ fontSize: 12, color: "var(--text-secondary)", marginTop: 4, whiteSpace: "pre-wrap" }}>
                    {t.detail}
                  </div>
                )}
                {t.actionLabel && t.onAction && (
                  <button
                    type="button"
                    onClick={() => {
                      dismiss(t.id);
                      t.onAction?.();
                    }}
                    style={{
                      marginTop: 6,
                      background: "transparent",
                      border: "none",
                      color: "var(--accent)",
                      fontFamily: "inherit",
                      fontSize: 12.5,
                      fontWeight: 700,
                      cursor: "pointer",
                      padding: 0
                    }}
                  >
                    {t.actionLabel}
                  </button>
                )}
              </div>
              <button
                type="button"
                aria-label="Dismiss notification"
                onClick={() => dismiss(t.id)}
                style={{
                  background: "transparent",
                  border: "none",
                  color: "var(--text-secondary)",
                  cursor: "pointer",
                  fontSize: 14,
                  lineHeight: 1,
                  padding: 2
                }}
              >
                ✕
              </button>
            </div>
          ))}
        </div>
      )}
    </ToastContext.Provider>
  );
}

export function useToast(): ToastContextValue {
  const ctx = useContext(ToastContext);
  if (!ctx) throw new Error("useToast must be used within ToastProvider");
  return ctx;
}
