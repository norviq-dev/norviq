// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// LOGIN-2: single place the session token lives. "Keep me signed in" picks the storage:
//   remember=true  -> localStorage   (survives the browser restart)
//   remember=false -> sessionStorage (cleared when the tab/browser closes)
// getToken() checks both so every consumer (fetch headers, WS urls, the App gate) works for either
// choice. The `nrvq_must_change` flag (forced first-login password change) also lives here so it is
// always cleared together with the token.

const TOKEN_KEY = "nrvq_token";
const MUST_CHANGE_KEY = "nrvq_must_change";

/** The current session token, from either storage (session-scoped wins), or null. */
export function getToken(): string | null {
  return sessionStorage.getItem(TOKEN_KEY) ?? localStorage.getItem(TOKEN_KEY);
}

/** Store a fresh session token in the storage matching "keep me signed in". */
export function setToken(token: string, remember: boolean): void {
  sessionStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(TOKEN_KEY);
  (remember ? localStorage : sessionStorage).setItem(TOKEN_KEY, token.trim());
}

/** Drop the session (token + forced-change flag) from every storage. */
export function clearSession(): void {
  sessionStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(MUST_CHANGE_KEY);
}

/** True while the account must change its (default) password before proceeding. */
export function getMustChange(): boolean {
  return localStorage.getItem(MUST_CHANGE_KEY) === "1";
}

export function setMustChange(on: boolean): void {
  if (on) localStorage.setItem(MUST_CHANGE_KEY, "1");
  else localStorage.removeItem(MUST_CHANGE_KEY);
}

/** The `sub` claim of the current session token, or null. Display/preference scoping only —
 *  the payload is NOT verified here (the server verifies the signature on every request).
 *  Used so persisted UI preferences (e.g. the namespace selection) belong to the identity
 *  that chose them and never leak to the next sign-in. */
export function tokenSubject(): string | null {
  const token = getToken();
  if (!token) return null;
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  try {
    const payload = JSON.parse(atob(parts[1].replace(/-/g, "+").replace(/_/g, "/"))) as { sub?: unknown };
    return typeof payload.sub === "string" && payload.sub ? payload.sub : null;
  } catch {
    return null;
  }
}
