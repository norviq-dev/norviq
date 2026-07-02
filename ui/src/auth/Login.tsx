// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// LOGIN-1: the login GATE. Rendered by App whenever there is no valid session token, so a fresh install
// shows a real login screen instead of a blank/unauthenticated console. Branches on oidcEnabled:
//   - OIDC configured  -> "Sign in with SSO" (Auth Code + PKCE via oidc.login()).
//   - no IdP           -> the `norviq login` quick-start + a paste-token fallback.
// Also consumes a `#access_token=<jwt>` URL fragment (the CLI deep-link) so one command → signed in.

import { useEffect, useState } from "react";
import { login, oidcEnabled } from "./oidc";

const TOKEN_KEY = "nrvq_token";

function storeAndEnter(token: string): void {
  localStorage.setItem(TOKEN_KEY, token.trim());
  // Drop any token fragment from the URL, then land in the authenticated console.
  window.location.replace("/");
}

export function Login() {
  const [pasted, setPasted] = useState("");
  const [error, setError] = useState<string | null>(null);

  // CLI deep-link: `<console>/login#access_token=<jwt>` → store + enter.
  useEffect(() => {
    const hash = window.location.hash.startsWith("#") ? window.location.hash.slice(1) : "";
    const token = new URLSearchParams(hash).get("access_token");
    if (token) storeAndEnter(token);
  }, []);

  const onPaste = () => {
    const t = pasted.trim();
    if (t.split(".").length !== 3) {
      setError("That does not look like a token. Paste the token printed by `norviq login`.");
      return;
    }
    storeAndEnter(t);
  };

  return (
    <div style={{ minHeight: "100vh", display: "grid", placeItems: "center", background: "var(--bg, #0b0f17)" }}>
      <div style={{ width: 420, maxWidth: "90vw", padding: 32, borderRadius: 12, background: "var(--panel, #121826)", boxShadow: "0 10px 40px rgba(0,0,0,0.4)" }}>
        <h1 style={{ margin: 0, fontSize: 22, color: "var(--text, #fff)" }}>Norviq</h1>
        <p style={{ marginTop: 6, color: "var(--text-secondary, #9aa4b2)", fontSize: 13 }}>
          Runtime security for AI agent tool calls
        </p>

        {oidcEnabled ? (
          <div style={{ marginTop: 24 }}>
            <button
              onClick={() => void login()}
              aria-label="Sign in with SSO"
              style={{ width: "100%", padding: "12px 16px", borderRadius: 8, border: "none", cursor: "pointer", fontWeight: 600, background: "var(--allow, #00e5a0)", color: "#06121b" }}
            >
              Sign in with SSO
            </button>
            <p style={{ marginTop: 12, fontSize: 12, color: "var(--text-secondary, #9aa4b2)" }}>
              You will be redirected to your identity provider. Your group maps to a Norviq role and namespace.
            </p>
          </div>
        ) : (
          <div style={{ marginTop: 24 }}>
            <div style={{ fontSize: 13, color: "var(--text-secondary, #9aa4b2)", lineHeight: 1.5 }}>
              <strong style={{ color: "var(--text, #fff)" }}>First login</strong> — run one command, then open the
              printed sign-in link:
              <pre style={{ marginTop: 8, padding: 10, borderRadius: 8, background: "#0b0f17", color: "#cbd5e1", fontSize: 12, overflowX: "auto" }}>
                norviq login --console-url {window.location.origin}
              </pre>
              No password, no manual token — the signing key never leaves the cluster.
            </div>
            <label style={{ display: "block", marginTop: 18, fontSize: 12, color: "var(--text-secondary, #9aa4b2)" }}>
              …or paste the token it printed:
            </label>
            <textarea
              value={pasted}
              onChange={(e) => { setPasted(e.target.value); setError(null); }}
              placeholder="eyJhbGciOiJIUzI1NiIs…"
              aria-label="Access token"
              rows={3}
              style={{ width: "100%", marginTop: 6, padding: 8, borderRadius: 8, border: "1px solid #263042", background: "#0b0f17", color: "#cbd5e1", fontFamily: "monospace", fontSize: 12 }}
            />
            {error && <div style={{ color: "var(--block, #ff5c7c)", fontSize: 12, marginTop: 6 }}>{error}</div>}
            <button
              onClick={onPaste}
              disabled={!pasted.trim()}
              style={{ width: "100%", marginTop: 10, padding: "10px 16px", borderRadius: 8, border: "none", cursor: pasted.trim() ? "pointer" : "not-allowed", fontWeight: 600, background: pasted.trim() ? "var(--allow, #00e5a0)" : "#263042", color: pasted.trim() ? "#06121b" : "#6b7688" }}
            >
              Sign in
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
