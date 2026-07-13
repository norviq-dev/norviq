// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// LOGIN-2: the login gate, built to the design handoff (design_handoff_login) — three states in one view:
//   1. Default login  — username/password (primary), "keep me signed in", collapsible CLI/dev-token field,
//                       and SSO when an IdP is configured.
//   2. First login    — forced password change from the default admin credential (strength meter, rule
//                       chips, confirm-match), entered automatically when /auth/login returns must_change.
//   3. Loading overlay — branded "Y" edge-trace during sign-in / SSO redirect / save, resolving to success.
// Wired to the REAL API: POST /api/v1/auth/login, POST /api/v1/auth/change-password, GET /api/v1/me for
// CLI-token validation, and oidc.login() for Auth Code + PKCE. Client-side rules are UX only — the server's
// validation is authoritative. Also consumes the `#access_token=<jwt>` CLI deep-link fragment.

import { useEffect, useRef, useState } from "react";
import { AlertTriangle, LogIn } from "lucide-react";
import { login as ssoLogin, oidcEnabled } from "./oidc";
import { getMustChange, getToken, setMustChange, setToken } from "./session";
import { BrandLoader } from "../components/common/BrandLoader";

// Same relative-by-default base as api/client.ts (vite proxy in dev; the UI nginx `location /api/` in prod).
const API_BASE = (import.meta.env.VITE_API_BASE_URL ?? "").replace(/\/+$/, "");
const MIN_LEN = 12;

type View = "default" | "first";
// `boot` is the branded splash shown on EVERY mount of the login screen (a page load / refresh): the "Y"
// edge-trace + emerald glow, backed by a real /readyz probe — so a reload always plays the brand moment
// instead of snapping straight to the form. It resolves to `idle` (the form) after a short guaranteed beat.
type Phase = "boot" | "idle" | "signing" | "sso" | "saving" | "done_sign" | "done_save";

// How long the boot splash is guaranteed to show so the brand moment always lands, even when the backend
// answers instantly. Collapsed to a blink under prefers-reduced-motion (and in jsdom, where matchMedia is
// absent) so motion-sensitive users — and the test suite — aren't held on the splash.
function bootMinMs(): number {
  try {
    if (!window.matchMedia || window.matchMedia("(prefers-reduced-motion: reduce)").matches) return 150;
  } catch {
    return 150;
  }
  return 1100;
}

// A1: a floor on how long the in-flight sign-in loader is shown. Token / API-key auth resolves in ~1 frame
// (unlike bcrypt password), so without this the brand loader flashed sub-perceptibly and the user just saw
// "Sign in". We transition to the app (or an error) only after BOTH auth resolves AND this minimum elapses.
const MIN_LOADER_MS = 400;
const delay = (ms: number) => new Promise<void>((resolve) => window.setTimeout(resolve, ms));

/** Strength score 0–100 for the meter (UX only; the server enforces the real policy). */
export function passwordStrength(p: string): number {
  let sc = 0;
  if (p.length >= 8) sc += 25;
  if (p.length >= 12) sc += 25;
  if (/[0-9]/.test(p)) sc += 15;
  if (/[a-z]/.test(p) && /[A-Z]/.test(p)) sc += 20;
  if (/[^A-Za-z0-9]/.test(p)) sc += 15;
  return Math.min(sc, 100);
}

/** The three requirement chips: 12+ chars · upper & lower · number or symbol. */
export function passwordRules(p: string): [boolean, boolean, boolean] {
  return [p.length >= MIN_LEN, /[a-z]/.test(p) && /[A-Z]/.test(p), /[0-9]/.test(p) || /[^A-Za-z0-9]/.test(p)];
}

async function detailOf(resp: Response): Promise<string> {
  try {
    const body = (await resp.json()) as { detail?: unknown };
    return typeof body.detail === "string" ? body.detail : "";
  } catch {
    return "";
  }
}

// The canonical Norviq "Y" (same paths as IconRail's NorviqMark; viewBox 0 0 166 200).
const Y1 = "M0.0 0.0 L77.5 72.3 L77.5 200.0 L74.3 197.2 L57.3 181.0 L57.3 87.4 L0.0 34.4 L0.0 0.4 Z";
const Y2 = "M165.6 0.0 L166.0 34.0 L108.3 87.4 L108.3 180.6 L88.1 200.0 L88.1 72.3 L165.2 0.4 Z";

const CSS = `
@keyframes nvFade { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; transform: translateY(0); } }
@keyframes nvSpin { to { transform: rotate(360deg); } }
@keyframes nvTrace { to { stroke-dashoffset: -100; } }
@keyframes nvGlow { 0%,100% { opacity: 0.5; transform: scale(0.94); } 50% { opacity: 1; transform: scale(1.06); } }
@keyframes nvIdle { 0%,100% { filter: drop-shadow(0 0 0 transparent); } 50% { filter: drop-shadow(0 0 4px #00e5a077); } }
.nv-input { width: 100%; height: 42px; padding: 0 13px; background: #0b0e14; border: 1px solid #1c2029;
  border-radius: 10px; color: #e8edf5; font-family: inherit; font-size: 14px; transition: 150ms ease; outline: none; box-sizing: border-box; }
.nv-input::placeholder { color: #55606f; }
.nv-input:focus { border-color: #00e5a0; box-shadow: 0 0 0 3px #00e5a020; }
.nv-ghost { background: none; border: none; padding: 0; cursor: pointer; color: #8a94a6; font-family: inherit; font-size: 12px; transition: 150ms ease; }
.nv-ghost:hover { color: #00e5a0; }
.nv-show { position: absolute; right: 5px; top: 5px; height: 32px; padding: 0 10px; background: transparent; border: none;
  color: #8a94a6; font-family: inherit; font-size: 11px; font-weight: 600; cursor: pointer; border-radius: 6px; transition: 150ms ease; }
.nv-show:hover { color: #e8edf5; }
.nv-primary { width: 100%; height: 44px; display: flex; align-items: center; justify-content: center; gap: 9px; border: none;
  border-radius: 10px; background: #00e5a0; color: #04241a; font-family: inherit; font-size: 14px; font-weight: 700; transition: 150ms ease; }
.nv-primary:hover:not(:disabled) { background: #3dedb5; }
.nv-primary:active:not(:disabled) { transform: translateY(1px); }
.nv-primary:disabled { opacity: 0.45; cursor: not-allowed; }
.nv-sso { width: 100%; height: 44px; display: flex; align-items: center; justify-content: center; gap: 9px;
  border: 1px solid #262b34; border-radius: 10px; background: transparent; color: #e8edf5; font-family: inherit;
  font-size: 14px; font-weight: 600; cursor: pointer; transition: 150ms ease; }
.nv-sso:hover { border-color: #00e5a0; color: #00e5a0; }
.nv-back { height: 36px; padding: 0 18px; border: 1px solid #262b34; border-radius: 10px; background: transparent;
  color: #e8edf5; font-family: inherit; font-size: 13px; font-weight: 600; cursor: pointer; transition: 150ms ease; }
.nv-back:hover { background: #141821; }
.nv-sso:disabled { opacity: 0.45; cursor: not-allowed; }
.nv-sso:disabled:hover { border-color: #262b34; color: #e8edf5; }
@media (prefers-reduced-motion: reduce) { .nv-root *, .nv-root *::before, .nv-root *::after {
  animation-duration: 0.001ms !important; animation-iteration-count: 1 !important; transition-duration: 0.001ms !important; } }
`;

const label: React.CSSProperties = { display: "block", fontSize: 12, color: "#8a94a6", margin: "0 0 6px", fontWeight: 600 };
const errorBox: React.CSSProperties = {
  display: "flex", alignItems: "center", gap: 8, fontSize: 13, color: "#ff3b5c", background: "#ff3b5c12",
  border: "1px solid #ff3b5c26", borderRadius: 8, padding: "9px 12px"
};

export function Login() {
  // Arriving with a live session that is still flagged must_change (e.g. a reload mid-change) lands
  // directly on the First-login view; otherwise the Default login.
  const [view, setViewRaw] = useState<View>(() => (getToken() && getMustChange() ? "first" : "default"));
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [showPwd, setShowPwd] = useState(false);
  const [remember, setRemember] = useState(false);
  const [devOpen, setDevOpen] = useState(false);
  const [devToken, setDevToken] = useState("");
  const [curPwd, setCurPwd] = useState("");
  const [newPwd, setNewPwd] = useState("");
  const [confirmPwd, setConfirmPwd] = useState("");
  const [showNewPwd, setShowNewPwd] = useState(false);
  const [capsOn, setCapsOn] = useState(false);
  const [phase, setPhase] = useState<Phase>("boot");
  // Live backend reachability from the boot /readyz probe: null = probing, true = ready, false = degraded/
  const [error, setError] = useState("");
  // The banner is client-known state: set once a login on this browser reported the default credential.
  const [defaultPwInUse, setDefaultPwInUse] = useState<boolean>(() => getMustChange());
  const formRef = useRef<HTMLDivElement>(null);

  const provider = (typeof window !== "undefined" && window.__NRVQ_CONFIG__?.oidcProviderName) || "SSO";
  const booting = phase === "boot";
  const busy = phase === "signing" || phase === "sso" || phase === "saving";
  const done = phase === "done_sign" || phase === "done_save";

  // Branded boot splash on every mount of the login screen. Probe the REAL backend (/readyz) so the "Y"
  // edge-trace reflects an actual connection, then reveal the form after a guaranteed brand beat. Readiness
  // runs concurrently and only tints the message — dismissal is time-based so a slow/down backend can't hang.
  useEffect(() => {
    const hash = window.location.hash.startsWith("#") ? window.location.hash.slice(1) : "";
    if (new URLSearchParams(hash).get("access_token")) return; // CLI deep-link: the redirect effect owns this
    let cancelled = false;
    // Time-based reveal of the form after a guaranteed brand beat (a slow/down backend can't hang it).
    const t = window.setTimeout(() => { if (!cancelled) setPhase((p) => (p === "boot" ? "idle" : p)); }, bootMinMs());
    return () => { cancelled = true; window.clearTimeout(t); };
  }, []);

  // CLI deep-link: `<console>/login#access_token=<jwt>` → store + enter (automation path).
  useEffect(() => {
    const hash = window.location.hash.startsWith("#") ? window.location.hash.slice(1) : "";
    const token = new URLSearchParams(hash).get("access_token");
    if (token) {
      setToken(token, true);
      setMustChange(false);
      window.location.replace("/");
    }
  }, []);

  // Focus trap while the overlay is up: the form beneath goes inert (attribute toggle; React 18-safe).
  useEffect(() => {
    formRef.current?.toggleAttribute("inert", busy || done);
  }, [busy, done]);

  const caps = (e: React.KeyboardEvent) => {
    if (e.getModifierState) setCapsOn(e.getModifierState("CapsLock"));
  };

  const enter = (fn: () => void) => (e: React.KeyboardEvent) => {
    caps(e);
    if (e.key === "Enter") {
      e.preventDefault();
      fn();
    }
  };

  /** Success → brief branded success state → into the app shell. */
  const finish = (p: Phase) => {
    setPhase(p);
    window.setTimeout(() => window.location.replace("/"), 900);
  };

  const signIn = async () => {
    if (busy || done) return;
    const token = devToken.trim();
    // A1: start the minimum-loader clock the moment we commit to signing, so a fast token/api-key auth still
    // shows the brand loader for at least MIN_LOADER_MS before we transition to the app (or reveal an error).
    // CLI/dev token path: validate the pasted token against the real API (GET /me), same success path.
    if (devOpen && token && !(username.trim() && password)) {
      setPhase("signing");
      setError("");
      const minTimer = delay(MIN_LOADER_MS);
      try {
        const resp = await fetch(`${API_BASE}/api/v1/me`, { headers: { Authorization: `Bearer ${token}` } });
        await minTimer; // hold the loader ≥ min even when /me returns in ~1 frame
        if (!resp.ok) {
          setPhase("idle");
          setError("That token is not valid. Mint one with `norviq login`.");
          return;
        }
        setToken(token, remember);
        setMustChange(false);
        finish("done_sign");
      } catch {
        await minTimer;
        setPhase("idle");
        setError("Could not reach the server. Check that the API is running.");
      }
      return;
    }
    if (!username.trim() || !password) {
      setError("Enter both username and password to continue.");
      return;
    }
    setPhase("signing");
    setError("");
    const minTimer = delay(MIN_LOADER_MS);
    try {
      const resp = await fetch(`${API_BASE}/api/v1/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: username.trim(), password })
      });
      await minTimer; // A1: floor the loader duration (no-op when bcrypt already took longer than the min)
      if (resp.status === 429) {
        setPhase("idle");
        setError("Too many failed attempts. Try again in a few minutes.");
        return;
      }
      if (!resp.ok) {
        setPhase("idle");
        setError("Invalid username or password.");
        return;
      }
      const body = (await resp.json()) as {
        access_token: string;
        must_change?: boolean;
        default_password_in_use?: boolean;
      };
      setToken(body.access_token, remember);
      if (body.must_change) {
        // Forced first-login change: switch to the First-login view instead of proceeding.
        setMustChange(true);
        setDefaultPwInUse(Boolean(body.default_password_in_use));
        setCurPwd(password); // they just proved it — prefill so the change is one step
        setPassword("");
        setPhase("idle");
        setViewRaw("first");
        return;
      }
      setMustChange(false);
      finish("done_sign");
    } catch {
      await minTimer;
      setPhase("idle");
      setError("Could not reach the server. Check that the API is running.");
    }
  };

  const saveNew = async () => {
    if (busy || done) return;
    const [r1, r2, r3] = passwordRules(newPwd);
    if (!(r1 && r2 && r3)) {
      setError(`New password must be at least ${MIN_LEN} characters with upper & lower case and a number or symbol.`);
      return;
    }
    if (newPwd !== confirmPwd) {
      setError("Passwords don't match.");
      return;
    }
    setPhase("saving");
    setError("");
    try {
      const token = getToken() ?? "";
      const resp = await fetch(`${API_BASE}/api/v1/auth/change-password`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
        body: JSON.stringify({ current_password: curPwd, new_password: newPwd })
      });
      if (!resp.ok) {
        setPhase("idle");
        const detail = await detailOf(resp);
        if (resp.status === 401 && !token) setError("Sign in with your current credentials first.");
        else setError(detail || "Could not change the password. Check your current password.");
        return;
      }
      setMustChange(false);
      finish("done_save");
    } catch {
      setPhase("idle");
      setError("Could not reach the server. Check that the API is running.");
    }
  };

  const sso = async () => {
    if (busy || done) return;
    setPhase("sso");
    setError("");
    try {
      await ssoLogin(); // Auth Code + PKCE redirect; the overlay stays up until the browser navigates away
    } catch {
      setPhase("idle");
      setError("Could not start the SSO flow. Check the IdP configuration.");
    }
  };

  // Derived (per the design spec)
  const sc = passwordStrength(newPwd);
  const scColor = !newPwd ? "#55606f" : sc < 40 ? "#ff3b5c" : sc < 70 ? "#ffb020" : "#00e5a0";
  const scLabel = !newPwd ? "" : sc < 40 ? "Weak" : sc < 70 ? "Fair" : "Strong";
  const [r1, r2, r3] = passwordRules(newPwd);
  const matchOk = confirmPwd.length > 0 && newPwd === confirmPwd;
  const canSave = r1 && r2 && r3 && matchOk && curPwd.length > 0;
  const credReady = Boolean(username.trim() && password) || Boolean(devOpen && devToken.trim());
  const chip = (ok: boolean, text: string) => (
    <span
      style={{
        display: "inline-flex", alignItems: "center", gap: 5, fontSize: 10.5,
        color: ok ? "#00e5a0" : "#55606f", border: `1px solid ${ok ? "#00e5a030" : "#1c2029"}`,
        borderRadius: 999, padding: "2px 8px", transition: "150ms ease"
      }}
    >
      {ok ? "✓" : "○"} {text}
    </span>
  );

  return (
    <div
      className="nv-root"
      style={{
        minHeight: "100vh", width: "100%", display: "flex", flexDirection: "column", alignItems: "center",
        justifyContent: "flex-start", padding: 28, fontFamily: "'Outfit', system-ui, sans-serif", color: "#e8edf5",
        background: "radial-gradient(circle at 50% 8%, #10141b 0%, #08090c 58%)", position: "relative",
        overflowX: "hidden", overflowY: "auto", boxSizing: "border-box"
      }}
    >
      <style>{CSS}</style>

      {/* background brand watermark */}
      <svg
        viewBox="0 0 166 200" width="560" fill="currentColor" aria-hidden="true"
        style={{ position: "absolute", left: "50%", top: "66%", transform: "translate(-50%, -50%)", color: "#00e5a0", opacity: 0.085, pointerEvents: "none", zIndex: 0 }}
      >
        <path d={Y1} />
        <path d={Y2} />
      </svg>

      <div ref={formRef} style={{ display: "flex", flexDirection: "column", alignItems: "center", margin: "auto 0", width: "100%", maxWidth: 384, position: "relative", zIndex: 1 }}>
        {/* No manual view switcher: the first-login (change password) view is SERVER-driven — it appears
            only when /auth/login flags must_change, and never again once the password is changed. */}

        {/* glass card */}
        <div
          style={{
            width: "100%", maxWidth: 384, background: "rgba(13,17,24,0.62)", backdropFilter: "blur(20px)",
            WebkitBackdropFilter: "blur(20px)", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 16,
            padding: "26px 26px 22px", position: "relative", zIndex: 1,
            boxShadow: "0 24px 60px -22px rgba(0,0,0,0.75), inset 0 1px 0 rgba(255,255,255,0.04)"
          }}
        >
          {/* L4: brand lockup — CENTERED (was left-aligned) so the mark shares the loader's anchor and never
              jumps between the login form, the loading overlay, and the app shell. Token color (brand teal). */}
          <div style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 10, marginBottom: 22 }}>
            <svg viewBox="0 0 166 200" width={20} height={24} fill="currentColor" role="img" aria-label="Norviq"
              style={{ color: "var(--accent)", animation: "nvIdle 4.5s ease-in-out infinite" }}>
              <path d={Y1} />
              <path d={Y2} />
            </svg>
            <span style={{ fontSize: 19, fontWeight: 700 }}>norviq</span>
          </div>

          {view === "default" ? (
            <div key="default" style={{ animation: "nvFade 0.3s ease both" }}>
              <div style={{ fontSize: 16, fontWeight: 700, marginBottom: 16 }}>Sign in</div>

              {defaultPwInUse && (
                <div
                  role="alert"
                  style={{
                    display: "flex", gap: 9, alignItems: "center", background: "#ffb0200f", border: "1px solid #ffb02026",
                    color: "#ffcb66", borderRadius: 10, padding: "9px 12px", fontSize: 12, margin: "0 0 18px", lineHeight: 1.4
                  }}
                >
                  <AlertTriangle size={15} color="#ffb020" strokeWidth={1.8} style={{ flex: "none" }} />
                  <div>Default password in use.</div>
                </div>
              )}

              <label htmlFor="nv-user" style={label}>Username</label>
              <input id="nv-user" type="text" className="nv-input" autoFocus value={username} aria-label="Username"
                onChange={(e) => { setUsername(e.target.value); setError(""); }} onKeyDown={enter(() => void signIn())}
                autoComplete="username" style={{ marginBottom: 14 }} />

              <label htmlFor="nv-pass" style={label}>Password</label>
              <div style={{ position: "relative", marginBottom: 4 }}>
                <input id="nv-pass" type={showPwd ? "text" : "password"} className="nv-input" value={password} aria-label="Password"
                  onChange={(e) => { setPassword(e.target.value); setError(""); }} onKeyDown={enter(() => void signIn())}
                  autoComplete="current-password" style={{ padding: "0 44px 0 13px" }} />
                <button type="button" tabIndex={-1} className="nv-show" onClick={() => setShowPwd(!showPwd)}>
                  {showPwd ? "HIDE" : "SHOW"}
                </button>
              </div>
              {capsOn && <div style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 11, color: "#ffb020", margin: "6px 0 0" }}>⇪ Caps Lock is on</div>}

              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", margin: "12px 0 16px" }}>
                <button type="button" onClick={() => setRemember(!remember)} aria-pressed={remember}
                  style={{ display: "inline-flex", alignItems: "center", gap: 8, background: "none", border: "none", padding: 0, cursor: "pointer", color: "#8a94a6", fontFamily: "inherit", fontSize: 12 }}>
                  <span
                    style={{
                      width: 15, height: 15, borderRadius: 5, border: `1px solid ${remember ? "#00e5a0" : "#262b34"}`,
                      background: remember ? "#00e5a0" : "transparent", display: "inline-flex", alignItems: "center",
                      justifyContent: "center", color: "#04241a", fontSize: 10, fontWeight: 700
                    }}
                  >
                    {remember ? "✓" : ""}
                  </span>
                  Keep me signed in
                </button>
                <button type="button" className="nv-ghost" onClick={() => setDevOpen(!devOpen)} aria-expanded={devOpen}>
                  Use a token / CLI
                </button>
              </div>

              {devOpen && (
                <div style={{ margin: "0 0 16px" }}>
                  <input type="text" className="nv-input" value={devToken} aria-label="Access token"
                    onChange={(e) => { setDevToken(e.target.value); setError(""); }} onKeyDown={enter(() => void signIn())}
                    placeholder="nrvq_dev_••••••••••••••••"
                    style={{ height: 40, fontFamily: "ui-monospace, 'SF Mono', 'JetBrains Mono', monospace", fontSize: 12 }} />
                </div>
              )}

              {error && <div role="alert" style={{ ...errorBox, marginBottom: 14 }}>{error}</div>}

              {/* L2: in-flight sign-in shows the shared BrandLoader (not a "Signing in…" text + generic spinner);
                  the button is disabled + aria-busy, and the loader's sr-only label announces the state. */}
              <button className="nv-primary" onClick={() => void signIn()} disabled={!credReady || busy} aria-busy={phase === "signing"}>
                {phase === "signing" ? (
                  <BrandLoader inline size={20} label="Signing in" />
                ) : (
                  <span style={{ whiteSpace: "nowrap" }}>Sign in</span>
                )}
              </button>

              {/* SSO is always DISCOVERABLE but honest: live once an IdP is configured (oidc.enabled),
                  visibly disabled with setup guidance until then — never a dead-looking active button. */}
              <div style={{ display: "flex", alignItems: "center", gap: 12, margin: "16px 0", color: "#55606f", fontSize: 11 }}>
                <div style={{ flex: 1, height: 1, background: "#1c2029" }} />or<div style={{ flex: 1, height: 1, background: "#1c2029" }} />
              </div>
              <button type="button" className="nv-sso" disabled={!oidcEnabled} onClick={() => void sso()}>
                <LogIn size={15} strokeWidth={1.8} />
                Sign in with SSO
              </button>
              {!oidcEnabled && (
                <p style={{ marginTop: 8, fontSize: 11, color: "#55606f", textAlign: "center" }}>
                  SSO isn’t configured yet — an admin can enable it via Helm (<code style={{ fontSize: 10.5 }}>oidc.enabled</code>).
                </p>
              )}

              {/* D1: no-egress password recovery. There is deliberately NO email/SMTP (that would be outbound
                  network); recovery is an authenticated in-cluster reset run by an operator with kubectl. */}
              <details style={{ marginTop: 16, fontSize: 11.5, color: "#6b7280" }}>
                <summary style={{ cursor: "pointer", textAlign: "center", listStyle: "none" }}>Can’t sign in?</summary>
                <div style={{ marginTop: 10, padding: "10px 12px", background: "#12141a", border: "1px solid #1c2029", borderRadius: 8, lineHeight: 1.55 }}>
                  Password recovery is an in-cluster admin reset (no email is sent — Norviq makes no outbound
                  network calls). An operator with cluster access runs:
                  <code style={{ display: "block", marginTop: 8, padding: "7px 9px", background: "#0c0e12", borderRadius: 6, fontSize: 10.8, color: "#9fe8cf", whiteSpace: "pre-wrap", wordBreak: "break-all" }}>norviq admin reset-password</code>
                  It prints a one-time password (and forces a change at next login). See docs for the
                  <code style={{ fontSize: 10.5 }}> kubectl exec</code> equivalent.
                </div>
              </details>
            </div>
          ) : (
            <div key="first" style={{ animation: "nvFade 0.3s ease both" }}>
              <div style={{ fontSize: 16, fontWeight: 700, marginBottom: 16 }}>Set a new password</div>

              <label htmlFor="nv-cur" style={label}>Current password</label>
              <input id="nv-cur" type="password" className="nv-input" value={curPwd} aria-label="Current password"
                onChange={(e) => { setCurPwd(e.target.value); setError(""); }} onKeyDown={enter(() => void saveNew())}
                autoComplete="current-password" style={{ marginBottom: 14 }} />

              <label htmlFor="nv-new" style={label}>New password</label>
              <div style={{ position: "relative" }}>
                <input id="nv-new" type={showNewPwd ? "text" : "password"} className="nv-input" value={newPwd} aria-label="New password"
                  onChange={(e) => { setNewPwd(e.target.value); setError(""); }} onKeyDown={enter(() => void saveNew())}
                  autoComplete="new-password" placeholder="At least 12 characters" style={{ padding: "0 44px 0 13px" }} />
                <button type="button" tabIndex={-1} className="nv-show" onClick={() => setShowNewPwd(!showNewPwd)}>
                  {showNewPwd ? "HIDE" : "SHOW"}
                </button>
              </div>
              {capsOn && <div style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 11, color: "#ffb020", margin: "6px 0 0" }}>⇪ Caps Lock is on</div>}

              <div style={{ display: "flex", alignItems: "center", gap: 10, margin: "9px 0 14px" }}>
                <div style={{ flex: 1, height: 5, borderRadius: 999, background: "#0b0e14", overflow: "hidden" }}>
                  <div style={{ height: "100%", width: `${newPwd ? sc : 0}%`, background: scColor, transition: "200ms ease" }} />
                </div>
                <span style={{ fontSize: 11, fontWeight: 600, color: scColor, minWidth: 42, textAlign: "right" }}>{scLabel}</span>
              </div>
              <div style={{ display: "flex", gap: 6, flexWrap: "wrap", margin: "0 0 14px" }}>
                {chip(r1, "12+ chars")}
                {chip(r2, "Upper & lower")}
                {chip(r3, "Number or symbol")}
              </div>

              <label htmlFor="nv-confirm" style={label}>Confirm new password</label>
              <div style={{ position: "relative" }}>
                <input id="nv-confirm" type="password" className="nv-input" value={confirmPwd} aria-label="Confirm new password"
                  onChange={(e) => { setConfirmPwd(e.target.value); setError(""); }} onKeyDown={enter(() => void saveNew())}
                  autoComplete="new-password" placeholder="Re-enter new password"
                  style={{ padding: "0 40px 0 13px", borderColor: confirmPwd.length > 0 ? (matchOk ? "#00e5a0" : "#ff3b5c40") : "#1c2029" }} />
                {matchOk && (
                  <span style={{ position: "absolute", right: 13, top: "50%", transform: "translateY(-50%)", color: "#00e5a0", fontSize: 15, fontWeight: 700 }}>✓</span>
                )}
              </div>

              {error && <div role="alert" style={{ ...errorBox, marginTop: 13 }}>{error}</div>}

              <button className="nv-primary" style={{ marginTop: 16 }} onClick={() => void saveNew()} disabled={!canSave || busy}>
                {phase === "saving" ? "Saving…" : "Save & continue"}
              </button>
            </div>
          )}

          {/* shared footer */}
          <div style={{ marginTop: 20, textAlign: "center", color: "#55606f", fontSize: 11, lineHeight: 1.5 }}>
            <div><b style={{ color: "#8a94a6" }}>Norviq</b> · v0.1.0</div>
          </div>
        </div>
      </div>

      {/* boot / loading / success overlay */}
      {(booting || busy || done) && (
        <div
          role="dialog" aria-modal="true"
          style={{
            display: "flex", position: "absolute", inset: 0, zIndex: 10, background: "rgba(8,9,12,0.88)",
            backdropFilter: "blur(6px)", WebkitBackdropFilter: "blur(6px)", alignItems: "center", justifyContent: "center"
          }}
        >
          {/* LOGO-ONLY throughout the whole sign-in → portal-open sequence: the overlay shows ONLY the centered
              branded logo for boot / signing / redirecting / success. Every status caption ("Establishing secure
              session", "Signed in", "Session established… ", "Loading Norviq", the SSO/save variants) is carried
              solely by the BrandLoader's aria-label on its role=status live region — sr-only, announced to screen
              readers, never rendered visibly (no visible innerText, no ✓, no fallback text/button). B2 centers the
              mark on both axes (direct flex child of the full-viewport overlay). */}
          <BrandLoader
            size={booting ? 60 : 56}
            label={
              booting
                ? "Loading Norviq"
                : phase === "sso"
                ? `Redirecting to ${provider}, completing Auth Code and PKCE`
                : phase === "saving"
                ? "Updating password"
                : phase === "signing"
                ? "Signing in, establishing secure session"
                : phase === "done_save"
                ? "Password updated, loading the security command center"
                : "Signed in, session established, loading the security command center"
            }
          />
        </div>
      )}
    </div>
  );
}
