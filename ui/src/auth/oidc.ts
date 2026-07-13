// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// OIDC Authorization Code + PKCE login (IDENTITY epic A3). Platform-agnostic: standard OIDC discovery,
// so pointing at Entra/Okta/Auth0 instead of Keycloak is a config swap (VITE_OIDC_ISSUER/CLIENT_ID).
// The IdP-issued ACCESS token is stored under "nrvq_token" so the existing authHeaders() keeps working.

// SLIM-OIDC: oidc-client-ts (~72KB) is imported ONLY as a TYPE here (fully erased at build), so a
// password-only install (no IdP) never ships it in the app-shell chunk. The runtime value is pulled via a
// dynamic import() inside userManager(), which only runs when SSO is configured AND a login is invoked.
import type { UserManager } from "oidc-client-ts";
import { clearSession, setToken } from "./session";

// LOGIN-1: OIDC config is runtime-first (window.__NRVQ_CONFIG__, written by the container entrypoint from
// Helm OIDC_ISSUER/OIDC_CLIENT_ID) with a build-time VITE_* fallback — one built image, per-cluster config,
// so a buyer enables SSO by setting Helm values without rebuilding the UI.
const runtime = (typeof window !== "undefined" && window.__NRVQ_CONFIG__) || {};
const issuer = runtime.oidcIssuer || (import.meta.env.VITE_OIDC_ISSUER as string | undefined);
const clientId = runtime.oidcClientId || (import.meta.env.VITE_OIDC_CLIENT_ID as string | undefined);

/** True when an IdP is configured. When false the app shows the no-IdP quick-start login. */
export const oidcEnabled = Boolean(issuer && clientId);

const redirectUri =
  runtime.oidcRedirectUri ||
  (import.meta.env.VITE_OIDC_REDIRECT_URI as string) ||
  `${window.location.origin}/auth/callback`;

let mgr: UserManager | null = null;

async function userManager(): Promise<UserManager> {
  if (!mgr) {
    // Runtime import — excluded from the app-shell chunk; only fetched when SSO login actually runs.
    const { UserManager, WebStorageStateStore } = await import("oidc-client-ts");
    mgr = new UserManager({
      authority: issuer!,
      client_id: clientId!,
      redirect_uri: redirectUri,
      post_logout_redirect_uri: window.location.origin,
      response_type: "code", // Auth Code + PKCE (oidc-client-ts uses PKCE for public clients)
      scope: "openid profile email",
      userStore: new WebStorageStateStore({ store: window.localStorage }),
      automaticSilentRenew: false
    });
  }
  return mgr;
}

/** Redirect to the IdP to begin the Auth Code + PKCE flow. */
export async function login(): Promise<void> {
  const um = await userManager();
  await um.signinRedirect();
}

/** Handle the IdP redirect: exchange the code (PKCE) and store the access token for API calls. */
export async function handleCallback(): Promise<void> {
  const um = await userManager();
  const user = await um.signinRedirectCallback();
  if (user?.access_token) {
    setToken(user.access_token, true); // SSO sessions persist (the IdP governs their lifetime)
  }
}

/** Clear the local session and sign out at the IdP. */
export async function oidcLogout(): Promise<void> {
  clearSession();
  try {
    const um = await userManager();
    await um.signoutRedirect();
  } catch {
    window.location.href = "/";
  }
}
