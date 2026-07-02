// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// OIDC Authorization Code + PKCE login (IDENTITY epic A3). Platform-agnostic: standard OIDC discovery,
// so pointing at Entra/Okta/Auth0 instead of Keycloak is a config swap (VITE_OIDC_ISSUER/CLIENT_ID).
// The IdP-issued ACCESS token is stored under "nrvq_token" so the existing authHeaders() keeps working.

import { UserManager, WebStorageStateStore } from "oidc-client-ts";

// LOGIN-1: OIDC config is runtime-first (window.__NRVQ_CONFIG__, written by the container entrypoint from
// Helm OIDC_ISSUER/OIDC_CLIENT_ID) with a build-time VITE_* fallback — one built image, per-cluster config,
// so a buyer enables SSO by setting Helm values without rebuilding the UI.
const runtime = (typeof window !== "undefined" && window.__NRVQ_CONFIG__) || {};
const issuer = runtime.oidcIssuer || (import.meta.env.VITE_OIDC_ISSUER as string | undefined);
const clientId = runtime.oidcClientId || (import.meta.env.VITE_OIDC_CLIENT_ID as string | undefined);

/** True when an IdP is configured. When false the app shows the no-IdP quick-start login. */
export const oidcEnabled = Boolean(issuer && clientId);

const TOKEN_KEY = "nrvq_token";
const redirectUri =
  runtime.oidcRedirectUri ||
  (import.meta.env.VITE_OIDC_REDIRECT_URI as string) ||
  `${window.location.origin}/auth/callback`;

let mgr: UserManager | null = null;

function userManager(): UserManager {
  if (!mgr) {
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
  await userManager().signinRedirect();
}

/** Handle the IdP redirect: exchange the code (PKCE) and store the access token for API calls. */
export async function handleCallback(): Promise<void> {
  const user = await userManager().signinRedirectCallback();
  if (user?.access_token) {
    localStorage.setItem(TOKEN_KEY, user.access_token);
  }
}

/** Clear the local session and sign out at the IdP. */
export async function oidcLogout(): Promise<void> {
  localStorage.removeItem(TOKEN_KEY);
  try {
    await userManager().signoutRedirect();
  } catch {
    window.location.href = "/";
  }
}
