# Norviq — Login & Onboarding

How operators sign in to the Norviq console and how a buyer assigns permissions via their identity
provider. Two paths: **SSO (OIDC)** for teams, and a **no-IdP quick start** for the first login / demos.

---

## 1. First login (no IdP yet) — one command

The console shows a login screen on a fresh install. With no IdP configured it offers a frictionless
first login that never exposes the signing key and needs no hand-crafted JWT:

```
norviq login -n <release-namespace> --console-url http://localhost:3000
```

`norviq login` runs `kubectl exec` into the api pod and mints a **short-lived admin token in-cluster**
(the pod holds `NRVQ_API_SECRET_KEY`; the CLI only captures the resulting token). It prints a sign-in
deep-link — open it and you are in — or paste the printed token into the console login screen.

This is intended for bootstrap / demos. For teams, enable SSO (below) so access is governed by your IdP.

---

## 2. SSO (OIDC) — recommended for teams

Norviq validates IdP-issued tokens (RS256/ES256 via JWKS, alg-confusion-safe) and maps **IdP groups →
Norviq role + namespace** server-side (never trusting a client-side claim). Works with any standard
OIDC IdP — Entra ID, Okta, Auth0, Keycloak, Google — by configuration, not code.

### 2a. Register a public (SPA) client in your IdP
- App type: **SPA / public client** (Authorization Code + PKCE, no client secret).
- **Redirect URI:** `https://<your-console-host>/auth/callback` (for a local port-forward: `http://localhost:3000/auth/callback`).
- Note the **issuer** URL and the **client id**.
- Add the user's groups to the token (a `groups` claim, or set `oidc.groupClaim`).

### 2b. Enable OIDC via Helm values
```yaml
oidc:
  enabled: true
  issuer: "https://<tenant>/"              # the token `iss`
  audience: "<api-client-or-audience-id>"  # the API's expected `aud`
  consoleClientId: "<spa-public-client-id>" # LOGIN-1: the browser client the console signs in with
  jwksUrl: "https://<tenant>/.well-known/jwks.json"
  groupClaim: groups
  groupMappings:
    norviq-admins:   { role: admin }                       # admin => all namespaces
    team-a-viewers:  { role: viewer, namespace: team-a }    # viewer scoped to one tenant
  legacyHs256Enabled: true   # keep the CLI/quick-start path working alongside SSO; set false to disable
```
`oidc.issuer` + `oidc.consoleClientId` are injected into the UI at runtime (config.js) — **no UI rebuild
needed**. Once enabled, the console shows **"Sign in with SSO"**; after sign-in, the header shows the
resolved **role + namespace** (from `/api/v1/me`).

### 2c. Group → role/namespace mapping semantics
- **admin** wins over viewer if a user is in multiple groups; an admin is namespace-agnostic (`*`).
- A viewer maps to exactly one namespace; **conflicting** non-admin namespace mappings **fail closed**.
- An authenticated but **unmapped** user gets the least-privilege floor: `viewer`, no namespace.

### 2d. IdP-specific notes
- **Entra ID (Azure AD):** emit group object-ids or names in the `groups` claim (Token configuration →
  add groups claim). Use those values as the `groupMappings` keys.
- **Okta:** add a `groups` claim to the authorization server (Filter: matches regex `.*`).
- **Auth0:** add a rule/action that copies the user's roles/groups into a `groups` claim.
- **Keycloak:** add a "Group Membership" mapper (claim name `groups`, full path off) to the SPA client.

---

## 3. What the console shows

- **Login screen** whenever there is no valid session (never a blank page). Any API `401` returns you here.
- **Who am I:** the header user menu shows your name, **role**, and **namespace** — the exact scope the
  server resolved for your token. Full profile on **Settings → Account**.
- **Logout** clears the session (and signs out at the IdP for SSO).

---

## 4. Deferred (post-GA)
In-console **user CRUD / invitations / SCIM provisioning** are intentionally out of scope for GA — for
now, user lifecycle is managed in your IdP and mapped via `oidc.groupMappings`. Tracked as a fast-follow.
