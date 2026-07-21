# Norviq — Login & Onboarding

How operators sign in to the Norviq console and how a buyer assigns permissions via their identity
provider. Three paths: a **local username/password login** (the default, no IdP required), **SSO (OIDC)**
for teams, and a **CLI token** for automation.

---

## 1. First login — local username/password (default)

The console shows a real login screen on a fresh install. With no IdP configured you sign in with the
seeded admin account:

- **username:** `admin` (Helm `auth.adminUsername`)
- **password:** `norviq` (Helm `auth.adminPassword`)

`POST /api/v1/auth/login` verifies the password with a constant-time bcrypt compare against a hash stored
in the API database (the plaintext seed is hashed at first boot and never logged), and returns a
**short-TTL session token** (role/namespace claims, signed with `NRVQ_API_SECRET_KEY`). Repeated failures
for a username are **rate-limited and locked out** (HTTP 429 after `auth.loginMaxAttempts` within
`auth.loginWindowSeconds`).

**Forced change on first login.** The seeded admin is flagged `must_change`, so the console funnels you to
a **change-password screen** (with a loud "default admin password in use" banner) before any page renders.
`POST /api/v1/auth/change-password` re-checks the current password and requires a new one of at least
`auth.minPasswordLength` characters that is neither the current nor the default password.

**Production:** set `auth.adminPassword` (rendered into `norviq-secrets`) before deploying. With
`api.requireStrongSecret=true` the API **refuses to start** while the admin password is still the shipped
default — so a production install can never ship on `norviq`.

```yaml
auth:
  enabled: true            # set false for SSO/CLI-only (no local login)
  adminUsername: "admin"
  adminPassword: "<a strong password>"
  loginMaxAttempts: 5
  loginWindowSeconds: 300
  minPasswordLength: 12
```

### Automation / CI — CLI token (no password)
For scripts and pipelines, mint a short-lived admin token in-cluster (the signing key never leaves the
cluster); it prints a sign-in deep-link, or paste the token under the console login's **Advanced** section:

```
norviq login -n <release-namespace> --console-url http://localhost:3000
```

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
  consoleClientId: "<spa-public-client-id>" # the browser client the console signs in with
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
