# Norviq — Login & Onboarding

How operators sign in to the Norviq console and how a buyer assigns permissions via their identity
provider. Three paths: a **local username/password login** (the default, no IdP required), **SSO (OIDC)**
for teams, and a **CLI token** for automation.

---

## 1. First login — local username/password (default)

The console shows a real login screen on a fresh install. With no IdP configured you sign in with the
seeded admin account:

- **username:** `admin` (Helm `auth.adminUsername`)
- **password:** **auto-generated at install** — the chart does *not* ship a usable default.

`auth.adminPassword` defaults to the sentinel `"norviq"`, and the chart treats that sentinel as
"generate one for me": `templates/secret.yaml` substitutes a random 20-character password into
`norviq-secrets`, and re-uses it across `helm upgrade` (it only re-generates while the stored value is
still the sentinel). Read your install's password with:

```bash
kubectl get secret norviq-secrets -n <release-namespace> \
  -o jsonpath='{.data.NRVQ_AUTH_ADMIN_PASSWORD}' | base64 -d
```

Set `auth.adminPassword` to an explicit non-default value and it is used verbatim instead.

`POST /api/v1/auth/login` verifies the password with a constant-time bcrypt compare against a hash stored
in the API database (the plaintext seed is hashed at first boot and never logged), and returns a
**short-TTL session token** (role/namespace claims, signed with `NRVQ_API_SECRET_KEY`). Repeated failures
for a username are **rate-limited and locked out** (HTTP 429 after `auth.loginMaxAttempts` within
`auth.loginWindowSeconds`).

**Forced change on first login.** The seeded admin is flagged `must_change`, so the console funnels you to
a **change-password screen** (with a loud "default admin password in use" banner) before any page renders.
`POST /api/v1/auth/change-password` re-checks the current password and requires a new one of at least
`auth.minPasswordLength` characters that is neither the current nor the default password.

**Production:** with `config.requireStrongSecret=true` (the chart default) the API **refuses to start**
while the admin password is the literal shipped default — which is exactly why the chart generates a
random one rather than shipping `norviq`. Setting `auth.adminPassword` yourself is still the clearest
option when you manage secrets externally.

```yaml
auth:
  enabled: true            # set false for SSO/CLI-only (no local login)
  adminUsername: "admin"
  adminPassword: "norviq"  # sentinel => chart generates a random first password (see above);
                           # set an explicit strong value to pin your own
  sessionTtlSeconds: 3600  # session-token lifetime
  loginMaxAttempts: 5
  loginWindowSeconds: 300
  minPasswordLength: 12    # enforced on the NEW password at change-time
```

### Automation / CI — CLI token (no password)
For scripts and pipelines, mint a short-lived admin token in-cluster (`kubectl exec` runs an in-pod
minter, so the signing key never leaves the cluster and is never printed). It prints a ready-to-use
deep-link `<console>/login#access_token=…`, or you can paste the token under the login screen's
**"Use a token / CLI"** control:

```
norviq login -n <release-namespace> --console-url http://localhost:8080
```

Defaults: `--namespace/-n norviq`, `--ttl 3600`, `--console-url http://localhost:8080` (match it to
your port-forward or ingress).

---

## 2. SSO (OIDC) — recommended for teams

Norviq validates IdP-issued tokens (RS256/ES256 via JWKS, alg-confusion-safe) and maps **IdP groups →
Norviq role + namespace** server-side (never trusting a client-side claim). Works with any standard
OIDC IdP — Entra ID, Okta, Auth0, Keycloak, Google — by configuration, not code.

### 2a. Register a public (SPA) client in your IdP
- App type: **SPA / public client** (Authorization Code + PKCE, no client secret).
- **Redirect URI:** `https://<your-console-host>/auth/callback` (for a local port-forward: `http://localhost:8080/auth/callback`). The console derives it from `window.location.origin`, so it must match the host you actually browse to.
- Note the **issuer** URL and the **client id**.
- Add the user's groups to the token (a `groups` claim, or set `oidc.groupClaim`).

### 2b. Enable OIDC via Helm values
```yaml
oidc:
  enabled: true
  issuer: "https://<tenant>/"              # the token `iss`
  audience: "<api-client-or-audience-id>"  # the API's expected `aud`
  consoleClientId: "<spa-public-client-id>" # the browser client the console signs in with
  providerName: "Okta"                     # optional: IdP name shown in the login copy
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
- **admin** wins over viewer if a user is in multiple groups; an admin is namespace-agnostic (no
  namespace claim at all) and, on a fleet install, spans all clusters (`cluster: "*"`).
- A viewer maps to exactly one namespace; **conflicting** non-admin namespace mappings **fail closed**
  (the token is rejected, not silently narrowed). The same rule applies to the `cluster` dimension.
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
