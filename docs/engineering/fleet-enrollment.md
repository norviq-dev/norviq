# Single-cluster-first + fleet enrollment

Norviq installs **single-cluster by default** — install-and-go, no fleet/hub/spoke concepts. Multi-cluster is an
**opt-in** mode whose onboarding is a **join-token** flow, not per-spoke Helm wiring.

## Single-cluster (default)
- `fleet.enabled: false` (chart default). The console shows **no cluster selector, no Fleet nav, no hub/spoke
  vocabulary** — `fleetEnabled` (UI) is `false` when `FLEET_API_URL` is unset, and `/fleet` redirects home.
- The UI image runs with **no fleet-api dependency**: the nginx `/fleet-api` proxy is emitted by the container
  entrypoint **only when `FLEET_API_URL` is set**, so a single-cluster/spoke install never references a
  `norviq-fleet-api` service (previously the image crash-looped on a spoke).

## Enabling a fleet (opt-in)
1. **Hub** — install once with `fleet.hub.enabled=true` (provisions the RS256 **private** signing key; it never
   leaves the hub). The hub runs the `norviq-fleet-api` deployment.
2. **Spokes** — install **plain** (single-cluster default). Enroll each with **one action**, no per-spoke Helm
   `--set apiUrl/bundlePubkey`:
   - In the console (hub): **Fleet → Add cluster** → enter the new cluster id + the spoke-reachable hub URL →
     **Mint join token**. Copy the `norviq fleet join <token>` command.
   - On the new cluster: `norviq fleet join <token>`.

### What the join token carries
A short-lived (default 10 min), **admin-minted**, **cluster-scoped**, **single-use** HMAC-signed token containing:
the hub endpoint, the spoke's `cluster_id`, and the **bundle PUBLIC key** (the trust root) derived from the hub's
private key. `POST /api/v1/fleet/clusters/join-token` mints it (records the `jti`); the spoke's
`POST /api/v1/fleet/join` verifies it, **claims it single-use** at the hub, persists `FleetJoinState`, and starts the
relay+puller **live**. The enrollment is re-applied at startup, so it survives restarts.

### Security properties
- **Admin-only** issuance · **short-lived** (TTL in the token) · **single-use** (`used_join_token` jti, replay → 409)
  · **cluster-scoped** (wrong cluster → 403) · **expired/tampered/garbage rejected** (422). The **private signing
  key never appears in a token** — only the public bundle key (trust root), delivered *with* the signed token, not
  blindly fetched. `verify_bundle` remains fail-closed on a bad/empty pubkey.
- In kind the relay's hub auth is the shared HS256 service secret (`api_secret_key`, `cluster`-scoped); production
  should use per-cluster OIDC client-credentials (`fleet.oidc.*`).
- **Enrollment claim auth (R5):** the `POST /fleet/join` → hub `…/join-token/claim` call uses the SAME OIDC-preferring
  service bearer as the relay (`fleet_service_bearer`): OIDC client-credentials when `fleet.oidc.tokenUrl` is set, else
  a self-minted HS256 service token only when `legacy_hs256_enabled`. So a **hardened hub** (`legacy_hs256_enabled=false`)
  accepts the OIDC-authenticated claim — configure the spoke's `fleet.oidc.*` before joining such a hub, or the claim
  will have no bearer and 401.

## Removing a cluster
- Console: **Fleet → Remove** (per cluster) → `DELETE /api/v1/fleet/clusters/{id}` deregisters at the hub (deletes
  the `Cluster` row + rollups/rollout, so it drops from the fleet table and its bundle endpoint 404s).
- On the spoke: `norviq fleet leave` → `POST /api/v1/fleet/leave` stops the relay+puller and **sheds any pushed
  policy** (reuses the F-52 retract/reconcile path). `FleetJoinState.enabled=false` persists, so the spoke stays
  single-cluster **across restarts** even if env still has fleet config.

## Helm values (reference)
`helm/norviq/values.yaml` → `fleet:` block. Single-cluster default = `fleet.enabled: false`. Hub =
`fleet.hub.enabled: true` (+ `fleet.hub.signingKey` / `signingKeySecretName`). Spokes joined via token no longer need
`fleet.apiUrl` / `fleet.bundlePubkey` set by hand — the join token provides them at runtime.

## CLI
- `norviq fleet status` — single-cluster vs enrolled.
- `norviq fleet join <token>` — enroll.
- `norviq fleet leave` — de-enroll (stops pulling, sheds pushed policy).

## Console cluster-awareness (F-69)
The hub console talks to ITS OWN (served) cluster's API; the hub only aggregates KPI/trust **rollups**, not per-spoke
detail. So when an operator selects a **remote** cluster in the nav:
- **Overview** shows the cluster-scoped metrics the hub has (Total/Blocked/Block-Rate + Trust); the tiles it doesn't
  (coverage, top-tools, latency, volume, recent) show a deep-link to that cluster's own console.
- **Every per-cluster detail page** (Policy Catalog/Packs/Targets, Audit, Agents, Policy Tester, Asset/Attack graph,
  MITRE) renders the same deep-link instead of the served cluster's data — it never shows local data under a remote
  label (`ui/src/components/common/ClusterScoped.tsx`).
- **Mutations are hard-blocked**: a cluster-scoped write to the local API while a remote cluster is selected is
  refused on TWO levels — the UI client guard (`ui/src/api/clusterGuard.ts`, `NRVQ-UI-4601`, first line) AND a SERVER
  backstop (`require_target_cluster` in `norviq/api/auth.py`, `NRVQ-API-7460`): the console sends the intended target
  on `X-Nrvq-Target-Cluster`, and the API 409s any mutation whose target != its served cluster, so even a non-SPA
  caller cannot change the served cluster
  under a remote label. Edit a remote cluster from its own console.

### `console_url` (the deep-link target)
Each spoke advertises its OWN console URL to the hub so the deep-link works. Set
`NRVQ_FLEET_CLUSTER_CONSOLE_URL=https://<spoke-console>` (Helm `fleet.consoleUrl`) on the spoke; the relay sends it on every
heartbeat (`console_url`), the hub stores it on the `cluster` row (additive `ALTER TABLE … ADD COLUMN IF NOT EXISTS`)
and returns it from `GET /fleet/clusters`. When unset, the deep-link degrades to cluster-id + guidance (never a dead
link). The hub's signing key is unaffected — `console_url` is display-only metadata, like `region`/`endpoint`.
