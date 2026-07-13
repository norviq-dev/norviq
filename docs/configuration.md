# Configuration

Reference for `helm/norviq/values.yaml`. Every knob below is read straight from that file — the
"what it does" column paraphrases the inline comments already in the chart, which are worth
reading directly if you want the full rationale for a given default.

Two ready-made overlays ship alongside the defaults:

- `helm/norviq/values-prod.yaml` — multi-node production posture (HA replicas, autoscaling, spread,
  TLS-required DB). Not live-validated on a single-node cluster; template-validated only.
- `helm/norviq/values-aks-dev.yaml` — an AKS dev overlay.

Apply an overlay with `helm install norviq ./helm/norviq -n norviq -f helm/norviq/values-prod.yaml`
(or `--set` individual keys, which always wins over a `-f` file for the same key).

## Production checklist

Before you point this chart at anything beyond a local/kind cluster, check these four:

| Key | Default | Why it matters |
|---|---|---|
| `api.secretKey` | `change-me-in-production` (sentinel) | Leave it at the sentinel and the chart auto-generates a strong random JWT signing secret on first install (persisted across upgrades via a live `lookup`). Set an explicit value only if you need to pin your own (rotation, multi-cluster fleet trust). |
| `config.requireStrongSecret` | `true` | Fail-closed: the API refuses to start on a weak/default/short JWT secret or the default admin password. Only turn this off for a throwaway/dev cluster. |
| `imagePullSecrets` | `[]` | Empty is correct for the public `ghcr.io/norviq-dev` images. Set a pull-secret name only if you point `images.registry` at a private registry. |
| `config.dbSslMode` | `require` | Correct for a managed/TLS-terminating Postgres. The **bundled** Postgres StatefulSet has no TLS listener, so a local/kind install must override this to `disable` (see [getting-started.md](getting-started.md)) — don't carry that override into production. |

## Images / registry

| Key | Default | What it does |
|---|---|---|
| `images.registry` | `ghcr.io/norviq-dev/` | Prefix prepended to every component repository. Override to `ghcr.io/<your-org>/`, an Artifact Registry/ACR path, or `""` + a Docker Hub `repository` to run your own build. |
| `images.engine/api/ui/webhook.repository` | `norviq-engine` | Same image, different tags per component (see below) — one multi-stage build produces all four. |
| `images.*.tag` | `engine-latest` / `api-latest` / `ui-latest` / `webhook-latest` | Per-component tag within the shared `norviq-engine` repository. |
| `images.*.pullPolicy` | `Always` (dev default) | `values-prod.yaml` sets `IfNotPresent` for all four — appropriate once you're pinning immutable tags. |
| `images.redis.repository`/`tag` | `redis` / `7-alpine` | Bundled Redis image. |
| `images.postgresql.repository`/`tag` | `postgres` / `16-alpine` | Bundled Postgres image. |
| `imagePullSecrets` | `[]` | See Production checklist above. |
| `gracefulShutdown.preStopSleepSeconds` | `3` | `preStop` sleep on api/engine/webhook so the Service deregisters the endpoint before `SIGTERM`, draining in-flight requests during a rolling upgrade. `0` disables the hook. |

## API (`api.*`)

| Key | Default | What it does |
|---|---|---|
| `api.replicas` | `2` | HA default: survive a single pod restart/drain without an enforcement gap. |
| `api.pdb.enabled` / `minAvailable` | `true` / `1` | Keeps at least 1 API pod available during voluntary node disruptions (drain/upgrade). |
| `api.autoscaling.enabled` | `false` | HPA — off by default (a single node can't autoscale); needs `metrics-server`. `minReplicas`/`maxReplicas`/`targetCPUUtilizationPercentage` = `2`/`6`/`70`. |
| `api.spread.enabled` | `false` | `podAntiAffinity` + `topologySpreadConstraints` across nodes (multi-node prod). |
| `api.rollout.maxSurge`/`maxUnavailable` | `1` / `0` | Zero-downtime rolling update; needs node headroom for the surge pod. |
| `api.resources` | `100m/128Mi` req, `500m/256Mi` limit | Per-pod CPU/memory. |
| `api.port` | `8080` | Container port. |
| `api.secretKey` | `change-me-in-production` | See Production checklist. |
| `api.env` | `NRVQ_DB_SSL_MODE=require`, pool/timeout knobs | Declared in `values.yaml` but not currently wired into the API Deployment template — the effective DB SSL mode is `config.dbSslMode` (below), not this array. |

## Engine (`engine.*`)

The standalone evaluation engine (used when the API doesn't evaluate in-process). Mirrors the API's
HA knobs at a smaller scale: `engine.replicas` (`1`), `engine.pdb`/`spread` (both `false` — turn on
for multi-node prod), `engine.rollout.maxSurge`/`maxUnavailable` (`1`/`0`), `engine.resources`
(`100m/128Mi` request, `500m/256Mi` limit), `engine.port` (`8282`).

## UI (`ui.*`)

| Key | Default | What it does |
|---|---|---|
| `ui.replicas` | `1` | Console pod count. |
| `ui.fleetApiUrl` | `""` | Set to `/fleet-api` on the **hub** cluster to show the multi-cluster Fleet view in the console (same-origin, proxied by nginx to `norviq-fleet-api`). Leave empty on spokes/single-cluster installs — the Fleet view stays gated off. |
| `ui.rollout.maxSurge`/`maxUnavailable` | `1` / `0` | Same zero-downtime rollout pattern as api/engine. |
| `ui.resources` | `50m/64Mi` req, `200m/128Mi` limit | Per-pod CPU/memory. |
| `ui.port` | `80` | nginx container port (also proxies `/api/*` and `/ws/*` to `norviq-api`). |

## Webhook (`webhook.*`)

| Key | Default | What it does |
|---|---|---|
| `webhook.enabled` | `true` | Deploys the admission webhook server. |
| `webhook.validating.enabled` | `false` | Separate validating-admission path (distinct from injection). |
| `webhook.injection.enabled` | `false` | Turnkey sidecar injection: renders the `MutatingWebhookConfiguration` plus a pre/post-install hook Job that self-signs a TLS cert and patches the webhook's `caBundle` — no cert-manager required. Enable with `--set webhook.injection.enabled=true`, then label target namespaces `norviq-injection=enabled`. |
| `webhook.injection.sidecarMode` | `proxy` | `proxy` — the injected sidecar POSTs each tool call to the central `norviq-api` `/evaluate` with a namespace-scoped service JWT (DB/OPA stay centralized, nothing per-pod). `embedded` — the sidecar runs its own `RedisCache` + OPA (subprocess) + `PolicyLoader` for air-gapped/edge deployments (the chart then wires `NRVQ_REDIS_URL`/`NRVQ_PG_URL` through to the injector). |
| `webhook.injection.certJobImage` | `alpine/k8s:1.30.0` | Image with `kubectl` + `openssl` used by the cert-bootstrap hook Job; publicly pullable. |
| `webhook.replicas` | `2` | Webhook server pod count. |
| `webhook.pdb`/`autoscaling`/`spread` | off by default | Same HA pattern as api/engine — turn on for multi-node prod (`autoscaling`: `2`–`4` replicas, 70% CPU target). |
| `webhook.rollout.maxSurge`/`maxUnavailable` | `1` / `0` | Zero-downtime rollout. |
| `webhook.port` | `8443` | Admission server port. |
| `webhook.resources` | `50m/64Mi` req, `200m/128Mi` limit | Per-pod CPU/memory. |
| `webhook.spiffe.inject` | `false` | Injects the SPIFFE Workload API socket + workload-api mode into injected workloads. Needs SPIRE + the SPIFFE CSI driver — off by default. |
| `webhook.oidc.enabled` | `false` | The controller mints its API bearer via OIDC client-credentials (a Keycloak service client) instead of the HS256 service token. Off by default (HS256 fallback). Set `webhook.oidc.tokenUrl`/`clientId`/`clientSecret` to enable. |

## Redis (`redis.*`)

| Key | Default | What it does |
|---|---|---|
| `redis.enabled` | `true` | Deploys the bundled single-replica Redis StatefulSet. |
| `redis.replicas` | `1` | Single instance. |
| `redis.ha.enabled` | `false` | **Gated, not live-validated on 1 node.** When true, renders a Sentinel HA topology instead of the single StatefulSet — requires the operator/Sentinel chart pre-installed. `redis.ha.replicas` (`3`), `redis.ha.serviceName` (`norviq-redis-ha`). |
| `redis.resources` | `100m/128Mi` req, `300m/256Mi` limit | Per-pod CPU/memory. |
| `redis.port` | `6379` | |
| `redis.password` | `norviq-redis-password` | Bundled Redis auth password — change for any non-throwaway install. |
| `redis.storage` | `1Gi` | PVC size. |

## PostgreSQL (`postgresql.*`)

| Key | Default | What it does |
|---|---|---|
| `postgresql.enabled` | `true` | Deploys the bundled single-replica Postgres StatefulSet. |
| `postgresql.replicas` | `1` | Single instance. |
| `postgresql.ha.enabled` | `false` | **Gated, not live-validated on 1 node.** When true, renders a CloudNativePG `Cluster` (3 instances) instead of the single StatefulSet, and points the API's PG URL at its service — requires the CloudNativePG operator pre-installed. `postgresql.ha.instances` (`3`), `postgresql.ha.serviceName` (`norviq-postgresql-ha-rw`). |
| `postgresql.resources` | `200m/256Mi` req, `500m/512Mi` limit | Per-pod CPU/memory. |
| `postgresql.port` | `5432` | |
| `postgresql.database`/`username`/`password` | `norviq` / `norviq` / `norviq-pg-password` | Bundled DB credentials — change the password for any non-throwaway install. |
| `postgresql.storage` | `5Gi` | PVC size. |

## OPA (`opa.*`)

| Key | Default | What it does |
|---|---|---|
| `opa.enabled` | `true` | Deploys OPA as a long-lived sidecar in every api/engine pod (`localhost:8181`) instead of forking `opa eval` per call. Each replica gets its own OPA — no shared single point of failure. |
| `opa.image` | `openpolicyagent/opa:1.18.0-static` | Pinned (not `latest-static`) so the running OPA version matches the one `scripts/gen-opa-capabilities.py` generated `helm/norviq/files/opa-capabilities.json` from; a drifted OPA could have a different builtin set than what `norviq/engine/opa_client.py::_check_capabilities` validates against. |
| `opa.port` | `8181` | |
| `opa.resources` | `50m/64Mi` req, `250m/128Mi` limit | Per-sidecar CPU/memory. |

Related: `config.opaMode` (below) selects whether the engine actually talks to this sidecar
(`server`, default) or falls back to a per-call `opa eval` fork (`subprocess`).

## `config.*` — core runtime settings

| Key | Default | What it does |
|---|---|---|
| `config.logLevel` | `INFO` | |
| `config.enforcementMode` | `block` | Global default enforcement mode (individual `NrvqPolicy` objects can override per-target). |
| `config.noPolicyDecision` | `deny` | What happens to a call in a namespace with **no matching policy**, in `block` mode. `deny` is fail-closed; setting `allow` restores fail-open behavior. |
| `config.opaMode` | `server` | `server` — evaluate via HTTP against the per-pod OPA sidecar (`opa.*` above). `subprocess` — per-call `opa eval` fork (rollback path). |
| `config.requireStrongSecret` | `true` | See Production checklist. |
| `config.trustThreshold` | `0.7` | Agent trust score below this affects evaluation/escalation behavior. |
| `config.violationPenalty` | `0.05` | Trust-score deduction per policy violation. |
| `config.rateLimit` | `60` | Default per-agent request rate limit. |
| `config.dbSslMode` | `require` | See Production checklist — override to `disable` for the bundled (non-TLS) local Postgres. |
| `config.dbPoolMaxOverflow`/`dbPoolTimeout`/`dbCommandTimeout` | `10` / `10` / `10` | DB connection pool tuning. |
| `config.retention.draftTtlDays` | `14` | Real policy-intent drafts auto-expire after N days. |
| `config.retention.draftTtlTestHours` | `24` | Test/e2e (synthetic-class) drafts expire faster. |
| `config.retention.draftCapPerNamespace` | `50` | Hard ceiling of real drafts per namespace (evicts oldest beyond it). |
| `config.retention.draftsPageSize` | `15` | Bounded drafts endpoint page size (top-N newest + total). |
| `config.retention.policyVersionKeepCount`/`policyVersionKeepDays` | `20` / `90` | Keep at least the last N policy versions, and any version within this window; prune older ones — never the current enforcing version. |
| `config.retention.redteamDetailKeepRuns`/`redteamDetailKeepDays` | `1` / `7` | Full per-attack red-team detail retained for the newest N runs / namespace, or any run within N days (older runs are detail-pruned, summary kept). |
| `config.retention.redteamSummaryKeepRuns`/`redteamSummaryKeepDays` | `20` / `30` | Red-team run summaries (no detail) retained for the newest N runs, or within N days; older summaries are deleted entirely. |
| `config.retention.redteamHistoryPageSize` | `20` | Bounded `/redteam/results` history page size (summaries only). |
| `config.spiffeMode` | `mock` | `mock` — env-var identity (default, no SPIRE needed). `workload-api` — real SPIFFE SVID resolution, fail-closed; requires SPIRE on the cluster + `pyspiffe`. |
| `config.spiffeSocket` | `/spiffe-workload-api/spire-agent.sock` | SPIFFE Workload API socket path (where the SPIFFE CSI driver publishes the agent socket). |
| `config.spiffeCsi.enabled` | `false` | Gates the `csi.spiffe.io` volume on api/engine pods. Off by default so deploys without SPIRE are unaffected (the volume would otherwise wedge pod creation with no driver/registration). Enable only where SPIRE + the SPIFFE CSI driver are installed. |

## Local auth (`auth.*`)

The primary no-IdP login path: username/password against a local, bcrypt-hashed account.

| Key | Default | What it does |
|---|---|---|
| `auth.enabled` | `true` | Set `false` to disable local login entirely (SSO/CLI-only). |
| `auth.adminUsername` | `admin` | Seeded admin username. |
| `auth.adminPassword` | `norviq` (sentinel) | Leave at the sentinel and the chart auto-generates a strong random first password (retrieve via `kubectl get secret norviq-secrets -o jsonpath='{.data.NRVQ_AUTH_ADMIN_PASSWORD}' | base64 -d`). You're forced to change it on first login either way. Set an explicit value to pin your own. With `config.requireStrongSecret: true`, the API refuses to start while the password is still the literal default `"norviq"`. |
| `auth.sessionTtlSeconds` | `3600` | Session token TTL. |
| `auth.loginMaxAttempts`/`loginWindowSeconds` | `5` / `300` | Brute-force lockout: after `loginMaxAttempts` failed logins for a username within `loginWindowSeconds`, further attempts 429 until the window passes. |
| `auth.minPasswordLength` | `12` | Enforced on a **new** password at change-time. |

## OIDC / SSO (`oidc.*`)

Default-off; the API keeps validating legacy HS256 tokens until an IdP is wired in. Enabling adds
RS256/ES256 validation **alongside** HS256 (set `legacyHs256Enabled: false` at cutover).

| Key | Default | What it does |
|---|---|---|
| `oidc.enabled` | `false` | |
| `oidc.issuer` / `oidc.audience` | `""` | Token `iss` / the API's client/audience id. |
| `oidc.consoleClientId` | `""` | The public (browser/SPA) OIDC client id the console uses for Auth Code + PKCE sign-in. Register a public client in your IdP with redirect URI `<console>/auth/callback`. When set (and `oidc.enabled`), the UI renders "Sign in with SSO" with no rebuild needed (injected at runtime). |
| `oidc.providerName` | `""` | Human-readable IdP name shown in login copy (e.g. "Okta"). |
| `oidc.jwksUrl` | `""` | IdP JWKS endpoint. |
| `oidc.groupClaim` | `groups` | Claim holding the user's group list. |
| `oidc.legacyHs256Enabled` | `true` | Keep validating local HS256 tokens alongside OIDC; flip off at cutover. |
| `oidc.groupMappings` | `{}` | Map IdP groups to Norviq `(role, namespace)`, e.g. `{"norviq-admins":{"role":"admin"},"team-a":{"role":"viewer","namespace":"team-a"}}`. |

## RBAC (`rbac.*`)

The chart ships `norviq-admin` / `norviq-policy-editor` / `norviq-viewer` ClusterRoles but no
subject bindings. `rbac.exampleBindings.enabled` (`false`) + `rbac.bindings` (`[]`) map them to
IdP groups or ServiceAccounts — see `docs/engineering/production-config.md` for the binding shape
(`role` / `kind` / `name` / `namespace`).

## SIEM (`siem.*`)

Outbound audit forwarder. `siem.enabled` (`false`) — when on, the API streams new audit rows to
`siem.webhookUrl` as `siem.format` (`ndjson` or `syslog`) every `siem.pollIntervalSeconds` (`30`).
The authenticated `GET /api/v1/audit/export` endpoint is always available regardless of this
setting.

## Multi-cluster fleet (`fleet.*`)

MVP P1, read-only. Everything is off by default — a single-cluster install renders **zero** fleet
resources and behaves exactly as a standalone install.

**Spoke side** (`fleet.enabled: false`): runs an in-process relay that pushes agent/audit rollups
to the hub. Key fields: `fleet.clusterId`/`clusterName`/`region`, `fleet.apiUrl` (hub base URL),
`fleet.relayIntervalSeconds` (`60`), `fleet.pullIntervalSeconds` (`60`, how often the spoke
pulls/verifies/applies the signed policy bundle), `fleet.staleAfterSeconds` (`180`, hub-side
heartbeat-staleness threshold), `fleet.residency` (`false`, keep raw audit in-cluster —
rollups still leave, drill-down from the hub is blocked), `fleet.bundlePubkey` (`""`, the fleet
signing public key/trust root — empty means the spoke applies no bundle), `fleet.oidc.*`
(relay→hub auth; HS256 break-glass fallback if unset).

**Hub side** (`fleet.hub.enabled: false`): renders the fleet-api control plane + a dedicated
`fleet-postgresql`, only meant for the cluster hosting the control plane. A hub outage never
affects local enforcement on any spoke (fire-and-forget relay). Key fields:
`fleet.hub.pgUrl`, `fleet.hub.signingKey`/`signingKeySecretName` (the fleet signing **private**
key — hub only, distinct from `api.secretKey`), `fleet.hub.bundleTtlSeconds` (`900`),
`fleet.hub.replicas`/`storage`/`resources`, and the same `pdb`/`autoscaling`/`spread` HA gates as
api/engine/webhook (all off by default — `values-prod.yaml` turns them on when the hub is
enabled: 3 replicas, PDB `minAvailable: 2`, HPA 3–6 @ 70%, spread on, plus HA Postgres).
`fleet.hub.postgresql.*` mirrors the top-level `postgresql.*` block for the fleet store.

## Ingress (`ingress.*`)

Off by default (`ingress.enabled: false`). When enabled: `ingress.className` (`nginx`),
`ingress.host` (`norviq.example.com`), `ingress.tls` (`false`).
