# Configuration

Reference for `helm/norviq/values.yaml`. Every knob below is read straight from that file — the
"what it does" column paraphrases the inline comments already in the chart, which are worth
reading directly if you want the full rationale for a given default.

Three ready-made overlays ship alongside the defaults:

- `helm/norviq/values-prod.yaml` — multi-node production posture (HA replicas, autoscaling, spread,
  TLS-required DB). Not live-validated on a single-node cluster; template-validated only. It
  deliberately blanks `postgresql.password`/`redis.password`, so it only renders once you supply them
  (see [deployment.md](deployment.md)).
- `helm/norviq/values-dev.yaml` — fixed dev secrets (`api.secretKey`, DB/Redis passwords),
  `logLevel: DEBUG`, and `enforcementMode: audit` so a fresh dev install logs decisions instead of
  enforcing them.
- `helm/norviq/values-light.yaml` — smallest viable single-node footprint (one replica of everything,
  PDBs/HPAs/HA/SPIFFE off). Enforcement behaviour is unchanged; only replicas and resources shrink.

Apply an overlay with `helm install norviq ./helm/norviq -n norviq -f helm/norviq/values-prod.yaml`
(or `--set` individual keys, which always wins over a `-f` file for the same key).

## Install-blocking guards (read this first)

Four settings can make `helm template`/`helm install` **fail on purpose** rather than render a
silently-insecure cluster. These are the first thing a new operator hits:

| Guard | Fails when | Fix |
|---|---|---|
| `baselineClusterPolicy.enabled` (`true`) | `policyQuotaNamespaces` is empty | Set `policyQuotaNamespaces` to your tenant namespaces (one baseline `NrvqPolicy` renders per namespace), or set `baselineClusterPolicy.enabled=false` to run without a cluster baseline. |
| `config.requireStrongSecret` (`true`) | `postgresql.password` is empty | `--set postgresql.password=...` |
| `config.requireStrongSecret` (`true`) | `redis.password` is empty | `--set redis.password=...` |
| `config.requireStrongSecret` (`true`) + `fleet.hub.enabled` | `fleet.hub.postgresql.password` is empty or the shipped `norviq_dev`, or `fleet.hub.pgUrl` embeds it | `--set fleet.hub.postgresql.password=...` and point `fleet.hub.pgUrl` at a strong credential. |

`agentEgressPolicy.enabled=true` adds two more render-time refusals: no namespaces to lock down, and
targeting the Norviq control-plane namespace itself.

`config.requireStrongSecret` also acts at **boot**, not just at render: the API refuses to start on a
weak/default/short JWT secret (`NRVQ-API-7099`) or the shipped default admin password
(`NRVQ-AUTH-14014`).

## Production checklist

Before you point this chart at anything beyond a local/kind cluster, check these four:

| Key | Default | Why it matters |
|---|---|---|
| `api.secretKey` | `change-me-in-production` (sentinel) | Leave it at the sentinel and the chart auto-generates a strong random JWT signing secret on first install (persisted across upgrades via a live `lookup`). Set an explicit value only if you need to pin your own (rotation, multi-cluster fleet trust). |
| `config.requireStrongSecret` | `true` | Fail-closed: the API refuses to start on a weak/default/short JWT secret or the default admin password. Only turn this off for a throwaway/dev cluster. |
| `imagePullSecrets` | `[]` | Empty is correct for the public `ghcr.io/norviq-dev` images. Set a pull-secret name only if you point `images.registry` at a private registry. |
| `config.dbSslMode` | `require` | Correct for a managed/TLS-terminating Postgres. The **bundled** Postgres StatefulSet has no TLS listener, so a local/kind install must override this to `disable` (see [getting-started.md](getting-started.md)) — don't carry that override into production. |

## Tenant namespaces (`policyQuotaNamespaces`, `baselineClusterPolicy.*`)

`policyQuotaNamespaces` (`[]`) is the chart's list of **tenant/agent namespaces**. It is not just a
quota list — three other things key off it, which is why it is effectively mandatory:

| Key | Default | What it does |
|---|---|---|
| `policyQuotaNamespaces` | `[]` | For each listed namespace: renders a `ResourceQuota` capping `count/nrvqpolicies.norviq.io` at 100, **and** one baseline `NrvqPolicy`, **and** (when `agentEgressPolicy.namespaces` is empty) the egress lockdown target set. Each namespace must already exist — a `ResourceQuota` is namespaced. |
| `baselineClusterPolicy.enabled` | `true` | Renders the fail-closed cluster baseline guard, one `NrvqPolicy` per namespace above. With `policyQuotaNamespaces` empty this **fails the render** rather than shipping zero baselines. |
| `baselineClusterPolicy.name` | `baseline-cluster-guard` | Name prefix; the rendered object is `<name>-<namespace>`. |
| `baselineClusterPolicy.clusterPriority` | `900` | Priority of the baseline relative to tenant-authored policy. |
| `baselineClusterPolicy.preset` | `strict` | Preset rego bundled with the webhook (`strict` / `moderate` / `permissive` — see `webhook/presets/`). |

## Agent egress lockdown (`agentEgressPolicy.*`)

Defense-in-depth at the **network** layer. Norviq's tool-call PEP is cooperative — the SDK asks for a
decision and the agent executes the tool — so a pod that ignores the SDK can reach tools directly.
This opt-in default-deny egress policy bounds that: an agent pod may egress only to the Norviq API,
DNS, and an operator-approved allowlist. It does **not** replace the PEP (per-call parameter policy
still needs the SDK) and requires a NetworkPolicy-enforcing CNI — kindnet ignores NetworkPolicy.

| Key | Default | What it does |
|---|---|---|
| `agentEgressPolicy.enabled` | `false` | Renders the lockdown. |
| `agentEgressPolicy.engine` | `networkpolicy` | `networkpolicy` — portable Kubernetes `NetworkPolicy`, IP/CIDR allowlist only. `cilium` — a `CiliumNetworkPolicy` that also supports FQDN allowlisting (needs the Cilium CNI). Any other value fails the render. |
| `agentEgressPolicy.namespaces` | `[]` | Namespaces to lock down. Empty reuses `policyQuotaNamespaces`. Empty on both fails the render; listing the control-plane namespace also fails. |
| `agentEgressPolicy.allowDNS` | `true` | Permit DNS egress (required for anything to resolve). |
| `agentEgressPolicy.allowedCIDRs` | `[]` | Approved tool endpoints. Everything else, including the internet, is denied — leave empty only if all of the agent's tools live in the Norviq namespace. |
| `agentEgressPolicy.allowedFQDNs` / `allowedFQDNPatterns` | `[]` | `engine: cilium` only — allow egress by hostname / wildcard instead of chasing rotating SaaS IPs. |
| `agentEgressPolicy.allowedPorts` | `[]` | Restrict the allowlist to these TCP ports (empty = all ports). |
| `agentEgressPolicy.embeddedDatastores` | `false` | Also permit egress to Redis/Postgres — needed only for `sidecarMode: embedded`, where the sidecar talks to the datastores directly instead of to the API. |

## Container hardening (`securityContext.*`)

Applied inline by the chart to the api/engine/webhook containers rather than relying on a
cluster-level PodSecurity/Kyverno mutation that may not exist on the target cluster. Set
`securityContext.enabled: false` to defer entirely to such a cluster policy.

| Key | Default |
|---|---|
| `securityContext.enabled` | `true` |
| `securityContext.runAsNonRoot` | `true` |
| `securityContext.allowPrivilegeEscalation` | `false` |
| `securityContext.readOnlyRootFilesystem` | `true` |
| `securityContext.capabilities.drop` | `["ALL"]` |
| `securityContext.seccompProfile.type` | `RuntimeDefault` |

`readOnlyRootFilesystem` is **not** applied to the api/engine Python containers (they need a writable
rootfs); the other four controls are. The OPA and TLS-proxy sidecars carry the same restricted profile.
The `norviq.waitFor` init containers (`busybox nc -z`, used for the Postgres/Redis/API dependency
waits) run the full profile including `readOnlyRootFilesystem` and `runAsUser: 65534`.

## Images / registry

| Key | Default | What it does |
|---|---|---|
| `images.registry` | `ghcr.io/norviq-dev/` | Prefix prepended to every component repository. Override to `ghcr.io/<your-org>/`, an Artifact Registry/ACR path, or `""` + a Docker Hub `repository` to run your own build. |
| `images.engine/api/ui/webhook.repository` | `norviq-engine` | Same image, different tags per component (see below) — one multi-stage build produces all four. |
| `images.*.tag` | `engine-latest` / `api-latest` / `ui-latest` / `webhook-latest` | Per-component tag within the shared `norviq-engine` repository. |
| `images.*.pullPolicy` | `Always` | `values-prod.yaml` sets `IfNotPresent` for all four — appropriate once you're pinning immutable tags. |
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

The standalone evaluation engine. Mirrors the API's HA knobs at a smaller scale: `engine.replicas`
(`1`), `engine.pdb`/`spread` (both `false` — turn on for multi-node prod),
`engine.rollout.maxSurge`/`maxUnavailable` (`1`/`0`), `engine.resources` (`100m/128Mi` request,
`500m/256Mi` limit), `engine.port` (`8282`).

The engine Deployment **pins `NRVQ_SIDECAR_MODE=embedded`** as a literal env, overriding the
`sidecar_mode` default of `proxy`. This is not configurable from `values.yaml`, and deliberately so:
nothing mints an `NRVQ_API_TOKEN` for this Deployment (only the webhook mints one, for the pods it
injects), so in `proxy` mode every decision would be forwarded to the central API, get a 401, and fail
closed — an outage that looks like enforcement. The engine carries its own OPA sidecar and waits on
both Postgres and Redis, which is exactly the embedded shape.

## UI (`ui.*`)

| Key | Default | What it does |
|---|---|---|
| `ui.replicas` | `1` | Console pod count. |
| `ui.fleetApiUrl` | `""` | Set to `/fleet-api` on the **hub** cluster to show the multi-cluster Fleet view in the console (same-origin, proxied by nginx to `norviq-fleet-api`). Leave empty on spokes/single-cluster installs — the Fleet view stays gated off. |
| `ui.rollout.maxSurge`/`maxUnavailable` | `1` / `0` | Same zero-downtime rollout pattern as api/engine. |
| `ui.resources` | `50m/64Mi` req, `200m/128Mi` limit | Per-pod CPU/memory. |
| `ui.port` | `8080` | nginx **container** port. The console runs on the unprivileged nginx image (uid 101), so it binds an unprivileged port and needs no `NET_BIND_SERVICE` — the pod can drop `ALL` caps. The `norviq-ui` Service still listens on `80` and targets the named `http` port, so this cascades automatically. nginx also proxies `/api/*` and `/ws/*` to `norviq-api`. |

## Webhook (`webhook.*`)

| Key | Default | What it does |
|---|---|---|
| `webhook.enabled` | `true` | Deploys the admission webhook server. |
| `webhook.validating.enabled` | `false` | Separate validating-admission path (distinct from injection). |
| `webhook.injection.enabled` | `false` | Turnkey sidecar injection: renders the `MutatingWebhookConfiguration` plus a pre/post-install hook Job that self-signs a TLS cert and patches the webhook's `caBundle` — no cert-manager required. Enable with `--set webhook.injection.enabled=true`, then label target namespaces `norviq-injection=enabled`. |
| `webhook.injection.sidecarMode` | `proxy` | `proxy` — the injected sidecar POSTs each tool call to the central `norviq-api` `/evaluate` with a namespace-scoped service JWT (DB/OPA stay centralized, nothing per-pod). `embedded` — the sidecar runs its own `RedisCache` + OPA (subprocess) + `PolicyLoader` for air-gapped/edge deployments (the chart then wires `NRVQ_REDIS_URL`/`NRVQ_PG_URL` through to the injector). |
| `webhook.injection.failurePolicy` | `Fail` | Admission posture for the injector. `Fail` is **fail-closed**: if the injector is unavailable, pod creation in an injection-enabled namespace is rejected, so an agent pod can never start un-guarded. Set `Ignore` (fail-open) only on a dev/eval cluster. The webhook is HA (2 replicas + PDB) and the control-plane/kube-system namespaces are excluded from the selector, so this doesn't self-deadlock. |
| `webhook.injection.allowPodOptOut` | `true` | Honour the per-pod opt-out (`norviq-injection=disabled` label / `norviq.io/skip-injection` annotation). Set `false` to make injection namespace-uniform so a pod author can't self-exempt their workload from enforcement — pair that with RBAC on pod label/annotation writes. |
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
| `redis.ha.enabled` | `false` | **Gated, not live-validated on 1 node.** When true, renders a Spotahome `RedisFailover` (`databases.spotahome.com/v1`, Sentinel) instead of the single StatefulSet — requires that operator pre-installed. Swap `templates/redis-ha.yaml` + `redis.ha.serviceName` for a different Redis HA stack. `redis.ha.replicas` (`3`), `redis.ha.serviceName` (`norviq-redis-ha`). |
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
| `opa.enabled` | `true` | Deploys OPA as a long-lived sidecar in every api/engine pod instead of forking `opa eval` per call. Each replica gets its own OPA — no shared single point of failure. The sidecar is started with `--addr=127.0.0.1:<opa.port>`: OPA's admin API is unauthenticated **read-write**, so it must never be reachable from another pod. It therefore carries **no kubelet probes** (a kubelet probe dials the pod IP, which can't reach a loopback bind, and the `-static` image is distroless so an exec probe isn't an option either) — OPA health reaches readiness through the app's own `/readyz`. |
| `opa.image` | `openpolicyagent/opa:1.18.0-static` | Pinned (not `latest-static`) so the running OPA version matches the one `scripts/gen-opa-capabilities.py` generated `helm/norviq/files/opa-capabilities.json` from; a drifted OPA could have a different builtin set than what `norviq/engine/opa_client.py::_check_capabilities` validates against. |
| `opa.port` | `8181` | |
| `opa.resources` | `50m/64Mi` req, `250m/128Mi` limit | Per-sidecar CPU/memory. |

Related: `config.opaMode` (below) selects whether the engine actually talks to this sidecar
(`server`, default) or falls back to a per-call `opa eval` fork (`subprocess`). The chart derives
`NRVQ_OPA_URL` from `opa.port` — there is no `values.yaml` key for it. Setting `NRVQ_OPA_URL` empty in
a non-chart deployment makes the app spawn its own managed `opa run --server`, bound to
`NRVQ_OPA_ADDR` (`127.0.0.1:8181`); that path is for local dev and tests, not the chart.

## `config.*` — core runtime settings

| Key | Default | What it does |
|---|---|---|
| `config.internalTls.enabled` | `true` | Zero-touch internal TLS/mTLS for control-plane traffic. A Helm hook mints an internal CA and the API serving cert, the API pod runs an nginx TLS terminator sidecar on `:8443` (the app itself stays plain HTTP on loopback, so probes are unaffected), and the injector gives each sidecar a CA-signed client cert for mTLS. No operator certs or CSRs. Set `false` only for a plaintext dev cluster. |
| `config.internalTls.proxyImage` | `nginx:1.27-alpine` | Image for that TLS terminator sidecar. |
| `config.logLevel` | `INFO` | |
| `config.enforcementMode` | `block` | Global default enforcement mode (individual `NrvqPolicy` objects can override per-target). |
| `config.noPolicyDecision` | `deny` | What happens to a call in a namespace with **no matching policy**, in `block` mode. `deny` is fail-closed; setting `allow` restores fail-open behavior. |
| `config.opaMode` | `server` | `server` — evaluate via HTTP against the per-pod OPA sidecar (`opa.*` above). `subprocess` — per-call `opa eval` fork (rollback path). |
| `config.requireStrongSecret` | `true` | See Production checklist. |
| `config.trustThreshold` | `0.7` | Agent trust score below this affects evaluation/escalation behavior. Renders `NRVQ_TRUST_THRESHOLD`, which binds to `settings.trust_threshold`. |
| `config.violationPenalty` | `0.05` | **Currently inert.** It renders `NRVQ_VIOLATION_PENALTY`, but the setting is `trust_violation_penalty`, so the value is ignored and the built-in `0.05` applies. To actually change it, pass `NRVQ_TRUST_VIOLATION_PENALTY` as an env var. |
| `config.rateLimit` | `60` | **Currently inert.** It renders `NRVQ_RATE_LIMIT`, but there is no `rate_limit` setting — the per-identity evaluator limit is `evaluator_rate_limit_per_window` (60 per `evaluator_rate_limit_window_s`, 60s). To actually change it, pass `NRVQ_EVALUATOR_RATE_LIMIT_PER_WINDOW`. Note this is the OPA-policy limit on evaluated tool calls; the separate HTTP-layer throttle in front of the API is `NRVQ_HTTP_RATE_LIMIT_*` and has no chart key either. |
| `config.inprocCacheTtlS` | `0` (off) | **Opt-in per-pod in-process L1 cache** for the enforcement hot path. Renders `NRVQ_EVALUATOR_INPROC_CACHE_TTL_S` → `settings.evaluator_inproc_cache_ttl_s`. Caches namespace posture, the stored trust score and the trust calculator's history/profile at this TTL, plus the pre-override base policy decision (that one additionally clamped to `redis_ttl_eval_s` and cleared on any policy change). The admin **freeze and trust cap are never cached** — read fresh on every call, so the kill switch is off the caching path. Measured on 2-node AKS: warm read p50 21.9 ms → 3.2 ms, floor 14.5 ms → 1.4 ms. **Cost:** a posture/threshold change, or any trust-input change, is not seen by an already-warm pod until the entry expires — so enable deliberately. Recommended production value: `5`. |
| `config.inprocCacheMax` | `8192` | Hard per-cache entry cap for those in-process L1s (bounds per-pod memory under identity/namespace churn). Renders `NRVQ_EVALUATOR_INPROC_CACHE_MAX`. |
| `config.dbSslMode` | `require` | See Production checklist — override to `disable` for the bundled (non-TLS) local Postgres. |
| `config.dbPoolMaxOverflow`/`dbPoolTimeout`/`dbCommandTimeout` | `10` / `10` / `10` | DB connection pool tuning. |
| `config.retention.auditRetentionDays` | `30` | Audit-log rows older than this are pruned. The console's Audit Log views read at most the last 30 days; raise to 90–365 for compliance evidence windows (export audit-evidence packs for long-term archival). `0` = keep forever. |
| `config.retention.coverageSnapshotRetentionDays` | `30` | Compliance coverage trend snapshots + export events older than this are pruned. `0` = keep forever. |
| `config.retention.graphSnapshotKeepPerNamespace` | `10` | Keep only the newest N asset-graph snapshots per namespace (readers only load the newest; caps growth under traffic). `0` = keep all. |
| `config.retention.agentRegistryRetentionDays` | `90` | Agent-registry entries are removed N days after `last_seen` (`0` = never). Admins can remove one immediately via `DELETE /api/v1/agents/{spiffe_id}`. |
| `config.retention.apiKeyDefaultTtlDays` | `90` | Default expiry for **newly created** API keys — per-key override at creation (incl. never). Pre-existing keys never expire; revoked keys are kept (soft revoke). `0` = new keys never expire. |
| `config.retention.draftTtlDays` | `14` | Real policy-intent drafts auto-expire after N days (expired drafts are also swept hourly in the background). |
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

All `config.retention.*` windows are enforced by a single hourly background retention pruner (an
extension of the audit pruner); `0` means keep forever (pruning disabled for that data type).
**Enforcing policies never expire** — an expiring security control would be silent un-protection.

`GET /api/v1/settings/retention` returns the cluster's **effective** values and is the authoritative
check that an override landed (any authenticated user may read it; it is read-only — mutating a
retention window from the UI could silently shorten audit evidence, so that stays operator-only via
Helm/env). It reports the 14 real windows/caps. `draftsPageSize` and `redteamHistoryPageSize` live
under `config.retention.*` in the chart but are **response page-size bounds, not retention windows**,
and are deliberately not part of that response. The Settings page renders this endpoint read-only.

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

Read-only. Everything is off by default — a single-cluster install renders **zero** fleet
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

## Telemetry (`otel.*`)

Off by default. `otel.enabled` (`false`), `otel.endpoint` (`http://otel-collector:4317`, OTLP gRPC),
`otel.prometheusPort` (`9090`). These render `NRVQ_OTEL_ENABLED` / `NRVQ_OTEL_ENDPOINT` /
`NRVQ_PROMETHEUS_PORT`. `NRVQ_OTEL_DISABLED=true` is a hard kill-switch that wins over
`NRVQ_OTEL_ENABLED` and has no chart key. The chart also ships a Grafana dashboard ConfigMap
(`helm/norviq/dashboards/`).

## Ingress (`ingress.*`)

Off by default (`ingress.enabled: false`). When enabled:

| Key | Default | What it does |
|---|---|---|
| `ingress.className` | `nginx` | IngressClass. |
| `ingress.host` | `norviq.example.com` | |
| `ingress.tls` | `false` | Set `true` for the HTTPS path; leaving it false serves plaintext (dev only). |
| `ingress.tlsSecretName` | `norviq-ingress-tls` | Pre-create this Secret, or have a cert-manager issuer populate it. |
| `ingress.annotations` | `{}` | Extra annotations (cert-manager issuer, body size, timeouts). The console's nginx already proxies `/api/*` to the API, so a single host routes both UI and API with no path rewrite. |
