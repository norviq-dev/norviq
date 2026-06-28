<!-- SPDX-License-Identifier: Apache-2.0 -->
# Norviq Production Deploy Runbook (multi-node)

The chart ships **one chart, two overlays**: `values-aks-dev.yaml` (single-node lean — the CI default)
and `values-prod.yaml` (multi-node). Everything prod-specific is **values-gated and off by default**, so
the dev cluster is unaffected. Companion: [`production-config.md`](production-config.md) (secrets/RBAC).

## Prerequisites (multi-node)
- **≥3 nodes** (so podAntiAffinity / topologySpread actually spread replicas).
- **metrics-server** installed (HPA reads CPU/mem).
- **CloudNativePG operator** installed (Postgres HA renders a `postgresql.cnpg.io/v1 Cluster`).
- **A Redis HA operator** — `values-prod` renders a Spotahome `RedisFailover` CR; swap
  `templates/redis-ha.yaml` + `redis.ha.serviceName` if you use a different stack (Bitnami, MemoryDB).
- A **public or pull-secret'd registry**. Default images are public on Docker Hub
  (`sanman97/norviq-engine`). For scale prefer **GHCR** (`images.registry: ghcr.io/`, repository
  `norviq-dev/norviq-engine`) or **ACR** — no Docker Hub anonymous pull-rate limit. Set
  `imagePullSecrets` to `[]` for a public registry, or to your registry's pull secret.

## What `values-prod.yaml` turns on
| Area | Dev (default) | Prod overlay |
|---|---|---|
| api replicas / PDB | 1 / off | 3 / minAvailable 2 |
| HPA (api, webhook) | off | on (CPU 70%) — needs metrics-server |
| podAntiAffinity + topologySpread | off | on (spread across nodes) |
| engine | 0 replicas | 2 replicas + PDB + spread |
| webhook | 1 | 2 + PDB + HPA + spread + injection on |
| Postgres | single StatefulSet | CloudNativePG `Cluster` (3) — operator required |
| Redis | single StatefulSet | `RedisFailover` (Sentinel, 3) — operator required |
| rollout | replace-in-place (maxSurge 0) | surge (maxSurge 1, zero-downtime) |
| strong-secret guard / DB TLS | off / disable | on / require |

## Deploy
```bash
# install operators first (CloudNativePG, redis-operator, metrics-server) per their docs, then:
helm upgrade --install norviq ./helm/norviq -n norviq --create-namespace \
  -f helm/norviq/values-prod.yaml \
  --set api.secretKey="$NRVQ_API_SECRET_KEY" \
  --set images.registry="ghcr.io/" --set images.api.tag=api-<sha> ...   # pin -sha tags
```
The HA StatefulSets are auto-disabled when `*.ha.enabled` (the operators own the datastores); the API's
`NRVQ_PG_URL`/`NRVQ_REDIS_URL` auto-retarget the HA services (`*-rw` / failover service).

## Runtime guarantees (live on dev too)
- **Startup ordering** is enforced at *runtime*, not by Helm apply order: initContainers gate
  api/engine on postgres+redis and webhook on api; `/readyz` gates the Service. So `helm upgrade`
  ordering is irrelevant — a pod only serves once its hard deps are reachable.
- **Dependency-restart resilience:** `/readyz` returns **503** when Postgres/Redis/OPA is unreachable →
  the pod goes NotReady (drains traffic) while liveness (`/healthz`, process-up) keeps it alive (no
  CrashLoop). On recovery, `pool_pre_ping` reconnects Postgres, redis-py reconnects, and OPA re-push
  self-heals → `/readyz` 200 → Ready. **No manual restart.** Test: `kubectl delete pod
  norviq-postgresql-0` → api NotReady → Ready (RESTARTS stays 0); repeat for redis / the OPA sidecar.
- **Graceful rollout:** `preStop` sleep + `terminationGracePeriodSeconds: 30` drain in-flight requests
  before SIGTERM.
- **Webhook → API:** the controller mints a short-lived **service-role HS256 JWT** from the API secret
  (the API accepts `service` on policy create/delete only). Injected sidecars are pinned to the
  **immutable `-sha`** image (the controller refuses a mutable-tag CRD override).

## Future
- HPA on custom/Prometheus metrics (KEDA) instead of CPU.
- Replace the shared-secret service JWT with a k8s **TokenReview/ServiceAccount** path (see
  `specs/EPIC-sso-oidc.md`).

## Not live-validated on the 1-node dev cluster
HPA, podAntiAffinity/topologySpread, and the CloudNativePG/RedisFailover HA datastores are
**template-validated** (`helm template -f values-prod.yaml` renders them) and documented here, but have
**not** been exercised on a live multi-node cluster.
