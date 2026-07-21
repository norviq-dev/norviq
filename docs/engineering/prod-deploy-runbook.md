<!-- SPDX-License-Identifier: Apache-2.0 -->
# Norviq Production Deploy Runbook (multi-node)

The chart ships **base `values.yaml` defaults** (single-node lean) plus a **`values-prod.yaml`**
overlay (multi-node). Everything prod-specific is **values-gated and off by default**, so
the dev cluster is unaffected. Companion: [`production-config.md`](production-config.md) (secrets/RBAC);
chart reference: [`helm/norviq/README.md`](../../helm/norviq/README.md); publishing:
[`release-runbook.md`](release-runbook.md).

This runbook is cloud-agnostic — the same steps stand up Norviq in any conformant cluster (AKS, EKS,
GKE, kind). Only the LoadBalancer/ingress annotations differ by provider, noted inline.

Two chart-wide behaviors to know up front:
- **Install namespace comes from `helm -n/--namespace`** (`.Release.Namespace`, the standard Helm
  contract) — there is no `namespace` value.
- **Values are validated against `values.schema.json`** on install/upgrade/template: a bad enum
  (e.g. `config.enforcementMode`) or type is rejected with a path + message before anything applies.
  Run `helm lint ./helm/norviq` to check a values file.

## Prerequisites (multi-node)
- **≥3 nodes** (so podAntiAffinity / topologySpread actually spread replicas).
- **metrics-server** installed (HPA reads CPU/mem).
- **CloudNativePG operator** installed (Postgres HA renders a `postgresql.cnpg.io/v1 Cluster`).
- **A Redis HA operator** — `values-prod` renders a Spotahome `RedisFailover` CR; swap
  `templates/redis-ha.yaml` + `redis.ha.serviceName` if you use a different stack (Bitnami, MemoryDB).
- A **public or pull-secret'd registry**. Default images are public on GHCR
  (`ghcr.io/norviq-dev/norviq-engine`). For scale prefer **Google Artifact Registry**
  (`images.registry: us-docker.pkg.dev/<PROJECT_ID>/<REPO>/`) or **ACR** — no anonymous
  pull-rate limit. Set `imagePullSecrets` to `[]` for a public registry, or to your
  registry's pull secret.

## What `values-prod.yaml` turns on
| Area | Dev (base `values.yaml`) | Prod overlay |
|---|---|---|
| api replicas / PDB | 2 / minAvailable 1 | HA floor 2 / minAvailable 2 |
| HPA | off | **api, engine, webhook** on — CPU 70% **+ memory 75%** (needs metrics-server). Sets a min floor and scales up on load; the Deployment drops its static `replicas` and the HPA owns the count (min→max: api 2→10, engine 2→8, webhook 2→4). |
| podAntiAffinity + topologySpread | off | on (spread across nodes) |
| engine replicas / PDB | 1 / off | HA floor 2 / minAvailable 1 + HPA + spread |
| webhook | 2, injection **off** | HA floor 2 + PDB + HPA + spread + injection **on** |
| Postgres | single StatefulSet | CloudNativePG `Cluster` (3) — operator required |
| Redis | single StatefulSet | `RedisFailover` (Sentinel, 3) — operator required |
| DB / Redis password | shipped dev defaults | **blank — you must supply them** (see below) |
| strong-secret guard / DB TLS | already on / already `require` | unchanged (on / `require`) |

Note what is *not* a prod-only setting: `config.requireStrongSecret` is **`true` by default** and
`config.dbSslMode` is already `require` in the base values. The overlay's real security delta is that
it **blanks `postgresql.password` / `redis.password`** so a prod install cannot silently ship the
well-known dev credentials — the render fails until you supply your own.

## Three values the chart REFUSES to guess

The chart fails the **render** (not the rollout) rather than install something quietly insecure. Each
`fail` names the missing value, so you find out at `helm template` time, not in production:

| Missing | Guard | Why it fails closed |
|---|---|---|
| `policyQuotaNamespaces` | `templates/baseline-cluster-policy.yaml` | `baselineClusterPolicy.enabled` is `true` by default and renders **one baseline per listed namespace**. With the list empty it would render ZERO baselines — every agent class silently loses the fail-closed cluster baseline. Set your tenant namespaces, or set `baselineClusterPolicy.enabled=false` to opt out explicitly. |
| `postgresql.password` | `templates/secret.yaml` | With `config.requireStrongSecret=true` (the default), an empty password would put a blank credential into `NRVQ_PG_URL`. |
| `redis.password` | `templates/secret.yaml` | Same, for `NRVQ_REDIS_URL`. |

Dry-run the render before you install — it costs nothing and catches all three at once:

```bash
helm template norviq ./helm/norviq -f helm/norviq/values-prod.yaml \
  --set-json 'policyQuotaNamespaces=["prod-agents","analytics"]' \
  --set postgresql.password="$PG_PASSWORD" --set redis.password="$REDIS_PASSWORD" >/dev/null
```

You do **not** need to pass `api.secretKey`: left at its sentinel default the chart auto-generates a
strong random JWT secret on first install and reuses the live one across upgrades (so upgrades never
invalidate sessions). Pass it explicitly only to pin your own — rotation, or a multi-cluster fleet
trust root.

## Deploy
```bash
# install operators first (CloudNativePG, redis-operator, metrics-server) per their docs, then:
helm upgrade --install norviq ./helm/norviq -n norviq --create-namespace \
  -f helm/norviq/values-prod.yaml \
  --set-json 'policyQuotaNamespaces=["prod-agents","analytics"]' \
  --set postgresql.password="$PG_PASSWORD" \
  --set redis.password="$REDIS_PASSWORD" \
  --set images.api.tag=api-<sha> --set images.engine.tag=engine-<sha> \
  --set images.ui.tag=ui-<sha> --set images.webhook.tag=webhook-<sha>   # pin -sha tags
```
`images.registry` already defaults to `ghcr.io/norviq-dev/` (all four components share the
`norviq-engine` repository, distinguished by tag prefix). Override the whole prefix — e.g.
`--set images.registry="us-docker.pkg.dev/<PROJECT_ID>/<REPO>/"` — only when mirroring to your own
registry; setting it to a bare `ghcr.io/` would resolve to a non-existent `ghcr.io/norviq-engine`.

The HA StatefulSets are auto-disabled when `*.ha.enabled` (the operators own the datastores); the API's
`NRVQ_PG_URL`/`NRVQ_REDIS_URL` auto-retarget the HA services (`*-rw` / failover service).

**Node scaling.** The HPAs scale *pods*; for the cluster to grow *nodes* to hold them, enable your
cloud's cluster-autoscaler on the node pool (e.g. AKS `az aks nodepool update
--enable-cluster-autoscaler --min-count N --max-count M`). Size the pool to hold at least the HA
floor (2× api+engine+webhook + the data tier).

## Reach the console (ingress + TLS)

Every Service is `ClusterIP`; the chart does not pick a hostname or mint a certificate — **host and
TLS are operator-supplied**. Two ways in:

**Port-forward (no ingress).** Fine for a bastion/VPN or a quick look. The console's nginx also
proxies `/api`, so one forward serves both UI and API:
```bash
kubectl -n norviq port-forward svc/norviq-ui 3000:80   # then http://localhost:3000
```

**Ingress (the product path).** Needs an ingress controller (the chart installs none):
```bash
# 1) install a controller. For an INTERNAL (private VNet) LB on AKS:
helm install ingress-nginx ingress-nginx/ingress-nginx -n ingress-nginx --create-namespace \
  --set controller.service.annotations."service\.beta\.kubernetes\.io/azure-load-balancer-internal"=true
# (EKS: service.beta.kubernetes.io/aws-load-balancer-internal="true"; GKE: cloud.google.com/load-balancer-type=Internal.
#  Omit the annotation for a public LB.)

# 2) get the LB IP, then supply your own host + TLS. Self-signed for a lab (a real deploy uses your
#    own cert or a cert-manager.io/cluster-issuer annotation via ingress.annotations):
LBIP=$(kubectl -n ingress-nginx get svc ingress-nginx-controller -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
HOST=${LBIP}.nip.io   # nip.io resolves the embedded IP anywhere; or use a real DNS name you own
openssl req -x509 -nodes -newkey rsa:2048 -days 825 -keyout tls.key -out tls.crt \
  -subj "/CN=${HOST}" -addext "subjectAltName=DNS:${HOST}"
kubectl -n norviq create secret tls norviq-ingress-tls --cert=tls.crt --key=tls.key

# 3) turn on the chart's ingress
helm upgrade norviq ./helm/norviq -n norviq --reuse-values \
  --set ingress.enabled=true --set ingress.host=$HOST --set ingress.tls=true
```
First-login credential: the chart auto-generates a strong admin password on first install (`admin` /
random, forced change on first login). Read it — `NOTES.txt` prints the exact command:
```bash
kubectl -n norviq get secret norviq-secrets -o jsonpath='{.data.NRVQ_AUTH_ADMIN_PASSWORD}' | base64 -d
```

## Observability (Prometheus + Grafana)

The API always serves Prometheus metrics at **`/metrics` on its Service port**, and the chart ships a
Grafana dashboard ConfigMap (`grafana_dashboard: "1"` — auto-imported by the Grafana sidecar). You
wire the *collection*:
```bash
# Prometheus Operator (kube-prometheus-stack) — a ServiceMonitor scoped to norviq-api:
--set otel.metrics.serviceMonitor.enabled=true \
--set otel.metrics.serviceMonitor.additionalLabels.release=kube-prometheus-stack   # match your Prometheus selector
# OR annotation-based Prometheus:
--set otel.metrics.scrapeAnnotations=true
# OPTIONAL: OTLP trace export — you MUST deploy a collector first (none ships with Norviq):
--set otel.enabled=true --set otel.endpoint=http://<your-collector>:4317
```
Without one of the two scrape paths, Prometheus never scrapes `/metrics` and the Grafana dashboard
shows "No data".

**Scrape per-pod when `api.replicas > 1`.** The `norviq_*` counters are in-memory and **per-replica** —
a long-lived agent/SDK connection pins its decisions to one API pod, so each replica holds only its own
slice (and resets on restart). Both scrape paths above discover pods individually, so Prometheus sums
across them correctly; a **single Service-level scrape or a `kubectl port-forward` can land on one
replica and read partial/zero** telemetry. The scrape target is the API **Service port** (`/metrics`) —
there is no separate metrics port.

**Traces (OTel) are opt-in and need a collector you run.** Norviq ships no collector. Tracing is OFF by
default with an empty endpoint; `otel.enabled=true` **fails the Helm render** unless you also set
`otel.endpoint` at a reachable OTLP/gRPC collector (e.g. an OpenTelemetry Collector or Grafana Tempo) —
so spans are never silently dropped into a void. Metrics (above) are independent of this and always on.

## Air-gapped / private registry

Norviq's own images use `images.registry` (default `ghcr.io/norviq-dev/`). The third-party images
(opa, redis, postgres, the tls-proxy nginx, the cert-bootstrap job, the helm-test curl) are mirrored
with `global.imageRegistry`:
```bash
--set images.registry="myregistry.example.com/norviq/" \
--set global.imageRegistry="myregistry.example.com"     # prepended to the six upstream images
```
Mirror the upstreams into your registry preserving their path (`.../openpolicyagent/opa`, `.../redis`, …).

## Verify the deploy
```bash
helm test norviq -n norviq            # a pod curls the API /healthz + /readyz through the Service
kubectl -n norviq get pods            # all Running/Ready
# enforcement, end-to-end, through an injected sidecar's unix socket (NDJSON, one JSON per line):
#   {"tool_name":"execute_sql","tool_params":{"query":"DROP TABLE x"},"session_id":"s"}  -> action=drop
#   {"tool_name":"search_kb","tool_params":{"q":"hi"},"session_id":"s"}                  -> action=forward
```

## Runtime guarantees (live on dev too)
- **Startup ordering** is enforced at *runtime*, not by Helm apply order: initContainers gate
  api/engine on postgres+redis and webhook on api; `/readyz` gates the Service. So `helm upgrade`
  ordering is irrelevant — a pod only serves once its hard deps are reachable.
- **Dependency-restart resilience:** `/readyz` returns **503** when Postgres/Redis/OPA is unreachable →
  the pod goes NotReady (drains traffic) while liveness (`/healthz`, process-up) keeps it alive (no
  CrashLoop). On recovery, `pool_pre_ping` reconnects Postgres, redis-py reconnects, and OPA re-push
  self-heals → `/readyz` 200 → Ready. **No manual restart.** Test: `kubectl delete pod
  norviq-postgresql-0` → api NotReady → Ready (RESTARTS stays 0); repeat for redis. (OPA is a sidecar
  *container*, not a pod — see the next bullet for how its health is asserted.)
- **OPA health has no kubelet probe — by design.** Both OPA sidecars (api and engine) bind
  **`127.0.0.1` only**, because `opa run --server`'s admin API (`/v1/policies`) is unauthenticated and
  read-**write**: anything that could reach it could rewrite or delete the enforcement policy. A
  kubelet probe dials the *pod IP*, never loopback, so any probe on that container would be refused
  forever and pin the pod NotReady; an exec probe is impossible too (the `-static` OPA image is
  distroless). Instead the **app's own `/readyz` calls `opa.health()` over localhost and ANDs it into
  readiness** — a dead OPA still removes the replica from the Service, and it proves the real consumer
  can reach OPA. Accepted trade-off: a wedged-but-listening OPA is **drained, not auto-restarted**.
  If you are debugging "is OPA up", read the app's `/readyz`; do not add a probe to the OPA container.
- **The engine evaluates locally.** The engine Deployment pins `NRVQ_SIDECAR_MODE=embedded`. The
  setting's own default is `proxy` (a thin forwarder to the central API), which is wrong for this
  workload: nothing issues it an `NRVQ_API_TOKEN`, so every call would 401 and fail closed — an outage
  that looks like enforcement. It runs its own OPA sidecar and waits on Postgres **and** Redis.
- **Graceful rollout:** `preStop` sleep + `terminationGracePeriodSeconds: 30` drain in-flight requests
  before SIGTERM.
- **Webhook → API:** the controller mints a short-lived **service-role HS256 JWT** from the API secret
  (the API accepts `service` on policy create/delete only). Injected sidecars are pinned to the
  **immutable `-sha`** image (the controller refuses a mutable-tag CRD override).

## Future
- HPA on custom/Prometheus metrics (KEDA) instead of CPU.
- Replace the shared-secret service JWT with a k8s **TokenReview/ServiceAccount** path.

## What is asserted by tests vs only template-validated
The chart's runtime contract is covered by tests you can run without a cluster:

| Suite | Asserts |
|---|---|
| `tests/helm/test_container_runtime_contract.py` | every container's securityContext / probe / writable-path contract |
| `tests/helm/test_network_exposure_matrix.py` | what each component actually binds and exposes (this is what pins the OPA loopback bind) |
| `tests/integration/test_data_plane_enforcement.py` | the enforcement path end-to-end |
| `tests/integration/test_injected_sidecar_health.py` | an injected sidecar comes up healthy |
| `tests/engine/test_failures_are_loud.py` | failures surface instead of silently degrading to allow |

Still only **template-validated**: HPA, podAntiAffinity/topologySpread, and the
CloudNativePG/RedisFailover HA datastores render from `helm template -f values-prod.yaml`, but the
multi-node behavior they buy has not been exercised on a live multi-node cluster.
