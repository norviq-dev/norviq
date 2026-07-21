<!-- SPDX-License-Identifier: Apache-2.0 -->
# Norviq Production Configuration Checklist

Run through this before promoting a Norviq install to production. Each item names the exact value /
env var and how to verify it.

## 1. Secrets (mostly handled — know what the chart does for you)
The API signs/validates tokens with `api_secret_key`. **You usually do not need to set it.** Left at
its sentinel default (`change-me-in-production`), `templates/secret.yaml` generates a strong random
48-char secret on first install and **reuses the live one on upgrade** via a cluster `lookup`, so
upgrades never invalidate existing sessions/JWTs. The seeded admin password gets the same treatment
(and is always `must_change=true` at first login). An explicit value always wins verbatim — set one
only to pin your own secret for rotation or as a multi-cluster fleet trust root:

```bash
helm upgrade --install norviq ./helm/norviq \
  --set-json 'policyQuotaNamespaces=["prod-agents"]' \
  --set api.secretKey="$(openssl rand -base64 48)"
```
(`policyQuotaNamespaces` is required on every install — see §3b.)

Retrieve the generated admin password (this reads a Secret — do it yourself, don't paste it anywhere):

```bash
kubectl get secret norviq-secrets -n norviq \
  -o jsonpath='{.data.NRVQ_AUTH_ADMIN_PASSWORD}' | base64 -d
```

- `config.requireStrongSecret` is **`true` by default** (not opt-in). It makes the API refuse to start
  on a weak/default JWT secret or the default admin password (logs `NRVQ-API-7099` and raises), and it
  makes the chart **fail the render** if `postgresql.password` or `redis.password` is empty (and, on a
  hub, if the fleet DB password is empty or still `norviq_dev`). Set it `false` only for a throwaway
  cluster.
- **Datastore passwords are yours to supply in prod.** `values-prod.yaml` deliberately blanks
  `postgresql.password` / `redis.password` so a prod install cannot ship the well-known dev
  credentials. See [`prod-deploy-runbook.md`](prod-deploy-runbook.md#three-values-the-chart-refuses-to-guess).
- Verify a rotation took effect:
  ```bash
  # A token signed with the OLD secret must now be rejected (401).
  curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer <old-token>" \
    http://<api>/api/v1/audit/records   # expect 401
  ```

## 2. Database TLS
- `config.dbSslMode` → `NRVQ_DB_SSL_MODE` (`require` | `verify-ca` | `verify-full`). **Already
  `require` in the base values** — raise it to `verify-ca`/`verify-full` if your Postgres presents a
  CA you pin. Verify: API startup logs `NRVQ-DB-DEBUG-CONNECT-ARGS` shows the resolved `ssl` mode.

## 3. High availability
- `api.replicas: 2` (default) + `api.pdb.enabled: true` (default) keep enforcement available during
  node drains/upgrades. Postgres/Redis ship as single-replica StatefulSets — point at managed HA
  datastores, or use the `values-prod.yaml` operator-backed HA, for production.

## 3b. Baseline policy coverage (fail-closed)
`baselineClusterPolicy.enabled` is `true` by default and renders **one baseline policy per namespace
listed in `policyQuotaNamespaces`** — which ships **empty**. The chart therefore **fails the render**
until you list your tenant namespaces (or explicitly set `baselineClusterPolicy.enabled=false`),
rather than installing with zero baselines and a silently fail-open posture.

```bash
helm upgrade --install norviq ./helm/norviq \
  --set-json 'policyQuotaNamespaces=["prod-agents","analytics"]'
```
Each listed namespace must already exist. The same list also drives the optional per-tenant
`NrvqPolicy` ResourceQuota and (when enabled) the agent-egress NetworkPolicy.

## 4. Sidecar injection (turnkey TLS)
- Enable: `--set webhook.injection.enabled=true`. A post-install hook Job self-signs the serving
  cert, writes the `norviq-webhook-tls` secret, and patches the webhook `caBundle` (no cert-manager
  required). Opt namespaces in: `kubectl label ns <ns> norviq-injection=enabled`.
- Verify: `kubectl get mutatingwebhookconfiguration norviq-sidecar-injector -o jsonpath='{.webhooks[0].clientConfig.caBundle}' | head -c 20` is non-empty.
- Two injection knobs decide whether enforcement can be dodged. Both already default to the safe
  value; changing them is a deliberate weakening:
  - `webhook.injection.failurePolicy: Fail` (default) — fail-**closed**: if the injector is
    unavailable, pod creation in an injection-enabled namespace is rejected, so an agent pod can never
    start un-guarded. `Ignore` (fail-open) is a dev/eval setting. The webhook is HA (2 replicas + PDB
    in the prod overlay) and control-plane namespaces are excluded from the selector, so `Fail` does
    not self-deadlock.
  - `webhook.injection.allowPodOptOut: true` (default, backward-compatible) — honors the per-pod
    `norviq-injection=disabled` label / `norviq.io/skip-injection` annotation. That means **a pod
    author in an injection-enabled namespace can exempt their own workload from enforcement.** Set it
    `false` to make injection namespace-uniform, and pair that with RBAC on pod label/annotation
    writes.
- Injected sidecars are pinned to the immutable `-sha` image; the controller refuses a mutable-tag
  (`:latest` / `…-latest`) override and keeps the pinned image, logging `NRVQ-WHK-4036`.

## 5. RBAC bindings
The chart ships ClusterRoles `norviq-admin`, `norviq-policy-editor`, `norviq-viewer` but **no
subject bindings**. Map them to your IdP groups / ServiceAccounts:
```yaml
rbac:
  exampleBindings:
    enabled: true
  bindings:
    - { role: norviq-admin,         kind: Group,          name: norviq-platform-admins }
    - { role: norviq-viewer,        kind: Group,          name: norviq-readonly }
    - { role: norviq-policy-editor, kind: ServiceAccount, name: ci-policy-bot, namespace: norviq }
```
Verify: `kubectl get clusterrolebinding | grep norviq-`.

## 6. SIEM export / forwarding
- Pull (always on, authenticated + namespace-scoped):
  `GET /api/v1/audit/export?format=ndjson|csv&range=24h&namespace=<ns>&decision=<d>`.
  `range` accepts `1h | 6h | 24h | 7d | 30d`. The `namespace` param goes through the same scoping
  helper as every other read (see [`namespace-scoping.md`](namespace-scoping.md)), so an export can
  never widen a caller's reach.
  Add **`signed=true`** (NDJSON only) for a tamper-evident export: each record carries a hash-chain
  link (`seq`, `prev_hash`, `record_hash`) and the stream ends with a `_manifest` line whose chain tip
  is HMAC-SHA256-signed **when `audit_export_signing_key` (`NRVQ_AUDIT_EXPORT_SIGNING_KEY`) is set** —
  it ships empty, so set it before you rely on signed exports as compliance evidence.
- Push (opt-in forwarder): `siem.enabled=true`, `siem.webhookUrl=https://siem/ingest`,
  `siem.format=ndjson|syslog` → `NRVQ_SIEM_*` env. The API POSTs new audit rows on
  `siem.pollIntervalSeconds` (default 30). Logs `NRVQ-SIEM-14000` on start.
- Audit rows are pruned by `config.retention.auditRetentionDays` (**30d default** — the console never
  shows a longer window anyway). SOC2/ISO horizons need more: raise it to 90–365, or schedule signed
  exports for durable evidence.

## 7. Enforcement posture
- `config.enforcementMode: block` (default; not `audit`) for real enforcement.
- `config.noPolicyDecision: deny` (default) — a namespace with **no** matching policy denies in block
  mode. Setting it to `allow` restores fail-**open** for uncovered namespaces; that is a deliberate
  choice, not a default. Combined with the per-namespace baselines from §3b this is what keeps an
  unconfigured tenant from being an enforcement hole.
- Confirm seeded policies cover every tenant `(namespace, agent_class)` you run.
- `config.opaMode: server` (default) runs OPA as the long-lived sidecar; `subprocess` forks per call
  and exists only as a rollback path.
