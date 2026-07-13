<!-- SPDX-License-Identifier: Apache-2.0 -->
# Norviq Production Configuration Checklist

Run through this before promoting a Norviq install to production. Each item names the exact value /
env var and how to verify it. Companion to [`docs/norviq-ops-guide.md`](../norviq-ops-guide.md).

## 1. JWT secret rotation (REQUIRED)
The API signs/validates tokens with `api_secret_key`; the shipped default
(`change-me-in-production`) makes tokens forgeable.

- Set a strong secret. The chart wires `NRVQ_API_SECRET_KEY` from the `norviq-secrets` Secret:
  ```bash
  helm upgrade --install norviq ./helm/norviq \
    --set api.secretKey="$(openssl rand -base64 48)" \
    --set config.requireStrongSecret=true
  ```
- `config.requireStrongSecret=true` makes the API **refuse to start** on the default secret
  (logs `NRVQ-API-7099` and raises). Leave it `false` only in dev/test.
- **Alias note:** `NRVQ_API_SECRET_KEY` / `NRVQ_DB_SSL_MODE` now bind correctly (the Tier-A pass
  fixed a pydantic alias bug where the chart's `NRVQ_`-prefixed env was ignored and the secret was
  pinned to the default). Verify rotation took effect:
  ```bash
  # A token signed with the OLD/default secret must now be rejected (401).
  curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer <old-token>" \
    http://<api>/api/v1/audit/records   # expect 401
  ```

## 2. Database TLS
- `config.dbSslMode` → `NRVQ_DB_SSL_MODE` (`require` | `verify-ca` | `verify-full`). Production
  should be `require` or stricter. Verify: API startup logs `NRVQ-DB-DEBUG-CONNECT-ARGS` shows the
  resolved `ssl` mode.

## 3. High availability
- `api.replicas: 2` (default) + `api.pdb.enabled: true` keep enforcement available during node
  drains/upgrades. Postgres/Redis ship as single-replica StatefulSets — point at managed HA
  datastores for production.

## 4. Sidecar injection (turnkey TLS)
- Enable: `--set webhook.injection.enabled=true`. A post-install hook Job self-signs the serving
  cert, writes the `norviq-webhook-tls` secret, and patches the webhook `caBundle` (no cert-manager
  required). Opt namespaces in: `kubectl label ns <ns> norviq-injection=enabled`.
- Verify: `kubectl get mutatingwebhookconfiguration norviq-sidecar-injector -o jsonpath='{.webhooks[0].clientConfig.caBundle}' | head -c 20` is non-empty.

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
  `GET /api/v1/audit/export?format=ndjson|csv&range=24h&namespace=<ns>`.
- Push (opt-in forwarder): `siem.enabled=true`, `siem.webhookUrl=https://siem/ingest`,
  `siem.format=ndjson` → `NRVQ_SIEM_*` env. The API POSTs new audit rows on
  `siem.pollIntervalSeconds`. Logs `NRVQ-SIEM-14000` on start.

## 7. Enforcement posture
- `config.enforcementMode: block` (not `audit`) for real enforcement. `baselineClusterPolicy.enabled:
  true` preserves fail-closed posture. Confirm seeded policies cover every tenant
  `(namespace, agent_class)` you run.
