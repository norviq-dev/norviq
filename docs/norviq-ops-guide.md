# Norviq Operations Guide

Critical operational knowledge for deployment, testing, and Lenovo/Zscaler pentest.

> **Going to production?** Start with the [Production Configuration Checklist](engineering/production-config.md)
> (secret rotation, DB TLS, HA, turnkey sidecar injection, RBAC bindings, SIEM export).

## 1. Webhook Safety Rules

| Rule | Why | How to Verify |
|---|---|---|
| failurePolicy: Fail (default) | Webhook down → pod creation in **injection-enabled** namespaces is BLOCKED (fail-closed — no un-guarded agent pods). Control-plane / system namespaces are excluded via namespaceSelector, so they still create. Override with `webhook.injection.failurePolicy=Ignore` only if you accept un-guarded pods on webhook outage. | `kubectl get mutatingwebhookconfiguration norviq-sidecar-injector -o jsonpath='{.webhooks[0].failurePolicy}'` (expect `Fail`) |
| System namespaces excluded | Never inject into kube-system, kube-public, kube-node-lease, norviq (the exclusion is what keeps a fail-closed webhook from deadlocking the control plane) | Check namespaceSelector in webhook config |
| Code-level namespace check | Belt + suspenders — handler.go also blocks system namespaces | Read webhook logs for NRVQ-WHK-4007 |
| timeoutSeconds: 5 | Webhook too slow → K8s skips it, pod creates normally | Check webhook config |
| Panic recovery | Webhook panics → returns Allowed:true → pod creates | Read handler code |
| Anti-tamper (fail-closed) | A pod that presents a fake/partial/pre-occupied version of the injector-owned plumbing (a sidecar with a command/args override, an untrusted-registry `norviq-engine` image, a rogue `NRVQ_API_URL`, a pre-set `norviq-socket` mount / `NRVQ_SOCKET_PATH` env, or a socket-mounting decoy) is **DENIED** (`NRVQ-WHK-4034`) rather than run un-injected. Injection is skipped only for a pod that is already *fully + correctly* wired. Init containers are wired too. | Try to create such a pod → expect admission denial |
| AKS + Azure Policy (clean install) | On AKS with the Azure Policy add-on, the built-in **"admissions-enforcer"** co-owns the injector `MutatingWebhookConfiguration`'s `namespaceSelector`, colliding with Helm's server-side apply and leaving the release **`failed`** (even though the webhook works). The chart carries `admissions.enforcer/disabled: "true"` so Helm fully owns the config (the AKS system-ns exclusions are baked into the chart's own selector), and preserves the cert-job-patched `caBundle` across upgrades via `lookup` (a second SSA conflict). No action needed — `helm upgrade` just succeeds. | `helm ls -n norviq` → `deployed`; `kubectl get mutatingwebhookconfiguration norviq-sidecar-injector -o jsonpath='{.metadata.annotations.admissions\.enforcer/disabled}'` → `true` |

### Enforcement-model limitations (defense-in-depth to add)

Sidecar enforcement is **cooperative-socket**: the injector wires each agent container to the sidecar's
local socket (`NRVQ_SOCKET_PATH`) and the SDK routes tool calls through it. The webhook makes this
**tamper-proof at admission time** (see the anti-tamper row above), but two vectors are outside what a
mutating webhook can close and must be handled operationally:

1. **Runtime bypass** — an app that, at runtime, *ignores* the injected socket and dials tools directly is
   not policed by the sidecar (the PEP is cooperative: the sidecar returns a forward/drop decision and the
   *agent* executes the tool). Two layers of mitigation:
   - **Shipped now — `agentEgressPolicy` (default-deny egress).** Set `agentEgressPolicy.enabled=true`
     and list your approved tool endpoints. Two engines:
     - `engine: networkpolicy` (default, portable) — allowlist by **CIDR**: `allowedCIDRs`, `allowedPorts`.
     - `engine: cilium` (requires the **Cilium** CNI) — allowlist by **hostname**: `allowedFQDNs`
       (exact, e.g. `api.openai.com`) and `allowedFQDNPatterns` (wildcard, e.g. `*.googleapis.com`), plus
       `allowedCIDRs` for IP-addressable tools. Cleaner for SaaS tools behind rotating/CDN IPs. The chart
       auto-adds the required Cilium DNS-visibility rule so `toFQDNs` resolves.

     Either way, an agent pod may then egress ONLY to the norviq API, DNS, and that allowlist — arbitrary
     data-exfiltration to the internet/attacker endpoints is blocked at the network layer. **Requires a
     NetworkPolicy-enforcing CNI (Calico/Cilium); kindnet ignores NetworkPolicy.** This bounds the blast
     radius but does NOT stop per-call param abuse of an *allowed* tool (e.g. `execute_sql` with
     `DROP TABLE` against an approved DB) — that still relies on the SDK routing the call through the PEP.
   - **Roadmap — non-cooperative enforcement.** Making the sidecar *execute* tools (agent → sidecar →
     tool, so a pod physically cannot run a tool without the PEP) is the full close; it is a separate
     re-architecture, not shipped. Prompt-injection of the model is NOT this case — enforcement sits in
     the tool-call path, so a routed-but-injected agent is still governed.
2. **`pods/ephemeralcontainers`** — the webhook intercepts pods `CREATE`, not the ephemeral-containers
   subresource, so a debug container added to a running pod is unwired. Mitigate by **not granting
   `pods/ephemeralcontainers`** to tenant roles (it is a break-glass/debug capability).

### Emergency: Webhook Breaking Cluster

```powershell
# Nuclear option — removes webhook entirely, pods create normally
kubectl delete mutatingwebhookconfiguration norviq-sidecar-injector
```

This instantly stops all sidecar injection. Existing pods are NOT affected.

## 2. Two-Gate Injection Model

```
Gate 1: NAMESPACE must have label    norviq-injection=enabled
Gate 2: POD must have label          norviq=enabled

Both required. Missing either = no injection.
```

### Enable injection for a namespace

```powershell
kubectl label namespace <name> norviq-injection=enabled
```

### Disable injection for a namespace

```powershell
kubectl label namespace <name> norviq-injection-
```

### Opt-out a specific pod (even in enabled namespace)

```yaml
metadata:
  labels:
    norviq: disabled
```

Or via annotation:

```yaml
metadata:
  annotations:
    norviq.io/skip-injection: "true"
```

### Protected namespaces (NEVER injectable)

- kube-system
- kube-public
- kube-node-lease
- norviq (our own namespace)

## 3. TLS Certificate Setup

The webhook requires a TLS certificate with proper SANs. Without SANs, K8s silently skips the webhook.

### Generate cert with SANs

```powershell
# Create openssl config
@"
[req]
default_bits = 2048
prompt = no
default_md = sha256
distinguished_name = dn
x509_extensions = v3_ext

[dn]
CN = norviq-webhook.norviq.svc

[v3_ext]
subjectAltName = DNS:norviq-webhook,DNS:norviq-webhook.norviq,DNS:norviq-webhook.norviq.svc,DNS:norviq-webhook.norviq.svc.cluster.local
"@ | Set-Content openssl.cnf

& "C:\Program Files\Git\usr\bin\openssl.exe" req -x509 -newkey rsa:2048 -keyout tls.key -out tls.crt -days 365 -nodes -config openssl.cnf -extensions v3_ext
```

### Verify SANs exist

```powershell
& "C:\Program Files\Git\usr\bin\openssl.exe" x509 -in tls.crt -text -noout | Select-String "DNS:"
```

Must show: `DNS:norviq-webhook, DNS:norviq-webhook.norviq, DNS:norviq-webhook.norviq.svc, DNS:norviq-webhook.norviq.svc.cluster.local`

### Create K8s secret

```powershell
kubectl create secret tls norviq-webhook-tls --cert=tls.crt --key=tls.key -n norviq
```

### Apply webhook config with caBundle

```powershell
$CA_BUNDLE = [Convert]::ToBase64String([System.IO.File]::ReadAllBytes("tls.crt"))

# Write to webhook-config-final.yaml with $CA_BUNDLE embedded
# Then: kubectl apply -f webhook-config-final.yaml
```

### Common TLS errors

| Error | Cause | Fix |
|---|---|---|
| `certificate relies on legacy Common Name field, use SANs instead` | Cert has CN but no SANs | Regenerate with `-extensions v3_ext` and openssl.cnf |
| `x509: certificate signed by unknown authority` | caBundle doesn't match the cert webhook is serving | Delete secret, regenerate cert, recreate secret, update caBundle |
| Pod creation blocked in an injection-enabled namespace | Webhook error (e.g. TLS verification failed) under the default `failurePolicy: Fail` | The injector is fail-closed by design — a webhook error blocks pods rather than silently skipping. Fix the underlying error (check webhook logs / caBundle); do NOT switch to `Ignore` as a workaround (that lets un-guarded pods through). |

## 4. Container Image Management

### Single Docker Hub repo with component tags

```
Repository: <DOCKERHUB_USERNAME>/norviq-engine
Tags:
  engine-latest     (Python: evaluator + cache + policy loader + sidecar)
  api-latest        (Python: FastAPI backend)
  ui-latest         (Node: React frontend + nginx)
  webhook-latest    (Go: mutating admission webhook)
  engine-{sha}      (versioned by git commit)
  api-{sha}
  ui-{sha}
  webhook-{sha}
```

### Force pull latest image (cached image issue)

```powershell
# All manifests have imagePullPolicy: Always
# But if stuck, restart the deployment:
kubectl rollout restart deployment/norviq-api -n norviq
kubectl rollout restart deployment/norviq-engine -n norviq
kubectl rollout restart deployment/norviq-webhook -n norviq
```

### Docker Hub free tier limits

- 1 private repo (we use <DOCKERHUB_USERNAME>/norviq-engine)
- Unlimited tags per repo
- 200 pulls per 6 hours
- Switch to public repo at public release

## 5. Database & Cache

### PostgreSQL

```
Service: norviq-postgresql.norviq.svc:5432
Database: norviq
User: norviq
Password: from values.yaml (<PASSWORD> for dev)
Storage: 5Gi PVC (values.yaml)
```

### Password mismatch fix

If API shows `InvalidPasswordError`:

```powershell
# Delete PG data and restart
kubectl delete statefulset norviq-postgresql -n norviq
kubectl delete pvc pg-data-norviq-postgresql-0 -n norviq
# If PVC stuck: kubectl patch pvc pg-data-norviq-postgresql-0 -n norviq --type=merge -p '{"metadata":{"finalizers":null}}'
helm upgrade norviq helm/norviq/ --namespace norviq -f helm/norviq/values-dev.yaml
```

### Redis

```
Service: norviq-redis.norviq.svc:6379
Password: from values.yaml (<PASSWORD> for dev)
Storage: 1Gi PVC
```

## 6. Accessing the Dashboard

```powershell
# Port forward UI
kubectl port-forward svc/norviq-ui 3000:80 -n norviq
# Open: http://localhost:3000

# Port forward API
kubectl port-forward svc/norviq-api 8080:8080 -n norviq
# Test: curl http://localhost:8080/healthz
```

### Dashboard shows zeros

| Cause | Fix |
|---|---|
| Namespace filter mismatch | Default namespace is 'default' in AppContext — data must be in that namespace |
| No audit data | Run seed script to generate test data |
| API unreachable | Check vite proxy uses 127.0.0.1 not localhost |

## 7. CLI Usage

```bash
# Set env vars
export NRVQ_API_URL=http://127.0.0.1:8080
export NRVQ_API_TOKEN=$(python -c "from jose import jwt; print(jwt.encode({'sub':'admin','role':'admin'}, '<API_SECRET_KEY>', algorithm='HS256'))")

# Commands
norviq status
norviq policy list
norviq audit stats --range 24h
norviq agent list
norviq audit top-blocked
```

### JWT token

```
Secret key: '<API_SECRET_KEY>' (from norviq/config.py settings.api_secret_key)
Algorithm: HS256
Payload: {"sub": "admin", "role": "admin"}
```

## 8. CI/CD Pipeline

```
Push to main → GitHub Actions:
  1. ci.yml: lint + test + security scan
  2. build.yml: build 4 images → push to Docker Hub (<DOCKERHUB_USERNAME>/norviq-engine:{component}-{sha})
  3. deploy.yml: helm upgrade to AKS
```

### GitHub Secrets required

| Secret | Value |
|---|---|
| DOCKERHUB_USERNAME | <DOCKERHUB_USERNAME> |
| DOCKERHUB_TOKEN | Docker Hub access token |
| AZURE_CREDENTIALS | Service principal JSON for AKS deployment |

### Azure details

```
Resource Group: rg-opsai-dev-eastus-001
AKS Cluster: norviq
Subscription: <SUBSCRIPTION_ID>
Service Principal: norviq-github-deploy (<SERVICE_PRINCIPAL_ID>)
```

**IMPORTANT: Rotate the service principal secret — it was exposed in chat.**

```powershell
az ad sp credential reset --id <SERVICE_PRINCIPAL_ID>
# Update AZURE_CREDENTIALS secret in GitHub with new JSON
```

## 9. Error Code Reference

```
NRVQ-SDK-1000s   Python SDK (interceptor, adapters)
NRVQ-ENG-2000s   Engine (evaluator, policy loader)
NRVQ-SDC-3000s   Sidecar (proxy, HTTP fallback)
NRVQ-WHK-4000s   Go Webhook (admission controller)
NRVQ-REG-5000s   Policy Registry
NRVQ-AUD-6000s   Audit Emitter (OTel + DB)
NRVQ-API-7000s   FastAPI Backend
NRVQ-CLI-8000s   CLI
NRVQ-DB-9000s    Database (PostgreSQL + Redis)
NRVQ-IDT-10000s  Identity (SPIFFE resolver)
```

### Query logs by error code

```powershell
# Specific error
kubectl logs deployment/norviq-api -n norviq | Select-String "NRVQ-API-7011"

# All errors
kubectl logs deployment/norviq-engine -n norviq | Select-String "error"

# Azure Monitor KQL (if Container Insights enabled)
# ContainerLogV2 | where LogMessage contains "NRVQ-WHK" | order by TimeGenerated desc
```

## 10. Helm Commands

```powershell
# Install / upgrade
helm upgrade --install norviq helm/norviq/ --namespace norviq -f helm/norviq/values-dev.yaml

# Check status
helm status norviq -n norviq
helm history norviq -n norviq

# Rollback
helm rollback norviq 1 -n norviq

# Uninstall (removes everything)
helm uninstall norviq -n norviq

# Template render (dry run)
helm template norviq helm/norviq/ -f helm/norviq/values-dev.yaml

# Lint
helm lint helm/norviq/
```

### Required onboarding step: quota coverage for tenant namespaces

`policyQuotaNamespaces` in Helm values must include **every** tenant namespace that can create `NrvqPolicy`.
If a namespace is missing from this list, no `ResourceQuota` is rendered there and policy-flood protection is absent.

Operational rule:
- On every tenant onboarding, add namespace to `policyQuotaNamespaces` and run `helm upgrade`.
- Label every tenant namespace with `norviq.io/policy-quota=enabled`; the ValidatingAdmissionPolicy denies `NrvqPolicy` creates/updates in unlabeled namespaces.

## 11. Troubleshooting Checklist

### Pod won't start

```powershell
kubectl describe pod <name> -n norviq
kubectl logs <pod-name> -n norviq --previous
kubectl get events -n norviq --sort-by='.lastTimestamp'
```

### ImagePullBackOff

```powershell
# Check image exists
docker pull <DOCKERHUB_USERNAME>/norviq-engine:api-latest

# Check pull secret
kubectl get secret dockerhub-secret -n norviq

# Check deployment uses imagePullSecrets
kubectl get deployment norviq-api -n norviq -o jsonpath='{.spec.template.spec.imagePullSecrets}'
```

### PVC stuck in Terminating

```powershell
kubectl patch pvc <name> -n norviq --type=merge -p '{"metadata":{"finalizers":null}}'
```

### Webhook not injecting

1. Check namespace has label: `kubectl get ns default --show-labels`
2. Check pod has label: `norviq=enabled`
3. Check webhook is running: `kubectl get pods -l app=norviq-webhook -n norviq`
4. Check webhook logs: `kubectl logs deployment/norviq-webhook -n norviq`
5. Temporarily set failurePolicy: Fail to see actual errors
6. Check cert SANs: `openssl x509 -in tls.crt -text -noout | grep DNS`

## 12. Lenovo/Zscaler Pentest Prep

### Before pentest

```powershell
# Scan all images for CVEs
# trivy image <DOCKERHUB_USERNAME>/norviq-engine:engine-latest
# trivy image <DOCKERHUB_USERNAME>/norviq-engine:api-latest
# trivy image <DOCKERHUB_USERNAME>/norviq-engine:ui-latest
# trivy image <DOCKERHUB_USERNAME>/norviq-engine:webhook-latest

# Scan Helm manifests
# kubescape scan helm/norviq/templates/

# Check Python deps
# pip-audit --skip-editable

# Check Node deps
# cd ui && npm audit

# Check Go deps
# cd webhook && govulncheck ./...
```

### Known items to fix before pentest

- [ ] Rotate Azure service principal secret (exposed in chat)
- [ ] Change API secret key from '<API_SECRET_KEY>' to a real secret
- [ ] Change Redis/PostgreSQL passwords from '<PASSWORD>' defaults
- [ ] Enable HTTPS on API (currently HTTP)
- [ ] Add rate limiting on API endpoints
- [ ] Add CORS restrictions on API
- [ ] Review all container security contexts
- [ ] Generate and store SBOMs

### What Zscaler/SPLX will test

| Area | What They Check | Our Status |
|---|---|---|
| API OWASP Top 10 | Injection, auth bypass, broken access | JWT auth on all endpoints |
| Container security | CVEs, root user, privileged containers | Non-root, drop ALL caps |
| K8s misconfig | RBAC, network policies, secrets | Secrets in K8s Secret objects |
| TLS | Weak ciphers, expired certs | TLS 1.2+, SANs configured |
| Supply chain | Vulnerable dependencies | pip-audit + npm audit + govulncheck |

## 13. Architecture Quick Reference

```
┌─────────────────────────────────────────────────────────┐
│ Kubernetes Cluster (AKS: norviq)                        │
│                                                         │
│  namespace: norviq                                      │
│  ├── norviq-api (FastAPI, port 8080)                   │
│  ├── norviq-engine (sidecar proxy, port 8282)          │
│  ├── norviq-ui (React + nginx, port 80)                │
│  ├── norviq-webhook (Go, port 8443, TLS)               │
│  ├── norviq-redis (StatefulSet, port 6379)             │
│  └── norviq-postgresql (StatefulSet, port 5432)        │
│                                                         │
│  namespace: default (norviq-injection=enabled)          │
│  ├── smartsales-agent (norviq=enabled) → sidecar ✅    │
│  ├── redis (no label) → no sidecar ✅                  │
│  └── test-agent (norviq=enabled) → sidecar ✅          │
│                                                         │
│  namespace: kube-system (PROTECTED)                     │
│  └── coredns, kube-proxy → NEVER injected ✅           │
└─────────────────────────────────────────────────────────┘
```
