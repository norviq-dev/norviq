# Norviq Operations Guide

Critical operational knowledge for deployment, testing, and Lenovo/Zscaler pentest.

## 1. Webhook Safety Rules

| Rule | Why | How to Verify |
|---|---|---|
| failurePolicy: Ignore | Webhook down → pods still create normally | `kubectl get mutatingwebhookconfiguration norviq-sidecar-injector -o jsonpath='{.webhooks[0].failurePolicy}'` |
| System namespaces excluded | Never inject into kube-system, kube-public, kube-node-lease, norviq | Check namespaceSelector in webhook config |
| Code-level namespace check | Belt + suspenders — handler.go also blocks system namespaces | Read webhook logs for NRVQ-WHK-4007 |
| timeoutSeconds: 5 | Webhook too slow → K8s skips it, pod creates normally | Check webhook config |
| Panic recovery | Webhook panics → returns Allowed:true → pod creates | Read handler code |

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
| Webhook silently skipped (failurePolicy: Ignore) | TLS verification failed | Temporarily set failurePolicy: Fail to see the actual error |

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
