# Getting Started

This walkthrough takes you from an empty Kubernetes cluster to a policy that actually blocks a
tool call — install the chart, apply a policy, and watch a decision flip from `allow` to `block`.

If you haven't already, skim the root [README](../README.md) for the concepts: Norviq is a
policy enforcement point (PEP) that sits between an agent and its tools, evaluates every call
against OPA/Rego policies scoped to the workload's identity, and returns `allow` / `block` /
`escalate` / `audit`.

## 1. Prerequisites

- A Kubernetes cluster, **1.30+**
- `kubectl`
- `helm` 3

For local evaluation, a single-node [kind](https://kind.sigs.k8s.io/) cluster is enough for
everything in this guide (multi-node HA and the fleet features need a real multi-node cluster —
see [deployment.md](deployment.md)):

```bash
kind create cluster --name norviq-local
kubectl version   # confirm the server is 1.30+
```

## 2. Install

```bash
git clone https://github.com/norviq-dev/norviq.git
cd norviq

# CRDs first (NrvqPolicy / NrvqClass / NrvqConfig)
kubectl apply -f helm/norviq/crds/

kubectl create namespace norviq

# On a local/kind cluster the bundled Postgres has no TLS listener, so the default
# config.dbSslMode=require will fail to connect — disable it for local eval:
helm install norviq ./helm/norviq -n norviq --set config.dbSslMode=disable
```

A few things worth knowing about this install:

- **Images** — `helm/norviq/values.yaml` defaults `images.registry` to `ghcr.io/norviq-dev/`, so
  this pulls the public `norviq-engine` images (api/engine/ui/webhook tags) straight from GHCR —
  no registry login or `imagePullSecrets` needed for a stock install.
- **Bundled dependencies** — the chart also deploys single-replica PostgreSQL (`postgres:16-alpine`)
  and Redis (`redis:7-alpine`) StatefulSets, plus an OPA (`openpolicyagent/opa:1.18.0-static`)
  sidecar in every API/engine pod. Nothing external is required to get the core stack running.
- **`config.dbSslMode`** — the API's DB connection mode. The chart default is `require` (correct
  for a managed/TLS-terminating Postgres in production — see `helm/norviq/values-prod.yaml`), but
  the bundled Postgres StatefulSet doesn't enable TLS, so a **local install must set
  `config.dbSslMode=disable`** as shown above (this is exactly what a single-node dev/eval overlay
  like `scripts/eval/values-local.yaml` sets for its cluster). Skipping this on kind will
  leave the API pod failing to connect to its own database.
- Wait for the rollout before continuing:

  ```bash
  kubectl -n norviq rollout status deploy/norviq-api
  kubectl -n norviq rollout status deploy/norviq-ui
  ```

## 3. Access the console and change the admin password

Port-forward the console (its nginx also proxies `/api/*` to the API, so this one
port-forward is enough for everything in this guide, including the `curl` example later):

```bash
kubectl -n norviq port-forward svc/norviq-ui 8080:80
```

Open http://localhost:8080.

The chart seeds a local `admin` account (`auth.adminUsername`/`auth.adminPassword` in
`values.yaml`). Leaving `auth.adminPassword` at its shipped sentinel value (`norviq`) makes the
chart **auto-generate a strong random first password** on install instead of using the literal
default — retrieve it with:

```bash
kubectl get secret norviq-secrets -n norviq -o jsonpath='{.data.NRVQ_AUTH_ADMIN_PASSWORD}' | base64 -d
```

Sign in as `admin` with that password. You'll be **forced to change it** before you can do
anything else (the API rejects every authenticated call except `/auth/change-password`,
`/auth/logout`, and `/me` while the account is flagged `must_change`). The new password must be
at least `auth.minPasswordLength` characters (12 by default) and can't be the current or default
password. After changing it, sign in again to get a session token that isn't flagged
`must_change`.

## 4. Enable sidecar injection for an agent namespace

Sidecar injection is off by default (`webhook.injection.enabled: false`). Turn it on:

```bash
helm upgrade norviq ./helm/norviq -n norviq --reuse-values --set webhook.injection.enabled=true
```

This renders the `MutatingWebhookConfiguration` and a one-shot Job that self-signs a TLS cert for
the webhook (no cert-manager required). Once it's up, label the namespace that runs your agent
workloads — the webhook's namespace selector matches the key `norviq-injection=enabled`
(`webhook/handler.go`'s `NRVQ_ENABLE_LABEL`, default `norviq-injection`):

```bash
kubectl create namespace chatbot-prod
kubectl label namespace chatbot-prod norviq-injection=enabled
```

Every new pod created in `chatbot-prod` from now on gets the Norviq sidecar injected
automatically (a pod can opt out individually with the label
`norviq-injection=disabled` or the annotation `norviq.io/skip-injection: "true"`). By default the
sidecar runs in `sidecarMode: proxy` — it forwards each tool call to the central API's
`/evaluate` over a namespace-scoped service token; nothing is evaluated per-pod. Tag your agent's
pod spec with `norviq.io/agent-class: <class>` so class-tier policy (below) actually matches it.

## 5. Apply your first policy

The repo ships ready-to-use examples under `crds/examples/`. Apply an agent class and two
policies that target it:

```bash
kubectl apply -f crds/examples/class-customer-support.yaml
kubectl apply -f crds/examples/policy-strict-chatbot.yaml
kubectl apply -f crds/examples/policy-namespace-baseline.yaml
```

What these do:

- **`class-customer-support.yaml`** (`NrvqClass`) — registers the `customer-support` agent class
  (with a descriptive tool list, call-rate cap, and trust-score fields in its spec) so that a
  `NrvqPolicy` can target it by name via `target.agentClass`. The actual tool-call decision comes
  from the policy below, not from this class spec.
- **`policy-strict-chatbot.yaml`** (`NrvqPolicy`, namespace `chatbot-prod`) — targets
  `agentClass: customer-support`, `enforcementMode: block`, `preset: strict`, `priority: 200`.
  The `strict` preset blocks high-risk tool calls outright (`execute_sql`, anything named
  `delete_*`/`drop_*`/`truncate_*`/`destroy_*`) plus prompt-injection, SQL/shell-injection,
  PII/PCI, and data-exfiltration patterns in the params — see `webhook/presets/strict.rego`.
- **`policy-namespace-baseline.yaml`** (`NrvqPolicy`, namespace `chatbot-prod`) — a whole-namespace
  fallback (`preset: permissive`, `enforcementMode: audit`, `priority: 50`). Priority is lower than
  the class policy above, so it only decides when nothing more specific matches.

The webhook's CRD controller watches these objects and syncs them to the API
(`POST /api/v1/policies`) automatically — nothing else to run. Confirm they synced:

```bash
kubectl get nrvqpolicy -n chatbot-prod
# STATUS should move from Pending to Active once the controller confirms the sync
```

### See a decision flip

You can watch this from the console's audit stream, or drive it directly against
`POST /api/v1/evaluate` (the exact request shape is `norviq/sdk/core/events.py`'s
`ToolCallEvent`: `tool_name`, `tool_params`, `agent_identity{spiffe_id, namespace, agent_class}`).

Get a session token (using the password you changed in step 3):

```bash
TOKEN=$(curl -s -X POST http://localhost:8080/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"<your new password>"}' | python3 -c 'import sys,json; print(json.load(sys.stdin)["access_token"])')
```

A call the `strict` preset blocks:

```bash
curl -s -X POST http://localhost:8080/api/v1/evaluate \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{
        "tool_name": "execute_sql",
        "tool_params": {"query": "SELECT * FROM orders"},
        "agent_identity": {
          "spiffe_id": "spiffe://norviq/ns/chatbot-prod/sa/chatbot-agent",
          "namespace": "chatbot-prod",
          "agent_class": "customer-support"
        }
      }'
# {"decision":"block","rule_id":"strict_default_block", ...}
```

The same shape with an allowed tool:

```bash
curl -s -X POST http://localhost:8080/api/v1/evaluate \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{
        "tool_name": "search_kb",
        "tool_params": {"query": "refund policy"},
        "agent_identity": {
          "spiffe_id": "spiffe://norviq/ns/chatbot-prod/sa/chatbot-agent",
          "namespace": "chatbot-prod",
          "agent_class": "customer-support"
        }
      }'
# {"decision":"allow","rule_id":"default_allow", ...}
```

Same identity, same endpoint — only the tool call changed, and the decision flipped. Every one of
these calls is also written to the audit log, which the console streams live.

## 6. Next steps

- **[Concepts](concepts.md)** — agent classes, policy tiers, enforcement modes, SPIFFE identity
- **[Writing Policies](guides/writing-policies.md)** — authoring Rego, the intent generator, red-team
- **[Configuration](configuration.md)** — the full Helm `values.yaml` reference
- **[Deployment](deployment.md)** — kind, cloud/AKS, HA, and multi-cluster fleet
