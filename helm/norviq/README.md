<!-- SPDX-License-Identifier: Apache-2.0 -->
# Norviq Helm chart

Runtime policy enforcement for LLM-agent tool calls on Kubernetes. This chart deploys the full
Norviq control plane and, optionally, the sidecar-injecting admission webhook.

## What it deploys

- **API** (`norviq-api`) — the control plane / policy decision point (PDP) + console backend, with a
  per-replica OPA sidecar bound to loopback.
- **Engine** (`norviq-engine`) — the standalone embedded evaluator on the enforcement hot path.
- **Console** (`norviq-ui`) — the React UI; its nginx also reverse-proxies `/api` to the API, so a
  single Ingress host serves both.
- **Webhook** (`norviq-webhook`) — a mutating admission webhook that injects the enforcement sidecar
  into pods in namespaces labelled `norviq-injection=enabled`. Off by default.
- **Postgres** and **Redis** — vendored as first-class templates (not subcharts), so their pod spec,
  security context and resources are governed by the same values and hardening as everything else,
  with no subchart value-passing. Bring your own managed Postgres/Redis by pointing the connection
  values at them and disabling the in-chart ones.
- **CRDs** — `NrvqPolicy`, `NrvqClass`, `NrvqConfig`, installed from `crds/`.

## Prerequisites

- **Kubernetes ≥ 1.30** (enforced via `Chart.yaml` `kubeVersion`).
- **metrics-server** — only if you enable autoscaling (the HPAs use `autoscaling/v2` resource metrics).
- **An ingress controller** (e.g. ingress-nginx) — only if you set `ingress.enabled=true`. The chart
  does not install one.
- A **NetworkPolicy-enforcing CNI** (Calico/Cilium) — only if you enable `agentEgressPolicy`.

## Install

The chart installs into the namespace from `helm -n/--namespace` (standard Helm), and fails closed
without an explicit tenant list — supply `policyQuotaNamespaces`:

```bash
helm install norviq oci://ghcr.io/norviq-dev/charts/norviq --version 0.2.4 \
  -n norviq --create-namespace \
  --set-json 'policyQuotaNamespaces=["default"]'
```

Production HA + autoscaling profile:

```bash
helm pull oci://ghcr.io/norviq-dev/charts/norviq --version 0.2.4 --untar   # for values-prod.yaml
helm install norviq ./norviq -n norviq --create-namespace \
  -f ./norviq/values-prod.yaml \
  --set postgresql.password=<strong> --set redis.password=<strong> \
  --set-json 'policyQuotaNamespaces=["team-a","team-b"]'
```

`--wait` / `--atomic` are supported on a fresh cluster. They did not used to be: the webhook mounts
its serving-cert Secret non-optionally and that Secret was minted by a **post-install** hook, which
Helm runs only after `--wait` returns — so the install blocked on a pod waiting for a Secret that the
blocked install was supposed to create. The cert hook now runs pre- *and* post-install (mint first,
patch the webhook `caBundle` after), so a scripted install completes.

Verify the release actually serves traffic:

```bash
helm test norviq -n norviq
```

Upgrade / uninstall:

```bash
helm upgrade norviq oci://ghcr.io/norviq-dev/charts/norviq --version 0.2.4 -n norviq --reset-then-reuse-values
helm uninstall norviq -n norviq
```

`--reset-then-reuse-values` needs Helm ≥ 3.14. Do not use `--reuse-values`: it replays only the
values *you* supplied last time and does not merge in values a newer chart added, so upgrading
across a release that introduced one fails with `nil pointer evaluating interface {}`. On older
Helm, pass your own `-f values.yaml` instead.

## Expose the console (optional)

Host and TLS are operator-supplied — the chart does not pick a hostname or mint a certificate:

```bash
--set ingress.enabled=true \
--set ingress.host=norviq.example.com \
--set ingress.tls=true --set ingress.tlsSecretName=norviq-ingress-tls
# then pre-create the TLS secret, or add a cert-manager.io/cluster-issuer via ingress.annotations
```

## Values

Values are validated against [`values.schema.json`](values.schema.json) on every
install/upgrade/template — a bad enum (e.g. `config.enforcementMode`) or type is rejected with a
clear path and message before anything is applied.

Every value is documented inline in [`values.yaml`](values.yaml); the environment overlays
[`values-prod.yaml`](values-prod.yaml), [`values-dev.yaml`](values-dev.yaml) and
[`values-light.yaml`](values-light.yaml) show complete, coherent profiles. The most load-bearing knobs:

| Key | Default | Notes |
|---|---|---|
| `policyQuotaNamespaces` | `[]` | **Required.** Tenant namespaces to protect. Empty + `baselineClusterPolicy.enabled` fails the install by design. |
| `config.enforcementMode` | `block` | `block` (enforce) or `audit` (visibility only). |
| `config.noPolicyDecision` | `allow` | Decision when no policy is loaded. Ships `allow`, matching `values.yaml`; the call carries the named `default_allow` rule. `deny` = fail-closed, and applies only in `block` enforcement mode. |
| `config.requireStrongSecret` | `true` | Refuse to boot on a weak/default JWT secret or admin password. |
| `webhook.injection.enabled` | `false` | Turn on sidecar injection (auto-bootstraps TLS, no cert-manager needed). |
| `webhook.injection.failurePolicy` | `Fail` | `Fail` = a pod the webhook **routes** cannot start un-guarded. Under `gateOnlyAgentPods: true` (default) only pods labelled `norviq.io/agent-class` are routed. |
| `{api,engine,webhook}.autoscaling.enabled` | `false` | HPA on CPU and/or memory; the Deployment then drops its static `replicas`. |
| `ingress.enabled` | `false` | See "Expose the console". |
| `images.registry` | `ghcr.io/norviq-dev/` | Override to mirror into your own registry/ACR/GAR. |

## Notes

- **CRDs are installed once from `crds/` and are NOT upgraded or deleted by `helm upgrade`/`uninstall`**
  (a Helm limitation for the `crds/` directory). To update a CRD schema, `kubectl apply` the new
  definition yourself; to remove them, delete them explicitly after uninstall.
- **Resource names are fixed** (`norviq-api`, …) — the chart is a cluster-singleton control plane
  (one PDP + one mutating webhook per cluster, like cert-manager/ingress-nginx), so it is not designed
  for two releases in one namespace. `nameOverride`/`fullnameOverride` affect only the
  `app.kubernetes.io/name` label, not resource names.
