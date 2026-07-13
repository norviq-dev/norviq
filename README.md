# Norviq

[![FOSSA Security](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fnorviq-dev%2Fnorviq.svg?type=shield&issueType=security)](https://app.fossa.com/projects/git%2Bgithub.com%2Fnorviq-dev%2Fnorviq?ref=badge_shield&issueType=security)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

**Runtime policy enforcement for LLM agent tool calls on Kubernetes.**

Norviq is a policy enforcement point (PEP) that sits between an AI agent's reasoning loop and the
tools it can call. Every tool call is intercepted, evaluated against OPA/Rego policies scoped to the
workload's Kubernetes/SPIFFE identity, and then **allowed, blocked, escalated, or audited** — before
the tool runs. It turns "the model decided to call `execute_sql` / `send_email` / `shell`" from an
implicit trust into an enforced, per-identity, auditable decision.

---

## Why

LLM agents are given real tools — databases, shells, email, cloud APIs, internal services. The model
chooses which to call at runtime, and a single prompt injection or reasoning error can turn a benign
agent into an exfiltration or destruction path. Norviq puts a deterministic, policy-driven gate on
that surface, so a tool call only happens if an explicit policy for that agent's identity allows it.

## How it works

```
  Agent (LangGraph / LangChain / SDK)
        │  tool call: {tool, params, agent identity}
        ▼
  Norviq sidecar / SDK  ──────►  POST /evaluate  ──►  Engine
                                                       ├─ resolve identity (SPIFFE SVID)
                                                       ├─ collect policies (class → namespace → cluster tiers + overlays)
                                                       ├─ evaluate against OPA/Rego
                                                       └─ decision: allow | block | escalate | audit
        ◄──────────────── decision + rule_id + reason ─┘
                                                       └─ audit log · trust score · asset/attack graph
```

- **Interception** — an injected sidecar (or the SDK) forwards each tool call to the engine's `/evaluate`.
- **Identity** — decisions are scoped to the calling workload's SPIFFE identity (SPIRE SVID), not a
  shared secret, so policy is per-agent-class and per-namespace.
- **Policy** — Rego policies are layered in tiers (agent-class → namespace baseline → cluster baseline)
  with tighten-only overlays; the most-restrictive matching rule wins.
- **Modes** — `block` (deny + reason), `escalate`, `audit` (log only / monitor mode), so you can roll
  out enforcement observably before turning it on.

## Features

- **Policy enforcement** — OPA/Rego evaluated per tool call, sub-second, fail-closed.
- **Kubernetes-native** — `NrvqPolicy` / `NrvqClass` / `NrvqConfig` CRDs, a mutating webhook that
  injects the enforcement sidecar, and a Helm chart.
- **Workload identity** — SPIFFE/SPIRE SVIDs (with a mock mode for non-SPIRE clusters).
- **Console UI** — policy catalog + editor, attack graph, asset graph, agent trust, audit stream.
- **Red-team suite** — built-in adversarial tests (prompt injection, encoding/nesting evasion, SQLi,
  PII/PCI exfil) that prove a policy actually blocks.
- **Compliance mapping** — MITRE ATLAS and OWASP LLM Top-10 coverage with generate-enforcing-policy
  remediation.
- **High availability** — multi-replica with cross-replica policy propagation and DB-authoritative
  deletes; HPA/PDB/anti-affinity for multi-node clusters.
- **Multi-cluster (fleet)** — signed policy-bundle distribution across a hub and spoke clusters.

## Quick start

**Prerequisites:** a Kubernetes cluster (1.30+), `kubectl`, and Helm 3.

```bash
git clone https://github.com/norviq-dev/norviq.git
cd norviq

# 1. Install the CRDs
kubectl apply -f crds/

# 2. Install Norviq (pulls the public images from ghcr.io/norviq-dev by default)
kubectl create namespace norviq
helm install norviq ./helm/norviq -n norviq \
  --set config.dbSslMode=disable   # the bundled Postgres has no TLS; omit if you point at an external TLS DB
```

The chart deploys the API, engine, console UI, mutating webhook, and bundled PostgreSQL + Redis + OPA.
Port-forward the console and sign in with the seeded admin account (you'll be prompted to change the
password on first login):

```bash
kubectl -n norviq port-forward svc/norviq-ui 8080:80
# open http://localhost:8080
```

To label a namespace for automatic sidecar injection:

```bash
kubectl label namespace <your-agent-namespace> norviq-injection=enabled
```

> Trying it locally? A single-node [kind](https://kind.sigs.k8s.io/) cluster is enough to evaluate
> everything except multi-node HA. See **[docs/getting-started.md](docs/getting-started.md)**.

## Documentation

- **[Getting Started](docs/getting-started.md)** — install, first policy, see enforcement flip a decision
- **[Concepts](docs/concepts.md)** — agent classes, policy tiers, enforcement modes, SPIFFE identity
- **[Writing Policies](docs/guides/writing-policies.md)** — authoring Rego, the intent generator, red-team
- **[Configuration](docs/configuration.md)** — Helm `values.yaml` reference
- **[Deployment](docs/deployment.md)** — kind, cloud/AKS, HA, and multi-cluster fleet
- **[Security Model](docs/security-model.md)** — trust boundaries and the threat model
- Engineering references live under [`docs/engineering/`](docs/engineering/).

## Development

```bash
pip install -e ".[dev]"   # backend + tooling
make test                 # ruff + pytest + vitest + opa
make lint
```

The stack is Python (FastAPI) + OPA/Rego for the engine, React + Vite (TypeScript) for the console, and
Go for the admission webhook. See **[CONTRIBUTING.md](CONTRIBUTING.md)**.

## Security

Found a vulnerability? Please follow the coordinated-disclosure process in **[SECURITY.md](SECURITY.md)** —
do not open a public issue for security reports.

## License

[Apache 2.0](LICENSE).
