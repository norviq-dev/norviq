# Norviq — Project Overview

**Norviq** is a runtime security platform for LLM agent tool calls on Kubernetes. It sits
between agent frameworks (LangChain / LangGraph) and their tools. Every tool call is
intercepted, evaluated against OPA/Rego policies scoped to Kubernetes workload identity
(SPIFFE/SPIRE), and either **allowed, blocked, escalated, or audited**.

## Deployable components
- **API** (Python / FastAPI) — policy CRUD, `/api/v1/evaluate`, audit, agents, graphs. Port 8080.
- **Engine / Sidecar** (Python) — tool-call interception over a Unix socket; runs the OPA evaluator.
- **Webhook** (Go) — K8s admission controller; injects the sidecar, validates `NrvqPolicy` CRDs,
  syncs CRDs → API. Port 8443.
- **UI** (React + Vite + TypeScript) — dashboard: policy editor (Monaco), audit feed (WebSocket),
  agent trust, D3 attack/asset graphs. Port 5173 (dev).

## Evaluation hot path
resolve SPIFFE identity → cache-first lookup (Redis) → compute 7-signal trust score →
build OPA input → Rego decision (via `opa` subprocess) → Python trust overrides
(frozen→block, low-trust→escalate) → fire-and-forget audit to Postgres + OTel.

## Key subsystems
- 7-signal behavioral **trust calculator** (violation rate, tool novelty, scope drift,
  param entropy, time decay, chain depth, session velocity).
- **attack-graph / asset-graph** engines (NetworkX + D3 viz).
- **red-team** suite (25+ OWASP-LLM attack scenarios).
- Three CRDs: `NrvqPolicy`, `NrvqClass`, `NrvqConfig`.

## Repo layout note
The working tree root is `norviq-migration/`; the actual git repo + code is in `repo/`.
This Serena project is rooted at `repo/`.

See also: [[codebase_structure]], [[architecture_and_flow]], [[dev_setup_and_run]],
[[conventions_and_review]], [[mcp_workflow]].
