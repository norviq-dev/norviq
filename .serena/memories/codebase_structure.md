# Codebase Structure

Root = `repo/`. ~700 files across Python, TypeScript, Go, Rego.

## Python package — `norviq/`
- `config.py` — pydantic-settings; all `NRVQ_*` env vars. Loads `.env` then `.env.local`.
- `exceptions.py` — `NorviqError`, `NorviqBlockError`, `NorviqEscalateError`, `NorviqConfigError`, `NorviqTimeoutError`.
- `api/` — FastAPI app.
  - `main.py` — app factory, lifespan (DB/Redis/evaluator/audit init, schema create, cache warm).
  - `db/models.py` — SQLAlchemy ORM: policies, policy_versions, agent_registry, audit_log, users, asset_graph, attack_paths.
  - `db/session.py` — async engine (asyncpg), `Base.metadata.create_all` on startup.
  - `auth.py` — JWT HS256 bearer; `get_current_user`, `require_admin`.
  - `routers/` — evaluate, policies, audit, agents, graphs, graph, health, redteam, attack_graph_compute.
  - `schemas/` — Pydantic request/response models.
- `engine/` — evaluation core.
  - `evaluator.py` — `OPAEvaluator`; **shells out to the `opa` binary** (`create_subprocess_exec("opa", ...)` ~line 417). Cache-first, trust overrides, precedence resolution.
  - `cache.py` — `RedisCache`; policy/eval/trust caches, Lua atomic trust ops, pub/sub `norviq:policy_events`.
  - `identity.py` — `SPIFFEResolver` (MVP mock from env vars).
  - `policy_loader.py` — `PolicyLoader`; load mem→Redis→PG, hot reload, version history.
  - `audit_emitter.py` — fire-and-forget audit to PG + OTel.
  - `attack_graph.py`, `attack_graph_models.py` — attack path compute.
  - `graph/` — `asset_graph.py` (NetworkX builder), `store.py`, `analyzer.py`, `models.py`.
  - `trust/` — `calculator.py`, `models.py`, `history.py`, `profile.py`, `signals/` (7 signals + base).
- `sdk/` — `core/` (interceptor, events, decisions, audit, trust), `client/engine.py` (HTTP client + circuit breaker), `langchain/adapter.py`, `langgraph/adapter.py`.
- `sidecar/` — `proxy.py` (Unix socket), `http_fallback.py`, `__main__.py`.
- `telemetry/` — provider, middleware, metrics, exporter, spans (OTel + Prometheus).
- `cli/` — Click CLI (`main.py`, `api_client.py`, `formatters.py`).
- `redteam/` — `attacks.py` (scenarios), `simulator.py`, `reporter.py`, `runner.py`.

## Frontend — `ui/`
React 18 + TS + Vite 5, Tailwind 4, React Router (lazy routes), ECharts + D3, Monaco editor.
- `src/api/client.ts` — fetch helpers + types; talks to `/api` (Vite proxy → 127.0.0.1:8080).
- `src/store/AppContext.tsx` — global context (cluster, namespace, timeRange, section); injects `VITE_DEV_TOKEN`.
- `src/hooks/` — `useApi` (cache), `useWebSocket` (live audit).
- `src/pages/` — Dashboard, PolicyCatalog (Monaco, 3-tier), AuditLog, AgentMonitor, PolicyTester, AttackGraph, AssetGraph, + Settings/RedTeam/MITRE stubs.
- `src/components/` — `common/`, `charts/`, `attack-graph/`, `asset-graph/`, `ui/` (shadcn-style), `layout/`.

## Go — `webhook/`
`main.go`, `handler.go` (/mutate, /validate-policy), `injector.go` (sidecar injection),
`controller.go` (watches NrvqPolicy/NrvqClass/NrvqConfig, syncs to API), `config.go`. Error codes `NRVQ-WHK-4xxx`.

## Infra & policy
- `crds/` — NrvqPolicy (namespaced), NrvqClass (cluster), NrvqConfig (cluster).
- `helm/norviq/` — chart, values.yaml, values-aks-dev.yaml, templates/ (deployments, RBAC, baseline policy).
- `policies/` — Rego by theme (owasp/, data_protection/, access_control/, tool_safety/, rate_limiting/, trust/, industry/, presets/). Root: `comprehensive.rego` (package `norviq.strict`), `simple.rego`.
- `Dockerfile.api|engine|ui`, `webhook/Dockerfile`, `docker-compose.dev.yml`, `Makefile`, `go.mod`, `pyproject.toml`.

## Process artifacts
- `specs/` (F###/S### feature specs), `registry/` (12-section code registries), `architecture/` (3 `.mmd` per feature), `docs/engineering/` (bug-patterns, opa-input-schema, test-baseline-discipline, aks-operations), `docs/error-codes.md`, `docs/backlog.md`, `.reviews/`.
- `CLAUDE.md` — review instructions + MCP Tooling Protocol.
