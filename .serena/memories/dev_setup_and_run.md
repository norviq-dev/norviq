# Local Dev Setup & Run (macOS)

Stack runs natively for API + UI; Postgres + Redis run in Docker. Reference doc:
`NEW-MACHINE-SETUP-macos.md` (note: it OMITS the OPA binary — see gotcha below).

## One-time prerequisites
- `brew install python@3.12 uv opa` and Node 20+ (have 22), Docker Desktop running.
- **`opa` binary is REQUIRED** — the evaluator shells out to it.

## Bring-up order (this order works)
```bash
cd repo
docker compose -f docker-compose.dev.yml up -d        # postgres :5433, redis :6379 (both healthy)
python3.12 -m venv .venv && source .venv/bin/activate
python -m pip install -e ".[dev]"
# start API once — it creates the schema (Base.metadata.create_all); the alembic step
# "fails" harmlessly because there is no alembic.ini at root
python -m uvicorn norviq.api.main:app --host 127.0.0.1 --port 8080   # NO --reload
# in another shell (venv active):
python scripts/seed-local-policies.py                 # seeds default:customer-support (priority 700)
# restart the API so it warms the in-memory cache with the seeded policy (cache_warmed count=1)
cd ui && npm install && npm run dev -- --port 5173 --strictPort
```

## Verify
- `curl http://127.0.0.1:8080/healthz` → 200.
- UI at http://localhost:5173 ; Vite proxies `/api`, `/ws`, `/healthz` → 127.0.0.1:8080.
- Auth: `/api/v1/evaluate` needs a JWT. Use `VITE_DEV_TOKEN` from `ui/.env.local`
  (valid against default secret `change-me-in-production`).
- Enforcement smoke test (with `Authorization: Bearer $VITE_DEV_TOKEN`):
  - `execute_sql {"query":"DROP TABLE users"}` → `block / deny_sql_injection`
  - `search_kb {"query":"hi"}` → `allow / default_allow`

## GOTCHA: missing `opa` binary → everything blocks
Without `opa` on PATH, every eval fails closed: `decision=block, rule_id=evaluator_error`.
This — not the stale `docs/backlog.md` "P0 policies not enforced" note — is the real local blocker.
`brew install opa` fixes it (no API restart needed; PATH dir already inherited).

## Other gotchas
- First eval after OPA install may return `evaluator_timeout` (OPA cold start, bug-pattern P-3). Retry.
- Failed eval calls pollute `agent_history:* trust:*` and tank trust to 0.0, masking real rule output.
  Clean read: `redis-cli` DEL `agent_history:* agent_profile:* trust:* eval:*` (per test-baseline-discipline.md).
- OTel export spams the API log trying `localhost:4317` despite `NRVQ_OTEL_DISABLED=true` — harmless, no collector locally.

## Tests / lint
- `make test` → `pytest tests/ -v --tb=short` ; `make lint` → `ruff check norviq/ tests/`.
- Attack baseline target: `tests/attacks/` at **78/78**, **zero xfails** (test-baseline-discipline.md).
- UI: `cd ui && npm test` (Vitest), `npm run build`.
