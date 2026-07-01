# Customer-Eval Tier-A Remediation (2026-06-28, uncommitted)

Bounded security/quality fixes from `.reviews/customer-eval/REPORT.md`. All in repo
`norviq-migration/repo`. No auto-commit (per instruction).

## What changed
- **A1 auth+scoping**: `norviq/api/auth.py` adds `scoped_namespace(user, requested)` and
  `decode_token(token)`. Auth added to `routers/audit.py`, `routers/graph.py`,
  `routers/policies.py` GET/list/get/versions/dry-run, `routers/agents.py` list. `/ws/audit` in
  `api/main.py` decodes `?token=` before `websocket.accept()`, closes 1008 on failure.
- **A2**: `config.py` alias lists include `NRVQ_API_SECRET_KEY` / `NRVQ_DB_SSL_MODE`; new
  `require_strong_secret: bool=False`. `main.py` lifespan warns `NRVQ-API-7099`, raises only if flag.
- **A3**: `require_admin(user)` on `policies.py` create/delete/rollback/apply.
- **A4**: `sidecar/proxy.py` + `sidecar/http_fallback.py` return `action=drop` on error (fail closed).
- **A5**: `comprehensive.rego` PII free-text SSN substring (`\b\d{3}-\d{2}-\d{4}\b`) + PCI
  whole-field/grouped card gated by a `luhn_valid` rego helper. (The former standalone
  `pci_card_numbers.rego` under the old `data_protection/` tree was consolidated INTO
  `comprehensive.rego` — the PCI logic lives there now; verify PCI cases via
  `tests/attacks/test_pii_pci.py`.)
- **A6**: `helm/norviq/values.yaml` api.replicas=2 + api.pdb; new `templates/api-pdb.yaml`;
  `configmap.yaml` NRVQ_REQUIRE_STRONG_SECRET; `engine/audit_emitter.py` init() returns early when
  `otel_enabled` false (`NRVQ-AUD-6008`).
- **A7**: `telemetry/metrics.py` adds prometheus_client mirror `NRVQ_REGISTRY`;
  `telemetry/exporter.py` mounts it on `/metrics`. `evaluator._safe_register_agent` upserts
  `agent_registry` (`db/session.py:upsert_agent_registry`); `agents.py:_agents_from_registry`
  read fallback. Codes `NRVQ-ENG-2051`, `NRVQ-API-7032`.
- **A8 UI**: `AuditLog.tsx` WS `&token=`; removed Red Team nav (`ExpandedPanel.tsx`) + route
  (`App.tsx`); `Settings.tsx` saved-locally note; `PolicyTester.tsx` `ruleLabel()` friendly
  `evaluator_error`.

## Verification commands
- `make lint` clean; `cd ui && npx tsc --noEmit` clean; `cd ui && npx vitest run` 37/37.
- Attacks: reseed `python3 scripts/seed-local-policies.py`, clear Redis drift, restart uvicorn,
  then `NRVQ_API_URL=http://127.0.0.1:8080 python -m pytest tests/attacks/` → **72/72** (was 66).
- `make test` (needs `pythonpath=['.']`, now in pyproject) → 377 pass / 6 pre-existing fail / 1 skip.

## The 6 pre-existing make-test failures (NOT regressions — verified by stashing norviq/)
sidecar `test_unix_socket_blocks_sql_injection`, `test_http_fallback_blocks_sql_injection`,
`test_proxy_runtime::test_sidecar_start_binds_loader_and_hydrates`,
`test_evaluator::test_cached_block_still_applies_post_decision`,
`test_policy_loader::test_create_updates_cache_and_evaluator`,
`test_langchain_adapter::test_protect_allowed_tool_executes`.
Root cause: local seed only has `default:customer-support`; sidecar/SDK resolve identity `sa/default`
→ eval candidates=0 → allow. Also `test_policy_crud_flow` is non-idempotent vs persistent DB
(loader.delete leaves the row; version accumulates) — clean `policies` row for payments/planner.

Tier C epics: `specs/EPIC-multi-cluster-fleet.md`, `specs/EPIC-sso-oidc.md`. Prompt archive:
`specs/prompts/EVAL-remediation.md`. See also `mem:task_completion_checklist`.
