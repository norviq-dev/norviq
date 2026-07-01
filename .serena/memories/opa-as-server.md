# OPA-as-Server (R7/R01) — 2026-06-28, uncommitted

Follows `mem:eval-closeout-tierB`. The evaluator queries a long-lived OPA over async HTTP instead of
forking `opa eval` per call.

## Components
- `norviq/engine/opa_client.py` `OpaClient`: `NRVQ_OPA_URL` (in-pod sidecar) or a process-wide managed
  `opa run --server --v0-compatible` (local/dev/tests; lazy-ensure; atexit cleanup). `push_policy` /
  `delete_policy` / `query` / `health`. Helpers `managed_package`/`sanitize_key`/`rewrite_package`.
- `norviq/engine/evaluator.py`: `_evaluate_opa(key, ns, class, input, rego)` dispatches by
  `settings.opa_mode`. `_evaluate_opa_server` lazy-pushes (digest in `self._pushed`) then
  `POST /v1/data/<pkg>`; re-push-on-undefined self-heal. `_evaluate_opa_subprocess` = legacy fork.
  `_eval_slot()` = semaphore (subprocess) | nullcontext (server). `_evaluate_single(event, key, rego, tr)`.
- `norviq/api/main.py` lifespan start/stop (server mode). `health.py /readyz` adds `opa`.
  `policies.py` dry-run uses isolated `dryrun:<ns>:<class>` key (don't clobber the live module).
- `norviq/config.py`: `opa_mode=server`, `opa_url`, `opa_addr=127.0.0.1:8181`, `opa_timeout_ms=250`.
- Helm: per-replica `opa` sidecar on api+engine (`opa.enabled`); configmap `NRVQ_OPA_MODE`/`NRVQ_OPA_URL`;
  `Dockerfile.engine` installs `opa`.

## Crux: policy isolation
All policies are `package norviq.strict`; OPA merges same-package modules. So each policy's package is
rewritten to `norviq.managed.<sanitized_key>` at push -> queried at `/v1/data/norviq/managed/<key>`.

## Rollback
`NRVQ_OPA_MODE=subprocess` (or helm `config.opaMode=subprocess`) -> the per-call fork, intact.

## Verify
`make lint` clean; `make test` 396 pass / 6 pre-existing fail / 1 skip (run with
`NRVQ_OPA_ADDR=127.0.0.1:8281` when the live API is up, else port clash on 8181); `tsc` clean;
`helm lint` clean. Attacks 75/75 in BOTH modes (reseed `scripts/seed-local-policies.py` first — the
seed gets deleted by make-test pollution). Perf: cache-miss p99 ~25–31ms→~9–12ms (~3×), 0 timeouts
@50/100-concurrent; <5ms not met (trust/Redis floor, separate opt). Codes NRVQ-ENG-2052/2053/2054/2057.
