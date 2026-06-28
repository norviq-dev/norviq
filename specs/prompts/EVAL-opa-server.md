# Prompt — OPA-as-server (latency + HA, R7/R01)

**Date:** 2026-06-28
**Work item:** Replace the per-call `opa eval` subprocess with a long-lived OPA server queried over
async HTTP, to fix cache-miss latency (40–120× the <5ms claim), concurrency failures, and HA.
Plan mode first (perf-critical, "do not auto-fix" gated); performance auditor in the loop.
**FEAT:** F009 (evaluator) + F021 (helm) + config. **Risk:** Med-High (hot-path rewrite).
**Depends on:** [EVAL-closeout-tierB.md](EVAL-closeout-tierB.md) (C1–C4 done; attacks 75/75).
**Commit:** (uncommitted — per instruction, no auto-commit)
**Result:** Implemented. `OpaClient` (`norviq/engine/opa_client.py`) talks to a long-lived OPA
(in-pod sidecar via `NRVQ_OPA_URL`, or a managed `opa run --server` for local/dev/tests). Policies
are mirrored into OPA with **per-policy package isolation** (`package` rewritten to
`norviq.managed.<key>` so modules never merge). Eval is `POST /v1/data/<pkg>`; failures fail CLOSED
(`evaluator_timeout`/`evaluator_error`); semaphore bypassed in server mode; re-push-on-undefined
self-heal. `NRVQ_OPA_MODE=server` default, `=subprocess` rolls back the fork path (kept intact).
Helm: per-replica `opa` sidecar on api+engine. New codes NRVQ-ENG-2052/2053/2054/2057.

**Parity (non-negotiable): IDENTICAL decisions** — `tests/engine/test_opa_parity.py` asserts
allow/sql-block/excessive-agency/base64-block/pii-block/scope-audit match across both modes; **attacks
75/75 in BOTH modes** (live). Fail-closed + self-heal + 50-concurrent covered in
`tests/engine/test_opa_server.py`.

**Performance (local, perf auditor before→after):**
| metric | subprocess (before) | server (after) | change |
|---|---|---|---|
| cache-miss p50 | ~24 ms | ~6–8 ms | ~3–4× |
| cache-miss p99 | ~25–31 ms | **~9–12 ms** | **~3×** |
| cache-hit p99 | ~5.7 ms | ~5.0 ms | flat |
| 50-conc p90 / timeouts | ~530 ms / 0 | ~507 ms / **0** | flat tail, 0 timeouts |

cache-miss p99 **< 5ms NOT met** (achieved ~9–12 ms). Why: the per-request floor is the trust-score
+ Redis pipeline (visible as the ~4–5 ms cache-hit latency); OPA query adds ~3–5 ms on top. The
concurrency tail is dominated by that same trust/Redis path (and pool sizing), not OPA — so it's flat
vs. baseline. OPA-as-server delivered its structural goal (removed fork+tempfile+Semaphore(10)
serialization, ~3× faster sequential miss, 0 timeouts at 50/100 concurrent); driving p99<5ms and the
tail further is a separate trust/Redis optimization. Gates: `make lint` clean, `make test` 396 pass /
6 pre-existing fail / 1 skip, `tsc` clean, `helm lint` clean; F009 `.mmd` regenerated. **No commit.**

Key constraints: decision PARITY (75/75 unchanged + a dedicated cross-mode parity test), fail-CLOSED
on OPA down, --v0-compatible, query data.norviq.strict, input.agent.*; NRVQ_OPA_MODE default =
**server** (Option 1 — active in local dev, CI/tests, and prod; subprocess is the rollback
fallback); sidecar OPA in prod + managed-subprocess for local/tests. F009 .mmd MUST be regenerated
(structural flow change). After this lands → v2 simulation.

---

## Prompt

```
ROLE: Implement OPA-as-server to fix evaluation latency + HA (R7 / R01) for Norviq
(repo: norviq-migration/repo). This is the perf-critical hot-path rewrite explicitly gated as
"do not auto-fix" — USE PLAN MODE, present the plan, WAIT for approval. Bring the performance
auditor into the loop. FEAT: F009 (evaluator) + F021 (helm) + config.

PROBLEM (verified in v1 report): evaluator._evaluate_opa forks a per-call `opa eval` in a
TemporaryDirectory (evaluator.py ~428/446), serialized by Semaphore(10). Cache-MISS p99 ≈0.2–0.6s
(40–120× the <5ms claim); 16/20 requests fail at 20 concurrent, 50/50 at 50; sync temp-file I/O on
the async hot path. Cache-HIT p50 ≈4.4ms (cache is fine).

DESIRED STATE: a long-lived OPA server queried over async HTTP; identical decisions; cache-miss p99
< 5ms; survives ≥50 concurrent with no timeouts; fail-CLOSED on OPA unavailability.

PLAN MUST COVER (state decisions + files + tests + rollback):
  1. OPA runtime model: OPA as a sidecar container at localhost:8181 in the api (and engine) pods
     via Helm; PLUS a managed-subprocess fallback for local/dev/tests when NRVQ_OPA_URL is unset
     (spawn `opa run --server --v0-compatible` on API startup, reused across requests). Decide and
     state the default.
  2. Policy push: push each policy/candidate module to OPA `/v1/policies/<id>` on load / create /
     reload / cache-invalidation (and during warm_cache and the cross-replica pub/sub invalidation).
     Loader stays the source of truth; OPA holds a mirror.
  3. Evaluation: replace the subprocess+tempfile path with async httpx `POST /v1/data/<pkg-path>`
     using the SAME query-path derivation (data.norviq.strict; P-8), the SAME input schema
     (input.agent.* NOT input.agent_identity.*), the SAME candidate-collection + precedence
     resolution, and the SAME rule_id provenance (default_allow / evaluator_timeout / evaluator_error
     / rate_limit_exceeded / escalate_low_trust — no hidden stub returns, P-1/P-2).
  4. v0 compatibility (P-9): run OPA with --v0-compatible. Timeout sizing (P-3): tight per-call
     timeout (~250ms) → on OPA down/timeout/error, fail-CLOSED block with the correct rule_id
     (NEVER fail open).
  5. Health: /readyz depends on OPA reachable + policies pushed; on OPA sidecar restart, re-push
     modules before serving.
  6. HA: with api.replicas>=2 (already shipped) each replica runs its own OPA → no single point.
  7. ROLLBACK SAFETY: gate behind NRVQ_OPA_MODE. DEFAULT = server (Option 1) — the server path is
     active in local dev, CI/tests, and prod; subprocess is the rollback fallback
     (NRVQ_OPA_MODE=subprocess) revertable without a redeploy.

NON-NEGOTIABLE PARITY: decisions must be IDENTICAL across modes. Keep attacks 75/75 (0 xfail/skip)
AND add a dedicated cross-mode parity test (e.g. tests/engine/test_opa_mode_parity.py) that runs the
SAME representative allow/block/escalate/audit inputs through BOTH NRVQ_OPA_MODE=server and
=subprocess and asserts identical decision + rule_id. It MUST run under `make test` so the rarely-
exercised subprocess fallback never silently rots.

PERFORMANCE VERIFICATION (performance auditor): before/after latency distribution; prove cache-miss
p99 < 5ms (or report the achieved number + why) and ≥50 concurrent with 0 timeouts. Put the numbers
in the summary.

GATES (after approval, implement):
  - REGENERATE architecture/F009.{class,sequence,deps}.mmd (the flow changes structurally — this is
    NOT additive) + update registry/F009.md, F021 (helm sidecar), config. New NRVQ-* codes in
    docs/error-codes.md.
  - Tests: allow/block/error paths + OPA-down fail-closed + concurrency + the cross-mode parity test
    (server vs subprocess) running under `make test`; assert rule_id; never monkeypatch get_session.
  - make lint + make test + tsc; keep 75/75; do NOT auto-commit; summarize results.
  - Record this prompt + outcome in specs/prompts/ and update the index.
```
