## CRITICAL: Day 8 — Policy not enforced at runtime

Symptoms:
- POST /api/v1/policies returns 200
- GET /api/v1/policies shows the policy with correct rego_length
- POST /api/v1/evaluate returns "decision":"allow", "rule_id":"default_allow"
- Even simple rules (tool_name == "delete_record" → block) don't fire
- Pod restart does not fix
- Only the earliest simple test policy ever worked, briefly

Likely cause:
- norviq-api stores policy in DB and own in-memory copy
- norviq-engine (evaluator) has separate in-memory _policies dict
- Cache pub/sub invalidation between pods is failing
- OR: evaluator uses key format different from what API writes

Files to investigate:
- norviq/engine/policy_loader.py (where _policies is populated)
- norviq/engine/evaluator.py (where _policies is read in evaluate())
- norviq/sidecar/proxy.py (_watch_policy_events listener)
- norviq/engine/cache.py (listen_policy_events)

Test to reproduce:
1. POST policy via API → 200 OK
2. GET policies → shows policy
3. POST evaluate with matching attack → returns default_allow

Impact: Day 8 attack tests at 25/66 pass — most policies not actually enforced
Blocks: Day 8 sign-off, Day 13 pentest readiness
Priority: P0 — fix before Day 9

## Day 8 — P0 — Policy evaluator broken

Symptoms:
- Policy stored in PostgreSQL (verified: SELECT COUNT(*) FROM policies = 1)
- warm_cache loads policy on API startup (NRVQ-REG-5015 count=1)
- POST /api/v1/evaluate returns "decision":"allow", "rule_id":"default_allow"
- Even simple tool_name == "delete_record" rule doesn't fire
- No NRVQ-ENG logs visible

Likely causes (investigate tomorrow):
1. _collect_candidates returns empty list (key format mismatch)
2. OPA Python evaluator silently fails
3. Rego stored corrupted (verify with SELECT LEFT(rego_source, 200))
4. evaluate() catches exception and falls through to default

Files to check:
- norviq/engine/evaluator.py _collect_candidates and evaluate methods
- norviq/engine/policy_loader.py _policies dict key format
- norviq/api/main.py lifespan startup

Day 8 result: 21/66 passing — most failures because policies not enforced
Blocker for: Day 9 onwards

## Day 8 — Post-MVP fixes (P1)

### 1. Policy deployment workflow (P1)
Current: comprehensive.rego (the canonical default policy) seeded via the API; baselines render from
`helm/norviq/templates/baseline-cluster-policy.yaml` (F-07). Remaining gap: rego is DB-seeded content, not
shipped by the image deploy, so live-cluster enforcement lags the repo until a re-seed (tracked as issue #4).
Real fix:
  - A re-seed path (job/bundle) wired into deploy so comprehensive.rego + sector packs propagate on upgrade
  - Engine startup detects no policies → auto-load the bundled comprehensive.rego default

### 2. OPA subprocess per-call (P0 for prod)
Current: spawn OPA subprocess every evaluation (~150ms cold start, 2s timeout)
Real fix:
  - Run OPA as long-lived process inside API container (or as sidecar)
  - HTTP API at localhost:8181/v1/data/norviq/strict
  - Evaluation drops to ~2ms (under <5ms p99 target)
  - Push Rego policies to OPA via /v1/policies API on startup + invalidation

### 3. Unicode normalization for injection detection (P1)
Current: hardcoded fullwidth patterns for "ignore", "dan", "bypass"
Real fix:
  - Add Python preprocessing to normalize input.tool_params strings via unicodedata.normalize('NFKC', s).lower()
  - Pass normalized version to OPA as input.tool_params_normalized
  - Rego matches against normalized version
  - Catches ANY Unicode obfuscation, not just the 3 hardcoded variants

## Day 8 — Remaining 6 attack failures (P1)

### Cross-tenant (2 tests)
Tests still failing after Rego fix:
- test_different_tenant_id_blocked
- test_different_namespace_blocked
Likely: input doc structure doesn't expose agent_identity.namespace the way Rego expects.
Debug: dump OPA input via NRVQ-ENG-DEBUG-OPA-IN log for these specific test cases.

### Trust calculator (3 tests)
- test_burst_with_low_trust — trust 0.3 should escalate, currently allows
- test_frozen_agent_blocked — trust 0.0 should block ALL calls, currently allows
- test_trust_with_dangerous_tool — medium trust + risky tool should escalate
Root cause: trust_score input from caller is ignored or overridden by computed signals.
Fix: respect caller-provided trust_score when present, OR enforce frozen=true regardless of policy decision.

### Base64 obfuscation (1 test)
- test_base64_encoded_payload
Known limitation. Phase 2: add base64 decoding pre-processor in API before OPA call.

## Code review follow-ups — deferred 2026-06-05

The 3 quick wins from an internal review pass were applied directly to evaluator behavior/log gating.
The remaining 7 architectural findings are deferred:

1. **P1 security:** Policy integrity/tampering hardening - add policy signing/verification and stronger mutation controls for loaded Rego.
2. **P2 security:** Enforce JWT namespace/tenant claim binding in evaluate path (do not trust client-provided namespace blindly).
3. **P0 performance:** Replace per-request OPA subprocess spawn with long-lived OPA process/API path.
4. **P0 performance:** Remove synchronous temp-file I/O from async evaluation hot path.
5. **P1 performance:** Reduce sequential per-candidate OPA evaluations (bundle/compile/optimize candidate execution).
6. **P1 correctness/security:** Strengthen fail-closed guarantees for all candidate-evaluation error paths under all config combinations.
7. **P2 architecture:** Reduce hot-path logging payload overhead and leakage risk further (structured redaction strategy + minimal default telemetry).

## Day 9 — OTel Collector Missing (Non-blocking)
otel-collector:4317 unavailable. Traces fail to export but PostgreSQL audit writes succeed.
Fix: deploy OTel collector via Helm subchart in Day 13 (TLS + admission controllers).
Alternative: set NRVQ_OTEL_DISABLED=true on AKS to silence the warning.


Day 10 backlog:
  1. F037 implementation (attack graph engine)
     - Walks asset_graph table
     - Computes paths agent → tool → data
     - Marks each step with policy_check (would_block/would_allow/no_policy)
     - Writes to attack_paths table
     - Trigger: cron, on-demand endpoint, or on every audit_log insert
  
  2. F037 trigger mechanism
     - Endpoint: POST /api/v1/attack-paths/compute
     - Or CronJob: kubectl cronjob every 5 min
     - Or background task in api worker

Day 10 focus:
  - Performance benchmarks
  - F037 implementation (so demo shows full feature)


## Test hygiene — RESOLVED
- **test_priority_enforcement.py leaves `__cluster__:__baseline__` policy in DB after run.**
  Pollutes subsequent attack baseline runs: the leftover priority-900 default-block cluster policy
  wins precedence over `default:customer-support` and blocks every safe operation (observed: 16
  false failures locally until the row was removed).
  RESOLVED: both tests now wrap in try/finally with `_cleanup_polluted_policies(loader)` that
  deletes the policies/policy_versions rows they insert. (Other tests creating `ns-*` policies may
  still linger — separate sweep if it recurs.)

## P-15-class: dry_run_policy endpoint broken — RESOLVED
policies.py dry_run_policy had the async-generator bug (await get_session()) and ignored the
submitted rego body (_ = body) — never validated rego, only reported audit block-rates.
RESOLVED: now uses Depends(get_session) (P-15 pattern) and actually validates the rego by
OPA-evaluating it against a sample input (returns valid/errors/sample_decision). Restores the
pre-apply safety gate.

## App-level DB/Redis connect backoff (defense-in-depth for P-14) — RESOLVED
main.py lifespan called init_db()/cache.connect() with no retry.
RESOLVED: `_connect_with_backoff` wraps init_db + cache.connect (5 attempts, 1→16s, logged with
NRVQ-DB-9034/9035 + NRVQ-REG-9034/9035; raises after the last attempt so the pod restarts).

## Node capacity — right-size AKS agentpool for zero-downtime
Current single ~1-vCPU node at 97% CPU requests forces replace-in-place
(values-aks-dev.yaml overlay). For true zero-downtime: add a node OR larger VM
OR lower resource requests, then drop the overlay (defaults give maxSurge:1).
Gate the switch on `kubectl top nodes` showing headroom.

## P0: API /evaluate path does not call emitter.emit — only sidecar does
Audit endpoints now return 200 (P-16 fix), but the API deployment writes NO audit data
(only the sidecar's http_fallback/proxy call emitter.emit; the API /evaluate handler never
does). So Dashboard/Audit Log endpoints work but show nothing on the API deployment.
Wire fire-and-forget audit emission into the /evaluate handler (must NOT block the hot path —
async task, per the <5ms perf rule). This completes the "see enforcement" pillar.
Priority: next P0 after the attack-path namespace leak.

## P0 (auth batch): namespace authz not enforced — caller can request any namespace
attack-paths/audit/policies filter by the namespace PARAM but don't ENFORCE that the
caller may access that namespace. Any valid token can query any namespace's data. The
attack-path data-scoping fix (namespace column + WHERE) is done; ENFORCEMENT (bind the
allowed namespace(s) to JWT claims / tenant identity) belongs with the P0 auth-flow work,
not the data fix. Until then, isolation is by correct scoping only, not authorization.

## P1 (auth batch): audit/* namespace convention inconsistency
audit/* endpoints use `Query(None)` → returns ALL namespaces when the param is omitted —
inconsistent with attack-paths/agents/policies which default-to-'default' (fail-safe).
Works today only because the UI always passes namespace; a missing param would leak
cross-tenant audit data. Align audit to default-to-'default', and add an explicit
`namespace=all` admin opt-in gated by RBAC. See docs/engineering/namespace-scoping.md.

## P1: Audit Log live WebSocket has no backend (/ws/audit → 404)
The UI (AuditLog) connects to `ws(s)://{origin}/ws/audit` for the live feed, but the API has
**zero WebSocket routes** (`grep websocket norviq/` → nothing) — so the connection 404s in BOTH
dev (vite proxy) and prod (nginx /ws proxy). The live feature never worked; the audit table itself
is fine (REST `/api/v1/audit/records`). Found during P0-B prod verification. The nginx `/ws`
upgrade proxy is already in place (returns a clean 404 now instead of SPA fallback). Fix: implement
an `/ws/audit` WebSocket on the API that broadcasts audit events (the emitter already produces them),
OR remove the live toggle until then.

## P1: loader.delete does not remove the policies row (DELETE endpoint no-op?)
loader.delete clears in-memory/cache only, never DELETEs the Postgres row — so
DELETE /policies/{ns}/{class} returns {deleted: true} but the row persists, and re-creates
accumulate version via ON CONFLICT. Two issues:
  a) Real correctness bug: DELETE endpoint doesn't actually delete (a customer would hit this).
  b) Test fragility: test_policy_crud_flow / test_apply_policy assert version==1 and only pass
     on a clean DB.
Fix: make DELETE actually remove the policies (+ policy_versions) rows; make the tests robust
to existing version state.

## BEFORE PUBLIC RELEASE: migrate container images Docker Hub → GHCR (2026-06-28)
Images are currently published to Docker Hub `norviq/norviq-engine`, and the repo was made
**public** to unblock injected-sidecar pulls on AKS (zero cost, fast path). Before the public
release, move the canonical image home to **GHCR (`ghcr.io/norviq-dev/...`)**.
Why: GHCR is free for public images, has **no Docker Hub anonymous pull-rate limit** (~100/6h per
IP — bites a multi-node autoscaling cluster), and is native to the GitHub Actions pipeline.
Scope:
  - `.github/workflows/build.yml`: log in to GHCR (`GITHUB_TOKEN` + `packages: write`), push
    `ghcr.io/norviq-dev/norviq-engine:<component>-<sha>` (+ `-latest`); mark the GHCR package public.
  - Update the chart's parameterized registry default (`images.*.repository`) + `values-aks-dev.yaml`
    / `values-prod.yaml` + the webhook injector's sidecar image to GHCR; keep registry overridable.
  - `deploy.yml`: pull from GHCR (no imagePullSecret needed for public). Verify a clean `helm
    install` pulls from GHCR on kind + AKS.
  - Optionally keep Docker Hub as a mirror during the transition.
Later (private/commercial): switch the prod pull path to **ACR + AKS managed identity** (no
imagePullSecret, same-region, image scanning) — registry is already parameterized for this in the
AKS-deploy-hardening pass.
