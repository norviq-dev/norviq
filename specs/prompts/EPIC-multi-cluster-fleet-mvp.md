# Prompt — Multi-cluster fleet (R3) MVP: Phase-1 read-only, local 2-cluster

**Date:** 2026-06-28
**Work item:** Fleet control plane, MVP-first = Phase 1 (read-only: cluster registry + heartbeat +
agent/audit rollups + aggregated console), Option A hub-and-spoke. Plan mode (staged); k8s/ops +
security auditor. Validated on TWO local kind clusters; AKS deferred.
**Design source:** `specs/EPIC-multi-cluster-fleet.md` (Option A; phasing P1→P4).
**Depends on:** Identity epic (OIDC cross-cluster RBAC; relay identity). **Docker:** 12 GB.
**FEAT:** F045 (fleet) + F018 (console). **Commit:** not committed (gate: do NOT auto-commit) · **Result:** see Outcome.

## Outcome (done — built + LIVE-validated on two local kind clusters; nothing committed; AKS untouched)
**FEAT F045.** Everything gated **off by default** → single-cluster dev/AKS render + behave exactly as today.
- **fleet-api hub** (`norviq/fleet/`): a SEPARATE FastAPI app (`create_fleet_app`) over a dedicated
  `fleet-postgresql` via a SEPARATE `FleetBase`/engine (`db.py`) — fleet tables never touch a spoke DB
  (verified: spoke engine stays uninitialized, zero table overlap). Reuses `norviq/api/auth.py` (no spoke
  DB pulled in). Tables `cluster`/`agent_rollup`/`audit_rollup`; relay-facing `POST heartbeat`/`rollup`
  (SET-absolute idempotent upsert, cluster-scoped on the path); console-facing `GET fleet/clusters` (status
  healthy/stale), `/agents`, `/audit/summary`, `/trust/distribution`.
- **Relay** (`norviq/fleet_relay.py`): in-process spoke background task mirroring the SIEM AuditForwarder;
  reads agent_registry + aggregates audit_log (hourly buckets) and pushes rollups; **fire-and-forget, strictly
  off the enforce path**. Hub auth = OIDC client-credentials (`fleet/oidc_cc.py`) with an HS256 break-glass
  self-mint fallback. Wired into the spoke lifespan; `start()` no-op unless `fleet_enabled`.
- **Cluster-scope RBAC** (`norviq/api/auth.py`): `_apply_group_mapping` gains a `cluster` claim (admin→"*",
  conflict fails closed); new `scoped_cluster` (403 cross-cluster). Backward-compatible — single-cluster endpoints ignore it.
- **Helm**: gated `fleet` block — `fleet.enabled` (spoke relay env) + `fleet.hub.enabled` (fleet-api + dedicated
  postgres, SAME api image, `uvicorn norviq.fleet.main:app`). values-aks-dev + values-prod render **ZERO** fleet resources.
- **Console** (F018): new gated **Fleet** page (`ui/src/pages/Fleet.tsx` + `api/fleet.ts`) shown only when
  `VITE_FLEET_API_URL` is set; existing pages untouched.

**LIVE (scripts/fleet-local/, fleet-a hub+spoke / fleet-b spoke over the shared kind net, NodePort 31090):**
both clusters heartbeat + register (healthy); the hub aggregates **BOTH** clusters' agents + per-cluster audit
summaries (relay reached the hub from fleet-b 8+×); **cluster-scope RBAC** — a fleet-a-scoped viewer gets **403
on ?cluster=fleet-b**, 200 on fleet-a; **hub-down fail-safe** — fleet-api scaled to 0 → the spoke STILL blocks a
SQL injection (`deny_sql_injection`). Evidence: `.reviews/fleet-local/EVIDENCE.md`.

**Gates:** ruff clean; new tests `tests/fleet/*` (9) + auth cluster-scope (4) pass; **zero new regressions**
(single-cluster unit suite = the same 9 pre-existing); tsc + vitest 37/37; `helm lint`+`template` clean for
values-aks-dev + values-prod (0 fleet) + the fleet overlays; **attacks 75/75** warm on a spoke (run-to-run
variance is the pre-existing trust-warming harness flakiness, identical hub-up vs hub-down → hub doesn't affect
enforcement). New codes NRVQ-FLT-15000..15014. registry/F045 + architecture/F045.*.mmd.
**P1 visibility DONE; P2 policy-push (the "manage all clusters" half) still OPEN** (+ P3/P4, SPIFFE-mTLS relay,
bundle-signing = deferred). **AKS untouched** (local-first).
**Rollback:** `fleet.enabled=false`/`fleet.hub.enabled=false` (helm renders nothing), `NRVQ_FLEET_ENABLED=false`
(relay no-op), `cluster` claim inert for single-cluster paths.

MVP = the VISIBILITY half of R3 (one console sees agents+audit across clusters, RBAC-scoped).
Policy-push (P2), live drill-down (P3), residency (P4), SPIFFE-mTLS relay (P2) are DEFERRED. Fleet is
OFF by default → single-cluster dev/AKS unchanged. Fail-safe invariant: hub connectivity never affects
local enforcement.

---

## Prompt

```
ROLE: Multi-cluster fleet — EPIC R3, MVP-FIRST (Phase 1: fleet READ-ONLY). Norviq (repo: norviq-
migration/repo). USE PLAN MODE — present a staged P1 plan, WAIT for approval, implement stage by
stage. Bring the k8s/ops + security auditor. Design source: specs/EPIC-multi-cluster-fleet.md (read
it — Option A hub-and-spoke is chosen; phasing P1→P4). Build on the identity epic (OIDC cross-cluster
RBAC; SPIRE/OIDC for relay identity). Validate end-to-end on TWO local kind clusters (12 GB). Nothing
may break the single-cluster path: fleet is OFF by default → dev/AKS behave exactly as today.

WHY (customer-eval R3): each Norviq install is an island; the console's cluster selector is cosmetic;
no aggregation, no fleet view. P1 delivers the VISIBILITY half (one console sees agents+audit across
clusters, RBAC-scoped). Policy-push (P2), live drill-down (P3), residency (P4) are LATER — do NOT
build them now.

SCOPE — P1 ONLY (fleet read-only), Option A:
  1. fleet-api control plane (new service, own store): cluster registry + heartbeat
     (cluster: id,name,endpoint,region,status,last_heartbeat). Gated/opt-in; absent → today's behavior.
  2. Spoke relay: each cluster pushes periodic agent + audit ROLLUPS to fleet-api (reuse the A7
     persistent agent_registry; pre-aggregated audit counters — raw audit stays in-cluster).
     Data model: agent_rollup + audit_rollup per the stub.
  3. Console: the cluster selector hits fleet-api; aggregated reads (agents, audit summaries, trust
     distribution) span clusters; per-cluster status shown.
  4. AuthN/Z: fleet-api auth via OIDC; IdP groups map to (role, CLUSTER_SCOPE, namespace_scope) —
     extend the identity group-mapping with a cluster dimension. Relay→hub auth via OIDC client-
     credentials now (SPIFFE/mTLS relay identity is a P2 hardening). fleet-api enforces cluster scope
     on every read.
  5. Fail-safe invariant: hub connectivity NEVER affects local enforcement — a spoke losing the hub
     keeps enforcing locally; fleet read views degrade gracefully (stale/last-heartbeat), never open up.

EXPLICITLY DEFERRED (design-note only): P2 signed policy-push + per-cluster override; P3 live single-
cluster drill-down; P4 residency flag; SPIFFE-mTLS relay identity; bundle-signing trust root.

LOCAL VALIDATION (two kind clusters, 12 GB — reuse the eval/identity-local harness pattern; new
scripts/fleet-local/ 00-up/10-verify/99-down):
  - Hub on cluster-A; spoke relays on A and B; register both; both heartbeat.
  - Seed agents+traffic on each; the console (via fleet-api) shows BOTH clusters' agents + audit
    summaries aggregated; per-cluster status correct.
  - RBAC: a user scoped to cluster-A cannot see cluster-B data (cluster-scope enforced) — add a test.
  - Kill the hub → spokes keep enforcing locally (attacks still block); fleet view degrades, never
    opens. Bring hub back → rollups resume.

GATES (after approval, per stage):
  - New FEAT id for fleet (propose, e.g. F045) — registry/{fleet}.md + architecture .mmd; new NRVQ-*
    codes in docs/error-codes.md. Identity + single-cluster paths unchanged.
  - Tests: registry/heartbeat, rollup push, aggregated read, cluster-scope RBAC, hub-down fail-safe.
    Keep attacks 75/75; unit suite green; tsc + vitest green.
  - helm lint + template clean for values-aks-dev AND values-prod with fleet OFF (renders nothing new),
    AND a fleet overlay that renders fleet-api + relay. AKS untouched (local-first; AKS fleet is later).
  - Do NOT auto-commit; summarize per stage. Record this prompt + outcome in specs/prompts/ + index.
  - Honestly label: P1 visibility done; P2 policy-push (the "manage all clusters" half) still open.
```
