# Prompt — AKS deploy-hardening + prod-readiness (single-node + multi-node)

**Date:** 2026-06-28
**Work item:** Close the two live AKS gaps (webhook controller 401; injected sidecar ErrImagePull)
and make the chart prod-ready for a future multi-node cluster while still running on the current
1-node dev cluster. Plan mode (substantial; helm + webhook + config). FEAT F021 + F016 + config/api.
**Depends on:** COMMIT-and-aks-validate (deploy green; gaps surfaced).
**Commit:** (pending) · **Result:** (to fill)

Locked decisions: registry → make image PUBLIC + parameterized (GHCR recommended for no Docker-Hub
pull-rate limit; SHA-pinned in injector); datastore → in-cluster HA via operators (CloudNativePG +
Redis Sentinel/operator), gated, dev stays single-replica; autoscaling → CPU/mem HPA via
metrics-server (api+webhook), gated; scope → one chart, values-dev (single-node) + values-prod
(multi-node), implement 2 live fixes on dev now, parameterize+document the multi-node posture.

---

## Prompt

```
ROLE: AKS deploy-hardening + prod-readiness for Norviq (repo: norviq-migration/repo). USE PLAN MODE
— present the plan, WAIT for approval, then implement. Bring the performance + a k8s/ops lens.
FEAT: F021 (helm) + F016 (webhook injector) + config/api. The chart must support BOTH a single-node
dev cluster AND a multi-node prod cluster via overlays — nothing here may break the current 1-node
AKS dev cluster.

CONTEXT (from the AKS validation): deploy is green, but two live gaps + prod-readiness work remain:
  - Webhook CRD controller's policy-sync to the API now returns 401 (a side-effect of the A1 auth
    hardening) — declarative NrvqPolicy CRDs no longer reach the API.
  - Injected sidecar can't run: ErrImagePull (private image, no imagePullSecret) and the injector
    pins the mutable engine-latest, not the -sha.
  - Prod-readiness: autoscaling, pod startup ordering, dependency-restart resilience, graceful
    rollout, and multi-node HA are not yet in place.

LOCKED DECISIONS:
  - Registry: make the image PUBLIC (default), parameterize registry/repo/tag in values (so GHCR/ACR
    are drop-in); GHCR recommended as the public home (no Docker Hub anonymous pull-rate limit at
    scale — document that caveat). Pin the SHA (not -latest) in injected pods.
  - Datastore: in-cluster HA via operators (CloudNativePG 3-replica Postgres + Redis Sentinel/
    operator), GATED by values for prod; dev keeps the single-replica StatefulSet.
  - Autoscaling: HPA on CPU/mem via metrics-server for api (+ webhook), gated (off single-node dev,
    on multi-node prod). KEDA/Prometheus = future note only.
  - Scope: single chart, two overlays (values-dev = single-node lean; values-prod = multi-node);
    implement the 2 live fixes on the dev cluster now; parameterize + helm-validate + document the
    multi-node-only parts (honest that HA/HPA aren't live-validated on 1 node).

PLAN MUST COVER (decisions + files + tests + rollback):
  1. WEBHOOK CONTROLLER AUTH (live fix): give the controller a service identity so CRD->API
     policy-sync authenticates. Recommended now: a "service"-role JWT minted from the API secret,
     delivered via the webhook's secret/env (aligns with the current HS256 model; a k8s TokenReview/
     ServiceAccount path is the future SSO-epic upgrade). Verify a NrvqPolicy CRD now syncs to the API.
  2. INJECTED SIDECAR PULL (live fix): make the image pullable (public) + parameterize the sidecar
     registry/image; pin the immutable -sha in the injector (F016), not -latest. Verify an injected
     pod reaches Running AND actually enforces (sidecar proxy live), closing the v2/AKS runtime gap.
  3. POD STARTUP ORDERING: initContainers gate api/engine on postgres+redis, webhook on api;
     readiness probes reflect real dependency health (/readyz). Document that Helm apply order is
     irrelevant — initContainers + readiness enforce "datastores first, then api, then webhook" at
     runtime, including on helm upgrade.
  4. DEPENDENCY-RESTART RESILIENCE (explicit requirement + test): when a dependency pod restarts
     (postgres / redis / the OPA sidecar), dependent pods MUST recover automatically with no manual
     restart. Implement: SQLAlchemy pool_pre_ping + reconnect/backoff, Redis reconnect, OPA re-push
     on reconnect; LIVENESS lenient (process up) vs READINESS strict (deps reachable) so a transient
     outage flips the pod NotReady (drains traffic) then back to Ready — never a permanent CrashLoop.
     TEST live on dev: kill postgres -> api NotReady -> postgres back -> api Ready (no manual action);
     repeat for redis and the OPA sidecar.
  5. GRACEFUL ROLLOUT/SHUTDOWN: preStop hook + terminationGracePeriodSeconds + readiness so rolling
     upgrades drain in-flight requests; rollout strategy per overlay (single-node = replace-in-place
     maxSurge0/maxUnavailable1; multi-node = surge).
  6. MULTI-NODE PROD POSTURE (parameterized; validate via helm template/lint + docs, not live on 1
     node): HPA (api + webhook); PodDisruptionBudgets; podAntiAffinity + topologySpreadConstraints to
     spread replicas across nodes; right-sized requests/limits; operator-managed HA datastores. Ship
     values-prod overlay + a prod deploy/runbook doc. Restore engine.replicas/HA in the prod overlay.

GATES (after approval, implement):
  - CLAUDE.md: update registry/{F021,F016}.md + architecture .mmd where structure changes; new NRVQ-*
    codes in docs/error-codes.md.
  - helm lint + helm template MUST render cleanly for BOTH values-dev (single-node) and values-prod
    (multi-node). Keep attacks 75/75. Implement+verify the dev-applicable items LIVE on AKS (controller
    sync works; injected sidecar Running+enforcing; the restart-resilience tests pass). Clearly label
    which prod-only items are template-validated + documented but NOT live-validated on the 1-node dev.
  - do NOT auto-commit; summarize results. Record this prompt + outcome in specs/prompts/ + index.

ROLLBACK: all new prod behavior is values-gated and defaults to current single-node dev behavior, so
the 1-node cluster is unaffected; helm rollback / helm upgrade with the prior overlay reverts.
```
