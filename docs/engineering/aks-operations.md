<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Norviq Contributors -->

# AKS Operations

Operating and recovering the Norviq stack on AKS. The cluster is the source of truth for the test
baseline (see [test-baseline-discipline.md](test-baseline-discipline.md)).

## P-14 permanent fix (applied)

The AKS startup race and the rollout deadlock are fixed in the chart — the manual recovery
sequence below is now a **fallback**, not routine. Applied to `api-deployment.yaml` and
`engine-deployment.yaml`:

- **initContainers** `wait-for-postgres` (`norviq-postgresql:5432`) + `wait-for-redis`
  (`norviq-redis:6379`) — the app container does not start until its backends accept TCP, so no
  more cold-start crashloop (was 3 restarts; now 0).
- **startupProbe** (`/healthz`, `failureThreshold: 30 × 5s = 150s`) — gives migrations + warm_cache
  time to finish without the liveness probe killing a slow-but-healthy start.
- **livenessProbe** less aggressive once started (`periodSeconds: 30`, `timeoutSeconds: 10`,
  `failureThreshold: 5`); engine gained liveness/readiness it never had (both on `/healthz` — the
  sidecar exposes no `/readyz`).
- **strategy `maxSurge: 0 / maxUnavailable: 1`** (replace-in-place) — **required** on the current
  single ~1-vCPU node: it sits at ~97% CPU *requests*, so a surge pod can never schedule. The old
  default (`maxSurge:1/maxUnavailable:0`) deadlocked — surge pod stuck `Pending (Insufficient cpu)`,
  old pod unable to drain. Replace-in-place terminates the old pod first (frees its request), then
  schedules the new one. Verified: one `helm upgrade` rolled api+engine cleanly in ~30s, 0 restarts,
  no Pending, no manual intervention; baseline held at 66/66.
- **terminationGracePeriodSeconds: 30** for clean shutdown.

**Zero-downtime rollout** (`maxSurge:1/maxUnavailable:0`) requires **more node capacity** (bigger VM
or a 2-node pool) or lower CPU requests. Only switch after `kubectl top nodes` shows real headroom
for a second app pod — otherwise the deadlock returns.

**Still tracked separately (backlog):** app-level DB/Redis connect backoff in the lifespan
(`main.py` has none today); initContainers cover ordering, but backoff is defense-in-depth for a
backend that accepts TCP before it is query-ready.

## Recovery sequence (ordered bring-up) — fallback

Dependencies must be serving before dependents start, or pods race their backends (P-14, the AKS
startup race — see [bug-patterns.md](bug-patterns.md)). The chart fix above normally prevents this;
use this only to recover from a bad/partial roll — scale everything down, then bring services up
**in dependency order**:

1. **Scale all app deployments to 0** — stop the churn first.
2. **postgres** — wait until it accepts connections and migrations are at head.
3. **redis** — wait until `PING` returns `PONG`.
4. **api** — depends on postgres + redis; warms the policy cache on startup.
5. **engine** — depends on redis (trust/eval cache) + the seeded policies.
6. **webhook / ui** — depend on the api being reachable.

`scripts/aks-recover.ps1` automates this ordering (create if absent; until then run the steps
manually with `kubectl scale`). `scripts/aks-verify.ps1` checks pod health and image SHAs after the
bring-up — run it before measuring any baseline.

```powershell
# Manual equivalent of the recovery sequence
kubectl scale deploy --all --replicas=0 -n norviq
kubectl rollout status statefulset/postgres -n norviq
kubectl rollout status deploy/redis      -n norviq
kubectl scale deploy/norviq-api    --replicas=1 -n norviq; kubectl rollout status deploy/norviq-api    -n norviq
kubectl scale deploy/norviq-engine --replicas=1 -n norviq; kubectl rollout status deploy/norviq-engine -n norviq
kubectl scale deploy/norviq-webhook --replicas=1 -n norviq
kubectl scale deploy/norviq-ui      --replicas=1 -n norviq
.\scripts\aks-verify.ps1
```

## Startup race fix — status

**Shipped** (see "P-14 permanent fix" above): initContainers gate the app on postgres + redis being
reachable, and a startupProbe absorbs slow migration/warm_cache starts. Remaining hardening, tracked
in backlog: readiness gating on a deeper dependency check (migration head applied) and app-level
connect backoff for the TCP-up-but-not-query-ready window.

## Verify the deploy actually applied

Old pods serve stale traffic (P-10). After a deploy, assert the running image SHA matches HEAD:

```powershell
kubectl get pods -n norviq -o jsonpath='{range .items[*]}{.metadata.name}{"`t"}{.spec.containers[0].image}{"`n"}{end}'
git rev-parse HEAD
```

If the tags don't match, the cluster is running old code — re-roll before trusting any result.

## Pod debugging

```powershell
kubectl get pods -n norviq
kubectl describe pod <pod> -n norviq           # events: image pulls, probe failures, OOM
kubectl logs <pod> -n norviq --tail=200
kubectl logs <pod> -n norviq --previous        # last crash before a restart
```

Search logs for NRVQ error codes (e.g. `NRVQ-GRP-11001` session-lifecycle, `NRVQ-ENG-2020` OPA
timeout). On Windows PowerShell, pipe to **`Select-String`**, not `grep`:

```powershell
kubectl logs <pod> -n norviq --tail=500 | Select-String "NRVQ-ENG-20"
```

## PowerShell / tooling gotchas

- Use `Select-String`, not `grep`. Use `Get-Content`, not `cat`/`tail` (or `-Tail N`).
- `psql` is not always on PATH on Windows; invoke the full path, e.g.
  `& "C:\Program Files\PostgreSQL\16\bin\psql.exe"`. Inspect real schema with `\d <table>` before
  trusting a query (P-8/P-10). The Redis CLI here is Memurai: `NRVQ_REDIS_CLI` in `.env.local`
  points at `memurai-cli.exe`.
- Local services (from `.env.local`): Postgres on **5433**, Redis on **6379**, API on **8080**.
