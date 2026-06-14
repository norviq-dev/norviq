<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Norviq Contributors -->

# AKS Operations

Operating and recovering the Norviq stack on AKS. The cluster is the source of truth for the test
baseline (see [test-baseline-discipline.md](test-baseline-discipline.md)).

## Recovery sequence (ordered bring-up)

Dependencies must be serving before dependents start, or pods race their backends (P-14, the AKS
startup race — see [bug-patterns.md](bug-patterns.md)). To recover from a bad/partial roll, scale
everything down, then bring services up **in dependency order**:

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

## Startup race fix plan (Day 14)

Pods currently report Ready on process-up, before backends serve. Planned fix:

- Readiness probe gates on a **real dependency check** — migration head applied + Redis `PING`,
  not just the port being open.
- API/engine use init-containers (or a startup probe) that block until postgres + redis are
  reachable, so Kubernetes won't send traffic into an unmigrated schema.
- Until shipped, rely on the ordered recovery sequence above and verify health before measuring.

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
