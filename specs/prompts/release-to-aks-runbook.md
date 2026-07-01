# Release to AKS Runbook (P-10 Hardened)

Date: 2026-07-01

## Purpose

Ensure AKS deploy integrity verifies **code + effect**, not tag equality alone.

## P-10 Gates (Required)

1. **Image/tag parity**
   - Deployed image tag matches `${GIT_SHA}` for API/UI/webhook (and fleet API when enabled).

2. **Build provenance parity**
   - `GET /api/v1/version` returns:
     - `build_git_sha == ${GIT_SHA}`
   - This proves running code provenance, not only image naming.

3. **R2 effect proof (live)**
   - Determine served cluster from `GET /api/v1/cluster-info` (`cluster_id`).
   - Send `X-Nrvq-Target-Cluster` with a genuinely different value.
   - For all intended cluster-scoped mutation endpoints, mismatch must return `409`.
   - Use reject-only/disposable payloads; no real-tenant state mutation.

## Mandatory Probe Set (R2)

- `POST /api/v1/policies`
- `POST /api/v1/policies/{namespace}/{agent_class}/rollback`
- `POST /api/v1/policies/dry-run`
- `POST /api/v1/policies/{namespace}/{agent_class}/apply`
- `POST /api/v1/policy-packs/{id}/enable`
- `POST /api/v1/policy-packs/{id}/disable`
- `PUT /api/v1/policy-packs/override`
- `DELETE /api/v1/policy-packs/override`
- `PUT /api/v1/settings`
- `POST /api/v1/attack-paths/compute`
- `PUT /api/v1/agents/{spiffe_id}/trust`

## Build Integrity Requirements

- CI must pass `NRVQ_GIT_SHA=${GIT_SHA}` into Docker builds.
- API image must bake this SHA in a late layer (`NRVQ_BUILD_GIT_SHA`) to force source-layer cache invalidation.
- Cache scope must be component-specific to avoid stale cross-component reuse.

## Failure Handling

- If `/version.build_git_sha != ${GIT_SHA}`: STOP release, rebuild image, redeploy.
- If any R2 mismatch probe != 409: STOP release, open P0, do not mark GA-ready.

