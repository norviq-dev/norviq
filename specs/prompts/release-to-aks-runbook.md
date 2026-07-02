# Release to AKS Runbook (P-10 Hardened)

Date: 2026-07-01

## Purpose

Ensure AKS deploy integrity verifies **code + effect**, not tag equality alone.

## P-10 Gates (Required)

0. **Context preflight (mandatory first gate)**
   - `kubectl config current-context` must equal `norviq`.
   - `GET /api/v1/cluster-info` must return `cluster_id == aks-dev`.
   - Abort immediately on any mismatch. Do not continue post-deploy checks.

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

- If preflight context/cluster checks fail: STOP verification, switch to the AKS context, and restart P-10.
- If `/version.build_git_sha != ${GIT_SHA}`: STOP release, rebuild image, redeploy.
- If any R2 mismatch probe != 409: STOP release, open P0, do not mark GA-ready.


---

## Pre-GA remediation → release tail (release/pre-ga-remediation)

After the kind release-exit + final fable pentest PASS (see `.reviews/live-pentest/FINAL-PENTEST-PRE-GA.md`), the
actual release is:

1. **Commit + merge** `release/pre-ga-remediation` → `main` (San). The images were stamped `pre-ga-<sha>` during the
   uncommitted release-exit; the merge commit's real SHA becomes the release `GIT_SHA`.
2. **Rebuild all 4 images** (api/engine/webhook/ui) from the merged `main` HEAD with `NRVQ_GIT_SHA=${GIT_SHA}` — the UI
   image now builds via the shipped `Dockerfile.ui` (BUG-1 fixed). Push to the registry.
3. **AKS deploy** the chart (thin-proxy sidecar mode is the default; embedded is opt-in for air-gapped/edge).
4. **Hardened P-10 on AKS**: assert `/api/v1/version.build_git_sha == ${GIT_SHA}` (provenance==HEAD) AND the live
   409/effect probes. STOP release on any mismatch.

Deployment caveats surfaced at release-exit (address before/at deploy):
- Chart `helm upgrade` conflicts with the cert-job's kubectl-patched MutatingWebhookConfiguration `caBundle`
  (server-side-apply field ownership). Fresh `helm install` is unaffected; for upgrades, treat caBundle as
  externally-managed or reconcile field managers.
- With `webhook.failurePolicy: Ignore`, roll tenant workloads AFTER the webhook is Ready so injection isn't skipped.
