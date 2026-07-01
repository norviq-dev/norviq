# Fleet R3 P2/P3/P4 — signed policy-push + drill-down + residency + AKS (F045)

Completes the multi-cluster fleet EPIC past P1 (`mem:fleet_mvp_p1` if present). Commits on `main`:
`f0caa8d` (P2 milestone S1–S6) · `de5e1b0` (S7 AKS rollout) · `11e8e7e` (docs SHAs — committed locally,
**push was gated by the auto-classifier**, so deployed image is still `api-de5e1b0…` as of 2026-06-29).

## Files / symbols
- `norviq/fleet/bundle.py` — the ONE shared canonicalizer: `canonical_bytes(payload)` (sort_keys,
  separators, ensure_ascii=False, RFC3339 `Z`, policies sorted) + `sign_bundle(payload, key, kid)` +
  `verify_bundle(body, pubkey)` (jose JWS RS256, single-alg, recompute-and-compare, returns the SIGNED
  payload — spoke acts on verified bytes; raises BundleVerifyError on empty pubkey/missing jws/tamper).
- `norviq/fleet/routers/fleet_policy.py` — hub: `POST /fleet/policies` (require_admin), `_resolve_for_cluster`
  (selector subset of labels + cluster_id override precedence), `GET /clusters/{id}/bundle` (resolve→
  bump-on-change version via sha256 vs rollout.detail→sign), `POST /clusters/{id}/rollout` (state machine
  pending/applied/failed/diverged), `GET /clusters/{id}/audit/records` (P3 drill-down, residency-blocked), `GET /fleet/rollout`.
- `norviq/fleet_puller.py` `FleetPolicyPuller` — spoke: mirrors FleetRelayForwarder; `start()` no-op unless
  fleet_enabled + cluster_id + api_url AND `fleet_bundle_pubkey` set (else fail-closed NRVQ-FLT-15016).
  `pull_once`: GET bundle→verify→cluster_id→temporal→version>last→`PolicyLoader.create` per policy→persist
  `FleetBundleState` after full loop→report. Wired in the spoke lifespan (`norviq/api/main.py`) next to fleet_relay.
- Models: `norviq/fleet/models.py` add `FleetPolicy`, `PolicyRollout`, `Cluster.{labels,bundle_version,
  residency,spiffe_id}`; `norviq/api/db/models.py` add `FleetBundleState` (spoke Base).
- Config (`norviq/config.py`): `fleet_signing_key`, `fleet_bundle_pubkey`, `fleet_bundle_ttl_s`,
  `fleet_pull_interval_s`, `fleet_residency`, `fleet_cluster_labels`.
- Helm: `fleet-hub.yaml` (+ `fleet.hub.signingKeySecretName` → NRVQ_FLEET_SIGNING_KEY via secretKeyRef),
  `fleet-ha.yaml` (HPA+PDB gated), `secret.yaml`/`configmap.yaml`/`values.yaml`/`values-prod.yaml`. All gated OFF.

## Trust model
Spoke `NRVQ_FLEET_BUNDLE_PUBKEY` (RS256 public) is the trust root; hub `NRVQ_FLEET_SIGNING_KEY` private,
hub-only, distinct from `NRVQ_API_SECRET_KEY`. Verify-before-apply; never downgrade; reject keeps last-good.

## AKS rollout (single-spoke)
CI build.yml→deploy.yml on push to main; `helm upgrade` with values-aks-dev. Signing **private** key =
pre-created Secret `norviq-fleet-signing` (kubectl create secret … --from-file=NRVQ_FLEET_SIGNING_KEY=priv.pem),
referenced by `fleet.hub.signingKeySecretName`; never in git/CI. Pubkey committed in values-aks-dev (safe).
Gates live-verified: P-10 SHA==HEAD, signed push applies+ENFORCES (wire_transfer→block), hub-down fail-safe,
**attacks 75/75**.

## Gotchas
- The "attacks 75/75" gate = `pytest tests/attacks/` (75 collected; HTTP-based, hits NRVQ_API_URL + redis,
  default agent **customer-support**). NOT `norviq/redteam` (only 26 catalog attacks). To run vs AKS:
  port-forward api + redis, set NRVQ_API_URL/NRVQ_API_TOKEN/NRVQ_REDIS_URL.
- `baseline-cluster-guard-*` policies live in namespace `norviq`; attacks must target seeded
  (default, customer-support) which holds the ~8.6k-char comprehensive rego.
- Admin token: HS256 with NRVQ_API_SECRET_KEY, claims {sub,role:admin,cluster:'*'}; fleet routes under `/api/v1/fleet/...`.
- bundle version bumps every pull even when unchanged (issued_at likely in the hashed payload) → harmless churn, follow-up.
- Codes NRVQ-FLT-15015..15026. Report `.reviews/fleet-p2/REPORT.md`.
