# IDENTITY epic live-local (A3/A4/B1/B3/B4) — 2026-06-28, built + live on kind, uncommitted

Deferred IDENTITY stages built + live-validated on kind (real Keycloak + SPIRE). Not committed.

## Code changed (all gated default-off)
- `norviq/engine/identity.py`: FIXED real pyspiffe-0.3.0 API in `_svid_source`/`_resolve_workload_api`
  (ctor `socket_path`, `unix://` scheme, `fetch_x509_svid()`, `spiffe_id` PROPERTY, close client).
- `webhook/injector.go` + `config.go`: B3 — gated `SpiffeInject` adds 2nd csi.spiffe.io volume+mount+
  `NRVQ_SPIFFE_MODE/SOCKET` env (sidecar + app). New tests TestCreatePatchSpiffeInject(+OffByDefault).
- `webhook/controller.go`: B4 — `oidcTokenSource` (clientcredentials.Config from NRVQ_OIDC_TOKEN_URL/
  CLIENT_ID/CLIENT_SECRET, NRVQ-WHK-4042); `bearerToken()` prefers it, HS256 fallback (NRVQ-WHK-4043).
- `norviq/api/routers/me.py` (new) + main.py: A3 `GET /api/v1/me` (NRVQ-API-7061).
- `ui/src/auth/oidc.ts` + `OidcCallback.tsx` + App.tsx/AppContext/client.ts: A3 oidc-client-ts PKCE.
- `Dockerfile.{engine,api}`: `pip install '.[spiffe]'` + arch-aware OPA (ARG TARGETARCH).
- helm: configmap NRVQ_SPIFFE_SOCKET; values config.spiffeCsi/spiffeSocket + webhook.spiffe/oidc;
  api/engine CSI volume+SA+label (gated config.spiffeCsi.enabled); spiffe-sa.yaml; secret NRVQ_OIDC_CLIENT_SECRET.

## Infra (scripts/identity-local/)
kind-config.yaml, spire-values.yaml, spire-clusterspiffeid.yaml (className spire-system-spire!),
keycloak.yaml + realm-norviq.json, b2-proof.yaml, values-identity.yaml, 00-up.sh/10-verify.sh/99-down.sh.

## Key gotchas
- Issuer-host match: KC_HOSTNAME=keycloak.localtest.me:8080 + kind extraPortMapping 30080->8080 +
  CoreDNS rewrite keycloak.localtest.me->keycloak.norviq.svc.
- ClusterSPIFFEID needs `spec.className: spire-system-spire` or it's ignored.
- csi.spiffe.io volume wedges pods if SPIRE absent -> gate everything off by default.
- SPIRE entry mint race -> retry resolve at workload startup.

Live: SVID spoof-proof+fail-closed; real RS256 group-mapping; per-user audit; B4 client-creds sync;
attacks 75/75. Unit 417/9-preexisting, ruff/go/tsc/vitest/helm-both green. AKS untouched (deferred).
