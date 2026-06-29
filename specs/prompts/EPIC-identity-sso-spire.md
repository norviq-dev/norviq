# Prompt — Identity epic: SSO/OIDC (R4/F033) + SPIRE/SPIFFE workload identity (F026)

**Date:** 2026-06-28
**Work item:** Implement the unified Identity epic — OIDC for human/service identity AND SPIRE/SPIFFE
real workload identity (replacing the env-var mock). Plan mode (staged); security auditor.
**Design source:** `specs/EPIC-sso-oidc.md` (full claims model, migration phases, SPIRE scope).
**Depends on:** Tier A (rotatable secret + guard), AKS deploy-hardening (controller service token).
**FEAT:** F033 + F026 + F007 (resolver) + F016 (injector) + F017 (API auth) + F018 (console).
**Commit:** not committed (gate: do NOT auto-commit) · **Result:** see Outcome below.

Two axes, one epic: (A) OIDC at the API/console edge (replace shared HS256, JWKS/RS256, group→role/
namespace, per-user audit, dual-mode migration, break-glass service token); (B) SPIRE/SPIFFE at the
tool-call/sidecar edge (deploy SPIRE, trust domain `norviq`, CSI socket, ClusterSPIFFEID; wire
identity.py resolver to the Workload API, NRVQ_SPIFFE_MODE gate, fail-closed, spoof-resistance). Keep
attacks 75/75; SPIRE validated on AKS (local eval stays mock).

## Scope (user-confirmed, AskUserQuestion)
**Now:** software core **A1 + A2 + B2**, gated default-off, zero-infra. OIDC validated against a
**synthetic in-process JWKS** (no live IdP). Group mappings in **Helm/config (GitOps)**.
**Deferred (designed + documented):** A3 console PKCE, A4 HS256 cutover + break-glass, B1 SPIRE-on-AKS,
B3 injector socket mount, B4 controller→SVID bridge.

## Outcome (done — implemented + locally validated; nothing committed)
- **A1 OIDC dual-mode (FIXED):** `norviq/api/auth.py` shared `_validate_token` dispatches HS256 (legacy,
  default-on) vs RS256/ES256 OIDC (gated `oidc_enabled`) on header `alg` with single-alg allowlists
  (alg-confusion-safe). New `norviq/api/jwks.py` `JwksClient` — kid-keyed cache, TTL + bounded unknown-kid
  refetch, **fail-closed** on fetch failure. `get_current_user`→401, `decode_token`(WS)→`jose.JWTError`.
  Codes NRVQ-AUTH-14000..14005.
- **A2 mapping + per-user audit (FIXED):** `_apply_group_mapping` (groups→role/ns; admin wins; conflicting
  non-admin ns fails closed; unmapped→viewer floor). `actor`(sub)+`actor_role` on admin-write audit lines
  NRVQ-API-7011/12/13/15 (no `audit_log` schema change). Helm `oidc.*`+`config.spiffeMode` passthrough.
- **B2 real resolver (FIXED):** `identity.py` `_resolve_from_socket` mode-gated on `NRVQ_SPIFFE_MODE`. `mock`
  unchanged (default). `workload-api` fetches/validates the X509-SVID via pyspiffe (`_svid_source` seam),
  **SVID ns/sa win over env (spoof-resistant)**, any failure → `SpiffeResolutionError` (**fail-closed, no
  fallback**). `pyspiffe` optional + import-guarded. Codes NRVQ-IDT-10004/10005/10006.
- **Gates:** ruff clean; unit suite **416 passed / 1 skip / 9 pre-existing fails** (identical with this change
  `git stash`ed → **zero regressions**); 22 new tests (16 OIDC + 6 identity); **attacks 75/75** (2nd API on
  :8090 running this code, shared dev Redis/PG/OPA; user's :8080 untouched); tsc clean; vitest 37/37; helm
  lint + template clean for `values-aks-dev.yaml` AND `values-prod.yaml` (OIDC/SPIFFE render default-off).
- **Rollback:** `oidc_enabled=false` + `legacy_hs256_enabled=true` + `spiffe_mode=mock` (today's defaults).
  New code ships dormant.
- **Registry/docs:** error-codes.md (AUTH + IDT ranges); architecture/F017.class.mmd + F007.class.mmd;
  registry/F017.md + F007.md dated sections. F033/F026 full registries land when their deferred stages do.

---

## Prompt

```
ROLE: Implement the IDENTITY epic for Norviq (repo: norviq-migration/repo) — both axes:
(A) SSO/OIDC for human + service identity (R4 / F033) and (B) SPIRE/SPIFFE real workload identity
(F026, replacing the env-var mock). USE PLAN MODE — present a STAGED plan, WAIT for approval, then
implement stage by stage. Bring the security auditor. Design source: specs/EPIC-sso-oidc.md (read it
first — it has the full claims model, migration phases, and SPIRE scope). FEAT: F033 + F026 + F007
(resolver) + F016 (injector) + F017 (API auth) + F018 (console). Nothing may break the 1-node AKS
dev cluster, the headless attack suite, or local/tests.

CONTEXT / WHY:
  - Auth today is a single shared HS256 secret (rotatable + strong-secret-guarded after Tier A/
    deploy-hardening, and the webhook controller now mints a short-lived service-role HS256 JWT) —
    but there is NO IdP, no per-user identity, no group->role mapping, no JWKS rotation.
  - Workload identity is a MOCK: engine/identity.py `_resolve_from_socket` builds the SPIFFE id from
    env vars (spoofable). No SPIRE in helm/. Namespace scoping (A1) + trust rest on this being real.

STAGED PLAN (propose stages + which to implement now vs defer; files/tests/rollback per stage):

  AXIS A — OIDC (human + service):
   A1 Dual-mode validate: add a JWKS client; the API validates RS256/ES256 access tokens (iss/aud/
      exp/sig, kid-keyed JWKS cache) ALONGSIDE legacy HS256, gated by `legacy_hs256_enabled` (default
      on during migration). Config: oidc.issuer/audience/jwksUrl/groupMappings. get_current_user()
      keeps returning a claims dict; require_admin()/scoped_namespace() unchanged in shape.
   A2 Group -> role/namespace mapping: configurable `groups` claim -> Norviq (role, namespace scope)
      via Helm/config; per-user `sub` written to audit_log (replaces anonymous admin).
   A3 Console SSO login: SPA does Auth Code + PKCE, drops the dev-injected static token.
   A4 Cutover: flip `legacy_hs256_enabled=false` once clients use OIDC; KEEP a break-glass/service
      token path (short TTL, audited) so the attack suite + CI + the webhook controller stay headless.

  AXIS B — SPIRE/SPIFFE (workload):
   B1 Deploy SPIRE (prefer upstream spiffe/spire + spire-crds + spire-controller-manager charts),
      trust domain `norviq` (matches existing spiffe ids + policy ns/sa parsing); SPIFFE CSI Driver
      to mount the agent socket; ClusterSPIFFEID registration (k8s workload attestor: ns + SA).
   B2 Resolver: implement identity.py `_resolve_from_socket` with pyspiffe (Workload API) to fetch +
      validate the X509-SVID and parse the id; cache per spiffe_cache_ttl_s; gate
      `NRVQ_SPIFFE_MODE=workload-api|mock` (prod=workload-api; mock for local/tests/socket-absent);
      FAIL-CLOSED on socket-unreachable/invalid-SVID (no silent "unknown"). Add pyspiffe to pyproject.
   B3 Injector (F016): injected workloads also get the Workload API socket mounted.
   B4 Bridge: upgrade the webhook controller's service-to-API auth from the HS256 service token toward
      a SPIFFE-svid / OIDC client-credentials identity.

  CONNECT THE AXES: OIDC governs the caller at the API/console edge; SPIRE governs the workload at the
  tool-call/sidecar edge; both feed the same (role + namespace/tenant scope) shape A1/scoped_namespace
  already consume. (Cluster scope becomes an extra mapped dimension for the future fleet epic.)

NON-NEGOTIABLES / SECURITY (auditor):
  - Spoofing NRVQ_NAMESPACE/NRVQ_SERVICE_ACCOUNT must NOT change the resolved identity in workload-api
    mode (the SVID wins). Namespace scoping derives from the attested SVID. Add a spoof-resistance test.
  - Keep attacks 75/75 (0 xfail/skip) — the test harness stays mock SPIFFE + the service-token auth path.
  - Dual-mode (HS256 + OIDC) so nothing breaks mid-migration; rollback = NRVQ_SPIFFE_MODE=mock and
    legacy_hs256_enabled=true.
  - SPIRE validated on AKS (not kind); the local eval harness stays mock — resolver mock fallback keeps
    the simulation + unit tests working unchanged.

GATES (after approval, implement per stage):
  - CLAUDE.md: update registry/{F033,F026,F007,F016,F017}.md + architecture .mmd where structure
    changes; new NRVQ-* codes (IDT/AUTH) in docs/error-codes.md.
  - Tests: OIDC RS256 validate (good/bad iss/aud/exp/kid), group->role mapping, per-user audit,
    SPIRE workload-api success / mock fallback / spoof-resistance / fail-closed, service-token path.
    Never monkeypatch get_session.
  - make lint + make test + tsc + vitest; helm lint both overlays; keep 75/75. Do NOT auto-commit;
    summarize per stage. Record this prompt + outcome in specs/prompts/ + index.
```
