# Prompt — Identity epic LIVE local end-to-end (Keycloak + SPIRE on kind)

**Date:** 2026-06-28
**Work item:** Live end-to-end validation of the deferred Identity stages (A3, A4, B1, B3, B4) against
a REAL OIDC IdP (Keycloak) + REAL SPIRE on a LOCAL kind cluster. Builds on the uncommitted A1+A2+B2
core. Plan mode (staged); security auditor. Platform-agnostic (Keycloak; no Azure/vendor SDKs).
**Depends on:** EPIC-identity-sso-spire (A1/A2/B2 software core). **Design:** specs/EPIC-sso-oidc.md.
**FEAT:** F033 + F026 + F007 + F016 + F017 + F018. **Docker:** 12 GB. **AKS:** deferred to a later session.
**Commit:** not committed (gate: do NOT auto-commit) · **Result:** see Outcome below.

Local-first decision: deploy Keycloak + SPIRE on kind and validate OIDC + workload-api end-to-end
locally; AKS later. Keep attacks 75/75 + unit suite green (mock). Platform-agnostic — cloud IdPs are
config swaps, not code. Locked (AskUserQuestion): B4 = OIDC client-credentials; A3 = oidc-client-ts;
Keycloak realm = declarative realm.json import.

## Outcome (done — built + LIVE-validated on a local kind cluster `norviq-identity`; nothing committed)

**A real bug the live run caught:** the committed B2 core called the WRONG pyspiffe API — real
`spiffe 0.3.0` uses ctor `socket_path` (not `spiffe_socket_path`), `fetch_x509_svid()` (not
`get_x509_svid()`), `spiffe_id` as a **property**, and requires the `unix://` scheme. Fixed
`norviq/engine/identity.py` + the test fakes; now verified against real pyspiffe.

- **B1 SPIRE on kind (LIVE):** upstream `spiffe/spire-crds` + `spiffe/spire` (server+agent+controller-
  manager+SPIFFE CSI), trust domain `norviq`, a `ClusterSPIFFEID` (k8s attestor ns+SA, `className:
  spire-system-spire`, opt-in label `norviq.io/svid`). Minted `spiffe://norviq/ns/norviq/sa/norviq-api`
  + `.../sa/norviq-test`. api/engine pods mount the `csi.spiffe.io` socket (gated `config.spiffeCsi`).
- **B3 injector (built + unit-tested):** `webhook/injector.go` injects a 2nd `csi.spiffe.io` volume +
  mount + `NRVQ_SPIFFE_MODE/SOCKET` into sidecar + app (gated `NRVQ_SPIFFE_INJECT`); idempotent. The CSI
  mount mechanism is live-proven (api/engine + the B2 job all mount it).
- **B2 workload-api (LIVE, the security crux):** a Job (SA norviq-test, bogus `NRVQ_NAMESPACE=attacker`)
  resolved the **attested** `spiffe://norviq/ns/norviq/sa/norviq-test` — env ignored (**spoof-proof**); a
  no-socket Job raised `SpiffeResolutionError` (**fail-closed**, no env fallback).
- **A1/A2 OIDC (LIVE):** Keycloak realm `norviq`; alice (group norviq-admins) → a real RS256 token the API
  validated against Keycloak JWKS (iss/aud/sig) → `/api/v1/me` `role=admin`; bob (team-a) → `viewer` +
  `namespace=team-a`. Per-user audit `NRVQ-API-7011 actor=<alice sub> actor_role=admin`. The classic
  kind/Keycloak issuer-host mismatch was solved with `KC_HOSTNAME=keycloak.localtest.me:8080` + a CoreDNS
  rewrite so the in-cluster API and the browser see the identical `iss`.
- **B4 controller→API (LIVE):** the controller mints an OIDC client-credentials token (Keycloak
  `norviq-webhook` client, `NRVQ-WHK-4042`); applying a `NrvqPolicy` CR → `NRVQ-WHK-4026 Policy synced to
  API successfully` (the API accepted the client-creds token via the existing OIDC path → role=service).
  HS256 fallback retained.
- **A3 console (built + unit-validated; browser flow manual):** `oidc-client-ts` Auth-Code+PKCE
  (`ui/src/auth/oidc.ts` + `/auth/callback`), drops the dev token, stores the access token where
  `authHeaders()` reads it; new `/api/v1/me`. tsc + vitest 37/37 green. Realm ships the PKCE SPA client.
- **A4 (LIVE):** local deploy runs `oidc.enabled=true` + `spiffe_mode=workload-api`; `legacy_hs256_enabled`
  stays true — the HS256 **break-glass** token still authenticates (`/me` role=admin) so CI/controller/
  attacks stay headless. **Attacks 75/75** via the break-glass token (oidc on).
- **Gates:** ruff clean; unit suite 417 pass / 1 skip / 9 pre-existing (zero new regressions); go
  build/vet/test green; tsc + vitest 37/37; `helm lint`+`template` clean for BOTH overlays (every new
  block — CSI, spiffe-inject, webhook OIDC, dedicated SAs — renders OFF by default). New codes
  NRVQ-WHK-4042/4043 (Go), NRVQ-API-7061 (/me). **The AKS dev cluster was never touched.**
- **Honestly deferred to the AKS session:** AKS SPIRE/OIDC rollout; a full injected-sidecar-with-SVID
  app demo (the injector + CSI mount are validated, an end-user injected workload pulling an SVID is the
  remaining live demo); the SPIFFE-JWT-SVID B4 variant; the permanent HS256 cutover.
- **Repeatable:** `scripts/identity-local/` — `00-up.sh` (kind+SPIRE+Keycloak+build/load+helm),
  `10-verify.sh` (e2e + evidence to `.reviews/identity-local/`), `99-down.sh`. Platform-agnostic: swap
  `oidc.issuer/jwksUrl/audience` + client to Entra/Okta/Auth0 — no code change.
- **Rollback:** all new behavior gated to defaults (`oidc.enabled=false`, `legacy_hs256_enabled=true`,
  `spiffe_mode=mock`, `config.spiffeCsi.enabled=false`, `NRVQ_SPIFFE_INJECT=false`). Product images now
  carry pyspiffe but stay mock by default. Local stack is a throwaway kind cluster.

---

## Prompt

```
ROLE: Identity epic — LIVE LOCAL end-to-end validation of the deferred stages (A3, A4, B1, B3, B4),
wired to a REAL OIDC IdP (Keycloak) + REAL SPIRE on a LOCAL kind cluster. Builds on the already-
implemented (uncommitted) A1+A2+B2 software core. USE PLAN MODE — present a staged plan, WAIT for
approval, implement stage by stage. Security auditor in the loop. PLATFORM-AGNOSTIC: Keycloak is the
test IdP; NO Azure/vendor SDKs; cloud IdPs are config examples only. Design source: specs/EPIC-sso-
oidc.md. FEAT: F033 + F026 + F007 + F016 + F017 + F018. Docker has 12 GB. AKS validation is a LATER
session — do not touch the AKS dev cluster; keep attacks 75/75 and the unit suite green (mock).

GOAL: prove identity end-to-end ON LOCAL KIND — a user logs in via Keycloak (OIDC), the API validates
the real token + maps groups→role/namespace, AND a workload gets a real SPIRE SVID that the resolver
attests (spoof-proof). Then multi-cluster is the next epic.

LOCAL STACK (repeatable script/overlay — extend scripts/eval or a new scripts/identity-local; 12 GB):
  kind cluster + Norviq via helm with oidc_enabled=true (issuer/jwksUrl → in-cluster Keycloak) and
  spiffe_mode=workload-api; + Keycloak (realm `norviq`, groups, a test user, an SPA client with
  Auth-Code+PKCE); + SPIRE (upstream spire-crds + spire + spire-controller-manager + SPIFFE CSI
  Driver), trust domain `norviq`, ClusterSPIFFEID (k8s attestor: ns+SA). Teardown script too.

STAGES (propose order + files/tests/rollback per stage):
  B1 Deploy SPIRE on kind (charts, CSI driver, ClusterSPIFFEID, trust domain norviq).
  B3 Injector (F016): mount the Workload API socket into injected workloads.
  B2(live) Run the resolver in workload-api mode against real SPIRE — attested ns/sa win; LIVE
     spoof test (set bogus NRVQ_NAMESPACE/NRVQ_SERVICE_ACCOUNT → identity unchanged); fail-closed
     when the socket is down.
  B4 Webhook controller→API auth uses a SPIFFE-SVID / OIDC client-credentials identity (keep the
     HS256 service token as fallback so nothing breaks).
  A3 Console Auth-Code+PKCE login against Keycloak; drop the dev-injected static token.
  A4 Flip oidc_enabled on for the local deploy; KEEP a break-glass/service token (short TTL, audited)
     so the attack suite + controller stay headless. Test legacy_hs256_enabled=false too, then leave
     dual-mode for safety.

END-TO-END VALIDATIONS (LIVE, local kind — capture evidence):
  - OIDC: log into the console via Keycloak (PKCE) → API validates RS256 against Keycloak JWKS →
    group→role/namespace mapping correct → per-user `sub` in the admin-write audit lines.
  - SPIRE: a workload pod receives an X509-SVID (spire-agent api fetch); resolver returns the
    attested spiffe://norviq/ns/<ns>/sa/<sa>; spoofing env vars does NOT change it; fail-closed proven.
  - Controller→API works via the new identity (B4).
  - Attacks 75/75 via the break-glass/service path; unit suite still green (mock).

PLATFORM-AGNOSTIC CHECK: everything is standard OIDC discovery+JWKS and SPIFFE Workload API — document
the one-line config swap to point at Entra/Okta/Auth0 instead of Keycloak; no vendor-specific code.

GATES (after approval, per stage):
  - Now land the FULL registry/{F033,F026,F016}.md + finish F007/F017 + architecture .mmd (the
    deferred stages are now built); new NRVQ-* codes in docs/error-codes.md.
  - make lint + make test + tsc + vitest; helm lint both overlays; keep attacks 75/75. AKS untouched.
  - Do NOT auto-commit; summarize per stage. Record this prompt + outcome in specs/prompts/ + index.
  - Note honestly which parts are validated locally vs deferred to the AKS session.
```
