# Prompt — Multi-cluster fleet (R3) PHASE 2: signed policy-push, prod-ready, intensive local POC

**Date:** 2026-06-28
**Work item:** Fleet P2 — signed fleet-wide policy distribution + per-cluster rollout/override +
SPIFFE-mTLS relay + HA fleet plane, made prod-ready and proven on an intensive local multi-cluster POC.
Plan mode (staged); security auditor REQUIRED. AKS live rollout deferred to a later session.
**Design source:** `specs/EPIC-multi-cluster-fleet.md` (Option A; P2). **Builds on:** P1 (F045) + identity epic.
**FEAT:** F045 (P2) + F018 (console). **Commit:** (pending; commit P1 first for a clean base) · **Result:** (to fill)

P2 = the "manage all clusters" half of R3. Crux = signed bundles + fail-safe (tampered/unsigned/replayed
→ rejected; hub-down → spoke keeps last good, never opens up). Everything gated OFF by default → single-
cluster dev/AKS unchanged. Validation report at `.reviews/fleet-p2/REPORT.md`.

---

## Prompt

```
ROLE: Multi-cluster fleet — EPIC R3, PHASE 2 (policy-push) — make multi-cluster PROD-READY with an
INTENSIVE local multi-cluster POC. Norviq (repo: norviq-migration/repo). USE PLAN MODE — present a
staged plan, WAIT for approval, implement stage by stage. Security auditor is REQUIRED throughout
(this is cross-cluster enforcement-policy distribution — a prime attack target). Design source:
specs/EPIC-multi-cluster-fleet.md (Option A; P2 = signed policy-push + per-cluster rollout/override).
Builds on P1 (fleet-api hub + relay + cluster-scope RBAC, FEAT F045) and the identity epic (OIDC +
SPIRE). Nothing may break the single-cluster path: all fleet behavior stays gated OFF by default →
dev/AKS unchanged. Keep attacks 75/75. AKS live rollout is a LATER session; this session is intensive
LOCAL multi-cluster.

GOAL: a SecOps admin authors a policy once on the hub → it is SIGNED → distributed to selected
clusters → each spoke VERIFIES the signature and applies it to local enforcement → rollout status is
visible per-cluster. Tampered/unsigned/replayed bundles are REJECTED; a spoke losing the hub keeps
enforcing the last good bundle and NEVER opens up.

STAGES (propose order + files/tests/rollback per stage; security-auditor review each):
  S1 — SIGNED BUNDLE CORE (the crux):
     - Hub: canonical fleet_policy (id,name,rego_source,version,target_selector); build a SIGNED
       bundle (detached JWS / signature over the canonical bundle bytes). Trust root: a DEDICATED
       fleet signing keypair (platform-agnostic; public key distributed to spokes via values/secret)
       — recommended over coupling to SPIRE for *integrity*; state the choice. Include version +
       not-before/expiry + a monotonic counter to defeat REPLAY/rollback.
     - Spoke relay: PULL bundle → verify signature against the configured trust root → apply to the
       local loader/engine. FAIL-CLOSED: invalid/missing/expired/older-version signature → REJECT,
       keep the last good bundle (never apply unsigned/tampered; never downgrade).
  S2 — ROLLOUT + TARGETING + OVERRIDES + CONSOLE:
     - policy_rollout per-cluster state (pending/applied/failed/diverged, applied_version, ts).
     - target_selector matches clusters by label (e.g. env=prod); per-cluster override precedence.
     - Console (F018): fleet policy authoring + per-cluster rollout status + override editor. RBAC:
       push requires admin + cluster-scope; viewer cannot push (403).
  S3 — PROD-READY TRANSPORT + HA + INTENSIVE POC:
     - Relay→hub transport hardened to SPIFFE-mTLS (reuse the identity epic's SPIRE SVIDs), OIDC
       client-creds retained as fallback.
     - Fleet plane prod-readiness (values-prod, gated): HA fleet-api (>=2 replicas + PDB) + HA
       fleet-postgres (CloudNativePG, reuse the deploy-hardening pattern); helm template/lint clean.
     - INTENSIVE local POC on >=2 kind clusters (extend scripts/fleet-local/): author a fleet policy
       → pushes to matching clusters → spokes apply → ENFORCE the new rule live; per-cluster override;
       and the ADVERSARIAL matrix — tampered bundle → rejected + spoke keeps last good; unsigned →
       rejected; replay/old-version → rejected; hub down → spokes keep enforcing (attacks still block);
       hub back → resync; compromised-hub "allow-all" push → rejected by signature/trust-root; RBAC
       viewer push → 403; cross-cluster scope → 403.

VALIDATION REPORT -> .reviews/fleet-p2/REPORT.md: a PASS/FAIL matrix per check above (especially the
adversarial/fail-safe rows) with live evidence per row; plus a "still-deferred" section (P3 drill-down,
P4 residency, AKS live rollout). Fix-on-the-fly during stages; the report reflects the final state.

GATES (after approval, per stage):
  - registry/F045.md (P2) + architecture/F045.*.mmd updated; new NRVQ-FLT-* codes in docs/error-codes.md.
  - Tests: signature verify (valid/invalid/tampered/expired/replay), rollout state machine, selector
    match, override precedence, fail-safe (hub-down keeps last good; bad bundle rejected), RBAC push.
    Keep attacks 75/75; unit suite green; tsc + vitest green.
  - helm lint + template clean for values-aks-dev + values-prod with fleet OFF (zero fleet resources),
    AND the fleet overlays incl. HA fleet-api + fleet-postgres. AKS untouched.
  - Do NOT auto-commit; summarize per stage. Record this prompt + outcome in specs/prompts/ + index.
  - Honest labeling: P2 policy-push done + prod-ready locally; P3/P4 + AKS live rollout still deferred.
```
