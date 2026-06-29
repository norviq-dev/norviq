# Prompt — Multi-cluster fleet (R3) REMAINING: P2 policy-push + P3 drill-down + P4 residency + AKS rollout

**Date:** 2026-06-28
**Work item:** Complete the multi-cluster epic in one staged pass — P2 signed policy-push (+ per-cluster
rollout/override + SPIFFE-mTLS relay + HA fleet plane), P3 live drill-down federation, P4 residency
controls, and the AKS live rollout of the fleet plane. Prod-ready, proven on an intensive local
multi-cluster POC first, AKS last (gated behind a green local POC). Plan mode (staged); security auditor REQUIRED.
**Design source:** `specs/EPIC-multi-cluster-fleet.md` (Option A; phasing P1→P4). **Builds on:** P1 (F045) + identity epic.
**FEAT:** F045 + F018 (console). **Commit:** (commit P2 before AKS; AKS rollout in its own commit) · **Result:** (to fill)

One prompt, but plan-mode staged. Crux = signed bundles + fail-safe (tampered/unsigned/replayed →
rejected; hub-down → spoke keeps last good, never opens up). Everything gated OFF by default → single-
cluster dev unchanged until flipped on. Local POC report → `.reviews/fleet-p2/REPORT.md`. AKS is the
LAST stage and only runs after the local POC is green + P2 committed.

---

## Prompt

```
ROLE: Multi-cluster fleet — EPIC R3, COMPLETE THE REMAINING WORK in one staged pass: P2 (signed
policy-push), P3 (drill-down federation), P4 (residency), then the AKS live rollout. Make multi-
cluster PROD-READY. Norviq (repo: norviq-migration/repo). USE PLAN MODE — present a staged plan for
the WHOLE remaining epic, WAIT for approval, implement stage by stage (do NOT blast it all at once).
Security auditor REQUIRED throughout (cross-cluster enforcement-policy distribution is a prime attack
target). Design source: specs/EPIC-multi-cluster-fleet.md (Option A; P1→P4). Builds on P1 (fleet-api
hub + relay + cluster-scope RBAC, FEAT F045) and the identity epic (OIDC + SPIRE). Nothing may break
the single-cluster path: all fleet behavior stays gated OFF by default → dev/AKS unchanged until
explicitly enabled. Keep attacks 75/75 throughout.

ORDERING / SAFETY GATES (hard):
  - Prove EVERYTHING on local kind first (intensive POC). AKS rollout is the LAST stage and runs ONLY
    after the local POC matrix is green.
  - Commit P2 (S1–S3) as a milestone BEFORE the AKS stage; AKS rollout is its own commit. P-10 SHA==HEAD
    on every commit; ships dormant elsewhere (gates off).

GOAL: a SecOps admin authors a policy once on the hub → it is SIGNED → distributed to selected
clusters → each spoke VERIFIES the signature and applies it to local enforcement → rollout status is
visible per-cluster; the console can drill into one cluster's live audit; and a residency flag keeps a
cluster's raw logs in-cluster. Tampered/unsigned/replayed bundles are REJECTED; a spoke losing the hub
keeps enforcing the last good bundle and NEVER opens up.

STAGES (propose order + files/tests/rollback per stage; security-auditor review each):
  S1 — SIGNED BUNDLE CORE (P2 crux):
     - Hub: canonical fleet_policy (id,name,rego_source,version,target_selector); build a SIGNED bundle
       (detached JWS / signature over canonical bundle bytes). Trust root: a DEDICATED fleet signing
       keypair (platform-agnostic; public key distributed to spokes via values/secret) — recommended
       over coupling to SPIRE for *integrity*; state the choice. Include version + not-before/expiry +
       a monotonic counter to defeat REPLAY/rollback.
     - Spoke relay: PULL bundle → verify signature against the configured trust root → apply to the
       local loader/engine. FAIL-CLOSED: invalid/missing/expired/older-version → REJECT, keep the last
       good bundle (never apply unsigned/tampered; never downgrade).
  S2 — ROLLOUT + TARGETING + OVERRIDES + CONSOLE (P2):
     - policy_rollout per-cluster state (pending/applied/failed/diverged, applied_version, ts).
     - target_selector matches clusters by label (e.g. env=prod); per-cluster override precedence.
     - Console (F018): fleet policy authoring + per-cluster rollout status + override editor. RBAC:
       push requires admin + cluster-scope; viewer cannot push (403).
  S3 — PROD-READY TRANSPORT + HA (P2):
     - Relay→hub transport hardened to SPIFFE-mTLS (reuse the identity epic's SPIRE SVIDs); OIDC
       client-creds retained as fallback.
     - Fleet plane prod-readiness (values-prod, gated): HA fleet-api (>=2 replicas + PDB) + HA
       fleet-postgres (CloudNativePG, reuse the deploy-hardening pattern); helm template/lint clean.
  S4 — P3 DRILL-DOWN FEDERATION:
     - Console can drill into ONE cluster's LIVE audit detail (Option-B style live query to that
       cluster's API), RBAC/cluster-scope enforced; hot aggregate path stays on the hub rollups.
  S5 — P4 RESIDENCY CONTROLS:
     - Per-cluster "raw logs never leave" flag → that spoke pushes ONLY rollups (no raw audit egress);
       hub keeps only rollups for it; drill-down for that cluster degrades gracefully (in-cluster only).
  S6 — INTENSIVE LOCAL POC (>=2 kind clusters; extend scripts/fleet-local/):
     author a fleet policy → pushes to matching clusters → spokes apply → ENFORCE the new rule live;
     per-cluster override; drill-down into one cluster's live audit; residency flag honored; and the
     ADVERSARIAL matrix — tampered → rejected + spoke keeps last good; unsigned → rejected; replay/old
     → rejected; hub down → spokes keep enforcing (attacks still block); hub back → resync; compromised
     -hub "allow-all" push → rejected by signature/trust-root; RBAC viewer push → 403; cross-cluster
     scope → 403; residency-flagged cluster leaks no raw audit to the hub.
  S7 — AKS LIVE ROLLOUT (LAST; only after S6 green + P2 committed):
     roll the fleet plane onto the AKS dev cluster (hub + relay), enable gated; CI build+deploy green;
     P-10 SHA==HEAD; verify cross-cluster (AKS + one more spoke) heartbeat/rollup/aggregate, a signed
     policy push applies, hub-down fail-safe, attacks 75/75 on AKS. If a 2nd live cluster isn't
     available, do the single-spoke AKS validation + document the 2-cluster step as the remaining live demo.

VALIDATION REPORT -> .reviews/fleet-p2/REPORT.md: a PASS/FAIL matrix per check above (especially the
adversarial/fail-safe rows) with live evidence per row; an AKS section; and a "still-deferred" section
if anything slips. Fix-on-the-fly during stages; the report reflects the final state.

GATES (after approval, per stage):
  - registry/F045.md + architecture/F045.*.mmd updated; new NRVQ-FLT-* codes in docs/error-codes.md.
  - Tests: signature verify (valid/invalid/tampered/expired/replay), rollout state machine, selector
    match, override precedence, fail-safe (hub-down keeps last good; bad bundle rejected), RBAC push,
    drill-down scope, residency (no raw egress). Keep attacks 75/75; unit suite green; tsc + vitest green.
  - helm lint + template clean for values-aks-dev + values-prod with fleet OFF (zero fleet resources),
    AND the fleet overlays incl. HA fleet-api + fleet-postgres.
  - Do NOT auto-commit; summarize per stage. Commit P2 (S1–S3) before AKS; AKS rollout its own commit.
    Record this prompt + outcome in specs/prompts/ + index.
  - Honest labeling: after this, R3 is complete incl. AKS; note anything that slipped to a follow-up.
```
