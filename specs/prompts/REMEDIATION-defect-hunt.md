# Prompt — Remediate defect-hunt findings F-01…F-05 (+ F-04 product decision)

**Date:** 2026-06-29
**Work item:** Fix the 5 findings from the defect-hunt (`.reviews/test-campaign/FINDINGS.md`) — F-01 P1
cross-tenant `/evaluate` BFLA (dual-caller-aware), F-02 P2 homoglyph/NFKC injection evasion, F-04 P2
no-policy fail-open (product decision: default-deny), F-03 P3 API-key throttle + constant-time, F-05 P3
graph-analysis caching. Each with a regression test. Plan mode (staged); security auditor on F-01/F-02/F-04.
**Source:** `.reviews/test-campaign/FINDINGS.md` + `COVERAGE.md`. **FEAT:** F017/F007/F046/F036/F037 as touched.
**Commit:** do NOT auto-commit (summarize per finding) · keep **attacks 75/75**.
**Result (DONE; branch `feat/console-f046-and-defect-remediation`):** Commits `b465b13` (Stage 1: F-01 + the
sibling **F-06**) + `c0bf6d8` (F-02/F-03/F-04/F-05). All 6 findings remediated, each with a regression test +
live-verified on kind `nv-a` (rebuilt working-tree image per engine stage):
- **F-01 P1** — `/evaluate` binds the namespace to the caller: `role!=service` → `scoped_namespace(user, body_ns)`
  (admin/service any, human viewer→403). Live: viewer cross-ns 200→**403**. Residual: service/SVID-derived ns (follow-up).
- **F-06 (sibling)** — `scoped_namespace` 403s the empty-claim non-admin/non-service floor user (was: reached any ns).
- **F-04 P2** — no-policy → **deny** (NRVQ_NO_POLICY_DECISION default deny); `no_policy_loaded` (ENG-2055) vs
  `policy_load_pending` (ENG-2056, loader `_warmed`) vs DB-fail (ENG-2000); audit mode allows. Live: ghost-ns→block.
- **F-02 P2** — `norviq/engine/confusables.py` skeleton (NFKD + strip combining/zero-width + casefold + cross-script
  fold) → `tool_params_normalized` (match-only); rego additive normalized clauses. Live: Cyrillic/zero-width→block; benign JP→allow.
- **F-03 P3** — `hmac.compare_digest` + per-prefix throttle (NRVQ-AUTH-14006). **F-05 P3** — graph analysis cache
  (NRVQ-DB-9023/24/25, content-hash version + invalidate-on-save).
Gates: ruff + tsc + vitest 37/37; **attacks 78/78** (corpus +3 homoglyph/zero-width/benign); error-codes 211→217;
513 tests collect. AKS untouched; F-01 committed as the P1 checkpoint then the rest.

**SHIP (PR #1, merged → AKS):** `feat/console-f046-and-defect-remediation` merged via merge commit → main HEAD
**`e4a8158`**; build+deploy green; deployed api == `api-e4a81582…` (P-10 ✓). Follow-up issue **#2** (F-01 service-role
SVID residual). Post-deploy verification PASSED on P-10, safe-default config (`NRVQ_NO_POLICY_DECISION=deny`,
baselineClusterPolicy enabled), `/readyz`, F-01 live (viewer cross-ns→403, same/admin→200), unauth/forged→401 — **except**
one RED row: **a deny-storm signal**.

**DENY-STORM (found in post-deploy, fixed forward — PR #3):** with F-04 deny-default live, any agent class WITHOUT an
explicit policy hard-denied (`block/no_policy_loaded`) on AKS. Root cause: the helm `baselineClusterPolicy` catch-all is
synced under `norviq:baseline-cluster-guard-<ns>` (admin ns + policy-name), but the engine baseline fallback
(`evaluator._collect_candidates`) only resolves `<ns>:__baseline__` / `__cluster__:__baseline__` → the catch-all was
inert (masked by the old fail-open; unmasked by deny-default). The two live agent classes (customer-support, payments-bot)
have policies and were unaffected. **Fix (controller-only, PR #3 `feat/fix-baseline-wiring`, head `3645d07`):**
`buildPolicySyncPayload` keys a whole-namespace cluster baseline at `<targetNs>:__baseline__` at a **low fallback priority
(1)**, not its clusterPriority (900) — clusterPriority authorizes the cross-ns target but must not be the eval priority, or
a permissive strict-preset baseline @900 outranks+weakens a stricter specific policy (verified: at 900 prompt-injection
passed a policied class, attacks 42-failed). Delete path keys symmetrically. New code `NRVQ-WHK-4042`. No engine/precedence
change (cluster block-floor override preserved). Verified on kind: brand-new class→allow, injection vs policied class→block,
**attacks 78/78**, `go test ./webhook` + ruff + engine precedence (vs real DB) green. **PR #3 open — awaiting merge gate;
merge SHA + AKS re-verify TBD.**

---

## Prompt

```
ROLE: Remediate the defect-hunt findings for Norviq (repo: norviq-migration/repo). USE PLAN MODE —
present a staged fix plan (one stage per finding, hardest first), WAIT for approval, implement stage by
stage with a regression test per fix. Bring the security auditor for F-01, F-02, F-04. Read
.reviews/test-campaign/FINDINGS.md (the 5 findings + repros) first. Nothing may break the single-cluster
path, the SDK/sidecar hot path, the headless attack suite, or existing tests. Keep attacks 75/75. Do NOT
auto-commit — summarize per stage.

STAGE 1 — F-01 (P1): `/evaluate` cross-tenant BFLA — bind the evaluated namespace to the CALLER's
identity, not the client-supplied body. CRITICAL DUAL-CALLER NUANCE (do not regress the hot path):
  - `/evaluate` has TWO caller types:
      (a) the agent's own WORKLOAD/SERVICE credential (sidecar/SDK, role=service, or a SPIFFE-attested
          workload) — in production the namespace must derive from the ATTESTED workload identity, NOT
          the request body; a service/cluster-scoped principal may evaluate within its allowed scope.
      (b) a HUMAN token (admin/viewer) — enforce scoped_namespace(user, body.agent_identity.namespace):
          admin = any; non-admin → 403 on mismatch.
  - Preferred: namespace is IDENTITY-DERIVED (attested SVID ns / service principal's namespace claim);
    the body namespace is only honored when it matches the caller's authorized scope, else 403.
  - Must NOT break: the break-glass/service token used by the attack suite + redteam (cluster-scoped →
    allowed), and the SDK sidecar flow (caller = the agent's own identity).
  - Regression tests: viewer cross-namespace /evaluate → 403; same-namespace → 200; admin/service any → 200;
    confirm confused-deputy (user∩agent) holds once bound. Keep attacks 75/75.

STAGE 2 — F-04 (P2, PRODUCT DECISION): no-policy namespace currently fails OPEN (no matching policy →
allow). DECISION (locked): for a deny-by-default PEP, the no-policy fallback must DEFAULT TO DENY when
enforcement is enabled. Implement:
  - A configurable fallback (e.g. NRVQ_NO_POLICY_DECISION = deny|allow), DEFAULT = deny when a namespace
    has enforcement on; surface "namespace has no policy loaded" loudly (audit/log + a distinct rule_id).
  - Preserve the baselineClusterPolicy catch-all behavior; document the intended default explicitly in
    the registry. Verify a fresh fleet spoke (pre-first-bundle) now DENIES destructive tools, not allows.
  - Regression tests: ghost-ns destructive tool → deny; configured ns unaffected; attacks 75/75 (the
    attack namespaces have policies, so unaffected — confirm).

STAGE 3 — F-02 (P2): homoglyph/Unicode injection evasion. NFKC-normalize (+ confusable/skeleton fold)
tool_params strings BEFORE injection pattern matching (engine preprocessing or rego input prep). Don't
over-block legit Unicode content; normalize for MATCHING only, preserve original for audit.
  - Regression tests: Cyrillic-homoglyph "ignore previous…" → block (same as ASCII); benign Unicode text
    (e.g. legitimate non-Latin tool args) → not falsely blocked; attacks 75/75 + add the homoglyph case.

STAGE 4 — F-03 (P3): API-key auth hardening. Constant-time compare on the key hash (hmac.compare_digest,
api_keys.py), per-IP/per-prefix attempt throttle/backoff on nrvq_ auth, and audit repeated nrvq_ auth
failures (new NRVQ-* code). Regression tests: revoked/bogus key → 401; throttle trips after N; valid key
still works.

STAGE 5 — F-05 (P3): cache graph ANALYSIS output (summary/blast-radius/attack-paths/critical-paths/
chokepoints/analysis) per (namespace, graph-version) with a short TTL (mirror the existing 5-min snapshot
cache); add a per-request compute budget. Regression test: repeated analysis call served from cache;
cache invalidates on graph change.

GATES (per stage):
  - CLAUDE.md: update registry/{FEAT}.md + architecture .mmd where structure changes; new NRVQ-* codes in
    docs/error-codes.md. Namespace/RBAC consistent with the rest of the API; never monkeypatch get_session.
  - make lint + make test green; tsc + vitest green; **attacks 75/75** at the end of EVERY stage.
  - Re-verify each fix against its FINDINGS.md repro (the bug no longer reproduces); note it in the ledger.
  - Do NOT auto-commit; summarize per stage. Record this prompt + outcome in specs/prompts/ + index.
  - Honest labeling: which findings are fully closed vs partially mitigated; update FINDINGS.md status.
```
