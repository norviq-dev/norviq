# Prompt — R11: independent adversarial sweep of the LIVE AKS deploy (post-release validation)

**Date:** 2026-07-01
**Context:** PR #12 shipped to AKS (main `0d3aef0`, helm rev 78) — the fleet-console overhaul + R1–R5 security
hardening + issue-#4 rego re-seed are now live. R11 is the independent, post-release adversarial validation of what is
actually running: does the shipped enforcement + hardened trust surface hold on the real cluster? This is authorized
defensive validation of San's OWN security product against its own deployment — source review + live read-only probing
+ evidence, not offensive tooling.
**Base branch:** new branch `chore/r11-aks-adversarial-sweep` off `main` (`0d3aef0`). Evidence-only; no product-code
change expected unless a finding is doable-in-scope (then fix it here, don't backlog).
**Gates:** plan mode · do NOT auto-commit · **NON-DESTRUCTIVE on AKS** (read-only `/evaluate` + reject-only probes
ONLY — the pytest harness teardowns DELETE policy rows, so DO NOT run them against AKS; `fleet-postgresql` untouched) ·
prove by EFFECT (the decision/rejection actually happens), never a 200 · record prompt + outcome in `specs/prompts/` +
index.
**Result:** done (local evidence-only, uncommitted) — Stage 1 generative lexical/unicode sweep under disposable
identity/class showed no allowed paraphrase bypass in the exercised corpus (136 cases; recall 1.000, precision 1.000,
false-block 0.000). Stage 2 reject controls passed for unauth 401, forged-default 401, viewer-mutation 403, and
F-40 reserved-scope 422; **R2 target-cluster mismatch 409 did not hold on live tested paths (HIGH finding)**.
R2-only confirmation pass (safety-redesigned with disposable/no-op payloads) proved mismatch was real (`served=fleet-c`,
`sent=fleet-c-mismatch-r11`) and enumerated all 11 intended mutation endpoints as missing 409 enforcement. Root cause
classified as deploy-integrity drift: main/source contains `require_target_cluster` + wiring, but the running AKS API
image did not include that source revision at runtime.
Deployed SHA observed as `ac50cda...`; trust-surface write-required controls kept as present-in-image + prior-kind/live
evidence split to avoid fleet DB writes. Report: `.reviews/live-pentest/R11-AKS-ADVERSARIAL.md`.

---

## Prompt

```
ROLE: Run R11 — independent adversarial validation of the LIVE Norviq AKS deployment (repo: norviq-migration/repo,
main 0d3aef0). This is authorized defensive testing of our OWN product against our OWN cluster. USE PLAN MODE; present
the plan, WAIT for approval, execute stage by stage. HARD SAFETY RULE: everything run against AKS must be
NON-DESTRUCTIVE — read-only /evaluate calls and reject-only control probes (a rejected request writes nothing). DO NOT
run the pytest attack suite (scripts/live-pentest/round2_audit.py etc.) against AKS — its teardowns delete policy rows
on the live cluster. Leave fleet-postgresql (the fleet/hub DB) completely untouched. Validation bar: prove the EFFECT
(the block/allow/rejection actually occurs), not a 200. Do NOT auto-commit — summarize per stage.

CONFIRM FIRST: the AKS target endpoint + a valid auth token (read-only where possible); the deployed image sha ==
current main HEAD (ac50cda at time of writing — code-identical to 0d3aef0 since; all changes since were docs/config
only, so enforcement is unchanged — but confirm the LIVE deployed sha, don't assume); which service is the app API
(/evaluate) vs the fleet-api. State the target before sending anything.

STAGE 1 — READ-ONLY adversarial /evaluate sweep with accuracy metrics (the core proof).
  - Build a NON-MUTATING evaluate driver (no policy writes, no teardown) that fires the full attack taxonomy at the
    live AKS /evaluate across the seeded sectors + baseline:
      * LLM01–LLM10 classes: prompt injection, insecure output, data exfiltration/export-egress, SoD/authorization
        bypass, PII leakage, SSRF/tool-abuse, excessive-agency, etc. — mapped to the sectors already seeded
        (finance SoD/export, healthcare PII, energy OT verbs, telecom CPNI, gov).
      * The issue-#4 unicode-evasion family explicitly: homoglyph, zero-width, fullwidth, combining-mark, mixed-script
        variants of known-blocked payloads (these are what the re-seed fixed — confirm they still block live).
      * LEXICAL/PHRASING variants (PRIORITY — a live spot-check on 2026-07-01 found "ignore all previous" ALLOWED
        while "ignore previous" BLOCKED, suggesting contiguous/exact-substring matching with trivial bypasses):
        systematically probe paraphrases of each known-blocked injection — insertions ("ignore ALL previous",
        "ignore the previous"), synonyms ("disregard/forget/override/skip prior/above/earlier instructions"),
        word-order + spacing + punctuation variants, split/obfuscated tokens. Any paraphrase of a blocked intent that
        ALLOWS is a real LLM01 false-negative → log severity + exact payload; if doable-in-scope, it becomes a
        Cursor-authored rego fix under the loop (do NOT dismiss as "malformed").
      * Benign controls per sector (must ALLOW) to measure false-block rate.
  - SCORE: recall (malicious → blocked), precision, false-block rate (benign → allowed), and per-class breakdown.
    Compare against the local/kind baseline (target parity with the 78/78 + company-sim recall). Every case logged
    with the decision + reason + rule_id from the live response.
  - OPTIONAL (if time/value): a small set of LLM-persona attacker turns (Sonnet) for realistic multi-step evasion,
    scored the same way — but the deterministic taxonomy sweep is the required core.

STAGE 2 — REJECT-ONLY security-control probes (no writes; each rejection proves the guard).
  - AuthZ/RBAC: unauthenticated → 401; viewer token → 403 on mutations + cross-namespace reads; forged/default-secret
    token → 401 (requireStrongSecret is on). These are attempts that MUST be denied → nothing persists.
  - R2 server backstop (the hardening just shipped): a cluster-scoped mutation carrying a MISMATCHED
    X-Nrvq-Target-Cluster → 409 (NRVQ-API-7460); absent/matching header → would-write, so DO NOT actually mutate —
    assert the 409 path only (mismatch) and the pre-check, not a real write.
  - F-40 reserved-scope push guard: a push targeting __baseline__/__pack__ → 422 (NRVQ-FLT-15023/15027). Reject-only.
  - Red-team endpoints gated (viewer → 403). Rate-limit/const-time behavior observed read-only where safe.
  - Produce a reject-matrix: probe → expected code → observed code → pass/fail. Any deviation is a finding.

STAGE 3 — Trust-surface presence check (verify the fix is DEPLOYED without writing the live fleet DB).
  - The R1 (console_url XSS validate-on-write) and R3 (join-token single-use TOCTOU) fixes require WRITES to exercise
    (heartbeat / join-token → fleet-postgresql). DO NOT write throwaway clusters into the live AKS fleet DB. Instead:
      * Confirm the DEPLOYED AKS image (0d3aef0) CONTAINS the R1–R5 code (verify by sha / inspect the running image or
        the deployed source), so the fixes are present in production.
      * RE-EXERCISE R1/R3 + rogue-spoke-isolation + compromised-hub-bundle-rejection on the LOCAL kind fleet (or cite
        the hardening-pass live proofs in REVIEW-FIXES-PR12.md), not on the shared AKS cluster.
  - State clearly in the report which controls were proven live-on-AKS (Stage 1–2, non-destructive) vs
    present-in-image + kind-exercised (Stage 3, to protect the shared fleet DB).

STAGE 4 — Console smoke (read-only) + evidence.
  - Load the live AKS console: Overview KPIs real, Catalog/Audit/Agents render with 0 app-console errors, the honest
    coverage headline + cluster posture show correctly. Screenshots.

FINDINGS + REPORT.
  - Any finding: if it's doable-in-scope, FIX it on this branch now (don't backlog) and re-verify; otherwise log it
    with severity + repro. Write .reviews/live-pentest/R11-AKS-ADVERSARIAL.md: the accuracy table (recall/precision/
    false-block + per-class), the reject-matrix, the Stage-3 present-vs-exercised split, console screenshots, and a
    clear GA-readiness verdict on the live deploy.

GATES:
  - NON-DESTRUCTIVE on AKS (read-only /evaluate + reject-only); fleet-postgresql untouched; no pytest teardown suite
    against AKS. ruff/opa/tsc clean if any code touched. Do NOT auto-commit — summarize per stage. Record this prompt
    + outcome in specs/prompts/ + index; deliverable R11-AKS-ADVERSARIAL.md.
```
