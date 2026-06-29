# Prompt — Intensive local multi-cluster DEFECT HUNT (5 kind clusters, role-based, all layers)

**Date:** 2026-06-29
**Work item:** Stand up ~5 local kind clusters with a rich synthetic dataset, then drive every use case ×
role × scenario (incl. adversarial/chaos) across frontend / API / engine-middle / DB / fleet / identity /
infra to surface EVERY bug. Plan mode (staged); QA + security-auditor mindset; role-based scout personas.
**Design source:** `.reviews/test-campaign/RECON.md` (product map, threat model, per-layer seeds, weak spots).
**FEAT:** all (esp. F007/F017/F018/F026/F027/F033/F036/F037/F041/F045/F046). **Docker:** 12 GB. **AKS:** untouched (local-only).
**Commit:** do NOT auto-commit · **Deliverable:** triaged bug ledger + coverage matrix + campaign report.
**Result (pass 1, uncommitted):** Built durable harness `scripts/test-campaign/` (`00-up.sh` PHASE=A|B|C, `lib.sh`
persona tokens, `seed_campaign.py` multi-tenant API seed, `20-run.sh` probes, `99-down.sh`, `values-campaign.yaml`
right-sized) + ran **Phase A** live (single kind cluster `nv-a`, working-tree `api-campaign` image incl. uncommitted
F046, ~1 GiB). Seeded 6 policies / 7 agents (incl. frozen) / 32 decisions. **5 findings** → FINDINGS.md: **F-01 P1**
`/evaluate` not namespace-scoped (cross-tenant BFLA, live-reproduced — reads ARE scoped, the hot path isn't);
**F-02 P2** homoglyph injection evasion (no NFKC); **F-04 P2** no-policy namespace fails open; **F-03 P3** no API-key
auth throttle + non-constant-time compare; **F-05 P3** graph analysis uncached. Verified-correct: viewer write/trust/
keys 403, cross-ns read 403, client trust_score ignored, pagination 422, audit completeness, **attacks 75/75**
(start+end). **Phase B** (identity, `kind-norviq-identity`: Keycloak+SPIRE, oidc-on/workload-api): group→role/ns
mapping correct (alice=admin, bob=viewer/team-a); OIDC forge probes ALL rejected — alg:none, off-allowlist,
**alg-confusion (HS256 w/ RS256 pubkey)**, wrong-secret, expired → 401; break-glass HS256 → 200; JWKS unknown-kid
storm → all 401; api-key admin-only + scoped principal under OIDC; **F-01 reconfirmed as confused-deputy** with bob's
real token. **Phase C** (fleet 1-hub+2-spoke `fleet-a/b/c`, working-tree image, right-sized): hub aggregates all 3;
signed push applies+ENFORCES; **hub-down fail-safe** holds; cross-cluster + **rogue-spoke isolation** 403; residency
drill-down blocked; **attacks 75/75** on a spoke; reinforces F-04 (fresh spoke fail-open until first bundle). Net:
**5 findings (1 P1, 2 P2, 2 P3)** + ~20 controls verified-correct across all layers; auth/fleet surfaces solid; the
clear bug is F-01. All 3 phases torn down (memory freed); AKS untouched. SEED-MANIFEST/COVERAGE/REPORT in `.reviews/test-campaign/`.

This is a DEFECT HUNT, not a scored eval. Output = bugs found, triaged, with repro — across all layers.
Also closes the two UI-cleanup residuals (live attacks 75/75; live browser route capture).

---

## Prompt

```
ROLE: Intensive LOCAL multi-cluster DEFECT HUNT for Norviq (repo: norviq-migration/repo). USE PLAN MODE
— propose the staged plan (environment → synthetic seed → scenario matrix → adversarial/chaos → triage),
WAIT for approval, execute stage by stage. Bring a QA + security-auditor mindset and ROLE-BASED SCOUT
personas that drive the product like real users (API + the console UI). GOAL: find EVERY bug across
frontend, API, engine/middle-layer, DB, fleet, identity, and infra. Read .reviews/test-campaign/RECON.md
first — it has the product map, threat model, per-layer test seeds (§5), highest-leverage families (§6),
and Norviq-specific weak spots (§7). This is NOT a scored eval; the output is a triaged BUG LEDGER with
reproductions. AKS is untouched — local kind only. Do NOT auto-commit. Keep the attack baseline at 75/75.

=== STAGE 1: ENVIRONMENT (≈5 kind clusters, 12 GB-aware) ===
Reuse/extend the existing harnesses (scripts/eval, scripts/identity-local, scripts/fleet-local) into a new
scripts/test-campaign/ (00-up / 10-seed / 20-run / 30-report / 99-down). Propose a topology that FITS 12 GB
(kind control planes are cheap but each Norviq stack is heavy) — e.g. 1 fleet HUB + 4 spokes, right-sized
(replicas=1, small requests, OPA server single, HA operators off), and STAGGER heavy scenarios rather than
running 5 identical full stacks at once. Verify memory headroom before proceeding. Enable the gated features
ON for the hunt (this is where we want bugs to show): OIDC (Keycloak), SPIRE workload-api, OPA server mode,
fleet hub+spokes, SIEM forwarder, API-keys auth — AND spot-check each feature's OFF state still works.
Clusters labeled env=prod/staging/dev; ONE spoke residency-flagged.

=== STAGE 2: SYNTHETIC SEED (exhaustive — a SEED MANIFEST is required so nothing is missed) ===
Build a realistic, named, multi-tenant dataset and record it in .reviews/test-campaign/SEED-MANIFEST.md
(entity type → count → identifiers/personas → which scenarios it feeds). Seed ALL of the following:

  USERS / IDENTITIES (Keycloak realm + group mappings + API keys + break-glass):
   - alice  — global ADMIN (group norviq-admins → role=admin, cluster=*)
   - dave   — SecOps admin scoped to ONE cluster (cluster-scope test)
   - bob    — VIEWER, namespace team-a @ cluster fleet-a
   - carol  — VIEWER, namespace payments @ cluster fleet-b (cross-cluster/ns denial test)
   - erin   — compliance/AUDITOR (read audit only)
   - frank  — UNMAPPED user (→ viewer floor) ; gwen — CONFLICTING groups (→ fail closed)
   - svc-webhook — SERVICE identity (OIDC client-credentials / role=service)
   - break-glass HS256 token (CI/attacks headless)
   - API KEYS (new F046): an admin-issued active key, a VIEWER-scoped key, and a REVOKED key
     (verify nrvq_ auth fires only on JWT failure, revoke is immediate, hash-only, no escalation)

  AGENTS (SPIFFE workloads across namespaces/classes/trust tiers/clusters):
   - well-behaved HIGH-trust agent (chatbot-prod) ; a LOW-trust agent ; an admin-FROZEN agent
   - "boiling-frog" agent that slowly inflates its baseline (HIGH-1 baseline-poisoning probe)
   - SPOOFING agent setting bogus NRVQ_NAMESPACE/NRVQ_SERVICE_ACCOUNT (must be IGNORED in workload-api)
   - UNREGISTERED agent (no SVID → fail-closed) ; agents spread across ≥4 namespaces and ≥3 clusters
   - enough class/tier variety to populate the trust-distribution donut + agent insights

  POLICIES (catalog across OWASP-LLM categories, namespaces, targets, decisions):
   - allow read-only tools ; BLOCK destructive (delete_record/drop_table) ; BLOCK exfil sinks
     (outbound email to non-corp, large DB reads) ; ESCALATE high-impact (DELETE/payments → human-in-loop)
   - AUDIT-only sensitive read ; PII / base64 / injection / unicode rules (the attack baseline)
   - per-namespace policies (ns-scoping) ; target bindings (agent class / tool / namespace)
   - a FLEET-distributed SIGNED policy (env=prod selector) + a per-cluster OVERRIDE on one spoke

  SUPPORTING DATA (so every console widget + endpoint has real data):
   - tool catalog / MCP servers ; deployments (/deployments) ; connections (/readyz) ; targets ; settings override ; version
   - asset graph + attack paths (agents↔tools↔data↔namespace) ; MITRE coverage ; red-team runs (F041)
   - fleet: clusters registered + heartbeating, agent/audit ROLLUPS, a signed bundle pushed with rollout
     states (pending/applied), residency-flagged spoke (rollup-only)

  TRAFFIC (generators producing decisions over a TIME RANGE across namespaces + clusters):
   - benign ALLOW volume (populate Dashboard volume/trends, tool-usage, trust-history over 1h/24h/7d)
   - BLOCK volume (top-blocked tools) ; ESCALATE ; AUDIT-only
   - the 75 ATTACK cases run LIVE → assert 75/75 (closes UI residual #1) ; PII/base64/injection/unicode variants
   - concurrency bursts (50/100) for latency + HA behavior

=== STAGE 3: SCENARIO MATRIX (role × use-case × layer) — drive via API AND the console ===
Run scout personas through their real workflows end to end, recording pass/fail + a finding for every defect:
  - SecOps(alice/dave): author policy → dry-run → enforce → see block → investigate audit → MITRE coverage → quarantine.
  - Platform: deploy enforcement; SPIFFE attestation; fleet hub→spoke signed push; detect drift; rollout status.
  - AI/ML: register tool; request scope; test policy before enforce.
  - Compliance(erin): pull audit report; verify every decision logs identity+rule+action+outcome; residency.
  - Viewer(bob/carol): confirm RBAC — cross-namespace/cross-cluster reads + admin verbs → 403; controls hidden.
  - Attacker: the per-layer adversarial seeds below.
Cover every console route (live browser network capture → finalize .reviews/ui-cleanup/ROUTES.md, closing UI
residual #2) and every API route.

=== STAGE 4: ADVERSARIAL / CHAOS (RECON §5–§7) — the bug-rich part ===
Execute the negative/chaos seeds from RECON.md §5 per layer and prioritize §6 highest-leverage families +
§7 Norviq weak spots. Minimum must-run set:
  - ENFORCE: no-rule→deny; conflicting rules; OPA subprocess↔server parity + fail-closed on OPA down;
    injection NFKC + base64-decode depth; policy hot-reload across pods.
  - TRUST: baseline poisoning (boiling-frog); Redis-down posture; cache-hit stale-trust fields; freeze/reset RBAC.
  - IDENTITY: OIDC alg:none / RS256→HS256 / jku/kid injection / JWKS stale-cache + unknown-kid storm / aud/iss/exp;
    SPIFFE env-spoof ignored + socket-down fail-closed; confused-deputy (user∩agent scope); API-key revoke/escalation.
  - API/RBAC: /evaluate namespace identity-bound (not client-supplied); BOLA/IDOR cross-tenant; mass-assignment;
    SSRF (webhook/cluster calls); SQLi/ReDoS/log-injection; rate-limit bypass; pagination; WS reconnect/replay/expiry.
  - DB: migration lock/concurrent-migrators; lost-update/serialization/deadlock retry; pool exhaustion + restart herd.
  - FLEET: tampered/unsigned/wrong-key/expired/REPLAY-older-version/compromised-hub-allow-all → all rejected, last-good
    kept; hub-down fail-safe (attacks still block); drift staleness loud; viewer push 403; cross-cluster 403;
    residency no raw egress; rogue spoke can't read another's data.
  - INFRA: webhook fail-open/closed + cert rotation + self-deadlock exclusion; readiness-vs-liveness restart safety;
    HA failover (if enabled).

=== STAGE 5: TRIAGE + DELIVERABLES ===
  - BUG LEDGER → .reviews/test-campaign/FINDINGS.md: one row per defect — ID, severity (P0/P1/P2/P3), layer,
    scenario, REPRO steps, evidence (logs/NRVQ codes/screens), root-cause hypothesis, suggested fix.
  - COVERAGE MATRIX → .reviews/test-campaign/COVERAGE.md: scenario × result (pass/fail/blocked), proving the
    matrix + SEED MANIFEST were fully exercised; list anything not reached and why.
  - CAMPAIGN REPORT → .reviews/test-campaign/REPORT.md: summary, severity counts, top risks, themes, recommendation.
  - Fix-on-the-fly ONLY trivial/safe issues (note them); everything else is LOGGED, not fixed, in this pass
    (a remediation pass follows). Re-run attacks LIVE → 75/75.

GATES:
  - Local kind only; AKS untouched. 12 GB-aware (stagger/right-size). Reuse existing harness patterns.
  - Do NOT auto-commit. Summarize per stage. Record this prompt + outcome in specs/prompts/ + index.
  - The SEED MANIFEST + COVERAGE MATRIX are the "miss-nothing" contract — every product entity seeded,
    every RECON §5–§7 seed exercised or explicitly deferred with reason.
```
