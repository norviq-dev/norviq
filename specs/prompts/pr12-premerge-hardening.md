# Prompt — PR #12 pre-merge hardening (security-review findings R1…R5)

**Date:** 2026-06-30
**Source:** consolidated security review of PR #12 (`feat/fleet-console-overhaul`, 1632f47). Merge verdict was
**merge-after-fixes** — 2×P1 blockers + 1×P2 + 2×P3, all in the NEW fleet cross-trust surface. Core (pack-weaken
floor, secrets/PII, single-cluster hot path, SQLi, endpoint auth) reviewed CLEAN. Fix these on the SAME branch so
PR #12 merges clean; this is the pre-AKS gate.
**Base branch:** CONTINUE ON `feat/fleet-console-overhaul` (do not start a new branch — these land in PR #12).
**Gates:** plan mode · do NOT auto-commit · attacks 75/75 on any engine/API stage · tsc+vitest green · AKS untouched
(local kind) · **security auditor on R1 + R2** · validation rule: prove the EFFECT (exploit blocked), not a 200.
**Result:** **DONE (2026-06-30, on `feat/fleet-console-overhaul` / PR #12; not committed).** All 5 fixed with a
regression test + a live proof. **R1** `console_url` XSS — `HeartbeatBody` blanks non-http(s) on write
(`NRVQ-FLT-15040`) + `RemoteClusterNotice` renders a link only for http(s); **live: `javascript:` heartbeat stored
`""`, `https://` preserved.** **R2** server backstop `require_target_cluster` (`NRVQ-API-7460`, 409) on 11
config-mutation endpoints (`/evaluate` excluded — hot path) + UI `X-Nrvq-Target-Cluster`; **live curl mismatch → 409,
match/absent → 200; attacks 78/78.** **R3** atomic conditional UPDATE (`WHERE claimed=false`, rowcount) → double-claim
409. **R4** `remove_cluster` deletes `UsedJoinToken`. **R5** reusable OIDC-preferring `fleet_service_bearer` for the
enroll claim (HS256 only when legacy). Gates: attacks 78/78, vitest 73/73, offline backend 97, opa/ruff/tsc clean;
docs corrected (guard = UI + server; console_url validated; OIDC enrollment). See `REVIEW-FIXES-PR12.md`.

---

## Prompt

```
ROLE: Pre-merge hardening of PR #12 (feat/fleet-console-overhaul) for Norviq (repo: norviq-migration/repo) —
fix the security-review findings R1…R5. USE PLAN MODE; present the plan, WAIT for approval, implement per finding
with a regression test + a live proof (the exploit is actually blocked, not a 200). Security auditor on R1 + R2.
CONTINUE ON branch feat/fleet-console-overhaul (these fixes belong in PR #12). Nothing may break the single-cluster
path, the SDK/sidecar hot path, fleet enforcement/retract, packs/compose, or existing tests. attacks 75/75 around
any engine/API stage. Do NOT auto-commit — summarize per finding.

R1 — P1: stored XSS via spoke-reported console_url (security auditor).
  - A spoke self-reports console_url in its heartbeat (scoped_cluster/service token); the hub stores it
    (fleet/models.py Cluster.console_url) and the UI renders it into <a href={consoleUrl}> in
    ui/src/components/common/RemoteClusterNotice.tsx (~:23) with NO scheme validation → a malicious spoke can set
    `javascript:...` and XSS a HUB ADMIN who clicks "Open console" (spoke→hub-admin priv-esc across trust boundary).
  - FIX both ends: (a) VALIDATE ON WRITE — the heartbeat/ingest handler (norviq/fleet/ingest.py + schemas.py
    HeartbeatBody.console_url) rejects/strips any console_url whose scheme is not http/https; (b) DEFENSE ON RENDER —
    RemoteClusterNotice only uses the href if it matches /^https?:\/\//i, else render as inert text/no-link.
  - PROVE: a heartbeat with console_url="javascript:alert(1)" is rejected/sanitized on write AND the UI never emits a
    javascript: href (test both). A normal http(s) console_url still deep-links. Regression tests both sides.

R2 — P1: cluster mutation guard is UI-only — add a server-side backstop (security auditor).
  - Today clusterGuard/apiSend block cluster-scoped mutations in the BROWSER only; the API has no "selected cluster"
    concept, so a token holder bypassing the SPA can mutate the served (local) cluster regardless of the UI label.
  - FIX (server backstop): the SPA sends the intended target cluster on cluster-scoped MUTATIONS (e.g. header
    `X-Nrvq-Target-Cluster`); the API rejects with a clear 4xx + NRVQ code when that target != the served cluster_id
    (from cluster-info / config). Keep the existing UI guard as the first line. (This is the real backstop the F-69
    framing promised.) Update the F-69 docs/registry so the guard is described accurately (UI guard + server check).
  - PROVE: a direct API mutation (curl, no SPA) carrying a mismatched target-cluster header → rejected; matching (or
    absent → treated as local) → works; the UI still blocks in-browser. Regression test the server rejection.

R3 — P2: join-token single-use TOCTOU. `claim_join_token` (norviq/fleet/fleet.py) does check-then-set on
  UsedJoinToken.claimed → two concurrent claims can both succeed. FIX: make the claim an atomic conditional UPDATE
  (`UPDATE used_join_token SET claimed=true WHERE jti=:jti AND claimed=false`, act on rowcount) or SELECT ... FOR
  UPDATE. Test: concurrent double-claim of one jti → exactly one succeeds, the other 409.

R4 — P3: remove_cluster leaks UsedJoinToken rows. `remove_cluster` deletes Cluster/rollups/rollout but not the
  cluster's UsedJoinToken rows. FIX: delete them on removal (and/or add a TTL prune of expired rows). Test: remove →
  the cluster's join-token rows are gone.

R5 — P3: OIDC-only enrollment HS256 gap. fleet_enroll mints an HS256 service token; a hardened hub with
  legacy_hs256_enabled=false will 401 the claim. FIX: in OIDC mode use the spoke's OIDC client-credentials token for
  the claim (fall back to HS256 only when legacy enabled); or, if out of scope, DOCUMENT the dependency explicitly
  in fleet-enrollment.md. Recommend the real fix; confirm.

GATES:
  - ruff + make test + opa check green; tsc + vitest green; new/updated NRVQ-* codes in docs/error-codes.md; F-69 +
    fleet-enrollment docs corrected (guard is UI + server; console_url validated). attacks 75/75 start/end of any
    engine/API stage. AKS untouched.
  - Prove each by EFFECT (R1 the javascript: href is gone; R2 the direct-API cross-cluster mutation is server-
    rejected; R3 concurrent claim → one wins) + screenshots where UI. Commit onto feat/fleet-console-overhaul so
    PR #12 carries the fixes. Do NOT auto-commit until I say; summarize per finding. Append to a REVIEW-FIXES note +
    record this prompt in specs/prompts/ + index.
```
