# Prompt — Close out bounded report findings (base64, webhook TLS, RBAC bindings, SIEM export)

**Date:** 2026-06-28
**Work item:** Finish the remaining BOUNDED customer-eval findings not done in Tier A. Plan mode
first, then implement. Excludes OPA-as-server (R7) and the R3/R4 epics (separate prompts).
**Depends on:** [EVAL-remediation.md](EVAL-remediation.md) (Tier A done).
**Commit:** (uncommitted — per instruction, no auto-commit)
**Result:** All four implemented (C2 = helm-hook only, per the testing-phase gate). **C1** base64
decode+rescan in `comprehensive.rego` (`base64_decoded_threat`, block; benign base64 stays audit —
verified no FP via `opa eval`); **attacks 75/75** (was 72; +3 cases), 0 xfail/skip. **C2** turnkey
webhook TLS: chart-native `MutatingWebhookConfiguration` + pre/post-install cert hook Job + scoped
RBAC (gated `webhook.injection.enabled`). **C3** `rbac-bindings.yaml` (gated) + `docs/engineering/
production-config.md` (linked from ops guide). **C4** streamed `GET /api/v1/audit/export?format=
ndjson|csv` (`NRVQ-API-7024`, keyset-paged, auth + ns-scoped) + `norviq/api/siem.py` `AuditForwarder`
stub (gated, `NRVQ-SIEM-14000/14001/14002`). Verify: `make lint` clean; `make test` 387 passed / 6
pre-existing fail (same set as Tier-A — local seed/identity + non-idempotent crud; not regressions)
/ 1 skip; vitest 37/37; tsc clean; `helm lint` clean + `helm template` renders each gate flag. Live:
export unauth 401 / admin ndjson+csv 200 / viewer cross-ns 403; base64-injection blocks. New codes
registered in `docs/error-codes.md`. **No commit.**

Items: C1 base64 payloads → safe (decode + re-scan, no new FP) (R2); C2 webhook TLS bootstrap — DEFAULT
self-contained Helm certgen hook (zero-touch install), optional cert-manager flag (R1); C3 RBAC
subject-binding examples + prod-config checklist doc (P2-14); C4 SIEM export — authed NDJSON/CSV +
syslog/webhook forwarder (R5).

Sequence context (full completion plan): this close-out → OPA-as-server (R7) → **v2 simulation** →
SSO/OIDC epic (R4) → multi-cluster fleet epic (R3) → **final simulation**.

---

## Prompt

```
ROLE: Close out the remaining BOUNDED customer-eval findings for Norviq (repo: norviq-migration/repo).
USE PLAN MODE FIRST — present a plan, wait for approval, then implement. Do NOT attempt OPA-as-server
(R7) or the R3/R4 epics here — those are separate prompts.

INPUTS: .reviews/customer-eval/REPORT.md + findings/*-scout.md (and REPORT-v2 if present).

ITEMS (plan each with files touched, tests added/updated, rollback risk):
  C1 Base64 payloads (R2): today base64-looking params only `audit` (proceed). Make them safe —
     decode base64 in tool_params and RE-SCAN the decoded text against the injection/SQL/PII rules
     (preferred), or escalate/block. MUST NOT raise false positives on legitimate base64 (e.g. a
     normal token/ID) — add both a blocked-malicious and an allowed-benign attack test.
  C2 Webhook TLS bootstrap (R1) — ZERO human intervention on `helm install` (hard requirement):
     DEFAULT to a self-contained Helm pre-install+pre-upgrade HOOK Job (kube-webhook-certgen or an
     openssl script) that generates a CA + server cert for norviq-webhook.norviq.svc, creates the
     norviq-webhook-tls Secret, and patches the MutatingWebhookConfiguration caBundle. Give the Job
     its own ServiceAccount + least-privilege Role (create/update that Secret) + ClusterRole (patch
     mutatingwebhookconfigurations); use a long cert expiry (re-issued on upgrade) so there is no
     renewal step. Add an OPTIONAL `webhook.certManager.enabled` flag that instead emits a
     cert-manager Certificate + ca-injector annotation for orgs that already run cert-manager. Net: a
     bare `helm install` brings up working sidecar injection with no manual steps. Document both paths.
     (Follow-up: once this lands, enable webhook.enabled in scripts/eval/values-local.yaml so the
     next simulation validates injection end-to-end.)
  C3 RBAC bindings + prod-config doc (P2-14): ship example bindings mapping the shipped norviq-admin/
     -policy-editor/-viewer ClusterRoles to subjects/groups; add a prod-config checklist doc that
     names secret rotation + the (now-fixed) alias wiring.
  C4 SIEM export (R5): authenticated, namespace-scoped GET /api/v1/audit/export?format=ndjson|csv
     (streamed); plus a webhook/syslog forwarder stub with config. Add OpenAPI + tests.

GATES (after plan approval, implement):
  - CLAUDE.md gates: update architecture/{FEAT}.*.mmd + registry/{FEAT}.md + tests (allow/block/error;
    assert rule_id; never monkeypatch get_session) for changed features. New NRVQ-* codes registered in
    docs/error-codes.md.
  - Keep the attack baseline GREEN (now 72/72, 0 xfail/skip) — re-run after every production change;
    C1 must not drop it or add false positives.
  - Run make lint + make test + vitest + tsc; do NOT auto-commit; summarize results.
  - Record this prompt + outcome in specs/prompts/ and update the index.
```

## C2 testing-phase gate (approved — verify these at test, not implementation)
Decision: **Helm pre-install hook ONLY** (no cert-manager). Check at testing:
1. Hook lifecycle: Job + RBAC annotated `pre-install,pre-upgrade` with
   `hook-delete-policy: before-hook-creation,hook-succeeded`; Secret exists before the webhook
   Deployment is created.
2. Least-privilege RBAC: Job SA limited to create/update/get the `norviq-webhook-tls` Secret and
   get/patch the specific MutatingWebhookConfiguration (resourceNames-pinned).
3. Cert SANs: `norviq-webhook.<ns>.svc` (+ `.svc.cluster.local`), serverAuth, ~10y expiry.
4. caBundle actually populated on the MutatingWebhookConfiguration post-install.
5. Hook image is pullable on a bare cluster (or certgen uses an image already in the chart).
6. `failurePolicy` decision is explicit (Ignore vs Fail), not silently bundled into C2.

**R1 proof:** fresh `helm install` on kind → webhook pod Ready, `norviq-webhook-tls` present,
caBundle populated, a pod labeled `norviq=enabled` gets the sidecar injected.
Follow-up: then set `webhook.enabled: true` in `scripts/eval/values-local.yaml` so the next
simulation validates injection end-to-end.
