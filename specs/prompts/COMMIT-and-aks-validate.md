# Prompt — Commit remediation + validate AKS deployment

**Date:** 2026-06-28
**Work item:** Commit the accumulated remediation (Tier A + close-out C1–C4 + R7 + eval harness/
reports + v2 install fixes), push to main (auto-triggers CI build+push → AKS deploy), and validate
the AKS cluster. Plan + PAUSE before pushing (push = auto prod deploy).
**Commit:** 7 commits `3d60dcb`→`9aad5fe` on main (6 thematic + 1 deploy hotfix) · **Result:** see below.

**Outcome (done, deployed + validated):** Committed the accumulated remediation in 6 thematic
commits + pushed to main; CI built 4 images and deployed to AKS. Two deploy issues surfaced and were
fixed live: (1) a pre-existing **unmanaged `norviq-sidecar-injector` MWC** blocked Helm adoption →
deleted the stale resource so Helm now owns it; (2) the **A2 alias fix exposed `dbSslMode=require`**
against the no-TLS in-cluster Postgres → API CrashLooped on "rejected SSL upgrade" → added
`config.dbSslMode: disable` to `values-aks-dev.yaml` (commit `9aad5fe`), redeployed green.

**Prod-secret + capacity (as planned):** `deploy.yml` now sets `api.secretKey` from the
`NRVQ_API_SECRET_KEY` repo secret + `config.requireStrongSecret=true`; the startup guard was hardened
to also reject empty/short keys. `values-aks-dev.yaml` right-sized for the saturated node
(api.replicas=1, PDB off, engine.replicas=0, webhook.replicas=1 + injection ON, trimmed OPA sidecar).

**AKS validation (live, source of truth):** deploy success (rev 60), **P-10 image SHA == HEAD**
(`api-9aad5fe…`); api **2/2** + OPA sidecar ready; `/healthz` 200, `/readyz` `{redis,db,opa:true}`,
`opaMode=server`. Security: unauth `/audit|/policies|/graph` → **401**; **token forged with the
default secret → 401** (deployed secret is 64-char rotated); rotated admin → 200; viewer DELETE/
cross-ns → **403**. Policy seeded via API (regex-cap fix), SQL-injection → block; **attack suite
75/75** against AKS; `/metrics` **155 `norviq_*`** lines.

**Injection on AKS — PARTIAL (honest):** the webhook **injects** the sidecar end-to-end
(`NRVQ-WHK-4003`, `norviq-sidecar` container + `norviq-socket` volume added), and the Helm-managed
MWC caBundle is populated by the (now-fixed) cert hook — BUT the injected sidecar **can't reach
Running**: `ErrImagePull` because `sanman97/norviq-engine` is **private** and **no imagePullSecret is
injected into the target namespace** (and the webhook injects `engine-latest`, not the `-sha`).
Separately, the webhook CRD controller's **policy-sync to the API now returns 401** (R8 side-effect —
it needs a service token). **Backlog:** inject `imagePullSecrets` + pin the `-sha` into injected pods
(or publish the image); give the webhook controller an API token; restore `engine.replicas`/HA once
the agentpool is scaled.

Two traps to handle in PHASE 1: (1) do NOT deploy the default JWT secret to AKS — A2's alias fix
means the chart secret is now read, so wire a real secret from GH Actions + requireStrongSecret=true;
(2) node capacity — single ~1-vCPU AKS node at ~97% CPU may not fit api.replicas=2 + OPA sidecars +
webhook → propose values-aks-dev overrides. AKS validation also closes the v2 gap (injected sidecar
*runtime* — real engine image available on AKS).

---

## Prompt

```
ROLE: Commit the accumulated remediation and validate the AKS deployment for Norviq
(repo: norviq-migration/repo). PLAN the commit + AKS secret/capacity strategy and PAUSE for approval
BEFORE pushing to main — pushing to main auto-triggers build.yml (build+push images) then deploy.yml
(helm upgrade to AKS). Do NOT push until I approve.

CONTEXT: the working tree holds all of Tier A + close-out (C1–C4) + R7 + the eval harness/specs/
reports + the v2 install fixes — all UNCOMMITTED. CI: .github/workflows/build.yml on push to main
builds engine/api/ui/webhook → pushes sanman97/norviq-engine:<component>-<sha> + -latest; deploy.yml
runs on that workflow's success → az aks get-credentials (rg-opsai-dev-eastus-001 / cluster norviq)
→ kubectl apply -f crds/ → helm upgrade --install norviq helm/norviq -n norviq -f values-aks-dev.yaml
with image tags pinned to the git SHA.

PHASE 1 — PLAN (present, then WAIT for approval):
  1. git status + git diff --stat. Propose a LOGICAL commit grouping (e.g. (a) security+config Tier A,
     (b) close-out C1–C4, (c) R7 OPA-server, (d) eval harness + specs/prompts + reports, (e) v2
     install fixes). Respect .gitignore; do NOT stage secrets/.env/.tmp/local artifacts. List exactly
     what each commit includes.
  2. PROD SECRET (critical — do NOT undo R8): with A2's alias fix the chart's api.secretKey is now
     actually read, so AKS must NOT deploy the default "change-me-in-production". Inspect
     values-aks-dev.yaml; wire api.secretKey + the Postgres/Redis passwords from GitHub Actions
     secrets (e.g. --set api.secretKey=${{ secrets.NRVQ_API_SECRET_KEY }} in deploy.yml) — NOT
     committed values — and set config.requireStrongSecret=true. Propose the exact deploy.yml /
     values-aks-dev.yaml change.
  3. NODE CAPACITY: the single ~1-vCPU AKS node ran ~97% CPU; api.replicas=2 + per-pod OPA sidecars +
     webhook (2 replicas) may not fit → Pending pods. Propose values-aks-dev overrides (right-size
     replicas/requests, or confirm node headroom / scale the pool) to avoid Pending.
  4. State the rollback (helm rollback / NRVQ_OPA_MODE=subprocess) if AKS validation fails.

PHASE 2 — COMMIT + PUSH (after approval): commit in the approved groups (no history rewrite); push to
main → triggers build.yml then deploy.yml. Monitor both to green.

PHASE 3 — VALIDATE AKS (live):
  - deploy.yml succeeded; pods Running; the deployed image SHA == HEAD (P-10 — confirm, don't assume).
  - /healthz + /readyz → 200; config.opaMode=server live; OPA sidecars Running.
  - Security spot-checks on the AKS API: unauth /audit|/policies|/graph → 401; token forged with the
    default secret → 401; real/rotated admin → 200; viewer DELETE policy → 403; viewer cross-ns → 403;
    sidecar fail-closed.
  - Attack baseline against the AKS API (AKS is source of truth — must hold >= baseline / 75).
  - /metrics exposes norviq_*.
  - INJECTION END-TO-END on AKS (real engine image is available here, unlike the kind harness — closes
    the v2 verification gap): label a ns norviq-injection=enabled, create a pod labeled norviq=enabled,
    confirm the sidecar is injected AND Running AND enforcing.

GUARDRAILS: never commit secrets; never deploy the default JWT secret to AKS; confirm deployed image
SHA == HEAD; report blockers honestly; on failure, helm rollback. Record this prompt + outcome in
specs/prompts/ and update the index.
```
