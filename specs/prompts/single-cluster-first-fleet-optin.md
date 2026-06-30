# Prompt — Single-cluster-first + fleet opt-in (join-token enrollment) + UI dedup F-59…F-65

**Date:** 2026-06-30
**Decision (San):** Keep multi-cluster, but make SINGLE-CLUSTER the clean default ("install & get going", zero fleet
surface when off); multi-cluster becomes an OPT-IN mode; replace Helm-`--set` hub/spoke enrollment with a
hub-minted **join-token** flow + an explicit **remove cluster** action. Fold in the live UI findings (dup cluster
selector, invisible push form, coverage-chart dup, risk-number hierarchy, IA/naming).
**Base branch:** new branch `feat/single-cluster-first-fleet-optin` off `feat/ui-quality-f52-f58` (latest UI).
**Gates:** plan mode · do NOT auto-commit · attacks 75/75 on any engine/API stage · tsc+vitest green · AKS untouched
(local kind) · security auditor on Stage 4 (token issuance / trust bootstrap) · **validation rule: prove the effect,
not a 200** (end-to-end + open/close + before/after screenshots).
**Result:** **DONE (2026-06-30, `feat/single-cluster-first`).** All 5 stages, each proven by effect + open/close +
screenshots. **S1** single-cluster is the clean default — `fleetEnabled` gates the Header cluster pill + `/fleet`
redirect; **also fixed a real defect: the ui nginx hard-referenced norviq-fleet-api and crash-looped on a spoke** —
the entrypoint now emits the `/fleet-api` proxy only when `FLEET_API_URL` is set; live: fleet-off console = 12 routes,
**0 fleet words**. **S2 (F-59)** one selector (global nav switcher); removed the page-level Fleet selector; live:
switch repoints in place. **S3 (F-60)** real labeled push form (`.input`+labels+btn), unified "Push signed policy";
live: clean enforcing push. **S4** join-token enrollment replaces Helm `--set` wiring — hub mint (single-use, scoped,
short-lived, pubkey-in-token; key never leaves) + spoke `/fleet/join` (durable `FleetJoinState`, live relay/puller) +
`norviq fleet join/leave/status` CLI + `DELETE /fleet/clusters/{id}` + UI Add/Remove; **live e2e: leave→pushed policy
ignored→join→enforces@8s→remove+leave→sheds+drops from hub→RESTART→still allow**; security: replay 409 / expired 422 /
garbage 422 / scoped; attacks 75/75. **S5** F-61 dup coverage removed, F-63 honest "Policy Coverage" headline (was
coverage% mislabeled "Security Score/High Risk"), F-64 Overview un-buried + Fleet→Security Operations. Gates: opa 139,
parity 13, tsc, vitest 50, ruff; **0 new regressions** (+12 new passing). Codes NRVQ-FLT-15030..15035. Doc
`docs/engineering/fleet-enrollment.md`. AKS untouched. See `CLOSEOUT-SINGLE-CLUSTER-FIRST.md`.
**Post-validation (San live-review):** **F-66** dup "All namespaces" (cluster-info returned the reserved `"all"`
wildcard → collided with the selector sentinel; backend `discard("all")` + UI dedupe) and **F-67** stagnant Overview
on cluster switch (now **cluster-aware**: KPIs+Trust from hub rollups for a remote cluster, hub-less panels honestly
scoped, `servedCluster` added) — both fixed + proven live (fleet-b → `[13/9/69%/—]`, back-to-local restores, spoke
single-cluster intact); attacks 78/78, cluster-info test 5/5, all clusters healthy.

---

## Prompt

```
ROLE: Implement "single-cluster-first + fleet opt-in" for Norviq (repo: norviq-migration/repo). USE PLAN MODE —
present the staged plan, WAIT for approval, implement stage by stage. Goal: the DEFAULT product is single-cluster,
install-and-go, with NO fleet/hub/spoke concepts visible; multi-cluster is an opt-in mode whose onboarding is a
join-token flow, not Helm-flag wiring. Keep all existing fleet capability (it works + is tested) — hide it when off,
smooth it when on. VALIDATION BAR: a 200 is not proof — demonstrate end-to-end effect + interaction state (open AND
close) + before/after screenshots on the running kind fleet. Security auditor on Stage 4. Base a NEW branch on
feat/ui-quality-f52-f58. Nothing may break the single-cluster path, SDK/sidecar hot path, the fleet enforcement/
retract path, packs/compose, or existing tests. attacks 75/75 around any engine/API stage. Do NOT auto-commit.

STAGE 1 — Single-cluster is the CLEAN default (hide ALL fleet surface when fleet.enabled=false).
  - When fleet is OFF: the console shows ZERO fleet concepts — no cluster selector anywhere (global chrome shows
    NAMESPACE only, no cluster pill), no Fleet nav item, no hub/spoke vocabulary, no "viewing local cluster" notice.
    It must look and read like a single-cluster product.
  - Verify on a single-cluster install (fleet off): walk every route — no fleet references appear; every page works.
    Before/after screenshots.

STAGE 2 — Fleet as opt-in + collapse the duplicate selector (F-59).
  - When fleet.enabled=TRUE: exactly ONE cluster selector — the global nav dropdown — and the Fleet view reacts to
    it. REMOVE the page-level top-right "Cluster:" dropdown added in F-57; no force-navigation to /fleet on change.
    Fleet nav item appears only in fleet mode. Namespace stays global in both modes.
  - Verify (fleet on): one selector; switching cluster updates the fleet view in place; no dup control.

STAGE 3 — Push-policy form is a REAL, visible form (F-60).
  - The "Push signed policy" fields (policy name, namespace, agent_class, target, confirm-fleet-wide) currently
    render as plain text with no input affordance. Make them real inputs: visible borders/background, labels ABOVE
    the fields, focus states; keep the Monaco rego editor. Prove a human can see, fill, and push from the UI
    (screenshot the filled form + a successful single-cluster push that enforces).

STAGE 4 — Join-token enrollment + remove (the onboarding redesign; security auditor).
  - Replace per-spoke Helm-`--set` wiring (apiUrl/bundlePubkey/signingKey by hand) with a JOIN-TOKEN flow:
      * Hub install stays a one-time choice (fleet.hub.enabled=true). On the hub, an "Add cluster" action MINTS a
        short-lived, scoped JOIN TOKEN that carries the hub endpoint + the signing PUBLIC key (trust root) + scoped
        relay auth. Surface it in the Fleet UI as a copyable join command.
      * A spoke installs PLAIN (single-cluster default), then ENROLLS with one action — `norviq fleet join <token>`
        (CLI/one-shot) — which sets apiUrl/bundlePubkey/identity from the token and registers. No hand-edited Helm
        values per spoke.
      * Add an explicit REMOVE/deregister action (UI + API) — today removal is only implicit "stale" (F-65). Remove
        deregisters at the hub AND stops the spoke pulling (reuse the F-52 retract/reconcile machinery so it's clean
        across restart).
  - Security (auditor): token short-lived + scoped + single-use where feasible; trust pubkey delivered via token,
    not blindly; relay auth provisioned by the token; joining a wrong/expired token is rejected.
  - Verify END-TO-END on the kind fleet: a fresh spoke joins via token → appears in the hub cluster table →
    pull works → a pushed policy enforces on it → REMOVE → it deregisters + stops enforcing the pushed policy
    (across a pod restart). attacks 75/75; comprehensive intact elsewhere.

STAGE 5 — Console IA / dedup polish (F-61, F-63, F-64).
  - F-61: "Policy Coverage by Category" renders on BOTH Overview and Policy Catalog — keep ONE canonical home
    (Overview) or clearly differentiate; no duplicate viz.
  - F-63: Overview has competing risk numbers (Security Score 37 / Block Rate 62% / Trust donut) — establish ONE
    headline verdict with the rest clearly supporting; a business user should get "am I secure?" at a glance.
  - F-64: naming/IA — make "Push signed policy"/"Push policy" consistent; the home Dashboard should not be buried
    under a section called "Intelligence"; Fleet (when shown) belongs in an ops/management section, not Analytics.
  - tsc+vitest; before/after screenshots.

GATES (per stage):
  - ruff + make test + opa check green; tsc + vitest green; new NRVQ-* codes in docs/error-codes.md; registry/
    architecture + the Helm values docs updated (document: single-cluster default, fleet opt-in, join-token + remove).
  - attacks 75/75 at start and end of any engine/API stage. AKS untouched (all kind).
  - Prove each by EFFECT + interaction-state + screenshots (esp. Stage 1 "zero fleet surface when off" and Stage 4
    join→enforce→remove). Update the relevant findings (F-59…F-65) status.
  - Do NOT auto-commit; summarize per stage. Append CLOSEOUT-SINGLE-CLUSTER-FIRST.md. Record this prompt + outcome
    in specs/prompts/ + index.
```
