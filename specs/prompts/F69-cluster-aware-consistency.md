# Prompt — F-69 console-wide cluster-awareness consistency (+ P1 apply-targets-wrong-cluster footgun)

**Date:** 2026-06-30
**Validated live (San + assistant, fleet-a console :18080, fleet-b selected):** cluster-awareness was wired ONLY
into the Overview KPIs/Trust (F-67). Every other page ignores the selected cluster and renders the LOCAL (hub/
fleet-a) data MISLABELED as the remote one:
- Asset Graph → fleet-a's graph (`/asset-graph?namespace=default`, no cluster param; shows fleet-a agents).
- Attack Graph → fleet-a's 13 paths, "Showing: default".
- Policy Catalog → fleet-a's `finance-money-movement` pack while pill=fleet-b (healthcare). **FOOTGUN (P1):** the
  console's API is fleet-a's, so **Apply/Save/pack-toggle while a remote cluster is selected mutates fleet-a** under
  a fleet-b label.
- Audit / Agents follow the same local-fetch pattern.
- Overview's Policy-Coverage-by-Category / Tool-Call-Volume / Recent-Blocked show "Not aggregated at the hub" (honest
  but a half-dashboard). KPIs/Trust correctly come from hub rollups.
**Root cause:** the hub only holds KPI/trust rollups, not per-spoke detail. Decision (San): make it CONSISTENT +
HONEST — a remote selection NEVER shows or mutates local data under a remote label; show hub-rollup where available,
else a clear "open <cluster>'s own console" deep-link. Do NOT build hub-proxies-everything.
**Base branch:** new branch `feat/cluster-aware-consistency-f69` off `feat/single-cluster-first-fleet-optin`.
**Gates:** plan mode · do NOT auto-commit · attacks 75/75 on any engine/API stage · tsc+vitest green · AKS untouched
(local kind) · **security auditor on Stage 1 (the mutate footgun)** · validation rule: prove the effect + before/
after screenshots, not a 200.
**Result:** **DONE (2026-06-30, `feat/f69-cluster-awareness`).** Approved fork: guard + whole-page deep-link.
Centralized `isRemote`/`scopeCluster`/`selectedClusterConsoleUrl` in AppContext + **persisted** selection
(refresh-safe). **S1** `clusterGuard.ts` + `apiSend` guard refuse any cluster-scoped LOCAL mutation while remote
(`NRVQ-UI-4601`); live-proven (fleet-a policies+packs sha **unchanged** after a fleet-b session) + vitest backstop.
**S2** `<ClusterScoped>` wraps the 9 per-cluster routes → remote = deep-link page (real page never mounts), local =
real page; live **5/5** pages deep-link under fleet-b, **0/5** under fleet-a. **S3** Dashboard hub-less tiles use the
shared deep-link component. **S4** optional `console_url` threaded env(`NRVQ_FLEET_CLUSTER_CONSOLE_URL`)→relay
heartbeat→`Cluster.console_url`(idempotent ALTER)→`/fleet/clusters`→UI; live deep-link href = fleet-b's
`http://127.0.0.1:18081`, fleet-a/c fallback. **fleet-b own console (:18081) shows real fleet-b data.** Gates:
attacks **78/78**, vitest **60/60** (+10), fleet pytest **46/46** (+1), tsc/ruff/opa clean; new `NRVQ-UI-4601`; doc
`fleet-enrollment.md`. AKS untouched. See `.reviews/live-pentest/CLOSEOUT-F69.md`. (Implemented on
`feat/f69-cluster-awareness`, not the originally-named `feat/cluster-aware-consistency-f69`.)

---

## Prompt

```
ROLE: Fix F-69 — console-wide cluster-awareness consistency — for Norviq (repo: norviq-migration/repo). USE PLAN
MODE; present the plan, WAIT for approval, implement stage by stage. Live-validated problem: only Overview KPIs honor
the selected cluster; every other page silently shows the LOCAL cluster's data mislabeled as the selected remote one,
and mutations (Policy Apply/Save, pack toggle) would hit the LOCAL cluster under a remote label (P1 footgun). The hub
only has KPI/trust rollups, not per-spoke detail. Make the console CONSISTENT + HONEST: a remote-cluster selection
must NEVER render or mutate local data under a remote label — show hub-rollup data where the hub has it, otherwise an
explicit "not available at the hub — open <cluster>'s own console" deep-link (the same pattern Overview's hub-less
panels already use). Do NOT build hub proxies for every spoke. VALIDATION BAR: prove the EFFECT with before/after
screenshots on the running 3-cluster fleet, not a 200. Security auditor on Stage 1. Base a NEW branch on
feat/single-cluster-first-fleet-optin. Nothing may break the single-cluster path, the local (served-cluster) full
experience, the SDK/sidecar hot path, fleet enforcement/retract, or existing tests. attacks 75/75 around any
engine/API stage. Do NOT auto-commit — summarize per stage.

DEFINITIONS: "served/local cluster" = the cluster whose API this console is actually talking to (servedCluster).
"remote cluster" = any selected cluster != served. The fix only changes behaviour when a REMOTE cluster is selected;
LOCAL selection keeps today's full functionality.

STAGE 1 — P1 SECURITY FOOTGUN: no mutation under a remote-cluster label (security auditor).
  - When a REMOTE cluster is selected, every mutating control must be DISABLED (not just hidden) with a clear note —
    "Editing applies to the local cluster <served>. To change <remote>, open its own console." Covers: Policy
    Catalog Save/Apply/Dry-Run-that-writes/rollback, Policy Packs enable/disable + the F-54 override, Target
    Settings/apply-mode, any New Policy. Belt-and-braces: the API/UI client must not send a mutate to the local API
    while a remote cluster is the active context.
  - PROVE: select fleet-b on the fleet-a console → Apply/Save/pack-toggle are disabled with the note; confirm NO
    fleet-a policy/pack changed (diff the local policy before/after). Select local (fleet-a) → mutations work
    normally. attacks 75/75.

STAGE 2 — P1 CORRECTNESS: no detail page shows local data under a remote label.
  - For every per-cluster page — Asset Graph, Attack Graph, Policy Catalog/Packs/Targets, Audit Log, Agents, MITRE,
    Policy Tester — when a REMOTE cluster is selected: do NOT fetch/show the local API's data. Show the honest
    "Not available at the fleet hub — open <remote>'s own console →" state (reuse the Overview hub-less-panel
    component). When LOCAL is selected → render normally as today.
  - PROVE per page: fleet-b selected → none of these render fleet-a's data; each shows the deep-link state. fleet-a
    selected → all render real data. Before/after screenshots for Asset Graph, Attack Graph, Policy Catalog, Audit.

STAGE 3 — Overview consistency.
  - Keep the cluster-aware KPIs + Trust (hub rollups) for a remote cluster. Make the remaining panels (Policy
    Coverage by Category, Tool Call Volume, Recent Blocked) use the SAME deep-link component + wording as Stage 2 —
    so the whole Overview reads consistently (hub-rollup tiles populated; detail tiles → "open the spoke console"),
    not a confusing mix.

STAGE 4 — the deep-link target (so "open <cluster>'s console" actually works).
  - The hub must know each registered cluster's console URL. Add an OPTIONAL consoleUrl to cluster registration
    (carry it in the join token / heartbeat from F-?? enrollment); when present, the deep-link opens it; when absent,
    show the cluster id + short guidance instead of a dead link. Document in the fleet-enrollment doc.
  - PROVE: with consoleUrl set for fleet-b, the deep-link opens fleet-b's console; without it, a clear non-dead
    fallback.

VERIFICATION STAGE (end-to-end, the whole point):
  - On the fleet-a console, select fleet-b: EVERY page is either hub-rollup data (Overview KPIs/Trust) or an honest
    deep-link — NO page shows fleet-a data under fleet-b, and NO mutation can target fleet-a. Select fleet-a (local):
    full normal function everywhere. Open fleet-b's OWN console (:18081) and confirm it shows fleet-b's real data.
    Capture screenshots for each. attacks 75/75; servedCluster correct on each console.

GATES (per stage):
  - ruff + make test + opa check green; tsc + vitest green; new NRVQ-* codes in docs/error-codes.md; registry/
    architecture + fleet-enrollment doc updated. attacks 75/75 at start/end of any engine/API stage. AKS untouched.
  - Re-verify each finding against the live repro (no page shows cross-cluster local data; no remote mutation).
    Update the findings ledger (F-69 closed; note the apply-footgun sub-item as the P1). Do NOT auto-commit;
    summarize per stage. Append CLOSEOUT-F69.md. Record this prompt + outcome in specs/prompts/ + index.
```
