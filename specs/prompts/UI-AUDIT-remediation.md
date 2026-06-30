# Prompt — Remediate live UI-audit findings F-29…F-39 (console correctness + UX)

**Date:** 2026-06-29
**Work item:** Fix the console findings from the live UI audit (`.reviews/live-pentest/UI-AUDIT.md`), reproduced by
driving fleet-a's console. P2: F-37 finance-hub 0-coverage (security-relevant, verify first), F-29 cluster selector
cosmetic, F-30 cluster pill non-deterministic, F-31 attack-graph severity empty-state, F-33 fleet push 422, F-34
fleet nav section. P3: F-32 graph readability/real-tool nodes, F-35 audit filter debounce/server-side, F-36
time-range feedback, F-38 target workloads hint, F-39 MITRE activity overlay.
**Base branch:** start from `feat/live-pentest-remediation-f20-f28` (so the F-25/F-26 fixes are already present —
do NOT re-derive them).
**Decisions in scope:** F-29 approach (scope-to-Fleet vs full per-page repoint), F-39 (activity overlay vs relabel),
F-37 (display-fix vs enforcement-fix — decided by Stage 0 verification).
**Source:** `.reviews/live-pentest/UI-AUDIT.md`. **Gates:** plan mode · do NOT auto-commit · tsc+vitest green ·
keep **attacks 75/75** on any engine/rego touch · AKS untouched (local kind) · honest status.

**Result (DONE — local only, nothing committed; new branch `feat/ui-audit-remediation-f29-f39` off the F-20..F-28
base; attacks 75/75 end of every engine/API stage; AKS untouched):** **10 CLOSED + F-32 PARTIAL.** Each fix has a
regression test + a headless Playwright re-verification on the live :8081 console (before/after in
`portal/ui-fix/`). **STAGE 0** root-caused **F-37 as a SECURITY bug** (not display): the pentest direct-seeded
`__pack__` (no NamespacePack), wiped by `_materialize` → finance pack not enforcing, coverage 0. **S1** F-37 fixed by
enabling via the real packs API (NamespacePack + materialize; durable) + a reserved-scope guard rejecting direct
`__pack__` POSTs (422, NRVQ-API-7016) → SoD/wire/export block again, coverage 3/3; F-29 (Option A) scope selector to
Fleet + "viewing local cluster" notice; F-30 pill = served cluster, stable. **S2** F-33 push validation + default
target + surfaced server detail; F-34 `/fleet`→Intelligence section. **S3** F-31 severity "0 of N" vs recompute;
F-32 legend + data-driven nodes (deep dagre relayout = roadmap, PARTIAL). **S4** F-35 debounce, F-36 loading+count
caption, F-38 deployments SDK hint, F-39 (Option A) MITRE audit activity overlay (observed/blocked per technique,
NRVQ-API-7071). **Incident (caught+recovered):** the F-33 *test* push to `agent_class=__baseline__` distributed
fleet-wide and clobbered comprehensive → 43 attacks failed / mitre 0/8; neutralized the pushed policy + re-seeded →
attacks 75/75, mitre 8/8. **Gates:** ruff clean, opa 133/133, parity 13/13, 14 new backend tests, tsc+vitest 44/44.
Before/after → `.reviews/live-pentest/CLOSEOUT-UI.md`; F-24 top-blocked `get_account` = historical pre-fix rows
(noted, not force-deleted).

---

## Prompt

```
ROLE: Remediate the live UI-audit findings for Norviq (repo: norviq-migration/repo). USE PLAN MODE — present a
staged plan (security-relevant + functional first, polish last), WAIT for approval, implement stage by stage with a
regression test per fix AND a live re-verification by driving the real console headless (Playwright/chromium against
the running fleet-a console :8081, admin JWT in localStorage; screenshot before/after). Read
.reviews/live-pentest/UI-AUDIT.md first. BASE THIS WORK ON branch feat/live-pentest-remediation-f20-f28 (the
F-25 Fleet page + F-26 Attack-Graph fixes are already there — build on them, don't redo them). Nothing may break the
single-cluster path, the SDK/sidecar hot path, the fleet path, the packs/compose machinery, or existing tests. Keep
attacks 75/75 at the start and end of any stage that touches the engine/rego/API. Do NOT auto-commit — summarize per
stage. New work goes on a NEW branch off the base.

STAGE 0 — VERIFY F-37 ROOT CAUSE (decides Stage 1 scope; do this before touching code).
  - On fleet-a (finance hub) the catalog "Policy Coverage by Category" shows Financial Controls = 0 while enabling a
    pack flips its category 0→100. Determine whether the finance pack is ACTUALLY ENFORCING on fleet-a or merely
    seeded at __pack__ without the "enabled" flag the coverage counts.
  - Test: run a finance SoD self-approval + a wire-over-threshold + an export-to-external eval against fleet-a's
    /evaluate (or Policy Tester). If they BLOCK/ESCALATE → enforcement is fine, the bug is COVERAGE COUNTING (display).
    If they ALLOW → the finance pack is NOT enforcing on the hub (security bug). Report which, with evidence.

STAGE 1 — F-37 + F-29 + F-30: make the multi-cluster console truthful.
  - F-37: per Stage 0 — if display-only, fix "Policy Coverage by Category" to count seeded __pack__ (and __baseline__)
    policies actually in effect for the namespace, not just toggle-enabled packs (so the finance hub shows its real
    financial-control coverage). If enforcement-gap, fix the seed/enable path so the sector pack enforces, THEN fix
    coverage. attacks 75/75.
  - F-29 (DECISION — recommend + confirm BEFORE building): the cluster pill repoints only the Fleet page; every other
    page ignores it (refetches local-cluster data with no cluster param), which is misleading. Option A (recommended,
    low-risk): scope the cluster selector to the Fleet page only, and on per-cluster pages show "Viewing local cluster
    <id> — use Fleet to compare clusters" (no false affordance). Option B (full): route per-page reads through the
    fleet-api drill-down so switching the cluster actually repoints Dashboard/Audit/Agents. Recommend A now, B as
    roadmap; confirm.
  - F-30: make the cluster pill label derive from the actually-served cluster (/cluster-info) and stay STABLE across
    navigations (it currently flips fleet-a/b/c on the same console).
  - Tests: tsc+vitest; a UI test asserting the per-cluster pages show the local-cluster label/notice (Option A) or
    repoint (Option B); screenshot the finance hub coverage showing real Financial-Controls coverage.

STAGE 2 — F-33 + F-34: Fleet page correctness.
  - F-33: "Push policy" currently POSTs an empty/default form → fleet-api 422, surfaced as a raw "Push failed (422)".
    Add client-side required-field validation (policy name, target, agent_class), pre-fill a sensible default target
    (e.g. {"env":"prod"}), and surface the server's validation detail (not a bare 422). Test: empty form → inline
    "target required" (no request); valid form → 200 + rollout reflects.
  - F-34: the Fleet link lives under the Intelligence section but opening /fleet switches the sidebar to Security
    Operations. Fix the active-section state so /fleet keeps its correct section highlighted.
  - Tests: tsc+vitest; screenshot a successful signed push + correct nav highlight.

STAGE 3 — F-31 + F-32: the graphs.
  - F-31: when the Attack-Graph severity filter matches 0 paths but paths EXIST (e.g. high when all are low/medium),
    show "0 of N paths at this severity — try All", NOT the "No attack paths yet / Recompute" no-data state (that copy
    must only show when there are genuinely zero stored paths).
  - F-32: improve graph insight — (a) derive Asset/Attack nodes from REALLY-OBSERVED tools (from audit/decision data),
    not the generic static catalog, so the graph describes the actual tenant; (b) reduce the hairball: hierarchical/
    dagre-style layout + label-collision handling; (c) add a legend for node types + edge decision colors. Keep the
    existing toggles working.
  - Tests: tsc+vitest; screenshots of the severity-filtered state and the improved layout with real tools.

STAGE 4 — F-35 + F-36 + F-38 + F-39: polish.
  - F-35: debounce the Audit tool-name filter (one request after typing settles, not per keystroke) and make it filter
    server-side across the whole selected range; show "showing X of Y in range".
  - F-36: add a loading indicator + a record-count caption to the Audit Log so a time-range change gives visible
    feedback even when the rows look similar. (No retention cap exists — don't add one.)
  - F-38: Target Settings → when /deployments is empty, show "No norviq-injected workloads observed (SDK integration
    in use)" instead of a bare empty section.
  - F-39 (DECISION — recommend + confirm): MITRE Coverage is a fixed 8/8/100% mapping. Recommended: overlay observed/
    attempted/blocked counts per technique from audit data so it reflects real activity; if that's out of scope this
    pass, relabel it "policy→technique mapping (not activity-based)". Recommend the overlay; confirm.
  - Tests: tsc+vitest; screenshots.

VERIFICATION STAGE — prove no UI residual.
  - Re-drive the console headless for EACH of F-29..F-39 against its UI-AUDIT.md repro; capture before/after
    screenshots to .reviews/live-pentest/portal/ui-fix/*.png. Mark each closed / partial / roadmap (F-29 Option B and
    F-32 layout depth may be partial — state honestly).
  - Note the F-24 demo-data artifact: after the F-20..F-28 branch is live, RE-SEED / clear the pre-fix mislabeled
    audit rows on the running clusters so the Dashboard "top blocked tool" no longer shows the benign get_account
    (historical rows, not a new bug — just clean the demo).
  - Append CLOSEOUT-UI.md = before/after table for F-29..F-39 with evidence links.

GATES (per stage):
  - tsc + vitest green; ruff + make test + opa check green for any backend/rego touch; new NRVQ-* codes in
    docs/error-codes.md; registry/architecture .md/.mmd updated where structure changes.
  - attacks 75/75 at start and end of any engine/rego/API-touching stage. AKS untouched (all kind).
  - Re-verify each finding against its UI-AUDIT.md repro (no longer reproduces); honest closed/partial/roadmap labels.
  - Do NOT auto-commit; summarize per stage. Record this prompt + outcome in specs/prompts/ + index.
```
