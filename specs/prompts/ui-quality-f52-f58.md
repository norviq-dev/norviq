# Prompt — UI quality + end-to-end validation F-52…F-58 (fix the gaps "200-checks" missed)

**Date:** 2026-06-30
**Why this exists:** prior headless audits validated "control fires API → 200 → numbers reconcile" and MISSED real
UX/behaviour gaps. This pass fixes the gaps San found in manual use AND raises the validation bar: prove END-TO-END
EFFECT (not HTTP status), test interaction state (open AND close), judge UX quality, and do a human-style
click-through with screenshots reviewed critically. Business-impact triaged — fix what serves the buyer, simplify
or cut what doesn't.
**Base branch:** `feat/round2-remediation-f42-f49` (head of the stack). New branch `feat/ui-quality-f52-f58`.
**Decisions (already made):** Fleet drilldown = KEEP + ENRICH; Target Settings = REPURPOSE if meaningful data can be
assembled, else REMOVE (business call, see F-58).
**Gates:** plan mode · do NOT auto-commit · keep **attacks 75/75** on any engine/API touch · tsc+vitest green · AKS
untouched (local kind) · security auditor on F-52. **Validation rule: a 200 is NOT proof — prove the effect.**
**Result:** **DONE (2026-06-30, `feat/ui-quality-f52-f58`).** All 7 closed, each proven end-to-end (effect +
open/close + screenshots), not a 200. **F-52 (P1)** the push enforced but couldn't be RETRACTED — root-caused to the
spoke puller never deleting dropped keys + `loader.delete` leaving the Postgres row & eval-cache; fixed with puller
**reconcile** (manifest), a complete `loader.delete` (Postgres + evaluator unload + caches), and a hub **retract**
endpoint + UI; **live: push→block→retract→allow→RESTART pod→still allow**, only-target, comprehensive intact,
regression tests added, attacks 75/75. **F-53** tool-name `icontains` substring + server-side SPIFFE filter +
no-results state (live: partial `approve`→rows, `zzz`→empty). **F-54** view pack rego + tighten-only **revertable**
per-ns override (`__pack_override__` overlay); live: override enforces, allow-only can't weaken SoD, revert restores.
**F-55** real Monaco rego Monarch tokenizer (visual). **F-56** decision-grade drilldown (block-rate/bundle/denials/
health) + ✕/Esc/backdrop close. **F-57** cluster `<select>` moved onto the Fleet page; global keeps namespace.
**F-58** repurposed Target Settings → "Effective Policy & Governance" via a read-only `GET /policies/effective`
reusing `_collect_candidates` (can't drift from enforcement). Gates: opa 139, parity 13, tsc, vitest 50, attacks
75/75; **zero new regressions** (71 failed == base; +6 new passing; caught+fixed one self-introduced 404 regression).
New codes NRVQ-ENG-2031, NRVQ-FLT-15028/15029, NRVQ-API-7098/7100. AKS untouched. See `CLOSEOUT-UI-QUALITY.md`.

---

## Prompt

```
ROLE: Fix the UI-quality + behaviour gaps F-52…F-58 for Norviq (repo: norviq-migration/repo). USE PLAN MODE —
present the staged plan, WAIT for approval, implement stage by stage. CRITICAL — VALIDATION BAR (this is why prior
runs missed these): a control returning 200 is NOT proof it works. For EVERY fix you must prove (a) the END-TO-END
EFFECT (the action actually changed behaviour, demonstrated), (b) INTERACTION STATE (panels open AND close — Esc,
close button, backdrop; no stuck overlays), (c) it works from a HUMAN click sequence (drive headless, but also
capture before/after screenshots and review them CRITICALLY — does it actually look/behave right, not just "an
endpoint fired"). Reuse scripts/live-pentest/round2_audit.py + headless Playwright on the running 3-cluster fleet.
Security auditor on F-52. Base on feat/round2-remediation-f42-f49 (new branch). Nothing may break the single-cluster
path, SDK/sidecar hot path, fleet path, packs/compose, or existing tests. attacks 75/75 around any engine/API stage.
Do NOT auto-commit — summarize per stage.

STAGE 1 — F-52 (P1, CRITICAL; security auditor): does fleet "Push policy" ACTUALLY enforce on the target cluster?
  - This is the #1 item. Do NOT accept "200 + bundle distributed" as success (that's exactly what passed before).
    PROVE it end-to-end: pick a single-cluster target (cluster_id of a spoke), author a policy that blocks a tool
    the spoke currently ALLOWS, push it, then RUN that tool call against the spoke's /evaluate (or via its chatbot)
    and show the decision flipped allow→block. Then remove it and show it flips back.
  - If it does NOT actually enforce on the spoke: root-cause the distribute → relay/pull → spoke materialize →
    evaluator-load chain and FIX it so a pushed policy takes effect on the target (and ONLY the target). Re-verify
    end-to-end. attacks 75/75; comprehensive intact on the other clusters.
  - Document the real propagation semantics (push → how long until the spoke enforces) in the registry.

STAGE 2 — F-53 (P2): Audit Log search/filter actually works in real use.
  - Re-verify with a HUMAN click sequence (type a tool name a user would search, change tabs + time range), not a
    headless type-and-assert. Find why San still sees it not working; fix so the tool-name + SPIFFE + quick filters
    return correct results across the selected range (server-side over the range, debounced), with a clear
    "showing X of Y / no results in range" state. Prove with before/after.

STAGE 3 — F-54 (P2, feature) + F-55 (P2, UX): policy packs are viewable/editable + Monaco everywhere policy is authored.
  - F-54: on /policies/packs let the user VIEW the pack's actual rego and EDIT/override it (not just enable/disable).
    Reuse the policy editor; changes persist via the real packs/policy path and re-verify they ENFORCE (edit a pack
    rule → the changed rule actually blocks/allows as edited). 
  - F-55: replace the plain-textarea policy editors (fleet "Push signed policy", and the catalog/pack editors if not
    already) with a Monaco editor with rego syntax highlighting + basic validation. Verify editing + apply still
    works end-to-end.

STAGE 4 — F-56 (P2, UX): Fleet drilldown — enrich + fix close.
  - KEEP the drilldown but make it DECISION-GRADE: per-cluster block rate, recent denials (rule/agent), rollout/
    bundle version, health, and any drift — data a fleet operator actually acts on (drop anything that just repeats
    the table row). FIX the sticky panel: it must close via an explicit close button, Esc, and backdrop click; test
    OPEN and CLOSE; no stuck overlay.

STAGE 5 — F-57 (P2, UX): cluster selector placement.
  - The global cluster pill only affects the Fleet page, which is confusing (change it → nothing happens unless
    you're on Fleet). Move cluster selection ONTO the Fleet page (cluster context lives there); keep NAMESPACE in
    the global chrome. Per-cluster pages show "viewing local cluster <id>" (the F-29 notice). Verify changing
    cluster on Fleet repoints the fleet view; no orphaned global control implying cross-page effect.

STAGE 6 — F-58 (DECISION, business standpoint): Target Settings — repurpose if meaningful, else remove.
  - Assess what genuinely useful data the page could show. Recommended REPURPOSE: "Targets → effective policy &
    governance" — per agent-class/namespace, the EFFECTIVE policy in force + enforcement mode + packs applied + the
    per-namespace apply-mode (F-51 dry-run-only) toggle. That answers "what is actually governing this target right
    now," which no other page does, and consolidates the apply-governance control here.
  - If that effective-policy mapping can't be assembled from real data (don't fabricate), REMOVE the page from the
    Security-Operations nav instead of leaving a purposeless page. State which you did and why.

GATES (per stage):
  - ruff + make test + opa check green; tsc + vitest green; new/updated NRVQ-* codes in docs/error-codes.md;
    registry/architecture updated where structure changes.
  - attacks 75/75 at start and end of any engine/API-touching stage. AKS untouched (all kind).
  - EVIDENCE per fix = the end-to-end effect demonstrated (esp. F-52 enforcement flip on the spoke) + interaction
    state (open/close) + before/after screenshots, NOT a 200. Re-verify each gap against San's report (no longer
    reproduces).
  - Do NOT auto-commit; summarize per stage. Append CLOSEOUT-UI-QUALITY.md (before/after F-52…F-58 with evidence).
    Record this prompt + outcome in specs/prompts/ + index.
```
