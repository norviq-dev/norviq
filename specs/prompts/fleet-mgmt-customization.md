# Prompt — Fleet management UX: apply transparency + extensive hub→spoke validation + full pack customization + monitoring drill-down

**Date:** 2026-06-30
**Customer-standpoint decisions (San):**
1. A hub exists to MONITOR + MANAGE all spokes centrally — not deep-link away. Centralize what's safe; the customer
   provides only spoke→hub OUTBOUND connectivity (no inbound holes into spokes). Document this contract.
2. Policy apply (local + hub→spoke) currently gives NO feedback — it must show a Rancher-style apply RESULT (the
   declarative resource that was applied + target + outcome + propagation), and the hub→spoke apply path must be
   EXTENSIVELY validated end-to-end.
3. Norviq is open-source — users must be able to fully VIEW, EDIT, and APPLY policy packs (full customization), not
   just toggle them.
**Base branch:** new branch `feat/fleet-mgmt-customization` off `feat/f69-cluster-awareness`.
**Gates:** plan mode · do NOT auto-commit · attacks 75/75 on any engine/API stage · tsc+vitest green · AKS untouched
(local kind) · security auditor on Stage 1 (apply) + Stage 2 (pack edit) + Stage 3 (cross-cluster data exposure /
residency) · **validation rule: prove the EFFECT end-to-end + before/after screenshots, never a 200.**
**Result:** **DONE (2026-06-30, `feat/fleet-mgmt`).** **S0** `docs/engineering/fleet-architecture.md` (monitor/manage/
residency + spoke-initiated-outbound, no-inbound contract). **S1** shared `ApplyResultPanel` (local Apply + fleet
Push + Retract): exact manifest + HONEST outcome (engine-load / signed-bundle, not fake kubectl) + NRVQ code + LIVE
rollout propagation; Dry-Run current-vs-new diff. **Live: hub→fleet-b push → allow→block flip → retract → flip-back →
survived restart; fleet-a/c untouched.** **S2** pack view/edit/dry-run/apply + bounded **advanced-weaken**: new
`__pack_weaken__` overlay (relaxes a pack block but `_resolve_with_packs` floors it at the comprehensive base) +
`allow_weaken` (admin, audited `NRVQ-API-7099`). **Live: tighten enforced; weaken relaxed SoD (block→allow) while
`drop_table` still blocked `llm06` (floor held); revert restored.** **S3** `ClusterScopedMonitor` seam (hub-render
when fresh, freshness badge, stale/residency→deep-link) + `RemoteAgents`: **Agents centralized** — hub shows fleet-b's
5 REAL agents (matching its own console). **Honest partial:** Effective-Policy/Coverage/graph summaries stay on the
F-69 deep-link (same seam; relay-`detail` centralization = documented next increment — not stale, not broken). Gates:
**attacks 78/78**, pack-precedence 16/16 (+8), parity 13/13, opa, pack-router 9/9, **vitest 67/67** (+7), tsc, ruff.
New `NRVQ-API-7099`. AKS untouched. See `.reviews/live-pentest/CLOSEOUT-FLEET-MGMT.md`.

---

## Prompt

```
ROLE: Implement fleet management UX for Norviq (repo: norviq-migration/repo). USE PLAN MODE — present the staged
plan, WAIT for approval, implement stage by stage. VALIDATION BAR: a 200 is NOT proof — every behaviour is proven by
end-to-end EFFECT (the thing actually changed) + before/after screenshots on the running 3-cluster kind fleet.
Security auditor on Stages 1, 2, 3. Base a NEW branch on feat/f69-cluster-awareness. Nothing may break the
single-cluster path, the SDK/sidecar hot path, fleet enforcement/retract, packs/compose, the F-69 cluster-guard, or
existing tests. attacks 75/75 around any engine/API stage. Do NOT auto-commit — summarize per stage.

STAGE 0 — Fleet architecture decision doc (foundation; write before building).
  - Author docs/engineering/fleet-architecture.md capturing the model: hub = central monitor + manage; the connection
    is SPOKE-INITIATED OUTBOUND (enrollment/heartbeat/bundle-pull today; reverse-channel for live manage = roadmap),
    so the customer contract is "allow spoke→hub outbound (443) + run join; NO inbound access to spokes required."
    Define the three data classes: MONITOR (bounded read-detail safe to centralize), MANAGE (writes; already safe
    via push-signed-policy → spoke-pull), RESIDENCY (raw audit / restricted — stays in the spoke, deep-link only).
    State what's built now (rollups, enrollment, push/retract, F-69 honesty) vs roadmap (reverse-channel live manage).

STAGE 1 — Policy apply TRANSPARENCY + extensive hub→spoke validation (security auditor). PRIORITY.
  - Today apply (local Apply AND fleet Push) shows nothing. Add a Rancher-style APPLY RESULT panel: show the exact
    declarative resource applied (the NrvqPolicy manifest / rego + target cluster + namespace + agent_class),
    a clear "applied / configured" confirmation line (honest to the REAL mechanism — if it's a DB policy-store write
    say so; if it's an NrvqPolicy CRD synced by the controller, show `nrvqpolicy.norviq.io/<name> configured`; do NOT
    fake `kubectl apply` if that's not what happens), the outcome (success/error + NRVQ code), and the PROPAGATION
    status (local: loaded@vN; fleet push: distributed → spoke pulled @vN → enforcing, with timing).
  - EXTENSIVELY VALIDATE the hub→spoke apply path end-to-end on the live fleet (this is the core ask):
      * Push a policy from the hub to fleet-b that blocks a tool fleet-b currently ALLOWS → the result panel shows
        the manifest + target + "configured" + propagation; then RUN that tool on fleet-b → decision flipped
        allow→block. Dry-Run first shows a real diff (current vs new). Retract → result panel shows removed →
        fleet-b flips back → survives a fleet-b pod restart. Confirm ONLY fleet-b changed (fleet-a/c untouched).
      * Error paths surface honestly in the panel: invalid rego → error; remote-cluster guard (F-69) → blocked with
        reason; fleet-wide push → confirm gate (F-40).
  - attacks 75/75; screenshots of the apply-result panel + the allow→block flip + the dry-run diff + the retract.

STAGE 2 — Policy packs: full VIEW + EDIT + APPLY (open-source customization; security auditor).
  - Extend F-54 (view + tighten-only override) to a FULL customization experience: the user can view the pack's
    rego, EDIT it in the Monaco editor, Dry-Run it, and APPLY it (with the Stage-1 apply-result transparency).
    Default safety = tighten-only (an edit cannot weaken/remove a pack block) — but since this is open-source and the
    user owns their policy, provide an explicit, loud "Advanced: allow weakening this pack" opt-in (clearly warned +
    audited) for users who deliberately want full control. Revert restores the shipped pack.
  - VALIDATE: edit a pack rule (e.g. tighten finance SoD) → Apply → the edited rule actually blocks/allows as edited
    live; the advanced-weaken opt-in is gated + audited; revert restores the original; attacks 75/75; parity green.

STAGE 3 — Fleet drill-down: centralize MONITORING (the "single pane") + graceful fallback.
  - Per the architecture doc's MONITOR class: extend the spoke→hub relay to push BOUNDED read-detail (agent list,
    effective policy + coverage, asset/attack-graph summaries — NOT raw audit). Render those pages for a REMOTE
    cluster directly in the hub (replacing the F-69 deep-link for these specific pages) using the pushed data.
  - GRACEFUL: if a spoke is unreachable/stale or residency-restricted (raw audit), keep the F-69 deep-link for that
    data — never show stale/empty as if live; label freshness (e.g. "as of last heartbeat").
  - VALIDATE: on the hub, select fleet-b → Agents / Effective-Policy / Coverage / graph summaries render fleet-b's
    REAL data (matches fleet-b's own console), labeled with freshness; raw Audit still deep-links; a residency spoke
    still deep-links for audit. fleet-a (local) unchanged. Screenshots both.

FINAL VERIFICATION STAGE — end-to-end UI sign-off, NO LOOSE ENDS (mandatory; do not skip).
  - After all stages, re-drive the WHOLE console end-to-end on the live fleet (headless Playwright + critical
    screenshot review, not a 200) and produce a coverage matrix proving every changed surface works in BOTH modes:
      * Hub console (fleet-a, :18080): LOCAL (fleet-a) selected → every page full real data + every mutating control
        works (apply shows the result panel; pack edit/apply enforces). REMOTE (fleet-b/c) selected → monitor pages
        (agents/effective-policy/coverage/graph summaries) show the spoke's REAL data with freshness; raw-audit +
        residency → deep-link; NO mutation can target the wrong cluster (F-69 guard holds); apply/push result panel
        shows manifest+target+propagation; allow→block flip + retract proven.
      * Spoke console (fleet-b, :18081): single-cluster experience intact, shows its own real data, no hub-only
        surfaces leaking.
      * Single-cluster (fleet off): zero fleet surface (regression check on the single-cluster-first work).
  - Walk EVERY route + EVERY interactive control touched by stages 1–3 (apply/dry-run/retract, pack view/edit/apply/
    revert + advanced-weaken, the result panel, drill-down pages, deep-link fallbacks); each item marked tested-ok /
    finding / n-a. Any control that doesn't behave = a finding fixed before close, not deferred. Capture screenshots
    for each. Re-run scripts/live-pentest/round2_audit.py as the sweep. attacks 75/75. Append the matrix +
    screenshots to CLOSEOUT-FLEET-MGMT.md — this is the proof of no loose ends.

GATES (per stage):
  - ruff + make test + opa check green; tsc + vitest green; new NRVQ-* codes in docs/error-codes.md; registry/
    architecture + fleet docs updated. attacks 75/75 at start/end of any engine/API stage. AKS untouched.
  - Prove each by EFFECT + screenshots (esp. Stage 1 allow→block flip + apply-result panel; Stage 2 edited-rule
    enforces; Stage 3 remote detail matches the spoke's own console). Update findings + CLOSEOUT-FLEET-MGMT.md.
  - Do NOT auto-commit; summarize per stage. Record this prompt + outcome in specs/prompts/ + index.
```
