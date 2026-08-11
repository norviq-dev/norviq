# Cut readiness — what actually blocks, and what ships as a known issue

Written 2026-08-10 to answer "cut ASAP; if a bug is not that important we proceed". Everything here
is classified against one question: **would a customer be harmed, misled, or unable to work around it?**
Anything else ships documented.

## The correction that matters most

I had been carrying "C2-024 and the egress module are not live on AKS" as a cut blocker. **That was
wrong.** `release.yml` fires on a `v*.*.*` tag and builds the four images **from the tag**, so every
committed fix ships automatically. Being absent from the dev cluster constrains further *testing*; it
has nothing to do with the release. Removing that leaves **one** real blocker.

## BLOCKS THE CUT (1)

**Nothing has been through CI.** 56 commits, unpushed, on no remote branch, no tag. The
`security.yml` gates — secrets scan, TS SAST, dependency audit, IaC — plus FOSSA have never run on any
of this code. For a security product that is not a defensible thing to skip; it is also the cheapest
gate to clear (push the branch and read the result).

## SHIPS AS A KNOWN ISSUE (documented, workaround exists, no data-loss or false-assurance risk)

| # | issue | why it can ship |
|---|---|---|
| C2-013 | no destination-keyed control an operator can toggle | The finding is documented, and `docs/campaign2/customer-data-egress.rego` is a working policy that blocks the chain and survives four evasions. The compiler landed this session; only the endpoint and console are missing. Customer answer is honest: "author this policy". |
| SEED-04 | `chain_depth_limit` fires on 1 of 5 adapters | Real coverage gap, but the shipped **caveat now states it correctly** (that was C2-004, where the copy said the opposite). A customer is not misled. |
| BUG-005 | any ISO-8601 date reads as an SSN | 100% reproducible false positive — but controls ship on **monitor**, so it records rather than drops traffic, and the caveat names it. Promotion is the operator's deliberate act, with blast radius shown first. |
| C2-023 residual | `d3lete_records` (leetspeak) evades | `skeleton()` folds confusable letters, not digit substitutions. Narrow, recorded, no false assurance. |
| C2-022 residual | `remove_records` evades | `remove` is not in the destructive verb list — a coverage decision, not a defect. |
| C2-011 / 014 / 015 / 016 | assorted coverage gaps from the campaign | All documented in FINDINGS with reproductions. None is a silent failure. |
| Tier 4 backlog | true open count unknown | Housekeeping. The tracker now says plainly that its status column is not truth, so nobody is misled by it. |
| deliverables | WALKTHROUGH / FRAMEWORK-MATRIX / UNMEASURED unwritten | Internal documentation. Does not affect a customer. |

## FIXED THIS SESSION — in source, therefore in the cut

`_gate_answer` monitor invariant · attack-graph verdict mapping · C2-002 completion (+`origin`) ·
C2-012 homoglyph · C2-019 credentials out of the pod spec · C2-020 expiry forewarning · C2-021 throttle
misclassification · C2-022 rename · C2-023 base64 false positives · C2-024 space separator ·
C2-013 compiler + precedence + scope reservation.

Four of these were verified live on AKS; the rest are covered by tests that were each checked against
their own reverted state.

## The recommended path to a tag

1. **Push the branch.** Let CI run. This is the only blocker.
2. If the security gates are green, **tag `v0.2.0`** — the release workflow does images, signing,
   SBOM, and a digest-pinned chart.
3. Optional but cheap: `workflow_dispatch` on `release.yml` first — a REAL rehearsal push into
   `charts-rehearsal/` that publishes nothing consumers can reach.
4. Ship this file's "known issues" table as the release note's known-issues section.

## What I would NOT hold the cut for

Perfecting the name-keyed control. Round 2 showed it is enumeration, not generalisation — each fix
catches the spellings in front of it and the next round finds one more separator. **C2-013 is the
thing that ends that loop**, and it is a post-cut feature, not a patch. Holding the release to add a
seventh separator to a split map would buy very little and delay everything else that did land.
