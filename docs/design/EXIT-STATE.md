# Exit state — the bar for "ready to cut a version"

This is the target the loop runs against. Every line is **machine-checkable**, and the checker is
`scripts/kind-e2e/exit-state.sh`. Nothing here is satisfied by a green exit code alone: each gate that
can pass vacuously has an explicit non-vacuity assertion beside it, because this project has already
been bitten four times by a suite that reported success having asked nothing.

Run it:

```bash
NRVQ_KUBE_CONTEXT=norviq bash scripts/kind-e2e/exit-state.sh
```

---

## G1 · Hermetic gates

| Check | Bar | Vacuity guard |
|---|---|---|
| `pytest` (excl. integration/attacks) | 0 failed | **>= 1900 passed** — a collection error exits 0 with 0 tests |
| `vitest` | 0 failed | **>= 750 passed** |
| `tsc --noEmit` | clean | — |
| `eslint src --max-warnings=0` | clean | — |
| `npm run build` | succeeds | — |
| `opa` on PATH | present | asserted before any rego-backed suite runs |

## G2 · Cluster suites (L3)

| Check | Bar | Vacuity guard |
|---|---|---|
| `tests/integration` | 0 failed | **>= 40 passed** — the conftest `pytest.skip`s into exit 0 on a dead API |
| `tests/attacks` | 0 failed | **>= 50 passed AND 0 xfailed** — xfail reads as "expected failure", i.e. green |

The xfail bar is `0`, not "few". Two security tests (admin freeze, low-trust cap) xfailed silently for
the life of the project because the suite had no Redis credential. Any xfail here means a control is
not being exercised.

## G3 · Browser suite (L4)

| Check | Bar |
|---|---|
| `scripts/e2e.sh` | **0 failed**, 0 "did not run" |
| Flaky | <= 2, and none in a spec touched by this work |
| Login gate | ran successfully (its absence silently fails ~27 tests) |

Run twice back-to-back from a reset baseline. **The failing set must be identical across both runs** —
a moving set is leaked state, and a suite whose result depends on what ran before it cannot certify
anything.

## G4 · Enforcement latency and capacity

Measured **in-cluster** (never through a port-forward — a laptop-to-Azure hop adds a uniform ~600ms
that looks like product latency).

| Check | Bar |
|---|---|
| p50 @ concurrency 1 | <= 150ms |
| p95 @ concurrency 8 | <= 500ms |
| p99 @ concurrency 8 | <= 1000ms (**hard ceiling 2000ms**: the engine fails CLOSED there) |
| Decisions under load | **every scenario returns exactly its expected decision at concurrency 16** |

The decision check is the real gate. A fast wrong answer is worse than a slow right one, and the
capacity ceiling first showed up as `block` on benign traffic, not as a timing number.

## G5 · Chaos — the system degrades honestly

For each fault, the bar is not "nothing breaks" but **"the failure is correct and legible"**.

| Fault | Required behaviour |
|---|---|
| Kill one API replica | No 5xx to a client; the survivor serves; enforcement unbroken |
| Kill OPA sidecar | Evaluate fails **CLOSED** (block), never open; recovers without a pod restart |
| Redis unavailable | Evaluate still decides; trust degrades safely; no crash loop |
| Postgres unavailable | Reads degrade to a stated error, never a silent empty list |
| Concurrent policy pushes | No two suites for one namespace; no torn policy state |

**Failing open anywhere here is a release blocker, not a bug.**

## G6 · Industry personas

Four autonomous personas (healthcare, fintech, e-commerce, legal), each: sets its own admin password,
registers MCP servers, authors policies, drives a real LLM chatbot through them, and probes its own
industry's edge cases.

| Check | Bar |
|---|---|
| Journey completes | all four, end to end, UI + API + DB |
| Enforcement proven | each persona shows >= 1 real decision FLIP (allow -> block) it caused |
| Findings | recorded with reproduction steps; each triaged as bug / feature-request / works-as-designed |
| Blockers | **0 unresolved product defects rated blocker** |

## G7 · Release hygiene

| Check | Bar |
|---|---|
| Working tree | clean |
| `gitleaks` (PR range) | clean — no key ever committed |
| Chart renders | `helm template` succeeds with required values |
| CI | `.github/workflows/kind-e2e.yml` valid, L3 after L4 |
| Docs | every product decision and defect in `IMPLEMENTATION-LOG.md` |

---

## What is explicitly NOT in scope

Stated so "done" is not confused with "everything":

- **`ConditionPicker`** — the handoff's grouped condition popover. Deliberately deferred: it changes
  the condition-editing model rather than the layout, and `ConditionChip` alone exposes ~20 testids
  both builder e2e specs drive, so shipping it alongside the chrome restructure would make any
  regression unattributable. The rest of the builder chrome (top bar, Stepper strip, footer action
  bar, RegoDrawer rail) IS built — see `IMPLEMENTATION-LOG.md`.
- **No merge to `main`, no PR, no release tag.** The exit state means *ready* to cut a version, and
  cutting it is the user's call.
