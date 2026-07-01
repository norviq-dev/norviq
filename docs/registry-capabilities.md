<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Norviq Contributors -->

# Capability registry — who owns what, and how to invoke it

So neither tool demands a capability the other owns or can't run. Each capability maps to an **owning
tool**, its **trigger**, and a **script/CLI equivalent** the other side can run. Orchestration:
[`WORKFLOW.md`](WORKFLOW.md); shared rules: [`AGENTS.md`](../AGENTS.md).

> Rule: the **reviewer must not require an artifact the author can't produce**, and the author must
> not expect the reviewer to fix code. If a capability has no script equivalent, it's owned by one
> tool only — don't block on it from the other side.

## Authoring (Cursor)
| Capability | Owner | Trigger | Script / CLI equivalent |
|-----------|-------|---------|-------------------------|
| Write feature source | Cursor `coder` (`.cursor/rules/coder.mdc`) | `@coder {FEAT}` on a spec | — (author-only) |
| Write tests | Cursor `tester` (`.cursor/rules/tester.mdc`) | `@tester {FEAT}` | `pytest`, `vitest` to run them |
| Fix (incl. review fix-list) | Cursor `fixer` (`.cursor/rules/fixer.mdc`) | bug / review REJECT | — (author-only) |
| Architecture diagrams | Cursor `diagram` (`.cursor/rules/diagram.mdc`) | `@diagram {FEAT}` | — |
| Code registry | Cursor `registry` (`.cursor/rules/registry.mdc`) | `@registry {FEAT}` | — |
| Pre-review self-audit (3 dimensions) | Cursor `.cursor/agents/*` via `.cursor/commands/parallel-review-and-fix.md` | >50 LOC under `norviq/`, before handoff | `scripts/verify.sh` (tiers) covers the automated part |
| UI visual QA (T4, Cursor side) | Cursor skill `.cursor/skills/visual-qa-testing` | UI change | `scripts/review-ui.sh` (headless capture into T4 evidence) |

## Review (Claude Code)
| Capability | Owner | Trigger | Script / CLI equivalent |
|-----------|-------|---------|-------------------------|
| Authoritative code review + verdict | Claude (`CLAUDE.md`) | `./scripts/review.sh {FEAT}` after gate green | — (reviewer-only; Cursor runs the gate, not the verdict) |
| Freshness / staleness guard (Step 0) | Claude (reviewer) | start of every review | **`scripts/serena-refresh.sh`** (reindex + memory health-check; `--memories-only` = pure git+grep) |
| Memory + lessons write-back (Step N) | Claude (reviewer) | on PASS | Serena `write_memory` + memory-graph MCP; `_bug-catalog.md` / `bug-patterns.md` |
| Assert T4 EFFECT from evidence | Claude (reviewer) | UI/enforcement change | inspects `.reviews/{FEAT}-t4-evidence/` (screenshots + decision-flip log) |

## The 4 auditor agents (shared criteria in AGENTS.md)
Run by Cursor as a self-audit (`parallel-review-and-fix`) AND applied by Claude in review — same
lists, so verdicts agree.
| Agent | Focus | Definition |
|-------|-------|-----------|
| `norviq-correctness-auditor` | P-1..P-10 Day-8 bug patterns | `.cursor/agents/norviq-correctness-auditor.md` |
| `norviq-security-auditor` | fail-open, secrets, injection, authZ, cross-tenant | `.cursor/agents/norviq-security-auditor.md` |
| `norviq-performance-auditor` | <5ms p99: subprocess, sync-in-async, N+1, pools | `.cursor/agents/norviq-performance-auditor.md` |
| `norviq-verifier` | "done" = exists + runs + effect + edge cases | `.cursor/agents/norviq-verifier.md` |

## Verification tiers (either tool can run; reviewer gates on them)
| Tier | Command |
|------|---------|
| T1 static+unit | `scripts/verify.sh {FEAT} --tier T1` |
| T2 integration (kind only) | `scripts/verify.sh {FEAT} --tier T2` |
| T3 regression | `scripts/verify.sh {FEAT} --tier T3` |
| T4 effect (emit evidence) | `scripts/verify.sh {FEAT} --tier T4` |
| T5 security gate | `scripts/verify.sh {FEAT} --tier T5` |
| all + Claude review | `scripts/review.sh {FEAT}` |

## SAST tools (T5 / security gate)
| Concern | Tool | Where it runs | Config |
|---------|------|---------------|--------|
| Python SAST | bandit, semgrep | pre-commit + `security.yml` | `[tool.bandit]`, `.semgrepignore` |
| Python deps | pip-audit | `security.yml` (report→ratchet) | — |
| TS/JS SAST | eslint-security | `security.yml` | ui eslint config |
| TS/JS deps | npm audit / osv-scanner | `security.yml` (report→ratchet) | — |
| Secrets | gitleaks (diff/PR-range) | pre-commit + `security.yml` | `.gitleaks.toml` |
| IaC / Helm / CRDs | checkov, kube-linter | `security.yml` (report→ratchet) | `.checkov.yaml` |
| Container images (4) | trivy image | `build.yml` post-build on `main` (fail HIGH/CRIT) | `.trivyignore` |
| IaC/Dockerfile/deps (FS) | trivy config | `security.yml` (no image pull on PR) | `.trivyignore` |

Triage rule + ratchet plan: `docs/engineering/security-baseline.md`.
