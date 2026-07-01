<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Norviq Contributors -->

# Security baseline & SAST triage

The SAST gate (`.github/workflows/security.yml` + `.pre-commit-config.yaml`, wired into
`scripts/verify.sh` T1/T5) is designed to **start GREEN on this mature codebase and then ratchet** —
a gate that is red on day one gets bypassed. This doc records how "green" is achieved and where the
baselined findings live, so nothing is silently ignored.

## Triage rule (also in AGENTS.md)
- **HIGH / CRITICAL → BLOCK** (fail-closed). Never backlogged.
- **MEDIUM / LOW →** fix in-scope if doable (AGENTS.md rule 2), else record here with a rationale +
  a ticket.

## How the gate starts green (and how it ratchets to blocking)
| Tool | PR scope | Starts blocking? | Ratchet to full-blocking |
|------|----------|------------------|--------------------------|
| gitleaks | PR commit **range** only (not history) | **Yes** — new secrets fail | already blocking; allowlist in `.gitleaks.toml` |
| bandit | **changed** `norviq/**/*.py`, `-ll` | **Yes** — new high fails | config `[tool.bandit]` in `pyproject.toml` |
| semgrep | diff-aware `--baseline-commit <base>` | **Yes** — new findings fail | ignores in `.semgrepignore` |
| eslint-security | changed `ui/src` | Yes (per eslint config) | ui eslint config |
| pip-audit / npm audit | whole repo | **No — report-only** | remove `continue-on-error` on `deps-audit` |
| checkov / kube-linter / trivy-config | whole `helm/` + `crds/` | **No — report-only** | `.checkov.yaml soft-fail:false`; set `iac` job `exit-code:1`; drop `continue-on-error` |
| trivy **image** (engine/api/ui/webhook) | post-build on `main` (`build.yml`) | **No — report-only** (`exit-code:"0"`) | capture `.trivyignore` baseline from first scan, then set `exit-code:"1"` |

Diff-aware jobs are green by construction — only NEW code is judged. The whole-repo jobs are the
ones that need a one-time baseline pass before they can block.

## One-time baseline pass (do this on the first CI run, before flipping the ratchet)
1. Run the whole-repo jobs (`deps-audit`, `iac`, and the `build.yml` image scan on a `main` build).
2. For each HIGH/CRITICAL finding: either FIX it in-scope, or add it to the matching ignore file
   (`.trivyignore` for CVE/misconfig IDs, `.checkov.yaml` `skip-check`, a pinned dep bump for
   pip/npm) **with a one-line rationale + date in the log below.**
3. Flip the ratchets (table above). From then on only NEW high/critical fails.

## Baselined findings log
_(empty — populate during the first CI baseline pass. One row per baselined item.)_

| Date | Tool | ID / finding | File / image | Why baselined (not fixed now) | Ticket |
|------|------|--------------|--------------|-------------------------------|--------|
| — | — | — | — | — | — |

## Notes
- Full history is deliberately **not** secret-scanned (it holds a rotated JWT + past secrets). If a
  history scan is ever needed, baseline those known findings here first.
- Attack payload dirs (`norviq/redteam/`, `norviq/sdk/attacks/`, `tests/`) intentionally contain
  injection strings — they are excluded from bandit/semgrep/gitleaks, not "clean."
