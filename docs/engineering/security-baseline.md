<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Norviq Contributors -->

# Security baseline & SAST triage

The SAST gate lives in `.github/workflows/security.yml`. `.pre-commit-config.yaml` runs a **subset**
locally — gitleaks (staged diff) and bandit, plus ruff/tsc — so a clean pre-commit does *not* mean a
clean CI run: semgrep, eslint-security, and every whole-repo job are CI-only.

The gate is designed to **start GREEN on this mature codebase and then ratchet** — a gate that is red
on day one gets bypassed. This doc records how "green" is achieved and where the baselined findings
live, so nothing is silently ignored.

## Triage rule
- **HIGH / CRITICAL → BLOCK** (fail-closed). Never backlogged.
- **MEDIUM / LOW →** fix in-scope if doable, else record here with a rationale +
  a ticket.

## How the gate starts green (and how it ratchets to blocking)
| Tool | PR scope | Starts blocking? | Ratchet to full-blocking |
|------|----------|------------------|--------------------------|
| gitleaks | PR commit **range** only (not history) | **Yes** — new secrets fail | already blocking; allowlist in `.gitleaks.toml` |
| bandit | **changed** `norviq/**/*.py`, `-ll` | **Yes** — new high fails | config `[tool.bandit]` in `pyproject.toml` |
| semgrep | diff-aware `--baseline-commit <base>` | **Yes** — new findings fail | ignores in `.semgrepignore` |
| eslint-security | changed `ui/src` | Yes (per eslint config) | ui eslint config |
| pip-audit / npm audit | whole repo | **No — report-only** | remove `continue-on-error` on `deps-audit` |
| checkov / kube-linter / trivy-config | whole `helm/` (chart + CRDs) | **No — report-only** | `.checkov.yaml soft-fail:false`; set `iac` job `exit-code:1`; drop `continue-on-error` |
| trivy **image** (engine/api/ui/webhook) | post-build on `main` (`build.yml`) | **No — report-only** (`exit-code:"0"`) | capture `.trivyignore` baseline from first scan, then set `exit-code:"1"` |
| FOSSA dependency gate | whole dependency graph (`fossa.yml`) | **Yes** — any dependency `vulnerability` or `malware` issue fails | already blocking; exceptions are an explicit `ACCEPTED_CVES` allow-list in the job |

Diff-aware jobs are green by construction — only NEW code is judged. The whole-repo jobs are the
ones that need a one-time baseline pass before they can block.

The FOSSA gate is the exception to "start report-only": it blocks today. It deliberately gates on
**vulnerability + malware only**, not license issues — the free tier cannot tune the license policy,
and its CC-BY-SA/APSL flags are documented false positives on bundled data inside permissive-code
deps. OS/image CVEs are trivy's job (`build.yml`); FOSSA covers the dependency graph.

## One-time baseline pass (do this on the first CI run, before flipping the ratchet)
1. Run the whole-repo jobs (`deps-audit`, `iac`, and the `build.yml` image scan on a `main` build).
2. For each HIGH/CRITICAL finding: either FIX it in-scope, or add it to the matching ignore file
   (`.trivyignore` for CVE/misconfig IDs, `.checkov.yaml` `skip-check`, a pinned dep bump for
   pip/npm) **with a one-line rationale + date in the log below.**
3. Flip the ratchets (table above). From then on only NEW high/critical fails.

## Baselined findings log
One row per item that is knowingly carried. Every entry here must correspond to a live line in an
ignore/allow-list file — if you remove the ignore, remove the row.

| Date | Tool | ID / finding | Where | Why baselined (not fixed now) | Exit condition |
|------|------|--------------|-------|-------------------------------|----------------|
| 2026-07 | trivy (image) | `CVE-2026-39822` — Go stdlib `os.Root` symlink following (HIGH) | `.trivyignore`; present via the embedded Go runtime of the pinned `opa 1.18.0-static` binary in the api/engine images, and the webhook Go binary | Not on any Norviq code path: OPA is driven as a policy evaluator over an HTTP API with no untrusted-filesystem/symlink surface, and the webhook does no `os.Root` traversal. Fixed in Go 1.25.12 / 1.26.5 / 1.27.0-rc.2; the pinned OPA is built with Go 1.26.4, so we cannot clear it by bumping our own code. | Drop the `.trivyignore` line when an OPA release built with Go ≥ 1.26.5 is pinned. |
| 2026-07 | FOSSA | `CVE-2026-45829`, `CVE-2026-26030`, `CVE-2026-25592` | `ACCEPTED_CVES` in `.github/workflows/fossa.yml` | All three live only in **optional** SDK framework-adapter extras (`norviq[frameworks]` / `[crewai]` / `[semantic-kernel]`), never in a shipped container image, and none can be closed by a version bump today. Per-CVE reachability rationale is the table in [`SECURITY.md`](../../SECURITY.md#accepted-dependency-exceptions) — that table and this allow-list must stay in lockstep. | Reviewed each release; drop the moment upstream ships a fixed release reachable without a pre-release dependency. |

Not baselined, and not to be baselined: a CVE a version bump *can* close gets bumped. `werkzeug>=3.1.6`
in `pyproject.toml` (resolving to 3.1.8) is the worked example — it closes CVE-2025-66221 /
CVE-2026-21860 / CVE-2026-27199 and appears in **neither** list above.

### Deliberately-noisy paths (excluded, not clean)
`.semgrepignore` excludes `tests/` (which covers `tests/attacks/`) and `norviq/redteam/`. These directories
contain injection strings and attack payloads **on purpose** — they are Norviq's own test corpus. They
are excluded so the SAST signal stays readable, not because they were reviewed and found clean. Never
promote an exclusion here into "this code is safe".

## Third-party GitHub Actions must be SHA-pinned (supply-chain)
Pin actions by **immutable commit SHA**, not a mutable tag — a compromised tag can be re-pointed at
malicious code (trivy-action itself had a March-2026 compromise; we use it AS our security gate).
- **Done:** `aquasecurity/trivy-action` pinned to `57a97c7e7821a5776cebc9bb87c984fa69cba8f1` # v0.35.0,
  plus `actions/checkout`, `actions/setup-python`, and `actions/setup-node` across `build.yml` and
  `security.yml`.
- **Remaining tag pins** (residual supply-chain risk — pin these next):
  - `bridgecrewio/checkov-action@v12` — `security.yml`
  - `fossas/fossa-action@v1.7.0` and `actions/upload-artifact@v4` — `fossa.yml`

  Verify the current state rather than trusting this list:
  ```bash
  grep -rn 'uses: .*@v[0-9]' .github/workflows/   # every hit is a mutable tag pin
  ```

## Notes
- Full history is deliberately **not** secret-scanned (it holds a rotated JWT + past secrets). If a
  history scan is ever needed, baseline those known findings here first.
- Attack payload dirs (`norviq/redteam/`, `tests/attacks/`, `tests/`) intentionally contain
  injection strings — they are excluded from bandit/semgrep/gitleaks, not "clean."
- The checkov scan is scoped to `helm/` (`.checkov.yaml`), so IaC findings outside the chart are not
  covered by that job.
