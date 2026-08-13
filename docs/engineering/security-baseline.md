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
| eslint-security | whole `ui/src` (eslint-plugin-security rules) | **Yes** — any finding fails, fail-closed (starts green today) | already blocking; rules in `ui/eslint.config.js` (`detect-object-injection` off as too noisy; confirmed false positives suppressed inline with a rationale) |
| pip-audit / npm audit | whole repo | **No — report-only** | remove `continue-on-error` on `deps-audit` |
| checkov / kube-linter / trivy-config | whole `helm/` (chart + CRDs) | **No — report-only** | `.checkov.yaml soft-fail:false`; set `iac` job `exit-code:1`; drop `continue-on-error` |
| trivy **image** (engine/api/ui/webhook) | post-build on `main` (`build.yml`) | **Yes — blocking** (`exit-code:"1"`, fail-closed) | already blocking; new fixable HIGH/CRITICAL findings fail the build; accepted findings are triaged into `.trivyignore.yaml` with a rationale (baselined findings log below). The YAML form (not the flat file) is what lets an entry carry `paths`, so a CVE accepted in a vendored third-party binary stays **blocking** in the binaries we build ourselves |
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
   (`.trivyignore.yaml` for CVE/misconfig IDs, `.checkov.yaml` `skip-check`, a pinned dep bump for
   pip/npm) **with a one-line rationale + date in the log below.**
3. Flip the ratchets (table above). From then on only NEW high/critical fails.

## Baselined findings log
One row per item that is knowingly carried. Every entry here must correspond to a live line in an
ignore/allow-list file — if you remove the ignore, remove the row.

**Currently empty.** The three rows that lived here (`CVE-2026-39822`, `GHSA-hrxh-6v49-42gf`,
`CVE-2026-56852`) were all cleared on 2026-08-13 by pinning **OPA 1.19.0** in place of 1.18.0 — every
one of them was an accepted risk in the *third-party* OPA static binary, and each carried an exit
condition naming the dependency version that would close it. 1.19.0 met all three at once: built with
go1.26.5 (was 1.26.4), grpc-go v1.82.1 (was v1.81.1), x/text v0.40.0 (was v0.38.0). The rows are
removed rather than annotated, per the rule directly above. Their full rationale remains in git
history and in `.trivyignore.yaml`'s header comment.

| Date | Tool | ID / finding | Where | Why baselined (not fixed now) | Exit condition |
|------|------|--------------|-------|-------------------------------|----------------|
| 2026-07 | FOSSA | `CVE-2026-45829`, `CVE-2026-26030`, `CVE-2026-25592` | `ACCEPTED_CVES` in `.github/workflows/fossa.yml` **and** marked *Ignored* in the FOSSA project UI (reason: vulnerable code not in execute path; version-scoped) so the FOSSA GitHub App's "Security Analysis" check also passes | All three live only in **optional** SDK framework-adapter extras (`norviq[frameworks]` / `[crewai]` / `[semantic-kernel]`), never in a shipped container image, and none can be closed by a version bump today. Per-CVE reachability rationale is the table in [`SECURITY.md`](../../SECURITY.md#accepted-dependency-exceptions) — that table, this allow-list, and the FOSSA-UI ignore must stay in lockstep. | Reviewed each release; drop the moment upstream ships a fixed release reachable without a pre-release dependency (and un-ignore in the FOSSA UI). |
| 2026-08 | FOSSA | `GHSA-qwww-vcr4-c8h2` — React Router RSC-mode CSRF bypass (no CVE assigned) | `ACCEPTED_CVES` in `.github/workflows/fossa.yml` **and** the table in [`SECURITY.md`](../../SECURITY.md#accepted-dependency-exceptions) | UNLIKE the three rows above, this one **does** ship — it is in the console bundle built by `Dockerfile.ui`. It is carried because the vulnerable path does not exist in this application: the console never enters RSC mode (plain `BrowserRouter` + `createRoot`, no server runtime, static bundle behind nginx). Not closable by a bump — the fix is react-router 8.3.0, which requires React >= 19.2.7 and Node >= 22.22.0 and drops `react-router-dom` entirely, i.e. a React 18->19 migration; and every version *below* the affected range is back inside the 7.17.0-and-below range of the three CVEs the 6.30.4 -> 7.18.2 upgrade just closed. **The allow-list matches GHSA ids as well as CVE ids** precisely because this advisory has none. | Drop when the console moves to React 19 and router 8.3.0+, or if any SSR/prerender/RSC step is introduced — which would make the path reachable and turn this into a fix, not an exception. |

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
  `security.yml`; `fossas/fossa-action` pinned to `3ebcea1862c6ffbd5cf1b4d0bd6b3fe7bd6f2cac` # v1.7.0
  in `fossa.yml` (the tag is annotated; SHA resolved by dereferencing the tag object to its commit).
- **Done (cont.):** `bridgecrewio/checkov-action` pinned to `7b972723c44fb3d256283fac96fae5d7c1894bb7` # v12
  (`security.yml`) and `actions/upload-artifact` pinned to `ea165f8d65b6e75b540449e92b4886f43607fa02` # v4
  (`fossa.yml`). **Every `uses:` in `.github/workflows/` is now SHA-pinned** — no mutable tag pins remain.

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
