<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Norviq Contributors -->

# Security baseline & SAST triage

The SAST gate lives in `.github/workflows/security.yml`. `.pre-commit-config.yaml` runs a **subset**
locally — gitleaks (staged diff) and bandit, plus ruff/tsc — so a clean pre-commit does *not* mean a
clean CI run: semgrep, eslint-security, and every whole-repo job are CI-only.

The gate is designed to **start GREEN on this mature codebase and then ratchet** — a gate that is red
on day one gets bypassed. This doc records how "green" is achieved and where the baselined findings
live, so nothing is silently ignored.

**None of these checks is required to merge.** `main` has no branch protection or ruleset today, so a
failing check reports on the PR or commit and stops nothing by itself; making the fail-closed checks
required is pending, not applied. "Fails" below means the job fails, not that a merge is refused.

## Triage rule
- **HIGH / CRITICAL → FAIL the check** (fail-closed). Never backlogged.
- **MEDIUM / LOW →** fix in-scope if doable, else record here with a rationale +
  a ticket.

## How the gate starts green (and how it ratchets to fail-closed)
| Tool | PR scope | Fails the check from day one? | Ratchet to fail-closed |
|------|----------|------------------|--------------------------|
| gitleaks | PR commit **range** only (not history) | **Yes** — new secrets fail | already fail-closed; allowlist in `.gitleaks.toml` |
| bandit | **changed** `norviq/**/*.py`, `-ll` | **Yes** — new medium or high fails | config `[tool.bandit]` in `pyproject.toml` |
| semgrep | diff-aware `--baseline-commit <base>` | **Yes** — new findings fail | ignores in `.semgrepignore` |
| eslint-security | whole `ui/src` (eslint-plugin-security rules) | **Yes** — any finding fails, fail-closed (starts green today) | already fail-closed; rules in `ui/eslint.config.js` (`detect-object-injection` off as too noisy; confirmed false positives suppressed inline with a rationale) |
| pip-audit / npm audit | the shipped `.[spiffe]` closure; each optional extra's closure, ignoring only `ACCEPTED` (a test holds the list of extras to `pyproject.toml`); `ui` | **No — report-only** | remove `continue-on-error` on `deps-audit` |
| checkov / kube-linter / trivy-config | whole `helm/` (chart + CRDs) | **No — report-only** | `.checkov.yaml soft-fail:false`; set `iac` job `exit-code:1`; drop `continue-on-error` |
| trivy **image** (engine/api/ui/webhook) | post-build on `main` (`build.yml`) | **Yes** — fails the job (`exit-code:"1"`) after the image is pushed: it stops the cosign signature, the SBOM attestation and, on a release, the chart and PyPI jobs, not the push itself | already fail-closed; new fixable HIGH/CRITICAL findings fail the job; accepted findings are triaged into `.trivyignore.yaml` with a rationale (baselined findings log below). The YAML form (not the flat file) is what lets an entry carry `paths`, so a CVE accepted in a vendored third-party binary stays **fail-closed** in the binaries we build ourselves |
| FOSSA dependency gate | the shipped graphs (`fossa.yml`): the Python closure the images install (`.[spiffe]`, checked line by line against fossa-cli's requirements grammar before the scan), `ui` production deps, `webhook` module — each asserted present in the scan summary | **Yes** — any dependency `vulnerability` or `malware` issue fails | already fail-closed; exceptions are an explicit allow-list, `ACCEPTED` in `scripts/check_fossa_issues.py`, held to SECURITY.md's table by a test |

Diff-aware jobs are green by construction — only NEW code is judged. The whole-repo jobs are the
ones that need a one-time baseline pass before they can fail the check.

The FOSSA gate is the exception to "start report-only": it fails the check today. It deliberately gates on
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

**Trivy: one row, `CVE-2026-78661` (2026-11-11), in the table below.** Before it, no Trivy finding was carried: the three rows that lived here (`CVE-2026-39822`, `GHSA-hrxh-6v49-42gf`,
`CVE-2026-56852`) were all cleared on 2026-08-13 by pinning **OPA 1.19.0** in place of 1.18.0 — every
one of them was an accepted risk in the *third-party* OPA static binary, and each carried an exit
condition naming the dependency version that would close it. 1.19.0 met all three at once: built with
go1.26.5 (was 1.26.4), grpc-go v1.82.1 (was v1.81.1), x/text v0.40.0 (was v0.38.0). The rows are
removed rather than annotated, per the rule directly above. Their full rationale remains in git
history and in `.trivyignore.yaml`'s header comment.

On 2026-08-16 the pin moved again, to **OPA 1.19.1**, for 8 HIGH Go-stdlib advisories in the 1.19.0
static binary. The chart's `opa.image` and every CI checksum moved together — the chart pin is the one
that matters, because it is the binary that actually serves decisions; leaving it behind would have
shipped the fix everywhere except where policy is evaluated.

On 2026-10-30 it moved to **OPA 1.21.4**, for 9 fixable HIGH findings in the 1.19.1 static binary:
four in its Go stdlib (1.26.6; fixed in 1.26.9 and 1.26.10), one each in x/crypto 0.53.0, x/net 0.56.0
and x/text 0.40.0, and two in grpc 1.82.1. Trivy 0.69.3 with CI's flags reported them, so the next api
and engine builds would have failed the gate. 1.21.4 is built with go1.27.3 against x/crypto 0.57.0, x/net
0.60.0, x/text 0.42.0 and grpc 1.83.2, and scans with 0 HIGH/CRITICAL. The Dockerfiles verify the release
binaries against OPA's published checksums. The sidecar image holds a separate build of the same commit, so
its sha256 never matches theirs (that was true of 1.19.1 as well). It was checked with `go version -m`
instead: the amd64 and arm64 images match the release binaries in everything but the build host.

| Date | Tool | ID / finding | Where | Why baselined (not fixed now) | Exit condition |
|------|------|--------------|-------|-------------------------------|----------------|
| 2026-11-11 | Trivy (image) | `CVE-2026-78661` (GO-2026-6860), HIGH, x/net/html quadratic text-node coalescing | `usr/local/bin/opa` (OPA 1.21.4-static, x/net v0.60.0) in the api and engine images | No OPA release through v1.22.3 requires x/net >= 0.62.0. The package is not linked: `go tool nm` finds no `golang.org/x/net/html` symbol in the amd64 or arm64 release binary (206 for `x/net/http2`), and `govulncheck -mode=binary` reports it at module level only | An OPA release that requires x/net >= 0.62.0 |
| 2026-07, 2026-10 | FOSSA | `CVE-2026-45829`, `CVE-2026-45830`, `CVE-2026-45831`, `CVE-2026-45833` (chromadb); `CVE-2026-26030`, `CVE-2026-25592` (semantic-kernel); `CVE-2024-6825` (litellm, spurious) | `ACCEPTED` in `scripts/check_fossa_issues.py` **and** marked *Ignored* in the FOSSA project UI (reason: vulnerable code not in execute path; version-scoped) so the FOSSA GitHub App's "Security Analysis" check also passes | All live only in **optional** SDK framework-adapter extras (`norviq[frameworks]` / `[crewai]` / `[semantic-kernel]`), never in a shipped container image. chromadb has no fixed release; every semantic-kernel fix needs a pre-release `azure-ai-agents`; litellm 1.100.4 is outside CVE-2024-6825's affected range (1.40.3.dev2-1.40.12). Per-CVE reachability rationale is the table in [`SECURITY.md`](../../SECURITY.md#accepted-dependency-exceptions) — that table, this allow-list, and the FOSSA-UI ignore must stay in lockstep. The 2026-10-30 relock moved chromadb and litellm, so their version-scoped UI ignores need re-review. | Reviewed each release; drop the moment upstream ships a fixed release reachable without a pre-release dependency (and un-ignore in the FOSSA UI). |
| 2026-09 | FOSSA | `CVE-2018-1002105`, `CVE-2019-11250`, `CVE-2020-8565` (k8s.io modules, admission webhook) | `ACCEPTED` in `scripts/check_fossa_issues.py` and the SECURITY.md table | Spurious matches: FOSSA flagged them against any v0.x, while the advisories end at kubernetes 1.12.3 / client-go 0.17.0 / 0.19.6 and the webhook pins v0.37.0. | Drop if FOSSA's data gains the upper bounds (its 2026-10-27 scan of `webhook/` raised none of the three). |

Not baselined, and not to be baselined: a CVE a version bump *can* close gets bumped. `werkzeug>=3.1.9`
in `pyproject.toml` is the worked example — it closes CVE-2025-66221 / CVE-2026-21860 /
CVE-2026-27199 / CVE-2026-102598 and appears in **neither** list above. So do the optional-extra floors
added on 2026-10-30 (pyproject.toml lists each with its CVEs).

The React Router row (`GHSA-qwww-vcr4-c8h2`) was removed on 2026-10-30. The advisory now ends at
`<7.18.2`, so the pinned 7.18.2 is the first patched release. `npm audit --omit=dev` reports 0, and
FOSSA's 2026-10-27 scan of the console raised nothing. Removing it follows the rule above: a stale
entry would only disarm the gate if the advisory were revised back.

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
