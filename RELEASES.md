# Releases

How Norviq is released today. The step-by-step commands, and the reasons each step is ordered the
way it is, are in [docs/engineering/release-runbook.md](docs/engineering/release-runbook.md). This
file is the summary.

## Who releases

The maintainer listed in [MAINTAINERS.md](MAINTAINERS.md). Pushing a `v*.*.*` tag is the only thing
that publishes a release; no branch push or manual run does.

## Versioning

One version number covers everything a release publishes: the git tag, `version` and `appVersion`
in `helm/norviq/Chart.yaml`, `version` in `pyproject.toml`, and the `--version` in the install docs.
`scripts/check_release_versions.py` fails the release, and the unit tests, if they disagree.

Numbers follow [SemVer](https://semver.org/). Norviq is pre-1.0, so a minor or patch release can
change behaviour an operator relies on; 0.2.6, for example, makes the namespace baseline block by
default, and its [CHANGELOG.md](CHANGELOG.md) entry is titled by that change and leads with an
upgrade-impact list. Each 0.2.x
CHANGELOG entry is a summary; the GitHub release for that version is the full account.

## Cadence and branches

There is no fixed cadence. A release is cut when the changes on `main` are ready to ship; v0.1.0 to
v0.2.5 were 17 tags between 2026-07-27 and 2026-08-20. Releases are tagged from `main`. There are no
maintenance branches and no release candidates.

## Supported versions

Only the latest release; see [Supported versions](SECURITY.md#supported-versions) in SECURITY.md.
There are no maintenance branches, so a fix, security fixes included, ships in the next
release and is not backported to an older one. When a release contains security fixes, their advisories
are published with it.

## What a tag publishes

On a tag push, `.github/workflows/release.yml` runs these jobs. Each of the first four starts only if
the one before it succeeded. (A rehearsal run, below, skips the images and pypi jobs and the GitHub
Release jobs, and still runs the chart job.)

1. **version** — `scripts/check_release_versions.py` checks the tag against the files above.
2. **images** — `.github/workflows/build.yml` builds five images (`engine`, `api`, `ui`, `webhook`,
   `bootstrap`) for linux/amd64 and linux/arm64, scans each with Trivy (a fixable HIGH or CRITICAL
   finding not accepted in `.trivyignore.yaml` fails the build), signs it with cosign (keyless),
   attests an SPDX SBOM, and only then tags it
   `ghcr.io/norviq-dev/norviq-engine:<component>-<version>`.
3. **chart** — stamps the chart version, pins every image by digest, checks that every rendered image
   reference is pinned (`scripts/check_image_pins.py`), packages the chart, pushes it to
   `oci://ghcr.io/norviq-dev/charts/norviq`, signs it with cosign (keyless) and verifies that
   signature.
4. **pypi** — builds the `norviq` wheel and sdist, checks the wheel contents
   (`scripts/check_wheel_contents.py`) and uploads to PyPI with Trusted Publishing, which attaches a
   PEP 740 attestation. It is the last irreversible step because a PyPI version cannot be
   re-uploaded.
5. **release-sbom**, **release-sign**, **github-release** — write an SPDX SBOM of the tagged source,
   give the wheel, sdist, chart `.tgz` and SBOM each a keyless Sigstore bundle
   (`<file>.sigstore.json`), verify every bundle, and attach them all to the GitHub Release for the
   tag. If no Release exists, the job creates one with short notes that point at the CHANGELOG; a
   draft the maintainer made first keeps its notes and gets the assets. These jobs change nothing
   that cannot be redone, so they run after PyPI.

## Before tagging

- Rehearse: `gh workflow run release.yml --ref main` pushes and signs the chart into
  `ghcr.io/norviq-dev/charts-rehearsal/`, which no install path uses. It does not build release
  images or upload to PyPI.
- Exercise the artifact: `.github/workflows/verify-release.yml` (or `scripts/verify_release.py`)
  installs the digest-pinned chart in a throwaway kind cluster, both as a fresh install and as an
  upgrade from the newest published release, and every check must pass.

## Verifying a release

```bash
cosign verify "ghcr.io/norviq-dev/charts/norviq:<x.y.z>" \
  --certificate-identity-regexp '^https://github.com/norviq-dev/norviq/.github/workflows/release.yml@.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Images are signed by `build.yml`, so their identity regexp names `build.yml`. The runbook has both
commands.
