<!-- SPDX-License-Identifier: Apache-2.0 -->
# Release runbook

How Norviq is released, what is irreversible, and what a human has to do that CI cannot.

A release is **one git tag**. Pushing `vX.Y.Z` builds the four images, publishes the Helm chart, and
uploads the Python package. There is no other trigger — no branch push and no manual dispatch
publishes anything.

## What a tag does

```
push tag vX.Y.Z
  └── release.yml
        ├── version   reconcile the tag against Chart.yaml + pyproject.toml (gate 0)
        ├── images    build 4 multi-arch images -> Trivy (fail-closed) -> cosign sign -> SBOM attest
        ├── chart     needs: images
        │             stamp Chart.yaml, resolve each image digest, pin images.<c>.digest,
        │             lint, render, package, push OCI, cosign sign, VERIFY the signature
        └── pypi      needs: images + chart   (calls pypi-publish.yml)
                      version gate -> build -> twine check -> wheel gate -> PyPI (Trusted Publishing)
```

`chart` depends on `images` so the chart can never be published referencing images that do not
exist. That ordering is only expressible between jobs of one workflow, which is why `build.yml` is
invoked as a reusable workflow rather than triggered separately.

`pypi` runs **last** for the same reason, and it is the one ordering that matters most: a PyPI
version cannot be re-uploaded or reused, only yanked. When `pypi-publish.yml` fired on the tag
independently, a Release that died at the chart step had already uploaded the wheel — which is how
`0.1.0` and `0.1.1` became permanently burnt version numbers for failures that had nothing to do
with the wheel. It is now a `workflow_call`, so the irreversible step happens only after every
retryable one has succeeded.

The PyPI Trusted Publisher stays configured as `pypi-publish.yml` even though `release.yml` is the
entry point: the publish step still runs inside that file, and PyPI matches the OIDC
`job_workflow_ref` claim, which names the workflow containing the job rather than its caller.

## Irreversible, so get it right before tagging

- **PyPI will not let you re-upload a version.** A bad version is burned; the next fix must be
  `0.1.1`.
- **Sigstore/Rekor entries are append-only.** A signature over a bad artifact is permanent public
  record.
- Image tags and OCI chart tags can be overwritten, but anyone who already pulled has the old bytes.
  Do not do this to a released version: re-pushing `0.1.2` means two people who both ran
  `helm pull --version 0.1.2` hold different bytes, and the existing cosign signature covers the old
  digest. That defeats the digest-pinning the whole pipeline is built around. Ship a new version.

## One version number, deliberately

`Chart.yaml version`, `Chart.yaml appVersion` and `pyproject.toml version` are held identical, and
`scripts/check_release_versions.py` fails the build if they drift. Helm permits `version` (the
chart's packaging version) and `appVersion` (the app it installs) to move independently, so this is
a deliberate choice rather than an oversight.

The cost is real and worth naming: a chart-only change — an Artifact Hub annotation, a docs link, a
template tweak — cannot ship without bumping the application version too, which also publishes a
wheel. Such changes therefore **accumulate on `main` and ride the next application release**, which
is why `main` can carry chart edits that are not yet visible on the Artifact Hub listing (annotations
reach it only via a published chart artifact).

That trade was taken over decoupling because:

- Extra PyPI versions are cheap. Patch versions are normal and nobody minds `0.1.3`. What actually
  hurt during 0.1.0–0.1.2 was **failed** releases consuming versions — the wheel uploading before the
  chart push failed. That is fixed by ordering (`pypi` now runs last), not by decoupling.
- One number is simpler for users, and matches how cert-manager and Istio ship their in-tree charts.
- A second release path is more surface on a pipeline that took three attempts to stabilise, and it
  would need its own rehearsal to be trustworthy.

If chart-only fixes ever become frequent enough that waiting is genuinely painful, the two
established ways out are a `chart-v*` tag path that skips the image and PyPI jobs, or moving the
chart to its own repository (what prometheus-community and grafana do). Neither is warranted for a
single chart with one maintainer.

## Rehearse first (nothing consumers can reach)

```bash
gh workflow run release.yml --ref main
```

This runs the version gate, stamps the chart, pins digests (from `-latest`), lints, renders,
packages, re-renders the packaged `.tgz`, and then **really pushes and really signs** — into
`ghcr.io/norviq-dev/charts-rehearsal/` rather than `charts/`, finishing with a `cosign verify` using
the same command this runbook gives consumers.

That push and signature are the point of the rehearsal. The earlier version skipped both, so it
reported success for precisely the two steps that broke `v0.1.0` (no chart published at all) and
`v0.1.1` (chart published **unsigned**, because `helm registry login` writes Helm's credential file
while cosign reads the Docker credential store). A rehearsal that cannot fail where releases fail is
not a rehearsal. A throwaway local registry would not close this either — it needs no auth, so it
cannot catch a credential-store mistake.

Still tag-only, so still unexercised by a rehearsal: the image build/scan/sign job, and the PyPI
upload. Confirm in the run's job list that `images` and `pypi` are skipped and `chart` is green.

`charts-rehearsal/` accumulates a chart and signature per rehearsal. It is never referenced by any
install path or doc; prune it whenever you like.

For the Python side:

```bash
gh workflow run pypi-publish.yml --ref main    # builds + twine check + wheel gate; never uploads
```

That still works directly — `workflow_dispatch` is retained precisely so the Python side can be
validated on its own. Only the **tag** trigger was removed.

Locally you can check the same invariants:

```bash
python3 scripts/check_release_versions.py 0.1.2   # tag vs Chart.yaml vs pyproject
python -m build && python3 scripts/check_wheel_contents.py dist
pytest tests/release/ -q
```

## One-time human setup

CI cannot do these — they need an account login.

1. **PyPI Trusted Publishing.** On pypi.org → *Your projects* → *Publishing* → add a **pending
   publisher**:
   - PyPI project name: `norviq`  (currently unclaimed — verify before relying on it)
   - Owner: `norviq-dev`  ·  Repository: `norviq`  ·  Workflow: `pypi-publish.yml`
   - Environment: **leave blank**. `pypi-publish.yml` declares no `environment:`, and a publisher
     configured *with* one will reject a workflow that has none.

   Until this exists the publish step fails **without uploading anything**, so a premature tag is
   survivable on the PyPI side.

2. **Artifact Hub.** Register the repo, then put the issued ID into `artifacthub-repo.yml`
   (`repositoryID`) and push the ownership artifact per that file's header comments. Chart.yaml
   already carries the Artifact Hub annotations.

## Cutting the release

```bash
# 1. versions agree (this is also gate 0 in CI, but fail locally first)
python3 scripts/check_release_versions.py 0.1.2

# 2. tag and push
git tag -a v0.1.2 -m "Norviq v0.1.2"
git push origin v0.1.2

# 3. watch both workflows
gh run list --limit 5
```

To bump the version, change `helm/norviq/Chart.yaml` (`version` **and** `appVersion`) and
`pyproject.toml` in one commit — the gate fails otherwise.

## Verify after publishing

```bash
# chart
helm install norviq oci://ghcr.io/norviq-dev/charts/norviq --version 0.1.2 --dry-run
cosign verify ghcr.io/norviq-dev/charts/norviq:0.1.2 \
  --certificate-identity-regexp '^https://github.com/norviq-dev/norviq/.github/workflows/release.yml@.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

# images (signed by build.yml, so the identity regexp names build.yml)
cosign verify ghcr.io/norviq-dev/norviq-engine:api-0.1.2 \
  --certificate-identity-regexp '^https://github.com/norviq-dev/norviq/.github/workflows/build.yml@.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

# the released chart must pin digests, never floating tags
helm template norviq oci://ghcr.io/norviq-dev/charts/norviq --version 0.1.2 \
  --set-json 'policyQuotaNamespaces=["default"]' | grep 'image:' | grep norviq-engine
# every line should read ...norviq-engine@sha256:...

# package
pip download norviq==0.1.2 --no-deps -d /tmp/nrvq && unzip -l /tmp/nrvq/*.whl | grep opa-capabilities
```

## After GA

Swap the README quick start from the local-clone `helm install ./helm/norviq` to
`helm install norviq oci://ghcr.io/norviq-dev/charts/norviq --version 0.1.2`. Keep the from-source
path documented for contributors.
