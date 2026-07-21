<!-- SPDX-License-Identifier: Apache-2.0 -->
# Release runbook

How Norviq is released, what is irreversible, and what a human has to do that CI cannot.

A release is **one git tag**. Pushing `vX.Y.Z` builds the four images, publishes the Helm chart, and
uploads the Python package. There is no other trigger — no branch push and no manual dispatch
publishes anything.

## What a tag does

```
push tag vX.Y.Z
  ├── release.yml
  │     ├── version   reconcile the tag against Chart.yaml + pyproject.toml (gate 0)
  │     ├── images    build 4 multi-arch images -> Trivy (fail-closed) -> cosign sign -> SBOM attest
  │     └── chart     needs: images
  │                   stamp Chart.yaml, resolve each image digest, pin images.<c>.digest,
  │                   lint, render, package, push OCI, cosign sign the chart
  └── pypi-publish.yml
        version gate -> build -> twine check -> wheel-contents gate -> PyPI (Trusted Publishing)
```

`chart` depends on `images` so the chart can never be published referencing images that do not
exist. That ordering is only expressible between jobs of one workflow, which is why `build.yml` is
invoked as a reusable workflow rather than triggered separately.

## Irreversible, so get it right before tagging

- **PyPI will not let you re-upload a version.** A bad `0.1.0` is burned; the next fix must be
  `0.1.1`.
- **Sigstore/Rekor entries are append-only.** A signature over a bad artifact is permanent public
  record.
- Image tags and OCI chart tags can be overwritten, but anyone who already pulled has the old bytes.

## Rehearse first (publishes nothing)

```bash
gh workflow run release.yml --ref main
```

This runs the version gate, stamps the chart, pins digests (from `-latest`), lints, renders,
packages, and re-renders the packaged `.tgz`. The `images` job, the chart push and the chart
signature are all skipped — confirm that in the run's job list.

For the Python side:

```bash
gh workflow run pypi-publish.yml --ref main    # builds + twine check + wheel gate; never uploads
```

Locally you can check the same invariants:

```bash
python3 scripts/check_release_versions.py 0.1.0   # tag vs Chart.yaml vs pyproject
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
python3 scripts/check_release_versions.py 0.1.0

# 2. tag and push
git tag -a v0.1.0 -m "Norviq v0.1.0"
git push origin v0.1.0

# 3. watch both workflows
gh run list --limit 5
```

To bump the version, change `helm/norviq/Chart.yaml` (`version` **and** `appVersion`) and
`pyproject.toml` in one commit — the gate fails otherwise.

## Verify after publishing

```bash
# chart
helm install norviq oci://ghcr.io/norviq-dev/charts/norviq --version 0.1.0 --dry-run
cosign verify ghcr.io/norviq-dev/charts/norviq:0.1.0 \
  --certificate-identity-regexp '^https://github.com/norviq-dev/norviq/.github/workflows/release.yml@.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

# images (signed by build.yml, so the identity regexp names build.yml)
cosign verify ghcr.io/norviq-dev/norviq-engine:api-0.1.0 \
  --certificate-identity-regexp '^https://github.com/norviq-dev/norviq/.github/workflows/build.yml@.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

# the released chart must pin digests, never floating tags
helm template norviq oci://ghcr.io/norviq-dev/charts/norviq --version 0.1.0 \
  --set-json 'policyQuotaNamespaces=["default"]' | grep 'image:' | grep norviq-engine
# every line should read ...norviq-engine@sha256:...

# package
pip download norviq==0.1.0 --no-deps -d /tmp/nrvq && unzip -l /tmp/nrvq/*.whl | grep opa-capabilities
```

## After GA

Swap the README quick start from the local-clone `helm install ./helm/norviq` to
`helm install norviq oci://ghcr.io/norviq-dev/charts/norviq --version 0.1.0`. Keep the from-source
path documented for contributors.
