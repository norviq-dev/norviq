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
        └── pypi      needs: images + chart   (inline — see the note below)
                      version gate -> build -> twine check -> wheel gate -> PyPI (Trusted Publishing)
```

`chart` depends on `images` so the chart can never be published referencing images that do not
exist. That ordering is only expressible between jobs of one workflow, which is why `build.yml` is
invoked as a reusable workflow rather than triggered separately.

`pypi` runs **last** for the same reason, and it is the one ordering that matters most: a PyPI
version cannot be re-uploaded or reused, only yanked. When `pypi-publish.yml` fired on the tag
independently, a Release that died at the chart step had already uploaded the wheel — which is how
`0.1.0` and `0.1.1` became permanently burnt version numbers for failures that had nothing to do
with the wheel. It is now a job of `release.yml`, so the irreversible step happens only after every
retryable one has succeeded.

**The PyPI Trusted Publisher must name `release.yml`, and the upload steps are INLINE in that file
rather than a call to `pypi-publish.yml`.** That is a PyPI constraint, not a preference — from their
[troubleshooting docs](https://docs.pypi.org/trusted-publishers/troubleshooting/): *"Reusable
workflows cannot currently be used as the workflow in a Trusted Publisher"* (warehouse#11096).

`v0.1.3` is the worked example. With the publish step in a called workflow, one run carries two
different workflow identities: the OIDC token quotes `job_workflow_ref` (the workflow containing the
job) while the PEP 740 attestation is signed with a certificate naming the **top-level** workflow.
PyPI accepted the token and then rejected the upload:

```
Certificate's Build Config URI (.../release.yml@refs/tags/v0.1.3) does not
match expected Trusted Publisher (pypi-publish.yml @ norviq-dev/norviq)
```

It failed closed — nothing uploaded, `0.1.3` still free — which is exactly what the ordering above
exists to guarantee. Inlining makes both claims name `release.yml`, so one publisher satisfies both.

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
gh workflow run pypi-publish.yml --ref main    # builds + twine check + wheel gate; CANNOT upload
```

That still works directly — `workflow_dispatch` is retained precisely so the Python side can be
validated on its own. Only the **tag** trigger was removed.

Locally you can check the same invariants:

```bash
# No argument: assert Chart.yaml version, appVersion and pyproject agree with EACH OTHER. That is
# the right check before a tag exists — passing a literal here just re-checks whatever version you
# happened to type, and a stale one silently "passes" against the release you already shipped.
python3 scripts/check_release_versions.py
python -m build && python3 scripts/check_wheel_contents.py dist
pytest tests/release/ -q
```

## Test images go to a DIFFERENT package

`ghcr.io/norviq-dev/norviq-engine` holds RELEASED artifacts: multi-arch, scanned fail-closed,
cosign-signed, SBOM-attested. Test builds do not belong in it.

Nothing about a stray test tag can corrupt a release — the released chart pins immutable **digests**, so a
tag push cannot repoint what `--version X` installs, and that was verified directly. The problem is
narrower and still real: unreleased, unsigned code becomes publicly pullable from the same namespace as the
official images, where a passer-by can pull `api-<sha>` and reasonably believe it is a release.

Use the dev package instead:

```bash
./scripts/push_dev_image.sh api engine webhook     # -> ghcr.io/norviq-dev/norviq-engine-dev
```

Then point a cluster at it:

```bash
helm upgrade ... --set images.registry=ghcr.io/norviq-dev/norviq-engine-dev/ \
                 --set-json 'imagePullSecrets=[{"name":"ghcr-dev"}]'
```

Why a separate GHCR package rather than a different registry (Docker Hub was considered): same registry,
same automatic `GITHUB_TOKEN`, so no new credential to provision or rotate; no pull-rate limits to trip
during a rollout; and one auth path instead of two. Docker Hub's public tier would not have solved the
exposure either — only a PRIVATE repository does, and the dev package can simply be created private.

The script refuses to build from a dirty tree unless `ALLOW_DIRTY=1`, and then marks the tag. That is not
pedantry: tagging from a dirty tree reuses the HEAD sha, so a second push OVERWRITES the first tag with
different content. That mutation happened during the latency work — the exact thing digest pinning exists
to prevent.

Dev images are deliberately unsigned and unattested, so `cosign verify` fails against them. That failure is
the feature: it is what keeps a release artifact distinguishable from a test build.

## One-time human setup

CI cannot do these — they need an account login.

1. **PyPI Trusted Publishing.** On pypi.org → *Your projects* → *Publishing* → add a **pending
   publisher**:
   - PyPI project name: `norviq`  (currently unclaimed — verify before relying on it)
   - Owner: `norviq-dev`  ·  Repository: `norviq`  ·  Workflow: **`release.yml`**
   - Environment: **leave blank**. `release.yml` declares no `environment:`, and a publisher
     configured *with* one will reject a workflow that has none.
   - It must be `release.yml`, NOT `pypi-publish.yml`: a reusable workflow cannot be a Trusted
     Publisher, and the attestation certificate names the top-level workflow. See the note above.

   Until this exists the publish step fails **without uploading anything**, so a premature tag is
   survivable on the PyPI side.

2. **Artifact Hub.** Register the repo, then put the issued ID into `artifacthub-repo.yml`
   (`repositoryID`) and push the ownership artifact per that file's header comments. Chart.yaml
   already carries the Artifact Hub annotations.

## Cutting the release

Set this once and every command below follows. It is a variable rather than a literal on purpose:
these blocks previously hardcoded the version, so each release meant hand-editing ~10 lines across
this file — and a stale one is not cosmetic, it makes you verify the version you *last* shipped and
conclude the new release is fine. That already happened once.

```bash
export VERSION=0.1.3          # the version you are cutting
```

```bash
# 1. versions agree (this is also gate 0 in CI, but fail locally first)
python3 scripts/check_release_versions.py "$VERSION"

# 2. exercise the ARTIFACT, not the source. Throwaway kind cluster: stamps the chart by digest
#    exactly as release.yml does, then installs, uses (sidecar injection + a real allow and block),
#    and uninstalls it, checking nothing is stranded.
#    Default is the UPGRADE path — install the previous release from OCI, seed a tenant policy, then
#    upgrade in and assert the generated credentials and PVCs survived and nothing is still running a
#    pre-upgrade image. That is what existing users do; a fresh install is what new ones do, and the
#    two break differently, so run both. CI runs them as a matrix.
python3 scripts/verify_release.py                      # upgrade path (auto-detects N-1)
python3 scripts/verify_release.py --upgrade-from none  # fresh install
# or, both in parallel on a runner:
gh workflow run verify-release.yml
# every check must pass before you tag

# 3. tag and push
git tag -a "v$VERSION" -m "Norviq v$VERSION"
git push origin "v$VERSION"

# 4. watch the workflow — Release drives everything, including the PyPI job
gh run list --limit 5
```

To bump the version, change `helm/norviq/Chart.yaml` (`version` **and** `appVersion`),
`pyproject.toml`, and the `--version` pinned by the install docs, in one commit — the gate fails
otherwise. `uv lock` picks up the `pyproject.toml` change; commit the one-line `uv.lock` diff with it.
See "One version number, deliberately" above for why they all move together.

`scripts/check_release_versions.py` enforces this and reports every disagreeing file with its line
number, so the bump is a mechanical follow-the-errors loop rather than a search you can half-finish.
It runs as gate 0 of the release *and* as a unit test on every PR, so drift is caught by the PR that
introduces it — not by a tag you cannot take back.

## Verify after publishing

```bash
# chart
helm install norviq oci://ghcr.io/norviq-dev/charts/norviq --version "$VERSION" --dry-run
cosign verify "ghcr.io/norviq-dev/charts/norviq:$VERSION" \
  --certificate-identity-regexp '^https://github.com/norviq-dev/norviq/.github/workflows/release.yml@.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

# images (signed by build.yml, so the identity regexp names build.yml)
cosign verify "ghcr.io/norviq-dev/norviq-engine:api-$VERSION" \
  --certificate-identity-regexp '^https://github.com/norviq-dev/norviq/.github/workflows/build.yml@.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

# the released chart must pin digests, never floating tags
helm template norviq oci://ghcr.io/norviq-dev/charts/norviq --version "$VERSION" \
  --set-json 'policyQuotaNamespaces=["default"]' | grep 'image:' | grep norviq-engine
# every line should read ...norviq-engine@sha256:...

# package
pip download "norviq==$VERSION" --no-deps -d /tmp/nrvq && unzip -l /tmp/nrvq/*.whl | grep opa-capabilities
```

## The docs pin a version too

Done as of 0.1.5: the README, `getting-started`, `configuration`, `deployment`, the chart README and
the prod runbook all install from `oci://ghcr.io/norviq-dev/charts/norviq --version <x.y.z>` rather
than a local clone, because a clone tracks main and is therefore not the artifact we signed. The
from-source path stays documented, marked as the contributor path.

The cost of that is a **fourth place carrying the version number**, spread over six files. Move it in
the same commit as `Chart.yaml` and `pyproject.toml` — a doc that tells a user to install a version
that was never published is a worse failure than a version that is merely stale, since it fails at
`helm install` with nothing to fall back to.
