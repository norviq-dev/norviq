# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""The release stamp is the step that makes a published chart reproducible.

A released chart that still says `api-latest` is not a release: `helm install --version 0.1.0` a
year later would deploy whatever is on main that day, and the cosign signature over the chart would
attest ~50 KB of YAML while saying nothing about the four binaries that actually enforce policy.

These tests run the real scripts/release_stamp.py against a COPY of the real chart and assert on the
rendered output, because the only thing that matters is what a consumer's `helm template` produces.
Nothing here touches a registry or a cluster.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
STAMP = ROOT / "scripts" / "release_stamp.py"
CHECK = ROOT / "scripts" / "check_release_versions.py"
sys.path.insert(0, str(CHECK.parent))  # release scripts are not a package; import them by path
COMPONENTS = ("engine", "api", "ui", "webhook")

# distinct per component so a copy/paste bug that pins them all to one digest fails loudly
DIGESTS = {
    "engine": "sha256:" + "a1" * 32,
    "api": "sha256:" + "b2" * 32,
    "ui": "sha256:" + "c3" * 32,
    "webhook": "sha256:" + "d4" * 32,
    # The chart's TLS-hook image (kubectl + openssl). First-party, so it is digest-pinned like the
    # rest — a hook that patches a webhook's caBundle must not resolve a mutable tag at install time.
    "bootstrap": "sha256:" + "e5" * 32,
}

pytestmark = pytest.mark.skipif(shutil.which("helm") is None, reason="helm not on PATH")


@pytest.fixture
def stamped(tmp_path: Path) -> Path:
    """A copy of the real chart, stamped for 9.9.9 with known digests."""
    chart = tmp_path / "norviq"
    shutil.copytree(ROOT / "helm" / "norviq", chart)
    res = subprocess.run(
        [sys.executable, str(STAMP), "9.9.9", "--chart-dir", str(chart),
         "--digests", ",".join(f"{c}={d}" for c, d in DIGESTS.items())],
        capture_output=True, text=True,
    )
    assert res.returncode == 0, f"stamp failed: {res.stderr}"
    return chart


def _render(chart: Path) -> str:
    res = subprocess.run(
        ["helm", "template", "norviq", str(chart), "--set-json", 'policyQuotaNamespaces=["default"]'],
        capture_output=True, text=True,
    )
    assert res.returncode == 0, f"render failed: {res.stderr[:800]}"
    return res.stdout


def test_every_norviq_image_is_digest_pinned(stamped: Path) -> None:
    """The regression itself: no shipped reference may resolve through a mutable tag."""
    unpinned = re.findall(r"ghcr\.io/norviq-dev/norviq-engine:[^\"\s]+", _render(stamped))
    assert not unpinned, f"released chart still references mutable tags: {sorted(set(unpinned))}"


def test_each_component_keeps_its_own_digest(stamped: Path) -> None:
    """A block-scoping bug in the stamp regex would pin every component to one image."""
    rendered = _render(stamped)
    for comp, digest in DIGESTS.items():
        assert digest in rendered, f"{comp} digest {digest} missing from the rendered chart"


def test_injected_sidecar_is_pinned_too(stamped: Path) -> None:
    """NRVQ_SIDECAR_IMAGE is the PEP that authorizes tool calls — the most important pin of all."""
    m = re.search(r"NRVQ_SIDECAR_IMAGE\s*\n\s*value:\s*\"([^\"]+)\"", _render(stamped))
    assert m, "NRVQ_SIDECAR_IMAGE not found in the rendered chart"
    assert m.group(1) == f"ghcr.io/norviq-dev/norviq-engine@{DIGESTS['engine']}", (
        f"injected enforcement sidecar is not digest-pinned: {m.group(1)}"
    )


def test_chart_version_comes_from_the_argument(stamped: Path) -> None:
    text = (stamped / "Chart.yaml").read_text()
    assert re.search(r"(?m)^version:\s*9\.9\.9$", text)
    assert re.search(r'(?m)^appVersion:\s*"9\.9\.9"$', text)


def test_values_comments_survive_stamping(stamped: Path) -> None:
    """values.yaml comments are the chart's user documentation; a YAML round-trip would eat them."""
    before = (ROOT / "helm" / "norviq" / "values.yaml").read_text().count("\n#")
    after = (stamped / "values.yaml").read_text().count("\n#")
    assert after == before, f"stamping lost comments: {before} -> {after}"


def test_unstamped_chart_still_uses_readable_tags() -> None:
    """Developing from a checkout must keep working — digest is empty, tag wins."""
    rendered = _render(ROOT / "helm" / "norviq")
    assert "ghcr.io/norviq-dev/norviq-engine:engine-latest" in rendered
    assert "@sha256:" not in rendered


@pytest.mark.parametrize("bad", ["not-a-digest", "sha256:tooshort", ""])
def test_stamp_refuses_a_non_digest(tmp_path: Path, bad: str) -> None:
    """Fail closed: never pin something that is not a sha256 digest."""
    chart = tmp_path / "norviq"
    shutil.copytree(ROOT / "helm" / "norviq", chart)
    digests = dict(DIGESTS, engine=bad)
    res = subprocess.run(
        [sys.executable, str(STAMP), "9.9.9", "--chart-dir", str(chart),
         "--digests", ",".join(f"{c}={d}" for c, d in digests.items())],
        capture_output=True, text=True,
    )
    assert res.returncode != 0, "stamp accepted a non-digest"


@pytest.mark.parametrize("bad", ["latest", "0.1", "v1.2.3.4", "abc"])
def test_stamp_refuses_a_non_semver_version(tmp_path: Path, bad: str) -> None:
    chart = tmp_path / "norviq"
    shutil.copytree(ROOT / "helm" / "norviq", chart)
    res = subprocess.run(
        [sys.executable, str(STAMP), bad, "--chart-dir", str(chart),
         "--digests", ",".join(f"{c}={d}" for c, d in DIGESTS.items())],
        capture_output=True, text=True,
    )
    assert res.returncode != 0, f"stamp accepted non-semver version {bad!r}"


def test_versions_agree_across_chart_and_pyproject() -> None:
    """Runs on every PR, so drift is caught here rather than by an unrepeatable PyPI upload."""
    res = subprocess.run([sys.executable, str(CHECK)], capture_output=True, text=True)
    assert res.returncode == 0, res.stdout + res.stderr


def test_version_guard_rejects_a_mismatched_tag() -> None:
    """The guard must actually fail — a guard that always passes is worse than none."""
    res = subprocess.run([sys.executable, str(CHECK), "99.99.99"], capture_output=True, text=True)
    assert res.returncode != 0, "version guard passed a tag that disagrees with the repo"


def test_version_guard_covers_the_docs_install_command() -> None:
    """The docs pin a chart version too, and a stale one is a command that fails for every reader.

    Since the install instructions moved from a local clone to
    `helm install ... oci://.../charts/norviq --version <x.y.z>`, the docs stopped being prose about
    the release and became the release's user interface — there is no repo to fall back to when the
    version does not exist. So the guard has to see them, and it has to still catch this specific
    drift (docs bumped, Chart.yaml forgotten, or the reverse) rather than only whole-repo mismatches.
    """
    import check_release_versions as chk  # noqa: PLC0415 — see the sys.path insert at module top

    docs = chk.collect_docs()
    assert docs, "the guard found no chart version in any doc — the reference pattern has rotted"

    chart_version = chk.collect()["helm/norviq/Chart.yaml:version"]
    assert set(docs.values()) == {chart_version}, f"docs pin {sorted(set(docs.values()))}, chart is {chart_version}"

    # Placeholders must NOT be compared: the release runbook uses "$VERSION" and "<x.y.z>" on purpose.
    assert not any(v.startswith(("$", "<")) for v in docs.values())


def _webhook_sidecar_allowlist() -> "re.Pattern[str]":
    """The webhook's own allow-list, read out of controller.go rather than restated here.

    Restating it would let the copy drift from the code it is supposed to mirror, which is the same
    class of mistake this test exists to catch — two sides of one contract, edited independently.
    """
    src = (ROOT / "webhook" / "controller.go").read_text()
    m = re.search(r"allowedSidecarImagePattern\s*=\s*regexp\.MustCompile\((.*?)\)\n", src, re.S)
    assert m, "allowedSidecarImagePattern not found in webhook/controller.go"
    parts = re.findall(r"`([^`]*)`", m.group(1))
    assert parts, "expected backtick-quoted pattern literal(s)"
    return re.compile("".join(parts))


def test_released_sidecar_image_passes_the_webhook_allowlist(stamped: Path) -> None:
    """The bug this exists for: the chart pinned a digest the webhook refused to inject.

    `release_stamp.py` writes NRVQ_SIDECAR_IMAGE as `...@sha256:<64 hex>` — that is the whole point
    of stamping. The webhook then validates that value against its own allow-list before building a
    patch, and the allow-list accepted only `:tag`. So every PUBLISHED release rejected its own
    sidecar, while every local run passed because the checked-in chart carries `-latest`.

    With `failurePolicy: Fail` the consequence was not a skipped injection: the agent pod was DENIED
    admission. Enabling the flagship feature stopped tenant workloads from starting.

    Neither side was wrong alone, which is why neither side's tests caught it. This asserts the two
    agree, using the real stamped output and the real regex.
    """
    m = re.search(r"NRVQ_SIDECAR_IMAGE\s*\n\s*value:\s*\"([^\"]+)\"", _render(stamped))
    assert m, "NRVQ_SIDECAR_IMAGE not found in the rendered chart"
    image = m.group(1)
    assert "@sha256:" in image, f"a released chart must pin the sidecar by digest, got {image}"
    assert _webhook_sidecar_allowlist().match(image), (
        f"the webhook would REFUSE the sidecar image the release pins: {image}"
    )
