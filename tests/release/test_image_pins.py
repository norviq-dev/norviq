# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Every image a released chart can deploy is pinned by digest, and the release gate proves it.

release.yml's gate was `grep 'image: "?ghcr\\.io/norviq-dev/norviq-engine' | grep -v @sha256:`. On a
stamped prep/0.2.6 chart it printed "GATE: PASS" with eleven image lines still on tags: busybox x5,
opa x2, nginx, postgres, valkey and curl. The gate now lives in scripts/check_image_pins.py so it can
be tested here, against the real stamped chart, the way the stamp itself is.

The third-party half of the pins is not stamped at release time; it is committed in values.yaml
(global.thirdPartyImageDigests), so the source-chart tests at the bottom are the PR-time half of the
same gate: a tag bumped without its digest fails on the PR that bumps it, not on the tag.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
STAMP = ROOT / "scripts" / "release_stamp.py"
GATE = ROOT / "scripts" / "check_image_pins.py"
sys.path.insert(0, str(GATE.parent))  # release scripts are not a package; import them by path

import check_image_pins as gate  # noqa: E402 — needs the sys.path insert above

DIGESTS = {c: "sha256:" + h * 32 for c, h in
           (("engine", "a1"), ("api", "b2"), ("ui", "c3"), ("webhook", "d4"), ("bootstrap", "e5"))}

# Every optional component that brings an image of its own: the CloudNativePG operand (postgresql.ha),
# the RedisFailover (redis.ha), the fleet hub and its CNPG store, and webhook injection. The default
# render emits none of their image fields, so a gate run only on it would never see them. The
# passwords are throwaway values that satisfy the chart's strong-secret guards; nothing is installed.
ALL_OPTIONAL = [
    "--set", "postgresql.ha.enabled=true", "--set", "redis.ha.enabled=true",
    "--set", "fleet.hub.enabled=true", "--set", "fleet.hub.postgresql.ha.enabled=true",
    "--set", "webhook.injection.enabled=true",
    "--set", "postgresql.password=x", "--set", "redis.password=x",
    "--set", "fleet.hub.postgresql.password=render-only-placeholder-0000",
    "--set", "fleet.hub.pgUrl=postgresql://fleet@fleet-postgresql-ha-rw:5432/norviq_fleet",
]

pytestmark = pytest.mark.skipif(shutil.which("helm") is None, reason="helm not on PATH")


@pytest.fixture
def stamped(tmp_path: Path) -> Path:
    chart = tmp_path / "norviq"
    shutil.copytree(ROOT / "helm" / "norviq", chart)
    res = subprocess.run(
        [sys.executable, str(STAMP), "9.9.9", "--chart-dir", str(chart),
         "--digests", ",".join(f"{c}={d}" for c, d in DIGESTS.items())],
        capture_output=True, text=True,
    )
    assert res.returncode == 0, f"stamp failed: {res.stderr}"
    return chart


def _render(chart: Path, *extra: str) -> str:
    res = subprocess.run(
        ["helm", "template", "norviq", str(chart), "--set-json", 'policyQuotaNamespaces=["default"]', *extra],
        capture_output=True, text=True,
    )
    assert res.returncode == 0, f"render failed: {res.stderr[:800]}"
    return res.stdout


def _run_gate(tmp_path: Path, rendered: str) -> subprocess.CompletedProcess[str]:
    f = tmp_path / "rendered.yaml"
    f.write_text(rendered)
    return subprocess.run([sys.executable, str(GATE), str(f)], capture_output=True, text=True)


def _digest_map() -> dict[str, str]:
    return yaml.safe_load((ROOT / "helm" / "norviq" / "values.yaml").read_text())["global"]["thirdPartyImageDigests"]


# ---- the gate against the real chart -------------------------------------------------------------

def test_gate_passes_the_stamped_chart(stamped: Path, tmp_path: Path) -> None:
    res = _run_gate(tmp_path, _render(stamped))
    assert res.returncode == 0, res.stdout + res.stderr


def test_gate_passes_every_optional_image_once_stamped(stamped: Path, tmp_path: Path) -> None:
    rendered = _render(stamped, *ALL_OPTIONAL)
    assert "imageName:" in rendered, "the CNPG Cluster did not render — ALL_OPTIONAL no longer reaches it"
    res = _run_gate(tmp_path, rendered)
    assert res.returncode == 0, res.stdout + res.stderr


@pytest.mark.parametrize("ref", sorted(_digest_map()))
def test_gate_refuses_a_stamped_chart_with_one_third_party_digest_missing(
    stamped: Path, tmp_path: Path, ref: str,
) -> None:
    """The regression, per image: drop ONE third-party pin and the release must stop.

    `ref` reaches the render through a values file rather than `--set`, whose key syntax treats the
    `.` in `1.19.1-static` as a path separator.

    The default render is gated beside ALL_OPTIONAL because neither alone carries every ref: with
    redis.ha on, the single-instance store is not rendered, and the failover runs its own redis.ha.image
    (for its redis and sentinel pods) rather than images.redis. Both default to the same Valkey ref.
    """
    drop = tmp_path / "drop-one.yaml"
    drop.write_text(yaml.safe_dump({"global": {"thirdPartyImageDigests": {ref: None}}}))
    res = _run_gate(tmp_path, _render(stamped, "-f", str(drop)) + _render(stamped, *ALL_OPTIONAL, "-f", str(drop)))
    assert res.returncode == 1, f"the gate passed a chart with {ref} on a bare tag:\n{res.stdout}"
    assert f"image is not digest-pinned: {ref}" in res.stderr, res.stderr


def test_gate_refuses_one_line_without_a_digest(stamped: Path, tmp_path: Path) -> None:
    """The same thing at the gate's own level: one edited line among nineteen pinned ones."""
    rendered = _render(stamped)
    victim = re.search(r'image: "(busybox:1\.36)@sha256:[0-9a-f]{64}"', rendered)
    assert victim, "no pinned busybox line to strip"
    res = _run_gate(tmp_path, rendered.replace(victim.group(0), f'image: "{victim.group(1)}"', 1))
    assert res.returncode == 1
    assert res.stderr.count("not digest-pinned") == 1, res.stderr


def test_gate_refuses_the_unstamped_source_chart(tmp_path: Path) -> None:
    """A checkout's chart tracks first-party `-latest` tags on purpose, so it must NOT pass."""
    res = _run_gate(tmp_path, _render(ROOT / "helm" / "norviq"))
    assert res.returncode == 1
    assert "norviq-engine:api-latest" in res.stderr


# ---- the parser, on the shapes helm emits --------------------------------------------------------

def test_gate_reads_every_shape_a_reference_takes() -> None:
    text = "\n".join([
        '          image: "a:1"',
        "      - image: b:2",
        "  imageName: 'c:3'",
        "            - name: NRVQ_SIDECAR_IMAGE",
        '              value: "d:4"',
        "            - name: FROM_SECRET_IMAGE",        # valueFrom is not a reference the chart chose
        "              valueFrom: {}",
        "            - name: NRVQ_ALLOW_LOCAL_SIDECAR_IMAGES",  # *_IMAGES, a boolean, not an image
        '              value: "false"',
        "        # image: in a comment is prose",
        "          imagePullPolicy: IfNotPresent",
    ])
    assert [r for _n, r in gate.find_refs(text)] == ["a:1", "b:2", "c:3", "d:4"]


def test_the_injected_sidecar_counts_as_an_image() -> None:
    """NRVQ_SIDECAR_IMAGE is an env value; a grep for `image:` never saw it."""
    text = '            - name: NRVQ_SIDECAR_IMAGE\n              value: "ghcr.io/norviq-dev/norviq-engine:engine-latest"\n'
    assert gate.unpinned(gate.find_refs(text)) == [(2, "ghcr.io/norviq-dev/norviq-engine:engine-latest")]


@pytest.mark.parametrize("value", ['""', "", "|", ">-", '"x:1@sha256:abc"', '"x@sha256:' + "A" * 64 + '"'])
def test_anything_short_of_a_full_digest_is_unpinned(value: str) -> None:
    refs = gate.find_refs(f"  image: {value}\n")
    assert len(refs) == 1 and gate.unpinned(refs) == refs, f"{value!r} read as pinned"


def test_an_empty_render_fails(tmp_path: Path) -> None:
    """A truncated `helm template` must not read as 'every image pinned'."""
    res = _run_gate(tmp_path, "")
    assert res.returncode == 1
    assert "no image references found" in res.stderr


# ---- the workflow actually runs it ---------------------------------------------------------------

def test_release_workflow_gates_the_working_tree_and_the_packaged_tgz() -> None:
    """A gate the workflow does not call is no gate: assert both renders go through the script."""
    wf = yaml.safe_load((ROOT / ".github" / "workflows" / "release.yml").read_text())
    runs = {s.get("name", ""): s.get("run", "") for s in wf["jobs"]["chart"]["steps"]}
    render = runs["Lint and render the chart that will actually ship"]
    assert "> /tmp/rendered.yaml" in render
    assert "python3 scripts/check_image_pins.py /tmp/rendered.yaml" in render
    assert "ghcr\\.io/norviq-dev" not in render, "the first-party-only grep is back as the gate"
    package = runs["Package"]
    assert "> /tmp/rendered-tgz.yaml" in package
    assert "python3 scripts/check_image_pins.py /tmp/rendered-tgz.yaml" in package


# ---- the third-party pins in the source chart ----------------------------------------------------

CHART = ROOT / "helm" / "norviq"
FIRST_PARTY = "ghcr.io/norviq-dev/"
_DATASTORE_SECRETS = ["--set", "postgresql.password=x", "--set", "redis.password=x"]
# The shipped profiles an operator installs with, plus every optional image. values-prod is the one
# that renders the CNPG operand in an ordinary install, so it is checked as a profile in its own right.
PROFILES = {
    "default": [],
    "all-optional": ALL_OPTIONAL,
    "values-light": ["-f", str(CHART / "values-light.yaml")],
    "values-dev": ["-f", str(CHART / "values-dev.yaml")],
    "values-prod": ["-f", str(CHART / "values-prod.yaml"), *_DATASTORE_SECRETS],
}


def _third_party(rendered: str) -> list[str]:
    return [r for _n, r in gate.find_refs(rendered) if not r.startswith(FIRST_PARTY)]


@pytest.mark.parametrize("profile", sorted(PROFILES))
def test_every_third_party_image_is_pinned_in_the_source_chart(profile: str) -> None:
    refs = _third_party(_render(CHART, *PROFILES[profile]))
    assert refs, f"{profile}: no third-party image rendered — the profile no longer reaches them"
    bare = sorted({r for r in refs if gate.unpinned([(0, r)])})
    assert not bare, (
        f"{profile}: third-party image(s) on a bare tag: {bare}. Resolve the index digest with "
        f"`docker buildx imagetools inspect <ref> --format '{{{{json .Manifest}}}}'` and add it to "
        f"global.thirdPartyImageDigests in values.yaml, keyed by the ref exactly as rendered."
    )


def test_every_digest_entry_is_still_rendered() -> None:
    """A pin for a tag nothing renders any more is a stale copy that reads as coverage."""
    rendered = _render(CHART) + _render(CHART, *ALL_OPTIONAL)
    stale = [ref for ref in _digest_map() if f'"{ref}@sha256:' not in rendered]
    assert not stale, f"global.thirdPartyImageDigests pins refs the chart never renders: {stale}"


def test_an_overridden_tag_never_inherits_the_old_digest() -> None:
    """The reason the pins are keyed by ref and not a `digest` beside each tag.

    `valkey/valkey:8.2-alpine@sha256:<the 8.1 index>` would run 8.1: the runtime resolves the digest
    and ignores the tag. An operator who moves a tag must get the tag, and only the tag.
    """
    refs = set(_third_party(_render(CHART, "--set", "images.redis.tag=8.2-alpine",
                                    "--set", "opa.image=openpolicyagent/opa:1.20.0-static")))
    assert "valkey/valkey:8.2-alpine" in refs, refs
    assert "openpolicyagent/opa:1.20.0-static" in refs, refs
    leaked = [r for r in refs if r.startswith(("valkey/valkey:", "openpolicyagent/opa:")) and "@" in r]
    assert not leaked, f"an old digest was applied to an overridden tag: {leaked}"


def test_pins_can_be_dropped_wholesale() -> None:
    """For a mirror that re-pushed the images under new digests (docker pull + push).

    Also the shape `helm upgrade --reuse-values` from 0.2.5 produces, where the key is absent: the
    chart must render, on tags, rather than dereference a missing map.
    """
    refs = _third_party(_render(CHART, "--set", "global.thirdPartyImageDigests=null"))
    assert refs and not [r for r in refs if "@" in r], refs


def test_a_malformed_digest_is_refused_at_render(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text(yaml.safe_dump({"global": {"thirdPartyImageDigests": {"busybox:1.36": "sha256:abc"}}}))
    res = subprocess.run(
        ["helm", "template", "norviq", str(CHART), "--set-json", 'policyQuotaNamespaces=["default"]',
         "-f", str(bad)], capture_output=True, text=True,
    )
    assert res.returncode != 0, "a truncated digest rendered — it would only fail later, at image pull"
    assert "thirdPartyImageDigests" in res.stderr, res.stderr[:400]
