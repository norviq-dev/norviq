# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""`verify_release.py --upgrade-from auto` must upgrade from a real published release, or fail.

The release gate's "verify (upgrade)" job reported success on PR #122 without upgrading anything. Its log:

    (no earlier release to upgrade from — running the fresh-install path)

`auto` read `git tag`, and CI's shallow checkout carries no tags, so it quietly ran the fresh-install path
under the upgrade job's name. The upgrade path had never run for that candidate, which is how the
0.2.5 -> 0.2.6 store crash (tests/helm/test_bundled_store_upgrade.py) got as far as it did. The selection
was also wrong with tags present: "highest tag that is not the candidate" skips the published 0.2.5 for
an unbumped 0.2.5 candidate, picks a newer release for an older candidate, and counts tags whose chart
was never published (v0.1.0, v0.2.0).

Nothing here touches a registry or a cluster. The registry listing is injected, and PUBLISHED_2026_10_30
is the real tag list of oci://ghcr.io/norviq-dev/charts/norviq on that date, signature tags included.
"""

from __future__ import annotations

import sys
import urllib.error
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))  # release scripts are not a package; import them by path
import verify_release as vr  # noqa: E402

# GET https://ghcr.io/v2/norviq-dev/charts/norviq/tags/list, 2026-10-30. 0.1.0 and 0.2.0 are absent
# because those releases shipped no chart, though their git tags exist.
PUBLISHED_2026_10_30 = [
    "0.1.1", "0.1.2", "sha256-f36dff5f7d48e34abbc69b559ba8a10011973e305215499cf2279707df67270e",
    "artifacthub.io", "0.1.3", "sha256-5a6f1ddb18fcdf201655a29025482f9cdb584d6429dc84c639164f8c3f4cd1ba",
    "0.1.4", "0.1.5", "0.1.6", "0.1.7", "0.1.8", "0.1.9", "0.1.10",
    "sha256-c6504cbd9e2006498d1d8a9a65a3336e3ab473fef08bf04210e782d3d98eb960", "0.2.1", "0.2.2", "0.2.3",
    "0.2.4", "0.2.5", "sha256-040e19a8e48f9112ca9c6853ebc8c51478a9425527cab0f4d29680eee47f97da",
]


@pytest.mark.parametrize(
    ("candidate", "published", "expected"),
    [
        # PR #122's case: the candidate was still 0.2.5. Upgrading the published 0.2.5 into it is a real
        # upgrade, and it is the one every 0.2.5 user is about to perform.
        pytest.param("0.2.5", PUBLISHED_2026_10_30, "0.2.5", id="equal-is-included"),
        pytest.param("0.2.6", PUBLISHED_2026_10_30, "0.2.5", id="newest-older-release"),
        # An older candidate (a backport branch) must not be "upgraded" from a newer release.
        pytest.param("0.2.4", PUBLISHED_2026_10_30, "0.2.4", id="newer-releases-excluded"),
        pytest.param("0.2.3", ["0.2.2", "0.2.5", "0.3.0"], "0.2.2", id="only-older-than-candidate"),
        # Numeric, not lexicographic: "0.1.9" > "0.1.10" as strings.
        pytest.param("0.2.0", PUBLISHED_2026_10_30, "0.1.10", id="numeric-ordering"),
        # A published prerelease is not a cluster anybody upgrades from.
        pytest.param("0.2.6", ["0.2.5", "0.2.6-rc.1"], "0.2.5", id="published-prerelease-skipped"),
        # A prerelease candidate sorts below its own release, so 0.2.6 does not qualify for 0.2.6-rc.1.
        pytest.param("0.2.6-rc.1", ["0.2.5", "0.2.6"], "0.2.5", id="prerelease-candidate"),
        pytest.param("0.2.6", ["0.2.5", "0.2.6"], "0.2.6", id="release-candidate-equal"),
        # Cosign signature tags and the Artifact Hub metadata tag are not versions.
        pytest.param("9.9.9", ["artifacthub.io", "sha256-" + "a" * 64, "latest"], "", id="non-versions-ignored"),
        pytest.param("0.1.0", PUBLISHED_2026_10_30, "", id="nothing-old-enough"),
        pytest.param("0.2.6", [], "", id="empty-registry"),
    ],
)
def test_select_upgrade_source(candidate: str, published: list[str], expected: str) -> None:
    assert vr.select_upgrade_source(candidate, published) == expected


def test_a_non_semver_candidate_is_refused() -> None:
    with pytest.raises(ValueError, match="not SemVer"):
        vr.select_upgrade_source("main", PUBLISHED_2026_10_30)


def test_auto_resolves_from_the_registry_listing() -> None:
    assert vr.resolve_upgrade_source("auto", "0.2.6", lambda: PUBLISHED_2026_10_30) == "0.2.5"


def test_only_an_explicit_none_selects_the_fresh_install_path() -> None:
    def must_not_list() -> list[str]:
        raise AssertionError("an explicit choice must not consult the registry")

    assert vr.resolve_upgrade_source("none", "0.2.6", must_not_list) == ""
    assert vr.resolve_upgrade_source("0.2.3", "0.2.6", must_not_list) == "0.2.3"


@pytest.mark.parametrize("requested", ["", "  "])
def test_an_empty_upgrade_from_is_an_error_not_the_fresh_path(requested: str) -> None:
    """`--upgrade-from ""` (an unset CI variable) used to be returned as the version "" -> fresh install."""
    def must_not_list() -> list[str]:
        raise AssertionError("an empty value must be refused before the registry is consulted")

    with pytest.raises(vr.UpgradeSourceError, match="empty"):
        vr.resolve_upgrade_source(requested, "0.2.6", must_not_list)


def test_auto_with_no_published_release_fails_instead_of_running_the_fresh_path() -> None:
    with pytest.raises(vr.UpgradeSourceError, match="--upgrade-from none"):
        vr.resolve_upgrade_source("auto", "0.1.0", lambda: PUBLISHED_2026_10_30)


def test_auto_with_an_unreachable_registry_fails_instead_of_running_the_fresh_path() -> None:
    def offline() -> list[str]:
        raise urllib.error.URLError("no route to ghcr.io")

    with pytest.raises(vr.UpgradeSourceError, match="could not list"):
        vr.resolve_upgrade_source("auto", "0.2.6", offline)


def test_main_fails_before_touching_a_cluster(monkeypatch: pytest.MonkeyPatch, capsys) -> None:
    """End to end through main(): no source means exit 1, with the remedy named, and no kind/helm call."""
    calls: list[tuple[str, ...]] = []

    def no_subprocess(*cmd: str, **_kw: object) -> None:
        calls.append(cmd)
        raise AssertionError(f"main() ran {cmd[:3]} before resolving what to upgrade from")

    monkeypatch.setattr(vr.shutil, "which", lambda tool: f"/usr/bin/{tool}")
    monkeypatch.setattr(vr, "run", no_subprocess)
    monkeypatch.setattr(vr, "published_chart_versions", lambda: PUBLISHED_2026_10_30)
    monkeypatch.setattr(sys, "argv", ["verify_release.py", "--version", "0.1.0", "--upgrade-from", "auto"])

    assert vr.main() == 1
    assert "--upgrade-from none" in capsys.readouterr().err
    assert not calls
