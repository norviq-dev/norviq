# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""The published wheel must carry the runtime assets, not just .py files.

setuptools ships only *.py unless told otherwise, so the wheel silently omitted
norviq/engine/opa-capabilities.json — the restricted OPA capability set that opa_client.py loads
relative to __file__ to re-compile submitted rego against a compiler with no http.send/net.*/io.*
builtins. That check is skip-on-absence:

    if not _CAPABILITIES_PATH.exists() or shutil.which("opa") is None:
        return

so a wheel missing the file imports cleanly, passes `twine check`, and quietly drops a
defense-in-depth layer. PyPI forbids re-uploading a version, so this has to be caught before the
upload — hence both this test and scripts/check_wheel_contents.py in the publish workflow.

Building a distribution is slow-ish, so the build is a module-scoped fixture.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
CHECKER = ROOT / "scripts" / "check_wheel_contents.py"
CAPABILITIES = "norviq/engine/opa-capabilities.json"


@pytest.fixture(scope="module")
def dist(tmp_path_factory: pytest.TempPathFactory) -> Path:
    out = tmp_path_factory.mktemp("dist")
    res = subprocess.run(
        [sys.executable, "-m", "build", "--outdir", str(out), str(ROOT)],
        capture_output=True, text=True,
    )
    if res.returncode != 0:
        pytest.skip(f"`python -m build` unavailable/failed in this env: {res.stderr[-300:]}")
    return out


def test_wheel_ships_the_opa_capabilities_file(dist: Path) -> None:
    whl = next(iter(sorted(dist.glob("*.whl"))), None)
    assert whl is not None, "no wheel was built"
    names = set(zipfile.ZipFile(whl).namelist())
    assert CAPABILITIES in names, (
        f"{whl.name} omits {CAPABILITIES}; the engine's forbidden-builtin check would silently "
        f"no-op for anyone installing from PyPI"
    )


def test_source_file_is_tracked_so_the_package_data_rule_has_something_to_ship() -> None:
    """Guards the other half: package-data pointing at a file nobody committed ships nothing."""
    assert (ROOT / CAPABILITIES).is_file(), f"{CAPABILITIES} is missing from the working tree"
    res = subprocess.run(
        ["git", "-C", str(ROOT), "ls-files", "--error-unmatch", CAPABILITIES],
        capture_output=True, text=True,
    )
    assert res.returncode == 0, f"{CAPABILITIES} is not tracked by git, so it cannot be packaged"


def test_checker_script_passes_on_a_good_dist(dist: Path) -> None:
    res = subprocess.run([sys.executable, str(CHECKER), str(dist)], capture_output=True, text=True)
    assert res.returncode == 0, res.stdout + res.stderr


def test_checker_script_fails_when_the_asset_is_missing(dist: Path, tmp_path: Path) -> None:
    """A gate that cannot fail is not a gate — rebuild the wheel without the asset and expect exit 1."""
    src = next(iter(sorted(dist.glob("*.whl"))))
    broken_dir = tmp_path / "broken"
    broken_dir.mkdir()
    # copy the sdist through untouched; strip the asset out of the wheel only
    for sd in dist.glob("*.tar.gz"):
        shutil.copy(sd, broken_dir / sd.name)
    with zipfile.ZipFile(src) as zin, zipfile.ZipFile(broken_dir / src.name, "w") as zout:
        for item in zin.infolist():
            if item.filename == CAPABILITIES:
                continue
            zout.writestr(item, zin.read(item.filename))

    res = subprocess.run([sys.executable, str(CHECKER), str(broken_dir)], capture_output=True, text=True)
    assert res.returncode != 0, "checker passed a wheel with the capabilities file removed"
    assert CAPABILITIES in res.stderr
