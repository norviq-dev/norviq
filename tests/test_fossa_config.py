# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Every analysis target .fossa.yml names must be one fossa-cli can actually discover.

`targets.only` is a filter, and a filter that matches nothing does not fail. The Python target said
`type: pip`. fossa-cli has no such type, so from 2026-08-19 every FOSSA run analysed two projects
(npm, gomod), printed "2 projects scanned", and the dependency gate passed without grading one Python
package. The job log said so and nothing read it.

Matching is not the end of it. The target must be fed what ships (the images install `.[spiffe]`, and
the export left the extra out), and fossa-cli must be able to read every line of it.
"""

from __future__ import annotations

import re
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest
import yaml

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "scripts"))

from check_fossa_requirements import is_discovered, normalise  # noqa: E402

# fossa-cli's project types, verbatim from `projectTypeToText` in src/Types.hs at v3.20.8 (the CLI
# fossa-action installed in the 2026-10-27 run). A type outside this set can never match a target.
# If a newer CLI adds one, check its Types.hs and extend the list; do not loosen the assertion.
_FOSSA_PROJECT_TYPES = frozenset(
    {
        "apkdb",
        "berkeleydb",
        "binary-deps",
        "bun",
        "bundler",
        "cabal",
        "cargo",
        "carthage",
        "cocoapods",
        "conan",
        "composer",
        "conda",
        "dpkgdb",
        "fpm",
        "glide",
        "gobinary",
        "godep",
        "gomod",
        "gradle",
        "leiningen",
        "maven",
        "mix",
        "ndb",
        "nimble",
        "npm",
        "nuget",
        "nuspec",
        "packagereference",
        "packagesconfig",
        "paket",
        "pdm",
        "perl",
        "pipenv",
        "pnpm",
        "poetry",
        "projectassetsjson",
        "projectjson",
        "pub",
        "rebar3",
        "renv",
        "repomanifest",
        "rpm",
        "scala",
        "setuptools",
        "sqlitedb",
        "stack",
        "swift",
        "uv",
        "vsi",
        "yarn",
    }
)
_IMAGES = ("Dockerfile.api", "Dockerfile.engine")


def _targets() -> list[dict]:
    return yaml.safe_load((_ROOT / ".fossa.yml").read_text())["targets"]["only"]


def _python_target() -> dict:
    python = [t for t in _targets() if t["type"] in {"setuptools", "pipenv", "poetry", "pdm", "uv", "conda"}]
    assert len(python) == 1, f"expected exactly one Python target, found {python}"
    return python[0]


def _workflow() -> str:
    return (_ROOT / ".github/workflows/fossa.yml").read_text()


def _pyproject() -> dict:
    return tomllib.loads((_ROOT / "pyproject.toml").read_text())


def _req_name(spec: str) -> str:
    return normalise(re.match(r"[A-Za-z0-9][A-Za-z0-9._-]*", spec).group(0))


def _export_extras(workflow: str) -> list[set[str]]:
    """The `--extra` set of every `uv export` that writes the runtime requirements file."""
    commands = re.findall(r"uv export ([^\n>]*)>\s*requirements-runtime\.txt", workflow)
    assert commands, "the workflow no longer exports requirements-runtime.txt"
    for cmd in commands:
        assert "--all-extras" not in cmd, f"{cmd!r} exports every extra; the images install a chosen few"
    return [set(re.findall(r"--extra[ =]([A-Za-z0-9_-]+)", cmd)) for cmd in commands]


def _image_installs() -> tuple[set[str], set[str]]:
    """(extras, other packages) the shipped images pip-install alongside the project."""
    extras: set[str] = set()
    others: set[str] = set()
    for dockerfile in _IMAGES:
        text = (_ROOT / dockerfile).read_text()
        projects = 0
        for cmd in re.findall(r"pip install ([^\n&;|]*)", text):
            for tok in (t.strip("'\"") for t in cmd.split()):
                if tok.startswith("-") or tok.startswith("/"):
                    continue  # options, and --target's directory
                m = re.fullmatch(r"\.(?:\[([^\]]*)\])?", tok)
                if m:
                    projects += 1
                    extras |= {e.strip() for e in (m.group(1) or "").split(",") if e.strip()}
                else:
                    others.add(_req_name(tok))
        assert projects == 1, f"{dockerfile}: expected one `pip install` of the project, found {projects}"
    return extras, others


def test_every_target_type_is_one_fossa_cli_has() -> None:
    unknown = [t["type"] for t in _targets() if t["type"] not in _FOSSA_PROJECT_TYPES]
    assert not unknown, f".fossa.yml names target types fossa-cli does not have, so they match nothing: {unknown}"


def test_the_python_target_discovers_the_file_the_workflow_generates() -> None:
    python = _python_target()
    assert python["type"] == "setuptools", "the runtime closure is a requirements file: setuptools reads it"
    generated = re.findall(r"uv export [^\n]*>\s*(\S+)", _workflow())
    assert generated, "fossa.yml no longer exports the runtime closure"
    for path in map(Path, generated):
        assert path.parent == Path(python["path"]), f"{path} is generated outside the target's directory"
        assert is_discovered(path.name), f"fossa-cli's setuptools discovery does not read {path.name}"


def test_no_committed_file_is_read_beside_the_generated_one() -> None:
    """setuptools reads EVERY file at the target path with "req" in its name and a .txt suffix. A
    committed `requirements-dev.txt` at the root would be graded as though it shipped, and the
    must/never checks only look at the generated file."""
    target = Path(_python_target()["path"])
    try:
        tracked = subprocess.run(
            ["git", "ls-files", "--", str(target)], cwd=_ROOT, capture_output=True, text=True, check=True
        ).stdout.split()
    except (OSError, subprocess.CalledProcessError) as exc:
        pytest.skip(f"not a git checkout: {exc}")
    read = [p for p in tracked if Path(p).parent == target and is_discovered(Path(p).name)]
    assert not read, f"fossa-cli would also read these committed files at {target}/: {read}"


def test_the_workflow_fails_when_a_target_was_not_analysed() -> None:
    """The type check above catches a typo; this catches everything else that makes a target silently
    vanish (default path filters, a renamed file, a discovery change in a new CLI)."""
    m = re.search(r'for t in ([a-z0-9 -]+); do\s+grep -qE "\\\* \$\{t\} project in', _workflow())
    assert m, "fossa.yml no longer asserts which projects the scan summary lists"
    asserted = set(m.group(1).split())
    configured = {t["type"] for t in _targets()}
    assert asserted == configured, f"fossa.yml asserts {sorted(asserted)} but .fossa.yml targets {sorted(configured)}"


def test_the_scanned_closure_is_what_the_images_install() -> None:
    """The export said `uv export --no-dev`, and both images install `.[spiffe]`. So FOSSA graded 60
    packages where the images carry 64 (spiffe, pem, pyasn1, pyasn1-modules), and protobuf 5.29.6 where
    the images get 7.35.1, because spiffe resolves in a fork of its own."""
    extras, others = _image_installs()
    assert extras, "the images no longer install any extra; check that this test still parses them"
    for exported in _export_extras(_workflow()):
        assert exported == extras, f"fossa.yml exports extras {sorted(exported)}; the images install {sorted(extras)}"
    base = {_req_name(d) for d in _pyproject()["project"]["dependencies"]}
    assert others <= base, f"the images also install {sorted(others - base)}, which no export includes"


def test_the_workflow_requires_each_installed_extra_in_the_export() -> None:
    """The test above holds the command; this holds the run-time check, so an export that silently
    lost the extra (a renamed extra, a resolver fork) fails in CI instead of scanning less."""
    m = re.search(r'MUST="([^"]+)"', _workflow())
    assert m, "fossa.yml no longer names the packages the export must contain"
    must = set(m.group(1).split())
    extras, _ = _image_installs()
    declared = _pyproject()["project"]["optional-dependencies"]
    needed = {_req_name(spec) for e in extras for spec in declared[e]}
    assert needed <= must, f"fossa.yml does not require {sorted(needed - must)}, which the images install"
    assert "fastapi" in must


def test_the_workflow_checks_what_fossa_cli_will_read_before_the_scan() -> None:
    """The summary assertion proves the setuptools project succeeded, which it also does with zero
    dependencies: fossa-cli's requirements parser drops lines it cannot parse. The check has to read
    the target fossa-cli reads, for the packages the export must hold, before `fossa analyze`."""
    wf = _workflow()
    m = re.search(r"python3 scripts/check_fossa_requirements\.py (\S+) \$MUST", wf)
    assert m, "fossa.yml no longer checks the Python input the way fossa-cli will read it"
    assert Path(m.group(1)) == Path(_python_target()["path"]), (
        f"the check reads {m.group(1)!r}; the setuptools target is {_python_target()['path']!r}"
    )
    assert m.start() < wf.index("uses: fossas/fossa-action@"), "the input check runs after the scan uploaded"
