# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Every analysis target .fossa.yml names must be one fossa-cli can actually discover.

`targets.only` is a filter, and a filter that matches nothing does not fail. The Python target said
`type: pip`. fossa-cli has no such type, so from 2026-08-19 every FOSSA run analysed two projects
(npm, gomod), printed "2 projects scanned", and the dependency gate passed without grading one Python
package. The job log said so and nothing read it.
"""

from __future__ import annotations

import fnmatch
import re
from pathlib import Path

import yaml

_ROOT = Path(__file__).resolve().parent.parent

# fossa-cli's project types, verbatim from `projectTypeToText` in src/Types.hs at v3.20.8 (the CLI
# fossa-action installed in the 2026-10-27 run). A type outside this set can never match a target.
# If a newer CLI adds one, check its Types.hs and extend the list; do not loosen the assertion.
_FOSSA_PROJECT_TYPES = frozenset({
    "apkdb", "berkeleydb", "binary-deps", "bun", "bundler", "cabal", "cargo", "carthage", "cocoapods",
    "conan", "composer", "conda", "dpkgdb", "fpm", "glide", "gobinary", "godep", "gomod", "gradle",
    "leiningen", "maven", "mix", "ndb", "nimble", "npm", "nuget", "nuspec", "packagereference",
    "packagesconfig", "paket", "pdm", "perl", "pipenv", "pnpm", "poetry", "projectassetsjson",
    "projectjson", "pub", "rebar3", "renv", "repomanifest", "rpm", "scala", "setuptools", "sqlitedb",
    "stack", "swift", "uv", "vsi", "yarn",
})
# setuptools project discovery (docs/references/strategies/languages/python/setuptools.md).
_SETUPTOOLS_GLOB = "req*.txt"


def _targets() -> list[dict]:
    return yaml.safe_load((_ROOT / ".fossa.yml").read_text())["targets"]["only"]


def _workflow() -> str:
    return (_ROOT / ".github/workflows/fossa.yml").read_text()


def test_every_target_type_is_one_fossa_cli_has() -> None:
    unknown = [t["type"] for t in _targets() if t["type"] not in _FOSSA_PROJECT_TYPES]
    assert not unknown, f".fossa.yml names target types fossa-cli does not have, so they match nothing: {unknown}"


def test_the_python_target_discovers_the_file_the_workflow_generates() -> None:
    python = [t for t in _targets() if t["type"] in {"setuptools", "pipenv", "poetry", "pdm", "uv", "conda"}]
    assert len(python) == 1, f"expected exactly one Python target, found {python}"
    assert python[0]["type"] == "setuptools", "the runtime closure is a requirements file: setuptools reads it"
    generated = re.findall(r"uv export [^\n]*>\s*(\S+)", _workflow())
    assert generated, "fossa.yml no longer exports the runtime closure"
    for path in map(Path, generated):
        assert path.parent == Path(python[0]["path"]), f"{path} is generated outside the target's directory"
        assert fnmatch.fnmatch(path.name, _SETUPTOOLS_GLOB), f"{path.name} is not discovered by {_SETUPTOOLS_GLOB}"


def test_the_workflow_fails_when_a_target_was_not_analysed() -> None:
    """The type check above catches a typo; this catches everything else that makes a target silently
    vanish (default path filters, a renamed file, a discovery change in a new CLI)."""
    m = re.search(r'for t in ([a-z0-9 -]+); do\s+grep -qE "\\\* \$\{t\} project in', _workflow())
    assert m, "fossa.yml no longer asserts which projects the scan summary lists"
    asserted = set(m.group(1).split())
    configured = {t["type"] for t in _targets()}
    assert asserted == configured, f"fossa.yml asserts {sorted(asserted)} but .fossa.yml targets {sorted(configured)}"
