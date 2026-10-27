# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""CI must lint with the ruff the lockfile pins.

The lint job installed ruff unpinned. The locked 0.15.21 reports 0 findings on this tree; 0.16.0
reports 930 and 0.17.3 reports 1,098. So the job's verdict depended on which ruff PyPI served that
morning, and its first real run failed before gofmt, go vet, go test and tsc ever executed.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent


def _locked(name: str) -> str:
    lock = tomllib.loads((_ROOT / "uv.lock").read_text())
    versions = {p["version"] for p in lock["package"] if p["name"] == name}
    assert len(versions) == 1, f"uv.lock holds {sorted(versions)} for {name}"
    return versions.pop()


def _ruff_install_specs(workflow: str) -> list[str]:
    """The ruff requirement specs `pip install` is given — the package arguments only.

    Parsed per command, stopping at `&&`, `;` or `|`. A first version regex-matched "ruff" anywhere after
    `pip install` on the line, so it matched the trailing `&& ruff check` and failed on a correctly
    pinned workflow — and its two controls then failed for that reason, not the ones they were for.
    """
    specs = []
    for line in workflow.splitlines():
        for cmd in re.split(r"&&|;|\|", line):
            m = re.search(r"\bpip install\b(.*)", cmd)
            if not m:
                continue
            for tok in m.group(1).split():
                tok = tok.strip("\"'")
                if re.match(r"ruff(\[|[=<>~!]|$)", tok):
                    specs.append(tok)
    return specs


def test_the_lint_job_installs_the_locked_ruff() -> None:
    specs = _ruff_install_specs((_ROOT / ".github/workflows/test.yml").read_text())
    assert specs, "test.yml no longer pip-installs ruff at all"
    unpinned = [s for s in specs if "==" not in s]
    assert not unpinned, f"test.yml installs ruff without an == pin: {unpinned}"
    versions = {s.split("==", 1)[1] for s in specs}
    assert versions == {_locked("ruff")}, f"test.yml pins ruff {sorted(versions)}, uv.lock has {_locked('ruff')}"
