# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""security.yml's deps-audit job must audit what ships and every optional extra.

SECURITY.md said the optional extras "are audited with `uv export --extra <name>`". No job did it:
pip-audit and FOSSA both read the runtime export only. On 2026-10-30 an audit by hand found 69
advisory matches in the extras that a version bump could close, and nothing in CI had reported one.
The job is report-only, and these tests do not change that; they hold what it reads.
"""

from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path

import yaml

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "scripts"))

from check_fossa_issues import ACCEPTED  # noqa: E402

_SHIPPED = "pip-audit (shipped closure)"
_EXTRAS = "pip-audit (each optional extra)"


def _steps() -> list[dict]:
    wf = yaml.safe_load((_ROOT / ".github/workflows/security.yml").read_text())
    return wf["jobs"]["deps-audit"]["steps"]


def _step(name: str) -> dict:
    found = [s for s in _steps() if s.get("name") == name]
    assert len(found) == 1, f"deps-audit has {len(found)} steps named {name!r}"
    return found[0]


def _export_args(script: str, out: str) -> str:
    m = re.search(rf"uv export ([^\n>]*)>\s*\"?{re.escape(out)}\"?", script)
    assert m, f"no `uv export ... > {out}` in the step"
    return " ".join(m.group(1).split())


def test_the_shipped_closure_audit_reads_the_export_fossa_scans() -> None:
    """Its comment says it is the same export fossa.yml uses, and fossa.yml's is held to the images'
    extras by tests/test_fossa_config.py. When only one of the two moved, they audited different sets."""
    fossa = (_ROOT / ".github/workflows/fossa.yml").read_text()
    shipped = _export_args(_step(_SHIPPED)["run"], "requirements-runtime.txt")
    assert shipped == _export_args(fossa, "requirements-runtime.txt")


def test_every_optional_extra_is_audited() -> None:
    script = _step(_EXTRAS)["run"]
    m = re.search(r"for extra in ([a-z0-9 -]+); do", script)
    assert m, "the extras step no longer loops over a list of extras"
    audited = set(m.group(1).split())
    declared = set(tomllib.loads((_ROOT / "pyproject.toml").read_text())["project"]["optional-dependencies"])
    assert audited == declared, (
        f"audited only: {sorted(audited - declared)}; never audited: {sorted(declared - audited)}"
    )
    args = _export_args(script, "requirements-$extra.txt")
    assert '--extra "$extra"' in args and "--frozen" in args, args
    assert re.search(r'pip-audit [^\n]*-r "requirements-\$extra\.txt"', script), "the export is not what gets audited"


def test_a_finding_in_the_shipped_closure_does_not_skip_the_extras() -> None:
    """A failed step skips every later step without `if:`. The extras audit is the last step and runs
    regardless, so one report never hides the other."""
    assert _step(_EXTRAS).get("if") == "always()"
    assert _steps()[-1].get("name") == _EXTRAS


def test_only_reviewed_advisories_are_ignored_and_never_in_what_ships() -> None:
    """The extras audit ignores the FOSSA gate's allow-list, the ids SECURITY.md writes up, so it turns
    red on an advisory nobody has reviewed. The shipped closure carries none of them and ignores nothing."""
    assert "--ignore-vuln" not in _step(_SHIPPED)["run"]
    script = _step(_EXTRAS)["run"]
    assert "from check_fossa_issues import ACCEPTED" in script, "the ignores no longer come from ACCEPTED"
    assert not re.findall(r"--ignore-vuln\s+[A-Z]", script), "an id is ignored that is not read from ACCEPTED"
    assert ACCEPTED, "ACCEPTED is empty, so the import in the step ignores nothing"
