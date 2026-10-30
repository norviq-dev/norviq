# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Every place that pins the `mcp` SDK must pin it the same way.

The `mcp` floor is a security floor (pyproject.toml, the crewai extra), and it is written five times:
the `crewai`, `mcp` and `frameworks` extras, and the chatbot example's two requirements files.
requirements-mcp.txt says in its own header that it matches the extra on purpose. The firewall sidecar
and the demo servers have to agree on the protocol revision, and when they do not, the error reads like
a policy failure. Nothing checked any of this. When the extras moved from 1.28.1 to 1.30.0 (four CVEs
open on the 1.29.0 the lock held), both example files still said 1.28.1. The images built from them
would have stayed open to those CVEs while every audit of the lock came back clean.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_EXAMPLES = ("examples/chatbot/requirements.txt", "examples/chatbot/requirements-mcp.txt")


def _mcp_spec(requirements: list[str]) -> str:
    specs = [re.sub(r"\s+", "", r)[len("mcp"):] for r in requirements if re.match(r"mcp\s*[<>=~!]", r)]
    assert len(specs) == 1, f"expected exactly one mcp requirement, found {specs}"
    return ",".join(sorted(specs[0].split(",")))


def _extras() -> dict[str, list[str]]:
    return tomllib.loads((_ROOT / "pyproject.toml").read_text())["project"]["optional-dependencies"]


def _requirements_file(rel: str) -> list[str]:
    lines = (_ROOT / rel).read_text().splitlines()
    return [ln.split("#", 1)[0].strip() for ln in lines if ln.split("#", 1)[0].strip()]


def test_the_extras_declare_one_mcp_floor() -> None:
    extras = _extras()
    specs = {name: _mcp_spec(extras[name]) for name in ("crewai", "mcp", "frameworks")}
    assert len(set(specs.values())) == 1, f"the extras disagree on the mcp pin: {specs}"


def test_the_chatbot_example_pins_mcp_exactly_as_the_extra_does() -> None:
    want = _mcp_spec(_extras()["mcp"])
    got = {rel: _mcp_spec(_requirements_file(rel)) for rel in _EXAMPLES}
    stale = {rel: spec for rel, spec in got.items() if spec != want}
    assert not stale, f"the mcp extra pins {want!r}; these files do not: {stale}"
