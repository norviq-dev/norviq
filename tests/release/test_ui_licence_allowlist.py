# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Every npm package the UI ships must be licensable under Apache-2.0 or the CNCF allowlist.

The CNCF Allowlist License Policy approves a third-party component automatically only when it is fully
licensable under Apache-2.0 or one of the allowlisted licenses. Anything else needs a Governing Board
exception. The UI shipped one font package under OFL-1.1, and the d3 umbrella package pulled in a
geometry library under the Unlicense; neither license is on the allowlist and nothing in CI noticed.

This reads ui/package-lock.json, the tree `npm ci` installs in Dockerfile.ui, and checks every package
that is not dev-only (dev-only packages build the bundle and are not shipped in it). A package with no
recorded license fails: an unknown license is not an allowed one.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent.parent
_LOCK = _ROOT / "ui" / "package-lock.json"

# Apache-2.0 plus "Approved Licenses for Allowlist" in cncf/foundation
# policies-guidance/allowed-third-party-license-policy.md (fetched 2026-11-04). Extend it only when that
# list grows; a component under any other license needs a CNCF exception first, not an entry here.
_ALLOWED = frozenset(
    {
        "Apache-2.0",
        "0BSD",
        "BSD-2-Clause",
        "BSD-2-Clause-FreeBSD",
        "BSD-3-Clause",
        "MIT",
        "MIT-0",
        "ISC",
        "OpenSSL",
        "OpenSSL-standalone",
        "PSF-2.0",
        "Python-2.0",
        "Python-2.0.1",
        "PostgreSQL",
        "SSLeay-standalone",
        "UPL-1.0",
        "X11",
        "Zlib",
    }
)

_TOKEN = re.compile(r"\(|\)|[A-Za-z0-9.+-]+")


def _satisfiable(expression: str) -> bool:
    """True when the SPDX expression can be met using allowed licenses only.

    OR needs one allowed side, AND needs both, WITH (an exception clause) is not accepted: fail closed.
    """
    tokens = _TOKEN.findall(expression)
    if "".join(tokens) != re.sub(r"\s+", "", expression):
        return False
    pos = 0

    def parse_or() -> bool:
        nonlocal pos
        result = parse_and()
        while pos < len(tokens) and tokens[pos] == "OR":
            pos += 1
            rhs = parse_and()
            result = result or rhs
        return result

    def parse_and() -> bool:
        nonlocal pos
        result = parse_atom()
        while pos < len(tokens) and tokens[pos] == "AND":
            pos += 1
            rhs = parse_atom()
            result = result and rhs
        return result

    def parse_atom() -> bool:
        nonlocal pos
        if pos >= len(tokens):
            raise ValueError(expression)
        token = tokens[pos]
        pos += 1
        if token == "(":
            result = parse_or()
            if pos >= len(tokens) or tokens[pos] != ")":
                raise ValueError(expression)
            pos += 1
            return result
        if token in {")", "AND", "OR", "WITH"}:
            raise ValueError(expression)
        return token in _ALLOWED

    try:
        result = parse_or()
    except ValueError:
        return False
    return result and pos == len(tokens)


def _shipped_packages() -> dict[str, dict]:
    lock = json.loads(_LOCK.read_text())
    assert lock.get("lockfileVersion", 0) >= 2, "ui/package-lock.json must record per-package metadata"
    return {
        path: meta
        for path, meta in lock["packages"].items()
        if path and not meta.get("dev") and not meta.get("devOptional")
    }


def test_shipped_ui_packages_are_on_the_cncf_allowlist() -> None:
    shipped = _shipped_packages()
    assert shipped, "no non-dev packages found in ui/package-lock.json"
    offenders = sorted(
        f"{path.removeprefix('node_modules/')}@{meta.get('version')}: {meta.get('license')}"
        for path, meta in shipped.items()
        if not _satisfiable(str(meta.get("license") or ""))
    )
    assert not offenders, "UI runtime packages outside the CNCF license allowlist:\n" + "\n".join(offenders)


@pytest.mark.parametrize(
    ("expression", "expected"),
    [
        ("MIT", True),
        ("(MPL-2.0 OR Apache-2.0)", True),
        ("Apache-2.0 AND MIT", True),
        ("OFL-1.1", False),
        ("Unlicense", False),
        ("MPL-2.0", False),
        ("MIT AND OFL-1.1", False),
        ("(MIT OR CC0-1.0) AND Unlicense", False),
        ("Apache-2.0 WITH LLVM-exception", False),
        ("", False),
        ("MIT OR", False),
        ("(MIT", False),
        ("MIT; OFL-1.1", False),
    ],
)
def test_license_expression_check_fails_closed(expression: str, expected: bool) -> None:
    assert _satisfiable(expression) is expected
