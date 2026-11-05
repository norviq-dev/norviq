# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Every `NRVQ-*` code in the source must be listed in docs/error-codes.md, and only those.

The page's "Full Code Index" says it holds every `NRVQ-*` literal in `norviq/**/*.py`, `webhook/*.go`
and `ui/src/**`, test files excluded. Nothing checked that. On 2026-11-04 the index held 538 codes and
the source carried 554: fifteen `NRVQ-MCP-50xx` codes and `NRVQ-SDK-1016` had shipped without being
added, and the page said so in a sentence instead of listing them.

This test builds the same set the page describes and compares it with the fenced block under
"## Full Code Index", both ways: a code in the source that the index lacks fails, and so does a code
in the index that the source no longer carries.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
DOC = REPO / "docs" / "error-codes.md"

# `NRVQ-API-7000`, `NRVQ-API-7050-ERR`, `NRVQ-ENG-DEBUG-OPA-IN`. A regex in the UI that matches codes
# (`/NRVQ-[A-Z]+-\d+/`) does not match: `[` follows the first hyphen.
CODE = re.compile(r"NRVQ-[A-Z]+(?:-[A-Z0-9]+)+")

SOURCES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("norviq", ("**/*.py",)),
    ("webhook", ("*.go",)),
    ("ui/src", ("**/*.ts", "**/*.tsx", "**/*.js", "**/*.jsx")),
)


def _is_test(path: Path) -> bool:
    # Judge the path relative to the repo root: a checkout that sits under a directory named `tests`
    # must not have every source file excluded.
    parts = path.relative_to(REPO).parts
    name = path.name
    return (
        "tests" in parts
        or "__tests__" in parts
        or name.startswith("test_")
        or name == "conftest.py"
        or name.endswith("_test.go")
        or ".test." in name
        or ".spec." in name
    )


def source_codes() -> dict[str, str]:
    """Each code mapped to the first `file:line` that carries it."""
    found: dict[str, str] = {}
    for root, patterns in SOURCES:
        for pattern in patterns:
            for path in sorted((REPO / root).glob(pattern)):
                if _is_test(path):
                    continue
                for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                    for code in CODE.findall(line):
                        found.setdefault(code, f"{path.relative_to(REPO)}:{lineno}")
    return found


def indexed_codes(text: str) -> set[str]:
    """The codes in the fenced block under "## Full Code Index"."""
    head, sep, section = text.partition("## Full Code Index")
    assert sep, "docs/error-codes.md has no '## Full Code Index' section"
    block = re.search(r"```text\n(.*?)```", section, re.S)
    assert block, "the Full Code Index section has no ```text block"
    return set(CODE.findall(block.group(1)))


def test_the_extractor_finds_codes():
    # A broken glob or regex would find nothing and make the checks below pass vacuously.
    codes = source_codes()
    assert len(codes) > 500, len(codes)
    assert "NRVQ-API-7000" in codes
    assert "NRVQ-WHK-4000" in codes
    assert "NRVQ-UI-4601" in codes


def test_every_code_in_the_source_is_indexed():
    codes = source_codes()
    missing = sorted(set(codes) - indexed_codes(DOC.read_text(encoding="utf-8")))
    assert not missing, (
        "codes emitted by the source but missing from the Full Code Index in docs/error-codes.md; "
        "add each to the index and describe it in its component's section:\n  "
        + "\n  ".join(f"{c}  ({codes[c]})" for c in missing)
    )


def test_every_indexed_code_is_in_the_source():
    stale = sorted(indexed_codes(DOC.read_text(encoding="utf-8")) - set(source_codes()))
    assert not stale, (
        "codes in the Full Code Index of docs/error-codes.md that no source file carries; remove "
        "them or restore the code:\n  " + "\n  ".join(stale)
    )


def test_the_summary_total_matches_the_index():
    text = DOC.read_text(encoding="utf-8")
    total = re.search(r"Total unique codes: \*\*(\d+)\*\*", text)
    assert total, "docs/error-codes.md lost its 'Total unique codes' line"
    assert int(total.group(1)) == len(indexed_codes(text))
