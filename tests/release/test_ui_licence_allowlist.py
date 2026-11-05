# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Every npm package the UI ships must be licensable under Apache-2.0 or the CNCF allowlist.

The CNCF Allowlist License Policy approves a third-party component automatically only when it is fully
licensable under Apache-2.0 or one of the allowlisted licenses. Anything else needs a Governing Board
exception. The UI shipped one font package under OFL-1.1, and the d3 umbrella package pulled in a
geometry library under the Unlicense; neither license is on the allowlist and nothing in CI noticed.

This reads ui/package-lock.json, the tree `npm ci` installs in Dockerfile.ui, and checks every package
that can reach the bundle: every package that is not dev-only, plus the dev-only packages the build
compiles into its output anyway. Those are each package named in an @import of ui/src/index.css
(tailwindcss, shadcn: their CSS is compiled into the shipped stylesheet) and the build-time emitters
listed in scripts/ui_third_party_notices.py (BUILD_TIME_EMITTERS), so this test and the notices file
cover the same set. A package with no recorded license fails: an unknown license is not an allowed one.

Font files committed into the UI source tree are checked too: Vite copies ui/public into the bundle
verbatim and imported assets are emitted alongside it, so a font file anywhere under ui/ ships in the
image without appearing in the lockfile. The Outfit typeface (OFL-1.1) shipped that way. A font file
fails unless _FONT_LICENSES lists it with an allowlisted license.
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent.parent
_UI = _ROOT / "ui"
_LOCK = _UI / "package-lock.json"

# The notices generator owns the definition of "reaches the bundle"; load it by path (scripts/ is not
# a package) so the licence check and ui/THIRD_PARTY_NOTICES.txt cannot drift apart.
_spec = importlib.util.spec_from_file_location("_ui_notices", _ROOT / "scripts" / "ui_third_party_notices.py")
assert _spec and _spec.loader
_notices = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_notices)

_FONT_SUFFIXES = frozenset({".ttf", ".otf", ".ttc", ".woff", ".woff2", ".eot", ".pfb", ".pfa"})
# Directories under ui/ that are not committed sources: installed packages (covered by the lockfile
# check above) and build output generated from the sources.
_NOT_SOURCES = frozenset({"node_modules", "dist", "coverage"})
# Font files the UI may ship, by path relative to ui/, with the SPDX license each is under. Empty: the
# console uses the platform's own font stacks. An entry needs a license _satisfiable() accepts.
_FONT_LICENSES: dict[str, str] = {}

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


def _shipped_packages(ui: Path = _UI, lock_path: Path = _LOCK) -> dict[str, dict]:
    lock = json.loads(lock_path.read_text())
    assert lock.get("lockfileVersion", 0) >= 2, "ui/package-lock.json must record per-package metadata"
    return _notices.bundle_packages(ui, lock["packages"])


def _licence_offenders(shipped: dict[str, dict]) -> list[str]:
    return sorted(
        f"{path.removeprefix('node_modules/')}@{meta.get('version')}: {meta.get('license')}"
        for path, meta in shipped.items()
        if not _satisfiable(str(meta.get("license") or ""))
    )


def test_shipped_ui_packages_are_on_the_cncf_allowlist() -> None:
    shipped = _shipped_packages()
    assert shipped, "no non-dev packages found in ui/package-lock.json"
    offenders = _licence_offenders(shipped)
    assert not offenders, "UI packages that reach the bundle outside the CNCF license allowlist:\n" + "\n".join(
        offenders
    )


def test_dev_packages_compiled_into_the_bundle_are_checked() -> None:
    """tailwindcss and shadcn are devDependencies, but index.css @imports them into the shipped CSS."""
    shipped = _shipped_packages()
    for name in ("tailwindcss", "shadcn", "tw-animate-css", *_notices.BUILD_TIME_EMITTERS):
        assert f"node_modules/{name}" in shipped, f"{name} reaches the bundle but is not licence-checked"


def test_a_disallowed_licence_on_a_bundled_dev_package_fails(tmp_path: Path) -> None:
    """Control: the same lockfile with tailwindcss (dev: true) under a non-allowlisted licence."""
    lock = json.loads(_LOCK.read_text())
    assert lock["packages"]["node_modules/tailwindcss"].get("dev"), "control assumes tailwindcss is dev-only"
    lock["packages"]["node_modules/tailwindcss"]["license"] = "OFL-1.1"
    scratch = tmp_path / "package-lock.json"
    scratch.write_text(json.dumps(lock))
    offenders = _licence_offenders(_shipped_packages(_UI, scratch))
    assert any(o.startswith("tailwindcss@") for o in offenders), offenders


@pytest.mark.parametrize(
    ("css", "expected"),
    [
        ('@import "tailwindcss";', ["tailwindcss"]),
        ("@import 'shadcn/tailwind.css' layer(base);", ["shadcn"]),
        ('@import url("@scope/pkg/x.css");', ["@scope/pkg"]),
        ('@import "./local.css"; @import "@/styles/a.css"; /* @import "commented"; */', []),
        ('@import "https://example.invalid/x.css";', []),
    ],
)
def test_css_import_parsing(css: str, expected: list[str]) -> None:
    assert _notices.css_import_packages(css) == expected


def _font_offenders(root: Path, licenses: dict[str, str]) -> list[str]:
    offenders = []
    fonts = []
    for dirpath, dirnames, filenames in os.walk(root):
        # Pruned at ANY depth: an installed tree (e.g. ui/tests/e2e/node_modules, which the Playwright
        # harness installs) is judged by the lockfile check above, not as committed source.
        dirnames[:] = [d for d in dirnames if d not in _NOT_SOURCES]
        fonts.extend(Path(dirpath) / f for f in filenames if Path(f).suffix.lower() in _FONT_SUFFIXES)
    for path in sorted(fonts):
        key = path.relative_to(root).as_posix()
        license_ = licenses.get(key, "")
        if not _satisfiable(license_):
            offenders.append(f"{key}: {license_ or 'not listed in _FONT_LICENSES'}")
    return offenders


def test_ui_ships_no_font_file_outside_the_cncf_allowlist() -> None:
    offenders = _font_offenders(_UI, _FONT_LICENSES)
    assert not offenders, "font files under ui/ without an allowlisted license:\n" + "\n".join(offenders)


def test_font_check_flags_unlisted_and_disallowed_fonts(tmp_path: Path) -> None:
    (tmp_path / "public" / "fonts").mkdir(parents=True)
    (tmp_path / "public" / "fonts" / "Outfit-Regular.ttf").write_bytes(b"\x00\x01\x00\x00")
    (tmp_path / "src" / "assets").mkdir(parents=True)
    (tmp_path / "src" / "assets" / "Mono.WOFF2").write_bytes(b"wOF2")
    (tmp_path / "public" / "Listed.otf").write_bytes(b"OTTO")
    (tmp_path / "node_modules" / "pkg").mkdir(parents=True)
    (tmp_path / "node_modules" / "pkg" / "font.ttf").write_bytes(b"\x00\x01\x00\x00")
    licenses = {"public/fonts/Outfit-Regular.ttf": "OFL-1.1", "public/Listed.otf": "MIT"}
    assert _font_offenders(tmp_path, licenses) == [
        "public/fonts/Outfit-Regular.ttf: OFL-1.1",
        "src/assets/Mono.WOFF2: not listed in _FONT_LICENSES",
    ]


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


def test_a_nested_installed_tree_is_not_read_as_source(tmp_path: Path) -> None:
    """ui/tests/e2e/node_modules is installed by the Playwright harness and bundles a codicon font;
    it is not shipped. A committed font next to it still fails."""
    nested = tmp_path / "tests" / "e2e" / "node_modules" / "playwright-core"
    nested.mkdir(parents=True)
    (nested / "codicon.ttf").write_bytes(b"\x00\x01\x00\x00")
    assert _font_offenders(tmp_path, {}) == []
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "brand.woff2").write_bytes(b"wOF2")
    assert _font_offenders(tmp_path, {}) == ["src/brand.woff2: not listed in _FONT_LICENSES"]
