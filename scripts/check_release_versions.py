#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Fail if the places that carry Norviq's version disagree.

    git tag v0.2.0
    helm/norviq/Chart.yaml  version: 0.1.0      <- publishes a chart labelled 0.1.0
    helm/norviq/Chart.yaml  appVersion: "0.1.0" <- reported by app.kubernetes.io/version
    pyproject.toml          version = "0.1.0"   <- uploads a wheel labelled 0.1.0
    *.md   helm install ... charts/norviq --version 0.1.0   <- what a user actually runs

Nothing else reconciles these, and PyPI will not let you re-upload a version to correct it. So this
runs as gate 0 of the release (before anything is built or pushed) and, without an argument, as an
ordinary unit test so drift is caught on the PR that introduces it rather than at the tag.

The docs are checked because they stopped being prose: since the install instructions moved from a
local clone to `oci://.../charts/norviq --version <x.y.z>`, a stale number there is a command that
fails outright for every reader — there is no repo to fall back to. Only literal versions are
compared; `$VERSION` / `<x.y.z>` placeholders are skipped on purpose.

Usage:
    check_release_versions.py            # all files must agree with each other
    check_release_versions.py 0.1.0      # ...and with this expected version (the git tag)
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _grab(path: Path, pattern: str) -> str:
    m = re.search(pattern, path.read_text(), re.M)
    if not m:
        sys.exit(f"{path}: no line matching {pattern!r}")
    return m.group(1).strip().strip('"').strip("'")


DOC_ROOTS = ("README.md", "SECURITY.md", "CONTRIBUTING.md", "docs", "helm")

# `charts/norviq --version 0.1.5`, `charts/norviq:0.1.5`, `charts/norviq@0.1.5`.
_CHART_REF = re.compile(r"charts/norviq(?:[:@]|\s+--version[= ])(\S+?)(?=[\s`'\"\\]|$)")
_SEMVER = re.compile(r"^\d+\.\d+\.\d+$")


def _doc_files() -> list[Path]:
    out: list[Path] = []
    for entry in DOC_ROOTS:
        p = ROOT / entry
        if p.is_file():
            out.append(p)
        elif p.is_dir():
            out.extend(sorted(q for q in p.rglob("*.md") if "node_modules" not in q.parts))
    return out


def collect_docs() -> dict[str, str]:
    """Every LITERAL chart version a reader could copy-paste, keyed by file:line."""
    found: dict[str, str] = {}
    for path in _doc_files():
        for lineno, line in enumerate(path.read_text().splitlines(), 1):
            for ref in _CHART_REF.findall(line):
                # `$VERSION`, `"$VERSION"`, `<x.y.z>` are templates, not claims about a release.
                if _SEMVER.match(ref):
                    found[f"{path.relative_to(ROOT)}:{lineno}"] = ref
    return found


def collect() -> dict[str, str]:
    return {
        "helm/norviq/Chart.yaml:version": _grab(ROOT / "helm/norviq/Chart.yaml", r"^version:\s*(\S+)"),
        "helm/norviq/Chart.yaml:appVersion": _grab(ROOT / "helm/norviq/Chart.yaml", r"^appVersion:\s*(\S+)"),
        "pyproject.toml:version": _grab(ROOT / "pyproject.toml", r'^version\s*=\s*"([^"]+)"'),
        **collect_docs(),
    }


def main() -> int:
    found = collect()
    expected = sys.argv[1].lstrip("v") if len(sys.argv) > 1 else None
    if expected:
        found["git tag"] = expected

    distinct = sorted(set(found.values()))
    if len(distinct) != 1:
        print("Version drift — these must all be identical:", file=sys.stderr)
        width = max(len(k) for k in found)
        for k, v in found.items():
            print(f"  {k:<{width}}  {v}", file=sys.stderr)
        print(
            "\nFix: make every file agree before tagging. A tag is the release; a mismatch would\n"
            "publish a chart and a wheel labelled with a version nobody asked for, and PyPI does\n"
            "not allow re-uploading a version to correct it. The *.md entries are install commands\n"
            "readers copy-paste: a version that was never published fails at `helm install` with no\n"
            "repo to fall back to.",
            file=sys.stderr,
        )
        return 1

    docs = collect_docs()
    print(f"version OK: {distinct[0]} ({len(found) - len(docs)} manifest + {len(docs)} doc reference(s))")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
