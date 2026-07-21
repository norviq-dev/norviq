#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Fail if the four places that carry Norviq's version disagree.

    git tag v0.2.0
    helm/norviq/Chart.yaml  version: 0.1.0      <- publishes a chart labelled 0.1.0
    helm/norviq/Chart.yaml  appVersion: "0.1.0" <- reported by app.kubernetes.io/version
    pyproject.toml          version = "0.1.0"   <- uploads a wheel labelled 0.1.0

Nothing else reconciles these, and PyPI will not let you re-upload a version to correct it. So this
runs as gate 0 of the release (before anything is built or pushed) and, without an argument, as an
ordinary unit test so drift is caught on the PR that introduces it rather than at the tag.

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


def collect() -> dict[str, str]:
    return {
        "helm/norviq/Chart.yaml:version": _grab(ROOT / "helm/norviq/Chart.yaml", r"^version:\s*(\S+)"),
        "helm/norviq/Chart.yaml:appVersion": _grab(ROOT / "helm/norviq/Chart.yaml", r"^appVersion:\s*(\S+)"),
        "pyproject.toml:version": _grab(ROOT / "pyproject.toml", r'^version\s*=\s*"([^"]+)"'),
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
            "not allow re-uploading a version to correct it.",
            file=sys.stderr,
        )
        return 1

    print(f"version OK: {distinct[0]} (" + ", ".join(found) + ")")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
