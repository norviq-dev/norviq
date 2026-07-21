#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Assert a built wheel/sdist actually contains the runtime assets the code loads.

`twine check` validates metadata and that the README renders; it never looks inside the archive. So
a packaging regression — e.g. dropping [tool.setuptools.package-data] — produces a wheel that passes
every existing gate, imports fine, and then silently skips a security check at runtime. PyPI does
not allow re-uploading a version, so this must fail BEFORE the upload, not after.

Usage: check_wheel_contents.py [dist_dir]
"""
from __future__ import annotations

import sys
import tarfile
import zipfile
from pathlib import Path

# Files that must be inside the distributions, as paths relative to the package root.
REQUIRED = ("norviq/engine/opa-capabilities.json",)


def main() -> int:
    dist = Path(sys.argv[1] if len(sys.argv) > 1 else "dist")
    wheels = sorted(dist.glob("*.whl"))
    sdists = sorted(dist.glob("*.tar.gz"))
    if not wheels or not sdists:
        print(f"no distributions found in {dist}/ (wheels={len(wheels)} sdists={len(sdists)})", file=sys.stderr)
        return 1

    failures: list[str] = []

    for whl in wheels:
        names = set(zipfile.ZipFile(whl).namelist())
        for req in REQUIRED:
            if req not in names:
                failures.append(f"{whl.name}: missing {req}")

    for sd in sdists:
        with tarfile.open(sd) as tf:
            # sdist entries are prefixed with "<name>-<version>/"
            names = {n.split("/", 1)[1] for n in tf.getnames() if "/" in n}
        for req in REQUIRED:
            if req not in names:
                failures.append(f"{sd.name}: missing {req}")

    if failures:
        print("Distribution is missing runtime assets:", file=sys.stderr)
        for f in failures:
            print(f"  {f}", file=sys.stderr)
        print(
            "\nFix: declare the file under [tool.setuptools.package-data] in pyproject.toml.\n"
            "This gate exists because the affected check fails OPEN when its data file is absent,\n"
            "so a broken wheel looks healthy at import time.",
            file=sys.stderr,
        )
        return 1

    print(f"distributions OK: {len(wheels)} wheel(s), {len(sdists)} sdist(s), all {len(REQUIRED)} asset(s) present")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
