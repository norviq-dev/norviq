#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Stamp the chart for a release: version from the tag, images pinned to immutable digests.

Run by .github/workflows/release.yml between "images built" and "chart packaged". It exists as a
real script rather than an inline heredoc so it can be unit-tested (tests/release/) — a bug here
publishes a chart that points at the wrong binaries, which is exactly the class of mistake that is
permanent once pushed.

Edits are done with targeted regex rather than a YAML round-trip on purpose: values.yaml is heavily
commented and those comments are the chart's user documentation, which a PyYAML load/dump would
silently discard.

Usage:
    release_stamp.py <version> [--resolve|--digests engine=sha256:..,api=sha256:..,...]

`--resolve` looks each digest up from the registry with `docker buildx imagetools inspect`.
`--digests` takes them literally (used by tests, and for a rehearsal with no registry access).
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

COMPONENTS = ("engine", "api", "ui", "webhook")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")


def resolve_digest(repo: str, tag: str) -> str:
    """Ask the registry for the immutable index digest behind a tag."""
    out = subprocess.run(
        ["docker", "buildx", "imagetools", "inspect", "--format", "{{json .Manifest}}", f"{repo}:{tag}"],
        capture_output=True, text=True, check=True,
    ).stdout
    return json.loads(out)["digest"]


def stamp_chart(chart_yaml: Path, version: str) -> None:
    s = chart_yaml.read_text()
    s, n1 = re.subn(r"(?m)^version:.*$", f"version: {version}", s, count=1)
    s, n2 = re.subn(r"(?m)^appVersion:.*$", f'appVersion: "{version}"', s, count=1)
    if not (n1 and n2):
        sys.exit(f"{chart_yaml}: expected both a version: and an appVersion: line (got {n1}/{n2})")
    chart_yaml.write_text(s)


def stamp_values(values_yaml: Path, version: str, digests: dict[str, str]) -> None:
    s = values_yaml.read_text()
    for comp in COMPONENTS:
        digest = digests[comp]
        if not DIGEST_RE.match(digest):
            sys.exit(f"refusing to pin {comp}: {digest!r} is not a sha256 digest")
        # Anchor on the component block inside images:, then rewrite its tag and digest lines. The
        # non-greedy (?:    .*\n)*? keeps each substitution inside the one component block.
        tag_pat = re.compile(rf"(?m)^(  {comp}:\n(?:    [^\n]*\n)*?    tag: )[^\n]*$")
        dig_pat = re.compile(rf"(?m)^(  {comp}:\n(?:    [^\n]*\n)*?    digest: )[^\n]*$")
        s, nt = tag_pat.subn(rf"\g<1>{comp}-{version}", s, count=1)
        s, nd = dig_pat.subn(rf'\g<1>"{digest}"', s, count=1)
        if nt != 1 or nd != 1:
            sys.exit(f"{values_yaml}: could not locate images.{comp}.tag/.digest (tag={nt} digest={nd})")
    values_yaml.write_text(s)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("version")
    ap.add_argument("--chart-dir", default="helm/norviq")
    ap.add_argument("--repo", default="ghcr.io/norviq-dev/norviq-engine")
    ap.add_argument("--resolve", action="store_true", help="look digests up from the registry")
    ap.add_argument("--digests", default="", help="comp=sha256:... comma-separated (tests/rehearsal)")
    args = ap.parse_args()

    version = args.version.lstrip("v")
    if not SEMVER_RE.match(version):
        sys.exit(f"refusing to release {version!r}: not a semantic version (expected e.g. 0.1.0)")

    if args.resolve:
        digests = {c: resolve_digest(args.repo, f"{c}-{version}") for c in COMPONENTS}
    else:
        digests = dict(p.split("=", 1) for p in args.digests.split(",") if p)
        missing = [c for c in COMPONENTS if c not in digests]
        if missing:
            sys.exit(f"--digests is missing: {', '.join(missing)}")

    chart_dir = Path(args.chart_dir)
    stamp_chart(chart_dir / "Chart.yaml", version)
    stamp_values(chart_dir / "values.yaml", version, digests)
    for c in COMPONENTS:
        print(f"pinned {c}: {c}-{version} @ {digests[c]}")


if __name__ == "__main__":
    main()
