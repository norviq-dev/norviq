#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Release gate: every image reference in a rendered chart must be pinned by digest.

    helm template norviq helm/norviq --set-json 'policyQuotaNamespaces=["default"]' > rendered.yaml
    check_image_pins.py rendered.yaml [more.yaml ...]      # or `-` for stdin

Exits 0 when every reference ends in `@sha256:<64 hex>`, 1 naming each one that does not.

Why every reference, not only Norviq's. release.yml's gate grepped `ghcr.io/norviq-dev/` lines and
nothing else, so it passed while six of the eight images in a default render (opa, valkey, postgres,
nginx, busybox, curl) still resolved through tags. `postgres:16-alpine` and `valkey/valkey:8.1-alpine`
are rebuilt upstream every few weeks, so two installs of one signed chart version could run different
datastore builds, and the signature over the chart said nothing about which.

What counts as a reference: the value of any `image:` or `imageName:` key (containers, init
containers, the CloudNativePG `imageName`, a RedisFailover's redis image), and the literal value of
any env var named `*_IMAGE`. NRVQ_SIDECAR_IMAGE is the enforcement sidecar the webhook injects into
every agent pod; it is an env value, not an `image:` field, and a grep for `image:` never saw it.

Line-based and standard-library only on purpose. release.yml runs this with the runner's system
python3, which is not guaranteed to have PyYAML, and `helm template` emits one key per line in a
fixed shape. A value it cannot read as a plain scalar (empty, or a `|`/`>` block) counts as unpinned:
a gate that skips what it does not understand passes exactly the case nobody wrote it for.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

# `image: x`, `- image: x`, `imageName: x`. A comment line starts with `#` and so never matches.
_KEY = re.compile(r"^\s*(?:-\s+)?(?:image|imageName):(?:\s+(?P<v>.*?))?\s*$")
_ENV_NAME = re.compile(r"""^\s*-\s+name:\s*["']?(?P<n>[A-Z0-9_]*_IMAGE)["']?\s*$""")
_ENV_VALUE = re.compile(r"^\s*value:(?:\s+(?P<v>.*?))?\s*$")
_PINNED = re.compile(r"@sha256:[0-9a-f]{64}$")


def _scalar(raw: str | None) -> str:
    v = (raw or "").strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
        v = v[1:-1]
    return v


def find_refs(text: str) -> list[tuple[int, str]]:
    """(line number, reference) for every image reference in a rendered manifest stream."""
    refs: list[tuple[int, str]] = []
    lines = text.splitlines()
    for i, line in enumerate(lines):
        m = _KEY.match(line)
        if m:
            refs.append((i + 1, _scalar(m.group("v"))))
            continue
        # An env var: `- name: FOO_IMAGE` with its literal on the next line. `valueFrom:` is not a
        # reference the chart chose, so only a `value:` line counts.
        if _ENV_NAME.match(line) and i + 1 < len(lines):
            v = _ENV_VALUE.match(lines[i + 1])
            if v:
                refs.append((i + 2, _scalar(v.group("v"))))
    return refs


def unpinned(refs: list[tuple[int, str]]) -> list[tuple[int, str]]:
    return [(n, r) for n, r in refs if r.startswith(("|", ">")) or not _PINNED.search(r)]


def main(argv: list[str]) -> int:
    if not argv:
        print("usage: check_image_pins.py <rendered.yaml|-> [...]", file=sys.stderr)
        return 2
    failed = False
    for arg in argv:
        text = sys.stdin.read() if arg == "-" else Path(arg).read_text()
        refs = find_refs(text)
        if not refs:
            # An empty or truncated render must not read as "everything pinned".
            print(f"::error::{arg}: no image references found — refusing to call that pinned", file=sys.stderr)
            failed = True
            continue
        bad = unpinned(refs)
        for n, ref in bad:
            print(f"::error::{arg}:{n}: image is not digest-pinned: {ref or '<empty>'}", file=sys.stderr)
        failed = failed or bool(bad)
        print(f"{arg}: {len(refs) - len(bad)}/{len(refs)} image references digest-pinned")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
