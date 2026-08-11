#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
#
# Deterministic digest over the SOURCE that goes into a Norviq image (norviq/ + pyproject.toml).
#
# WHY THIS EXISTS. The no-stale-image discipline is "prove the running image was built from the code
# you are claiming to have validated". `git rev-parse HEAD` is the normal marker and it is the wrong
# one for uncommitted work: HEAD does not move when you edit a file, so a stale image and a fresh one
# report the same sha. This digest changes iff the image's input changes, so
# `image tree digest == working tree digest` is a real check rather than a ritual.
#
# PORTABLE ON PURPOSE. This runs on the developer's machine, and a demo that only works on Linux is
# a demo nobody runs. macOS ships `shasum` and not `sha256sum`, and BSD `sort`/`xargs` differ from
# GNU's, so the implementation sticks to what both have. The OUTPUT is identical on both — the digest
# is quoted in the design note and in commit history, and a platform-dependent digest would be worse
# than no digest at all.
#
# Filenames containing a newline would break the line-oriented read below. Nothing in this repo has
# one, and a source tree that did would break far more than this script.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

# GNU coreutils vs macOS/BSD. Both emit "<hex>  <path>", so the hashed stream is byte-identical.
if command -v sha256sum >/dev/null 2>&1; then
  _sha256() { sha256sum "$@"; }
elif command -v shasum >/dev/null 2>&1; then
  _sha256() { shasum -a 256 "$@"; }
else
  echo "tree-digest: need sha256sum or shasum on PATH" >&2
  exit 1
fi

# LC_ALL=C pins the sort to byte order. Without it a locale with different collation rules reorders
# the file list and silently produces a different digest for identical source.
find norviq pyproject.toml -type f \
     \( -name '*.py' -o -name '*.json' -o -name '*.toml' \) \
     ! -path '*/__pycache__/*' -print \
  | LC_ALL=C sort \
  | while IFS= read -r f; do _sha256 "$f"; done \
  | _sha256 \
  | cut -d' ' -f1
