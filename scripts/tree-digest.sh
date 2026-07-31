#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
#
# Deterministic digest over the SOURCE that goes into a Norviq image (norviq/ + pyproject.toml).
#
# WHY THIS EXISTS. The no-stale-image discipline is "prove the running image was built from the code
# you are claiming to have validated". `git rev-parse HEAD` is the normal marker and it is exactly
# the wrong one for uncommitted work: HEAD does not move when you edit a file, so a stale image and
# a fresh one report the same sha. This digest changes iff the image's input changes, so
# `image tree digest == working tree digest` is a real check rather than a ritual.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
find norviq pyproject.toml -type f \( -name '*.py' -o -name '*.json' -o -name '*.toml' \) \
  ! -path '*/__pycache__/*' -print0 \
  | sort -z \
  | xargs -0 sha256sum \
  | sha256sum \
  | cut -d' ' -f1
