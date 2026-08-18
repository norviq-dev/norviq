# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""The build is part of the product, and these are the two ways it was silently wrong.

Both were found while cutting a release, and neither would fail any other gate: the code was correct,
the tests were green, and the thing shipped was still wrong.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
MAKEFILE = (ROOT / "Makefile").read_text(encoding="utf-8")
BUILD_LINES = [
    line.strip() for line in MAKEFILE.splitlines()
    if line.strip().startswith("docker build") and "norviq-engine:" in line
]


def test_there_is_a_build_line_for_every_shipped_image():
    images = {re.search(r"norviq-engine:([a-z]+)-latest", line).group(1) for line in BUILD_LINES}
    assert images == {"api", "ui", "engine", "webhook", "bootstrap"}


@pytest.mark.parametrize("line", BUILD_LINES, ids=lambda l: re.search(r"engine:([a-z]+)-", l).group(1))
def test_every_dockerfile_the_makefile_names_actually_exists(line: str):
    """`make docker-build` pointed at `Dockerfile.webhook`, which does not exist — the real one is
    `webhook/Dockerfile` with the `webhook` directory as its context. So the documented build had
    NEVER built the webhook, and the only reason nobody noticed is that a stale image kept running.

    That mattered more than a broken target usually does: the webhook carries the shipped presets and
    re-renders every namespace's baseline when it rolls, so an install running an older webhook
    enforces an older ruleset while the console describes the newer one.
    """
    dockerfile = re.search(r"-f (\S+)", line).group(1)
    assert (ROOT / dockerfile).is_file(), f"Makefile builds with a missing {dockerfile}"


@pytest.mark.parametrize("line", BUILD_LINES, ids=lambda l: re.search(r"engine:([a-z]+)-", l).group(1))
def test_every_image_is_stamped_with_the_commit_it_was_built_from(line: str):
    """Without the build-arg, `ENV NRVQ_BUILD_GIT_SHA` keeps its `unknown` default and
    `GET /api/v1/version` reports "unknown" for every image built the documented way — so an operator
    cannot tell which build any component is running, and a mixed-version install is undetectable.

    Measured: a false positive fixed in the preset kept firing for hours because one component's image
    predated the fix, and no surface could have said so.
    """
    assert "--build-arg NRVQ_GIT_SHA=" in line, f"unstamped image build: {line}"


@pytest.mark.parametrize("line", BUILD_LINES, ids=lambda l: re.search(r"engine:([a-z]+)-", l).group(1))
def test_every_dockerfile_actually_consumes_the_stamp(line: str):
    """Passing the build-arg proves nothing if the Dockerfile does not receive it.

    `Dockerfile.bootstrap` had no `ARG NRVQ_GIT_SHA`, no ENV and no label, so docker accepted the
    build-arg and discarded it — the bootstrap image shipped unidentifiable while the test above
    passed. That test asserts the CALLER passes the argument; this one asserts the thing that has to
    be true. A build-arg with no ARG to receive it is silently dropped, which is precisely the failure
    mode a stamp exists to make impossible.
    """
    dockerfile = ROOT / re.search(r"-f (\S+)", line).group(1)
    body = dockerfile.read_text()
    assert "ARG NRVQ_GIT_SHA" in body, f"{dockerfile.name} is passed the SHA but never declares ARG"
    assert "NRVQ_BUILD_GIT_SHA=${NRVQ_GIT_SHA}" in body, f"{dockerfile.name} does not export the SHA at runtime"
    assert "org.opencontainers.image.revision=${NRVQ_GIT_SHA}" in body, (
        f"{dockerfile.name} carries no OCI revision label, so the built image cannot be identified"
    )


def test_the_sha_defaults_to_the_working_tree_not_to_a_literal():
    """`NRVQ_GIT_SHA ?=` so CI can override it, defaulting to the real HEAD rather than "unknown"."""
    assert re.search(r"^NRVQ_GIT_SHA \?= .*git rev-parse", MAKEFILE, re.MULTILINE)
