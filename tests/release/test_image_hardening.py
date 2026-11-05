# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""What the runtime stage of each shipped image must not carry.

The api and engine images take their dependencies from the builder's /deps, so nothing in the final
stage installs packages, yet `python:3.12-slim` ships its own pip there. An unused pip is still code in
the image and still a scanner finding. The webhook's distroless base is held to the current Debian
release, whose static image scans clean where debian12's carried fixable ca-certificates and tzdata.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
PYTHON_IMAGES = ["Dockerfile.api", "Dockerfile.engine"]


def _final_stage(path: Path) -> str:
    """The Dockerfile text from its last FROM onward, with comments and line continuations folded."""
    lines = [ln for ln in path.read_text().splitlines() if not ln.lstrip().startswith("#")]
    text = re.sub(r"\\\n", " ", "\n".join(lines))
    starts = [m.start() for m in re.finditer(r"^FROM\s", text, re.M)]
    assert starts, f"{path.name} has no FROM"
    return text[starts[-1]:]


@pytest.mark.parametrize("name", PYTHON_IMAGES)
def test_python_runtime_stage_removes_pip(name: str) -> None:
    stage = _final_stage(ROOT / name)
    removal = re.search(r"pip uninstall -y\b[^\n]*\bpip\b", stage)
    assert removal, f"{name}: the runtime stage keeps the base image's pip"
    # The bundled ensurepip wheel is the same pip, one command away from coming back.
    assert re.search(r"rm -f\s+\S*ensurepip/_bundled/pip-\*\.whl", stage), f"{name}: ensurepip's pip wheel is kept"
    # Removed after the dependencies are copied in, so a dependency cannot reintroduce it, and
    # nothing later in the stage may need it.
    deps = stage.find("COPY --from=builder /deps")
    assert 0 <= deps < removal.start(), f"{name}: pip is removed before /deps is copied over site-packages"
    later = stage[removal.end():]
    assert not re.search(r"\bpip3?(\.\d+)?\s+install\b|-m pip\b|ensurepip", later), (
        f"{name}: the runtime stage uses pip after removing it"
    )


def test_webhook_runtime_base_is_distroless_static_debian13() -> None:
    stage = _final_stage(ROOT / "webhook" / "Dockerfile")
    base = re.match(r"FROM\s+(\S+)", stage).group(1)
    assert re.fullmatch(r"gcr\.io/distroless/static-debian13(@sha256:[0-9a-f]{64})?", base), base
    # static-* has no libc: the binary must be built without cgo for the base to run it.
    assert "CGO_ENABLED=0" in (ROOT / "webhook" / "Dockerfile").read_text()
