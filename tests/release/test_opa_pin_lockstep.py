# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Every OPA pin names the version the chart's sidecar runs, with the same checksum everywhere.

The version lives in seven files: the chart's opa.image, the two image Dockerfiles (URL plus one sha256 per
arch), three workflows (four installs, amd64 only) and the MCP demo image. Nothing tied them together, and two
bumps in a row left some behind. 5e2977c found four workflow installs on a checksum their URL could never
serve. The 1.19.1 bump left scripts/mcp-demo.Dockerfile, whose comment says "same version the chart's
sidecar runs", on 1.19.0. It stayed there until the 1.21.4 bump.

scripts/gen-opa-capabilities.py documented an `--opa-version-check` mode that did not exist: the regenerate
command in its own docstring exited 2 with "unrecognized arguments". The last two tests hold the mode to what
the docstring says it does.
"""

from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
VALUES = ROOT / "helm" / "norviq" / "values.yaml"
DOCKERFILES = [ROOT / "Dockerfile.api", ROOT / "Dockerfile.engine"]
WORKFLOWS = [ROOT / ".github" / "workflows" / n for n in ("test.yml", "kind-e2e.yml", "framework-compat.yml")]
MCP_DEMO = ROOT / "scripts" / "mcp-demo.Dockerfile"
GEN = ROOT / "scripts" / "gen-opa-capabilities.py"

_DOWNLOAD = re.compile(r"openpolicyagent\.org/downloads/v([^/\s]+)/opa_linux_")


def _sidecar_version() -> str:
    image = yaml.safe_load(VALUES.read_text())["opa"]["image"]
    m = re.fullmatch(r"openpolicyagent/opa:(\d+\.\d+\.\d+)-static", image)
    assert m, f"opa.image is {image!r}; these tests expect openpolicyagent/opa:<x.y.z>-static"
    return m.group(1)


def _dockerfile_sha(text: str, arch: str) -> str:
    found = re.findall(rf'{arch}\) OPA_SHA256="([0-9a-f]{{64}})"', text)
    assert len(found) == 1, f"expected one {arch} OPA_SHA256, found {found}"
    return found[0]


def test_every_opa_download_names_the_sidecar_version() -> None:
    version = _sidecar_version()
    for path in DOCKERFILES + WORKFLOWS:
        found = _DOWNLOAD.findall(path.read_text())
        assert found, f"{path.relative_to(ROOT)} no longer downloads OPA; update this test's site list"
        assert set(found) == {version}, (
            f"{path.relative_to(ROOT)} downloads OPA {sorted(set(found))}, sidecar is {version}"
        )
    demo = re.findall(r"^FROM openpolicyagent/opa:(\S+)", MCP_DEMO.read_text(), re.M)
    assert demo == [f"{version}-static"], f"mcp-demo.Dockerfile copies OPA from {demo}, sidecar is {version}"
    digests = yaml.safe_load(VALUES.read_text())["global"]["thirdPartyImageDigests"]
    assert f"openpolicyagent/opa:{version}-static" in digests, "opa.image has no thirdPartyImageDigests entry"


def test_every_opa_checksum_agrees() -> None:
    api, engine = (p.read_text() for p in DOCKERFILES)
    for arch in ("amd64", "arm64"):
        assert _dockerfile_sha(api, arch) == _dockerfile_sha(engine, arch), f"the Dockerfiles disagree on {arch}"
    amd64 = _dockerfile_sha(api, "amd64")
    for path in WORKFLOWS:
        sums = re.findall(r'echo "([0-9a-f]{64})  /usr/local/bin/opa"', path.read_text())
        assert sums, f"{path.relative_to(ROOT)} installs OPA without a checksum"
        assert set(sums) == {amd64}, f"{path.relative_to(ROOT)} checks {sorted(set(sums))}, Dockerfiles say {amd64}"


@pytest.fixture
def gen(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    spec = importlib.util.spec_from_file_location("gen_opa_capabilities", GEN)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    out = tmp_path / "out" / "opa-capabilities.json"
    monkeypatch.setattr(mod, "OUTPUT_PATHS", [out])  # never touch the committed files

    def run(reported_version: str) -> tuple[int, Path]:
        fake = tmp_path / "opa"
        fake.write_text(
            "#!/bin/sh\n"
            f'case "$1" in version) echo "Version: {reported_version}" ;; '
            'capabilities) echo \'{"builtins": [{"name": "abs"}, {"name": "http.send"}]}\' ;; esac\n'
        )
        fake.chmod(0o755)
        monkeypatch.setattr(sys, "argv", ["gen-opa-capabilities.py", "--opa-bin", str(fake), "--opa-version-check"])
        return mod.main(), out

    return mod, run


def test_the_generator_reads_the_sidecar_pin(gen) -> None:
    mod, _ = gen
    assert mod.pinned_opa_version(VALUES.read_text()) == _sidecar_version()


def test_the_version_check_refuses_any_other_opa(gen) -> None:
    _, run = gen
    rc, out = run("1.19.1")
    assert rc == 1 and not out.exists()
    rc, out = run(_sidecar_version())
    assert rc == 0
    assert '"name": "abs"' in out.read_text() and "http.send" not in out.read_text()
