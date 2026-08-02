# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Cross-compiler parity — the PYTHON half.

Two compilers now emit Rego for overlapping intent semantics: this one
(``norviq/engine/intent/compiler.py``) and the console's TypeScript
``ui/src/lib/builderCompile.ts``. Neither derives from the other and each has its own passing
suite, which is precisely how two implementations of one idea drift apart without anyone noticing.

``tests/fixtures/cross_compiler/*.json`` states each policy TWICE — once as a declared intent, once
as a BuilderGraph — with the calls to evaluate and the decision both must reach. This file asserts
the intent half; ``ui/src/lib/crossCompilerParity.test.ts`` asserts the graph half against the SAME
fixtures and the SAME expected decisions. A divergence fails one side and names the fixture.

Decisions are compared, never emitted text: the two modules legitimately differ in shape, so a text
assertion would pin an irrelevance while missing the only thing that matters.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from norviq.engine.intent.compiler import compile_intent

_OPA = shutil.which("opa")
_FIXTURE_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "cross_compiler"


def _fixtures() -> list[dict]:
    return [json.loads(p.read_text(encoding="utf-8")) for p in sorted(_FIXTURE_DIR.glob("*.json"))]


def _decide(rego: str, payload: dict) -> str:
    """Evaluate the compiled module through the real opa, querying the package it declares."""
    package = compile_intent  # placeholder to keep the import used if the body changes
    del package
    import re

    declared = re.search(r"(?m)^\s*package\s+([A-Za-z0-9_.]+)\s*$", rego).group(1)
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "policy.rego"
        path.write_text(rego, encoding="utf-8")
        proc = subprocess.run(
            ["opa", "eval", "--v0-compatible", "-d", str(path), "-I", "-f", "json", f"data.{declared}.decision"],
            input=json.dumps(payload), capture_output=True, text=True, check=True,
        )
        result = json.loads(proc.stdout).get("result") or []
        return result[0]["expressions"][0]["value"] if result else "<undefined>"


def test_fixtures_exist() -> None:
    """A parity guard with no fixtures passes vacuously, which is worse than not having one."""
    assert _fixtures(), f"no cross-compiler fixtures found in {_FIXTURE_DIR}"


def test_every_fixture_is_covered_by_both_sides_or_says_why() -> None:
    """A fixture the builder cannot express is allowed — but it must SAY so.

    Without this, `"graph": null` is indistinguishable from someone forgetting to write the graph
    half, and the coverage gap becomes permanent silently. With it, the gap is a sentence in the
    fixture that has to be deleted when the gap closes.
    """
    for fx in _fixtures():
        if fx.get("graph") is None:
            assert fx.get("gap"), f"{fx['name']}: graph is null but no `gap` explains why"


@pytest.mark.skipif(_OPA is None, reason="opa binary required")
@pytest.mark.parametrize("fixture", _fixtures(), ids=lambda f: f["name"])
def test_intent_compiler_reaches_the_agreed_decision(fixture: dict) -> None:
    """The Python compiler's half of the parity contract."""
    rego = compile_intent(fixture["intent"]).rego
    for case in fixture["cases"]:
        got = _decide(rego, case["input"])
        assert got == case["expect"], (
            f"{fixture['name']} / {case['note']}: intent compiler decided {got!r}, "
            f"fixture says {case['expect']!r}"
        )


@pytest.mark.skipif(_OPA is None, reason="opa binary required")
@pytest.mark.parametrize("fixture", _fixtures(), ids=lambda f: f["name"])
def test_intent_output_passes_the_real_server_write_gate(fixture: dict) -> None:
    """Parity in DECISIONS is not enough if one side's output cannot be saved — that was the actual
    state of this compiler before the package/resolver fix, and it was invisible to every decision
    test because a decision test never calls the validator."""
    from norviq.api.routers.policies import validate_rego_source

    validate_rego_source(compile_intent(fixture["intent"]).rego, "block")
