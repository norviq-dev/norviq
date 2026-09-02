"""The text test in test_chart_defaults_track_code.py says the template uses the right idiom.
This renders it, because the idiom is only right if helm agrees: a nulled boolean must come out
as the code default, an explicit false must survive, and true must stay true."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(shutil.which("helm") is None, reason="helm binary not on PATH")

_CHART = Path(__file__).resolve().parents[2] / "helm/norviq"


def _env_value(env_name: str, *extra: str) -> str:
    res = subprocess.run(
        ["helm", "template", "norviq", str(_CHART), "--set", "policyQuotaNamespaces={default}", *extra],
        capture_output=True, text=True,
    )
    assert res.returncode == 0, res.stderr
    line = next(line for line in res.stdout.splitlines() if line.strip().startswith(env_name + ":"))
    return line.split(":", 1)[1].strip()


@pytest.mark.parametrize("key, env_name", [
    ("auth.requireBoundAgentIdentity", "NRVQ_AUTH_REQUIRE_BOUND_AGENT_IDENTITY"),
    ("config.requireStrongSecret", "NRVQ_REQUIRE_STRONG_SECRET"),
])
def test_null_renders_the_code_default_and_an_explicit_false_survives(key, env_name):
    assert _env_value(env_name, "--set", f"{key}=null") == '"true"', "a nulled key must fall back to the CODE default, which is True"
    assert _env_value(env_name, "--set", f"{key}=false") == '"false"', "an operator who chose false must get false"
    assert _env_value(env_name, "--set", f"{key}=true") == '"true"'
