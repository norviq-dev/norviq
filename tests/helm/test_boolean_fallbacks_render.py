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


def _env_value(env_name: str, *extra: str, template: str = "templates/configmap.yaml") -> str:
    res = subprocess.run(
        ["helm", "template", "norviq", str(_CHART), "--set", "policyQuotaNamespaces={default}",
         "--show-only", template, *extra],
        capture_output=True, text=True,
    )
    assert res.returncode == 0, res.stderr
    line = next(line for line in res.stdout.splitlines() if line.strip().startswith(env_name + ":"))
    return line.split(":", 1)[1].strip()


# The fleet hub renders its own ConfigMap with the same auth flags, and only when it is enabled.
_FLEET_HUB = ("--set", "fleet.hub.enabled=true", "--set", "fleet.hub.postgresql.password=fleet-test-strong-pw",
              "--set", "fleet.hub.pgUrl=postgresql://fleet:fleet-test-strong-pw@fleet-pg:5432/fleet")


@pytest.mark.parametrize("key, env_name, template, extra", [
    ("auth.requireBoundAgentIdentity", "NRVQ_AUTH_REQUIRE_BOUND_AGENT_IDENTITY", "templates/configmap.yaml", ()),
    ("config.requireStrongSecret", "NRVQ_REQUIRE_STRONG_SECRET", "templates/configmap.yaml", ()),
    # `| default true` turned an explicit false into "true": an operator who set auth.enabled=false for an
    # SSO-only install kept local password login, and one who set oidc.legacyHs256Enabled=false at the OIDC
    # cutover kept accepting shared-secret HS256 tokens. Rendered before the fix: false -> "true" for both.
    ("auth.enabled", "NRVQ_AUTH_LOGIN_ENABLED", "templates/configmap.yaml", ()),
    ("oidc.legacyHs256Enabled", "NRVQ_LEGACY_HS256_ENABLED", "templates/configmap.yaml", ()),
    ("oidc.legacyHs256Enabled", "NRVQ_LEGACY_HS256_ENABLED", "templates/fleet-hub.yaml", _FLEET_HUB),
    # The hub's copy used `| default false`, so a nulled key switched the check off there while the spoke's
    # ConfigMap and config.py both said it was on.
    ("config.requireStrongSecret", "NRVQ_REQUIRE_STRONG_SECRET", "templates/fleet-hub.yaml", _FLEET_HUB),
])
def test_null_renders_the_code_default_and_an_explicit_false_survives(key, env_name, template, extra):
    def value(setting: str) -> str:
        return _env_value(env_name, *extra, "--set", f"{key}={setting}", template=template)

    assert value("null") == '"true"', "a nulled key must fall back to the CODE default, which is True"
    assert value("false") == '"false"', "an operator who chose false must get false"
    assert value("true") == '"true"'


def test_the_fleet_hub_password_guard_applies_when_the_strong_secret_key_is_nulled():
    """The hub's weak-password guard was `if .Values.config.requireStrongSecret`, which skips on null while
    config.py defaults the control on. A nulled key must keep the guard, like an explicit true."""
    res = subprocess.run(
        ["helm", "template", "norviq", str(_CHART), "--set", "policyQuotaNamespaces={default}",
         "--set", "fleet.hub.enabled=true", "--set", "config.requireStrongSecret=null"],
        capture_output=True, text=True,
    )
    assert res.returncode != 0 and "fleet.hub.postgresql.password" in res.stderr, (
        "a nulled requireStrongSecret rendered the fleet hub with its shipped default DB password"
    )
