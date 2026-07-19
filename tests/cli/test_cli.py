# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""CLI tests for F020."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
from click.testing import CliRunner

from norviq.cli.main import cli


@dataclass
class FakeResponse:
    """Simple response test double."""

    status_code: int
    payload: Any
    text: str = "ok"

    def raise_for_status(self) -> None:
        """Raise error for bad statuses."""
        if self.status_code >= 400:
            req = httpx.Request("GET", "http://test")
            resp = httpx.Response(self.status_code, request=req, json=self.payload)
            raise httpx.HTTPStatusError("boom", request=req, response=resp)

    def json(self) -> Any:
        """Return response body."""
        if self.payload == "__bad_json__":
            raise ValueError("invalid")
        return self.payload


def _runner() -> CliRunner:
    """Create CLI runner."""
    return CliRunner()


def _patch_request(monkeypatch, routes: dict[tuple[str, str], FakeResponse], error: Exception | None = None) -> None:
    """Patch httpx.request for CLI tests."""

    def fake_request(method: str, url: str, **_: Any) -> FakeResponse:
        if error:
            raise error
        key = (method.upper(), url)
        if key not in routes:
            return FakeResponse(404, {"detail": "missing"})
        return routes[key]

    monkeypatch.setattr("norviq.cli.api_client.httpx.request", fake_request)


def _url(path: str) -> str:
    """Build test API URL."""
    return f"http://127.0.0.1:8080{path}"


def test_status_shows_api_and_backing_services(monkeypatch) -> None:
    """Test 1 status output."""
    _patch_request(
        monkeypatch,
        {
            ("GET", _url("/healthz")): FakeResponse(200, {"status": "ok"}),
            ("GET", _url("/readyz")): FakeResponse(200, {"redis": True, "db": True}),
        },
    )
    result = _runner().invoke(cli, ["status"])
    assert result.exit_code == 0
    assert "API:   Online" in result.output and "Redis: Connected" in result.output


def test_policy_list_table(monkeypatch) -> None:
    """Test 2 policy list table."""
    _patch_request(
        monkeypatch,
        {("GET", _url("/api/v1/policies")): FakeResponse(200, [{"namespace": "default", "agent_class": "support", "current_version": 2, "rego_length": 42}])},
    )
    result = _runner().invoke(cli, ["policy", "list"])
    assert result.exit_code == 0
    assert "NAMESPACE" in result.output and "support" in result.output


def test_policy_list_json(monkeypatch) -> None:
    """Test 3 policy list json."""
    _patch_request(monkeypatch, {("GET", _url("/api/v1/policies")): FakeResponse(200, [{"namespace": "default"}])})
    result = _runner().invoke(cli, ["-o", "json", "policy", "list"])
    assert result.exit_code == 0
    assert '"namespace": "default"' in result.output


def test_policy_get_prints_rego(monkeypatch) -> None:
    """Test 4 policy get output."""
    _patch_request(
        monkeypatch,
        {("GET", _url("/api/v1/policies/default/customer-support")): FakeResponse(200, {"namespace": "default", "agent_class": "customer-support", "version": 3, "rego_source": "package x"})},
    )
    result = _runner().invoke(cli, ["policy", "get", "default", "customer-support"])
    assert result.exit_code == 0
    assert "package x" in result.output


def test_policy_create_from_rego_file(monkeypatch, tmp_path: Path) -> None:
    """Test 5 policy create."""
    rego_file = tmp_path / "test.rego"
    rego_file.write_text("package p", encoding="utf-8")
    _patch_request(monkeypatch, {("POST", _url("/api/v1/policies")): FakeResponse(200, {"version": 1})})
    result = _runner().invoke(cli, ["policy", "create", "-f", str(rego_file), "-n", "default", "-c", "test-class"])
    assert result.exit_code == 0
    assert "Policy created: default/test-class v1" in result.output


def test_audit_list_with_range(monkeypatch) -> None:
    """Test 6 audit list output."""
    path = "/api/v1/audit/records?range=24h&limit=20"
    payload = [{"timestamp": "2026-01-01T00:00:00Z", "tool_name": "tool.a", "decision": "block", "rule_id": "deny", "namespace": "default", "trust_score": 0.2, "latency_ms": 12.0}]
    _patch_request(monkeypatch, {("GET", _url(path)): FakeResponse(200, payload)})
    result = _runner().invoke(cli, ["audit", "list", "--range", "24h"])
    assert result.exit_code == 0
    assert "tool.a" in result.output


def test_audit_stats(monkeypatch) -> None:
    """Test 7 audit stats output."""
    _patch_request(monkeypatch, {("GET", _url("/api/v1/audit/stats?range=24h")): FakeResponse(200, {"total": 9, "blocked": 2, "allowed": 7})})
    result = _runner().invoke(cli, ["audit", "stats"])
    assert result.exit_code == 0
    assert "Total: 9" in result.output and "Blocked: 2" in result.output


def test_audit_top_blocked(monkeypatch) -> None:
    """Test 8 top blocked output."""
    _patch_request(monkeypatch, {("GET", _url("/api/v1/audit/top-blocked?range=24h")): FakeResponse(200, [{"tool_name": "tool.blocked", "count": 5}])})
    result = _runner().invoke(cli, ["audit", "top-blocked"])
    assert result.exit_code == 0
    assert "tool.blocked" in result.output


def test_agent_list(monkeypatch) -> None:
    """Test 9 agent list output."""
    payload = [{"spiffe_id": "spiffe://test", "score": 0.9, "category": "trusted", "violation_count": 0}]
    _patch_request(monkeypatch, {("GET", _url("/api/v1/agents")): FakeResponse(200, payload)})
    result = _runner().invoke(cli, ["agent", "list"])
    assert result.exit_code == 0
    assert "spiffe://test" in result.output


def test_agent_reset_trust(monkeypatch) -> None:
    """Test 10 agent reset output."""
    payload = {"spiffe_id": "spiffe://test", "score": 0.9, "category": "trusted"}
    _patch_request(monkeypatch, {("PUT", _url("/api/v1/agents/spiffe://test/trust")): FakeResponse(200, payload)})
    result = _runner().invoke(cli, ["agent", "reset-trust", "spiffe://test", "--score", "0.9"])
    assert result.exit_code == 0
    assert "Trust reset: spiffe://test -> 0.9 (trusted)" in result.output


def test_config_show(monkeypatch) -> None:
    """Test 11 config show output."""
    _patch_request(monkeypatch, {})
    result = _runner().invoke(cli, ["--token", "abcdefghijkl", "config", "show"])
    assert result.exit_code == 0
    assert "API URL: http://127.0.0.1:8080" in result.output and "****ijkl" in result.output


def test_api_down_exit_1(monkeypatch) -> None:
    """Test 12 API connection failure."""
    _patch_request(monkeypatch, {}, error=httpx.ConnectError("down"))
    result = _runner().invoke(cli, ["status"])
    assert result.exit_code == 1
    assert "Cannot connect" in result.output


def test_bad_token_exit_1(monkeypatch) -> None:
    """Test 13 authentication failure."""
    _patch_request(monkeypatch, {("GET", _url("/healthz")): FakeResponse(401, {"detail": "bad token"})})
    result = _runner().invoke(cli, ["status"])
    assert result.exit_code == 1
    assert "Authentication failed" in result.output


def _capture_redteam_sim(monkeypatch) -> dict[str, Any]:
    """Patch AttackSimulator so red-team commands record the (api_url, token) they receive."""
    captured: dict[str, Any] = {}

    class FakeSim:
        def __init__(self, api_url: str, token: str) -> None:
            captured["api_url"] = api_url
            captured["token"] = token

        async def run_suite(self, agent: str, namespace: str, categories: Any) -> Any:
            return SimpleNamespace(passed=0, total=0, pass_rate=0.0, duration_seconds=0.0, results=[])

        async def run_by_id(self, attack_id: str) -> Any:
            return SimpleNamespace(
                passed=True, attack_id=attack_id, attack_name="fake",
                expected_decision="block", actual_decision="block", actual_rule="deny", latency_ms=1.0,
            )

        async def close(self) -> None:
            return None

    monkeypatch.setattr("norviq.redteam.runner.AttackSimulator", FakeSim)
    return captured


def test_redteam_run_inherits_global_api_url_and_token(monkeypatch) -> None:
    """P7: global --api-url/--token flow into `redteam run` via the shared group context."""
    captured = _capture_redteam_sim(monkeypatch)
    result = _runner().invoke(cli, ["--api-url", "http://api.example:9000", "--token", "secret", "redteam", "run"])
    assert result.exit_code == 0
    assert captured == {"api_url": "http://api.example:9000", "token": "secret"}


def test_redteam_run_defaults_to_shared_cli_host(monkeypatch) -> None:
    """P7: absent flags, `redteam run` uses the shared 127.0.0.1 host, not the old localhost default."""
    captured = _capture_redteam_sim(monkeypatch)
    result = _runner().invoke(cli, ["redteam", "run"])
    assert result.exit_code == 0
    assert captured["api_url"] == "http://127.0.0.1:8080"


def test_redteam_run_per_command_flag_overrides_global(monkeypatch) -> None:
    """P7: an explicit per-command --api-url still overrides the global value."""
    captured = _capture_redteam_sim(monkeypatch)
    result = _runner().invoke(
        cli, ["--api-url", "http://global:1", "redteam", "run", "--api-url", "http://override:2"]
    )
    assert result.exit_code == 0
    assert captured["api_url"] == "http://override:2"


def test_redteam_single_inherits_global_api_url_and_token(monkeypatch) -> None:
    """P7: global --api-url/--token flow into `redteam single` via the shared group context."""
    captured = _capture_redteam_sim(monkeypatch)
    result = _runner().invoke(cli, ["--api-url", "http://api.example:9000", "--token", "secret", "redteam", "single", "PI-001"])
    assert result.exit_code == 0
    assert captured == {"api_url": "http://api.example:9000", "token": "secret"}
