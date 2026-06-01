# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Programmatic attack simulator for Norviq red-team tests."""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass

import httpx
import structlog

from norviq.config import settings
from norviq.redteam.attacks import ATTACKS, AttackCategory, AttackDefinition, get_attack_by_id

log = structlog.get_logger()


@dataclass(slots=True)
class AttackResult:
    """Single attack execution result."""

    attack_id: str
    attack_name: str
    category: str
    tool_name: str
    expected_decision: str
    actual_decision: str
    expected_rule: str
    actual_rule: str
    passed: bool
    latency_ms: float
    trust_score: float = 0.0
    error: str | None = None


@dataclass(slots=True)
class SuiteReport:
    """Aggregated suite report."""

    total: int
    passed: int
    failed: int
    errors: int
    pass_rate: float
    results: list[AttackResult]
    by_category: dict[str, dict[str, int]]
    duration_seconds: float


class AttackSimulator:
    """Run synthetic attacks against Norviq API."""

    def __init__(self, api_url: str = "http://localhost:8080", token: str = "") -> None:
        """Initialize client with API endpoint."""
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        self._api_url = api_url.rstrip("/")
        self._client = httpx.AsyncClient(timeout=10, headers=headers)

    async def close(self) -> None:
        """Close async HTTP client."""
        await self._client.aclose()

    async def run(self, attack: AttackDefinition, target_agent: str = "test-agent", target_namespace: str = "default") -> AttackResult:
        """Execute one attack scenario."""
        start = time.perf_counter()
        payload = _request_payload(attack, target_agent, target_namespace)
        try:
            data = await _execute_attack(self._client, self._api_url, payload, attack.category)
            return _build_success_result(attack, data, start)
        except Exception as exc:
            return _build_error_result(attack, start, exc)

    async def run_suite(
        self,
        target_agent: str = "test-agent",
        target_namespace: str = "default",
        categories: list[AttackCategory] | None = None,
    ) -> SuiteReport:
        """Execute all attacks, optionally filtered."""
        started = time.perf_counter()
        attacks = [attack for attack in ATTACKS if not categories or attack.category in categories]
        log.info("nrvq.redteam.suite_started", total=len(attacks), code="NRVQ-RED-13000")
        results = [await self.run(attack, target_agent, target_namespace) for attack in attacks]
        report = _suite_report(results, time.perf_counter() - started)
        log.info("nrvq.redteam.suite_complete", total=report.total, pass_rate=report.pass_rate, code="NRVQ-RED-13003")
        return report

    async def run_by_id(self, attack_id: str, target_agent: str = "test-agent", target_namespace: str = "default") -> AttackResult:
        """Execute one attack by ID."""
        attack = get_attack_by_id(attack_id)
        if attack is None:
            return AttackResult(attack_id, "unknown", "unknown", "", "", "error", "", "", False, 0.0, error=f"Attack {attack_id} not found")
        return await self.run(attack, target_agent, target_namespace)


def _request_payload(attack: AttackDefinition, target_agent: str, target_namespace: str) -> dict:
    """Build evaluate payload for one attack."""
    return {
        "tool_name": attack.tool_name,
        "tool_params": attack.tool_params,
        "agent_identity": {
            "spiffe_id": f"spiffe://norviq/ns/{target_namespace}/sa/{target_agent}",
            "namespace": target_namespace,
            "agent_class": target_agent,
        },
        "session_id": f"redteam-{attack.id}",
        "trust_score": 0.3 if attack.category == AttackCategory.TRUST_MANIPULATION else 0.8,
    }


def _build_success_result(attack: AttackDefinition, data: dict, started: float) -> AttackResult:
    """Create attack result from successful response."""
    latency_ms = (time.perf_counter() - started) * 1000
    actual_decision, actual_rule = _extract_decision(data)
    passed = actual_decision == attack.expected_decision
    if not passed:
        log.warning("nrvq.redteam.attack_not_blocked", attack=attack.id, expected=attack.expected_decision, actual=actual_decision, code="NRVQ-RED-13001")
    elif actual_rule != attack.expected_rule:
        log.warning("nrvq.redteam.rule_mismatch", attack=attack.id, expected_rule=attack.expected_rule, actual_rule=actual_rule, code="NRVQ-RED-13001")
    return AttackResult(
        attack.id,
        attack.name,
        attack.category.value,
        attack.tool_name,
        attack.expected_decision,
        actual_decision,
        attack.expected_rule,
        actual_rule,
        passed,
        latency_ms,
        float(data.get("trust_score", 0.0)),
    )


async def _execute_attack(client: httpx.AsyncClient, api_url: str, payload: dict, category: AttackCategory) -> dict:
    """Execute one attack, replaying rate-limit scenarios."""
    attempts = settings.evaluator_rate_limit_per_window + 1 if category == AttackCategory.OWASP_LLM10 else 1
    data: dict = {}
    for _ in range(attempts):
        response = await client.post(f"{api_url}/api/v1/evaluate", json=payload)
        response.raise_for_status()
        data = response.json()
    return data


def _extract_decision(data: dict) -> tuple[str, str]:
    """Extract decision and rule from flat or nested responses."""
    decision = data.get("decision", "unknown")
    if isinstance(decision, dict):
        return str(decision.get("decision", "unknown")), str(decision.get("rule_id", "unknown"))
    return str(decision), str(data.get("rule_id", "unknown"))


def _build_error_result(attack: AttackDefinition, started: float, exc: Exception) -> AttackResult:
    """Create attack result for execution errors."""
    latency_ms = (time.perf_counter() - started) * 1000
    log.error("nrvq.redteam.attack_error", attack=attack.id, error=str(exc), code="NRVQ-RED-13002")
    return AttackResult(
        attack.id, attack.name, attack.category.value, attack.tool_name, attack.expected_decision, "error", attack.expected_rule, "", False, latency_ms, 0.0, str(exc)
    )


def _suite_report(results: list[AttackResult], duration_seconds: float) -> SuiteReport:
    """Aggregate all result metrics into report."""
    grouped = _group_by_category(results)
    passed = sum(1 for result in results if result.passed)
    errors = sum(1 for result in results if result.error)
    failed = len(results) - passed - errors
    pass_rate = round((passed / len(results) * 100), 1) if results else 0.0
    return SuiteReport(len(results), passed, failed, errors, pass_rate, results, grouped, round(duration_seconds, 2))


def _group_by_category(results: list[AttackResult]) -> dict[str, dict[str, int]]:
    """Group suite results by category name."""
    grouped: dict[str, dict[str, int]] = {}
    for result in results:
        grouped.setdefault(result.category, {"total": 0, "passed": 0, "failed": 0})
        grouped[result.category]["total"] += 1
        grouped[result.category]["passed"] += int(result.passed)
        grouped[result.category]["failed"] += int(not result.passed)
    return grouped


def report_to_dict(report: SuiteReport) -> dict:
    """Convert suite report to serializable dict."""
    return {
        "total": report.total,
        "passed": report.passed,
        "failed": report.failed,
        "errors": report.errors,
        "pass_rate": report.pass_rate,
        "results": [asdict(result) for result in report.results],
        "by_category": report.by_category,
        "duration_seconds": report.duration_seconds,
    }
