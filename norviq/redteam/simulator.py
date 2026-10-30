# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Programmatic attack simulator for Norviq red-team tests."""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass

import httpx
import structlog

# Unused here since RL-001 stopped reading the limiter ceiling, and kept on purpose: this is the CLI's
# only import of norviq.config, and importing it runs `_preload_env_files` (docs/cli.md, ".env
# loading"). Dropping it would silently stop `norviq` reading the repository-root .env.
import norviq.config  # noqa: F401
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
            data = await _execute_attack(self._client, self._api_url, payload)
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
        # EXPLICIT, not inherited. This payload used to omit `framework` and rely on
        # EvaluateRequest defaulting it to "redteam" — which is what tagged these fabricated attacks
        # as non-real everywhere (`audit_row_is_non_real`). That default is being removed, because it
        # also silently tagged REAL operator traffic posted over raw HTTP. The suite that genuinely is
        # synthetic now declares itself, the same way the console-driven runner already does.
        "framework": "redteam",
        "session_id": f"redteam-{attack.id}",
        "trust_score": 0.3 if attack.category == AttackCategory.TRUST_MANIPULATION else 0.8,
    }


def _non_policy_rule(rule_id: str) -> str | None:
    """The bare engine-fault or throttle rule a decision carries, or None when a policy decided it.

    The console's verdict (`norviq/api/redteam_efficacy.py::_row_outcome`) asks the same resolver, so
    the CLI and the scorecard cannot disagree about what a throttled or faulted block is. Imported
    here and not at module top: redteam must not require the API package at import (precision.py
    does the same). Measured: importing this module loads 6 norviq modules; the first call here
    takes that to 65, FastAPI and SQLAlchemy included, in 0.6-0.95 s, once per process.
    """
    from norviq.api.routers.system_health import non_policy_rule_for

    return non_policy_rule_for(rule_id)


def _build_success_result(attack: AttackDefinition, data: dict, started: float) -> AttackResult:
    """Create attack result from successful response."""
    latency_ms = (time.perf_counter() - started) * 1000
    actual_decision, actual_rule = _extract_decision(data)
    # A block no policy made is not a pass. `rate_limit_exceeded` fires only on a call the policy stack
    # already ALLOWED, and a fail-closed `evaluator_timeout` is the engine failing, so either one met a
    # block expectation by accident. Measured against the real engine with the read exemption off,
    # where RL-001's old 61-call replay was counted: seven attacks the baseline does not block passed
    # on `rate_limit_exceeded`, and the run read 32/34 against 27/34 real.
    non_policy = _non_policy_rule(actual_rule)
    passed = actual_decision == attack.expected_decision and non_policy is None
    if not passed:
        log.warning("nrvq.redteam.attack_not_blocked", attack=attack.id, expected=attack.expected_decision, actual=actual_decision, non_policy_rule=non_policy, code="NRVQ-RED-13001")
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


async def _execute_attack(client: httpx.AsyncClient, api_url: str, payload: dict) -> dict:
    """POST one attack once — RL-001 included, as the console's suite (`routers/redteam.py::run_suite`) does.

    RL-001 used to be replayed `evaluator_rate_limit_per_window + 1` times. Its expectation is a
    single call's `allow` (attacks.py), and every attack posts under the same SPIFFE id, which is
    what the engine's limiter counts on. Under the shipped read exemption `search_kb` is never
    counted, so the replay measured nothing; with the exemption off, the 61st call was throttled and
    failed RL-001 because the limiter worked, and the identity's window stayed over its ceiling for
    every attack after it.
    """
    response = await client.post(f"{api_url}/api/v1/evaluate", json=payload)
    response.raise_for_status()
    return response.json()


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
