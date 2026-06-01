# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Format red-team suite outputs for export."""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime, timezone

import structlog

from norviq.redteam.simulator import SuiteReport

log = structlog.get_logger()


class RedTeamReporter:
    """Generate JSON/Markdown red-team reports."""

    @staticmethod
    def to_json(report: SuiteReport) -> str:
        """Serialize report as JSON."""
        payload = _payload(report)
        log.info("nrvq.redteam.report_generated", format="json", code="NRVQ-RED-13005")
        return json.dumps(payload, indent=2)

    @staticmethod
    def to_markdown(report: SuiteReport) -> str:
        """Serialize report as Markdown."""
        lines = _summary_lines(report) + _category_lines(report) + _detail_lines(report)
        log.info("nrvq.redteam.report_generated", format="markdown", code="NRVQ-RED-13005")
        return "\n".join(lines)

    @staticmethod
    def failed_only(report: SuiteReport) -> list[dict]:
        """Return only failed scenarios."""
        return [
            {"id": result.attack_id, "name": result.attack_name, "expected": result.expected_decision, "actual": result.actual_decision, "error": result.error}
            for result in report.results
            if not result.passed
        ]


def _payload(report: SuiteReport) -> dict:
    """Build report payload for serialization."""
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total": report.total,
            "passed": report.passed,
            "failed": report.failed,
            "errors": report.errors,
            "pass_rate": report.pass_rate,
            "duration_seconds": report.duration_seconds,
        },
        "by_category": report.by_category,
        "results": [asdict(result) for result in report.results],
    }


def _summary_lines(report: SuiteReport) -> list[str]:
    """Build markdown summary section."""
    ts = datetime.now(timezone.utc).isoformat()
    return [
        "# Norviq Red-Team Report",
        "",
        f"**Date:** {ts}",
        f"**Total:** {report.total} | **Passed:** {report.passed} | **Failed:** {report.failed} | **Pass Rate:** {report.pass_rate}%",
        f"**Duration:** {report.duration_seconds}s",
        "",
    ]


def _category_lines(report: SuiteReport) -> list[str]:
    """Build markdown category table."""
    lines = ["## Results by Category", "", "| Category | Total | Passed | Failed |", "|---|---|---|---|"]
    for category, counts in report.by_category.items():
        lines.append(f"| {category} | {counts['total']} | {counts['passed']} | {counts['failed']} |")
    lines.extend(["", "## Detailed Results", "", "| ID | Attack | Tool | Expected | Actual | Pass | Latency |", "|---|---|---|---|---|---|---|"])
    return lines


def _detail_lines(report: SuiteReport) -> list[str]:
    """Build markdown per-attack rows."""
    lines: list[str] = []
    for result in report.results:
        status = "PASS" if result.passed else "FAIL"
        lines.append(
            f"| {result.attack_id} | {result.attack_name} | {result.tool_name} | {result.expected_decision} | {result.actual_decision} | {status} | {result.latency_ms:.1f}ms |"
        )
    return lines
