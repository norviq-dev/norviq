# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Tests for red-team report generation."""

from __future__ import annotations

import json

from norviq.redteam.reporter import RedTeamReporter
from norviq.redteam.simulator import AttackResult, SuiteReport


def _sample_report() -> SuiteReport:
    """Create deterministic suite report fixture."""
    results = [
        AttackResult("PI-001", "Prompt inject", "prompt_injection", "search_kb", "block", "block", "llm01_prompt_injection", "llm01_prompt_injection", True, 10.0, 0.7, None),
        AttackResult("SQL-001", "SQLi", "sql_injection", "execute_sql", "block", "allow", "deny_sql_injection", "default_allow", False, 11.0, 0.6, None),
    ]
    return SuiteReport(2, 1, 1, 0, 50.0, results, {"prompt_injection": {"total": 1, "passed": 1, "failed": 0}}, 0.2)


def test_to_json_outputs_valid_json() -> None:
    """Emit parseable JSON report."""
    payload = json.loads(RedTeamReporter.to_json(_sample_report()))
    assert payload["summary"]["total"] == 2
    assert len(payload["results"]) == 2


def test_to_markdown_outputs_table() -> None:
    """Emit markdown table sections."""
    markdown = RedTeamReporter.to_markdown(_sample_report())
    assert "| Category | Total | Passed | Failed |" in markdown
    assert "| ID | Attack | Tool | Expected | Actual | Pass | Latency |" in markdown


def test_failed_only_returns_failures() -> None:
    """Return only failed result rows."""
    rows = RedTeamReporter.failed_only(_sample_report())
    assert len(rows) == 1
    assert rows[0]["id"] == "SQL-001"
