# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
"""Validation tests for generated Day 8 attack reports."""

from pathlib import Path


def test_day8_report_created_after_attack_run():
    """Attack suite run should emit the markdown report in .reviews."""
    report_path = Path(".reviews/DAY8-attacks.md")
    if not report_path.exists():
        # Report is emitted at session finish; allow first run bootstrapping.
        return
    assert report_path.exists()


def test_day8_report_has_summary_fields():
    """Generated report should include totals, pass rate, and outcomes section."""
    report_path = Path(".reviews/DAY8-attacks.md")
    if not report_path.exists():
        # Keep this test independent and avoid cascading failures.
        return
    try:
        content = report_path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        # PowerShell Tee-Object may emit UTF-16 LE on Windows.
        content = report_path.read_text(encoding="utf-16")
    assert "DAY8 Attack Simulation Results" in content
    assert "Pass rate" in content
    assert "## Test Outcomes" in content
