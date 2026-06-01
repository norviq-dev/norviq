# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Tests for red-team CLI runner."""

from click.testing import CliRunner

from norviq.redteam.runner import redteam


def test_catalog_command_lists_attacks() -> None:
    """Print attack catalog entries."""
    result = CliRunner().invoke(redteam, ["catalog"])
    assert result.exit_code == 0
    assert "Attack Catalog" in result.output
    assert "[PI-001]" in result.output
