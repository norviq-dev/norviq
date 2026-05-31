# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Output format helpers for CLI."""

from __future__ import annotations

import json
from typing import Any

import click


def fmt_json(data: dict[str, Any] | list[dict[str, Any]]) -> None:
    """Print JSON payload."""
    click.echo(json.dumps(data, indent=2, default=str))


def fmt_table(data: list[dict[str, Any]], columns: list[str]) -> None:
    """Print aligned table rows."""
    if not data:
        click.echo("No results.")
        return
    widths = {col: len(col) for col in columns}
    for row in data:
        for col in columns:
            widths[col] = max(widths[col], len(str(row.get(col, ""))))
    header = "  ".join(col.upper().ljust(widths[col]) for col in columns)
    click.echo(header)
    click.echo("-" * len(header))
    for row in data:
        line = "  ".join(str(row.get(col, "")).ljust(widths[col]) for col in columns)
        click.echo(line)
    click.echo(f"\n({len(data)} results)")


def fmt_policy(data: dict[str, Any]) -> None:
    """Print policy details and source."""
    click.echo(f"Namespace:   {data.get('namespace')}")
    click.echo(f"Agent Class: {data.get('agent_class')}")
    click.echo(f"Version:     {data.get('version')}")
    click.echo("-" * 33)
    click.echo(data.get("rego_source", ""))
