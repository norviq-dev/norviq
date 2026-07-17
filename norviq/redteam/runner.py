# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""CLI commands for red-team attack simulation."""

from __future__ import annotations

import asyncio

import click
import structlog

from norviq.redteam.attacks import ATTACKS, AttackCategory
from norviq.redteam.reporter import RedTeamReporter
from norviq.redteam.simulator import AttackSimulator

log = structlog.get_logger()
# Keep the fallback host aligned with the shared CLI group (norviq/cli/main.py).
DEFAULT_API_URL = "http://127.0.0.1:8080"


def _shared(ctx: click.Context, key: str, override: str | None, default: str) -> str:
    """Prefer a per-command flag; else the shared CLI group context (ctx.obj); else the default."""
    if override:
        return override
    return (ctx.obj or {}).get(key) or default


@click.group()
def redteam() -> None:
    """Norviq red-team testing commands."""


@redteam.command()
@click.option("--api-url", default=None)
@click.option("--token", default=None)
@click.option("--agent", default="test-agent")
@click.option("--namespace", default="default")
@click.option("--category", default=None)
@click.option("--output", "-o", type=click.Choice(["table", "json", "markdown"]), default="table")
@click.pass_context
def run(ctx: click.Context, api_url: str | None, token: str | None, agent: str, namespace: str, category: str | None, output: str) -> None:
    """Run full suite or one category."""
    api_url = _shared(ctx, "api_url", api_url, DEFAULT_API_URL)
    token = _shared(ctx, "token", token, "")
    asyncio.run(_run_suite(api_url, token, agent, namespace, category, output))


async def _run_suite(api_url: str, token: str, agent: str, namespace: str, category: str | None, output: str) -> None:
    """Run suite and print selected output format."""
    sim = AttackSimulator(api_url, token)
    categories = [AttackCategory(category)] if category else None
    report = await sim.run_suite(agent, namespace, categories)
    await sim.close()
    if output == "json":
        click.echo(RedTeamReporter.to_json(report))
    elif output == "markdown":
        click.echo(RedTeamReporter.to_markdown(report))
    else:
        _render_table(report)


def _render_table(report) -> None:
    """Render human-friendly result table."""
    click.echo(f"Red-Team Results: {report.passed}/{report.total} passed ({report.pass_rate}%)")
    click.echo(f"Duration: {report.duration_seconds}s")
    for result in report.results:
        icon = "PASS" if result.passed else "FAIL"
        click.echo(f"{icon} [{result.attack_id}] {result.attack_name}: {result.actual_decision} ({result.latency_ms:.1f}ms)")


@redteam.command()
@click.option("--api-url", default=None)
@click.option("--token", default=None)
@click.argument("attack_id")
@click.pass_context
def single(ctx: click.Context, api_url: str | None, token: str | None, attack_id: str) -> None:
    """Run one attack by ID."""
    api_url = _shared(ctx, "api_url", api_url, DEFAULT_API_URL)
    token = _shared(ctx, "token", token, "")
    asyncio.run(_run_single(api_url, token, attack_id))


async def _run_single(api_url: str, token: str, attack_id: str) -> None:
    """Run one attack and print output."""
    sim = AttackSimulator(api_url, token)
    result = await sim.run_by_id(attack_id)
    await sim.close()
    icon = "PASS" if result.passed else "FAIL"
    click.echo(f"{icon} [{result.attack_id}] {result.attack_name}")
    click.echo(f"Expected: {result.expected_decision} | Actual: {result.actual_decision}")
    click.echo(f"Rule: {result.actual_rule} | Latency: {result.latency_ms:.1f}ms")


@redteam.command()
def catalog() -> None:
    """List available attacks."""
    log.info("nrvq.redteam.catalog_loaded", total=len(ATTACKS), code="NRVQ-RED-13004")
    click.echo(f"Norviq Attack Catalog: {len(ATTACKS)} attacks")
    for attack in ATTACKS:
        click.echo(f"[{attack.id}] {attack.name} ({attack.category.value}/{attack.severity})")
