# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Norviq CLI command tree."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

import click
import structlog

from norviq.cli.api_client import APIClient
from norviq.cli.formatters import fmt_json, fmt_policy, fmt_table
from norviq.redteam.runner import redteam

log = structlog.get_logger()
DEFAULT_API_URL = "http://127.0.0.1:8080"
DEFAULT_RANGE = "24h"
DEFAULT_LIMIT = 20
def _load_dotenv() -> None:
    """Load .env values into environment."""
    env_file = Path(".env")
    if not env_file.exists():
        return
    for line in env_file.read_text(encoding="utf-8").splitlines():
        clean = line.strip()
        if clean and not clean.startswith("#") and "=" in clean:
            key, value = clean.split("=", 1)
            os.environ.setdefault(key.strip(), value.strip())
def _read_rego(path: str) -> str:
    """Read rego policy file text."""
    return Path(path).read_text(encoding="utf-8")

def _emit(ctx: click.Context, data: Any, columns: list[str]) -> None:
    """Emit data as selected output format."""
    fmt_json(data) if ctx.obj["output"] == "json" else fmt_table(data, columns)
def _query(data: dict[str, Any]) -> str:
    """Build query string from optional fields."""
    return urlencode({k: v for k, v in data.items() if v is not None})

def _ok(command: str) -> None:
    """Log command success."""
    log.info("nrvq.cli.command_ok", command=command, code="NRVQ-CLI-8003")
_load_dotenv()
@click.group()
@click.option("--api-url", envvar="NRVQ_API_URL", default=DEFAULT_API_URL, show_default=True)
@click.option("--token", envvar="NRVQ_API_TOKEN", default="")
@click.option("--output", "-o", type=click.Choice(["table", "json"]), default="table")
@click.pass_context
def cli(ctx: click.Context, api_url: str, token: str, output: str) -> None:
    """Norviq CLI for runtime policy operations."""
    ctx.ensure_object(dict)
    ctx.obj["client"] = APIClient(api_url, token)
    ctx.obj["output"] = output
    ctx.obj["api_url"] = api_url
    ctx.obj["token"] = token
    log.info("nrvq.cli.started", api_url=api_url, code="NRVQ-CLI-8000")
@cli.command()
@click.pass_context
def status(ctx: click.Context) -> None:
    """Show API readiness summary."""
    client = ctx.obj["client"]
    health = client.get("/healthz")
    ready = client.get("/readyz")
    click.echo(f"API:   {'Online' if health.get('status') == 'ok' else 'Offline'}")
    click.echo(f"Redis: {'Connected' if ready.get('redis') else 'Disconnected'}")
    click.echo(f"DB:    {'Connected' if ready.get('db') else 'Disconnected'}")
    _ok("status")
@cli.group()
def policy() -> None:
    """Manage policies."""
@policy.command("list")
@click.pass_context
def policy_list(ctx: click.Context) -> None:
    """List all policies."""
    data = ctx.obj["client"].get("/api/v1/policies")
    _emit(ctx, data, ["namespace", "agent_class", "current_version", "rego_length"])
    _ok("policy.list")
@policy.command("get")
@click.argument("namespace")
@click.argument("agent_class")
@click.pass_context
def policy_get(ctx: click.Context, namespace: str, agent_class: str) -> None:
    """Get one policy and source."""
    data = ctx.obj["client"].get(f"/api/v1/policies/{namespace}/{agent_class}")
    if ctx.obj["output"] == "json":
        fmt_json(data)
    else:
        fmt_policy(data)
    _ok("policy.get")
@policy.command("create")
@click.option("-f", "--file", "rego_file", required=True, type=click.Path(exists=True))
@click.option("-n", "--namespace", required=True)
@click.option("-c", "--class", "agent_class", required=True)
@click.option("--mode", type=click.Choice(["block", "audit", "escalate"]), default="block")
@click.pass_context
def policy_create(ctx: click.Context, rego_file: str, namespace: str, agent_class: str, mode: str) -> None:
    """Create or update policy."""
    payload = {
        "namespace": namespace,
        "agent_class": agent_class,
        "rego_source": _read_rego(rego_file),
        "enforcement_mode": mode,
        "saved_by": "cli",
    }
    data = ctx.obj["client"].post("/api/v1/policies", payload)
    click.echo(f"Policy created: {namespace}/{agent_class} v{data.get('version', '?')}")
    _ok("policy.create")
@policy.command("delete")
@click.argument("namespace")
@click.argument("agent_class")
@click.confirmation_option(prompt="Delete this policy?")
@click.pass_context
def policy_delete(ctx: click.Context, namespace: str, agent_class: str) -> None:
    """Delete policy by key."""
    ctx.obj["client"].delete(f"/api/v1/policies/{namespace}/{agent_class}")
    click.echo(f"Policy deleted: {namespace}/{agent_class}")
    _ok("policy.delete")
@policy.command("versions")
@click.argument("namespace")
@click.argument("agent_class")
@click.pass_context
def policy_versions(ctx: click.Context, namespace: str, agent_class: str) -> None:
    """List policy versions."""
    data = ctx.obj["client"].get(f"/api/v1/policies/{namespace}/{agent_class}/versions")
    _emit(ctx, data, ["version", "saved_by", "saved_at"])
    _ok("policy.versions")
@policy.command("rollback")
@click.argument("namespace")
@click.argument("agent_class")
@click.argument("version", type=int)
@click.pass_context
def policy_rollback(ctx: click.Context, namespace: str, agent_class: str, version: int) -> None:
    """Rollback policy version."""
    ctx.obj["client"].post(f"/api/v1/policies/{namespace}/{agent_class}/rollback", {"target_version": version})
    click.echo(f"Rolled back to v{version}")
    _ok("policy.rollback")
@policy.command("dry-run")
@click.option("-f", "--file", "rego_file", required=True, type=click.Path(exists=True))
@click.option("-n", "--namespace", required=True)
@click.option("-c", "--class", "agent_class", required=True)
@click.pass_context
def policy_dry_run(ctx: click.Context, rego_file: str, namespace: str, agent_class: str) -> None:
    """Run policy dry run."""
    data = ctx.obj["client"].post(
        "/api/v1/policies/dry-run",
        {"namespace": namespace, "agent_class": agent_class, "rego_source": _read_rego(rego_file)},
    )
    click.echo(f"Records checked: {data.get('total_records_checked', 0)}")
    click.echo(f"Would block: {data.get('would_block', 0)}")
    click.echo(f"Would allow: {data.get('would_allow', 0)}")
    click.echo(f"Recommendation: {data.get('recommendation', 'N/A')}")
    _ok("policy.dry-run")
@policy.command("apply")
@click.argument("namespace")
@click.argument("agent_class")
@click.option("--target-type", type=click.Choice(["agent_class", "workload", "namespace"]), default="agent_class")
@click.option("--target-ns", required=True)
@click.option("--mode", type=click.Choice(["block", "audit", "escalate"]), default="block")
@click.pass_context
def policy_apply(ctx: click.Context, namespace: str, agent_class: str, target_type: str, target_ns: str, mode: str) -> None:
    """Apply policy to target scope."""
    payload = {"target_type": target_type, "target_namespace": target_ns, "enforcement_mode": mode}
    data = ctx.obj["client"].post(f"/api/v1/policies/{namespace}/{agent_class}/apply", payload)
    click.echo(f"Applied: {data.get('applied', False)}")
    _ok("policy.apply")
@cli.group()
def audit() -> None:
    """Query audit data."""
@audit.command("list")
@click.option("--namespace", "-n", default=None)
@click.option("--decision", "-d", type=click.Choice(["allow", "block", "escalate", "audit"]), default=None)
@click.option("--tool", "-t", default=None)
@click.option("--range", "time_range", default=DEFAULT_RANGE)
@click.option("--limit", "-l", default=DEFAULT_LIMIT, type=int)
@click.pass_context
def audit_list(ctx: click.Context, namespace: str | None, decision: str | None, tool: str | None, time_range: str, limit: int) -> None:
    """List audit records."""
    query = _query({"namespace": namespace, "decision": decision, "tool_name": tool, "range": time_range, "limit": limit})
    data = ctx.obj["client"].get(f"/api/v1/audit/records?{query}")
    _emit(ctx, data, ["timestamp", "tool_name", "decision", "rule_id", "namespace", "trust_score", "latency_ms"])
    _ok("audit.list")
@audit.command("stats")
@click.option("--range", "time_range", default=DEFAULT_RANGE)
@click.option("--namespace", "-n", default=None)
@click.pass_context
def audit_stats(ctx: click.Context, time_range: str, namespace: str | None) -> None:
    """Show audit statistics."""
    query = _query({"range": time_range, "namespace": namespace})
    data = ctx.obj["client"].get(f"/api/v1/audit/stats?{query}")
    if ctx.obj["output"] == "json":
        fmt_json(data)
    else:
        click.echo(f"Total: {data.get('total', 0)}")
        click.echo(f"Blocked: {data.get('blocked', 0)}")
        click.echo(f"Allowed: {data.get('allowed', 0)}")
    _ok("audit.stats")
@audit.command("top-blocked")
@click.option("--range", "time_range", default=DEFAULT_RANGE)
@click.option("--namespace", "-n", default=None)
@click.pass_context
def audit_top_blocked(ctx: click.Context, time_range: str, namespace: str | None) -> None:
    """Show top blocked tools."""
    query = _query({"range": time_range, "namespace": namespace})
    data = ctx.obj["client"].get(f"/api/v1/audit/top-blocked?{query}")
    _emit(ctx, data, ["tool_name", "count"])
    _ok("audit.top-blocked")
@cli.group()
def agent() -> None:
    """Manage agents."""
@agent.command("list")
@click.pass_context
def agent_list(ctx: click.Context) -> None:
    """List known agents."""
    data = ctx.obj["client"].get("/api/v1/agents")
    _emit(ctx, data, ["spiffe_id", "score", "category", "violation_count"])
    _ok("agent.list")
@agent.command("get")
@click.argument("spiffe_id")
@click.pass_context
def agent_get(ctx: click.Context, spiffe_id: str) -> None:
    """Show one agent trust score."""
    data = ctx.obj["client"].get(f"/api/v1/agents/{spiffe_id}")
    if ctx.obj["output"] == "json":
        fmt_json(data)
    else:
        click.echo(f"Agent: {data.get('spiffe_id')}")
        click.echo(f"Trust: {data.get('score')} ({data.get('category')})")
        click.echo(f"Violations: {data.get('violation_count')}")
    _ok("agent.get")
@agent.command("reset-trust")
@click.argument("spiffe_id")
@click.option("--score", default=0.8, type=float)
@click.pass_context
def agent_reset_trust(ctx: click.Context, spiffe_id: str, score: float) -> None:
    """Reset an agent trust score."""
    data = ctx.obj["client"].put(f"/api/v1/agents/{spiffe_id}/trust", {"score": score})
    click.echo(f"Trust reset: {data.get('spiffe_id')} -> {data.get('score')} ({data.get('category')})")
    _ok("agent.reset-trust")
@agent.command("freeze")
@click.argument("spiffe_id")
@click.pass_context
def agent_freeze(ctx: click.Context, spiffe_id: str) -> None:
    """Freeze agent trust to zero."""
    ctx.obj["client"].put(f"/api/v1/agents/{spiffe_id}/trust", {"score": 0.0})
    click.echo(f"Agent frozen: {spiffe_id}")
    _ok("agent.freeze")
@cli.group()
def config() -> None:
    """Manage CLI settings."""
@config.command("show")
@click.pass_context
def config_show(ctx: click.Context) -> None:
    """Show active config values."""
    token = ctx.obj["token"]
    masked = f"****{token[-4:]}" if token else "(not set)"
    click.echo(f"API URL: {ctx.obj['api_url']}")
    click.echo(f"Token: {masked}")
    click.echo(f"Output: {ctx.obj['output']}")
    _ok("config.show")
@config.command("set")
@click.argument("key")
@click.argument("value")
@click.pass_context
def config_set(ctx: click.Context, key: str, value: str) -> None:
    """Set one in-memory config value."""
    allowed = {"api_url", "token", "output"}
    if key not in allowed:
        log.error("nrvq.cli.config_invalid", key=key, code="NRVQ-CLI-8004")
        raise click.ClickException(f"Unsupported key: {key}")
    ctx.obj[key] = value
    click.echo(f"Set {key}={value}")
    _ok("config.set")


cli.add_command(redteam)


def main() -> None:
    """Run CLI entry point."""
    cli()

if __name__ == "__main__":
    main()
