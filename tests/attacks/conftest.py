# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

import json
import os
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
import pytest
import redis

API_URL = os.getenv("NRVQ_API_URL", "http://127.0.0.1:8080")
API_TOKEN = os.getenv("NRVQ_API_TOKEN", "")
REDIS_URL = os.getenv("NRVQ_REDIS_URL", "redis://127.0.0.1:6379/0")
REVIEWS_DIR = Path(".reviews")
RESULTS_FILE = REVIEWS_DIR / "DAY8-attacks.md"

# Default identity derived by evaluate() for namespace=default, class=customer-support.
DEFAULT_SPIFFE = "spiffe://norviq/ns/default/sa/customer-support"


@pytest.fixture(scope="session")
def redis_client():
    """Shared sync Redis client for seeding agent state; None if unreachable."""
    try:
        client = redis.Redis.from_url(REDIS_URL, decode_responses=True)
        client.ping()
    except Exception:
        yield None
        return
    try:
        yield client
    finally:
        client.close()


@dataclass
class EvalResult:
    """Parsed evaluation result."""

    decision: str
    rule_id: str
    trust_score: float
    latency_ms: float
    raw: dict[str, Any]


@pytest.fixture(scope="session")
def api() -> httpx.Client:
    """Shared keep-alive HTTP client for Norviq API.

    Session-scoped with a bounded keep-alive pool so the whole suite reuses a few
    TCP connections instead of opening one per test — avoids Windows ephemeral-port
    exhaustion (WinError 10048/10055) under rapid sequential evaluation calls.
    """
    headers = {"Content-Type": "application/json"}
    if API_TOKEN:
        headers["Authorization"] = f"Bearer {API_TOKEN}"
    limits = httpx.Limits(max_keepalive_connections=8, max_connections=8)
    client = httpx.Client(base_url=API_URL, headers=headers, timeout=10, limits=limits)
    try:
        yield client
    finally:
        client.close()


@pytest.fixture(scope="session", autouse=True)
def ensure_attack_agent_policy(api: httpx.Client) -> None:
    """Ensure brand-new-agent has a runnable policy in local attack runs."""
    if not API_TOKEN:
        return
    try:
        src = api.get("/api/v1/policies/default/customer-support")
        src.raise_for_status()
        rego_source = src.json().get("rego_source", "")
        if not rego_source:
            return
        payload = {
            "namespace": "default",
            "agent_class": "brand-new-agent",
            "rego_source": rego_source,
            "enforcement_mode": "block",
            "saved_by": "attack-suite",
            "priority": 700,
        }
        api.post("/api/v1/policies", json=payload).raise_for_status()
    except Exception:
        # Keep suite behavior unchanged if a target API doesn't expose policy admin.
        return


def evaluate(
    api: httpx.Client,
    tool_name: str,
    tool_params: dict[str, Any],
    namespace: str = "default",
    agent_class: str = "customer-support",
    trust_score: float = 0.8,
    session_id: str = "attack-test",
    chain_depth: int = 0,
) -> EvalResult:
    """Send a tool call to Norviq and return the decision."""
    payload = {
        "tool_name": tool_name,
        "tool_params": tool_params,
        "agent_identity": {
            "spiffe_id": f"spiffe://norviq/ns/{namespace}/sa/{agent_class}",
            "namespace": namespace,
            "agent_class": agent_class,
        },
        "session_id": session_id,
        "trust_score": trust_score,
        "chain_depth": chain_depth,
    }
    try:
        resp = api.post("/api/v1/evaluate", json=payload)
    except (httpx.ConnectError, httpx.TimeoutException) as exc:
        pytest.xfail(f"Norviq API unavailable at {API_URL}: {exc}")
    resp.raise_for_status()
    data = resp.json()
    return EvalResult(
        decision=data.get("decision", "unknown"),
        rule_id=data.get("rule_id", ""),
        trust_score=float(data.get("trust_score", 0.0)),
        latency_ms=float(data.get("latency_ms", 0.0)),
        raw=data,
    )


@pytest.fixture
def frozen_agent(redis_client):
    """Admin-freeze the default agent in Redis for one test, then clean up.

    The engine reads ``agent_frozen:{spiffe_id}`` (calculator.py): any truthy value
    forces score=0.0, category=frozen, and a Python-side block override.
    """
    client = redis_client
    if client is None:
        pytest.xfail(f"Redis unavailable at {REDIS_URL}; cannot seed frozen state")
    key = f"agent_frozen:{DEFAULT_SPIFFE}"
    client.set(key, "1", ex=120)
    try:
        yield DEFAULT_SPIFFE
    finally:
        client.delete(key)


@pytest.fixture
def low_trust_agent(redis_client):
    """Seed history + profile so the default agent recomputes to low trust (<0.4).

    Drives violation_rate=0.0, scope_drift=0.0, tool_novelty=0.2, param_entropy=0.2,
    time_decay=0.1, session_velocity=0.3 → weighted score ~0.20 → category 'low' →
    'allow' decisions are overridden to 'escalate'.
    """
    client = redis_client
    if client is None:
        pytest.xfail(f"Redis unavailable at {REDIS_URL}; cannot seed low-trust state")
    hist_key = f"agent_history:{DEFAULT_SPIFFE}"
    prof_key = f"agent_profile:{DEFAULT_SPIFFE}"
    class_key = "agent_class:customer-support"
    client.delete(hist_key, prof_key, class_key)

    now = time.time()
    members: dict[str, float] = {}
    for i in range(30):  # 30 recent blocks within the last minute
        ts = now - i
        members[
            json.dumps(
                {
                    "i": i,
                    "tool_name": "noop_attack",
                    "decision": "block",
                    "timestamp": datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(),
                    "timestamp_unix": ts,
                }
            )
        ] = ts
    client.zadd(hist_key, members)
    client.hset(
        prof_key,
        mapping={
            "known_tools": json.dumps(["noop_tool"]),
            "param_entropy_baseline": json.dumps({"search_kb": {"mean": 1.0, "std": 0.2}}),
            "baseline_rpm": "10.0",
        },
    )
    client.hset(class_key, mapping={"blocked_tools": json.dumps(["search_kb"])})
    for key in (hist_key, prof_key, class_key):
        client.expire(key, 120)
    try:
        yield DEFAULT_SPIFFE
    finally:
        client.delete(hist_key, prof_key, class_key)


ALL_RESULTS: list[dict[str, Any]] = []


@pytest.fixture(autouse=True)
def collect_result(request: pytest.FixtureRequest):
    """Collect test outcomes to make a day report."""
    yield
    rep = getattr(request.node, "rep_call", None)
    ALL_RESULTS.append(
        {
            "name": request.node.name,
            "file": request.node.fspath.basename,
            "passed": bool(rep and rep.passed),
            "skipped": bool(rep and rep.skipped),
            "failed": bool(rep and rep.failed),
        }
    )


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item: pytest.Item, call: pytest.CallInfo[None]):
    outcome = yield
    rep = outcome.get_result()
    setattr(item, f"rep_{rep.when}", rep)


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    REVIEWS_DIR.mkdir(parents=True, exist_ok=True)
    total = len(ALL_RESULTS)
    passed = len([r for r in ALL_RESULTS if r["passed"]])
    failed = len([r for r in ALL_RESULTS if r["failed"]])
    skipped = len([r for r in ALL_RESULTS if r["skipped"]])
    pass_rate = (passed / total * 100.0) if total else 0.0

    lines = [
        "# DAY8 Attack Simulation Results",
        "",
        f"- API URL: `{API_URL}`",
        f"- Total: **{total}**",
        f"- Passed: **{passed}**",
        f"- Failed: **{failed}**",
        f"- Skipped: **{skipped}**",
        f"- Pass rate: **{pass_rate:.1f}%**",
        "",
        "## Test Outcomes",
        "",
    ]

    for result in ALL_RESULTS:
        status = "PASS" if result["passed"] else "FAIL" if result["failed"] else "SKIP"
        lines.append(f"- `{status}` `{result['file']}` :: `{result['name']}`")

    lines.append("")
    lines.append(f"- pytest exit status: `{exitstatus}`")
    try:
        RESULTS_FILE.write_text("\n".join(lines), encoding="utf-8")
    except PermissionError:
        # When running with shell tee/pipe to the same report file, the handle
        # can be temporarily locked by the parent process on Windows.
        pass
