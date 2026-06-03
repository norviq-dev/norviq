# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
import pytest

API_URL = os.getenv("NRVQ_API_URL", "http://127.0.0.1:8080")
API_TOKEN = os.getenv("NRVQ_API_TOKEN", "")
REVIEWS_DIR = Path(".reviews")
RESULTS_FILE = REVIEWS_DIR / "DAY8-attacks.md"


@dataclass
class EvalResult:
    """Parsed evaluation result."""

    decision: str
    rule_id: str
    trust_score: float
    latency_ms: float
    raw: dict[str, Any]


@pytest.fixture
def api() -> httpx.Client:
    """HTTP client for Norviq API."""
    headers = {"Content-Type": "application/json"}
    if API_TOKEN:
        headers["Authorization"] = f"Bearer {API_TOKEN}"
    client = httpx.Client(base_url=API_URL, headers=headers, timeout=10)
    try:
        yield client
    finally:
        client.close()


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
