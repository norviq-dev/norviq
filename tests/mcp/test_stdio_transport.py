# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""End-to-end tests of the stdio driver as a real subprocess.

These spawn the actual `python -m norviq.mcp` binary against a stub policy engine, because the
failures this catches are precisely the ones an in-process test cannot see: what gets written to
file descriptor 1, whether messages are framed, and whether the process exits without losing
in-flight replies. Two shipped bugs came from exactly there.
"""

from __future__ import annotations

import asyncio
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest


class _StubEngine(BaseHTTPRequestHandler):
    """Answers /api/v1/evaluate: blocks anything whose tool name starts with `delete`."""

    def do_POST(self):  # noqa: N802 - BaseHTTPRequestHandler's interface
        length = int(self.headers.get("content-length", 0))
        body = json.loads(self.rfile.read(length) or b"{}")
        blocked = str(body.get("tool_name", "")).startswith("delete")
        payload = json.dumps({
            "decision": "block" if blocked else "allow",
            "rule_id": "stub_block" if blocked else "stub_allow",
            "trust_score": 1.0,
        }).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *_args):  # keep the test output readable
        pass


@pytest.fixture()
def stub_engine():
    server = HTTPServer(("127.0.0.1", 0), _StubEngine)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()


async def _run_session(engine_url: str, server: str, messages: list[dict]) -> tuple[list[dict], bytes]:
    """Drive one proxy session over real pipes; return (parsed stdout messages, raw stderr)."""
    proc = await asyncio.create_subprocess_exec(
        sys.executable, "-m", "norviq.mcp", "--server-id", server, "--",
        sys.executable, "-m", "norviq.mcp.adversarial.servers", server,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env={
            "PATH": "/usr/bin:/bin", "PYTHONPATH": ".", "PYTHONUNBUFFERED": "1",
            "NRVQ_POLICY_ENGINE_URL": engine_url,
            "NRVQ_NAMESPACE": "agents", "NRVQ_AGENT_CLASS": "mcp-agent",
        },
    )
    payload = b"".join(json.dumps(m).encode() + b"\n" for m in messages)
    stdout, stderr = await asyncio.wait_for(proc.communicate(payload), timeout=60)
    parsed = [json.loads(line) for line in stdout.splitlines() if line.strip()]
    return parsed, stderr


async def test_stdout_carries_only_json_rpc(stub_engine):
    """The single most important property of a stdio server: fd 1 is the protocol, not a log."""
    messages = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
    ]
    parsed, stderr = await _run_session(stub_engine, "benign", messages)
    assert len(parsed) == 2, "every line on stdout must be a JSON-RPC message"
    assert all(m.get("jsonrpc") == "2.0" for m in parsed)
    # ...and the logs still had to go somewhere. Silently dropping them would be its own bug.
    assert b"nrvq.mcp.proxy.started" in stderr


async def test_in_flight_replies_survive_client_eof(stub_engine):
    """Closing stdin after the last request is how a scripted session ends; it must not lose replies."""
    messages = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
         "params": {"name": "search_docs", "arguments": {"query": "x"}}},
    ]
    parsed, _ = await _run_session(stub_engine, "benign", messages)
    assert {m["id"] for m in parsed} == {1, 2, 3}


async def test_blocked_call_never_reaches_the_server_over_a_real_pipe(stub_engine):
    messages = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
         "params": {"name": "delete_records", "arguments": {"table": "users"}}},
    ]
    parsed, _ = await _run_session(stub_engine, "benign", messages)
    blocked = next(m for m in parsed if m["id"] == 2)
    assert blocked["result"]["isError"] is True
    assert "stub_block" in json.dumps(blocked)
    # The upstream fixture echoes the arguments it executed; absence of that echo is the evidence.
    assert "benign:delete_records executed" not in json.dumps(parsed)


async def test_poisoned_catalog_is_neutralised_over_a_real_pipe(stub_engine):
    messages = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
    ]
    parsed, _ = await _run_session(stub_engine, "poisoned", messages)
    listing = next(m for m in parsed if m["id"] == 2)
    assert [t["name"] for t in listing["result"]["tools"]] == ["search_docs"]
    assert "id_rsa" not in json.dumps(listing)
