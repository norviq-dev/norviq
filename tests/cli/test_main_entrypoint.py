# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Tests for the console entry point (main), run in a subprocess."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# What the stub API answers for GET /api/v1/policies. Shaped like the real list, but its only job is
# to be recognisable on the far side of stdout.
_POLICIES = [{"namespace": "agents", "agent_class": "support-bot", "priority": 100}]


def _cli_env() -> dict[str, str]:
    """The test's own environment minus every proxy variable.

    subprocess.run inherits the environment, and httpx honours HTTP(S)_PROXY / ALL_PROXY. Under a
    proxy the deliberately-unreachable 127.0.0.1:1 and the loopback stub below are both routed
    through it, so the error path no longer produces a connect error and the success path never
    reaches the stub (measured: the error-path test failed on `returncode != 0` behind a proxy).
    tests/mcp/test_stdio_transport.py passes an explicit env for the same reason.
    """
    env = {k: v for k, v in os.environ.items() if k.lower() not in {"http_proxy", "https_proxy", "all_proxy"}}
    env["NO_PROXY"] = env["no_proxy"] = "*"
    return env


def _run_cli(api_url: str, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "norviq.cli.main", "--api-url", api_url, "-o", "json", *args],
        capture_output=True,
        text=True,
        timeout=60,
        env=_cli_env(),
    )


def test_json_payload_reaches_stdout_and_logs_go_to_stderr() -> None:
    """main() sends structlog lines to stderr so -o json stays pipeable."""
    proc = _run_cli("http://127.0.0.1:1", "policy", "list")

    assert proc.returncode != 0, "the unreachable-API error path is expected"
    assert "nrvq.cli.started" in proc.stderr
    assert "nrvq.cli.connect_error" in proc.stderr
    assert "nrvq.cli.started" not in proc.stdout
    assert "nrvq.cli.command_ok" not in proc.stdout


class _PoliciesHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - http.server's naming
        found = self.path.split("?")[0] == "/api/v1/policies"
        body = json.dumps(_POLICIES).encode() if found else b"{}"
        self.send_response(200 if found else 404)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args) -> None:  # keep the test output clean
        return


def test_successful_json_output_on_stdout_parses_as_json() -> None:
    """The half the test above cannot see: on SUCCESS, stdout is exactly the JSON payload.

    The error-path test only asserts that log lines are absent from stdout, so moving the payload to
    stderr as well would leave it green while `norviq -o json policy list | jq` reads nothing. This
    asserts what issue #104 asked for — `json.loads(proc.stdout)` — against a stub API, and that the
    success log line (`nrvq.cli.command_ok`) still arrives, on stderr.
    """
    server = ThreadingHTTPServer(("127.0.0.1", 0), _PoliciesHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        proc = _run_cli(f"http://127.0.0.1:{server.server_address[1]}", "policy", "list")
    finally:
        server.shutdown()
        server.server_close()

    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout) == _POLICIES
    assert "nrvq.cli.command_ok" in proc.stderr
