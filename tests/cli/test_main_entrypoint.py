# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Tests for the console entry point (main), run in a subprocess."""

from __future__ import annotations

import subprocess
import sys


def test_json_payload_reaches_stdout_and_logs_go_to_stderr() -> None:
    """main() sends structlog lines to stderr so -o json stays pipeable."""
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "norviq.cli.main",
            "--api-url",
            "http://127.0.0.1:1",
            "-o",
            "json",
            "policy",
            "list",
        ],
        capture_output=True,
        text=True,
        timeout=60,
    )

    assert proc.returncode != 0, "the unreachable-API error path is expected"
    assert "nrvq.cli.started" in proc.stderr
    assert "nrvq.cli.connect_error" in proc.stderr
    assert "nrvq.cli.started" not in proc.stdout
    assert "nrvq.cli.command_ok" not in proc.stdout
