"""`file` with no path degrades to an in-process pin store on purpose. It must never do so silently.

The HTTP proxy warned (NRVQ-MCP-5067). The stdio proxy did not: `stdio.py` called `build_store`
bare, so `NRVQ_MCP_PIN_STORE=file` with no `NRVQ_MCP_PIN_PATH` produced a MemoryPinStore with no log
line at all — while the identical misconfiguration on HTTP warned. Verified end to end through the
shipped `python -m norviq.mcp` entrypoint: stdio reached `proxy.started` with zero occurrences of
the code across both streams; HTTP emitted exactly one. Same env, same MemoryPinStore, one transport
said so.

stdio is the path the published quickstart recommends, so every reader following it got no drift
detection and no warning that they lacked it. The warning now lives in `build_store`, where no
caller can forget it, and these tests pin that on the unit AND through the real stdio entrypoint.
"""

from __future__ import annotations

import os
import subprocess
import sys

import structlog

from norviq.mcp.pins import MemoryPinStore, build_store, effective_store_kind


def _degradation_events(kind: str, path: str) -> list[dict]:
    with structlog.testing.capture_logs() as logs:
        store = build_store(kind, path)
    assert isinstance(store, MemoryPinStore) == (effective_store_kind(kind, path) == "memory")
    return [e for e in logs if e.get("code") == "NRVQ-MCP-5078"]


def test_file_without_a_path_is_announced():
    events = _degradation_events("file", "")
    assert len(events) == 1, events
    assert events[0]["configured"] == "file" and events[0]["using"] == "memory"


def test_the_announcement_is_not_vacuous(tmp_path):
    """Controls: the cases that are NOT degradations must stay silent, or the warning is noise."""
    assert _degradation_events("file", str(tmp_path / "pins.json")) == []
    assert _degradation_events("memory", "") == []
    assert _degradation_events("", "") == []  # unset means the default, not a downgrade


def _run_stdio_proxy(env: dict[str, str]) -> str:
    """Start the real entrypoint the quickstart names, give it a real (closed) stdin pipe, and read
    whatever it logged before we stop it. The proxy does not exit on its own once the upstream is
    up, so this is a bounded observation, not a run to completion. Both streams are returned: the
    stdio transport routes logs to stderr, the HTTP one to stdout, and reading only one of them is
    how a warning gets reported as absent."""
    proc = subprocess.Popen(
        [sys.executable, "-m", "norviq.mcp", "--server-id", "degradation-probe", "--", "cat"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env,
    )
    try:
        out, err = proc.communicate(input="", timeout=15)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, err = proc.communicate()
    return out + err


def _env(**overrides: str) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k != "NRVQ_MCP_PIN_PATH"}
    env.update({"NRVQ_MCP_PIN_STORE": "file", "NRVQ_LOG_LEVEL": "WARNING", "NO_PROXY": "*"})
    env.update(overrides)
    return env


def test_the_stdio_entrypoint_actually_reaches_it():
    """The unit test proves build_store warns. This proves the transport that FORGOT to warn now
    goes through the code that does — by running the real entrypoint, the way the quickstart says."""
    both = _run_stdio_proxy(_env())
    assert "NRVQ-MCP-5078" in both, f"stdio started without announcing the degraded store:\n{both[-1500:]}"


def test_the_stdio_entrypoint_is_quiet_when_configured_correctly(tmp_path):
    """Control for the test above: with a path, the same entrypoint must NOT warn, or the assertion
    is matching noise the proxy always emits."""
    both = _run_stdio_proxy(_env(NRVQ_MCP_PIN_PATH=str(tmp_path / "pins.json")))
    assert "NRVQ-MCP-5078" not in both, both[-800:]
