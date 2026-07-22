# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""A client that disconnects mid-conversation must not raise out of the connection callback.

Found during pentest prep by probing the live sidecar socket with a malformed request: the handler's
`except Exception` caught the read error, but the `finally` block's close()/wait_closed() ran
*outside* it, so an abrupt disconnect produced an "Unhandled exception in client_connected_cb"
traceback per connection. Any local peer that can reach the socket could generate that at will —
log spam that also buries the real NRVQ-SDC-3001 line.

Enforcement was never affected (nothing is forwarded without an allow), so this is a robustness
guard, not a policy one. These tests drive a real asyncio unix-socket server over a real socket.
"""

from __future__ import annotations

import asyncio
import json
import socket
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="unix sockets")


@pytest.fixture
def proxy_module():
    return pytest.importorskip("norviq.sidecar.proxy")


def _make_proxy(proxy_module, tmp_path, decision_action="forward"):
    """A SidecarProxy wired to a stub evaluator, serving on a temp socket."""
    SidecarProxy = getattr(proxy_module, "SidecarProxy", None)
    if SidecarProxy is None:  # pragma: no cover - class rename guard
        pytest.skip("SidecarProxy not exported from norviq.sidecar.proxy")
    return SidecarProxy, tmp_path / "probe.sock"


async def _serve_one(handler, sock_path):
    server = await asyncio.start_unix_server(handler, path=str(sock_path))
    return server


@pytest.mark.asyncio
async def test_abrupt_disconnect_does_not_escape_the_callback(proxy_module, caplog):
    """Client closes without reading the response -> teardown must swallow the broken pipe."""
    # NOT pytest's tmp_path: sockaddr_un caps the path near 104 bytes on macOS and pytest's
    # per-test temp dirs blow through that ("AF_UNIX path too long").
    import tempfile
    import uuid
    sock_dir = tempfile.mkdtemp(prefix="nq", dir="/tmp")
    sock_path = Path(sock_dir) / f"{uuid.uuid4().hex[:6]}.sock"
    escaped: list[BaseException] = []

    # Reuse the REAL handler; give it a trivial _process_request via a tiny stand-in object.
    class _Stub:
        _process_request = staticmethod(
            lambda raw: asyncio.sleep(0, result=json.dumps({"action": "forward"}))
        )

    handler = proxy_module.SidecarProxy._handle_connection.__get__(_Stub(), _Stub)

    async def wrapped(reader, writer):
        try:
            await handler(reader, writer)
        except BaseException as exc:  # noqa: BLE001 - the whole point is to catch escapes
            escaped.append(exc)

    server = await _serve_one(wrapped, sock_path)
    try:
        c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        c.connect(str(sock_path))
        c.sendall(b'{"tool_name":"x","tool_params":{},"session_id":"s"}\n')
        # Slam the connection shut without reading -> writer.drain()/close() hits a broken pipe.
        c.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, __import__("struct").pack("ii", 1, 0))
        c.close()
        await asyncio.sleep(0.3)
    finally:
        server.close()
        await server.wait_closed()

    assert not escaped, f"exception escaped the connection callback: {escaped!r}"


@pytest.mark.asyncio
async def test_malformed_line_is_answered_fail_closed(proxy_module, tmp_path):
    """Garbage in must produce a drop, not a crash — the live probe's original symptom."""
    process = proxy_module.SidecarProxy._process_request

    class _Stub:
        pass

    out = await process.__get__(_Stub(), _Stub)("this is not json")
    parsed = json.loads(out)
    assert parsed.get("action") == "drop", f"malformed input must fail closed, got {parsed}"
