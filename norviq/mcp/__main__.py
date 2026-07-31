# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Entrypoint for the Norviq MCP action-firewall.

    # stdio (the child-process model an MCP host spawns)
    python -m norviq.mcp --server-id filesystem -- npx -y @modelcontextprotocol/server-filesystem /work

    # streamable-HTTP (front a remote MCP server)
    python -m norviq.mcp --http --listen 0.0.0.0:9000 --upstream https://mcp.example.com/mcp

Configuration comes from the same environment the SDK and the injected sidecar already use
(NRVQ_POLICY_ENGINE_URL / NRVQ_API_TOKEN / NRVQ_SPIFFE_* / NRVQ_MCP_*), so a pod that is already
running a Norviq-governed agent needs no new configuration surface to gain MCP governance.
"""

from __future__ import annotations

import argparse
import asyncio
import sys

import structlog

log = structlog.get_logger()


def _parse(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="norviq-mcp",
        description="Policy-enforcing proxy for Model Context Protocol traffic.",
    )
    parser.add_argument("--http", action="store_true",
                        help="run the streamable-HTTP driver instead of stdio")
    parser.add_argument("--listen", default="127.0.0.1:9000",
                        help="HTTP mode: host:port to listen on (default 127.0.0.1:9000)")
    parser.add_argument("--upstream", default="",
                        help="HTTP mode: base URL of the upstream MCP endpoint")
    parser.add_argument("--server-id", default="",
                        help="stable id for the upstream server (keys the definition pins)")
    parser.add_argument("--session-id", default="",
                        help="session id reported to the policy engine (default: mcp-<server-id>)")
    parser.add_argument("--tool-name-prefix", default="",
                        help="prefix prepended to tool_name when evaluating. OFF by default: it breaks "
                             "the 1:1 mapping onto the engine's contract, so it is only for multi-server "
                             "deployments whose policies must distinguish two identically-named tools.")
    parser.add_argument("command", nargs=argparse.REMAINDER,
                        help="stdio mode: '--' followed by the upstream MCP server command")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse(argv if argv is not None else sys.argv[1:])

    if args.http:
        if not args.upstream:
            print("--http requires --upstream", file=sys.stderr)
            return 2
        from norviq.mcp.http import HttpProxy

        host, _, port = args.listen.rpartition(":")
        proxy = HttpProxy(
            upstream=args.upstream,
            host=host or "127.0.0.1",
            port=int(port),
            server_id=args.server_id or "upstream",
            tool_name_prefix=args.tool_name_prefix,
        )
        return asyncio.run(proxy.run())

    cmd = [a for a in args.command if a != "--"]
    if not cmd:
        print("stdio mode requires an upstream server command after '--'", file=sys.stderr)
        return 2

    from norviq.mcp.stdio import StdioProxy

    proxy = StdioProxy(
        server_cmd=cmd,
        server_id=args.server_id,
        session_id=args.session_id,
        tool_name_prefix=args.tool_name_prefix,
    )
    try:
        return asyncio.run(proxy.run())
    except KeyboardInterrupt:  # pragma: no cover - operator interrupt
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
