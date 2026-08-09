# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Entry point for the demo MCP servers.

    python -m demo_mcp --server kb    # or crm, or ops

One image, three roles, chosen by a flag. The alternative -- three images, or three CMDs -- would
mean three things to rebuild every time a tool's description changes, and the descriptions are
exactly what Norviq's Gate A reads, so they change often while the demo is being tuned.
"""

from __future__ import annotations

import argparse
import asyncio
import sys

from .servers import SERVER_IDS, build_server, verify_catalog


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="python -m demo_mcp",
        description="Run one of the Norviq chatbot demo's upstream MCP servers.",
    )
    # `choices` rather than a hand-rolled check: argparse then prints the valid ids and exits 2,
    # which is the behaviour the container contract wants (non-zero, and a message that says what
    # was expected). A hand-rolled check tends to grow a helpful default and start a server nobody
    # asked for -- the failure mode where a typo in a manifest silently deploys the wrong surface.
    parser.add_argument("--server", required=True, choices=SERVER_IDS, help="which server to run")
    # Bind rationale is in servers.build_server: a Service and a kubelet probe both arrive on the
    # pod IP, so localhost would fail both.
    parser.add_argument(
        "--host",
        default="0.0.0.0",  # nosec B104 - reached from other pods via a Service
        help="bind address (default: 0.0.0.0)",
    )
    parser.add_argument("--port", type=int, default=8080, help="bind port (default: 8080)")
    return parser.parse_args(argv)


async def _serve(server_id: str, host: str, port: int) -> None:
    mcp = build_server(server_id, host=host, port=port)
    # Before the listener binds, not after. A catalog that does not match the contract is a
    # deployment that will fail its policy checks in a way that looks like a policy bug, so it is
    # worth one round-trip through the tool manager to turn that into a start-up crash instead.
    names = await verify_catalog(mcp, server_id)
    print(f"demo_mcp: server={server_id} listen={host}:{port} path=/mcp tools={', '.join(names)}", flush=True)
    await mcp.run_streamable_http_async()


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        asyncio.run(_serve(args.server, args.host, args.port))
    except KeyboardInterrupt:
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())
