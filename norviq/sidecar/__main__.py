# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
"""Sidecar process entrypoint (`python -m norviq.sidecar`): runs the Unix-socket proxy
alongside its HTTP fallback server until interrupted."""
import asyncio

import uvicorn

from norviq.config import settings
from norviq.sidecar.http_fallback import create_http_fallback
from norviq.sidecar.proxy import SidecarProxy


async def main() -> None:
    """Start sidecar Unix socket proxy and HTTP fallback server."""
    proxy = SidecarProxy()
    await proxy.start()
    app = create_http_fallback(proxy._interceptor, proxy._emitter, proxy._resolver)
    config = uvicorn.Config(app, host="0.0.0.0", port=settings.http_fallback_port, log_level="error")
    server = uvicorn.Server(config)

    try:
        await server.serve()
    except (KeyboardInterrupt, SystemExit):
        pass
    finally:
        await proxy.stop()


if __name__ == "__main__":
    asyncio.run(main())
