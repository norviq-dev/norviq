# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
"""Sidecar process entrypoint (`python -m norviq.sidecar`): runs the Unix-socket proxy
alongside its HTTP fallback server until interrupted."""
import asyncio

import uvicorn

import structlog

from norviq.config import settings
from norviq.logging_setup import configure_logging
from norviq.sidecar.http_fallback import create_http_fallback
from norviq.sidecar.proxy import SidecarProxy

log = structlog.get_logger()


async def main() -> None:
    """Start sidecar Unix socket proxy and HTTP fallback server."""
    # BEFORE anything logs. norviq/api/main.py was the ONLY configure_logging() call site, so
    # NRVQ_LOG_LEVEL was still completely inert in THIS process — the one that sits beside every
    # governed agent and logs every enforcement decision. An operator setting config.logLevel=WARNING
    # to keep decision and identity detail out of a shared sink got a quieter API and a fully verbose
    # enforcement plane, which is the exact scenario logging_setup's own docstring names as why the
    # knob is not merely cosmetic.
    applied = configure_logging()
    log.info("nrvq.sidecar.log_level_applied", level=applied, code="NRVQ-SDC-3013")
    proxy = SidecarProxy()
    await proxy.start()
    app = create_http_fallback(proxy._interceptor, proxy._emitter, proxy._resolver)
    config = uvicorn.Config(app, host="0.0.0.0", port=settings.http_fallback_port, log_level="error")  # nosec B104 - HTTP fallback for the injected sidecar; binds within the pod's own network namespace (the app container reaches it on 127.0.0.1), never exposed as a Service
    server = uvicorn.Server(config)

    try:
        await server.serve()
    except (KeyboardInterrupt, SystemExit):
        pass
    finally:
        await proxy.stop()


if __name__ == "__main__":
    asyncio.run(main())
