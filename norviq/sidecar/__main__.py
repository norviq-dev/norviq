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
    # "token" mode verifies remote callers' JWTs with api_secret_key. The same weak-key guard the API and
    # fleet hub apply: a shipped-default or short key makes every such token forgeable, so this mode must
    # refuse to start on one rather than authenticate against it.
    if str(settings.sidecar_remote_callers).lower() == "token":
        secret = settings.api_secret_key or ""
        if secret == "change-me-in-production" or len(secret) < 16:
            log.error("nrvq.sidecar.weak_secret_for_remote_callers", code="NRVQ-SDC-3043")
            if settings.require_strong_secret:
                raise RuntimeError("Refusing to start: sidecar_remote_callers=token needs a strong api_secret_key.")
    proxy = SidecarProxy()
    await proxy.start()
    app = create_http_fallback(proxy._interceptor, proxy._emitter, proxy._resolver)
    config = uvicorn.Config(app, host="0.0.0.0", port=settings.http_fallback_port, log_level="error")  # nosec B104 - all interfaces so kubelet probes (which dial the pod IP) reach /healthz and /readyz. /v1/evaluate refuses off-pod callers unless sidecar_remote_callers=token, which the chart sets only on the standalone engine Deployment (a ClusterIP Service); there it requires a service JWT. This comment used to say the port was never exposed as a Service, which was false for that Deployment.
    server = uvicorn.Server(config)

    try:
        await server.serve()
    except (KeyboardInterrupt, SystemExit):
        pass
    finally:
        await proxy.stop()


if __name__ == "__main__":
    asyncio.run(main())
