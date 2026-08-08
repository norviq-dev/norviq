# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""One place that makes `config.logLevel` mean something.

`NRVQ_LOG_LEVEL` was rendered into the ConfigMap by the chart, exposed as `config.logLevel` in
values.yaml, documented in configuration.md, and pointed at by deployment.md ("values-dev.yaml sets
logLevel: DEBUG so a dev install logs more"). Nothing outside the MCP stdio proxy ever configured
structlog, so the API, the engine and the injected sidecar all ran on structlog's default
PrintLogger — which emits everything. Setting `WARNING` or `ERROR` to cut volume, or to keep decision
and identity detail out of a shared log sink, changed nothing at all: the setting was accepted and the
logs kept coming. That last case is why this is not merely cosmetic — an operator can believe they have
narrowed what leaves the pod.

Kept deliberately small and dependency-free so every entrypoint can call it before anything logs.
"""

from __future__ import annotations

import logging

import structlog

from norviq.config import settings

_configured = False


def configure_logging(force: bool = False) -> str:
    """Apply `settings.log_level` to structlog and the stdlib root logger. Returns the level applied.

    Idempotent: repeated calls are a no-op unless `force`, so a worker that re-imports cannot reset a
    level an entrypoint deliberately chose.
    """
    global _configured
    if _configured and not force:
        return logging.getLevelName(logging.getLogger().level)

    raw = str(getattr(settings, "log_level", "INFO") or "INFO").strip().upper()
    level = getattr(logging, raw, None)
    if not isinstance(level, int):
        # An unrecognised level must not stop a pod from starting, and must not silently become
        # DEBUG either — fall back to INFO and say so once the logger exists.
        level = logging.INFO
        raw = "INFO"

    logging.basicConfig(level=level, format="%(message)s")
    logging.getLogger().setLevel(level)
    structlog.configure(
        wrapper_class=structlog.make_filtering_bound_logger(level),
        cache_logger_on_first_use=True,
    )
    _configured = True
    return raw
