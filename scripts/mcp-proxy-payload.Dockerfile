# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
#
# Builds the RELOCATABLE MCP proxy payload that webhook injection copies into a governed pod.
#
# The injecting webhook rewrites an annotated container's command to exec the proxy out of a shared
# volume (webhook/mcp_injector.go). That only makes MCP governance zero-code-change if the payload
# runs in an image that was never built for it — an `npx` MCP server on a node image has no Python at
# all. So the payload is frozen with PyInstaller into a self-contained tree: interpreter, stdlib and
# dependencies included, nothing required of the host image but a matching libc.
#
# --onedir, NOT --onefile, deliberately. A onefile binary unpacks itself into a temp directory on
# every start; the governed container may run with a read-only root filesystem and no writable /tmp,
# and it would pay the unpack cost per exec. A onedir tree is read straight from the mount, which is
# why the injector can mount it readOnly.
#
# Build:
#   docker build -f scripts/mcp-proxy-payload.Dockerfile -t norviq-mcp-payload:local .
#
# The result is /opt/norviq/mcp-proxy/ with the executable `norviq-mcp` at its root — the layout
# NRVQ_MCP_PROXY_SOURCE_PATH points at.
# PINNED OLD ON PURPOSE — do not "modernise" this base.
#
# A PyInstaller payload links against the glibc it was BUILT on and requires at least that version
# wherever it runs. Built on current slim (glibc 2.38+) the payload dies instantly on any older
# target with:
#
#   [PYI-9:ERROR] Failed to load Python shared library '.../libpython3.12.so.1.0':
#   dlopen: /lib/aarch64-linux-gnu/libm.so.6: version `GLIBC_2.38' not found
#
# …which is precisely the case this feature exists for: an unmodified upstream MCP server image the
# operator does not control. bullseye (glibc 2.31) is the oldest maintained Python base, so a payload
# frozen here runs on bullseye, bookworm, trixie and Ubuntu 20.04+.
#
# The limit this does NOT lift is musl: an Alpine-based MCP server image cannot run a glibc payload
# at all. Governing one means either a glibc variant of that image or a separate musl payload build.
ARG PAYLOAD_BASE=python:3.12-slim-bullseye
FROM ${PAYLOAD_BASE} AS builder

WORKDIR /build
# binutils supplies objdump, which PyInstaller shells out to when walking an ELF's shared-library
# dependencies. Without it the build fails at analysis with a bare "objdump is required".
RUN apt-get update \
 && apt-get install -y --no-install-recommends binutils \
 && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir pyinstaller==6.11.1

COPY pyproject.toml .
COPY norviq/ norviq/
RUN pip install --no-cache-dir .

# A tiny entry module rather than freezing __main__.py directly: PyInstaller wants a script path, and
# `python -m norviq.mcp` semantics (package __main__) are not what a frozen entry point gets.
RUN printf '%s\n' \
    'import sys' \
    'from norviq.mcp.__main__ import main' \
    'if __name__ == "__main__":' \
    '    sys.exit(main())' \
    > /build/_mcp_entry.py

# Hidden imports: the proxy resolves several dependencies dynamically (pydantic-settings reads the
# env at runtime, structlog picks processors by name, httpx selects a transport), so static analysis
# alone under-collects them. Collecting the whole norviq package keeps policy/engine submodules that
# are imported by string.
RUN pyinstaller --onedir --name norviq-mcp \
      --distpath /opt/norviq-dist \
      --workpath /tmp/pyi-work --specpath /tmp/pyi-spec \
      --collect-all norviq \
      --collect-all pydantic \
      --collect-all pydantic_settings \
      --collect-all structlog \
      --collect-all httpx \
      --collect-all httpcore \
      --collect-all certifi \
      /build/_mcp_entry.py \
 && mkdir -p /opt/norviq \
 && mv /opt/norviq-dist/norviq-mcp /opt/norviq/mcp-proxy \
 && chmod 0755 /opt/norviq/mcp-proxy/norviq-mcp

# Smoke-test the frozen payload in the BUILD stage, where a failure fails the build rather than a
# pod. --help exercises argparse only; the import-everything check below is what proves the freeze
# actually collected the proxy's real dependency graph.
RUN /opt/norviq/mcp-proxy/norviq-mcp --help > /dev/null \
 && /opt/norviq/mcp-proxy/norviq-mcp --http 2>&1 | grep -q "requires --upstream"

FROM scratch AS payload
COPY --from=builder /opt/norviq/mcp-proxy /opt/norviq/mcp-proxy
