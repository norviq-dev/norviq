#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
#
# Proves the injected MCP proxy payload actually runs in images that were never built for it.
#
# Webhook injection (webhook/mcp_injector.go) rewrites an annotated container's command to exec the
# proxy out of a shared volume filled by an init container. The whole claim — MCP governance with no
# change to the workload's image — rests on that payload starting in an arbitrary upstream image. A
# unit test cannot check this: it is a property of the frozen binary and the target's libc.
#
# It is worth scripting because the failure is silent at build time and total at run time. Freezing
# on a current Python base produced a payload that ran fine in its own image and died instantly on
# Debian bookworm with:
#
#   [PYI-9:ERROR] Failed to load Python shared library '.../libpython3.12.so.1.0':
#   dlopen: .../libm.so.6: version `GLIBC_2.38' not found
#
# This script replays the exact init-container copy into a shared volume, then execs the payload from
# each target image with the mount READ-ONLY, exactly as an injected pod does.
#
# Usage:  scripts/mcp-proxy-payload-verify.sh [image ...]
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILDER_TAG="${BUILDER_TAG:-norviq-mcp-payload-builder:local}"
VOLUME="${VOLUME:-nrvq-mcp-payload-verify}"
# The mount paths the injector actually uses; kept in sync with webhook/mcp_injector.go.
STAGING="/norviq-mcp-staging"
MOUNT="/norviq/mcp"

# Defaults span the realistic MCP server bases: a Python-free node image (the `npx` servers), the
# glibc floor this payload targets, and a current Python base. Alpine is deliberately NOT here — a
# musl target cannot run a glibc payload, so including it would fail every run rather than report a
# regression. Pass it explicitly if you want to see that limit for yourself.
TARGETS=("$@")
if [[ ${#TARGETS[@]} -eq 0 ]]; then
  TARGETS=(node:20-slim debian:bookworm-slim python:3.12-slim ubuntu:22.04)
fi

say() { printf '\n\033[1m== %s\033[0m\n' "$*"; }

command -v docker >/dev/null || { echo "docker is required" >&2; exit 1; }

say "building the payload"
docker build -f "${REPO_ROOT}/scripts/mcp-proxy-payload.Dockerfile" \
  --target builder -t "$BUILDER_TAG" "$REPO_ROOT" >/dev/null
echo "  built $BUILDER_TAG"

say "init container: copying the payload into a shared volume"
docker volume rm -f "$VOLUME" >/dev/null 2>&1 || true
docker volume create "$VOLUME" >/dev/null
# Byte-for-byte the command mcpInitContainer() generates.
docker run --rm -v "${VOLUME}:${STAGING}" "$BUILDER_TAG" /bin/sh -c \
  "set -e; cp -a /opt/norviq/mcp-proxy/. ${STAGING}/; chmod 0755 ${STAGING}/norviq-mcp" >/dev/null
SIZE="$(docker run --rm -v "${VOLUME}:/v" "$BUILDER_TAG" du -sh /v | cut -f1)"
echo "  payload staged (${SIZE})"

say "exec from each target image, mount read-only"
FAILED=0
for image in "${TARGETS[@]}"; do
  printf '  %-24s ' "$image"
  # --entrypoint is overridden because some target images set one; the injected container execs the
  # payload as its command, which is what this must reproduce.
  if out="$(docker run --rm --entrypoint "${MOUNT}/norviq-mcp" \
              -v "${VOLUME}:${MOUNT}:ro" "$image" --help 2>&1)"; then
    if grep -q "Policy-enforcing proxy" <<<"$out"; then
      echo "OK"
    else
      echo "UNEXPECTED OUTPUT"; echo "$out" | sed 's/^/      /' | head -5; FAILED=1
    fi
  else
    echo "FAILED"
    echo "$out" | sed 's/^/      /' | head -5
    FAILED=1
  fi
done

docker volume rm -f "$VOLUME" >/dev/null 2>&1 || true

if [[ $FAILED -ne 0 ]]; then
  say "RESULT: at least one target could not run the payload"
  echo "If the failure names GLIBC, the payload was frozen on too NEW a base — see the PAYLOAD_BASE"
  echo "comment in scripts/mcp-proxy-payload.Dockerfile. If it names musl, that target is Alpine and"
  echo "is a known, documented limitation rather than a regression."
  exit 1
fi
say "RESULT: payload ran in every target image"
