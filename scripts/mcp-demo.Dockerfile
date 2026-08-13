# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
#
# Image for the MCP action-firewall kind demo: the API image plus the `mcp` extra (the streamable-
# HTTP driver's starlette, and the real `mcp` SDK client that the adversarial harness and
# norviq.mcp.demo_client drive). The PROXY itself needs none of this — it depends only on the base
# package — but the demo has to be driven by a real client to prove anything.
#
# Build:
#   docker build -f scripts/mcp-demo.Dockerfile \
#     --build-context certs=/etc/ssl/certs \
#     --build-arg NRVQ_GIT_SHA=$(git rev-parse HEAD) \
#     --build-arg NRVQ_TREE_DIGEST=$(scripts/tree-digest.sh) \
#     -t norviq-mcp:local .
#
# The `certs` build context supplies a `ca-bundle.crt` for pip. On an unrestricted network point it
# at any directory holding a CA bundle under that name (or symlink the system bundle); it exists
# because the environment this was developed in re-terminates TLS at an egress proxy, and a build
# that silently disables certificate verification instead would be worse than an extra flag.
FROM openpolicyagent/opa:1.19.0-static AS opabin

FROM python:3.12-slim AS builder
WORKDIR /build
COPY --from=certs ca-bundle.crt /etc/build-ca-bundle.crt
ENV PIP_CERT=/etc/build-ca-bundle.crt \
    SSL_CERT_FILE=/etc/build-ca-bundle.crt \
    REQUESTS_CA_BUNDLE=/etc/build-ca-bundle.crt
COPY pyproject.toml .
COPY norviq/ norviq/
RUN pip install --no-cache-dir --target=/deps '.[spiffe,mcp]' uvicorn

FROM python:3.12-slim
WORKDIR /app
COPY --from=builder /deps /usr/local/lib/python3.12/site-packages

# NO-STALE-IMAGE MARKERS.
#   NRVQ_BUILD_GIT_SHA    — the commit, matching every other shipped Norviq image.
#   NRVQ_BUILD_TREE_DIGEST — a sha256 over the exact source COPYed in. The git sha alone cannot
#   prove "running image == working tree" for uncommitted work, and this spike is deliberately never
#   committed, so the demo script verifies BOTH before it will report any result.
ARG NRVQ_GIT_SHA=unknown
ARG NRVQ_TREE_DIGEST=unknown
ENV NRVQ_BUILD_GIT_SHA=${NRVQ_GIT_SHA}
ENV NRVQ_BUILD_TREE_DIGEST=${NRVQ_TREE_DIGEST}
LABEL org.opencontainers.image.revision=${NRVQ_GIT_SHA}

# The OPA binary is copied from the pinned OPA image rather than downloaded, so the build needs no
# egress to openpolicyagent.org. Same version the chart's sidecar runs.
COPY --from=opabin /opa /usr/local/bin/opa
RUN chmod +x /usr/local/bin/opa && /usr/local/bin/opa version

RUN printf "%s\n" "${NRVQ_GIT_SHA}" > /app/.build_git_sha \
 && printf "%s\n" "${NRVQ_TREE_DIGEST}" > /app/.build_tree_digest

COPY norviq/ norviq/
COPY policies/ policies/

RUN useradd -r -u 999 -s /usr/sbin/nologin norviq
USER 999

EXPOSE 8080
CMD ["python", "-m", "uvicorn", "norviq.api.main:app", "--host", "0.0.0.0", "--port", "8080"]
