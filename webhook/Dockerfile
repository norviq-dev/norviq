# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
# Build on the runner's native arch and cross-compile to the target arch (TARGETOS/TARGETARCH
# are provided by buildx) — avoids running the Go toolchain under slow QEMU emulation.
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS builder
ARG TARGETOS
ARG TARGETARCH
# Build-provenance stamp (broadcast by CI: build.yml build-args NRVQ_GIT_SHA=github.sha). The
# distroless final stage has no shell, so write the NO-STALE marker file HERE (alpine) and COPY it over.
ARG NRVQ_GIT_SHA=unknown
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
COPY presets ./presets
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} go build -ldflags="-s -w" -o webhook .
RUN printf "%s\n" "${NRVQ_GIT_SHA}" > /build/.build_git_sha

FROM gcr.io/distroless/static-debian12
# Uniform build provenance across ALL shipped images (mirrors Dockerfile.api), not just api.
ARG NRVQ_GIT_SHA=unknown
ENV NRVQ_BUILD_GIT_SHA=${NRVQ_GIT_SHA}
LABEL org.opencontainers.image.revision=${NRVQ_GIT_SHA}
COPY --from=builder /build/webhook /webhook
COPY --from=builder /build/presets /app/presets
COPY --from=builder /build/.build_git_sha /app/.build_git_sha
USER 65534:65534
EXPOSE 8443
ENTRYPOINT ["/webhook"]
