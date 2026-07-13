# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
# Build on the runner's native arch and cross-compile to the target arch (TARGETOS/TARGETARCH
# are provided by buildx) — avoids running the Go toolchain under slow QEMU emulation.
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS builder
ARG TARGETOS
ARG TARGETARCH
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
COPY presets ./presets
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} go build -ldflags="-s -w" -o webhook .

FROM gcr.io/distroless/static-debian12
COPY --from=builder /build/webhook /webhook
COPY --from=builder /build/presets /app/presets
USER 65534:65534
EXPOSE 8443
ENTRYPOINT ["/webhook"]
