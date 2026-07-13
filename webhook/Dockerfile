# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
FROM golang:1.26-alpine AS builder
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
COPY presets ./presets
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o webhook .

FROM gcr.io/distroless/static-debian12
COPY --from=builder /build/webhook /webhook
COPY --from=builder /build/presets /app/presets
USER 65534:65534
EXPOSE 8443
ENTRYPOINT ["/webhook"]
