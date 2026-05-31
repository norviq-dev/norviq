# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
FROM golang:1.22-alpine AS builder
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o webhook .

FROM gcr.io/distroless/static-debian12
COPY --from=builder /build/webhook /webhook
USER nonroot:nonroot
EXPOSE 8443
ENTRYPOINT ["/webhook"]
