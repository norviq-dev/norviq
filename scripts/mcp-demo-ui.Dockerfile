# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
#
# LOCAL console image for the MCP demo. Identical to Dockerfile.ui except that it installs a CA
# bundle into both stages before anything reaches the network.
#
# WHY: Dockerfile.ui runs `npm ci` and `apk upgrade` inside the build. Behind a TLS-inspecting egress
# proxy — which this development environment uses, and which plenty of corporate networks do — both
# fail with a certificate error. The alternative fixes are to disable certificate verification
# (`npm config set strict-ssl false`, `apk --allow-untrusted`), which would be a genuinely worse
# thing to ship in a security product's build, so the CA is supplied instead. The `apk upgrade`
# security-patch step is KEPT, not skipped.
#
# Build:
#   docker build -f scripts/mcp-demo-ui.Dockerfile \
#     --build-context certs=/etc/ssl/certs \
#     --build-arg NRVQ_GIT_SHA=$(git rev-parse HEAD) -t norviq-ui:local .
#
# `certs` must be a directory containing `ca-bundle.crt`. On an unrestricted network any system CA
# bundle works; behind an inspecting proxy, point it at that proxy's bundle.

FROM --platform=$BUILDPLATFORM node:20-alpine AS builder
WORKDIR /build
COPY --from=certs ca-bundle.crt /etc/build-ca-bundle.crt
# NODE_EXTRA_CA_CERTS covers node/npm; SSL_CERT_FILE covers anything else the build shells out to.
ENV NODE_EXTRA_CA_CERTS=/etc/build-ca-bundle.crt \
    SSL_CERT_FILE=/etc/build-ca-bundle.crt
COPY ui/package*.json ./
RUN npm ci
COPY ui/ .
RUN npm run build

FROM nginxinc/nginx-unprivileged:1.27-alpine
USER root
ARG NRVQ_GIT_SHA=dev
ARG NRVQ_TREE_DIGEST=unknown
ENV NRVQ_BUILD_GIT_SHA=${NRVQ_GIT_SHA}
ENV NRVQ_BUILD_TREE_DIGEST=${NRVQ_TREE_DIGEST}
LABEL org.opencontainers.image.revision=${NRVQ_GIT_SHA}
# apk verifies the repository index over TLS, so the CA has to land before `apk update`.
#
# NON-FATAL HERE, AND ONLY HERE. `Dockerfile.ui` keeps this step fatal, which is correct: the shipped
# console image must carry current OS security patches, and the release build's Trivy gate depends on
# it. This local variant tolerates failure because the environment it was developed in blocks
# `dl-cdn.alpinelinux.org` outright at the egress proxy, and the alternative — dropping the step —
# would silently produce an unpatched image with no record of it. The build PRINTS which happened, so
# a demo image that skipped patching says so rather than pretending.
COPY --from=certs ca-bundle.crt /usr/local/share/ca-certificates/build-ca.crt
RUN cat /usr/local/share/ca-certificates/build-ca.crt >> /etc/ssl/certs/ca-certificates.crt \
    && { apk update && apk upgrade --no-cache && echo "os-patched @ ${NRVQ_GIT_SHA}"; } \
    || echo "WARNING: alpine package repo unreachable — this LOCAL DEMO image is NOT OS-patched"
COPY --from=builder /build/dist /usr/share/nginx/html
COPY ui/nginx.conf /etc/nginx/conf.d/default.conf
COPY ui/docker-entrypoint.sh /docker-entrypoint.d/99-nrvq-config.sh
RUN printf "%s\n" "${NRVQ_GIT_SHA}" > /usr/share/nginx/html/.build_git_sha \
    && printf "%s\n" "${NRVQ_TREE_DIGEST}" > /usr/share/nginx/html/.build_tree_digest \
    && chmod +x /docker-entrypoint.d/99-nrvq-config.sh \
    && touch /etc/nginx/fleet-proxy.conf \
    && chown -R 101:0 /usr/share/nginx/html /etc/nginx/fleet-proxy.conf /etc/nginx/conf.d \
    && chmod -R g+w /usr/share/nginx/html /etc/nginx/fleet-proxy.conf
USER 101
EXPOSE 8080
CMD ["/docker-entrypoint.d/99-nrvq-config.sh"]
