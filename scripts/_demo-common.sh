#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
#
# Shared plumbing for the MCP demo scripts, factored out because both had the same three
# environment assumptions baked in and both were wrong off the machine they were written on.
#
# Sourced, not executed.

# --- preflight ---------------------------------------------------------------------------------
# Fail with a sentence a human can act on, rather than a stack trace forty lines later.
demo_preflight() {
  local missing=()
  for tool in docker kind kubectl helm git; do
    command -v "$tool" >/dev/null 2>&1 || missing+=("$tool")
  done
  if [ ${#missing[@]} -gt 0 ]; then
    echo "missing required tools: ${missing[*]}" >&2
    echo "  macOS:  brew install kind kubectl helm   (Docker Desktop provides docker)" >&2
    echo "  Linux:  see https://kind.sigs.k8s.io/docs/user/quick-start/" >&2
    return 1
  fi
  if ! docker info >/dev/null 2>&1; then
    echo "the Docker daemon is not reachable — start Docker Desktop (macOS) or dockerd (Linux)" >&2
    return 1
  fi
  if ! kind get clusters 2>/dev/null | grep -qx "${CLUSTER}"; then
    echo "kind cluster '${CLUSTER}' does not exist. Create it with:" >&2
    echo "    kind create cluster --name ${CLUSTER}" >&2
    return 1
  fi
}

# --- CA bundle for the build ---------------------------------------------------------------------
# The demo Dockerfiles take a `certs` build context because the environment this was developed in
# re-terminates TLS at an egress proxy, and `pip`/`apk` fail without its CA. On an ordinary network
# there is nothing to inject — but the COPY is unconditional, so the context still has to exist.
#
# Rather than make the caller find a CA bundle, provision one from the system trust store. On a
# normal network this is a no-op that satisfies the COPY; behind an inspecting proxy, set CA_DIR to a
# directory holding that proxy's `ca-bundle.crt` and it is used instead.
#
# Deliberately NOT solved by disabling certificate verification in the build. That would be a worse
# thing to ship in a security product than an extra build flag.
demo_ca_dir() {
  if [ -n "${CA_DIR:-}" ]; then
    if [ ! -f "${CA_DIR}/ca-bundle.crt" ]; then
      echo "CA_DIR=${CA_DIR} does not contain ca-bundle.crt" >&2
      return 1
    fi
    printf '%s' "${CA_DIR}"
    return 0
  fi
  local dir="${TMPDIR:-/tmp}/norviq-demo-ca"
  mkdir -p "$dir"
  if [ ! -s "$dir/ca-bundle.crt" ]; then
    local src=""
    for candidate in \
      /etc/ssl/cert.pem \
      /etc/ssl/certs/ca-certificates.crt \
      /etc/pki/tls/certs/ca-bundle.crt \
      /usr/local/etc/openssl@3/cert.pem
    do
      [ -f "$candidate" ] && { src="$candidate"; break; }
    done
    if [ -z "$src" ]; then
      echo "could not find a system CA bundle; set CA_DIR to a directory containing ca-bundle.crt" >&2
      return 1
    fi
    cp "$src" "$dir/ca-bundle.crt"
  fi
  printf '%s' "$dir"
}

# --- loading an image into kind --------------------------------------------------------------------
# `kind load docker-image` is the supported path and is what works on Docker Desktop. The archive
# fallback exists because a daemon running the containerd snapshotter can hold a multi-arch index
# whose other-platform blobs were never fetched, and `kind load docker-image` then fails on the
# missing content. Never pin --platform here: on Apple Silicon the kind node is arm64, and forcing
# linux/amd64 loads an image the node cannot execute — which surfaces as a CrashLoopBackOff with an
# "exec format error" rather than anything that names the real cause.
demo_kind_load() {
  local image="$1"
  if kind load docker-image --name "${CLUSTER}" "$image" >/dev/null 2>&1; then
    return 0
  fi
  echo "  (kind load docker-image failed; retrying via image archive)" >&2
  local tar="${TMPDIR:-/tmp}/norviq-demo-image.tar"
  docker save "$image" -o "$tar"
  kind load image-archive --name "${CLUSTER}" "$tar"
  rm -f "$tar"
}

# --- the newest RUNNING api pod ---------------------------------------------------------------------
# Not `items[0]`: during a rollout both the old and new pods exist and the unsorted list can hand back
# the terminating one, which reports the PREVIOUS image's digest and trips the stale-image guard on a
# build that was actually fine.
demo_api_pod() {
  kubectl -n "${NS_CTRL}" get pod -l app.kubernetes.io/component=api \
    --field-selector=status.phase=Running \
    --sort-by=.metadata.creationTimestamp \
    -o jsonpath='{.items[-1:].metadata.name}'
}
