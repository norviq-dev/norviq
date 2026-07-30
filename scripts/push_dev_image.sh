#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
#
# Build and push a TEST image to the private dev package, never to the release package.
#
# Why this exists. Ad-hoc `docker buildx --push` during testing puts unreleased, unsigned code in
# ghcr.io/norviq-dev/norviq-engine — the same package that holds released artifacts. Nothing breaks
# (the released chart pins immutable DIGESTS, so a tag push cannot repoint it), but it is bad supply-chain
# hygiene: the release namespace should contain only signed, released images, and a passer-by should not be
# able to pull `api-<sha>` from it and believe it is official.
#
# It also removes a foot-gun this repo has already been bitten by: tagging from a DIRTY tree reuses the
# HEAD sha, so a second push silently OVERWRITES the first tag with different content. That mutation is
# exactly what digest pinning exists to prevent, and it happened during the latency work. This script
# refuses to build from a dirty tree unless you opt in, and then marks the tag so it can never collide.
#
#   ./scripts/push_dev_image.sh api                 # build+push api from a clean HEAD
#   ./scripts/push_dev_image.sh api engine webhook  # several at once
#   ALLOW_DIRTY=1 ./scripts/push_dev_image.sh api   # dirty tree -> tag gets a -dirty<epoch> suffix
#
# ONE-TIME SETUP (the package must be created private; a package inherits nothing useful by default):
#   1. push once with this script
#   2. gh api --method PATCH /orgs/norviq-dev/packages/container/norviq-engine-dev \
#        -f visibility=private
#      ...or set it in the GitHub UI under the org's Packages tab.
#   Then grant the cluster a pull secret and point the chart at it:
#     kubectl create secret docker-registry ghcr-dev -n norviq \
#       --docker-server=ghcr.io --docker-username=<user> --docker-password=<PAT with read:packages>
#     helm upgrade ... --set images.registry=ghcr.io/norviq-dev/norviq-engine-dev/ \
#                      --set-json 'imagePullSecrets=[{"name":"ghcr-dev"}]'
set -euo pipefail

DEV_PACKAGE="${DEV_PACKAGE:-ghcr.io/norviq-dev/norviq-engine-dev}"
PLATFORM="${PLATFORM:-linux/amd64}"

if [ $# -eq 0 ]; then
    echo "usage: $0 <component> [component...]   (api | engine | webhook | ui | bootstrap)" >&2
    exit 2
fi

cd "$(dirname "$0")/.."

SHA="$(git rev-parse HEAD)"
SUFFIX=""
# `git status --porcelain` rather than `git diff HEAD`, because diff IGNORES UNTRACKED FILES. A brand-new
# source file — precisely what a work-in-progress build contains — leaves `git diff HEAD` clean, so the
# earlier check called the tree pristine and tagged with a sha that did not describe it. That is the same
# blind spot as `git stash push` without `-u`, which silently no-opped on untracked files during the latency
# work and produced three invalid regression comparisons before it was noticed.
if [ -n "$(git status --porcelain)" ]; then
    if [ "${ALLOW_DIRTY:-0}" != "1" ]; then
        echo "ERROR: working tree is dirty, so the HEAD sha does NOT describe what would be built." >&2
        echo "       Tagging anyway reuses a sha that may already be pushed, silently overwriting a tag" >&2
        echo "       with different content — a mutation digest pinning exists to prevent, and one this" >&2
        echo "       repo has already hit. Commit first, or re-run with ALLOW_DIRTY=1 for a marked tag." >&2
        exit 1
    fi
    # Unique per invocation, so a dirty build can never collide with a previous tag.
    SUFFIX="-dirty$(date +%s)"
    echo "WARNING: dirty tree — tagging with ${SUFFIX} so this cannot overwrite an existing tag." >&2
fi

for component in "$@"; do
    case "$component" in
        api)       dockerfile="Dockerfile.api";       context="." ;;
        engine)    dockerfile="Dockerfile.engine";    context="." ;;
        ui)        dockerfile="Dockerfile.ui";        context="." ;;
        bootstrap) dockerfile="Dockerfile.bootstrap"; context="." ;;
        webhook)   dockerfile="webhook/Dockerfile";   context="webhook" ;;
        *) echo "unknown component: $component" >&2; exit 2 ;;
    esac

    # Braces are load-bearing: in zsh `$VAR:api-...` applies the `:a` history modifier and silently
    # mangles the tag into a filesystem path. That produced three failed pushes during the latency work.
    tag="${DEV_PACKAGE}:${component}-${SHA}${SUFFIX}"
    echo "==> ${tag}"
    docker buildx build --platform "${PLATFORM}" \
        -f "${dockerfile}" --build-arg "NRVQ_GIT_SHA=${SHA}" \
        -t "${tag}" --push "${context}"
done

echo
echo "Pushed to the DEV package. These images are unsigned and carry no SBOM attestation by design —"
echo "cosign verification against them fails, which is how a release artifact stays distinguishable."
