#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Tear down the IDENTITY local e2e kind cluster (throwaway). Leaves .reviews/identity-local/ evidence.
set -euo pipefail
CLUSTER="${CLUSTER:-norviq-identity}"
pkill -f "port-forward.*norviq" 2>/dev/null || true
kind delete cluster --name "$CLUSTER" || true
echo "deleted kind cluster $CLUSTER"
