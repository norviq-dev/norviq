#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Tear down the local customer-eval environment (deletes the kind clusters).
#   bash scripts/eval/99-teardown-local.sh

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

# kill any stray port-forwards we started
pkill -f "port-forward svc/norviq-" >/dev/null 2>&1 || true

for c in "$CLUSTER_A" "$CLUSTER_B"; do
  if kind get clusters 2>/dev/null | grep -qx "$c"; then
    log "deleting kind cluster $c..."
    kind delete cluster --name "$c"
  fi
done
log "teardown complete. (Findings under $STATE_DIR are kept.)"
