#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Open long-lived port-forwards so the scouts can reach the UI + API while they work.
# Run in its own terminal and LEAVE IT RUNNING. Ctrl-C to stop.
#
#   bash scripts/eval/20-portforward.sh

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

PIDS=()
stop() { log "stopping port-forwards..."; for p in "${PIDS[@]}"; do kill "$p" >/dev/null 2>&1 || true; done; exit 0; }
trap stop INT TERM

log "$CLUSTER_A  UI  -> http://127.0.0.1:$PORT_UI_A   (set localStorage nrvq_token from env.json, then reload)"
PIDS+=("$(start_pf "$CTX_A" norviq-ui "$PORT_UI_A" 80)")
log "$CLUSTER_A  API -> http://127.0.0.1:$PORT_API_A"
PIDS+=("$(start_pf "$CTX_A" norviq-api "$PORT_API_A" 8080)")

if [ "${SKIP_CLUSTER_B:-0}" != "1" ] && kind get clusters 2>/dev/null | grep -qx "$CLUSTER_B"; then
  log "$CLUSTER_B  API -> http://127.0.0.1:$PORT_API_B   (the multi-cluster test target)"
  PIDS+=("$(start_pf "$CTX_B" norviq-api "$PORT_API_B" 8080)")
fi

log "port-forwards live. Press Ctrl-C to stop."
wait
