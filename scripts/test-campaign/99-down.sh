#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Tear down campaign clusters (frees memory between staggered phases). Local kind only.
set -uo pipefail
pkill -f "port-forward.*norviq" 2>/dev/null || true
for c in nv-a; do kind get clusters 2>/dev/null | grep -qx "$c" && { echo "delete kind $c"; kind delete cluster --name "$c"; }; done
# Phase B/C clusters are owned by their own harnesses:
echo "Phase B teardown: bash scripts/identity-local/99-down.sh"
echo "Phase C teardown: bash scripts/fleet-local/99-down.sh"
