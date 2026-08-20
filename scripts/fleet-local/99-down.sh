#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
pkill -f "port-forward.*fleet" 2>/dev/null || true
for c in fleet-a fleet-b; do kind delete cluster --name "$c" || true; done
echo "deleted kind clusters fleet-a, fleet-b"
