#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# F-25: write the runtime config from env BEFORE nginx serves it. Build-once image, per-cluster config.
# FLEET_API_URL: the hub sets "/fleet-api" (same-origin, proxied by nginx); spokes/single-cluster leave it empty.
set -e
cat > /usr/share/nginx/html/config.js <<EOF
window.__NRVQ_CONFIG__ = { fleetApiUrl: "${FLEET_API_URL:-}" };
EOF
exec nginx -g "daemon off;"
