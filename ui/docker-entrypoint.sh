#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# F-25 + single-cluster-first: write the runtime config from env BEFORE nginx serves it. Build-once image, per-cluster
# config. FLEET_API_URL: the hub sets "/fleet-api" (same-origin, proxied by nginx); spokes/single-cluster leave it
# empty. The /fleet-api nginx proxy is emitted ONLY when FLEET_API_URL is set, so the default (single-cluster) image
# does NOT reference the norviq-fleet-api upstream and starts cleanly with no fleet-api service present.
set -e

cat > /usr/share/nginx/html/config.js <<EOF
window.__NRVQ_CONFIG__ = {
  fleetApiUrl: "${FLEET_API_URL:-}",
  oidcIssuer: "${OIDC_ISSUER:-}",
  oidcClientId: "${OIDC_CLIENT_ID:-}",
  oidcRedirectUri: "${OIDC_REDIRECT_URI:-}"
};
EOF

if [ -n "${FLEET_API_URL:-}" ]; then
  cat > /etc/nginx/fleet-proxy.conf <<'EOF'
location /fleet-api/ {
    proxy_pass http://norviq-fleet-api:8080/;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
}
EOF
else
  # single-cluster default: no fleet-api proxy (empty include) — no dependency on a fleet-api service.
  : > /etc/nginx/fleet-proxy.conf
fi

exec nginx -g "daemon off;"
