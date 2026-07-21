// SPDX-License-Identifier: Apache-2.0
// Runtime config. Default (dev + single-cluster) leaves fleetApiUrl empty so the Fleet view stays gated
// off. In the container, the entrypoint OVERWRITES this file from the FLEET_API_URL env (the hub sets
// "/fleet-api"). Build-once image, configured per cluster.
window.__NRVQ_CONFIG__ = window.__NRVQ_CONFIG__ || { fleetApiUrl: "" };
