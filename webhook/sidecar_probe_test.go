// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors

package main

import "testing"

// The injected sidecar has two startup profiles and the probes have to survive the slow one.
//
// `proxy` (default) binds its HTTP server almost immediately. `embedded` builds a whole engine first
// — Postgres, Redis, policy warm, an OPA subprocess — and the entrypoint does all of that BEFORE
// uvicorn binds the port. With liveness probing from 5s and no startupProbe, the kubelet killed the
// container while the server did not yet exist, forever:
//
//	Readiness probe failed: dial tcp ...:8282: connect: connection refused
//	Container norviq-sidecar failed liveness probe, will be restarted
//
// And every probe left timeoutSeconds unset, inheriting Kubernetes' 1s default — fine for the
// constant /healthz, not fine for /readyz, which proves the PDP is reachable and under
// NRVQ_OPA_MODE=subprocess forks `opa` to do it.
func TestSidecarProbeBudgets(t *testing.T) {
	const port = 8282

	startup := sidecarStartupProbe(port)
	if startup == nil {
		t.Fatal("no startupProbe: liveness will kill a slow embedded sidecar before it binds")
	}
	// The whole point is a generous budget: periodSeconds * failureThreshold must comfortably exceed
	// embedded startup. 30 * 3s = 90s.
	budget := startup["periodSeconds"].(int) * startup["failureThreshold"].(int)
	if budget < 60 {
		t.Errorf("startupProbe budget is only %ds; embedded startup needs more headroom", budget)
	}

	for name, probe := range map[string]map[string]interface{}{
		"startup":   startup,
		"liveness":  sidecarLivenessProbe(port),
		"readiness": sidecarReadinessProbe(port),
	} {
		// Unset means 1s, silently. Every probe states its own budget.
		if _, ok := probe["timeoutSeconds"]; !ok {
			t.Errorf("%s probe leaves timeoutSeconds unset — it inherits Kubernetes' 1s default", name)
		}
	}

	// /readyz does real work (it dials the PDP; embedded forks OPA), so it needs more than the
	// constant-time /healthz.
	rt := sidecarReadinessProbe(port)["timeoutSeconds"].(int)
	lt := sidecarLivenessProbe(port)["timeoutSeconds"].(int)
	if rt <= lt {
		t.Errorf("readiness timeout (%ds) should exceed liveness (%ds): /readyz forks OPA, /healthz is a constant", rt, lt)
	}
}
