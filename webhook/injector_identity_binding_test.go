// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
package main

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

// The API pins /evaluate to the caller's identity (api/auth.py scoped_identity): a token carrying an
// `agent_class` claim may ONLY be evaluated as that class. The sidecar reports the class it reads from
// NRVQ_AGENT_CLASS, so the minted token's claim and that env var MUST be the same string — if they ever
// drift, every tool call from every injected pod 403s in production. These tests lock that invariant.

func sidecarTokenClaims(t *testing.T, token string) map[string]interface{} {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("not a 3-part JWT: %q", token)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("unmarshal claims: %v", err)
	}
	return claims
}

// sidecarEnvValue returns the value of the named env var in the rendered sidecar env, and whether it was found.
func sidecarEnvValue(env []map[string]interface{}, name string) (string, bool) {
	for _, e := range env {
		if e["name"] == name {
			v, _ := e["value"].(string)
			return v, true
		}
	}
	return "", false
}

func TestSidecarTokenAgentClassClaimMatchesInjectedEnv(t *testing.T) {
	cfg := LoadConfig()
	cfg.ApiSecret = "test-secret-for-mint-only-not-a-real-key"
	cfg.SidecarMode = "proxy" // thin-proxy path is the one that mints a token

	const agentClass = "customer-support"
	env := sidecarEnv(agentClass, "team-a", "", cfg)

	gotClass, ok := sidecarEnvValue(env, "NRVQ_AGENT_CLASS")
	if !ok {
		t.Fatal("NRVQ_AGENT_CLASS not injected")
	}
	if gotClass != agentClass {
		t.Fatalf("NRVQ_AGENT_CLASS = %q, want %q", gotClass, agentClass)
	}

	token, ok := sidecarEnvValue(env, "NRVQ_API_TOKEN")
	if !ok || token == "" {
		t.Fatal("no sidecar token minted (expected one in proxy mode with an ApiSecret)")
	}
	claims := sidecarTokenClaims(t, token)
	claimClass, _ := claims["agent_class"].(string)
	if claimClass != gotClass {
		t.Fatalf("token agent_class claim = %q but NRVQ_AGENT_CLASS = %q — identity binding would 403 "+
			"every tool call from this pod", claimClass, gotClass)
	}
	if ns, _ := claims["namespace"].(string); ns != "team-a" {
		t.Fatalf("namespace claim = %q, want team-a", ns)
	}
	if role, _ := claims["role"].(string); role != "service" {
		t.Fatalf("role claim = %q, want service", role)
	}
}

func TestSidecarTokenSpiffeClaimMatchesMockResolver(t *testing.T) {
	// The claim MUST equal what the sidecar itself reports, or every tool call 403s. In the default
	// "mock" resolver the sidecar builds spiffe://norviq/ns/<ns>/sa/<NRVQ_SERVICE_ACCOUNT or "default">
	// (norviq/engine/identity.py _mock_resolve) and nothing here injects NRVQ_SERVICE_ACCOUNT, so the
	// expected value is fully determined by the namespace. If either side's formula changes, this fails.
	cfg := LoadConfig()
	cfg.ApiSecret = "test-secret-for-mint-only-not-a-real-key"
	cfg.SidecarMode = "proxy"
	cfg.SpiffeMode = "mock"

	env := sidecarEnv("customer-support", "team-a", "", cfg)
	token, ok := sidecarEnvValue(env, "NRVQ_API_TOKEN")
	if !ok || token == "" {
		t.Fatal("no sidecar token minted")
	}
	got, _ := sidecarTokenClaims(t, token)["spiffe_id"].(string)
	const want = "spiffe://norviq/ns/team-a/sa/default"
	if got != want {
		t.Fatalf("spiffe_id claim = %q, want %q (must match engine/identity.py _mock_resolve)", got, want)
	}
}

func TestSidecarTokenWorkloadApiModeLeavesSpiffeUnbound(t *testing.T) {
	// In workload-api mode the SPIFFE id comes from a SPIRE-issued SVID whose trust domain the webhook
	// does not control. Minting a guessed id would pin the token to a value the sidecar never sends and
	// 403 every tool call — so the claim must be ABSENT (unbound) there.
	cfg := LoadConfig()
	cfg.ApiSecret = "test-secret-for-mint-only-not-a-real-key"
	cfg.SidecarMode = "proxy"
	cfg.SpiffeMode = "workload-api"

	env := sidecarEnv("customer-support", "team-a", "", cfg)
	token, _ := sidecarEnvValue(env, "NRVQ_API_TOKEN")
	if _, present := sidecarTokenClaims(t, token)["spiffe_id"]; present {
		t.Fatal("spiffe_id claim must be absent in workload-api mode (SVID-derived, not predictable)")
	}
}

func TestSidecarTokenUnlabeledPodStaysUnbound(t *testing.T) {
	// A pod with no norviq.io/agent-class label injects an EMPTY class. The claim must be empty too:
	// empty == unbound in scoped_identity, so such a pod keeps working exactly as before (it must NOT
	// get a bogus non-empty claim, which would pin it to a class it never reports).
	cfg := LoadConfig()
	cfg.ApiSecret = "test-secret-for-mint-only-not-a-real-key"
	cfg.SidecarMode = "proxy"

	env := sidecarEnv("", "team-a", "", cfg)
	gotClass, _ := sidecarEnvValue(env, "NRVQ_AGENT_CLASS")
	if gotClass != "" {
		t.Fatalf("NRVQ_AGENT_CLASS = %q, want empty for an unlabeled pod", gotClass)
	}
	token, ok := sidecarEnvValue(env, "NRVQ_API_TOKEN")
	if !ok || token == "" {
		t.Fatal("no sidecar token minted")
	}
	if claimClass, _ := sidecarTokenClaims(t, token)["agent_class"].(string); claimClass != "" {
		t.Fatalf("token agent_class claim = %q, want empty (unbound) for an unlabeled pod", claimClass)
	}
}
