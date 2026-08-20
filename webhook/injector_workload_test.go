// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors

package main

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// AgentIdentity.workload existed, the evaluator read it to build `<ns>:deployment:<workload>`, the
// console offered a Workload tier, the CRD accepted target.kind/name and the CLI could apply to it —
// and NOTHING ever populated the field. Every production request carried "", so the tier matched zero
// calls while every surface reported the policy Active. These pin the producer half of that chain.
func podWithOwner(kind, name string, labels map[string]string) *corev1.Pod {
	p := &corev1.Pod{}
	p.Labels = labels
	if kind != "" {
		p.OwnerReferences = []metav1.OwnerReference{{Kind: kind, Name: name}}
	}
	return p
}

func TestWorkloadFromPod(t *testing.T) {
	cases := []struct {
		desc string
		pod  *corev1.Pod
		want string
	}{
		{"deployment via its ReplicaSet", podWithOwner("ReplicaSet", "checkout-7d9f8b5c4", nil), "checkout"},
		{"hyphenated deployment name survives", podWithOwner("ReplicaSet", "billing-api-6c9fd4b7f", nil), "billing-api"},
		{"direct StatefulSet owner", podWithOwner("StatefulSet", "postgres", nil), "postgres"},
		{"direct DaemonSet owner", podWithOwner("DaemonSet", "node-agent", nil), "node-agent"},
		// REWRITTEN, deliberately. This case used to assert "explicit label wins over the owner" and
		// expect "checkout-canary" — it pinned the behaviour as intended, and the behaviour was a
		// forgeable identity. A pod controls its own labels, and the workload tier selects which policy
		// program runs, so a pod under a strict policy could relabel itself onto a permissive one. The
		// attested value from the object graph must win; the label is now a fallback for pods that have
		// no attested value at all (the two cases below).
		{"a pod cannot relabel itself off its attested workload", podWithOwner("ReplicaSet", "checkout-7d9f8b5c4",
			map[string]string{workloadLabel: "checkout-canary"}), "checkout"},
		{"the label still names a bare pod's workload", podWithOwner("", "",
			map[string]string{workloadLabel: "batch-runner"}), "batch-runner"},
		{"the label still covers an owner kind we do not recognise", podWithOwner("Rollout", "argo-thing",
			map[string]string{workloadLabel: "checkout-canary"}), "checkout-canary"},
		{"bare pod resolves to nothing rather than guessing", podWithOwner("", "", nil), ""},
		{"unknown owner kind is not guessed at", podWithOwner("Rollout", "argo-thing", nil), ""},
		{"nil pod is safe", nil, ""},
	}
	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			if got := workloadFromPod(tc.pod); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// The suffix is only stripped when it actually looks like a pod-template-hash, so a Deployment really
// called `billing-api` is never truncated to `billing`.
func TestStripPodTemplateHashOnlyStripsAHash(t *testing.T) {
	cases := map[string]string{
		"checkout-7d9f8b5c4":  "checkout",
		"billing-api":         "billing-api", // "api" is too short to be a hash
		"svc-UPPERCASE":       "svc-UPPERCASE",
		"svc-toolongsuffixxx": "svc-toolongsuffixxx",
		"nodash":              "nodash",
		"trailing-":           "trailing-",
	}
	for in, want := range cases {
		if got := stripPodTemplateHash(in); got != want {
			t.Errorf("stripPodTemplateHash(%q) = %q, want %q", in, got, want)
		}
	}
}

// NRVQ_WORKLOAD must be ABSENT rather than empty when nothing resolved: an empty value is
// indistinguishable from "resolved to nothing" on the reader side, and the tier must stay inapplicable.
func TestSidecarEnvOmitsWorkloadWhenUnresolved(t *testing.T) {
	cfg := Config{SidecarPort: 8282}
	has := func(env []map[string]interface{}, key string) (string, bool) {
		for _, e := range env {
			if e["name"] == key {
				v, _ := e["value"].(string)
				return v, true
			}
		}
		return "", false
	}

	if v, ok := has(sidecarEnv("support", "team-a", "checkout", cfg), "NRVQ_WORKLOAD"); !ok || v != "checkout" {
		t.Fatalf("expected NRVQ_WORKLOAD=checkout, got %q present=%v", v, ok)
	}
	if _, ok := has(sidecarEnv("support", "team-a", "", cfg), "NRVQ_WORKLOAD"); ok {
		t.Fatal("NRVQ_WORKLOAD must not be set at all when no workload resolved")
	}
}

// The other half of the chain, and the one that made injecting NRVQ_WORKLOAD insufficient on its own:
// api/auth.py scoped_identity treats `workload` as an ADDITIVE tier field and CLEARS whatever the body
// sent unless the token carries a matching claim — so the sidecar sent the workload and the API threw
// it away on arrival. Its comment said "no issuer mints a workload claim today"; nothing did. The
// injector is the issuer, and the value is derived at admission from the pod's owner, so a bound token
// grants exactly the tier its own pod is entitled to and no other.
func TestSidecarTokenBindsTheWorkloadClaim(t *testing.T) {
	cfg := Config{ApiSecret: "test-secret-at-least-16-chars", SpiffeMode: "mock", SidecarTokenTTLHours: 1}

	claims := decodeJWTClaims(t, mintSidecarToken(cfg, "agents", "payments", "checkout-svc"))
	if claims["workload"] != "checkout-svc" {
		t.Fatalf("workload claim = %v, want checkout-svc — without it the API clears the field and the "+
			"workload tier never applies", claims["workload"])
	}

	// No resolvable owner -> no claim, leaving the field unbound and the tier inapplicable, which is
	// the correct outcome rather than a default.
	bare := decodeJWTClaims(t, mintSidecarToken(cfg, "agents", "payments", ""))
	if _, present := bare["workload"]; present {
		t.Fatal("workload claim must be OMITTED when nothing resolved, not sent empty")
	}
}

func decodeJWTClaims(t *testing.T, token string) map[string]interface{} {
	t.Helper()
	if token == "" {
		t.Fatal("mintSidecarToken returned empty")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT: %d parts", len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode claims: %v", err)
	}
	var claims map[string]interface{}
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatalf("unmarshal claims: %v", err)
	}
	return claims
}
