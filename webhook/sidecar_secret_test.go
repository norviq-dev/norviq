// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors

package main

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// C2-019: the sidecar's credentials must not appear as literal values in a pod spec, because
// Kubernetes deliberately excludes Secrets from the built-in `view` role and a credential in the spec
// is therefore readable by anyone `view` was considered safe to give.

type fakeSecretWriter struct {
	calls []map[string]string
	names []string
	ns    []string
	err   error
}

func (f *fakeSecretWriter) Upsert(_ context.Context, namespace, name string, data map[string]string) error {
	if f.err != nil {
		return f.err
	}
	f.calls = append(f.calls, data)
	f.names = append(f.names, name)
	f.ns = append(f.ns, namespace)
	return nil
}

func envOf(t *testing.T, sidecar map[string]interface{}) []map[string]interface{} {
	t.Helper()
	env, ok := sidecar["env"].([]map[string]interface{})
	if !ok {
		t.Fatalf("sidecar env has unexpected type %T", sidecar["env"])
	}
	return env
}

func literalValue(env []map[string]interface{}, name string) (string, bool) {
	for _, e := range env {
		if n, _ := e["name"].(string); n == name {
			v, ok := e["value"].(string)
			return v, ok
		}
	}
	return "", false
}

func secretRefOf(env []map[string]interface{}, name string) (string, bool) {
	for _, e := range env {
		if n, _ := e["name"].(string); n != name {
			continue
		}
		vf, ok := e["valueFrom"].(map[string]interface{})
		if !ok {
			return "", false
		}
		skr, ok := vf["secretKeyRef"].(map[string]interface{})
		if !ok {
			return "", false
		}
		sn, _ := skr["name"].(string)
		return sn, true
	}
	return "", false
}

// testConfigWithMTLS gives an injector that mints BOTH a token and a client cert/key, so the test
// exercises every credential the fix is meant to move.
func testConfigWithMTLS(t *testing.T) Config {
	t.Helper()
	certFile, keyFile, _ := writeTestCA(t, t.TempDir())
	return Config{
		InternalTLS: true,
		CACertFile:  certFile,
		CAKeyFile:   keyFile,
		ApiURL:      "http://norviq-api:8080",
		ApiSecret:   "test-secret",
		SidecarMode: "proxy",
		Runtime:     &RuntimeConfig{},
	}
}

func injectorWithSecrets(t *testing.T, w SecretWriter) *Injector {
	t.Helper()
	inj := NewInjector(testConfigWithMTLS(t))
	inj.SetSecretWriter(w)
	return inj
}

func TestCredentialsAreMovedOutOfThePodSpec(t *testing.T) {
	w := &fakeSecretWriter{}
	inj := injectorWithSecrets(t, w)
	sidecar := inj.buildSidecar("finance-ops", "analytics", "finance-agent")
	env := envOf(t, sidecar)

	for _, key := range []string{"NRVQ_API_TOKEN", "NRVQ_CLIENT_KEY_PEM", "NRVQ_CLIENT_CERT_PEM"} {
		if v, ok := literalValue(env, key); ok && v != "" {
			t.Errorf("%s is STILL a literal value in the pod spec (%d bytes) — readable by `view`",
				key, len(v))
		}
		if _, ok := secretRefOf(env, key); !ok {
			t.Errorf("%s is not delivered via secretKeyRef", key)
		}
	}
	if len(w.calls) != 1 {
		t.Fatalf("expected exactly one Secret write, got %d", len(w.calls))
	}
	if w.ns[0] != "analytics" {
		t.Errorf("Secret written to %q, must be the POD's namespace (secretKeyRef is same-namespace)", w.ns[0])
	}
	if _, ok := w.calls[0]["NRVQ_CLIENT_KEY_PEM"]; !ok {
		t.Error("the private key never reached the Secret")
	}
}

func TestTheCAIsNotTreatedAsASecret(t *testing.T) {
	// A CA certificate is public by construction — it is what you hand out so peers can verify you.
	w := &fakeSecretWriter{}
	env := envOf(t, injectorWithSecrets(t, w).buildSidecar("finance-ops", "analytics", "finance-agent"))
	if _, ok := literalValue(env, "NRVQ_API_CA_PEM"); !ok {
		t.Error("NRVQ_API_CA_PEM should stay an ordinary literal value")
	}
}

func TestWithoutAWriterTheBehaviourIsUnchanged(t *testing.T) {
	// An operator who has not granted Secret write must still be able to schedule pods.
	env := envOf(t, NewInjector(testConfigWithMTLS(t)).buildSidecar("finance-ops", "analytics", "finance-agent"))
	if v, ok := literalValue(env, "NRVQ_API_TOKEN"); !ok || v == "" {
		t.Error("with no writer configured the token must still be delivered as a literal value")
	}
}

func TestAFailedSecretWriteFallsBackRatherThanBreakingScheduling(t *testing.T) {
	// failurePolicy: Fail means this webhook gates ALL pod creation in labelled namespaces. Turning a
	// transient API error into a cluster-wide scheduling outage would be worse than the exposure.
	w := &fakeSecretWriter{err: errors.New("apiserver said no")}
	inj := injectorWithSecrets(t, w)
	env := envOf(t, inj.buildSidecar("finance-ops", "analytics", "finance-agent"))
	if v, ok := literalValue(env, "NRVQ_API_TOKEN"); !ok || v == "" {
		t.Error("a failed Secret write must fall back to the literal value, not drop the credential")
	}
	if inj.lastSecretError == nil {
		t.Error("the fault must be recorded so SidecarSecretRequired can refuse admission")
	}
}

func TestDryRunProducesTheSamePatchWithoutWriting(t *testing.T) {
	// A dry-run must not create the Secret (the pod it previews is not created either), but it must
	// preview the SAME shape or it is lying about what admission would do.
	w := &fakeSecretWriter{}
	inj := injectorWithSecrets(t, w)
	env := envOf(t, inj.buildSidecar("finance-ops", "analytics", "finance-agent", PatchOptions{DryRun: true}))
	if len(w.calls) != 0 {
		t.Errorf("dry-run wrote %d Secret(s) — admission dry-run must be side-effect free", len(w.calls))
	}
	if _, ok := secretRefOf(env, "NRVQ_API_TOKEN"); !ok {
		t.Error("dry-run must still preview the secretKeyRef shape")
	}
	if v, _ := literalValue(env, "NRVQ_API_TOKEN"); v != "" {
		t.Error("dry-run must not preview a literal credential either")
	}
}

func TestRotationStillHappens(t *testing.T) {
	// Token rotation in this product IS pod replacement, verified live. The Secret is rewritten on
	// every admission rather than created-if-absent, or a replacement pod would reuse stale material.
	w := &fakeSecretWriter{}
	inj := injectorWithSecrets(t, w)
	inj.buildSidecar("finance-ops", "analytics", "finance-agent")
	inj.buildSidecar("finance-ops", "analytics", "finance-agent")
	if len(w.calls) != 2 {
		t.Fatalf("expected a write per admission, got %d", len(w.calls))
	}
	if w.names[0] != w.names[1] {
		t.Errorf("the Secret name must be deterministic or every rollout leaks one: %q vs %q",
			w.names[0], w.names[1])
	}
}

func TestSecretNameIsDeterministicSafeAndCollisionResistant(t *testing.T) {
	if a, b := sidecarSecretName("finance-agent", "finance-ops"), sidecarSecretName("finance-agent", "finance-ops"); a != b {
		t.Errorf("not deterministic: %q vs %q", a, b)
	}
	// Two workloads that sanitise to the same readable string must NOT share a Secret — they would
	// hand each other's claims out.
	if a, b := sidecarSecretName("finance.agent", "x"), sidecarSecretName("finance/agent", "x"); a == b {
		t.Errorf("distinct workloads collided onto one Secret: %q", a)
	}
	for _, in := range []string{"Finance_Agent", "a/b.c", strings.Repeat("x", 200), "", "---"} {
		got := sidecarSecretName(in, "")
		if len(got) > 63 {
			t.Errorf("name for %q is %d chars, over the DNS-1123 label bound", in, len(got))
		}
		if !dns1123OK(got) {
			t.Errorf("name for %q is not DNS-1123 safe: %q", in, got)
		}
	}
}

func dns1123OK(s string) bool {
	if s == "" || strings.HasPrefix(s, "-") || strings.HasSuffix(s, "-") {
		return false
	}
	for _, r := range s {
		if !(r == '-' || (r >= '0' && r <= '9') || (r >= 'a' && r <= 'z')) {
			return false
		}
	}
	return true
}

// One workload, two agent classes, one Secret. The suffix that separates them used to be conditional.
func TestSidecarSecretNameSeparatesAgentClasses(t *testing.T) {
	// `checkout` is already lower-case DNS-1123 and well inside the length budget, so it needed no
	// sanitising and no truncation — and the hash suffix was only appended when one of those applied.
	// The agent_class therefore dropped out of the name entirely for exactly the well-behaved names
	// real deployments use.
	//
	// Admission REWRITES the Secret rather than merging, so a collision is not a shared credential —
	// it is each pod's admission overwriting the other's. The surviving pod's sidecar picks up claims
	// minted for a different agent_class on its next restart: a refusal, or the wrong policy tier, and
	// no signal either way because both writes succeeded from the webhook's side.
	support := sidecarSecretName("checkout", "support-agent")
	payments := sidecarSecretName("checkout", "payments-agent")
	if support == payments {
		t.Fatalf("two agent classes on one workload share a Secret (%q) — each pod's admission "+
			"overwrites the other's credential", support)
	}

	// Determinism is the other half and must survive: the same Deployment admitting a replacement pod
	// has to land on the SAME object, or every rollout leaks a new Secret.
	if again := sidecarSecretName("checkout", "support-agent"); again != support {
		t.Fatalf("not deterministic: %q then %q", support, again)
	}

	// And the readable part is still readable — the point of the prefix is that an operator can tell
	// what a Secret belongs to without decoding it.
	if !strings.HasPrefix(support, "norviq-sidecar-checkout-") {
		t.Fatalf("lost the readable workload segment: %q", support)
	}
	if len(support) > 63 {
		t.Fatalf("name exceeds the DNS-1123 label bound: %d chars", len(support))
	}
}
