// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// Regression tests for the policy retry sweep. The bug these lock down: a policy whose sync to the
// API failed (an API rollout/restart, a network blip) latched status phase=Error and was NEVER
// retried — the error path returns without requeueing, and the informer's 30s resync cannot re-drive
// it because shouldProcessUpdate compares Generation, which a resync does not change. The declared
// policy in the CR then silently diverged from what the engine actually enforced.
package main

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/tools/cache"
)

// retryTestRego is the minimum policy validateRego accepts (v0 syntax, matching the engine's
// --v0-compatible OPA).
const retryTestRego = `package norviq.custom

default decision = "allow"
default rule_id = "retry_test_default_allow"
default reason = "allowed by retry test policy"

decision = "block" {
  input.tool_name == "drop_table"
}

rule_id = "retry_test_block" {
  input.tool_name == "drop_table"
}

reason = "drop_table is denied" {
  input.tool_name == "drop_table"
}
`

// retryPolicyObj builds a minimal NrvqPolicy carrying inline rego, optionally with a status phase.
func retryPolicyObj(name, phase string) *unstructured.Unstructured {
	u := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "norviq.io/v1alpha1",
		"kind":       "NrvqPolicy",
		"metadata": map[string]interface{}{
			"name":      name,
			"namespace": "default",
		},
		"spec": map[string]interface{}{
			"enforcementMode": "block",
			"target": map[string]interface{}{
				"agentClass": "customer-support",
			},
			// validateRego requires: a reachable `decision = "block"|"escalate"` rule, rules named
			// decision/rule_id/reason, and a `default decision` — otherwise the policy is rejected
			// before it ever reaches syncPolicy.
			"rego": retryTestRego,
		},
	}}
	if phase != "" {
		_ = unstructured.SetNestedField(u.Object, phase, "status", "phase")
	}
	return u
}

// retryTestController wires a controller at a counting httptest API with a store holding objs.
// client stays nil so updatePolicyStatus short-circuits (no fake dynamic client needed).
func retryTestController(t *testing.T, objs ...*unstructured.Unstructured) (*Controller, *int32) {
	t.Helper()
	var posts int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&posts, 1)
		w.WriteHeader(http.StatusCreated)
	}))
	t.Cleanup(server.Close)

	c := newTestController()
	c.apiURL = server.URL
	c.apiSecret = "secret"
	c.httpClient = server.Client()

	store := cache.NewStore(cache.MetaNamespaceKeyFunc)
	for _, o := range objs {
		if err := store.Add(o); err != nil {
			t.Fatalf("store.Add: %v", err)
		}
	}
	c.policyStore = store
	return c, &posts
}

// THE regression test: a policy left in Error by a transient failure must be re-synced by the sweep.
func TestRetryUnsyncedPolicies_RetriesErrorPhase(t *testing.T) {
	c, posts := retryTestController(t, retryPolicyObj("stranded", policyPhaseError))
	c.retryUnsyncedPolicies()
	c.wg.Wait() // handlePolicy syncs in a semaphore-bounded goroutine
	if got := atomic.LoadInt32(posts); got != 1 {
		t.Fatalf("expected the Error-phase policy to be re-synced once, got %d POSTs", got)
	}
}

// A policy that never synced at all (no status yet) must also be picked up.
func TestRetryUnsyncedPolicies_RetriesEmptyPhase(t *testing.T) {
	c, posts := retryTestController(t, retryPolicyObj("never-synced", ""))
	c.retryUnsyncedPolicies()
	c.wg.Wait()
	if got := atomic.LoadInt32(posts); got != 1 {
		t.Fatalf("expected the never-synced policy to be synced once, got %d POSTs", got)
	}
}

// Already-Active policies must NOT be re-synced — otherwise the sweep would re-POST every policy
// every interval, turning a convergence mechanism into steady-state load on the API.
func TestRetryUnsyncedPolicies_SkipsActivePhase(t *testing.T) {
	c, posts := retryTestController(t, retryPolicyObj("healthy", policyPhaseActive))
	c.retryUnsyncedPolicies()
	c.wg.Wait()
	if got := atomic.LoadInt32(posts); got != 0 {
		t.Fatalf("expected Active policies to be skipped, got %d POSTs", got)
	}
}

// Deletions are driven by the delete handler + finalizer; the sweep must not resurrect them.
func TestRetryUnsyncedPolicies_SkipsDeletingPolicies(t *testing.T) {
	obj := retryPolicyObj("going-away", policyPhaseError)
	now := metav1.NewTime(time.Now())
	obj.SetDeletionTimestamp(&now)
	c, posts := retryTestController(t, obj)
	c.retryUnsyncedPolicies()
	c.wg.Wait()
	if got := atomic.LoadInt32(posts); got != 0 {
		t.Fatalf("expected deleting policies to be skipped, got %d POSTs", got)
	}
}

// Mixed store: only the unsynced ones are re-driven.
func TestRetryUnsyncedPolicies_OnlyUnsyncedAreRedriven(t *testing.T) {
	c, posts := retryTestController(t,
		retryPolicyObj("ok-1", policyPhaseActive),
		retryPolicyObj("bad-1", policyPhaseError),
		retryPolicyObj("ok-2", policyPhaseActive),
		retryPolicyObj("bad-2", ""),
	)
	c.retryUnsyncedPolicies()
	c.wg.Wait()
	if got := atomic.LoadInt32(posts); got != 2 {
		t.Fatalf("expected exactly the 2 unsynced policies to be re-synced, got %d POSTs", got)
	}
}

// Convergence: the API is down for the first attempt and healthy for the second. Before the fix the
// policy stayed stranded forever; now the next sweep pushes it through.
func TestRetryUnsyncedPolicies_ConvergesOnceAPIRecovers(t *testing.T) {
	var posts int32
	var healthy atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&posts, 1)
		if !healthy.Load() {
			w.WriteHeader(http.StatusServiceUnavailable) // API mid-rollout
			return
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()

	c := newTestController()
	c.apiURL = server.URL
	c.apiSecret = "secret"
	c.httpClient = server.Client()
	store := cache.NewStore(cache.MetaNamespaceKeyFunc)
	obj := retryPolicyObj("converge", policyPhaseError)
	if err := store.Add(obj); err != nil {
		t.Fatalf("store.Add: %v", err)
	}
	c.policyStore = store

	c.retryUnsyncedPolicies() // attempt 1 -> API down, still stranded
	c.wg.Wait()
	if got := atomic.LoadInt32(&posts); got != 1 {
		t.Fatalf("expected 1 attempt while the API was down, got %d", got)
	}

	healthy.Store(true)
	c.retryUnsyncedPolicies() // attempt 2 -> API healthy, converges
	c.wg.Wait()
	if got := atomic.LoadInt32(&posts); got != 2 {
		t.Fatalf("expected a second attempt after the API recovered, got %d", got)
	}
}

// A nil store (controller not started) must be a no-op, never a panic.
func TestRetryUnsyncedPolicies_NilStoreIsNoop(t *testing.T) {
	c := newTestController()
	c.policyStore = nil
	c.retryUnsyncedPolicies()
}
