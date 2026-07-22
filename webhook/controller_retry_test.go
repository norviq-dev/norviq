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

// --- audit follow-ups: the sweep must not undo deliberate state, and must not spin forever ---

// The "referenced class deleted" latch is deliberate terminal state (the NrvqClass is gone). Before
// this guard the sweep re-POSTed the orphaned policy and flipped it back to Active — nothing
// downstream re-rejects it, since handlePolicy does no class-existence check.
func TestRetryUnsyncedPolicies_PreservesClassDeletedLatch(t *testing.T) {
	obj := retryPolicyObj("orphaned", policyPhaseError)
	_ = unstructured.SetNestedField(obj.Object, msgClassDeleted, "status", "message")
	c, posts := retryTestController(t, obj)
	c.retryUnsyncedPolicies()
	c.wg.Wait()
	if got := atomic.LoadInt32(posts); got != 0 {
		t.Fatalf("class-deleted latch must NOT be re-synced, got %d POSTs", got)
	}
}

// A sync dropped because the semaphore was full is transient back-pressure: it must land in Pending
// so the sweep re-drives it. Leaving the status untouched was the one divergence class the retry
// worker still missed.
func TestRetryUnsyncedPolicies_RetriesPendingPhase(t *testing.T) {
	c, posts := retryTestController(t, retryPolicyObj("queued", policyPhasePending))
	c.retryUnsyncedPolicies()
	c.wg.Wait()
	if got := atomic.LoadInt32(posts); got != 1 {
		t.Fatalf("expected a Pending policy to be retried once, got %d POSTs", got)
	}
}

// A deterministically-invalid policy cannot succeed on retry. Re-driving it every tick would be an
// unbounded status-write loop any namespace user could trigger with one malformed CR.
func TestRetryUnsyncedPolicies_SkipsDeterministicFailureUntilSpecChanges(t *testing.T) {
	obj := retryPolicyObj("bad-rego", policyPhaseError)
	obj.SetGeneration(3)
	c, posts := retryTestController(t, obj)
	c.markDeterministicFailure(obj)

	c.retryUnsyncedPolicies()
	c.wg.Wait()
	if got := atomic.LoadInt32(posts); got != 0 {
		t.Fatalf("same generation must not be re-driven, got %d POSTs", got)
	}

	obj.SetGeneration(4) // the author fixed the spec
	c.retryUnsyncedPolicies()
	c.wg.Wait()
	if got := atomic.LoadInt32(posts); got != 1 {
		t.Fatalf("a new generation must be retried once, got %d POSTs", got)
	}
}

// --- derived class/config status refresh: a policy change never re-drives class/config status via the
// informer (see refreshDerivedStatusIfStale), so the retry sweep's dirty-flag-gated refresh is the
// only thing that converges policyCount/activeNamespaces/totalPolicies. ---

// retryClassObj builds a minimal NrvqClass.
func retryClassObj(name string) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "norviq.io/v1alpha1",
		"kind":       "NrvqClass",
		"metadata": map[string]interface{}{
			"name": name,
		},
	}}
}

// retryConfigObj builds a minimal NrvqConfig.
func retryConfigObj(name string) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "norviq.io/v1alpha1",
		"kind":       "NrvqConfig",
		"metadata": map[string]interface{}{
			"name": name,
		},
	}}
}

// A policy add marks derived status stale, and the sweep re-enqueues the cached classes and configs.
func TestRefreshDerivedStatusIfStale_PolicyAddTriggersSweep(t *testing.T) {
	c, _ := retryTestController(t)
	classStore := cache.NewStore(cache.MetaNamespaceKeyFunc)
	if err := classStore.Add(retryClassObj("customer-support")); err != nil {
		t.Fatalf("classStore.Add: %v", err)
	}
	configStore := cache.NewStore(cache.MetaNamespaceKeyFunc)
	if err := configStore.Add(retryConfigObj("default")); err != nil {
		t.Fatalf("configStore.Add: %v", err)
	}
	c.classStore = classStore
	c.configStore = configStore
	c.classQueue = make(chan *unstructured.Unstructured, 4)
	c.configQueue = make(chan *unstructured.Unstructured, 4)
	c.derivedStatusStale.Store(false) // start clean, as if a prior sweep already consumed it

	c.handlePolicy(retryPolicyObj("new-policy", ""), "created")
	c.wg.Wait()
	if !c.derivedStatusStale.Load() {
		t.Fatalf("expected handlePolicy to mark derived status stale")
	}

	c.refreshDerivedStatusIfStale()

	select {
	case u := <-c.classQueue:
		if u.GetName() != "customer-support" {
			t.Fatalf("unexpected class enqueued: %s", u.GetName())
		}
	default:
		t.Fatalf("expected the cached class to be re-enqueued")
	}
	select {
	case u := <-c.configQueue:
		if u.GetName() != "default" {
			t.Fatalf("unexpected config enqueued: %s", u.GetName())
		}
	default:
		t.Fatalf("expected the cached config to be re-enqueued")
	}
	if c.derivedStatusStale.Load() {
		t.Fatalf("expected the dirty flag to be cleared after a successful sweep")
	}
}

// Control test: with no policy change, the sweep must NOT enqueue anything — proves the dirty-flag
// gate actually prevents churn (processConfig's appliedAt would otherwise rewrite resourceVersion
// forever on an unconditional refresh).
func TestRefreshDerivedStatusIfStale_NoChangeDoesNotEnqueue(t *testing.T) {
	c, _ := retryTestController(t)
	classStore := cache.NewStore(cache.MetaNamespaceKeyFunc)
	if err := classStore.Add(retryClassObj("customer-support")); err != nil {
		t.Fatalf("classStore.Add: %v", err)
	}
	configStore := cache.NewStore(cache.MetaNamespaceKeyFunc)
	if err := configStore.Add(retryConfigObj("default")); err != nil {
		t.Fatalf("configStore.Add: %v", err)
	}
	c.classStore = classStore
	c.configStore = configStore
	c.classQueue = make(chan *unstructured.Unstructured, 4)
	c.configQueue = make(chan *unstructured.Unstructured, 4)
	c.derivedStatusStale.Store(false) // nothing changed since the last sweep

	c.refreshDerivedStatusIfStale()

	select {
	case u := <-c.classQueue:
		t.Fatalf("expected no class enqueue when nothing changed, got %q", u.GetName())
	default:
	}
	select {
	case u := <-c.configQueue:
		t.Fatalf("expected no config enqueue when nothing changed, got %q", u.GetName())
	default:
	}
}

// Queue-full: if the class queue is full, the dirty flag must be left SET so the next sweep retries
// instead of silently dropping the refresh forever.
func TestRefreshDerivedStatusIfStale_QueueFullKeepsFlagSet(t *testing.T) {
	c, _ := retryTestController(t)
	classStore := cache.NewStore(cache.MetaNamespaceKeyFunc)
	if err := classStore.Add(retryClassObj("customer-support")); err != nil {
		t.Fatalf("classStore.Add: %v", err)
	}
	c.classStore = classStore
	c.configStore = cache.NewStore(cache.MetaNamespaceKeyFunc) // empty, keeps this test isolated to the class queue
	c.classQueue = make(chan *unstructured.Unstructured)       // unbuffered + nobody reading -> the send always hits default
	c.configQueue = make(chan *unstructured.Unstructured, 4)
	c.derivedStatusStale.Store(true)

	c.refreshDerivedStatusIfStale()

	if !c.derivedStatusStale.Load() {
		t.Fatalf("expected the dirty flag to remain set when the class queue is full")
	}
}

// Policy delete also marks derived status stale.
func TestRefreshDerivedStatusIfStale_PolicyDeleteMarksStale(t *testing.T) {
	c, _ := retryTestController(t)
	c.derivedStatusStale.Store(false)

	c.handlePolicyDelete(retryPolicyObj("deleted-policy", ""))
	c.wg.Wait()

	if !c.derivedStatusStale.Load() {
		t.Fatalf("expected handlePolicyDelete to mark derived status stale")
	}
}
