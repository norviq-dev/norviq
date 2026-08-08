// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// controller.go is the CRD controller: it watches NrvqPolicy / NrvqClass / NrvqConfig
// custom resources and syncs them to the central API, validating rego and targets,
// managing deletion finalizers, and keeping resource status up to date.
package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/open-policy-agent/opa/v1/ast"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/dynamic/dynamicinformer"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
)

var policyGVR = schema.GroupVersionResource{
	Group:    "norviq.io",
	Version:  "v1alpha1",
	Resource: "nrvqpolicies",
}
var classGVR = schema.GroupVersionResource{
	Group:    "norviq.io",
	Version:  "v1alpha1",
	Resource: "nrvqclasses",
}
var configGVR = schema.GroupVersionResource{
	Group:    "norviq.io",
	Version:  "v1alpha1",
	Resource: "nrvqconfigs",
}

const deleteSyncedAnnotation = "norviq.io/delete-synced"

// Fingerprint of the rego this controller last successfully pushed to the API for a CR.
//
// Policy CONTENT can change without the CR changing at all. A baseline CR names a `preset`, and the
// rego for that preset is a FILE IN THIS IMAGE (`presetBasePath`) — so shipping a new image changes
// what the CR means while its spec, and therefore its Generation, stay byte-identical. The informer's
// resync does not bump Generation either, and the retry sweep skipped anything already Active. Net
// effect: repo rego changes, new images roll out, and the DB keeps enforcing the OLD rego forever —
// every version string reports the new release while enforcement silently lags it.
//
// Recording what was applied lets the sweep notice that drift and re-converge. An ANNOTATION rather
// than a status field on purpose: CRDs are installed once from `crds/` and are NOT upgraded by
// `helm upgrade` (a Helm limitation), so a new status property would be silently PRUNED by the
// structural schema on every existing install — exactly where this fix is needed most. Annotations
// carry no schema and work on a cluster that has never seen the new CRD. Writing one also does not
// bump Generation, so it cannot feed back into the update handler as a reconcile loop.
const appliedRegoAnnotation = "norviq.io/applied-rego-sha256"

// regoFingerprint returns a short, stable content hash. Truncated to 16 hex chars: it only has to
// detect change, and annotation values are read by humans debugging drift.
func regoFingerprint(rego string) string {
	sum := sha256.Sum256([]byte(rego))
	return fmt.Sprintf("%x", sum)[:16]
}

// Policy status phases. `policyPhaseActive` is the ONLY terminal-success phase: the retry sweep
// re-drives every policy that is not in it (Error, or an empty phase that never synced at all).
const (
	policyPhaseActive  = "Active"
	policyPhaseError   = "Error"
	policyPhasePending = "Pending"
)

// msgClassDeleted is a DELIBERATE terminal latch, not a transient failure: the policy's NrvqClass is
// gone, so re-syncing it would resurrect an orphaned policy against a class that no longer exists.
// The retry sweep must recognise and preserve it. Compared by value, so keep set and check in sync.
const msgClassDeleted = "referenced class deleted"

// How often the retry sweep re-drives policies that are not Active.
//
// Why a ticker-driven sweep instead of re-processing on the informer's resync: a failed sync calls
// updatePolicyStatus, which stamps a fresh `lastApplied` timestamp on every write. That always bumps
// resourceVersion and fires another UpdateFunc — so widening shouldProcessUpdate to re-process
// non-Active objects would spin a tight feedback loop (fail -> status write -> event -> fail ...)
// hammering both the API server and the Norviq API. A ticker decouples retry from status writes, so
// the retry rate is bounded no matter how many policies are failing or how fast statuses churn.
var policyRetryInterval = 60 * time.Second

var finalizerMaxAge = 15 * time.Minute

// The `@sha256:` alternative is not decoration — it is the form EVERY RELEASE USES. release_stamp.py
// pins the injected sidecar to an immutable digest (tests/release asserts it, and isMutableTag below
// exists to refuse anything less), so a tag-only allow-list rejected the chart's own sidecar on every
// published release. With failurePolicy Fail that is not a skipped injection: the webhook refuses to
// build a patch, and the pod is DENIED — enabling injection stopped tenant workloads from starting.
// It stayed hidden because the checked-in chart carries `-latest` tags, which this pattern accepted,
// so every render-based test and every local install passed.
var allowedSidecarImagePattern = regexp.MustCompile(
	`^(norviq/norviq-engine|docker\.io/norviq/norviq-engine|ghcr\.io/norviq-dev/norviq-engine)` +
		`(?::[a-zA-Z0-9._-]+|@sha256:[0-9a-f]{64})$`)

type policySyncRequest struct {
	Namespace       string                 `json:"namespace"`
	AgentClass      string                 `json:"agent_class"`
	EnforcementMode string                 `json:"enforcement_mode"`
	SavedBy         string                 `json:"saved_by"`
	RegoSource      string                 `json:"rego_source,omitempty"`
	Target          map[string]interface{} `json:"target,omitempty"`
	Rules           []string               `json:"rules,omitempty"`
	Priority        int64                  `json:"priority"`
	PolicyName      string                 `json:"policy_name"`
}

type Controller struct {
	client       dynamic.Interface
	apiURL       string
	apiSecret    string // HS256 signing key; the controller mints short-lived service JWTs from it
	tokenMu      sync.Mutex
	cachedJWT    string
	cachedJWTExp time.Time
	// When configured, the controller authenticates to the API with an OIDC client-credentials
	// access token (validated by the API's existing OIDC path) instead of the HS256 service JWT.
	// nil -> HS256 path. The TokenSource caches + auto-refreshes.
	oidcTokenSource      oauth2.TokenSource
	httpClient           *http.Client
	syncSemaphore        chan struct{}
	presetBasePath       string
	adminPolicyNamespace string
	runtime              *RuntimeConfig
	defaultSidecarImage  string
	policyStore          cache.Store
	classStore           cache.Store
	configStore          cache.Store
	classQueue           chan *unstructured.Unstructured
	configQueue          chan *unstructured.Unstructured
	wg                   sync.WaitGroup
	// Generations whose sync failed DETERMINISTICALLY (invalid rego/target/priority/payload). Such a
	// policy cannot succeed on retry, so the sweep skips it until its spec changes — otherwise one
	// malformed CR becomes an unbounded status-write loop, per replica, forever.
	failedGenMu  sync.Mutex
	failedGenMap map[string]int64
	// Rego fingerprint last successfully applied per CR, mirroring appliedRegoAnnotation. The annotation
	// is the durable record (survives restart, shared across replicas); this is a same-process backstop so
	// that if the annotation PATCH keeps failing — RBAC drift, a stale informer copy — drift detection
	// re-syncs once rather than re-POSTing every policy on every tick forever.
	appliedRegoMu  sync.Mutex
	appliedRegoMap map[string]string
	// Set whenever the cached policy set may have changed (add/update/delete). processClass and
	// processConfig derive policyCount/activeNamespaces/totalPolicies from that cache, but nothing
	// re-drives them when it's a POLICY that changed — see refreshDerivedStatusIfStale for why.
	derivedStatusStale atomic.Bool
}

func NewController(apiURL, apiToken string) (*Controller, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("NRVQ-WHK-4020: in-cluster config failed: %w", err)
	}
	client, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("NRVQ-WHK-4021: dynamic client failed: %w", err)
	}

	return NewControllerWithClient(client, apiURL, apiToken), nil
}

func NewControllerWithClient(client dynamic.Interface, apiURL, apiSecret string) *Controller {
	defaultSidecar := envStr("NRVQ_SIDECAR_IMAGE", "ghcr.io/norviq-dev/norviq-engine:engine-latest")
	runtime := &RuntimeConfig{}
	runtime.SetSidecarImage(defaultSidecar)
	var oidcTS oauth2.TokenSource
	tokenURL := envStr("NRVQ_OIDC_TOKEN_URL", "")
	clientID := envStr("NRVQ_OIDC_CLIENT_ID", "")
	clientSecret := envStr("NRVQ_OIDC_CLIENT_SECRET", "")
	if tokenURL != "" && clientID != "" && clientSecret != "" {
		ccfg := &clientcredentials.Config{ClientID: clientID, ClientSecret: clientSecret, TokenURL: tokenURL}
		oidcTS = ccfg.TokenSource(context.Background())
		slog.Info("NRVQ-WHK-4042: controller using OIDC client-credentials identity", "clientID", clientID, "tokenURL", tokenURL)
	}
	httpClient, err := buildAPIHTTPClient(envBool("NRVQ_INTERNAL_TLS", false), envStr("NRVQ_CA_CERT_FILE", ""))
	if err != nil {
		// Fail closed: internal-TLS is requested but the CA could not be loaded. Use a client whose
		// RootCAs pool is empty so every TLS handshake to the API fails verification, rather than
		// silently downgrading to plaintext.
		slog.Error("NRVQ-WHK-4046: internal-TLS API client build failed; using fail-closed client", "error", err)
		httpClient = &http.Client{
			Timeout:   5 * time.Second,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: x509.NewCertPool(), MinVersion: tls.VersionTLS12}},
		}
	}
	return &Controller{
		client:               client,
		apiURL:               apiURL,
		apiSecret:            apiSecret,
		oidcTokenSource:      oidcTS,
		httpClient:           httpClient,
		syncSemaphore:        make(chan struct{}, 10),
		presetBasePath:       "/app/presets",
		adminPolicyNamespace: envStr("NRVQ_ADMIN_POLICY_NAMESPACE", "norviq"),
		runtime:              runtime,
		defaultSidecarImage:  defaultSidecar,
		classQueue:           make(chan *unstructured.Unstructured, 64),
		configQueue:          make(chan *unstructured.Unstructured, 64),
		failedGenMap:         make(map[string]int64),
		appliedRegoMap:       make(map[string]string),
	}
}

// buildAPIHTTPClient builds the controller's HTTP client for talking to the central API. When
// internalTLS is false it returns the historical plaintext client (byte-identical to the pre-mTLS
// behavior). When true it pins the API's serving cert to the internal CA loaded from caCertFile
// (server-auth TLS); the controller keeps its bearer service JWT for authentication on top.
func buildAPIHTTPClient(internalTLS bool, caCertFile string) (*http.Client, error) {
	if !internalTLS {
		return &http.Client{Timeout: 5 * time.Second}, nil
	}
	pemBytes, err := os.ReadFile(caCertFile)
	if err != nil {
		return nil, fmt.Errorf("NRVQ-WHK-4044: read internal CA cert %q: %w", caCertFile, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, fmt.Errorf("NRVQ-WHK-4045: internal CA cert %q contained no valid PEM certificates", caCertFile)
	}
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		},
	}, nil
}

func (c *Controller) Start(ctx context.Context) error {
	factory := dynamicinformer.NewDynamicSharedInformerFactory(c.client, 30*time.Second)
	policyInformer := factory.ForResource(policyGVR).Informer()
	classInformer := factory.ForResource(classGVR).Informer()
	configInformer := factory.ForResource(configGVR).Informer()
	c.policyStore = policyInformer.GetStore()
	c.classStore = classInformer.GetStore()
	c.configStore = configInformer.GetStore()

	policyInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			c.handlePolicy(obj, "created")
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			if !shouldProcessUpdate(oldObj, newObj) {
				return
			}
			c.handlePolicy(newObj, "updated")
		},
		DeleteFunc: func(obj interface{}) {
			c.handlePolicyDelete(obj)
		},
	})
	classInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			c.handleClassEvent(obj)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			if !shouldProcessUpdate(oldObj, newObj) {
				return
			}
			c.handleClassEvent(newObj)
		},
		DeleteFunc: func(obj interface{}) {
			c.handleClassDelete(obj)
		},
	})
	configInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			c.handleConfigEvent(obj)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			if !shouldProcessUpdate(oldObj, newObj) {
				return
			}
			c.handleConfigEvent(newObj)
		},
		DeleteFunc: func(obj interface{}) {
			c.handleConfigDelete(obj)
		},
	})

	slog.Info("NRVQ-WHK-4022: CRD controller starting")
	factory.Start(ctx.Done())
	factory.WaitForCacheSync(ctx.Done())
	slog.Info("NRVQ-WHK-4023: CRD controller cache synced")
	c.wg.Add(3)
	go c.classWorker(ctx)
	go c.configWorker(ctx)
	go c.policyRetryWorker(ctx)

	<-ctx.Done()
	c.wg.Wait()
	return nil
}

// policyRetryWorker periodically re-drives policies whose sync to the API did not succeed.
//
// Without this, a sync that fails transiently (an API rollout/restart, a network blip — exactly what
// a cluster cold start or a helm upgrade produces) is NEVER retried: the error path latches
// phase=Error and returns, and the informer's resync cannot re-drive it because shouldProcessUpdate
// compares Generation, which a resync does not change. The declared policy in the CR would then
// silently diverge from what the engine actually enforces, with only a log line to show for it.
func (c *Controller) policyRetryWorker(ctx context.Context) {
	defer c.wg.Done()
	ticker := time.NewTicker(policyRetryInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.retryUnsyncedPolicies()
			c.refreshDerivedStatusIfStale()
		}
	}
}

// refreshDerivedStatusIfStale re-enqueues every cached NrvqClass/NrvqConfig so their derived status
// (policyCount, activeNamespaces, totalPolicies) is recomputed against the current policy cache.
//
// processClass/processConfig are ONLY reachable through the NrvqClass/NrvqConfig informer handlers —
// creating, updating, or deleting an NrvqPolicy never enqueues a class or config, so those derived
// counts go stale the moment the policy set changes. The 30s informer resync can't rescue this either:
// resync doesn't bump Generation, and the class/config UpdateFuncs are gated on shouldProcessUpdate's
// Generation check, exactly like the policy retry case above. Piggybacking on this same ticker avoids
// running a second timer for what is the same bug class.
//
// Gated on derivedStatusStale (rather than refreshing unconditionally every tick) because
// processConfig always stamps a fresh appliedAt, so an unconditional refresh would churn the config's
// resourceVersion forever even when nothing actually changed. A no-op class re-enqueue is cheap (the
// apiserver treats an identical status write as a no-op), but there's no reason to pay even that when
// the cache hasn't moved.
func (c *Controller) refreshDerivedStatusIfStale() {
	if !c.derivedStatusStale.Swap(false) {
		return
	}
	queueFull := false
	if c.classStore != nil {
		for _, obj := range c.classStore.List() {
			u, ok := obj.(*unstructured.Unstructured)
			if !ok {
				continue
			}
			select {
			case c.classQueue <- u.DeepCopy():
			default:
				slog.Warn("NRVQ-WHK-4028: class queue full, skipping", "class", u.GetName())
				queueFull = true
			}
		}
	}
	if c.configStore != nil {
		for _, obj := range c.configStore.List() {
			u, ok := obj.(*unstructured.Unstructured)
			if !ok {
				continue
			}
			select {
			case c.configQueue <- u.DeepCopy():
			default:
				slog.Warn("NRVQ-WHK-4028: config queue full, skipping", "config", u.GetName())
				queueFull = true
			}
		}
	}
	if queueFull {
		// At least one enqueue was dropped: re-arm the flag so the next tick retries, instead of
		// silently losing the refresh for good.
		c.derivedStatusStale.Store(true)
	}
}

// stampAppliedRego records the fingerprint of the rego just pushed for this CR, so a later sweep can
// distinguish "already synced" from "synced from an older image's preset". See appliedRegoAnnotation.
//
// Best-effort by design: this runs AFTER a successful sync, so failing it must not report an error. The
// only cost of a missed stamp is one more idempotent re-sync on the next tick.
func (c *Controller) stampAppliedRego(ctx context.Context, u *unstructured.Unstructured, rego string) {
	if rego == "" {
		return
	}
	want := regoFingerprint(rego)
	// Record in-process BEFORE anything can return early. The backstop's whole job is to bound the loop
	// when the durable write cannot happen, so it must not sit behind a guard for that same condition —
	// a nil client IS "the write can't happen", and recording after it would re-POST every tick forever.
	c.appliedRegoMu.Lock()
	if c.appliedRegoMap == nil {
		c.appliedRegoMap = make(map[string]string)
	}
	c.appliedRegoMap[genKey(u)] = want
	c.appliedRegoMu.Unlock()
	if c.client == nil {
		return
	}
	if u.GetAnnotations()[appliedRegoAnnotation] == want {
		return // unchanged — skip the write rather than churn resourceVersion every sync
	}
	// Patch, not Update: the informer's copy may be stale, and a full Update would clobber a concurrent
	// status/finalizer write. A merge patch on one annotation key touches nothing else.
	patch := fmt.Sprintf(`{"metadata":{"annotations":{%q:%q}}}`, appliedRegoAnnotation, want)
	_, err := c.client.Resource(policyGVR).Namespace(u.GetNamespace()).Patch(
		ctx, u.GetName(), types.MergePatchType, []byte(patch), metav1.PatchOptions{},
	)
	if err != nil {
		slog.Warn(
			"NRVQ-WHK-4060: applied-rego stamp failed; policy is synced but drift detection will re-sync it",
			"policy", u.GetName(), "namespace", u.GetNamespace(), "error", err,
		)
	}
}

// policyContentDrifted reports whether the rego this controller WOULD apply now differs from what it
// last recorded applying. True after a new image ships a changed preset for an otherwise-unchanged CR.
//
// A CR with no stamp yet (installed before this controller version, or whose stamp write failed) is
// treated as drifted so it converges once; the sync stamps it and the next sweep is a no-op. That is
// why the comparison is on CONTENT and not on a timestamp — the known trap here is that
// updatePolicyStatus rewrites `lastApplied` on every status write, so anything keyed off time re-drives
// forever. A content hash is stable exactly as long as the content is.
func (c *Controller) policyContentDrifted(u *unstructured.Unstructured) (bool, string) {
	body, err := c.buildPolicySyncPayload(u)
	if err != nil {
		// Can't determine the desired content (e.g. the preset file is missing in this image). Leave it
		// alone: handlePolicy is what should surface that, and re-driving would only spam the failure.
		return false, ""
	}
	if body.RegoSource == "" {
		return false, ""
	}
	want := regoFingerprint(body.RegoSource)
	if u.GetAnnotations()[appliedRegoAnnotation] == want {
		return false, want
	}
	c.appliedRegoMu.Lock()
	seen := c.appliedRegoMap[genKey(u)]
	c.appliedRegoMu.Unlock()
	return seen != want, want
}

// retryUnsyncedPolicies re-submits every cached policy that is not in the Active phase, plus any Active
// policy whose CONTENT has drifted from what was applied. Reuses the normal handlePolicy path, so both
// inherit the same validation and the same syncSemaphore concurrency bound as event-driven syncs.
func (c *Controller) retryUnsyncedPolicies() {
	if c.policyStore == nil {
		return
	}
	for _, obj := range c.policyStore.List() {
		u, ok := obj.(*unstructured.Unstructured)
		if !ok || u.GetDeletionTimestamp() != nil {
			continue // deletions are driven by the delete handler + finalizer, not this sweep
		}
		phase, _, _ := unstructured.NestedString(u.Object, "status", "phase")
		if phase == policyPhaseActive {
			// "Active" only means the last sync SUCCEEDED — not that it applied the rego this image
			// carries now. A preset's rego lives in the image, so a new release changes the desired
			// content while the CR's spec and Generation stay identical, and nothing else re-drives it.
			// Without this check the DB enforces the old rego indefinitely.
			drifted, want := c.policyContentDrifted(u)
			if !drifted {
				continue // genuinely converged
			}
			slog.Info(
				"NRVQ-WHK-4061: policy content drifted from the applied rego; re-syncing",
				"policy", u.GetName(),
				"namespace", u.GetNamespace(),
				"applied", u.GetAnnotations()[appliedRegoAnnotation],
				"desired", want,
			)
			c.handlePolicy(u, "content-drift")
			continue
		}
		msg, _, _ := unstructured.NestedString(u.Object, "status", "message")
		if msg == msgClassDeleted {
			// DELIBERATE terminal latch, not a transient failure — re-syncing would resurrect a policy
			// whose NrvqClass is gone. Nothing downstream re-rejects it (handlePolicy does no
			// class-existence check and the API does not validate agent_class), so the retry would
			// silently flip it back to Active.
			continue
		}
		// Deterministic failures (bad rego, bad target, bad priority) cannot succeed on retry: re-driving
		// them every tick would be an unbounded status-write loop that any namespace user could trigger by
		// applying one malformed CR. Only re-attempt once the spec actually changes.
		if gen, seen := c.failedGeneration(u); seen && gen == u.GetGeneration() {
			continue
		}
		slog.Info(
			"NRVQ-WHK-4059: retrying unsynced policy",
			"policy", u.GetName(),
			"namespace", u.GetNamespace(),
			"phase", phase,
		)
		c.handlePolicy(u, "retry")
	}
}

// genKey identifies one CR across sweeps (UID would be ideal but the fake clients in tests omit it).
func genKey(u *unstructured.Unstructured) string {
	return u.GetNamespace() + "/" + u.GetName()
}

// markDeterministicFailure records that THIS generation cannot succeed on retry.
func (c *Controller) markDeterministicFailure(u *unstructured.Unstructured) {
	c.failedGenMu.Lock()
	defer c.failedGenMu.Unlock()
	if c.failedGenMap == nil {
		c.failedGenMap = make(map[string]int64)
	}
	c.failedGenMap[genKey(u)] = u.GetGeneration()
}

// clearDeterministicFailure forgets a prior deterministic failure (the spec changed, or it synced).
func (c *Controller) clearDeterministicFailure(u *unstructured.Unstructured) {
	c.failedGenMu.Lock()
	defer c.failedGenMu.Unlock()
	delete(c.failedGenMap, genKey(u))
}

// failedGeneration returns the generation last recorded as a deterministic failure for this CR.
func (c *Controller) failedGeneration(u *unstructured.Unstructured) (int64, bool) {
	c.failedGenMu.Lock()
	defer c.failedGenMu.Unlock()
	gen, ok := c.failedGenMap[genKey(u)]
	return gen, ok
}

func (c *Controller) handlePolicy(obj interface{}, action string) {
	// The cached policy set may have just changed (add or update). Mark class/config derived status
	// stale unconditionally — cheap, and correctness beats precision here (see
	// refreshDerivedStatusIfStale for why nothing else re-drives it).
	c.derivedStatusStale.Store(true)
	u, ok := obj.(*unstructured.Unstructured)
	if !ok {
		slog.Error("NRVQ-WHK-4024: unexpected object type in handler")
		return
	}
	name := u.GetName()
	namespace := u.GetNamespace()
	ctx := context.Background()

	if u.GetDeletionTimestamp() != nil {
		if containsFinalizer(u, "norviq.io/policy-protection") {
			c.reconcileDeletingPolicyAsync(ctx, u)
		}
		return
	}

	body, err := c.buildPolicySyncPayload(u)
	if err != nil {
		if strings.Contains(err.Error(), "NRVQ-WHK-4029") {
			slog.Error("NRVQ-WHK-4029: preset file not found", "policy", name, "error", err)
		} else {
			slog.Error("NRVQ-WHK-4025: API sync failed for policy", "policy", name, "error", err)
		}
		c.markDeterministicFailure(u)
		c.updatePolicyStatus(context.Background(), u, policyPhaseError, err.Error())
		return
	}
	spec, _, _ := unstructured.NestedMap(u.Object, "spec")
	if err := validateClusterPriority(namespace, spec, c.adminPolicyNamespace); err != nil {
		slog.Warn("NRVQ-WHK-4037: invalid cluster priority rejected", "policy", name, "error", err)
		c.markDeterministicFailure(u)
		c.updatePolicyStatus(context.Background(), u, policyPhaseError, err.Error())
		return
	}
	_, hasClusterPriority := spec["clusterPriority"]
	if err := validateTarget(namespace, c.adminPolicyNamespace, body.Target, hasClusterPriority); err != nil {
		slog.Warn("NRVQ-WHK-4034: cross-namespace policy rejected", "policy", name, "error", err)
		c.markDeterministicFailure(u)
		c.updatePolicyStatus(context.Background(), u, policyPhaseError, err.Error())
		return
	}
	if rego, found, _ := unstructured.NestedString(u.Object, "spec", "rego"); found && rego != "" {
		if err := validateRego(rego); err != nil {
			slog.Warn("NRVQ-WHK-4032: invalid rego rejected", "policy", name, "error", err)
			c.markDeterministicFailure(u)
			c.updatePolicyStatus(context.Background(), u, policyPhaseError, err.Error())
			return
		}
	}
	if c.client != nil && !containsFinalizer(u, "norviq.io/policy-protection") {
		if err := c.addFinalizerWithRetry(ctx, namespace, name); err != nil {
			slog.Error("NRVQ-WHK-4035: finalizer add failed", "policy", name, "error", err)
			return
		}
	}

	select {
	case c.syncSemaphore <- struct{}{}:
		c.wg.Add(1)
		go func() {
			defer c.wg.Done()
			defer func() { <-c.syncSemaphore }()
			if err := c.syncPolicy(context.Background(), body); err != nil {
				slog.Error("NRVQ-WHK-4025: API sync failed for policy", "policy", name, "error", err)
				c.updatePolicyStatus(context.Background(), u, policyPhaseError, err.Error())
				return
			}
			c.clearDeterministicFailure(u)
			c.updatePolicyStatus(context.Background(), u, policyPhaseActive, "policy synced")
			// Record WHAT was applied, so the sweep can tell "already synced" from "synced, but from an
			// older image's preset". Best-effort: a failed stamp costs one extra idempotent re-sync on the
			// next tick and must never turn a successful sync into an error.
			c.stampAppliedRego(context.Background(), u, body.RegoSource)
			slog.Info(
				"NRVQ-WHK-4026: Policy synced to API successfully",
				"policy", name,
				"namespace", namespace,
				"action", action,
			)
		}()
	default:
		// Mark Pending (not Error) so the retry sweep re-drives it: a full queue is transient back-pressure,
		// and leaving the status untouched made this the one divergence class the retry worker still missed
		// (the engine keeps enforcing the old rego while the CR looks fine).
		slog.Warn("NRVQ-WHK-4028: sync queue full, queued for retry", "policy", name)
		c.updatePolicyStatus(context.Background(), u, policyPhasePending, "sync queue full; queued for retry")
	}
}

func (c *Controller) handleClassEvent(obj interface{}) {
	u, ok := obj.(*unstructured.Unstructured)
	if !ok {
		return
	}
	select {
	case c.classQueue <- u.DeepCopy():
	default:
		slog.Warn("NRVQ-WHK-4028: class queue full, skipping", "class", u.GetName())
	}
}

func (c *Controller) processClass(u *unstructured.Unstructured) {
	if c.client == nil {
		return
	}
	className := u.GetName()
	policies := c.listCachedPolicies()
	policyCount := int64(0)
	for _, item := range policies {
		target, _, _ := unstructured.NestedMap(item.Object, "spec", "target")
		agentClass, _ := target["agentClass"].(string)
		if agentClass == className {
			policyCount++
		}
	}
	// agentCount and averageTrustScore are NOT written. They were int64(0)/float64(0) literals on every
	// reconcile, sitting behind the DEFAULT printer columns "Agents" and "Avg-Trust" — next to a real
	// policyCount, which made the zeros look measured. `kubectl get nrvqclass` therefore told an operator
	// that a class with dozens of live agents had none, and that its fleet trust was 0.0 on a 0..1 scale
	// where 0.7 is the threshold. Same defect as the Blocks-24h column, same resolution: the controller
	// cannot compute either number (it has no agent registry access and never queries the API), so it
	// writes neither and the columns are gone. Real values: the Agent Monitor, GET /api/v1/agents.
	status := map[string]interface{}{
		"policyCount": policyCount,
	}
	if err := c.updateStatusWithRetry(context.Background(), classGVR, "", u.GetName(), status); err != nil {
		slog.Warn("NRVQ-WHK-4038: class status update failed", "class", u.GetName(), "error", err)
	}
}

func (c *Controller) handleConfigEvent(obj interface{}) {
	u, ok := obj.(*unstructured.Unstructured)
	if !ok {
		return
	}
	select {
	case c.configQueue <- u.DeepCopy():
	default:
		slog.Warn("NRVQ-WHK-4028: config queue full, skipping", "config", u.GetName())
	}
}

func (c *Controller) processConfig(u *unstructured.Unstructured) {
	if c.client == nil {
		return
	}
	if u.GetName() != "default" {
		return
	}
	if image, found, _ := unstructured.NestedString(u.Object, "spec", "sidecar", "image"); found && image != "" {
		if c.runtime == nil {
			c.runtime = &RuntimeConfig{}
		}
		if !validateImage(image) {
			slog.Warn("NRVQ-WHK-4033: config attempted unauthorized sidecar image", "image", image)
		} else if isMutableTag(image) {
			// Refuse to downgrade the pinned (-sha) sidecar image to a mutable tag — injected pods
			// must reference an immutable digest/sha so they can't silently drift. Keep the default.
			slog.Warn("NRVQ-WHK-4036: ignoring mutable sidecar tag override; keeping pinned image",
				"rejected", image, "pinned", c.defaultSidecarImage)
		} else {
			c.runtime.SetSidecarImage(image)
		}
	}
	policies := c.listCachedPolicies()
	namespaceSet := map[string]struct{}{}
	for _, item := range policies {
		namespaceSet[item.GetNamespace()] = struct{}{}
	}
	// totalAgents omitted for the same reason as NrvqClass.agentCount: a hard-coded 0 next to a correct
	// totalPolicies reads as measured. activeNamespaces and totalPolicies ARE counted from the live
	// policy list above, so they stay.
	status := map[string]interface{}{
		"appliedAt":        time.Now().UTC().Format(time.RFC3339),
		"activeNamespaces": int64(len(namespaceSet)),
		"totalPolicies":    int64(len(policies)),
	}
	if err := c.updateStatusWithRetry(context.Background(), configGVR, "", u.GetName(), status); err != nil {
		slog.Warn("NRVQ-WHK-4039: config status update failed", "config", u.GetName(), "error", err)
	}
}

func (c *Controller) classWorker(ctx context.Context) {
	defer c.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case u := <-c.classQueue:
			c.processClass(u)
		}
	}
}

func (c *Controller) configWorker(ctx context.Context) {
	defer c.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case u := <-c.configQueue:
			c.processConfig(u)
		}
	}
}

func (c *Controller) handleClassDelete(obj interface{}) {
	u, ok := obj.(*unstructured.Unstructured)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			return
		}
		u, ok = tombstone.Obj.(*unstructured.Unstructured)
		if !ok {
			return
		}
	}
	deletedClass := u.GetName()
	for _, policy := range c.listCachedPolicies() {
		target, _, _ := unstructured.NestedMap(policy.Object, "spec", "target")
		agentClass, _ := target["agentClass"].(string)
		if agentClass != deletedClass {
			continue
		}
		c.updatePolicyStatus(context.Background(), policy, policyPhaseError, msgClassDeleted)
	}
}

func (c *Controller) handleConfigDelete(obj interface{}) {
	u, ok := obj.(*unstructured.Unstructured)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			return
		}
		u, ok = tombstone.Obj.(*unstructured.Unstructured)
		if !ok {
			return
		}
	}
	if u.GetName() != "default" {
		return
	}
	if c.runtime == nil {
		c.runtime = &RuntimeConfig{}
	}
	c.runtime.SetSidecarImage(c.defaultSidecarImage)
}

func (c *Controller) updatePolicyStatus(ctx context.Context, u *unstructured.Unstructured, phase, message string) {
	if c.client == nil {
		return
	}
	// matchingWorkloads and blockCount24h are NOT written. They used to be hard-coded to int64(0) on
	// every status write, and the CRD advertised blockCount24h as a printer column called "Blocks-24h"
	// — so `kubectl get nrvqpolicy` showed a confident 0 for a policy that was blocking all day, and an
	// operator reading it concludes their policy has caught nothing. A fabricated metric on a security
	// product is worse than an absent one.
	//
	// They are not computed here on purpose: nothing in the controller knows the count, there is no
	// per-policy block-count endpoint to ask (audit/top-blocked aggregates by TOOL), and a status write
	// happens on every reconcile — a rolling 24h figure fetched over the network on that path would be
	// both expensive and stale between reconciles. Leaving the fields unset makes kubectl print
	// "<none>", which is honest. The real numbers live in the console's audit view and GET
	// /api/v1/audit/stats. The schema fields are retained (removing them from a published CRD would be
	// a breaking change) and their descriptions now say they are unpopulated.
	status := map[string]interface{}{
		"phase":       phase,
		"message":     message,
		"lastApplied": time.Now().UTC().Format(time.RFC3339),
	}
	if err := c.updateStatusWithRetry(ctx, policyGVR, u.GetNamespace(), u.GetName(), status); err != nil {
		slog.Warn("NRVQ-WHK-4040: policy status update failed", "policy", u.GetName(), "namespace", u.GetNamespace(), "error", err)
	}
}

func (c *Controller) reconcileDeletingPolicy(ctx context.Context, u *unstructured.Unstructured) {
	name := u.GetName()
	namespace := u.GetNamespace()
	delNs, delClass := policyStorageKey(u)
	deletePath := fmt.Sprintf("/api/v1/policies/%s/%s", delNs, delClass)
	if err := c.syncDelete(ctx, deletePath); err != nil {
		if c.forceFinalizeAfterTimeout(ctx, u, err) {
			return
		}
		slog.Error("NRVQ-WHK-4031: API delete failed", "policy", name, "error", err)
		return
	}
	annotations := u.GetAnnotations()
	if annotations == nil {
		annotations = map[string]string{}
	}
	annotations[deleteSyncedAnnotation] = "true"
	u.SetAnnotations(annotations)
	removeFinalizer(u, "norviq.io/policy-protection")
	if c.client == nil {
		return
	}
	if _, err := c.client.Resource(policyGVR).Namespace(namespace).Update(ctx, u, metav1.UpdateOptions{}); err != nil {
		slog.Error("NRVQ-WHK-4036: finalizer remove failed", "policy", name, "error", err)
		return
	}
	slog.Info("NRVQ-WHK-4027: policy deleted from API", "policy", name, "namespace", namespace)
}

func (c *Controller) forceFinalizeAfterTimeout(ctx context.Context, u *unstructured.Unstructured, deleteErr error) bool {
	if u.GetDeletionTimestamp() == nil {
		return false
	}
	if time.Since(u.GetDeletionTimestamp().Time) < finalizerMaxAge {
		return false
	}
	name := u.GetName()
	namespace := u.GetNamespace()
	slog.Warn(
		"NRVQ-WHK-4041: forcing finalizer removal after timeout",
		"policy", name,
		"namespace", namespace,
		"maxAge", finalizerMaxAge.String(),
		"deleteError", deleteErr,
	)
	annotations := u.GetAnnotations()
	if annotations == nil {
		annotations = map[string]string{}
	}
	annotations[deleteSyncedAnnotation] = "timeout-forced"
	u.SetAnnotations(annotations)
	removeFinalizer(u, "norviq.io/policy-protection")
	if c.client == nil {
		return true
	}
	if _, err := c.client.Resource(policyGVR).Namespace(namespace).Update(ctx, u, metav1.UpdateOptions{}); err != nil {
		slog.Error("NRVQ-WHK-4036: finalizer remove failed", "policy", name, "error", err)
		return false
	}
	return true
}

func (c *Controller) handlePolicyDelete(obj interface{}) {
	// Same as handlePolicy: the cached policy set is about to shrink, so class/config derived status
	// is stale.
	c.derivedStatusStale.Store(true)
	u, ok := obj.(*unstructured.Unstructured)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			slog.Error("NRVQ-WHK-4030: unexpected delete object type")
			return
		}
		u, ok = tombstone.Obj.(*unstructured.Unstructured)
		if !ok {
			return
		}
	}
	name := u.GetName()
	namespace := u.GetNamespace()
	if annotations := u.GetAnnotations(); annotations != nil && (annotations[deleteSyncedAnnotation] == "true" || annotations[deleteSyncedAnnotation] == "timeout-forced") {
		return
	}

	select {
	case c.syncSemaphore <- struct{}{}:
		c.wg.Add(1)
		go func() {
			defer c.wg.Done()
			defer func() { <-c.syncSemaphore }()
			delNs, delClass := policyStorageKey(u)
			deletePath := fmt.Sprintf("/api/v1/policies/%s/%s", delNs, delClass)
			if err := c.syncDelete(context.Background(), deletePath); err != nil {
				slog.Error("NRVQ-WHK-4031: API delete failed", "policy", name, "error", err)
				return
			}
			slog.Info("NRVQ-WHK-4027: policy deleted from API", "policy", name, "namespace", namespace)
		}()
	default:
		slog.Warn("NRVQ-WHK-4028: sync queue full, delete skipped", "policy", name)
	}
}

func (c *Controller) buildPolicySyncPayload(u *unstructured.Unstructured) (policySyncRequest, error) {
	var payload policySyncRequest
	name := u.GetName()
	namespace := u.GetNamespace()
	payload.Namespace = namespace
	payload.PolicyName = name
	payload.AgentClass = ""
	payload.SavedBy = fmt.Sprintf("crd/%s", name)

	mode, found, err := unstructured.NestedString(u.Object, "spec", "enforcementMode")
	if err != nil || !found || mode == "" {
		return payload, fmt.Errorf("missing required spec.enforcementMode")
	}
	payload.EnforcementMode = mode

	spec, _, _ := unstructured.NestedMap(u.Object, "spec")
	target, _ := spec["target"].(map[string]interface{})
	if target != nil {
		targetCopy := make(map[string]interface{}, len(target)+1)
		for key, value := range target {
			targetCopy[key] = value
		}
		if ns, ok := targetCopy["namespace"].(string); !ok || ns == "" {
			targetCopy["namespace"] = namespace
		}
		payload.Target = targetCopy
		if agentClass, ok := target["agentClass"].(string); ok && agentClass != "" {
			payload.AgentClass = agentClass
		}
	}

	// A whole-namespace cluster baseline (cluster-priority, target.namespace set, no agentClass or
	// workload) is the catch-all for its target namespace. Store it at <targetNs>:__baseline__ so the
	// engine's no-policy baseline fallback (evaluator._collect_candidates) resolves it; otherwise it
	// lands under the admin namespace + policy-name key and is unreachable, leaving unseeded agent
	// classes to deny-by-default once NRVQ_NO_POLICY_DECISION=deny is in effect.
	baselineNs, baselineClass, isNamespaceBaseline := namespaceBaselineKey(u)
	if isNamespaceBaseline {
		payload.Namespace = baselineNs
		payload.AgentClass = baselineClass
		slog.Info("NRVQ-WHK-4042: namespace baseline keyed to target namespace",
			"policy", name, "namespace", baselineNs, "agentClass", baselineClass)
	}

	rules, _, _ := unstructured.NestedStringSlice(u.Object, "spec", "rules")
	payload.Rules = rules
	priority, found, _ := unstructured.NestedInt64(u.Object, "spec", "priority")
	clusterPriority, foundClusterPriority, _ := unstructured.NestedInt64(u.Object, "spec", "clusterPriority")
	if foundClusterPriority {
		payload.Priority = clusterPriority
	} else if found {
		payload.Priority = priority
	} else {
		payload.Priority = 100
	}
	// The namespace baseline is a FALLBACK, not an override: it must apply only when no more-specific
	// policy matches. clusterPriority authorizes the cross-namespace target but must NOT become the
	// evaluation priority, or a permissive baseline (e.g. the strict preset, which allows anything but
	// destructive tool names) would outrank and weaken a stricter namespace/agent-class policy via the
	// engine's highest-priority-wins precedence. Store it below any real policy so specifics always win.
	if isNamespaceBaseline {
		payload.Priority = baselineFallbackPriority
	}
	if rego, found, _ := unstructured.NestedString(u.Object, "spec", "rego"); found && rego != "" {
		payload.RegoSource = rego
		return payload, nil
	}
	if preset, found, _ := unstructured.NestedString(u.Object, "spec", "preset"); found && preset != "" {
		data, err := os.ReadFile(fmt.Sprintf("%s/%s.rego", c.presetBasePath, preset))
		if err != nil {
			return payload, fmt.Errorf("NRVQ-WHK-4029: preset file not found: %w", err)
		}
		payload.RegoSource = string(data)
	}

	return payload, nil
}

// baselineFallbackPriority is the evaluation priority a whole-namespace baseline is stored under.
// It sits below any real policy (API/controller default is 100) so the baseline only decides when
// no more-specific policy matches, never overriding one via highest-priority-wins precedence.
const baselineFallbackPriority = 1

// namespaceBaselineKey reports the registry key (namespace, agentClass) for a whole-namespace
// cluster baseline CR: a cluster-priority policy whose target names a namespace but no agentClass
// or workload kind+name. Such a policy is that namespace's catch-all and must be stored at
// <targetNs>:__baseline__ to match the engine's baseline fallback (evaluator._collect_candidates).
// ok is false for every other policy shape, leaving its keying unchanged.
// policyStorageKey returns the (namespace, loader key) a CR is actually STORED under, mirroring
// resolve_policy_key in norviq/api/routers/policies.py.
//
// This exists because the delete path used metadata.name while the create path let the API resolve a
// key from spec.target — and once targeted policies were fixed to key on their target, deleting the CR
// issued DELETE /policies/<ns>/<metadata.name>, a row that does not exist. kubectl reported the CR
// gone and the policy KEPT ENFORCING, with no way to remove it short of the API directly. Consistently
// wrong was survivable; half-fixed was worse. Both sides must derive the key the same way, so they
// derive it here.
//
// Precedence must match the Python exactly: agentClass, then workload kind+name, then target namespace,
// then metadata.name as the untargeted fallback.
func policyStorageKey(u *unstructured.Unstructured) (ns, class string) {
	namespace := u.GetNamespace()
	if bns, bclass, ok := namespaceBaselineKey(u); ok {
		return bns, bclass
	}
	spec, _, _ := unstructured.NestedMap(u.Object, "spec")
	target, _ := spec["target"].(map[string]interface{})
	if target != nil {
		if agentClass, _ := target["agentClass"].(string); agentClass != "" {
			return namespace, agentClass
		}
		kind, _ := target["kind"].(string)
		wlName, _ := target["name"].(string)
		if kind != "" && wlName != "" {
			return namespace, fmt.Sprintf("%s:%s", strings.ToLower(strings.TrimSpace(kind)), strings.TrimSpace(wlName))
		}
		// The controller back-fills target.namespace with the CR's namespace when absent, so this
		// branch is reached by any target that names neither a class nor a workload.
		if targetNs, _ := target["namespace"].(string); targetNs != "" {
			return namespace, fmt.Sprintf("namespace:%s", strings.TrimSpace(targetNs))
		}
	}
	return namespace, u.GetName()
}

func namespaceBaselineKey(u *unstructured.Unstructured) (ns, class string, ok bool) {
	spec, _, _ := unstructured.NestedMap(u.Object, "spec")
	if spec == nil {
		return "", "", false
	}
	if _, has := spec["clusterPriority"]; !has {
		return "", "", false
	}
	target, _ := spec["target"].(map[string]interface{})
	if target == nil {
		return "", "", false
	}
	targetNs, _ := target["namespace"].(string)
	agentClass, _ := target["agentClass"].(string)
	kind, _ := target["kind"].(string)
	name, _ := target["name"].(string)
	if targetNs == "" || agentClass != "" || kind != "" || name != "" {
		return "", "", false
	}
	return targetNs, "__baseline__", true
}

func validateRego(rego string) error {
	// OPA v1's ast.ParseModule defaults to RegoV1 syntax (requires the `if`/`contains` keywords).
	// The engine's OPA server/check runs with --v0-compatible (norviq/engine/opa_client.py), and
	// every shipped/customer policy is written in v0 syntax without `import rego.v1`. Pin the parser
	// to RegoV0 here so validation stays consistent with what actually evaluates the policy.
	module, err := ast.ParseModuleWithOpts("policy.rego", rego, ast.ParserOptions{RegoVersion: ast.RegoV0})
	if err != nil {
		return fmt.Errorf("rego parse failed: %w", err)
	}
	cleaned := stripRegoComments(rego)
	if !hasEnforcementDecision(module) {
		return fmt.Errorf("policy must contain at least one block or escalate rule")
	}
	if hasOnlyConstantFalseEnforcement(module) {
		return fmt.Errorf("policy enforcement rule must be reachable")
	}
	requiredRules := map[string]bool{
		"decision": false,
		"rule_id":  false,
		"reason":   false,
	}
	for _, rule := range module.Rules {
		requiredRules[string(rule.Head.Name)] = true
	}
	for name, found := range requiredRules {
		if !found {
			return fmt.Errorf("policy must define %s", name)
		}
	}
	// Without a `default decision` a policy whose sole
	// `decision = "block" { ... }` rule never fires (e.g. an unreachable condition, or simply no
	// matching input) evaluates `decision` as undefined, which the engine's evaluator treats as
	// allow. Every legitimate/shipped policy already declares a default, so require it here too.
	if !hasDefaultDecision(module) {
		return fmt.Errorf("policy must define default decision")
	}
	if strings.Count(cleaned, "\n") > 500 {
		return fmt.Errorf("policy exceeds 500 line limit")
	}
	// MUST match validate_rego_source's cap of 25 (norviq/api/routers/policies.py). This was 5, and a
	// controller stricter than the API is a policy an operator can never apply through the CRD path at
	// all: the shipped `strict.rego` preset alone uses 23-26 regex ops. Divergence in EITHER direction
	// is a defect — laxer here means the CR clears admission and then dies at the API with a 422 that
	// markDeterministicFailure records once and never retries, so it cannot self-heal.
	reCount := countRegexBuiltins(module)
	if reCount > 25 {
		return fmt.Errorf("too many regex operations (%d) - max 25 per policy", reCount)
	}
	// The API rejects network/env-escaping builtins and cross-package `data.` reads; the controller did
	// not check either, so those policies passed admission and then failed terminally at the API.
	if err := rejectForbiddenRego(cleaned); err != nil {
		return err
	}
	return nil
}

// forbiddenRegoTokens mirrors _FORBIDDEN_REGO_TOKENS in norviq/api/routers/policies.py. Keep the two
// lists in step: a token here that is missing there (or vice versa) recreates the split-brain this
// function exists to close.
var forbiddenRegoTokens = []*regexp.Regexp{
	regexp.MustCompile(`\bhttp\.send\b`),
	regexp.MustCompile(`\bopa\.runtime\b`),
	regexp.MustCompile(`\bnet\.[a-z_]+\b`),
	regexp.MustCompile(`\bio\.[a-z_]+\b`),
	regexp.MustCompile(`\brego\.parse_module\b`),
	regexp.MustCompile(`\btrace\s*\(`), // only the call form; a rule named `trace` is legal rego
	regexp.MustCompile(`\bdata\s*\.\s*norviq\s*\.\s*managed\b`),
}

var (
	regoStringLiteral = regexp.MustCompile(`"(?:\\.|[^"\\])*"`)
	regoPackageDecl   = regexp.MustCompile(`(?m)^\s*package\s+([A-Za-z0-9_.]+)`)
	regoDataRef       = regexp.MustCompile(`\bdata\.([A-Za-z0-9_.]*)`)
)

// rejectForbiddenRego is the Go half of _reject_forbidden_rego. `cleaned` is comment-stripped; string
// literals are removed here so a policy's own `reason` text may mention these words freely — only real
// rego references are rejected.
func rejectForbiddenRego(cleaned string) error {
	dequoted := regoStringLiteral.ReplaceAllString(cleaned, `""`)
	for _, pattern := range forbiddenRegoTokens {
		if pattern.MatchString(dequoted) {
			return fmt.Errorf("policy references a forbidden builtin/cross-package data (network/env access is not permitted)")
		}
	}
	// A `data.` read outside the module's OWN package is the cross-tenant escape: OPA's shared managed
	// server namespaces every pushed module under data.norviq.managed.<key>, so one namespace can read
	// another's compiled policy.
	ownPkg := ""
	if m := regoPackageDecl.FindStringSubmatch(dequoted); m != nil {
		ownPkg = m[1]
	}
	for _, m := range regoDataRef.FindAllStringSubmatch(dequoted, -1) {
		ref := m[1]
		if ownPkg != "" && (ref == ownPkg || strings.HasPrefix(ref, ownPkg+".")) {
			continue
		}
		return fmt.Errorf("policy references a forbidden builtin/cross-package data (network/env access is not permitted)")
	}
	return nil
}

func validateTarget(namespace, adminPolicyNamespace string, target map[string]interface{}, hasClusterPriority bool) error {
	if adminPolicyNamespace == "" {
		adminPolicyNamespace = "norviq"
	}
	if len(target) == 0 {
		return fmt.Errorf("target must specify agentClass, namespace, or workload kind+name")
	}
	// Checked FIRST, before any branch that can return nil. The evaluator resolves exactly one workload
	// key shape, `deployment:<name>` (_collect_candidates), but the CRD used to offer StatefulSet,
	// DaemonSet and ReplicaSet: all three synced clean, went phase=Active and decided nothing, forever,
	// with every surface reporting them healthy. Refusing with a reason beats admitting a silent no-op.
	if kind, _ := target["kind"].(string); strings.TrimSpace(kind) != "" {
		if !strings.EqualFold(strings.TrimSpace(kind), "Deployment") {
			return fmt.Errorf("workload target kind %q is not enforceable: the engine resolves only "+
				"Deployment workload policies (loader key deployment:<name>)", kind)
		}
	}
	targetNs, ok := target["namespace"].(string)
	if namespace == adminPolicyNamespace && targetNs != "" && targetNs != namespace {
		if hasClusterPriority {
			return nil
		}
		if ac, ok := target["agentClass"].(string); ok && ac != "" {
			return nil
		}
		kind, _ := target["kind"].(string)
		name, _ := target["name"].(string)
		if kind != "" && name != "" {
			return nil
		}
		return fmt.Errorf("cross-namespace target from admin namespace requires clusterPriority or scoped workload/agentClass target")
	}
	if ok && targetNs != "" && targetNs != namespace {
		return fmt.Errorf("cross-namespace targeting not allowed: CR in %s targeting %s", namespace, targetNs)
	}
	if ac, ok := target["agentClass"].(string); ok && ac != "" {
		return nil
	}
	if targetNs != "" {
		return nil
	}
	kind, _ := target["kind"].(string)
	name, _ := target["name"].(string)
	if kind != "" && name != "" {
		return nil
	}
	return fmt.Errorf("target must include agentClass, namespace, or workload kind+name")
}

// hasDefaultDecision reports whether the module declares `default decision = ...`. Required so that a
// `decision` rule which never fires (unreachable condition, or simply no matching input) has an
// explicit fallback value instead of evaluating to undefined, which the engine's evaluator otherwise
// treats as allow.
func hasDefaultDecision(module *ast.Module) bool {
	for _, rule := range module.Rules {
		if rule.Default && string(rule.Head.Name) == "decision" {
			return true
		}
	}
	return false
}

func hasEnforcementDecision(module *ast.Module) bool {
	for _, rule := range module.Rules {
		if string(rule.Head.Name) != "decision" || rule.Head.Value == nil {
			continue
		}
		if value, ok := rule.Head.Value.Value.(ast.String); ok {
			text := string(value)
			if text == "block" || text == "escalate" {
				return true
			}
		}
	}
	return false
}

// hasOnlyConstantFalseEnforcement blocks dead-enforcement patterns where every
// enforcement rule body is provably false at parse time (for example `{ false }`
// or constant-false equality checks like `{ 1 == 2 }`).
// More complex data-dependent unsatisfiable predicates still require baseline
// cluster-priority policies for defense in depth.
func hasOnlyConstantFalseEnforcement(module *ast.Module) bool {
	enforcementRules := 0
	falseRules := 0
	for _, rule := range module.Rules {
		if string(rule.Head.Name) != "decision" || rule.Head.Value == nil {
			continue
		}
		value, ok := rule.Head.Value.Value.(ast.String)
		if !ok {
			continue
		}
		text := string(value)
		if text != "block" && text != "escalate" {
			continue
		}
		enforcementRules++
		if len(rule.Body) == 1 {
			if isProvablyFalseExpr(rule.Body[0]) {
				falseRules++
			}
		}
	}
	return enforcementRules > 0 && enforcementRules == falseRules
}

func isProvablyFalseExpr(expr *ast.Expr) bool {
	if strings.TrimSpace(expr.String()) == "false" {
		return true
	}
	if !expr.IsCall() {
		return false
	}
	op := expr.Operator()
	if op == nil || op.String() != "equal" {
		return false
	}
	operands := expr.Operands()
	if len(operands) != 2 {
		return false
	}
	left := operands[0].Value
	right := operands[1].Value
	switch l := left.(type) {
	case ast.Number:
		r, ok := right.(ast.Number)
		return ok && l.Compare(r) != 0
	case ast.String:
		r, ok := right.(ast.String)
		return ok && string(l) != string(r)
	case ast.Boolean:
		r, ok := right.(ast.Boolean)
		return ok && bool(l) != bool(r)
	default:
		return false
	}
}

func (c *Controller) reconcileDeletingPolicyAsync(ctx context.Context, u *unstructured.Unstructured) {
	select {
	case c.syncSemaphore <- struct{}{}:
		c.wg.Add(1)
		go func(obj *unstructured.Unstructured) {
			defer c.wg.Done()
			defer func() { <-c.syncSemaphore }()
			c.reconcileDeletingPolicy(ctx, obj.DeepCopy())
		}(u)
	default:
		slog.Warn("NRVQ-WHK-4028: sync queue full, delete reconcile skipped", "policy", u.GetName())
	}
}

func countRegexBuiltins(module *ast.Module) int {
	count := 0
	for _, rule := range module.Rules {
		for _, expr := range rule.Body {
			if !expr.IsCall() {
				continue
			}
			op := expr.Operator()
			if op == nil {
				continue
			}
			ref := op.String()
			if ref == "regex.match" || strings.HasPrefix(ref, "regex.") || ref == "re_match" {
				count++
			}
		}
	}
	return count
}

func (c *Controller) updateStatusWithRetry(
	ctx context.Context,
	gvr schema.GroupVersionResource,
	namespace, name string,
	status map[string]interface{},
) error {
	const attempts = 3
	for attempt := 1; attempt <= attempts; attempt++ {
		var resource dynamic.ResourceInterface
		if namespace != "" {
			resource = c.client.Resource(gvr).Namespace(namespace)
		} else {
			resource = c.client.Resource(gvr)
		}
		current, err := resource.Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return err
		}
		if err := unstructured.SetNestedMap(current.Object, status, "status"); err != nil {
			return err
		}
		_, err = resource.UpdateStatus(ctx, current, metav1.UpdateOptions{})
		if err == nil {
			return nil
		}
		if apierrors.IsConflict(err) && attempt < attempts {
			time.Sleep(time.Duration(attempt*50) * time.Millisecond)
			continue
		}
		return err
	}
	return fmt.Errorf("status update retries exhausted for %s/%s", gvr.Resource, name)
}

func (c *Controller) addFinalizerWithRetry(ctx context.Context, namespace, name string) error {
	const attempts = 3
	for attempt := 1; attempt <= attempts; attempt++ {
		current, err := c.client.Resource(policyGVR).Namespace(namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return err
		}
		if containsFinalizer(current, "norviq.io/policy-protection") {
			return nil
		}
		addFinalizer(current, "norviq.io/policy-protection")
		_, err = c.client.Resource(policyGVR).Namespace(namespace).Update(ctx, current, metav1.UpdateOptions{})
		if err == nil {
			return nil
		}
		if !apierrors.IsConflict(err) {
			return err
		}
		slog.Warn("NRVQ-WHK-4035: finalizer conflict, retrying", "policy", name, "attempt", attempt)
		time.Sleep(time.Duration(attempt*50) * time.Millisecond)
	}
	return fmt.Errorf("finalizer add failed after 3 retries")
}

func stripRegoComments(rego string) string {
	lines := strings.Split(rego, "\n")
	cleaned := make([]string, 0, len(lines))
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		cleaned = append(cleaned, line)
	}
	return strings.Join(cleaned, "\n")
}

func validateClusterPriority(namespace string, spec map[string]interface{}, adminPolicyNamespace string) error {
	if adminPolicyNamespace == "" {
		adminPolicyNamespace = "norviq"
	}
	raw, found := spec["clusterPriority"]
	if !found {
		return nil
	}
	if namespace != adminPolicyNamespace {
		return fmt.Errorf("clusterPriority is only allowed in %s namespace", adminPolicyNamespace)
	}
	switch value := raw.(type) {
	case int:
		if value < 500 || value > 1000 {
			return fmt.Errorf("clusterPriority must be between 500 and 1000")
		}
	case int32:
		if value < 500 || value > 1000 {
			return fmt.Errorf("clusterPriority must be between 500 and 1000")
		}
	case int64:
		if value < 500 || value > 1000 {
			return fmt.Errorf("clusterPriority must be between 500 and 1000")
		}
	case float64:
		if value < 500 || value > 1000 {
			return fmt.Errorf("clusterPriority must be between 500 and 1000")
		}
	default:
		return fmt.Errorf("clusterPriority must be numeric")
	}
	return nil
}

func containsFinalizer(u *unstructured.Unstructured, finalizer string) bool {
	for _, f := range u.GetFinalizers() {
		if f == finalizer {
			return true
		}
	}
	return false
}

func addFinalizer(u *unstructured.Unstructured, finalizer string) {
	u.SetFinalizers(append(u.GetFinalizers(), finalizer))
}

func removeFinalizer(u *unstructured.Unstructured, finalizer string) {
	current := u.GetFinalizers()
	filtered := make([]string, 0, len(current))
	for _, f := range current {
		if f != finalizer {
			filtered = append(filtered, f)
		}
	}
	u.SetFinalizers(filtered)
}

func shouldProcessUpdate(oldObj, newObj interface{}) bool {
	oldU, okOld := oldObj.(*unstructured.Unstructured)
	newU, okNew := newObj.(*unstructured.Unstructured)
	if !okOld || !okNew {
		return true
	}
	if oldU.GetDeletionTimestamp() != nil || newU.GetDeletionTimestamp() != nil {
		return true
	}
	return oldU.GetGeneration() != newU.GetGeneration()
}

func isAllowedSidecarImage(image string) bool {
	return allowedSidecarImagePattern.MatchString(image)
}

// isMutableTag reports whether the image reference uses a mutable tag (":latest" or "...-latest")
// rather than an immutable digest/-sha. Injected sidecars must be pinned, so mutable overrides are
// refused (the deployed -sha image is kept instead).
func isMutableTag(image string) bool {
	idx := strings.LastIndex(image, ":")
	if idx < 0 {
		return true // no tag at all -> would default to :latest
	}
	tag := image[idx+1:]
	return tag == "latest" || strings.HasSuffix(tag, "-latest")
}

func validateImage(image string) bool {
	return isAllowedSidecarImage(image)
}

func (c *Controller) listCachedPolicies() []*unstructured.Unstructured {
	if c.policyStore == nil {
		return nil
	}
	items := c.policyStore.List()
	policies := make([]*unstructured.Unstructured, 0, len(items))
	for _, item := range items {
		u, ok := item.(*unstructured.Unstructured)
		if !ok {
			continue
		}
		policies = append(policies, u)
	}
	return policies
}

// bearerToken returns a short-lived service-role HS256 JWT signed with the API secret, minted+cached
// here so the controller authenticates to the API (which validates JWTs, not the raw secret). Returns
// "" when no secret is configured (the request then goes unauthenticated, as before).
func (c *Controller) bearerToken() string {
	// Prefer the OIDC client-credentials access token (the TokenSource caches + auto-refreshes).
	// Fall back to the HS256 service JWT on any error so policy sync never breaks mid-migration.
	if c.oidcTokenSource != nil {
		if tok, err := c.oidcTokenSource.Token(); err == nil && tok.AccessToken != "" {
			return tok.AccessToken
		} else {
			slog.Warn("NRVQ-WHK-4043: OIDC client-credentials token failed; falling back to HS256", "error", err)
		}
	}
	if c.apiSecret == "" {
		return ""
	}
	c.tokenMu.Lock()
	defer c.tokenMu.Unlock()
	if c.cachedJWT != "" && time.Now().Before(c.cachedJWTExp.Add(-60*time.Second)) {
		return c.cachedJWT
	}
	now := time.Now()
	exp := now.Add(time.Hour)
	claims := map[string]interface{}{
		"sub":       "norviq-webhook",
		"role":      "service",
		"namespace": c.adminPolicyNamespace,
		"iat":       now.Unix(),
		"exp":       exp.Unix(),
	}
	tok, err := signHS256JWT(c.apiSecret, claims)
	if err != nil {
		slog.Error("NRVQ-WHK-4027: service token mint failed", "error", err)
		return ""
	}
	c.cachedJWT = tok
	c.cachedJWTExp = exp
	slog.Info("NRVQ-WHK-4026: service token minted", "sub", "norviq-webhook", "role", "service")
	return tok
}

// signHS256JWT mints a compact HS256 JWT with stdlib only (no external dependency).
func signHS256JWT(secret string, claims map[string]interface{}) (string, error) {
	b64 := func(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
	header, err := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT"})
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signingInput := b64(header) + "." + b64(payload)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signingInput))
	return signingInput + "." + b64(mac.Sum(nil)), nil
}

func (c *Controller) syncPolicy(ctx context.Context, payload policySyncRequest) error {
	if c.httpClient == nil {
		c.httpClient = &http.Client{Timeout: 5 * time.Second}
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.apiURL+"/api/v1/policies", bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if tok := c.bearerToken(); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("unexpected response status %d", resp.StatusCode)
	}

	return nil
}

func (c *Controller) syncDelete(ctx context.Context, path string) error {
	if c.httpClient == nil {
		c.httpClient = &http.Client{Timeout: 5 * time.Second}
	}
	// Uses HTTP DELETE to sync CRD deletions to API.
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.apiURL+path, nil)
	if err != nil {
		return err
	}
	if tok := c.bearerToken(); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("unexpected response status %d", resp.StatusCode)
	}
	return nil
}
