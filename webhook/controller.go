// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/open-policy-agent/opa/ast"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
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

var finalizerMaxAge = 15 * time.Minute
var allowedSidecarImagePattern = regexp.MustCompile(`^(norviq/norviq-engine|docker\.io/norviq/norviq-engine):[a-zA-Z0-9._-]+$`)

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
	// B4: when configured, the controller authenticates to the API with an OIDC client-credentials
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
	classQueue           chan *unstructured.Unstructured
	configQueue          chan *unstructured.Unstructured
	wg                   sync.WaitGroup
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
	defaultSidecar := envStr("NRVQ_SIDECAR_IMAGE", "norviq/norviq-engine:engine-latest")
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
	return &Controller{
		client:          client,
		apiURL:          apiURL,
		apiSecret:       apiSecret,
		oidcTokenSource: oidcTS,
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
		},
		syncSemaphore:        make(chan struct{}, 10),
		presetBasePath:       "/app/presets",
		adminPolicyNamespace: envStr("NRVQ_ADMIN_POLICY_NAMESPACE", "norviq"),
		runtime:              runtime,
		defaultSidecarImage:  defaultSidecar,
		classQueue:           make(chan *unstructured.Unstructured, 64),
		configQueue:          make(chan *unstructured.Unstructured, 64),
	}
}

func (c *Controller) Start(ctx context.Context) error {
	factory := dynamicinformer.NewDynamicSharedInformerFactory(c.client, 30*time.Second)
	policyInformer := factory.ForResource(policyGVR).Informer()
	classInformer := factory.ForResource(classGVR).Informer()
	configInformer := factory.ForResource(configGVR).Informer()
	c.policyStore = policyInformer.GetStore()

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
	c.wg.Add(2)
	go c.classWorker(ctx)
	go c.configWorker(ctx)

	<-ctx.Done()
	c.wg.Wait()
	return nil
}

func (c *Controller) handlePolicy(obj interface{}, action string) {
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
		return
	}
	spec, _, _ := unstructured.NestedMap(u.Object, "spec")
	if err := validateClusterPriority(namespace, spec, c.adminPolicyNamespace); err != nil {
		slog.Warn("NRVQ-WHK-4037: invalid cluster priority rejected", "policy", name, "error", err)
		return
	}
	_, hasClusterPriority := spec["clusterPriority"]
	if err := validateTarget(namespace, c.adminPolicyNamespace, body.Target, hasClusterPriority); err != nil {
		slog.Warn("NRVQ-WHK-4034: cross-namespace policy rejected", "policy", name, "error", err)
		return
	}
	if rego, found, _ := unstructured.NestedString(u.Object, "spec", "rego"); found && rego != "" {
		if err := validateRego(rego); err != nil {
			slog.Warn("NRVQ-WHK-4032: invalid rego rejected", "policy", name, "error", err)
			c.updatePolicyStatus(context.Background(), u, "Error", err.Error())
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
				c.updatePolicyStatus(context.Background(), u, "Error", err.Error())
				return
			}
			c.updatePolicyStatus(context.Background(), u, "Active", "policy synced")
			slog.Info(
				"NRVQ-WHK-4026: Policy synced to API successfully",
				"policy", name,
				"namespace", namespace,
				"action", action,
			)
		}()
	default:
		slog.Warn("NRVQ-WHK-4028: sync queue full, skipping", "policy", name)
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
	status := map[string]interface{}{
		"agentCount":        int64(0),
		"averageTrustScore": float64(0),
		"policyCount":       policyCount,
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
	status := map[string]interface{}{
		"appliedAt":        time.Now().UTC().Format(time.RFC3339),
		"activeNamespaces": int64(len(namespaceSet)),
		"totalPolicies":    int64(len(policies)),
		"totalAgents":      int64(0),
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
		c.updatePolicyStatus(context.Background(), policy, "Error", "referenced class deleted")
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
	status := map[string]interface{}{
		"phase":             phase,
		"message":           message,
		"lastApplied":       time.Now().UTC().Format(time.RFC3339),
		"matchingWorkloads": int64(0),
		"blockCount24h":     int64(0),
	}
	if err := c.updateStatusWithRetry(ctx, policyGVR, u.GetNamespace(), u.GetName(), status); err != nil {
		slog.Warn("NRVQ-WHK-4040: policy status update failed", "policy", u.GetName(), "namespace", u.GetNamespace(), "error", err)
	}
}

func (c *Controller) reconcileDeletingPolicy(ctx context.Context, u *unstructured.Unstructured) {
	name := u.GetName()
	namespace := u.GetNamespace()
	delNs, delClass := namespace, name
	if bns, bclass, ok := namespaceBaselineKey(u); ok {
		delNs, delClass = bns, bclass
	}
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
			delNs, delClass := namespace, name
			if bns, bclass, ok := namespaceBaselineKey(u); ok {
				delNs, delClass = bns, bclass
			}
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
	module, err := ast.ParseModule("policy.rego", rego)
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
	// FIX 5 (enforcement-correctness parity): without a `default decision` a policy whose sole
	// `decision = "block" { ... }` rule never fires (e.g. an unreachable condition, or simply no
	// matching input) evaluates `decision` as undefined, which the engine's evaluator treats as
	// allow. Every legitimate/shipped policy already declares a default, so require it here too.
	if !hasDefaultDecision(module) {
		return fmt.Errorf("policy must define default decision")
	}
	if strings.Count(cleaned, "\n") > 500 {
		return fmt.Errorf("policy exceeds 500 line limit")
	}
	reCount := countRegexBuiltins(module)
	if reCount > 5 {
		return fmt.Errorf("too many regex operations (%d) - max 5 per policy", reCount)
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
	// B4: prefer the OIDC client-credentials access token (the TokenSource caches + auto-refreshes).
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
