// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

// Delivering the sidecar's credentials through a Secret instead of literal pod env.
//
// WHY (C2-019). The injector used to emit NRVQ_API_TOKEN, NRVQ_CLIENT_CERT_PEM and
// NRVQ_CLIENT_KEY_PEM as `value:` entries in the pod spec. Kubernetes deliberately excludes Secrets
// from the built-in `view` ClusterRole — verified on a live cluster, `view` grants `get pods` and does
// NOT grant `get secrets` — and that exclusion is the whole reason `view` is considered safe to hand
// an auditor, an SRE, a dashboard or a CI service account. A credential in the pod spec sits on the
// other side of that line: `kubectl get pod -o yaml` returned a working 30-day workload JWT, including
// the `workload` claim the API refuses to accept unbound from a request body. Pod specs also live in
// etcd (unencrypted unless the cluster enables encryption-at-rest), in `kubectl describe`, and in any
// GitOps diff or controller that captures pod objects.
//
// The sidecar is unchanged: `valueFrom.secretKeyRef` populates the same environment variables it
// already reads.
//
// THREE constraints shaped this, and each one is load-bearing:
//
//  1. FAIL SOFT. This webhook runs with `failurePolicy: Fail`, so it gates ALL pod creation in
//     injection-labelled namespaces. A Secret write is an API round-trip on that path, and turning a
//     transient API hiccup into a cluster-wide "no pods may be created" outage would be a far worse
//     bug than the one being fixed. On any failure the caller keeps the literal-env behaviour and logs
//     loudly. `cfg.SidecarSecretRequired` flips that to fail-closed for operators who would rather
//     stop scheduling than ship a credential in a pod spec — off by default, matching this product's
//     stated posture that a Norviq problem must not take the customer's workloads down.
//
//  2. DRY RUN MUST NOT WRITE. `req.DryRun` previously only logged, which was harmless while injection
//     had no side effects. It does now. A dry-run still gets the SAME patch shape (secretKeyRef), so
//     what it previews is what a real admission would apply — it simply does not create the object,
//     exactly as the pod it is previewing is not created.
//
//  3. ROTATION MUST SURVIVE. Token rotation in this product IS pod replacement, and that was verified
//     live (a replacement pod gets a new token with a later `iat` and an unchanged identity). So the
//     Secret is REWRITTEN on every admission rather than created-if-absent: a new pod still gets
//     freshly minted material. Overwriting is safe for pods already running, because `secretKeyRef`
//     env is resolved by the kubelet at container start and the running container holds its own copy.
//
// The Secret is keyed per (namespace, workload, agent_class) rather than per pod: a pod's name is not
// knowable at admission time for anything created by a ReplicaSet (only `generateName` is set), and
// every pod of one Deployment is entitled to exactly the same claims anyway.

// secretGVR is the core v1 Secrets resource, reached through the dynamic client the webhook already
// builds for its CRD informers rather than adding a second typed clientset dependency.
var secretGVR = schema.GroupVersionResource{Group: "", Version: "v1", Resource: "secrets"}

// SecretWriter upserts the sidecar credential Secret and reports the name it wrote.
//
// An interface so the injector can be tested without an API server, and so a nil writer cleanly means
// "not configured — keep the literal-env behaviour".
type SecretWriter interface {
	Upsert(ctx context.Context, namespace, name string, data map[string]string) error
}

type dynamicSecretWriter struct {
	client dynamic.Interface
}

// NewSecretWriter returns a writer backed by the dynamic client, or nil if the client is nil.
func NewSecretWriter(client dynamic.Interface) SecretWriter {
	if client == nil {
		return nil
	}
	return &dynamicSecretWriter{client: client}
}

func (w *dynamicSecretWriter) Upsert(ctx context.Context, namespace, name string, data map[string]string) error {
	sec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "norviq-sidecar-injector",
				"norviq.io/component":          "sidecar-credentials",
			},
			Annotations: map[string]string{
				// Rotation evidence for an operator reading the object: this is rewritten on every
				// admission, so a stale timestamp means injection stopped happening.
				"norviq.io/minted-at": time.Now().UTC().Format(time.RFC3339),
			},
		},
		Type:       corev1.SecretTypeOpaque,
		StringData: data,
	}
	obj, err := runtime.DefaultUnstructuredConverter.ToUnstructured(sec)
	if err != nil {
		return fmt.Errorf("convert secret: %w", err)
	}
	// Kind/APIVersion are dropped by the converter for typed objects built this way; the dynamic
	// client requires them on the wire.
	u := &unstructured.Unstructured{Object: obj}
	u.SetAPIVersion("v1")
	u.SetKind("Secret")

	api := w.client.Resource(secretGVR).Namespace(namespace)
	_, err = api.Create(ctx, u, metav1.CreateOptions{})
	if err == nil {
		return nil
	}
	if !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("create secret: %w", err)
	}
	// Rewrite rather than leave stale material in place — see the rotation note above.
	if _, err = api.Update(ctx, u, metav1.UpdateOptions{}); err != nil {
		return fmt.Errorf("update secret: %w", err)
	}
	return nil
}

// sidecarSecretName is a deterministic, DNS-1123-safe name for the (namespace, workload, agent_class)
// triple. Deterministic because admission is not the only writer over time — the same Deployment
// admitting a replacement pod must land on the SAME object, or every rollout would leak a new Secret.
//
// A hash suffix is appended whenever the readable part had to be altered or would overflow, so two
// distinct workloads whose names sanitise to the same string cannot collide onto one Secret and hand
// each other's claims out.
func sidecarSecretName(workload, agentClass string) string {
	raw := workload
	if raw == "" {
		raw = agentClass
	}
	if raw == "" {
		raw = "default"
	}
	sanitized := nonDNS1123.ReplaceAllString(strings.ToLower(raw), "-")
	sanitized = strings.Trim(sanitized, "-")

	const prefix = "norviq-sidecar-"
	const maxLen = 63 // Secret names are DNS-1123 labels in practice; stay inside the strictest bound.
	const hashLen = 8
	needsHash := sanitized != strings.ToLower(raw) || sanitized == ""
	budget := maxLen - len(prefix)
	if needsHash || len(sanitized) > budget {
		sum := sha256.Sum256([]byte(workload + "\x00" + agentClass))
		suffix := hex.EncodeToString(sum[:])[:hashLen]
		keep := budget - hashLen - 1
		if keep < 1 {
			keep = 1
		}
		if len(sanitized) > keep {
			sanitized = sanitized[:keep]
		}
		sanitized = strings.Trim(sanitized, "-")
		if sanitized == "" {
			sanitized = "wl"
		}
		return prefix + sanitized + "-" + suffix
	}
	return prefix + sanitized
}

var nonDNS1123 = regexp.MustCompile(`[^a-z0-9-]+`)

// secretRefEnv returns the pod-spec env entries that read `keys` from `secretName`, replacing the
// literal `value:` entries that used to carry the same data.
func secretRefEnv(secretName string, keys []string) []map[string]interface{} {
	out := make([]map[string]interface{}, 0, len(keys))
	for _, k := range keys {
		out = append(out, map[string]interface{}{
			"name": k,
			"valueFrom": map[string]interface{}{
				"secretKeyRef": map[string]interface{}{
					"name": secretName,
					"key":  k,
					// The sidecar cannot start without these, so a missing key must surface as a pod
					// event an operator can see rather than as a silently empty credential that fails
					// later as an authentication error.
					"optional": false,
				},
			},
		})
	}
	return out
}

// logSecretFallback records that a credential is being shipped in the pod spec after all. Kept as one
// function so the message and code are identical on every path an operator might grep for.
func logSecretFallback(namespace, name string, err error) {
	slog.Error("NRVQ-WHK-4049: sidecar credential Secret write failed; FALLING BACK to literal pod env."+
		" The token and client key will be readable by anyone with `get pod` in this namespace"+
		" (the built-in `view` role grants that and does NOT grant `get secrets`)."+
		" Set NRVQ_SIDECAR_SECRET_REQUIRED=true to refuse admission instead.",
		"namespace", namespace, "secret", name, "error", err)
}

// secretBackedEnvKeys are the injected env vars that carry a CREDENTIAL and must not appear as
// literal values in a pod spec.
//
// NRVQ_API_CA_PEM is deliberately absent: a CA certificate is public by construction — it is the
// thing you hand out so peers can verify you — and moving it would cost a Secret key for no gain.
// The CLIENT cert is included: it is not itself secret, but it is the public half of a key pair whose
// private half is, and keeping the pair together is what makes the Secret self-describing.
var secretBackedEnvKeys = map[string]bool{
	"NRVQ_API_TOKEN":       true,
	"NRVQ_CLIENT_CERT_PEM": true,
	"NRVQ_CLIENT_KEY_PEM":  true,
}

// credentialEnv moves every credential-bearing entry out of the pod spec and into a Secret, returning
// the env list with those entries replaced by `valueFrom.secretKeyRef`.
//
// Written as a post-processing pass over the env `sidecarEnv` already built, rather than threaded
// through that function, so the minting logic has exactly one home and this transform can be tested
// on its own. Entries that are already a `valueFrom` are left alone.
//
// Returns the input UNCHANGED on every failure path — no writer configured, nothing to move, or the
// API rejected the write — because this webhook gates all pod creation under `failurePolicy: Fail`
// and refusing to schedule is a worse outcome than the exposure being closed. `SidecarSecretRequired`
// inverts that for operators who disagree; it is honoured by the caller, which can fail admission,
// because only the caller can produce an AdmissionResponse.
func (inj *Injector) credentialEnv(
	namespace, workload, agentClass string,
	env []map[string]interface{},
	opts PatchOptions,
) []map[string]interface{} {
	if inj.secrets == nil {
		return env
	}
	data := map[string]string{}
	for _, e := range env {
		name, _ := e["name"].(string)
		if !secretBackedEnvKeys[name] {
			continue
		}
		v, ok := e["value"].(string)
		if !ok || v == "" {
			continue // already a valueFrom, or never minted (no API secret) — nothing to move
		}
		data[name] = v
	}
	if len(data) == 0 {
		return env
	}

	name := sidecarSecretName(workload, agentClass)
	if !opts.DryRun {
		ctx, cancel := context.WithTimeout(context.Background(), secretWriteTimeout)
		defer cancel()
		if err := inj.secrets.Upsert(ctx, namespace, name, data); err != nil {
			logSecretFallback(namespace, name, err)
			inj.lastSecretError = err
			return env
		}
	}
	inj.lastSecretError = nil

	keys := make([]string, 0, len(data))
	for _, e := range env { // preserve the original ordering rather than map order
		n, _ := e["name"].(string)
		if _, moved := data[n]; moved {
			keys = append(keys, n)
		}
	}
	refs := secretRefEnv(name, keys)
	out := make([]map[string]interface{}, 0, len(env))
	for _, e := range env {
		n, _ := e["name"].(string)
		if _, moved := data[n]; moved {
			continue
		}
		out = append(out, e)
	}
	return append(out, refs...)
}

// secretWriteTimeout bounds the API round-trip this adds to the admission path. Short on purpose: a
// webhook with `failurePolicy: Fail` holds up pod creation for as long as it takes to answer, so a
// slow API server must degrade to the literal-env fallback quickly rather than stall scheduling.
const secretWriteTimeout = 3 * time.Second
