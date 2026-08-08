// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// injector.go builds the JSON patch that injects the enforcement sidecar into a pod:
// the shared socket volume, the sidecar container, per-container socket mounts + env,
// and the optional SPIFFE and internal-mTLS material.
package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
)

const workloadLabel = "norviq.io/workload"

type Injector struct {
	cfg             Config
	sidecarTemplate map[string]interface{}
	sharedVolume    map[string]interface{}
}

const socketMountPath = "/var/run/norviq"
const socketFilePath = "/var/run/norviq/norviq-proxy.sock"
const spiffeMountPath = "/spiffe-workload-api"

// Sidecar-private scratch space. readOnlyRootFilesystem leaves the sidecar with no writable path, but
// the internal-mTLS client must briefly materialize its cert/key as files. Mounted into the sidecar
// ONLY — never the app container — so the workload can never read the key.
const tmpVolumeName = "norviq-tmp"
const tmpMountPath = "/tmp"

type patchOp struct {
	Op    string      `json:"op"`
	Path  string      `json:"path"`
	Value interface{} `json:"value,omitempty"`
}

type containerPatchState struct {
	HasList bool
	Needs   bool
}

func NewInjector(cfg Config) *Injector {
	if cfg.Runtime == nil {
		runtime := &RuntimeConfig{}
		runtime.SetSidecarImage(cfg.SidecarImage)
		cfg.Runtime = runtime
	}
	return &Injector{
		cfg:             cfg,
		sidecarTemplate: newSidecarTemplate(cfg),
		sharedVolume:    volumeTemplate(),
	}
}

func (inj *Injector) CreatePatch(pod *corev1.Pod, agentClass string, namespace string) ([]byte, error) {
	image := inj.cfg.Runtime.SidecarImage(inj.cfg.SidecarImage)
	if !inj.validateImage(image) {
		slog.Error("NRVQ-WHK-4033: blocked unauthorized sidecar image", "image", image)
		return nil, fmt.Errorf("unauthorized sidecar image")
	}
	patches := make([]patchOp, 0, 8)
	patches = append(patches, patchOp{Op: "add", Path: "/spec/containers/-", Value: inj.buildSidecar(agentClass, namespace, workloadFromPod(pod))})
	patches = append(patches, volumePatch(len(pod.Spec.Volumes) > 0, inj.sharedVolume))
	// The sidecar runs with readOnlyRootFilesystem, but the internal-mTLS path must materialize the
	// client cert/key on disk (stdlib load_cert_chain reads files only — see remote_evaluator.py).
	// Without a writable temp dir the sidecar dies at start with "No usable temporary directory",
	// so every injected pod crash-loops. This tmpfs is mounted into the SIDECAR ONLY (never the app
	// container) so the private key is never readable by the workload, and never lands on real disk.
	// After the first volume add, /spec/volumes always exists -> append.
	patches = append(patches, volumePatch(true, tmpVolumeTemplate()))
	if inj.cfg.SpiffeInject {
		// After the first volume add, /spec/volumes always exists -> append the SPIFFE CSI volume.
		patches = append(patches, volumePatch(true, spiffeVolumeTemplate()))
	}
	// Wire the app containers AND the init containers to the enforcement socket: an agent workload placed
	// in an initContainer would otherwise run before the sidecar with no socket mount/env — unpoliced
	// (webhook enforcement-integrity class). The socket only exists once the sidecar starts, so a wired
	// init container that reaches for it fails CLOSED, which is the correct posture for init-phase calls.
	patches = append(patches, mountPatches("containers", len(pod.Spec.Containers), mountState(pod.Spec.Containers), inj.cfg.SpiffeInject)...)
	patches = append(patches, envPatches("containers", len(pod.Spec.Containers), envState(pod.Spec.Containers), inj.cfg)...)
	patches = append(patches, mountPatches("initContainers", len(pod.Spec.InitContainers), mountState(pod.Spec.InitContainers), inj.cfg.SpiffeInject)...)
	patches = append(patches, envPatches("initContainers", len(pod.Spec.InitContainers), envState(pod.Spec.InitContainers), inj.cfg)...)
	// MCP action-firewall. Emitted LAST because it appends to container env lists with "/env/-", which
	// requires those lists to exist — envPatches above creates them for any container that had none.
	// A pod with no norviq.io/mcp-servers annotation (or a cluster with McpInject off) adds nothing, so
	// the emitted patch stays byte-identical to before this path existed.
	mcpOps, err := inj.mcpPatchOps(pod, agentClass, namespace)
	if err != nil {
		return nil, err
	}
	patches = append(patches, mcpOps...)
	patches = append(patches, injectedAnnotationPatch(pod.Annotations))
	return json.Marshal(patches)
}

// mcpPatchOps builds the MCP half of the patch: the proxy volume, the init container that fills it,
// and the per-container command rewrite. Returns a *mcpConfigError when the pod's annotation cannot
// be honored, which the handler surfaces to the operator verbatim — an unwrappable container must be
// a loud denial, not a silent ungoverned server.
func (inj *Injector) mcpPatchOps(pod *corev1.Pod, agentClass, namespace string) ([]patchOp, error) {
	if !inj.cfg.McpInject {
		return nil, nil
	}
	targets, err := mcpTargets(inj.cfg, pod)
	if err != nil {
		slog.Warn("NRVQ-WHK-4039: MCP injection refused", "pod", pod.Name, "namespace", namespace,
			"annotations", mcpAnnotationKeys(pod), "error", err)
		return nil, &mcpConfigError{msg: err.Error()}
	}
	if len(targets) == 0 {
		return nil, nil
	}
	ops := make([]patchOp, 0, len(targets)*4+2)
	// After the sidecar's volume adds, /spec/volumes always exists -> append.
	ops = append(ops, volumePatch(true, mcpVolumeTemplate()))
	ops = append(ops, mcpPatches(inj.cfg, targets, namespace, agentClass)...)
	// The delivery init container is emitted LAST and PREPENDED, and both halves of that matter.
	//
	// Prepended, because init containers run in order: appending it put the payload copy AFTER an
	// annotated init container, so a wrapped init container tried to exec a binary that did not exist
	// yet and the pod could never start.
	//
	// Last, because prepending shifts every existing init container's index by one. Every
	// index-addressed op above — the sidecar's mount/env wiring and the MCP command rewrite — was
	// computed against the ORIGINAL spec, and JSON Patch applies in order, so they must all land
	// before the shift happens.
	ops = append(ops, initContainerPatch(len(pod.Spec.InitContainers) > 0, mcpInitContainer(inj.cfg)))
	slog.Info("NRVQ-WHK-4040: MCP proxy injected", "pod", pod.Name, "namespace", namespace,
		"containers", len(targets))
	return ops, nil
}

// mcpConfigError marks a denial caused by the pod's own MCP annotation, so the handler can return the
// reason to the operator instead of the generic patch-failure message.
type mcpConfigError struct{ msg string }

func (e *mcpConfigError) Error() string { return e.msg }

// initContainerPatch PREPENDS to /spec/initContainers, creating the list when the pod has none, so
// the payload is staged before any init container that might need it. Callers must emit this after
// every index-addressed op, because index 0 shifts the rest of the list.
func initContainerPatch(hasInitContainers bool, container map[string]interface{}) patchOp {
	if hasInitContainers {
		return patchOp{Op: "add", Path: "/spec/initContainers/0", Value: container}
	}
	return patchOp{Op: "add", Path: "/spec/initContainers", Value: []map[string]interface{}{container}}
}

// injectedAnnotationPatch stamps injectedAnnotation ("norviq.io/injected": "true") on every patched pod
// as an operator-visible marker only. It is NOT a trust input: classifyPod (handler.go) recognizes an
// injected pod by its structural wiring, never by this annotation (a tenant can self-stamp it).
func injectedAnnotationPatch(annotations map[string]string) patchOp {
	if len(annotations) == 0 {
		return patchOp{Op: "add", Path: "/metadata/annotations", Value: map[string]string{injectedAnnotation: "true"}}
	}
	return patchOp{Op: "add", Path: "/metadata/annotations/norviq.io~1injected", Value: "true"}
}

func (inj *Injector) validateImage(image string) bool {
	return isAllowedSidecarImage(image)
}

func volumePatch(hasVolumes bool, volume map[string]interface{}) patchOp {
	if hasVolumes {
		return patchOp{Op: "add", Path: "/spec/volumes/-", Value: volume}
	}
	return patchOp{Op: "add", Path: "/spec/volumes", Value: []map[string]interface{}{volume}}
}

// kind is the pod-spec container slice being wired: "containers" or "initContainers".
func mountPatches(kind string, containerCount int, states []containerPatchState, spiffeInject bool) []patchOp {
	mounts := []map[string]interface{}{{"name": "norviq-socket", "mountPath": socketMountPath}}
	if spiffeInject {
		mounts = append(mounts, map[string]interface{}{"name": "spiffe-workload-api", "mountPath": spiffeMountPath, "readOnly": true})
	}
	patches := make([]patchOp, 0, containerCount)
	for idx := 0; idx < containerCount; idx++ {
		state := states[idx]
		if !state.Needs {
			continue
		}
		if !state.HasList {
			patches = append(patches, patchOp{
				Op:    "add",
				Path:  fmt.Sprintf("/spec/%s/%d/volumeMounts", kind, idx),
				Value: mounts,
			})
			continue
		}
		for _, m := range mounts {
			patches = append(patches, patchOp{
				Op:    "add",
				Path:  fmt.Sprintf("/spec/%s/%d/volumeMounts/-", kind, idx),
				Value: m,
			})
		}
	}
	return patches
}

func envPatches(kind string, containerCount int, states []containerPatchState, cfg Config) []patchOp {
	envs := []map[string]interface{}{{"name": "NRVQ_SOCKET_PATH", "value": socketFilePath}}
	if cfg.SpiffeInject {
		envs = append(envs,
			map[string]interface{}{"name": "NRVQ_SPIFFE_MODE", "value": cfg.SpiffeMode},
			map[string]interface{}{"name": "NRVQ_SPIFFE_SOCKET", "value": cfg.SpiffeSocket},
		)
	}
	patches := make([]patchOp, 0, containerCount)
	for idx := 0; idx < containerCount; idx++ {
		state := states[idx]
		if !state.Needs {
			continue
		}
		if !state.HasList {
			patches = append(patches, patchOp{
				Op:    "add",
				Path:  fmt.Sprintf("/spec/%s/%d/env", kind, idx),
				Value: envs,
			})
			continue
		}
		for _, e := range envs {
			patches = append(patches, patchOp{
				Op:    "add",
				Path:  fmt.Sprintf("/spec/%s/%d/env/-", kind, idx),
				Value: e,
			})
		}
	}
	return patches
}

func mountState(containers []corev1.Container) []containerPatchState {
	result := make([]containerPatchState, len(containers))
	for idx, container := range containers {
		result[idx] = containerPatchState{
			HasList: len(container.VolumeMounts) > 0,
			Needs:   !hasSocketMount(container),
		}
	}
	return result
}

func envState(containers []corev1.Container) []containerPatchState {
	result := make([]containerPatchState, len(containers))
	for idx, container := range containers {
		result[idx] = containerPatchState{
			HasList: len(container.Env) > 0,
			Needs:   !hasSocketEnv(container),
		}
	}
	return result
}

// workloadFromPod resolves the Deployment a pod belongs to, so the sidecar can name it and a
// WORKLOAD-tier policy (loader key `deployment:<name>`) can actually match.
//
// Nothing populated this before. AgentIdentity.workload existed, the evaluator read it
// (evaluator.py:1963 builds `<ns>:deployment:<workload>`), the console offered a Workload tier, the CRD
// accepted `target.kind/name` and `norviq policy apply --target-type workload` wrote the row — and the
// field was empty on every request from every production path, so the tier never matched a single call.
// Authored, persisted, "Ready", and inert.
//
// Derived from the OWNER, never from the pod name. A pod created by a Deployment is owned by a
// ReplicaSet named `<deployment>-<pod-template-hash>`, so stripping the hash segment is a fact about
// the object graph rather than a guess about naming — which is what the SDK's own note
// (sdk/core/events.py) rules out. A bare pod has no owner and gets no workload: the tier then does not
// apply, which is the correct outcome, not a default.
//
// An explicit `norviq.io/workload` label always wins, for the cases the ownership chain cannot express
// (a bare pod, a CRD-managed workload, an Argo Rollout).
func workloadFromPod(pod *corev1.Pod) string {
	if pod == nil {
		return ""
	}
	if explicit := strings.TrimSpace(pod.Labels[workloadLabel]); explicit != "" {
		return explicit
	}
	for _, ref := range pod.OwnerReferences {
		switch ref.Kind {
		case "ReplicaSet":
			if name := stripPodTemplateHash(ref.Name); name != "" {
				return name
			}
		case "Deployment", "StatefulSet", "DaemonSet", "Job":
			return ref.Name
		}
	}
	return ""
}

// stripPodTemplateHash turns `checkout-7d9f8b5c4` into `checkout`. The suffix is only removed when it
// actually looks like a pod-template-hash, so a Deployment genuinely named `billing-api` is never
// truncated to `billing` by a ReplicaSet whose name we failed to recognise.
func stripPodTemplateHash(rsName string) string {
	idx := strings.LastIndex(rsName, "-")
	if idx <= 0 || idx == len(rsName)-1 {
		return rsName
	}
	suffix := rsName[idx+1:]
	if len(suffix) < 5 || len(suffix) > 10 {
		return rsName
	}
	for _, r := range suffix {
		if !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9') {
			return rsName
		}
	}
	return rsName[:idx]
}

func (inj *Injector) buildSidecar(agentClass string, namespace string, workload string) map[string]interface{} {
	sidecar := cloneMap(inj.sidecarTemplate)
	sidecar["image"] = inj.cfg.Runtime.SidecarImage(inj.cfg.SidecarImage)
	sidecar["env"] = sidecarEnv(agentClass, namespace, workload, inj.cfg)
	return sidecar
}

func newSidecarTemplate(cfg Config) map[string]interface{} {
	mounts := []map[string]interface{}{
		{"name": "norviq-socket", "mountPath": socketMountPath},
		// Writable scratch for the mTLS cert/key materialization; see tmpVolumeTemplate.
		{"name": tmpVolumeName, "mountPath": tmpMountPath},
	}
	if cfg.SpiffeInject {
		mounts = append(mounts, map[string]interface{}{"name": "spiffe-workload-api", "mountPath": spiffeMountPath, "readOnly": true})
	}
	return map[string]interface{}{
		"name":  "norviq-sidecar",
		"image": cfg.SidecarImage,
		"ports": []map[string]interface{}{
			{"containerPort": cfg.SidecarPort, "name": "sidecar", "protocol": "TCP"},
		},
		"resources":       sidecarResources(cfg),
		"securityContext": sidecarSecurityContext(),
		"startupProbe":    sidecarStartupProbe(cfg.SidecarPort),
		"livenessProbe":   sidecarLivenessProbe(cfg.SidecarPort),
		"readinessProbe":  sidecarReadinessProbe(cfg.SidecarPort),
		"volumeMounts":    mounts,
	}
}

// sidecarEnv wires the injected sidecar so it can actually enforce. Base env is common to both
// modes; proxy mode (the default) adds the central API URL + a namespace-scoped service JWT and needs
// no Redis/OPA/Postgres; embedded mode passes the cluster datastore wiring through from the webhook's env.
// NRVQ_NAMESPACE is always set to the pod's namespace so mock identity resolves the real tenant.
func sidecarEnv(agentClass string, namespace string, workload string, cfg Config) []map[string]interface{} {
	env := []map[string]interface{}{
		{"name": "NRVQ_AGENT_CLASS", "value": agentClass},
		{"name": "NRVQ_NAMESPACE", "value": namespace},
		{"name": "NRVQ_HTTP_FALLBACK_PORT", "value": fmt.Sprintf("%d", cfg.SidecarPort)},
		{"name": "NRVQ_SOCKET_PATH", "value": socketFilePath},
		{"name": "NRVQ_SIDECAR_MODE", "value": sidecarMode(cfg)},
	}
	// Only set when the owner chain (or an explicit label) actually named a workload. Setting it empty
	// would be indistinguishable from "resolved to nothing", and the workload tier must stay inapplicable
	// rather than match a "" key.
	if workload != "" {
		env = append(env, map[string]interface{}{"name": "NRVQ_WORKLOAD", "value": workload})
	}
	if sidecarMode(cfg) == "embedded" {
		// Air-gapped/edge: the sidecar runs its own engine and needs the datastore wiring. OPA runs as a
		// subprocess fork (the sidecar pod has no OPA server sidecar).
		env = appendIfSet(env, "NRVQ_REDIS_URL", cfg.RedisURL)
		env = appendIfSet(env, "NRVQ_PG_URL", cfg.PgURL)
		env = append(env,
			map[string]interface{}{"name": "NRVQ_OPA_MODE", "value": cfg.OpaMode},
			map[string]interface{}{"name": "NRVQ_DB_SSL_MODE", "value": cfg.DBSSLMode},
		)
	} else {
		// Thin proxy (default): call the central engine with a per-workload namespace-scoped service JWT.
		// When auto-mTLS is on, the API URL is upgraded to https and mTLS material is delivered as PEM
		// env alongside the JWT (defense in depth). When off, the env below is byte-identical to before.
		apiURL := cfg.ApiURL
		tlsEnv, tlsOn := buildSidecarTLSEnv(cfg, namespace, &apiURL)
		env = append(env, map[string]interface{}{"name": "NRVQ_API_URL", "value": apiURL})
		if tok := mintSidecarToken(cfg, namespace, agentClass); tok != "" {
			env = append(env, map[string]interface{}{"name": "NRVQ_API_TOKEN", "value": tok})
		} else {
			slog.Warn("NRVQ-WHK-4037: no API secret to mint sidecar token; thin-proxy sidecar will fail closed",
				"namespace", namespace)
		}
		if tlsOn {
			env = append(env, tlsEnv...)
		}
	}
	if cfg.SpiffeInject {
		env = append(env,
			map[string]interface{}{"name": "NRVQ_SPIFFE_MODE", "value": cfg.SpiffeMode},
			map[string]interface{}{"name": "NRVQ_SPIFFE_SOCKET", "value": cfg.SpiffeSocket},
		)
	}
	// Give the injected sidecar the same outage posture the operator configured for the SDK, so the
	// zero-code-change path and the in-process path behave identically during an engine outage.
	env = appendIfSet(env, "NRVQ_SDK_FALLBACK_MODE", cfg.FallbackMode)
	return env
}

// sidecarMode normalizes the configured mode; anything other than "embedded" is the safe thin-proxy default.
func sidecarMode(cfg Config) string {
	if cfg.SidecarMode == "embedded" {
		return "embedded"
	}
	return "proxy"
}

func appendIfSet(env []map[string]interface{}, name, value string) []map[string]interface{} {
	if value == "" {
		return env
	}
	return append(env, map[string]interface{}{"name": name, "value": value})
}

// mintSidecarToken issues the namespace-scoped role=service JWT the thin-proxy sidecar presents to
// /evaluate. The token is baked into the pod env (cannot self-refresh), hence the long TTL; mTLS +
// short-lived tokens are the documented fast-follow. Returns "" if no signing secret is set.
func mintSidecarToken(cfg Config, namespace string, agentClass string) string {
	if cfg.ApiSecret == "" {
		return ""
	}
	now := time.Now()
	ttl := time.Duration(cfg.SidecarTokenTTLHours) * time.Hour
	if ttl <= 0 {
		ttl = 720 * time.Hour
	}
	claims := map[string]interface{}{
		"sub":       "norviq-sidecar",
		"role":      "service",
		"namespace": namespace,
		// Identity BINDING (api/auth.py scoped_identity): pin this sidecar's token to the identity the pod
		// was actually admitted with. `agent_class` (from the norviq.io/agent-class label) selects which
		// Rego program /evaluate enforces; `spiffe_id` keys the trust score, the per-agent rate limit and
		// the agent_frozen: kill-switch. Without these claims a namespace-scoped sidecar token could assert
		// a sibling class (running its looser policy) or another SPIFFE id (shedding an operator's freeze).
		"agent_class": agentClass,
		"iat":         now.Unix(),
		"exp":         now.Add(ttl).Unix(),
	}
	// Bind spiffe_id ONLY when we can predict it byte-for-byte. In the default "mock" resolver the
	// sidecar builds spiffe://norviq/ns/<ns>/sa/<NRVQ_SERVICE_ACCOUNT|default> (engine/identity.py
	// _mock_resolve) and the webhook never injects NRVQ_SERVICE_ACCOUNT, so the id is deterministic and
	// TestSidecarTokenSpiffeClaimMatchesMockResolver locks the formula. In workload-api mode the id comes
	// from a SPIRE-issued SVID whose trust domain we do not control here — minting a guess would 403 every
	// tool call, so the field is left unbound (the SVID is separately attested at the source).
	if cfg.SpiffeMode == "mock" {
		claims["spiffe_id"] = fmt.Sprintf("spiffe://norviq/ns/%s/sa/default", namespace)
	}
	tok, err := signHS256JWT(cfg.ApiSecret, claims)
	if err != nil {
		slog.Error("NRVQ-WHK-4038: sidecar token mint failed", "namespace", namespace, "error", err)
		return ""
	}
	return tok
}

// buildSidecarTLSEnv returns the auto-mTLS env for the injected sidecar (defense in depth alongside
// the JWT): the trusted CA PEM plus a freshly minted per-namespace client cert/key, and NRVQ_INTERNAL_TLS
// so the Python sidecar builds an SSLContext. It also upgrades apiURL to https (leaving an already-https
// cfg.ApiURL untouched). Returns (nil,false) when the flag is off OR the CA material can't be read/minted
// — in the failure case the caller keeps the current plaintext+JWT env so injection never hard-fails.
func buildSidecarTLSEnv(cfg Config, namespace string, apiURL *string) ([]map[string]interface{}, bool) {
	if !cfg.InternalTLS {
		return nil, false
	}
	caPEM, err := os.ReadFile(cfg.CACertFile)
	if err != nil {
		slog.Error("NRVQ-WHK-4047: read internal CA cert for sidecar mTLS failed; falling back to plaintext+JWT",
			"namespace", namespace, "error", err)
		return nil, false
	}
	certPEM, keyPEM, err := mintClientCert(cfg, namespace)
	if err != nil {
		slog.Error("NRVQ-WHK-4048: sidecar client cert mint failed; falling back to plaintext+JWT",
			"namespace", namespace, "error", err)
		return nil, false
	}
	if !strings.HasPrefix(*apiURL, "https://") {
		*apiURL = "https://norviq-api:8443"
	}
	return []map[string]interface{}{
		{"name": "NRVQ_INTERNAL_TLS", "value": "true"},
		{"name": "NRVQ_API_CA_PEM", "value": string(caPEM)},
		{"name": "NRVQ_CLIENT_CERT_PEM", "value": certPEM},
		{"name": "NRVQ_CLIENT_KEY_PEM", "value": keyPEM},
	}, true
}

// mintClientCert mints a per-namespace CLIENT certificate signed by the internal CA (ca.crt/ca.key read
// from cfg.CACertFile/cfg.CAKeyFile, mounted from secret norviq-internal-ca). The leaf is a 2048-bit RSA
// key, CN=norviq-sidecar, OU=<namespace>, ExtKeyUsage=ClientAuth, 30-day validity. Both PEMs are returned
// as strings so the injector can deliver them to the sidecar via pod env.
func mintClientCert(cfg Config, namespace string) (certPEM string, keyPEM string, err error) {
	caCertBytes, err := os.ReadFile(cfg.CACertFile)
	if err != nil {
		return "", "", fmt.Errorf("NRVQ-WHK-4049: read CA cert %q: %w", cfg.CACertFile, err)
	}
	caKeyBytes, err := os.ReadFile(cfg.CAKeyFile)
	if err != nil {
		return "", "", fmt.Errorf("NRVQ-WHK-4050: read CA key %q: %w", cfg.CAKeyFile, err)
	}
	caCert, caSigner, err := parseCAKeyPair(caCertBytes, caKeyBytes)
	if err != nil {
		return "", "", err
	}

	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", fmt.Errorf("NRVQ-WHK-4051: generate sidecar key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", "", fmt.Errorf("NRVQ-WHK-4052: generate serial: %w", err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:         "norviq-sidecar",
			OrganizationalUnit: []string{namespace},
		},
		NotBefore:             now.Add(-1 * time.Minute),
		NotAfter:              now.Add(30 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &leafKey.PublicKey, caSigner)
	if err != nil {
		return "", "", fmt.Errorf("NRVQ-WHK-4053: sign sidecar cert: %w", err)
	}
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(leafKey)}))
	return certPEM, keyPEM, nil
}

// parseCAKeyPair decodes the internal CA's cert + private key PEM. The key may be PKCS#1, PKCS#8, or SEC1
// (EC); any crypto.Signer is accepted so the CA can be RSA or ECDSA.
func parseCAKeyPair(certPEM, keyPEM []byte) (*x509.Certificate, crypto.Signer, error) {
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return nil, nil, fmt.Errorf("NRVQ-WHK-4054: CA cert PEM did not decode to a CERTIFICATE block")
	}
	caCert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("NRVQ-WHK-4055: parse CA cert: %w", err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, nil, fmt.Errorf("NRVQ-WHK-4056: CA key PEM did not decode")
	}
	signer, err := parsePrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}
	return caCert, signer, nil
}

// parsePrivateKey parses a DER-encoded private key trying PKCS#8, then PKCS#1 (RSA), then SEC1 (EC).
func parsePrivateKey(der []byte) (crypto.Signer, error) {
	if k, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		if signer, ok := k.(crypto.Signer); ok {
			return signer, nil
		}
		return nil, fmt.Errorf("NRVQ-WHK-4057: PKCS#8 CA key is not a crypto.Signer")
	}
	if k, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return k, nil
	}
	if k, err := x509.ParseECPrivateKey(der); err == nil {
		return k, nil
	}
	return nil, fmt.Errorf("NRVQ-WHK-4058: CA private key is not a supported PKCS#8/PKCS#1/SEC1 key")
}

// sidecarResources takes its budget from config rather than hardcoding one.
//
// It was fixed at 64Mi/128Mi for every injected sidecar regardless of mode. `proxy` (the default) is
// a thin forwarder and fits comfortably; `embedded` builds a full engine in-pod — redis client,
// policy warm, audit emitter, pubsub watcher and an OPA subprocess — and was OOMKilled (exit 137)
// every time, after reaching `nrvq.sidecar.started` but before uvicorn could bind. So embedded mode
// had never worked in any release, and the symptom looked like a probe failure rather than a memory
// one. The chart now picks the budget per mode and passes it in.
func sidecarResources(cfg Config) map[string]interface{} {
	return map[string]interface{}{
		"requests": map[string]string{"cpu": cfg.SidecarCPURequest, "memory": cfg.SidecarMemRequest},
		"limits":   map[string]string{"cpu": cfg.SidecarCPULimit, "memory": cfg.SidecarMemLimit},
	}
}

func sidecarSecurityContext() map[string]interface{} {
	return map[string]interface{}{
		"runAsNonRoot":             true,
		"runAsUser":                65534,
		"readOnlyRootFilesystem":   true,
		"allowPrivilegeEscalation": false,
		"capabilities":             map[string]interface{}{"drop": []string{"ALL"}},
		"seccompProfile":           map[string]interface{}{"type": "RuntimeDefault"},
	}
}

// sidecarStartupProbe holds liveness off until the sidecar is actually serving.
//
// The entrypoint runs `await proxy.start()` BEFORE uvicorn binds the port. In `proxy` mode that is
// near-instant. In `embedded` mode the sidecar builds a whole engine first — Postgres, Redis, policy
// warm, an OPA subprocess — and liveness was probing from 5s with a 3x15s budget, so the kubelet
// killed the container while the HTTP server had not been created yet:
//
//	Readiness probe failed: dial tcp ...:8282: connect: connection refused
//	Container norviq-sidecar failed liveness probe, will be restarted
//
// …forever. A startupProbe is the primitive for exactly this: liveness and readiness do not begin
// until it first succeeds, so the slow path gets 90s to come up WITHOUT loosening the steady-state
// liveness check. Costs proxy mode nothing — it passes on the first probe.
func sidecarStartupProbe(sidecarPort int) map[string]interface{} {
	return map[string]interface{}{
		"httpGet":             map[string]interface{}{"path": "/healthz", "port": sidecarPort},
		"initialDelaySeconds": 2,
		"periodSeconds":       3,
		"timeoutSeconds":      2,
		"failureThreshold":    30,
	}
}

func sidecarLivenessProbe(sidecarPort int) map[string]interface{} {
	return map[string]interface{}{
		"httpGet":             map[string]interface{}{"path": "/healthz", "port": sidecarPort},
		"initialDelaySeconds": 5,
		"periodSeconds":       15,
		// /healthz is a constant response, so 2s is generous; set it EXPLICITLY rather than
		// inheriting Kubernetes' 1s default, which is the kind of implicit budget that only shows up
		// as a mystery restart under load.
		"timeoutSeconds":   2,
		"failureThreshold": 3,
	}
}

// sidecarReadinessProbe gates pod Readiness on the sidecar actually serving enforcement, so a
// mis-wired or crash-looping sidecar surfaces as NotReady instead of silently forwarding tool calls.
func sidecarReadinessProbe(sidecarPort int) map[string]interface{} {
	return map[string]interface{}{
		"httpGet":             map[string]interface{}{"path": "/readyz", "port": sidecarPort},
		"initialDelaySeconds": 3,
		"periodSeconds":       10,
		// Unset meant Kubernetes' 1s default, and /readyz does real work: it proves the PDP is
		// reachable. Under NRVQ_OPA_MODE=subprocess (what embedded mode uses) that forks `opa`, which
		// does not answer inside a second — so the check timed out on a sidecar that was fine.
		"timeoutSeconds":   5,
		"failureThreshold": 3,
	}
}

func volumeTemplate() map[string]interface{} {
	return map[string]interface{}{"name": "norviq-socket", "emptyDir": map[string]interface{}{"sizeLimit": "10Mi"}}
}

// tmpVolumeTemplate is the sidecar's private scratch space. `medium: Memory` keeps it a tmpfs so the
// short-lived mTLS client key (written 0600 and unlinked immediately) never touches a real disk. It is
// deliberately NOT the shared norviq-socket volume, which the app container also mounts.
func tmpVolumeTemplate() map[string]interface{} {
	return map[string]interface{}{
		"name":     tmpVolumeName,
		"emptyDir": map[string]interface{}{"medium": "Memory", "sizeLimit": "16Mi"},
	}
}

// spiffeVolumeTemplate is the SPIFFE Workload API socket, published by the SPIFFE CSI driver.
func spiffeVolumeTemplate() map[string]interface{} {
	return map[string]interface{}{
		"name": "spiffe-workload-api",
		"csi":  map[string]interface{}{"driver": "csi.spiffe.io", "readOnly": true},
	}
}

func cloneMap(src map[string]interface{}) map[string]interface{} {
	// Intentionally shallow: nested template values are treated as immutable/read-only.
	dst := make(map[string]interface{}, len(src))
	for key, value := range src {
		dst[key] = value
	}
	return dst
}

func hasSocketEnv(container corev1.Container) bool {
	for _, env := range container.Env {
		if env.Name == "NRVQ_SOCKET_PATH" {
			return true
		}
	}
	return false
}
