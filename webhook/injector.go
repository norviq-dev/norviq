// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
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

type Injector struct {
	cfg             Config
	sidecarTemplate map[string]interface{}
	sharedVolume    map[string]interface{}
}

const socketMountPath = "/var/run/norviq"
const socketFilePath = "/var/run/norviq/norviq-proxy.sock"
const spiffeMountPath = "/spiffe-workload-api"

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
	patches = append(patches, patchOp{Op: "add", Path: "/spec/containers/-", Value: inj.buildSidecar(agentClass, namespace)})
	patches = append(patches, volumePatch(len(pod.Spec.Volumes) > 0, inj.sharedVolume))
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
	patches = append(patches, injectedAnnotationPatch(pod.Annotations))
	return json.Marshal(patches)
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

func (inj *Injector) buildSidecar(agentClass string, namespace string) map[string]interface{} {
	sidecar := cloneMap(inj.sidecarTemplate)
	sidecar["image"] = inj.cfg.Runtime.SidecarImage(inj.cfg.SidecarImage)
	sidecar["env"] = sidecarEnv(agentClass, namespace, inj.cfg)
	return sidecar
}

func newSidecarTemplate(cfg Config) map[string]interface{} {
	mounts := []map[string]interface{}{{"name": "norviq-socket", "mountPath": socketMountPath}}
	if cfg.SpiffeInject {
		mounts = append(mounts, map[string]interface{}{"name": "spiffe-workload-api", "mountPath": spiffeMountPath, "readOnly": true})
	}
	return map[string]interface{}{
		"name":  "norviq-sidecar",
		"image": cfg.SidecarImage,
		"ports": []map[string]interface{}{
			{"containerPort": cfg.SidecarPort, "name": "sidecar", "protocol": "TCP"},
		},
		"resources":       sidecarResources(),
		"securityContext": sidecarSecurityContext(),
		"livenessProbe":   sidecarLivenessProbe(cfg.SidecarPort),
		"readinessProbe":  sidecarReadinessProbe(cfg.SidecarPort),
		"volumeMounts":    mounts,
	}
}

// sidecarEnv wires the injected sidecar so it can actually enforce (SIDE-1). Base env is common to both
// modes; proxy mode (SIDE-2 default) adds the central API URL + a namespace-scoped service JWT and needs
// no Redis/OPA/Postgres; embedded mode passes the cluster datastore wiring through from the webhook's env.
// NRVQ_NAMESPACE is always set to the pod's namespace so mock identity resolves the real tenant (SIDE-4).
func sidecarEnv(agentClass string, namespace string, cfg Config) []map[string]interface{} {
	env := []map[string]interface{}{
		{"name": "NRVQ_AGENT_CLASS", "value": agentClass},
		{"name": "NRVQ_NAMESPACE", "value": namespace},
		{"name": "NRVQ_HTTP_FALLBACK_PORT", "value": fmt.Sprintf("%d", cfg.SidecarPort)},
		{"name": "NRVQ_SOCKET_PATH", "value": socketFilePath},
		{"name": "NRVQ_SIDECAR_MODE", "value": sidecarMode(cfg)},
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
		if tok := mintSidecarToken(cfg, namespace); tok != "" {
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
// short-lived tokens are the documented fast-follow (FLAG-D). Returns "" if no signing secret is set.
func mintSidecarToken(cfg Config, namespace string) string {
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
		"iat":       now.Unix(),
		"exp":       now.Add(ttl).Unix(),
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

func sidecarResources() map[string]interface{} {
	return map[string]interface{}{
		"requests": map[string]string{"cpu": "50m", "memory": "64Mi"},
		"limits":   map[string]string{"cpu": "200m", "memory": "128Mi"},
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

func sidecarLivenessProbe(sidecarPort int) map[string]interface{} {
	return map[string]interface{}{
		"httpGet":             map[string]interface{}{"path": "/healthz", "port": sidecarPort},
		"initialDelaySeconds": 5,
		"periodSeconds":       15,
		"failureThreshold":    3,
	}
}

// sidecarReadinessProbe (SIDE-1) gates pod Readiness on the sidecar actually serving enforcement, so a
// mis-wired or crash-looping sidecar surfaces as NotReady instead of silently forwarding tool calls.
func sidecarReadinessProbe(sidecarPort int) map[string]interface{} {
	return map[string]interface{}{
		"httpGet":             map[string]interface{}{"path": "/readyz", "port": sidecarPort},
		"initialDelaySeconds": 3,
		"periodSeconds":       10,
		"failureThreshold":    3,
	}
}

func volumeTemplate() map[string]interface{} {
	return map[string]interface{}{"name": "norviq-socket", "emptyDir": map[string]interface{}{"sizeLimit": "10Mi"}}
}

// spiffeVolumeTemplate is the SPIFFE Workload API socket, published by the SPIFFE CSI driver (B3).
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
