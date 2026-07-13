// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
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
	mountStates := mountState(pod.Spec.Containers)
	envStates := envState(pod.Spec.Containers)
	containerCount := len(pod.Spec.Containers)
	patches := make([]patchOp, 0, 6)
	patches = append(patches, patchOp{Op: "add", Path: "/spec/containers/-", Value: inj.buildSidecar(agentClass, namespace)})
	patches = append(patches, volumePatch(len(pod.Spec.Volumes) > 0, inj.sharedVolume))
	if inj.cfg.SpiffeInject {
		// After the first volume add, /spec/volumes always exists -> append the SPIFFE CSI volume.
		patches = append(patches, volumePatch(true, spiffeVolumeTemplate()))
	}
	patches = append(patches, mountPatches(containerCount, mountStates, inj.cfg.SpiffeInject)...)
	patches = append(patches, envPatches(containerCount, envStates, inj.cfg)...)
	patches = append(patches, injectedAnnotationPatch(pod.Annotations))
	return json.Marshal(patches)
}

// injectedAnnotationPatch stamps injectedAnnotation ("norviq.io/injected": "true") on every patched
// pod. hasSidecar (handler.go) trusts this over the container name, which an attacker can forge with a
// decoy container; the annotation is set only here, by the injector itself, on the admission path.
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

func mountPatches(containerCount int, states []containerPatchState, spiffeInject bool) []patchOp {
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
				Path:  fmt.Sprintf("/spec/containers/%d/volumeMounts", idx),
				Value: mounts,
			})
			continue
		}
		for _, m := range mounts {
			patches = append(patches, patchOp{
				Op:    "add",
				Path:  fmt.Sprintf("/spec/containers/%d/volumeMounts/-", idx),
				Value: m,
			})
		}
	}
	return patches
}

func envPatches(containerCount int, states []containerPatchState, cfg Config) []patchOp {
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
				Path:  fmt.Sprintf("/spec/containers/%d/env", idx),
				Value: envs,
			})
			continue
		}
		for _, e := range envs {
			patches = append(patches, patchOp{
				Op:    "add",
				Path:  fmt.Sprintf("/spec/containers/%d/env/-", idx),
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
		env = append(env, map[string]interface{}{"name": "NRVQ_API_URL", "value": cfg.ApiURL})
		if tok := mintSidecarToken(cfg, namespace); tok != "" {
			env = append(env, map[string]interface{}{"name": "NRVQ_API_TOKEN", "value": tok})
		} else {
			slog.Warn("NRVQ-WHK-4037: no API secret to mint sidecar token; thin-proxy sidecar will fail closed",
				"namespace", namespace)
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
