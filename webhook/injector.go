// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
package main

import (
	"encoding/json"
	"fmt"
	"log/slog"

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

func (inj *Injector) CreatePatch(pod *corev1.Pod, agentClass string) ([]byte, error) {
	image := inj.cfg.Runtime.SidecarImage(inj.cfg.SidecarImage)
	if !inj.validateImage(image) {
		slog.Error("NRVQ-WHK-4033: blocked unauthorized sidecar image", "image", image)
		return nil, fmt.Errorf("unauthorized sidecar image")
	}
	mountStates := mountState(pod.Spec.Containers)
	envStates := envState(pod.Spec.Containers)
	containerCount := len(pod.Spec.Containers)
	patches := make([]patchOp, 0, 6)
	patches = append(patches, patchOp{Op: "add", Path: "/spec/containers/-", Value: inj.buildSidecar(agentClass)})
	patches = append(patches, volumePatch(len(pod.Spec.Volumes) > 0, inj.sharedVolume))
	if inj.cfg.SpiffeInject {
		// After the first volume add, /spec/volumes always exists -> append the SPIFFE CSI volume.
		patches = append(patches, volumePatch(true, spiffeVolumeTemplate()))
	}
	patches = append(patches, mountPatches(containerCount, mountStates, inj.cfg.SpiffeInject)...)
	patches = append(patches, envPatches(containerCount, envStates, inj.cfg)...)
	return json.Marshal(patches)
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

func (inj *Injector) buildSidecar(agentClass string) map[string]interface{} {
	sidecar := cloneMap(inj.sidecarTemplate)
	sidecar["image"] = inj.cfg.Runtime.SidecarImage(inj.cfg.SidecarImage)
	sidecar["env"] = sidecarEnv(agentClass, inj.cfg)
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
		"volumeMounts":    mounts,
	}
}

func sidecarEnv(agentClass string, cfg Config) []map[string]interface{} {
	env := []map[string]interface{}{
		{"name": "NRVQ_AGENT_CLASS", "value": agentClass},
		{"name": "NRVQ_HTTP_FALLBACK_PORT", "value": fmt.Sprintf("%d", cfg.SidecarPort)},
		{"name": "NRVQ_SOCKET_PATH", "value": socketFilePath},
	}
	if cfg.SpiffeInject {
		env = append(env,
			map[string]interface{}{"name": "NRVQ_SPIFFE_MODE", "value": cfg.SpiffeMode},
			map[string]interface{}{"name": "NRVQ_SPIFFE_SOCKET", "value": cfg.SpiffeSocket},
		)
	}
	return env
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
