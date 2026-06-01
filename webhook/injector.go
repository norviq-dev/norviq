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
	patches := make([]patchOp, 0, 4)
	patches = append(patches, patchOp{Op: "add", Path: "/spec/containers/-", Value: inj.buildSidecar(agentClass)})
	patches = append(patches, volumePatch(len(pod.Spec.Volumes) > 0, inj.sharedVolume))
	patches = append(patches, mountPatches(containerCount, mountStates)...)
	patches = append(patches, envPatches(containerCount, envStates)...)
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

func mountPatches(containerCount int, states []containerPatchState) []patchOp {
	patches := make([]patchOp, 0, containerCount)
	for idx := 0; idx < containerCount; idx++ {
		state := states[idx]
		if !state.Needs {
			continue
		}
		if !state.HasList {
			patches = append(patches, patchOp{
				Op:   "add",
				Path: fmt.Sprintf("/spec/containers/%d/volumeMounts", idx),
				Value: []map[string]interface{}{
					{"name": "norviq-socket", "mountPath": socketMountPath},
				},
			})
			continue
		}
		patches = append(patches, patchOp{
			Op:    "add",
			Path:  fmt.Sprintf("/spec/containers/%d/volumeMounts/-", idx),
			Value: map[string]interface{}{"name": "norviq-socket", "mountPath": socketMountPath},
		})
	}
	return patches
}

func envPatches(containerCount int, states []containerPatchState) []patchOp {
	patches := make([]patchOp, 0, containerCount)
	for idx := 0; idx < containerCount; idx++ {
		state := states[idx]
		if !state.Needs {
			continue
		}
		if !state.HasList {
			patches = append(patches, patchOp{
				Op:   "add",
				Path: fmt.Sprintf("/spec/containers/%d/env", idx),
				Value: []map[string]interface{}{
					{"name": "NRVQ_SOCKET_PATH", "value": socketFilePath},
				},
			})
			continue
		}
		patches = append(patches, patchOp{
			Op:    "add",
			Path:  fmt.Sprintf("/spec/containers/%d/env/-", idx),
			Value: map[string]interface{}{"name": "NRVQ_SOCKET_PATH", "value": socketFilePath},
		})
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
	sidecar["env"] = sidecarEnv(agentClass, inj.cfg.SidecarPort)
	return sidecar
}

func newSidecarTemplate(cfg Config) map[string]interface{} {
	return map[string]interface{}{
		"name":  "norviq-sidecar",
		"image": cfg.SidecarImage,
		"ports": []map[string]interface{}{
			{"containerPort": cfg.SidecarPort, "name": "sidecar", "protocol": "TCP"},
		},
		"resources":       sidecarResources(),
		"securityContext": sidecarSecurityContext(),
		"livenessProbe":   sidecarLivenessProbe(cfg.SidecarPort),
		"volumeMounts": []map[string]interface{}{
			{"name": "norviq-socket", "mountPath": socketMountPath},
		},
	}
}

func sidecarEnv(agentClass string, sidecarPort int) []map[string]interface{} {
	return []map[string]interface{}{
		{"name": "NRVQ_AGENT_CLASS", "value": agentClass},
		{"name": "NRVQ_HTTP_FALLBACK_PORT", "value": fmt.Sprintf("%d", sidecarPort)},
		{"name": "NRVQ_SOCKET_PATH", "value": socketFilePath},
	}
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
