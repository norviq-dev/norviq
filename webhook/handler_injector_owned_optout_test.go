// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
package main

// The injector's parts under names of the pod's own choosing, on the two paths where they used to pass.
//
// A pod that opts out of injection is admitted as it stands, with nothing added beside it. There the
// sidecar image is the sidecar whatever command it is given: the engine image declares no ENTRYPOINT,
// so a command that spells out its CMD is the sidecar process itself. On a pod that is injected, a
// command keeps the shipped pattern of running another norviq module from the engine image working.
//
// With MCP injection on, delivering or running the MCP proxy is the injector's job on every pod, so a
// container running the proxy image, or a command naming its executable or payload, is refused under
// any container name and at any path.

import (
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
)

const sidecarCMD = "python -m norviq.sidecar" // Dockerfile.engine's CMD; the image has no ENTRYPOINT

// guardedPod is integrityPod plus a container named guard running image with the given command, args
// and an outage posture of the pod's own, as an app container or as a native init sidecar.
func guardedPod(image string, command, args []string, optOut, nativeInit bool) corev1.Pod {
	p := integrityPod()
	if optOut {
		p.Labels["norviq-injection"] = "disabled"
	}
	g := corev1.Container{Name: "guard", Image: image, Command: command, Args: args,
		Env: []corev1.EnvVar{{Name: "NRVQ_SDK_FALLBACK_MODE", Value: "allow"}}}
	if nativeInit {
		always := corev1.ContainerRestartPolicyAlways
		g.RestartPolicy = &always
		p.Spec.InitContainers = append(p.Spec.InitContainers, g)
	} else {
		p.Spec.Containers = append(p.Spec.Containers, g)
	}
	return p
}

func optOutConfig(cfg Config) Config {
	cfg.AllowPodOptOut = true // the chart default
	return cfg
}

func TestOptedOutPodRunningTheSidecarImageUnderAnotherNameIsRefused(t *testing.T) {
	cfg := optOutConfig(integrityConfig())
	img := configuredSidecarImage(cfg)
	repo := imageRepository(img)
	cmd := strings.Fields(sidecarCMD)
	cases := []struct {
		name          string
		image         string
		command, args []string
		nativeInit    bool
	}{
		{"command spells out the image CMD", img, cmd, nil, false},
		{"args spell out the image CMD under another tag", repo + ":0.0.1-any", nil, cmd, false},
		{"interpreter as command, module as args, by digest", repo + "@sha256:" + strings.Repeat("a", 64),
			cmd[:1], cmd[1:], false},
		{"native init sidecar with the CMD", img, cmd, nil, true},
		{"the -dev repository the allowlist accepts, image entrypoint", "ghcr.io/norviq-dev/norviq-engine-dev:engine-latest",
			nil, nil, false},
		{"the -dev repository with the CMD", "ghcr.io/norviq-dev/norviq-engine-dev:engine-latest", cmd, nil, false},
		{"the repository name from another registry, with the CMD", "mirror.example.com/norviq/norviq-engine:1",
			cmd, nil, false},
		{"a shell running the module", img, []string{"sh", "-c", "exec " + sidecarCMD}, nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pod := guardedPod(tc.image, tc.command, tc.args, true, tc.nativeInit)
			assertDenied(t, cfg, pod, codeOwnedPart, "container guard runs the sidecar image "+tc.image)
		})
	}
}

// The other half of the rule, which keeps the shipped examples admitting: on a pod that is injected,
// the engine image running with a command of its own, and the -dev repository running its own
// entrypoint (examples/chatbot), are injected beside the real sidecar.
func TestInjectedPodKeepsRunningOtherModulesFromTheEngineImage(t *testing.T) {
	cfg := optOutConfig(integrityConfig())
	img := configuredSidecarImage(cfg)
	cases := []struct {
		name          string
		image         string
		command, args []string
	}{
		{"an MCP firewall from the engine image", img, nil, []string{"python", "-m", "norviq.mcp", "--server-id", "kb"}},
		{"the -dev repository's own entrypoint", "ghcr.io/norviq-dev/norviq-engine-dev:demo-chatbot", nil, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := assertInjected(t, cfg, guardedPod(tc.image, tc.command, tc.args, false, false))
			sidecarIn(t, &out)
		})
	}
}

// mcpDeliveredPod is integrityPod with a delivery init container of the pod's own, copying from image
// into a volume of the pod's own, and an MCP server whose command is set by the caller.
func mcpDeliveredPod(initName, initImage string, initCmd, serverCmd []string, optOut bool) corev1.Pod {
	p := integrityPod()
	if optOut {
		p.Labels["norviq-injection"] = "disabled"
	}
	addVolume(&p, "mytools")
	p.Spec.InitContainers = []corev1.Container{{Name: initName, Image: initImage, Command: initCmd,
		VolumeMounts: []corev1.VolumeMount{{Name: "mytools", MountPath: "/tools"}}}}
	p.Spec.Containers = append(p.Spec.Containers, corev1.Container{Name: "mcp", Image: "node:22",
		Command:      serverCmd,
		Env:          []corev1.EnvVar{{Name: "NRVQ_SDK_FALLBACK_MODE", Value: "allow"}},
		VolumeMounts: []corev1.VolumeMount{{Name: "mytools", MountPath: "/tools", ReadOnly: true}}})
	return p
}

func TestMcpDeliveryAndWrapUnderAnotherNameAreRefused(t *testing.T) {
	cfg := optOutConfig(mcpIntegrityConfig())
	proxyRepo := imageRepository(mcpIntegrityProxyImage)
	copyCmd := []string{"sh", "-c", "cp -a " + cfg.McpProxySourcePath + " /tools/"}
	wrap := []string{"/tools/mcp-proxy/norviq-mcp", "--server-id", "mcp", "--", "npx", "server-github"}
	plain := []string{"npx", "server-github"}
	cases := []struct {
		name      string
		initName  string
		initImage string
		initCmd   []string
		serverCmd []string
		optOut    bool
		want      string
	}{
		{"delivery renamed, opted out", "tools", mcpIntegrityProxyImage, copyCmd, wrap, true,
			"container tools runs the MCP proxy image"},
		{"delivery renamed, injected", "tools", mcpIntegrityProxyImage, copyCmd, wrap, false,
			"container tools runs the MCP proxy image"},
		{"delivery by digest, no wrap", "tools", proxyRepo + "@sha256:" + strings.Repeat("b", 64),
			[]string{"true"}, plain, true, "container tools runs the MCP proxy image"},
		{"wrap at a relocated path", "tools", "busybox:1.36", []string{"true"}, wrap, true,
			"container mcp runs the MCP proxy executable /tools/mcp-proxy/norviq-mcp"},
		{"wrap inside a shell string", "tools", "busybox:1.36", []string{"true"},
			[]string{"sh", "-c", "set -e; exec /tools/x/norviq-mcp --server-id mcp -- npx server-github"}, true,
			"container mcp runs the MCP proxy executable /tools/x/norviq-mcp"},
		{"wrap found on PATH", "tools", "busybox:1.36", []string{"true"},
			[]string{"norviq-mcp", "--server-id", "mcp", "--", "npx", "server-github"}, true,
			"container mcp runs the MCP proxy executable norviq-mcp"},
		{"payload copied from another image", "tools", "mirror.example.com/payload:1", copyCmd, plain, true,
			"container tools refers to the MCP proxy payload at " + cfg.McpProxySourcePath},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pod := mcpDeliveredPod(tc.initName, tc.initImage, tc.initCmd, tc.serverCmd, tc.optOut)
			assertDenied(t, cfg, pod, codeOwnedPart, tc.want)
		})
	}
}

// Controls for the MCP rule: with MCP injection off nothing MCP-shaped changes admission (the opted-out
// pod is admitted unpatched as before), and a name that merely begins like the executable is not it.
func TestMcpProxyRuleLeavesOtherPodsAlone(t *testing.T) {
	wrap := []string{"/tools/mcp-proxy/norviq-mcp", "--server-id", "mcp", "--", "npx", "server-github"}
	off := optOutConfig(integrityConfig())
	pod := mcpDeliveredPod("tools", mcpIntegrityProxyImage, []string{"true"}, wrap, true)
	if allowed, patch, msg := admitPod(t, off, pod); !allowed || patch != nil {
		t.Fatalf("with MCP injection off an opted-out pod is admitted unpatched; allowed=%v patched=%v %q",
			allowed, patch != nil, msg)
	}

	on := optOutConfig(mcpIntegrityConfig())
	lookalike := mcpDeliveredPod("tools", "busybox:1.36", []string{"true"},
		[]string{"/usr/bin/norviq-mcp-lint", "--server-id", "norviq-mcpx"}, false)
	assertInjected(t, on, lookalike)
}

func TestImageRepository(t *testing.T) {
	cases := map[string]string{
		"ghcr.io/norviq-dev/norviq-mcp-proxy:0.2.6":                             "ghcr.io/norviq-dev/norviq-mcp-proxy",
		"ghcr.io/norviq-dev/norviq-mcp-proxy@sha256:" + strings.Repeat("c", 64): "ghcr.io/norviq-dev/norviq-mcp-proxy",
		"registry.local:5000/payload:1":                                         "registry.local:5000/payload",
		"registry.local:5000/payload":                                           "registry.local:5000/payload",
		"docker.io/library/payload:1":                                           "payload",
		"payload":                                                               "payload",
	}
	for in, want := range cases {
		if got := imageRepository(in); got != want {
			t.Errorf("imageRepository(%q) = %q, want %q", in, got, want)
		}
	}
}
