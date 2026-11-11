// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// Tests for MCP action-firewall injection. Where it matters these APPLY the emitted JSON patch and
// assert the resulting pod, rather than counting patch ops: the thing that must be true is that the
// container actually execs the proxy, and an op-count assertion can pass while the patch is invalid.
package main

import (
	"encoding/json"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"

	jsonpatch "gopkg.in/evanphx/json-patch.v4"
	admissionv1 "k8s.io/api/admission/v1"
)

// mcpTestConfig is a config with MCP injection on and a signing secret present, so the minted
// service token path is exercised too.
func mcpTestConfig() Config {
	cfg := LoadConfig()
	cfg.McpInject = true
	cfg.ApiSecret = "test-secret-for-sidecar-token-mint"
	// Required now: there is no safe default proxy image (the engine image carries no payload).
	cfg.McpProxyImage = "ghcr.io/norviq-dev/norviq-mcp-proxy:test"
	return cfg
}

// applyPatch runs the injector over pod and returns the mutated pod, exactly as the API server would.
func applyPatch(t *testing.T, cfg Config, pod *corev1.Pod, agentClass, namespace string) *corev1.Pod {
	t.Helper()
	patchBytes, err := NewInjector(cfg).CreatePatch(pod, agentClass, namespace)
	if err != nil {
		t.Fatalf("create patch failed: %v", err)
	}
	patch, err := jsonpatch.DecodePatch(patchBytes)
	if err != nil {
		t.Fatalf("emitted patch is not a valid JSON patch: %v\n%s", err, patchBytes)
	}
	original, err := json.Marshal(pod)
	if err != nil {
		t.Fatalf("marshal pod: %v", err)
	}
	mutated, err := patch.Apply(original)
	if err != nil {
		t.Fatalf("patch did not apply: %v\npatch: %s", err, patchBytes)
	}
	var out corev1.Pod
	if err := json.Unmarshal(mutated, &out); err != nil {
		t.Fatalf("unmarshal mutated pod: %v", err)
	}
	return &out
}

func mcpPod(annotations map[string]string, containers []corev1.Container) *corev1.Pod {
	pod := testPodWithContainers(nil, containers)
	pod.Annotations = annotations
	return pod
}

func containerByName(pod *corev1.Pod, name string) (corev1.Container, bool) {
	for _, c := range pod.Spec.Containers {
		if c.Name == name {
			return c, true
		}
	}
	for _, c := range pod.Spec.InitContainers {
		if c.Name == name {
			return c, true
		}
	}
	return corev1.Container{}, false
}

func joinCmd(c corev1.Container) string { return strings.Join(c.Command, " ") }

// -- the core rewrite ----------------------------------------------------------------------------

func TestMcpInjection_WrapsCommandAndArgs(t *testing.T) {
	pod := mcpPod(
		map[string]string{mcpServersAnnotation: "mcp"},
		[]corev1.Container{
			{Name: "agent", Command: []string{"python", "agent.py"}},
			{Name: "mcp", Command: []string{"npx"}, Args: []string{"-y", "@modelcontextprotocol/server-filesystem", "/work"}},
		},
	)
	out := applyPatch(t, mcpTestConfig(), pod, "sales", "agents")

	mcp, ok := containerByName(out, "mcp")
	if !ok {
		t.Fatal("mcp container missing from mutated pod")
	}
	want := mcpProxyBinary + " --server-id mcp -- npx -y @modelcontextprotocol/server-filesystem /work"
	if got := joinCmd(mcp); got != want {
		t.Fatalf("command not wrapped as expected\n got: %s\nwant: %s", got, want)
	}
	// args must be emptied: with `command` set and `args` empty Kubernetes ignores the image CMD, so
	// the effective argv is exactly the command above. A leftover args would append stray tokens.
	if len(mcp.Args) != 0 {
		t.Fatalf("expected args cleared after folding into command, got %v", mcp.Args)
	}
	// the un-annotated container must be untouched apart from the ordinary sidecar wiring
	agent, _ := containerByName(out, "agent")
	if joinCmd(agent) != "python agent.py" {
		t.Fatalf("non-MCP container was rewritten: %v", agent.Command)
	}
}

func TestMcpInjection_DeliversProxyViaInitContainer(t *testing.T) {
	pod := mcpPod(
		map[string]string{mcpServersAnnotation: "mcp"},
		[]corev1.Container{{Name: "mcp", Command: []string{"mcp-server"}}},
	)
	out := applyPatch(t, mcpTestConfig(), pod, "sales", "agents")

	init, ok := containerByName(out, mcpInitContainerName)
	if !ok {
		t.Fatal("MCP init container was not injected")
	}
	if !strings.Contains(joinCmd(init), mcpTestConfig().McpProxySourcePath) {
		t.Fatalf("init container does not copy the proxy: %v", init.Command)
	}
	var found bool
	for _, v := range out.Spec.Volumes {
		if v.Name == mcpVolumeName {
			found = true
			if v.EmptyDir == nil {
				t.Fatal("proxy volume should be an emptyDir")
			}
		}
	}
	if !found {
		t.Fatalf("proxy volume %s missing", mcpVolumeName)
	}
	// The app container must mount it READ-ONLY: it only needs to exec the payload, and a writable
	// mount would let the governed workload replace its own firewall.
	mcp, _ := containerByName(out, "mcp")
	var mounted bool
	for _, m := range mcp.VolumeMounts {
		if m.Name == mcpVolumeName {
			mounted = true
			if !m.ReadOnly {
				t.Fatal("MCP container mounts the proxy volume writable; it must be readOnly")
			}
		}
	}
	if !mounted {
		t.Fatal("MCP container does not mount the proxy volume")
	}
}

// Regression: the MCP mount patch must APPEND to volumeMounts, never create the list. Deriving
// create-vs-append from the original container emitted a second "add /volumeMounts" that replaced
// the list the sidecar's socket-mount patch had just created — leaving the MCP container mounting the
// proxy but NOT the enforcement socket, i.e. wrapped but unwired. Only caught by applying the patch.
func TestMcpInjection_KeepsSocketWiringOnTargetContainer(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mounts []corev1.VolumeMount
		env    []corev1.EnvVar
	}{
		{"container with no mounts or env", nil, nil},
		{"container with pre-existing mounts and env",
			[]corev1.VolumeMount{{Name: "data", MountPath: "/data"}},
			[]corev1.EnvVar{{Name: "HOME", Value: "/root"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := applyPatch(t, mcpTestConfig(), mcpPod(
				map[string]string{mcpServersAnnotation: "mcp"},
				[]corev1.Container{{Name: "mcp", Command: []string{"mcp-server"}, VolumeMounts: tc.mounts, Env: tc.env}},
			), "sales", "agents")

			mcp, _ := containerByName(out, "mcp")
			if !containerWired(mcp) {
				t.Fatalf("wrapped MCP container lost its enforcement wiring: mounts=%v env=%v",
					mcp.VolumeMounts, mcp.Env)
			}
			if !mountsMcpProxyVolumeReadOnly(mcp) {
				t.Fatalf("wrapped MCP container lost the proxy mount: %v", mcp.VolumeMounts)
			}
			for _, m := range tc.mounts {
				if !hasMount(mcp, m.Name) {
					t.Fatalf("pre-existing mount %q was dropped: %v", m.Name, mcp.VolumeMounts)
				}
			}
			for _, e := range tc.env {
				if _, ok := envValue(mcp, e.Name); !ok {
					t.Fatalf("pre-existing env %q was dropped: %v", e.Name, mcp.Env)
				}
			}
		})
	}
}

func hasMount(c corev1.Container, name string) bool {
	for _, m := range c.VolumeMounts {
		if m.Name == name {
			return true
		}
	}
	return false
}

func TestMcpInjection_WiresEngineEnv(t *testing.T) {
	cfg := mcpTestConfig()
	out := applyPatch(t, cfg, mcpPod(
		map[string]string{mcpServersAnnotation: "mcp"},
		[]corev1.Container{{Name: "mcp", Command: []string{"mcp-server"}}},
	), "sales", "agents")

	mcp, _ := containerByName(out, "mcp")
	env := map[string]string{}
	for _, e := range mcp.Env {
		env[e.Name] = e.Value
	}
	for name, want := range map[string]string{
		"NRVQ_API_URL":       cfg.ApiURL,
		"NRVQ_NAMESPACE":     "agents",
		"NRVQ_AGENT_CLASS":   "sales",
		"NRVQ_MCP_PIN_STORE": cfg.McpPinStore,
		"NRVQ_MCP_PIN_MODE":  cfg.McpPinMode,
	} {
		if env[name] != want {
			t.Fatalf("env %s = %q, want %q", name, env[name], want)
		}
	}
	if env["NRVQ_API_TOKEN"] == "" {
		t.Fatal("expected a minted service token for the MCP proxy")
	}
}

func TestMcpInjection_ServerIDOverrideKeysThePins(t *testing.T) {
	pod := mcpPod(map[string]string{
		mcpServersAnnotation:      "mcp",
		mcpServerIDPrefix + "mcp": "github-prod",
	}, []corev1.Container{{Name: "mcp", Command: []string{"mcp-server"}}})
	out := applyPatch(t, mcpTestConfig(), pod, "sales", "agents")

	mcp, _ := containerByName(out, "mcp")
	if !strings.Contains(joinCmd(mcp), "--server-id github-prod") {
		t.Fatalf("server-id override not applied: %v", mcp.Command)
	}
}

func TestMcpInjection_WrapsInitContainerTarget(t *testing.T) {
	pod := testPodWithContainers(nil, []corev1.Container{{Name: "agent", Command: []string{"agent"}}})
	pod.Annotations = map[string]string{mcpServersAnnotation: "mcp-init"}
	pod.Spec.InitContainers = []corev1.Container{{Name: "mcp-init", Command: []string{"mcp-server"}}}
	out := applyPatch(t, mcpTestConfig(), pod, "sales", "agents")

	target, ok := containerByName(out, "mcp-init")
	if !ok {
		t.Fatal("init container target missing")
	}
	if !isMcpProxyCommand(target.Command) {
		t.Fatalf("init container target not wrapped: %v", target.Command)
	}
}

// -- fail-closed refusals ------------------------------------------------------------------------

// A container with no explicit command cannot be wrapped: its real argv is the image ENTRYPOINT,
// which admission cannot see. Refusing is the point — the alternative is a silently ungoverned server.
func TestMcpInjection_DeniesContainerWithNoExplicitCommand(t *testing.T) {
	pod := mcpPod(
		map[string]string{mcpServersAnnotation: "mcp"},
		[]corev1.Container{{Name: "mcp", Args: []string{"--port", "9000"}}},
	)
	_, err := NewInjector(mcpTestConfig()).CreatePatch(pod, "sales", "agents")
	if err == nil {
		t.Fatal("expected refusal for a container with no explicit command")
	}
	var mcpErr *mcpConfigError
	if !asMcpConfigError(err, &mcpErr) {
		t.Fatalf("expected a *mcpConfigError so the handler can surface it, got %T", err)
	}
	if !strings.Contains(err.Error(), "ENTRYPOINT") {
		t.Fatalf("refusal should tell the operator why: %v", err)
	}
}

func TestMcpInjection_DeniesUnknownContainerName(t *testing.T) {
	pod := mcpPod(
		map[string]string{mcpServersAnnotation: "typo"},
		[]corev1.Container{{Name: "mcp", Command: []string{"mcp-server"}}},
	)
	_, err := NewInjector(mcpTestConfig()).CreatePatch(pod, "sales", "agents")
	if err == nil {
		t.Fatal("expected refusal when the annotation names a container the pod does not have")
	}
}

// -- feature-off byte-identity -------------------------------------------------------------------

// With McpInject off the emitted patch must be exactly what it was before this path existed, even
// for a pod carrying the annotation. This is the upgrade-safety guarantee.
func TestMcpInjection_OffEmitsIdenticalPatch(t *testing.T) {
	makePod := func() *corev1.Pod {
		return mcpPod(
			map[string]string{mcpServersAnnotation: "mcp"},
			[]corev1.Container{{Name: "mcp", Command: []string{"mcp-server"}}},
		)
	}
	off := LoadConfig()
	off.McpInject = false

	withAnnotation, err := NewInjector(off).CreatePatch(makePod(), "sales", "agents")
	if err != nil {
		t.Fatalf("create patch failed: %v", err)
	}
	// An unrelated annotation, not NO annotations: injectedAnnotationPatch legitimately emits a
	// different op shape for a pod with an empty annotation map, and that difference is not ours.
	bare := makePod()
	bare.Annotations = map[string]string{"example.com/unrelated": "x"}
	without, err := NewInjector(off).CreatePatch(bare, "sales", "agents")
	if err != nil {
		t.Fatalf("create patch failed: %v", err)
	}
	if string(withAnnotation) != string(without) {
		t.Fatalf("MCP annotation changed the patch while McpInject is off\n with: %s\nwithout: %s",
			withAnnotation, without)
	}
}

// -- re-admission and enforcement integrity ------------------------------------------------------

// admitMcp sends pod through the admission handler under cfg.
func admitMcp(t *testing.T, cfg Config, pod *corev1.Pod) admissionv1.AdmissionReview {
	t.Helper()
	return sendReview(t, NewHandler(cfg), makeReviewFromPod(*pod, gvkPod(), "agents"))
}

// Rewritten: this asserted that re-admitting the injector's own MCP output was SKIPPED. The webhook is
// CREATE-only, so such a pod is a copied spec, and it is now refused.
func TestMcpInjection_ReadmissionOfOwnOutputIsRefused(t *testing.T) {
	cfg := mcpTestConfig()
	out := applyPatch(t, cfg, mcpPod(
		map[string]string{mcpServersAnnotation: "mcp"},
		[]corev1.Container{{Name: "mcp", Command: []string{"mcp-server"}}},
	), "sales", "agents")
	assertRefusedAsCopy(t, admitMcp(t, cfg, out))
}

// A pod with a correct sidecar but an UNWRAPPED MCP container must not be admitted unpatched — that
// server would run unpoliced. (Rewritten from a fullyInjected check, which no longer exists: the pod is
// refused for carrying the sidecar at all.)
func TestMcpInjection_SidecarWithoutWrapIsRefused(t *testing.T) {
	cfg := mcpTestConfig()
	out := applyPatch(t, cfg, mcpPod(
		map[string]string{mcpServersAnnotation: "mcp"},
		[]corev1.Container{{Name: "mcp", Command: []string{"mcp-server"}}},
	), "sales", "agents")

	// unwrap it, leaving every other piece of injection in place
	for i := range out.Spec.Containers {
		if out.Spec.Containers[i].Name == "mcp" {
			out.Spec.Containers[i].Command = []string{"mcp-server"}
		}
	}
	assertRefusedAsCopy(t, admitMcp(t, cfg, out))
}

// A proxy-shaped command with the server id swung elsewhere pins against a catalogue the operator
// never approved, so it must not read as already-governed. (Rewritten from an mcpFullyInjected check to
// the admission outcome.)
func TestMcpInjection_ForeignServerIDIsRefused(t *testing.T) {
	cfg := mcpTestConfig()
	out := applyPatch(t, cfg, mcpPod(
		map[string]string{mcpServersAnnotation: "mcp"},
		[]corev1.Container{{Name: "mcp", Command: []string{"mcp-server"}}},
	), "sales", "agents")

	for i := range out.Spec.Containers {
		if out.Spec.Containers[i].Name == "mcp" {
			out.Spec.Containers[i].Command = []string{mcpProxyBinary, "--server-id", "attacker", "--", "mcp-server"}
		}
	}
	assertRefusedAsCopy(t, admitMcp(t, cfg, out))
}

// Rewritten from classifyPod verdicts to injectorPlumbing, which replaced it; the outcome (refused) is
// unchanged for every case.
func TestMcpInjection_PreOccupiedPlumbingIsDenied(t *testing.T) {
	cfg := mcpTestConfig()
	cases := []struct {
		name string
		pod  func() *corev1.Pod
	}{
		{"proxy volume", func() *corev1.Pod {
			p := mcpPod(nil, []corev1.Container{{Name: "app"}})
			p.Spec.Volumes = []corev1.Volume{{Name: mcpVolumeName}}
			return p
		}},
		{"proxy mount", func() *corev1.Pod {
			return mcpPod(nil, []corev1.Container{{Name: "app",
				VolumeMounts: []corev1.VolumeMount{{Name: "x", MountPath: mcpMountPath}}}})
		}},
		{"proxy command", func() *corev1.Pod {
			return mcpPod(nil, []corev1.Container{{Name: "app", Command: []string{mcpProxyBinary, "--", "sh"}}})
		}},
		{"init container name", func() *corev1.Pod {
			p := mcpPod(nil, []corev1.Container{{Name: "app"}})
			p.Spec.InitContainers = []corev1.Container{{Name: mcpInitContainerName, Image: "attacker/x"}}
			return p
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, reason, found := injectorPlumbing(cfg, tc.pod()); !found {
				t.Fatalf("pre-occupied %s: not found (%s), want refused", tc.name, reason)
			}
			if resp := admitMcp(t, cfg, tc.pod()); resp.Response.Allowed {
				t.Fatalf("pre-occupied %s was admitted", tc.name)
			}
		})
	}
}

// The same pre-occupied plumbing must NOT change admission when the feature is off, so enabling MCP
// injection is the only thing that changes behavior. (Rewritten from classifyPod to the admission
// outcome: the pod is injected.)
func TestMcpInjection_PreOccupiedPlumbingIgnoredWhenOff(t *testing.T) {
	off := LoadConfig()
	off.McpInject = false
	pod := mcpPod(nil, []corev1.Container{{Name: "app", Command: []string{mcpProxyBinary, "--", "sh"}}})
	if _, reason, found := injectorPlumbing(off, pod); found {
		t.Fatalf("with McpInject off an MCP-shaped command must not affect admission, got %s", reason)
	}
	if resp := admitMcp(t, off, pod); !resp.Response.Allowed || resp.Response.Patch == nil {
		t.Fatal("with McpInject off the pod must be injected")
	}
}

// A copy of the injector's output whose init container was changed to copy nothing. (Rewritten: the
// exact-match recognizer of the injector's own init container no longer exists; the copy is refused.)
func TestMcpInjection_DecoyInitContainerStillDenied(t *testing.T) {
	cfg := mcpTestConfig()
	out := applyPatch(t, cfg, mcpPod(
		map[string]string{mcpServersAnnotation: "mcp"},
		[]corev1.Container{{Name: "mcp", Command: []string{"mcp-server"}}},
	), "sales", "agents")

	for i := range out.Spec.InitContainers {
		if out.Spec.InitContainers[i].Name == mcpInitContainerName {
			out.Spec.InitContainers[i].Command = []string{"/bin/sh", "-c", "true"} // copies nothing
		}
	}
	assertRefusedAsCopy(t, admitMcp(t, cfg, out))
}

// -- annotation parsing --------------------------------------------------------------------------

func TestMcpAnnotatedNames(t *testing.T) {
	pod := &corev1.Pod{}
	pod.Annotations = map[string]string{mcpServersAnnotation: " a , b ,, a , c "}
	got := mcpAnnotatedNames(pod)
	want := []string{"a", "b", "c"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

// asMcpConfigError keeps the errors.As call out of the assertion so the test reads cleanly.
func asMcpConfigError(err error, target **mcpConfigError) bool {
	e, ok := err.(*mcpConfigError)
	if ok {
		*target = e
	}
	return ok
}

// -- regressions from the adversarial review -----------------------------------------------------

// THE BYPASS. Recognizing the delivery init container by NAME alone let a tenant hand-build a pod
// that looked fully injected, be admitted UNPATCHED, and run an MCP server through a three-line
// shell shim of their own instead of the firewall. Nothing in this pod requires anything only the
// webhook can produce — no minted JWT, no CA material — which is exactly why name-shaped plumbing is
// not evidence of injection.
func TestMcpInjection_SelfWiredPodWithFakeProxyIsDenied(t *testing.T) {
	cfg := mcpTestConfig()
	pod := mcpPod(map[string]string{mcpServersAnnotation: "mcp"}, []corev1.Container{
		{
			Name:         "norviq-sidecar",
			Image:        configuredSidecarImage(cfg),
			Env:          []corev1.EnvVar{{Name: "NRVQ_SIDECAR_MODE", Value: "proxy"}, {Name: "NRVQ_API_URL", Value: cfg.ApiURL}, {Name: "NRVQ_SOCKET_PATH", Value: socketFilePath}},
			VolumeMounts: []corev1.VolumeMount{{Name: "norviq-socket", MountPath: socketMountPath}},
		},
		{
			Name:  "mcp",
			Image: "docker.io/attacker/mcp:1",
			// looks proxied; the binary it execs is the tenant's own shim
			Command: []string{mcpProxyBinary, "--server-id", "mcp", "--", "mcp-server"},
			Env: []corev1.EnvVar{{Name: "NRVQ_SOCKET_PATH", Value: socketFilePath},
				{Name: "NRVQ_API_URL", Value: cfg.ApiURL},
				{Name: "NRVQ_MCP_PIN_STORE", Value: cfg.McpPinStore},
				{Name: "NRVQ_MCP_PIN_MODE", Value: cfg.McpPinMode}},
			VolumeMounts: []corev1.VolumeMount{
				{Name: mcpVolumeName, MountPath: mcpMountPath, ReadOnly: true},
				{Name: "norviq-socket", MountPath: socketMountPath}},
		},
	})
	pod.Spec.Volumes = []corev1.Volume{
		{Name: "norviq-socket", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
		{Name: mcpVolumeName, VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
	}
	pod.Spec.InitContainers = []corev1.Container{{
		Name:  mcpInitContainerName, // injector-owned NAME, tenant image and command
		Image: "docker.io/attacker/payload:1",
		Command: []string{"/bin/sh", "-c",
			`printf '#!/bin/sh\nshift 3\nexec "$@"\n' > /stage/norviq-mcp; chmod 755 /stage/norviq-mcp`},
		Env:          []corev1.EnvVar{{Name: "NRVQ_SOCKET_PATH", Value: socketFilePath}},
		VolumeMounts: []corev1.VolumeMount{{Name: mcpVolumeName, MountPath: "/stage"}, {Name: "norviq-socket", MountPath: socketMountPath}},
	}}

	// Rewritten from mcpFullyInjected/classifyPod to the admission outcome: refused.
	assertRefusedAsCopy(t, admitMcp(t, cfg, pod))
}

func TestMcpInjection_UntrustedDeliveryPlumbingIsRejected(t *testing.T) {
	cfg := mcpTestConfig()
	base := func() *corev1.Pod {
		return applyPatch(t, cfg, mcpPod(
			map[string]string{mcpServersAnnotation: "mcp"},
			[]corev1.Container{{Name: "mcp", Command: []string{"mcp-server"}}},
		), "sales", "agents")
	}
	cases := map[string]func(*corev1.Pod){
		"hostPath delivery volume": func(p *corev1.Pod) {
			for i := range p.Spec.Volumes {
				if p.Spec.Volumes[i].Name == mcpVolumeName {
					p.Spec.Volumes[i].VolumeSource = corev1.VolumeSource{
						HostPath: &corev1.HostPathVolumeSource{Path: "/tmp/evil"}}
				}
			}
		},
		"writable proxy mount": func(p *corev1.Pod) {
			for i := range p.Spec.Containers {
				for j := range p.Spec.Containers[i].VolumeMounts {
					if p.Spec.Containers[i].VolumeMounts[j].Name == mcpVolumeName {
						p.Spec.Containers[i].VolumeMounts[j].ReadOnly = false
					}
				}
			}
		},
		"routing swung at another engine": func(p *corev1.Pod) {
			for i := range p.Spec.Containers {
				if p.Spec.Containers[i].Name == "mcp" {
					p.Spec.Containers[i].Env = append(p.Spec.Containers[i].Env,
						corev1.EnvVar{Name: "NRVQ_API_URL", Value: "http://attacker.local:8080"})
				}
			}
		},
		"pin mode weakened locally": func(p *corev1.Pod) {
			for i := range p.Spec.Containers {
				if p.Spec.Containers[i].Name == "mcp" {
					p.Spec.Containers[i].Env = append(p.Spec.Containers[i].Env,
						corev1.EnvVar{Name: "NRVQ_MCP_PIN_MODE", Value: "off"})
				}
			}
		},
		"payload source shadowed in the init container": func(p *corev1.Pod) {
			for i := range p.Spec.InitContainers {
				if p.Spec.InitContainers[i].Name == mcpInitContainerName {
					p.Spec.InitContainers[i].VolumeMounts = append(p.Spec.InitContainers[i].VolumeMounts,
						corev1.VolumeMount{Name: "shadow", MountPath: cfg.McpProxySourcePath})
				}
			}
		},
	}
	// Rewritten from mcpFullyInjected to the admission outcome: every tampered copy is refused.
	for name, tamper := range cases {
		t.Run(name, func(t *testing.T) {
			pod := base()
			tamper(pod)
			assertRefusedAsCopy(t, admitMcp(t, cfg, pod))
		})
	}
}

// Init containers run in order, so the payload must be staged before anything that execs it.
func TestMcpInjection_DeliveryInitContainerRunsBeforeWrappedTarget(t *testing.T) {
	pod := testPodWithContainers(nil, []corev1.Container{{Name: "agent", Command: []string{"agent"}}})
	pod.Annotations = map[string]string{mcpServersAnnotation: "mcp-init"}
	pod.Spec.InitContainers = []corev1.Container{{Name: "mcp-init", Command: []string{"mcp-server"}}}
	out := applyPatch(t, mcpTestConfig(), pod, "sales", "agents")

	var deliveryAt, targetAt = -1, -1
	for i, c := range out.Spec.InitContainers {
		switch c.Name {
		case mcpInitContainerName:
			deliveryAt = i
		case "mcp-init":
			targetAt = i
		}
	}
	if deliveryAt < 0 || targetAt < 0 {
		t.Fatalf("expected both init containers, got %v", out.Spec.InitContainers)
	}
	if deliveryAt > targetAt {
		t.Fatalf("payload is staged at index %d but the wrapped target runs at %d — it would exec a "+
			"binary that does not exist yet", deliveryAt, targetAt)
	}
	// the shift must not have corrupted the wrapped target
	if !isMcpProxyCommand(out.Spec.InitContainers[targetAt].Command) {
		t.Fatalf("wrapped init container lost its wrapping: %v", out.Spec.InitContainers[targetAt].Command)
	}
	if !containerWired(out.Spec.InitContainers[targetAt]) {
		t.Fatalf("wrapped init container lost its socket wiring: %v", out.Spec.InitContainers[targetAt])
	}
}

// The engine image carries the norviq package, not the frozen payload, so falling back to it
// produced pods whose init container could never succeed. Unset is a refusal, not a default.
func TestMcpInjection_RequiresAnExplicitProxyImage(t *testing.T) {
	cfg := mcpTestConfig()
	cfg.McpProxyImage = ""
	_, err := NewInjector(cfg).CreatePatch(mcpPod(
		map[string]string{mcpServersAnnotation: "mcp"},
		[]corev1.Container{{Name: "mcp", Command: []string{"mcp-server"}}},
	), "sales", "agents")
	if err == nil {
		t.Fatal("expected refusal when no MCP proxy image is configured")
	}
	if !strings.Contains(err.Error(), "NRVQ_MCP_PROXY_IMAGE") {
		t.Fatalf("refusal should name the setting to fix: %v", err)
	}
}

// The injector's output under one proxy image tag, submitted again after the tag rolled.
//
// Rewritten: this asserted SKIP across the roll. Re-submitting the injector's output is refused under
// every configuration now, so the roll changes nothing.
func TestMcpInjection_ImageTagRollIsRefused(t *testing.T) {
	cfg := mcpTestConfig()
	out := applyPatch(t, cfg, mcpPod(
		map[string]string{mcpServersAnnotation: "mcp"},
		[]corev1.Container{{Name: "mcp", Command: []string{"mcp-server"}}},
	), "sales", "agents")

	rolled := cfg
	rolled.McpProxyImage = "ghcr.io/norviq-dev/norviq-mcp-proxy:v2"
	assertRefusedAsCopy(t, admitMcp(t, rolled, out))
}

func TestMcpInjection_NoDuplicateSpiffeEnv(t *testing.T) {
	cfg := mcpTestConfig()
	cfg.SpiffeInject = true
	out := applyPatch(t, cfg, mcpPod(
		map[string]string{mcpServersAnnotation: "mcp"},
		[]corev1.Container{{Name: "mcp", Command: []string{"mcp-server"}}},
	), "sales", "agents")

	mcp, _ := containerByName(out, "mcp")
	counts := map[string]int{}
	for _, e := range mcp.Env {
		counts[e.Name]++
	}
	for _, name := range []string{"NRVQ_SPIFFE_MODE", "NRVQ_SPIFFE_SOCKET", "NRVQ_SOCKET_PATH"} {
		if counts[name] > 1 {
			t.Fatalf("env %s appears %d times on the wrapped container", name, counts[name])
		}
	}
}
