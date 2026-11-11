// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
package main

// A pod that already carries any part the injector adds is refused at CREATE (injector_owned.go):
// NRVQ-WHK-4063 for the injector's own parts, NRVQ-WHK-4034 for something of the pod's own placed at a
// path the injector mounts at. A pod with none of them is injected exactly as before, opt-outs included.
//
// Each part is tested ALONE on an otherwise fresh pod, with the part named in the message, so a denial
// cannot come from some other part of the fixture. The copies of the injector's output with one thing
// changed (handler_injector_owned_copies_test.go) carry every part at once and only need the code.
//
// Everything goes through the admission handler, so the namespace and agent class are the ones the
// handler derives from the request.

import (
	"encoding/json"
	"strings"
	"testing"

	jsonpatch "gopkg.in/evanphx/json-patch.v4"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	integrityNamespace      = "team-a"
	serviceAccountTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount"
	mcpIntegrityProxyImage  = "ghcr.io/norviq-dev/norviq-mcp-proxy:0.2.6"
	codeOwnedPart           = "NRVQ-WHK-4063"
	codePathOccupied        = "NRVQ-WHK-4034"
)

// integrityPod is a Deployment-owned agent pod with an agent class, so the injected sidecar carries a
// workload, a class and (with a signing secret) a bound token.
func integrityPod() corev1.Pod {
	return corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "checkout-7d9f8b5c4-x2x9q",
			Labels: map[string]string{"norviq.io/agent-class": "support"},
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "checkout-7d9f8b5c4", UID: "rs-uid",
			}},
		},
		Spec: corev1.PodSpec{Containers: []corev1.Container{
			{Name: "agent", Image: "mycorp/agent:v1", Command: []string{"/agent"}},
		}},
	}
}

// integrityConfig is the proxy-mode default with a signing secret and the outage posture set to block.
func integrityConfig() Config {
	cfg := LoadConfig()
	cfg.ApiSecret = "integrity-test-signing-secret"
	cfg.FallbackMode = "block"
	return cfg
}

func mcpIntegrityConfig() Config {
	cfg := integrityConfig()
	cfg.McpInject = true
	cfg.McpProxyImage = mcpIntegrityProxyImage
	return cfg
}

func spiffeIntegrityConfig() Config {
	cfg := integrityConfig()
	cfg.SpiffeInject = true
	return cfg
}

func tlsIntegrityConfig(caFile, keyFile string) Config {
	cfg := integrityConfig()
	cfg.InternalTLS = true
	cfg.CACertFile = caFile
	cfg.CAKeyFile = keyFile
	return cfg
}

func withSidecarImage(cfg Config, image string) Config {
	cfg.SidecarImage = image
	cfg.Runtime = &RuntimeConfig{}
	cfg.Runtime.SetSidecarImage(image)
	return cfg
}

// mcpIntegrityPod is integrityPod with one stdio MCP server container named for wrapping.
func mcpIntegrityPod() corev1.Pod {
	p := integrityPod()
	p.Annotations = map[string]string{mcpServersAnnotation: "mcp"}
	p.Spec.Containers = append(p.Spec.Containers,
		corev1.Container{Name: "mcp", Image: "node:22", Command: []string{"npx", "server-github"}})
	return p
}

// injectorOutput runs pod through the injector with the agent class the handler would use, applies the
// patch exactly as the API server would, and returns the admitted pod.
func injectorOutput(t *testing.T, cfg Config, pod corev1.Pod, writer SecretWriter) corev1.Pod {
	t.Helper()
	agentClass := pod.Labels[cfg.AgentClassLabel]
	if !isValidLabel(agentClass) {
		agentClass = ""
	}
	inj := NewInjector(cfg)
	if writer != nil {
		inj.SetSecretWriter(writer)
	}
	patchBytes, err := inj.CreatePatch(&pod, agentClass, integrityNamespace)
	if err != nil {
		t.Fatalf("create patch: %v", err)
	}
	return applyJSONPatch(t, pod, patchBytes)
}

func applyJSONPatch(t *testing.T, pod corev1.Pod, patchBytes []byte) corev1.Pod {
	t.Helper()
	patch, err := jsonpatch.DecodePatch(patchBytes)
	if err != nil {
		t.Fatalf("decode patch: %v", err)
	}
	raw, err := json.Marshal(pod)
	if err != nil {
		t.Fatalf("marshal pod: %v", err)
	}
	mutated, err := patch.Apply(raw)
	if err != nil {
		t.Fatalf("apply patch: %v", err)
	}
	var out corev1.Pod
	if err := json.Unmarshal(mutated, &out); err != nil {
		t.Fatalf("unmarshal mutated pod: %v", err)
	}
	return out
}

func admitPod(t *testing.T, cfg Config, pod corev1.Pod) (allowed bool, patch []byte, message string) {
	t.Helper()
	resp := sendReview(t, NewHandler(cfg), makeReviewFromPod(pod, gvkPod(), integrityNamespace))
	if resp.Response.Result != nil {
		message = resp.Response.Result.Message
	}
	return resp.Response.Allowed, resp.Response.Patch, message
}

// assertDenied requires a refusal with no patch, under code, with want in the message.
func assertDenied(t *testing.T, cfg Config, pod corev1.Pod, code, want string) {
	t.Helper()
	allowed, patch, msg := admitPod(t, cfg, pod)
	if allowed || patch != nil {
		t.Fatalf("expected a refusal under %s; allowed=%v patched=%v message=%q", code, allowed, patch != nil, msg)
	}
	if !strings.HasPrefix(msg, code+": ") {
		t.Fatalf("refused, but not under %s: %q", code, msg)
	}
	if !strings.Contains(msg, want) {
		t.Fatalf("refused for another reason; want %q in %q", want, msg)
	}
}

// assertCopyDenied is the outcome for any pod carrying the injector's output: refused under 4063, with
// the instruction to remove the injected parts.
func assertCopyDenied(t *testing.T, cfg Config, pod corev1.Pod) {
	t.Helper()
	assertDenied(t, cfg, pod, codeOwnedPart, "Remove the injected parts from the spec and create the pod again")
}

func assertInjected(t *testing.T, cfg Config, pod corev1.Pod) corev1.Pod {
	t.Helper()
	allowed, patch, msg := admitPod(t, cfg, pod)
	if !allowed || patch == nil {
		t.Fatalf("expected the pod to be injected; allowed=%v patched=%v message=%q", allowed, patch != nil, msg)
	}
	return applyJSONPatch(t, pod, patch)
}

func sidecarIn(t *testing.T, pod *corev1.Pod) *corev1.Container {
	t.Helper()
	return containerIn(t, pod, injectedSidecarName)
}

func containerIn(t *testing.T, pod *corev1.Pod, name string) *corev1.Container {
	t.Helper()
	for i := range pod.Spec.InitContainers {
		if pod.Spec.InitContainers[i].Name == name {
			return &pod.Spec.InitContainers[i]
		}
	}
	for i := range pod.Spec.Containers {
		if pod.Spec.Containers[i].Name == name {
			return &pod.Spec.Containers[i]
		}
	}
	t.Fatalf("pod has no container %s", name)
	return nil
}

func mcpDeliveryIn(t *testing.T, pod *corev1.Pod) *corev1.Container {
	t.Helper()
	return containerIn(t, pod, mcpInitContainerName)
}

func setEnv(c *corev1.Container, name, value string) {
	for i := range c.Env {
		if c.Env[i].Name == name {
			c.Env[i] = corev1.EnvVar{Name: name, Value: value}
			return
		}
	}
	c.Env = append(c.Env, corev1.EnvVar{Name: name, Value: value})
}

func appendEnv(c *corev1.Container, name, value string) {
	c.Env = append(c.Env, corev1.EnvVar{Name: name, Value: value})
}

func removeEnv(c *corev1.Container, name string) {
	kept := c.Env[:0]
	for _, e := range c.Env {
		if e.Name != name {
			kept = append(kept, e)
		}
	}
	c.Env = kept
}

func envOn(c *corev1.Container, name string) (corev1.EnvVar, bool) {
	for _, e := range c.Env {
		if e.Name == name {
			return e, true
		}
	}
	return corev1.EnvVar{}, false
}

// envValue is the EFFECTIVE value of an env var: the last occurrence, as Kubernetes resolves it.
func envValue(c corev1.Container, name string) (string, bool) {
	val, found := "", false
	for _, e := range c.Env {
		if e.Name == name {
			val, found = e.Value, true
		}
	}
	return val, found
}

// containerWired reports whether the injector wired c to the enforcement socket: the socket volume at
// socketMountPath and NRVQ_SOCKET_PATH pointing at the socket file.
func containerWired(c corev1.Container) bool {
	mounted := false
	for _, m := range c.VolumeMounts {
		if m.Name == socketVolumeName && m.MountPath == socketMountPath {
			mounted = true
		}
	}
	v, ok := envValue(c, "NRVQ_SOCKET_PATH")
	return mounted && ok && v == socketFilePath
}

func mountsMcpProxyVolumeReadOnly(c corev1.Container) bool {
	for _, m := range c.VolumeMounts {
		if m.Name == mcpVolumeName && m.MountPath == mcpMountPath {
			return m.ReadOnly
		}
	}
	return false
}

func replaceVolume(pod *corev1.Pod, name string, src corev1.VolumeSource) {
	for i := range pod.Spec.Volumes {
		if pod.Spec.Volumes[i].Name == name {
			pod.Spec.Volumes[i].VolumeSource = src
		}
	}
}

func addVolume(pod *corev1.Pod, name string) {
	pod.Spec.Volumes = append(pod.Spec.Volumes, corev1.Volume{Name: name,
		VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}})
}

func addPVC(pod *corev1.Pod, name string) {
	pod.Spec.Volumes = append(pod.Spec.Volumes, corev1.Volume{Name: name, VolumeSource: corev1.VolumeSource{
		PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: name}}})
}

func ptrInt32(v int32) *int32 { return &v }
func ptrInt64(v int64) *int64 { return &v }
func ptrBool(v bool) *bool    { return &v }

// --- each injector-owned part, alone on a fresh pod ------------------------------------------------

func TestInjectorOwned_EachPartAloneIsDenied(t *testing.T) {
	always := corev1.ContainerRestartPolicyAlways
	engine := func(cfg Config, name string) corev1.Container {
		return corev1.Container{Name: name, Image: configuredSidecarImage(cfg),
			Env: []corev1.EnvVar{{Name: "NRVQ_SDK_FALLBACK_MODE", Value: "allow"},
				{Name: "HTTPS_PROXY", Value: "http://10.255.255.1:3128"}}}
	}
	type part struct {
		cfg  func() Config
		add  func(cfg Config, p *corev1.Pod)
		want string
	}
	parts := map[string]part{
		"the injected annotation": {integrityConfig, func(_ Config, p *corev1.Pod) {
			p.Annotations = map[string]string{injectedAnnotation: "true"}
		}, "carries the norviq.io/injected annotation"},
		"the injected annotation with another value": {integrityConfig, func(_ Config, p *corev1.Pod) {
			p.Annotations = map[string]string{injectedAnnotation: "false"}
		}, "carries the norviq.io/injected annotation"},
		"the socket volume": {integrityConfig, func(_ Config, p *corev1.Pod) {
			addVolume(p, socketVolumeName)
		}, "declares the injector-owned volume norviq-socket"},
		"the sidecar scratch volume": {integrityConfig, func(_ Config, p *corev1.Pod) {
			p.Spec.Volumes = []corev1.Volume{{Name: tmpVolumeName, VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{Medium: corev1.StorageMediumMemory}}}}
		}, "declares the injector-owned volume norviq-tmp"},
		"the MCP proxy volume": {mcpIntegrityConfig, func(_ Config, p *corev1.Pod) {
			addVolume(p, mcpVolumeName)
		}, "declares the injector-owned volume norviq-mcp-proxy"},
		"the SPIFFE volume under SPIFFE injection": {spiffeIntegrityConfig, func(_ Config, p *corev1.Pod) {
			p.Spec.Volumes = []corev1.Volume{{Name: spiffeVolumeName, VolumeSource: corev1.VolumeSource{
				CSI: &corev1.CSIVolumeSource{Driver: "csi.spiffe.io", ReadOnly: ptrBool(true)}}}}
		}, "declares the injector-owned volume spiffe-workload-api"},
		"a container with the sidecar's name": {integrityConfig, func(_ Config, p *corev1.Pod) {
			p.Spec.Containers = append(p.Spec.Containers, corev1.Container{Name: injectedSidecarName, Image: "attacker/decoy:latest"})
		}, "container norviq-sidecar takes the injected sidecar's name"},
		"an init container with the sidecar's name": {integrityConfig, func(_ Config, p *corev1.Pod) {
			p.Spec.InitContainers = []corev1.Container{{Name: injectedSidecarName, Image: "busybox:1.36", Command: []string{"true"}}}
		}, "container norviq-sidecar takes the injected sidecar's name"},
		"an init container with the MCP init container's name": {mcpIntegrityConfig, func(_ Config, p *corev1.Pod) {
			p.Spec.InitContainers = []corev1.Container{{Name: mcpInitContainerName, Image: "attacker/x", Command: []string{"true"}}}
		}, "container norviq-mcp-init takes the MCP proxy init container's name"},
		"a container with the MCP init container's name": {mcpIntegrityConfig, func(_ Config, p *corev1.Pod) {
			p.Spec.Containers = append(p.Spec.Containers, corev1.Container{Name: mcpInitContainerName,
				Image: "busybox:1.36", Command: []string{"sleep", "infinity"}})
		}, "container norviq-mcp-init takes the MCP proxy init container's name"},
		"the sidecar image as shipped, in containers": {integrityConfig, func(cfg Config, p *corev1.Pod) {
			p.Spec.Containers = append(p.Spec.Containers, engine(cfg, "warmup"))
		}, "container warmup runs the sidecar image"},
		"the sidecar image as shipped, as a native init sidecar": {integrityConfig, func(cfg Config, p *corev1.Pod) {
			c := engine(cfg, "warmup")
			c.RestartPolicy = &always
			p.Spec.InitContainers = []corev1.Container{c}
		}, "container warmup runs the sidecar image"},
		"the sidecar image as shipped, as a plain init container": {integrityConfig, func(cfg Config, p *corev1.Pod) {
			p.Spec.InitContainers = []corev1.Container{engine(cfg, "warmup")}
		}, "container warmup runs the sidecar image"},
		"another tag of the sidecar image": {integrityConfig, func(_ Config, p *corev1.Pod) {
			p.Spec.Containers = append(p.Spec.Containers, corev1.Container{Name: "warmup",
				Image: "ghcr.io/norviq-dev/norviq-engine:engine-0.2.2"})
		}, "container warmup runs the sidecar image ghcr.io/norviq-dev/norviq-engine:engine-0.2.2"},
		"a digest of the sidecar image": {integrityConfig, func(_ Config, p *corev1.Pod) {
			p.Spec.Containers = append(p.Spec.Containers, corev1.Container{Name: "warmup",
				Image: "ghcr.io/norviq-dev/norviq-engine@sha256:" + strings.Repeat("0", 64)})
		}, "container warmup runs the sidecar image"},
		"the sidecar image name from another registry": {integrityConfig, func(_ Config, p *corev1.Pod) {
			p.Spec.Containers = append(p.Spec.Containers, corev1.Container{Name: "warmup",
				Image: "docker.io/attacker/norviq-engine:evil"})
		}, "container warmup runs the sidecar image docker.io/attacker/norviq-engine:evil"},
		"a mount of the socket volume at another path": {integrityConfig, func(_ Config, p *corev1.Pod) {
			p.Spec.Containers[0].VolumeMounts = []corev1.VolumeMount{{Name: socketVolumeName, MountPath: "/other"}}
		}, "container agent mounts the injector-owned volume norviq-socket"},
		"a mount of the scratch volume, app container": {integrityConfig, func(_ Config, p *corev1.Pod) {
			p.Spec.Containers[0].VolumeMounts = []corev1.VolumeMount{{Name: tmpVolumeName, MountPath: "/sidecar-tmp"}}
		}, "container agent mounts the injector-owned volume norviq-tmp"},
		"a mount of the scratch volume, init container": {integrityConfig, func(_ Config, p *corev1.Pod) {
			p.Spec.InitContainers = []corev1.Container{{Name: "setup", Image: "busybox", Command: []string{"true"},
				VolumeMounts: []corev1.VolumeMount{{Name: tmpVolumeName, MountPath: "/scratch"}}}}
		}, "container setup mounts the injector-owned volume norviq-tmp"},
		"a mount of the MCP proxy volume": {mcpIntegrityConfig, func(_ Config, p *corev1.Pod) {
			p.Spec.Containers[0].VolumeMounts = []corev1.VolumeMount{{Name: mcpVolumeName, MountPath: "/payload"}}
		}, "container agent mounts the injector-owned volume norviq-mcp-proxy"},
		"the socket volume mapped as a device": {integrityConfig, func(_ Config, p *corev1.Pod) {
			p.Spec.Containers[0].VolumeDevices = []corev1.VolumeDevice{{Name: socketVolumeName, DevicePath: "/dev/xvdz"}}
		}, "container agent maps the injector-owned volume norviq-socket as a device"},
		"the socket volume and a pre-wired native init sidecar": {integrityConfig, func(cfg Config, p *corev1.Pod) {
			c := engine(cfg, "warmup")
			c.RestartPolicy = &always
			c.Env = append(c.Env, corev1.EnvVar{Name: "NRVQ_SOCKET_PATH", Value: socketFilePath})
			c.VolumeMounts = []corev1.VolumeMount{{Name: socketVolumeName, MountPath: socketMountPath}}
			p.Spec.InitContainers = []corev1.Container{c}
		}, "container warmup"},
		"NRVQ_SOCKET_PATH on an app container": {integrityConfig, func(_ Config, p *corev1.Pod) {
			p.Spec.Containers[0].Env = []corev1.EnvVar{{Name: "NRVQ_SOCKET_PATH", Value: "/tmp/evil.sock"}}
		}, "container agent sets NRVQ_SOCKET_PATH"},
		"NRVQ_SOCKET_PATH on an init container": {integrityConfig, func(_ Config, p *corev1.Pod) {
			p.Spec.InitContainers = []corev1.Container{{Name: "setup", Image: "busybox", Command: []string{"true"},
				Env: []corev1.EnvVar{{Name: "NRVQ_SOCKET_PATH", Value: socketFilePath}}}}
		}, "container setup sets NRVQ_SOCKET_PATH"},
		"NRVQ_SPIFFE_MODE under SPIFFE injection": {spiffeIntegrityConfig, func(_ Config, p *corev1.Pod) {
			p.Spec.Containers[0].Env = []corev1.EnvVar{{Name: "NRVQ_SPIFFE_MODE", Value: "mock"}}
		}, "container agent sets NRVQ_SPIFFE_MODE"},
		"NRVQ_SPIFFE_SOCKET under SPIFFE injection": {spiffeIntegrityConfig, func(_ Config, p *corev1.Pod) {
			p.Spec.Containers[0].Env = []corev1.EnvVar{{Name: "NRVQ_SPIFFE_SOCKET", Value: "unix:///var/run/norviq/evil.sock"}}
		}, "container agent sets NRVQ_SPIFFE_SOCKET"},
		"the sidecar credential Secret by key": {integrityConfig, func(_ Config, p *corev1.Pod) {
			p.Spec.Containers[0].Env = []corev1.EnvVar{{Name: "TOKEN", ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{Key: "NRVQ_API_TOKEN",
					LocalObjectReference: corev1.LocalObjectReference{Name: sidecarSecretName("checkout", "support")}}}}}
		}, "container agent reads TOKEN from the sidecar credential Secret norviq-sidecar-"},
		"the sidecar credential Secret by envFrom": {integrityConfig, func(_ Config, p *corev1.Pod) {
			p.Spec.Containers[0].EnvFrom = []corev1.EnvFromSource{{SecretRef: &corev1.SecretEnvSource{
				LocalObjectReference: corev1.LocalObjectReference{Name: "norviq-sidecar-checkout-0000beef"}}}}
		}, "container agent imports the sidecar credential Secret norviq-sidecar-checkout-0000beef"},
		"the sidecar credential Secret as a volume": {integrityConfig, func(_ Config, p *corev1.Pod) {
			p.Spec.Volumes = []corev1.Volume{{Name: "creds", VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{SecretName: "norviq-sidecar-checkout-0000beef"}}}}
		}, "volume creds reads the sidecar credential Secret norviq-sidecar-checkout-0000beef"},
		"the sidecar credential Secret in a projected volume": {integrityConfig, func(_ Config, p *corev1.Pod) {
			p.Spec.Volumes = []corev1.Volume{{Name: "creds", VolumeSource: corev1.VolumeSource{
				Projected: &corev1.ProjectedVolumeSource{Sources: []corev1.VolumeProjection{{Secret: &corev1.SecretProjection{
					LocalObjectReference: corev1.LocalObjectReference{Name: "norviq-sidecar-checkout-0000beef"}}}}}}}}
		}, "volume creds reads the sidecar credential Secret norviq-sidecar-checkout-0000beef"},
		"a command that starts with the MCP proxy": {mcpIntegrityConfig, func(_ Config, p *corev1.Pod) {
			p.Spec.Containers[0].Command = []string{mcpProxyBinary, "--server-id", "agent", "--", "/agent"}
		}, "container agent runs a command under the MCP proxy"},
		"args that start with the MCP proxy": {mcpIntegrityConfig, func(_ Config, p *corev1.Pod) {
			p.Spec.Containers[0].Command = nil
			p.Spec.Containers[0].Args = []string{mcpProxyBinary, "--", "/agent"}
		}, "container agent runs a command under the MCP proxy"},
		"the MCP proxy inside a shell string": {mcpIntegrityConfig, func(_ Config, p *corev1.Pod) {
			p.Spec.Containers[0].Command = []string{"sh", "-c", "exec " + mcpProxyBinary + " --server-id x -- /agent"}
		}, "container agent runs a command under the MCP proxy"},
		"the MCP proxy with doubled slashes": {mcpIntegrityConfig, func(_ Config, p *corev1.Pod) {
			p.Spec.Containers[0].Command = []string{"/norviq//mcp/bin/norviq-mcp", "--", "/agent"}
		}, "container agent runs a command under the MCP proxy"},
		"the MCP staging path in a command": {mcpIntegrityConfig, func(_ Config, p *corev1.Pod) {
			p.Spec.InitContainers = []corev1.Container{{Name: "stage", Image: "busybox",
				Command: []string{"sh", "-c", "printf shim > " + mcpInitMountPath + "/bin/norviq-mcp"}}}
		}, "container stage runs a command under the MCP proxy"},
	}
	for name, tc := range parts {
		t.Run(name, func(t *testing.T) {
			cfg := tc.cfg()
			pod := integrityPod()
			if cfg.McpInject {
				pod = mcpIntegrityPod()
			}
			assertInjected(t, cfg, pod) // the fixture without the part is a fresh pod
			tc.add(cfg, &pod)
			assertDenied(t, cfg, pod, codeOwnedPart, tc.want)
		})
	}
}

// Something of the pod's own at or below a path the injector mounts at: refused under 4034, named.
func TestInjectorOwned_PathOccupiedIsDenied(t *testing.T) {
	mountAt := func(path string) func(p *corev1.Pod) {
		return func(p *corev1.Pod) {
			addVolume(p, "own")
			p.Spec.Containers[0].VolumeMounts = []corev1.VolumeMount{{Name: "own", MountPath: path}}
		}
	}
	cases := map[string]struct {
		cfg    func() Config
		change func(p *corev1.Pod)
		want   string
	}{
		"own volume at the socket directory": {integrityConfig, mountAt(socketMountPath),
			"container agent mounts volume own at /var/run/norviq, inside the injector-owned path /var/run/norviq"},
		"own volume over the socket file": {integrityConfig, mountAt(socketFilePath),
			"inside the injector-owned path /var/run/norviq"},
		"own volume at the socket directory, trailing slash": {integrityConfig, mountAt(socketMountPath + "/"),
			"inside the injector-owned path /var/run/norviq"},
		"own volume below the socket directory, doubled slash": {integrityConfig, mountAt("/var/run//norviq/x"),
			"inside the injector-owned path /var/run/norviq"},
		"own volume below the socket directory, dot segment": {integrityConfig, mountAt("/var/run/norviq/./x"),
			"inside the injector-owned path /var/run/norviq"},
		"own volume at the /run alias of the socket directory": {integrityConfig, mountAt("/run/norviq/norviq-proxy.sock"),
			"inside the injector-owned path /run/norviq"},
		"termination message file in the socket directory": {integrityConfig, func(p *corev1.Pod) {
			p.Spec.Containers[0].TerminationMessagePath = socketMountPath + "/log"
		}, "container agent writes its termination message to /var/run/norviq/log"},
		"block device over the socket file": {integrityConfig, func(p *corev1.Pod) {
			addPVC(p, "blk")
			p.Spec.Containers[0].VolumeDevices = []corev1.VolumeDevice{{Name: "blk", DevicePath: socketFilePath}}
		}, "container agent maps a device at /var/run/norviq/norviq-proxy.sock"},
		"own volume at the MCP proxy path": {mcpIntegrityConfig, mountAt(mcpMountPath),
			"inside the injector-owned path /norviq/mcp"},
		"own volume below the MCP proxy path": {mcpIntegrityConfig, mountAt(mcpMountPath + "/bin"),
			"inside the injector-owned path /norviq/mcp"},
		"own volume at the MCP proxy path, trailing slash": {mcpIntegrityConfig, mountAt(mcpMountPath + "/"),
			"inside the injector-owned path /norviq/mcp"},
		"own volume over the proxy binary, doubled slash": {mcpIntegrityConfig, mountAt("/norviq//mcp/bin/norviq-mcp"),
			"inside the injector-owned path /norviq/mcp"},
		"own volume below the MCP staging path": {mcpIntegrityConfig, mountAt(mcpInitMountPath + "/bin"),
			"inside the injector-owned path /norviq-mcp-staging"},
		"wrapped container's termination message over the proxy binary": {mcpIntegrityConfig, func(p *corev1.Pod) {
			p.Spec.Containers[1].TerminationMessagePath = mcpProxyBinary
		}, "container mcp writes its termination message to /norviq/mcp/bin/norviq-mcp"},
		"wrapped container's termination message below the proxy path": {mcpIntegrityConfig, func(p *corev1.Pod) {
			p.Spec.Containers[1].TerminationMessagePath = "/norviq/mcp/bin/_internal/libssl.so.3"
		}, "inside the injector-owned path /norviq/mcp"},
		"app container's termination message over the proxy binary": {mcpIntegrityConfig, func(p *corev1.Pod) {
			p.Spec.Containers[0].TerminationMessagePath = mcpProxyBinary
		}, "container agent writes its termination message to /norviq/mcp/bin/norviq-mcp"},
		"own volume at the SPIFFE socket directory": {spiffeIntegrityConfig, mountAt(spiffeMountPath),
			"inside the injector-owned path /spiffe-workload-api"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := tc.cfg()
			pod := integrityPod()
			if cfg.McpInject {
				pod = mcpIntegrityPod()
			}
			tc.change(&pod)
			assertDenied(t, cfg, pod, codePathOccupied, tc.want)
		})
	}
}

// --- fresh pods are injected ----------------------------------------------------------------------

func TestInjectorOwned_FreshPodsAreInjected(t *testing.T) {
	cases := map[string]struct {
		cfg func() Config
		pod func() corev1.Pod
	}{
		"fresh pod": {integrityConfig, integrityPod},
		// What a ReplicaSet actually submits: generateName and no name, the pod-template-hash label, the
		// ServiceAccount token volume and mount and the default termination message path the API server
		// has already added by the time admission webhooks run.
		"Deployment-template-shaped pod": {integrityConfig, func() corev1.Pod {
			return corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "checkout-7d9f8b5c4-",
					Labels: map[string]string{"app": "checkout", "pod-template-hash": "7d9f8b5c4",
						"norviq.io/agent-class": "support"},
					OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet",
						Name: "checkout-7d9f8b5c4", UID: "rs-uid", Controller: ptrBool(true)}},
				},
				Spec: corev1.PodSpec{
					Volumes: []corev1.Volume{{Name: "kube-api-access-x1", VolumeSource: corev1.VolumeSource{
						Projected: &corev1.ProjectedVolumeSource{}}}},
					Containers: []corev1.Container{{Name: "agent", Image: "mycorp/agent:v1", Command: []string{"/agent"},
						TerminationMessagePath: corev1.TerminationMessagePathDefault,
						VolumeMounts: []corev1.VolumeMount{{Name: "kube-api-access-x1",
							MountPath: serviceAccountTokenPath, ReadOnly: true}}}},
				},
			}
		}},
		"own volume mounted by app and init containers": {integrityConfig, func() corev1.Pod {
			p := integrityPod()
			addVolume(&p, "scratch")
			p.Spec.Containers[0].VolumeMounts = []corev1.VolumeMount{{Name: "scratch", MountPath: "/scratch"}}
			p.Spec.InitContainers = []corev1.Container{{Name: "setup", Image: "busybox", Command: []string{"true"},
				VolumeMounts: []corev1.VolumeMount{{Name: "scratch", MountPath: "/scratch"}}}}
			return p
		}},
		"mounts above and beside the injector's paths": {mcpIntegrityConfig, func() corev1.Pod {
			p := mcpIntegrityPod()
			addVolume(&p, "data")
			p.Spec.Containers[1].VolumeMounts = []corev1.VolumeMount{
				{Name: "data", MountPath: "/norviq"}, {Name: "data", MountPath: "/var/run", SubPath: "a"},
				{Name: "data", MountPath: "/var/run/norviqx", SubPath: "b"}, {Name: "data", MountPath: "/norviq/mcp-tools", SubPath: "c"}}
			return p
		}},
		"SDK settings and an ordinary Secret on the app container": {integrityConfig, func() corev1.Pod {
			p := integrityPod()
			p.Spec.Containers[0].Env = []corev1.EnvVar{{Name: "NRVQ_API_URL", Value: "http://norviq-api.norviq:8080"},
				{Name: "NRVQ_AGENT_CLASS", Value: "support"}, {Name: "NRVQ_SDK_FALLBACK_MODE", Value: "block"},
				{Name: "TOKEN", ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{
					Key: "t", LocalObjectReference: corev1.LocalObjectReference{Name: "agent-secrets"}}}}}
			return p
		}},
		// examples/chatbot runs norviq.mcp firewalls from the engine image with an explicit command.
		"engine image running another module": {integrityConfig, func() corev1.Pod {
			p := integrityPod()
			p.Spec.Containers = append(p.Spec.Containers, corev1.Container{Name: "mcp-fw-kb",
				Image: configuredSidecarImage(integrityConfig()), Command: []string{"python", "-m", "norviq.mcp"},
				Args: []string{"--http", "--listen", "127.0.0.1:9101", "--server-id", "kb"}})
			return p
		}},
		"SPIFFE injection on a fresh pod": {spiffeIntegrityConfig, integrityPod},
		// The MCP plumbing is the injector's only while MCP injection is on; with it off the injector
		// never adds it, so the same names are the pod's own and change nothing.
		"MCP-shaped plumbing with MCP injection off": {integrityConfig, func() corev1.Pod {
			p := integrityPod()
			addVolume(&p, mcpVolumeName)
			p.Spec.Containers[0].Command = []string{mcpProxyBinary, "--", "sh"}
			p.Spec.Containers[0].VolumeMounts = []corev1.VolumeMount{{Name: mcpVolumeName, MountPath: mcpMountPath}}
			p.Spec.InitContainers = []corev1.Container{{Name: mcpInitContainerName, Image: "busybox", Command: []string{"true"}}}
			return p
		}},
		"SPIFFE-shaped plumbing with SPIFFE injection off": {integrityConfig, func() corev1.Pod {
			p := integrityPod()
			p.Spec.Volumes = []corev1.Volume{{Name: spiffeVolumeName, VolumeSource: corev1.VolumeSource{
				CSI: &corev1.CSIVolumeSource{Driver: "csi.spiffe.io", ReadOnly: ptrBool(true)}}}}
			p.Spec.Containers[0].VolumeMounts = []corev1.VolumeMount{{Name: spiffeVolumeName, MountPath: spiffeMountPath}}
			p.Spec.Containers[0].Env = []corev1.EnvVar{{Name: "NRVQ_SPIFFE_MODE", Value: "spiffe"}}
			return p
		}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			out := assertInjected(t, tc.cfg(), tc.pod())
			if _, ok := out.Annotations[injectedAnnotation]; !ok {
				t.Fatal("the injected pod does not carry the injected annotation")
			}
			if !containerWired(out.Spec.Containers[0]) {
				t.Fatalf("the app container is not wired: %+v", out.Spec.Containers[0])
			}
		})
	}
}

func TestInjectorOwned_McpFreshPodIsInjectedWithTheWrap(t *testing.T) {
	cfg := mcpIntegrityConfig()
	out := assertInjected(t, cfg, mcpIntegrityPod())
	mcp := containerIn(t, &out, "mcp")
	want := []string{mcpProxyBinary, "--server-id", "mcp", "--", "npx", "server-github"}
	if strings.Join(mcp.Command, " ") != strings.Join(want, " ") || len(mcp.Args) != 0 {
		t.Fatalf("the MCP container is not wrapped: command=%v args=%v", mcp.Command, mcp.Args)
	}
	if !mountsMcpProxyVolumeReadOnly(*mcp) || !containerWired(*mcp) {
		t.Fatalf("the wrapped container lacks the proxy mount or the socket wiring: %+v", mcp.VolumeMounts)
	}
	if out.Spec.InitContainers[0].Name != mcpInitContainerName {
		t.Fatalf("the proxy delivery init container is not first: %v", out.Spec.InitContainers)
	}
	// And the injected pod, submitted again, is refused: the decided behaviour.
	assertCopyDenied(t, cfg, out)
}

// --- opt-out ----------------------------------------------------------------------------------------

func TestInjectorOwned_OptOutIsUnchangedForFreshPods(t *testing.T) {
	optOuts := map[string]func(p *corev1.Pod){
		"label":      func(p *corev1.Pod) { p.Labels["norviq-injection"] = "disabled" },
		"annotation": func(p *corev1.Pod) { p.Annotations = map[string]string{"norviq.io/skip-injection": "true"} },
	}
	for name, optOut := range optOuts {
		t.Run(name+", opt-out allowed: admitted unpatched", func(t *testing.T) {
			cfg := integrityConfig()
			cfg.AllowPodOptOut = true
			pod := integrityPod()
			optOut(&pod)
			allowed, patch, msg := admitPod(t, cfg, pod)
			if !allowed || patch != nil {
				t.Fatalf("an opted-out fresh pod must be admitted unpatched; allowed=%v patched=%v message=%q",
					allowed, patch != nil, msg)
			}
		})
		t.Run(name+", opt-out disallowed: injected", func(t *testing.T) {
			cfg := integrityConfig()
			cfg.AllowPodOptOut = false
			pod := integrityPod()
			optOut(&pod)
			assertInjected(t, cfg, pod)
		})
	}
}

// An opted-out pod carrying injector parts is refused under either setting: it would read as governed
// to anyone looking at its spec while nothing in it was built by the webhook.
func TestInjectorOwned_OptedOutPodCarryingPartsIsDenied(t *testing.T) {
	for _, allow := range []bool{true, false} {
		cfg := integrityConfig()
		cfg.AllowPodOptOut = allow

		copied := injectorOutput(t, cfg, integrityPod(), nil)
		copied.Annotations["norviq.io/skip-injection"] = "true"
		assertCopyDenied(t, cfg, copied)

		labelled := integrityPod()
		labelled.Labels["norviq-injection"] = "disabled"
		labelled.Spec.Containers = append(labelled.Spec.Containers, corev1.Container{Name: injectedSidecarName,
			Image: configuredSidecarImage(cfg)})
		assertDenied(t, cfg, labelled, codeOwnedPart, "takes the injected sidecar's name")

		occupied := integrityPod()
		occupied.Labels["norviq-injection"] = "disabled"
		addVolume(&occupied, "own")
		occupied.Spec.Containers[0].VolumeMounts = []corev1.VolumeMount{{Name: "own", MountPath: socketMountPath}}
		assertDenied(t, cfg, occupied, codePathOccupied, "inside the injector-owned path /var/run/norviq")
	}
}

func TestReferencesPath(t *testing.T) {
	for s, want := range map[string]bool{
		"/norviq/mcp":                               true,
		"/norviq/mcp/bin/norviq-mcp":                true,
		"/norviq//mcp/bin/norviq-mcp":               true,
		"exec /norviq/mcp/bin/norviq-mcp --x":       true,
		"x=/norviq/mcp/bin":                         true,
		"'/norviq/mcp'":                             true,
		"/norviq/mcp-tools":                         false,
		"/opt/norviq/mcp/bin":                       false,
		"/opt/norviq/mcp-proxy":                     false,
		"norviq/mcp":                                false,
		"/norviq/mcpx /norviq/mcp-y /norviq/mcp/ok": true,
	} {
		if got := referencesPath(s, mcpMountPath); got != want {
			t.Errorf("referencesPath(%q) = %v, want %v", s, got, want)
		}
	}
}
