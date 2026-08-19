// SPDX-License-Identifier: Apache-2.0
// SCRATCH REVIEW PROBE — delete after use.
package main

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"sort"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	jsonpatch "gopkg.in/evanphx/json-patch.v4"
)

// ---- the PREVIOUS deny predicate + the classification it produced ------------------------------

func dpxOldNeutered(cfg Config, pod *corev1.Pod) bool {
	img := configuredSidecarImage(cfg)
	if img == "" {
		return false
	}
	for _, c := range allPodContainers(pod) {
		if cfg.McpInject && isInjectorMcpInitContainer(cfg, c) {
			continue
		}
		if (len(c.Command) > 0 || len(c.Args) > 0) && isSidecarContainer(c, img) {
			return true
		}
	}
	return false
}

func dpxOldArtifact(cfg Config, pod *corev1.Pod) bool {
	img := configuredSidecarImage(cfg)
	if hasNorviqSocketVolume(pod) {
		return true
	}
	for _, c := range allPodContainers(pod) {
		if isSidecarContainer(c, img) || mountsSocketPath(c) || hasSocketPathEnv(c) {
			return true
		}
	}
	if cfg.McpInject {
		if _, ok := mcpArtifact(cfg, pod); ok {
			return true
		}
	}
	return false
}

func dpxOldClassify(cfg Config, pod *corev1.Pod) podVerdict {
	if dpxOldNeutered(cfg, pod) {
		return verdictDeny
	}
	if fullyInjected(cfg, pod) {
		return verdictSkip
	}
	if dpxOldArtifact(cfg, pod) {
		return verdictDeny
	}
	return verdictInject
}

func dpxVname(v podVerdict) string {
	switch v {
	case verdictDeny:
		return "DENY"
	case verdictSkip:
		return "SKIP"
	}
	return "INJECT"
}

func dpxCfg() Config {
	cfg := LoadConfig()
	cfg.McpInject = true
	cfg.ApiSecret = "probe-secret"
	cfg.McpProxyImage = "ghcr.io/norviq-dev/norviq-mcp-proxy:test"
	return cfg
}

type dpxSlot struct {
	name  string
	image string
	cmd   []string
	args  []string
	mount []corev1.VolumeMount
	env   []corev1.EnvVar
}

func dpxBuildSlots(cfg Config) []dpxSlot {
	names := []string{"app", "norviq-sidecar", "norviq-mcp-init", "mcp-fw-kb"}
	images := []string{cfg.SidecarImage, "attacker/norviq-engine:evil", "tenant/app:1",
		cfg.McpProxyImage, "evil/norviq-mcp-proxy:x"}
	initCmd, _ := mcpInitContainer(cfg)["command"].([]string)
	cmds := [][]string{
		nil,
		{"sleep", "1d"},
		initCmd,
		{mcpProxyBinary, "--server-id", "mcp-fw-kb", "--", "srv"},
	}
	argsets := [][]string{nil, {"--x"}}
	mounts := [][]corev1.VolumeMount{
		nil,
		{{Name: "norviq-socket", MountPath: socketMountPath}},
		{{Name: "other", MountPath: socketMountPath}},
		{{Name: "norviq-socket", MountPath: "/elsewhere"}},
		{{Name: mcpVolumeName, MountPath: mcpMountPath, ReadOnly: true}},
		{{Name: mcpVolumeName, MountPath: mcpInitMountPath}},
		{{Name: mcpVolumeName, MountPath: mcpInitMountPath}, {Name: "norviq-socket", MountPath: socketMountPath}},
		{{Name: "data", MountPath: "/data"}},
	}
	envs := [][]corev1.EnvVar{
		nil,
		{{Name: "NRVQ_SOCKET_PATH", Value: socketFilePath}},
		{{Name: "NRVQ_SOCKET_PATH", Value: "/tmp/evil.sock"}},
		{{Name: "NRVQ_API_URL", Value: cfg.ApiURL}, {Name: "NRVQ_SIDECAR_MODE", Value: sidecarMode(cfg)}},
		{{Name: "NRVQ_API_URL", Value: cfg.ApiURL}, {Name: "NRVQ_MCP_PIN_STORE", Value: cfg.McpPinStore},
			{Name: "NRVQ_MCP_PIN_MODE", Value: cfg.McpPinMode}, {Name: "NRVQ_SOCKET_PATH", Value: socketFilePath}},
		{{Name: "FOO", Value: "bar"}},
	}
	out := []dpxSlot{}
	for _, n := range names {
		for _, im := range images {
			for _, c := range cmds {
				for _, a := range argsets {
					for _, m := range mounts {
						for _, e := range envs {
							out = append(out, dpxSlot{n, im, c, a, m, e})
						}
					}
				}
			}
		}
	}
	return out
}

func (s dpxSlot) container(suffix string) corev1.Container {
	name := s.name
	if suffix != "" && name == "app" {
		name = "app" + suffix
	}
	return corev1.Container{Name: name, Image: s.image, Command: s.cmd, Args: s.args,
		VolumeMounts: s.mount, Env: s.env}
}

func TestZZDeltaProbe(t *testing.T) {
	cfg := dpxCfg()
	slots := dpxBuildSlots(cfg)
	t.Logf("dpxSlot templates: %d", len(slots))
	vols := [][]corev1.Volume{
		nil,
		{{Name: "norviq-socket", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}}},
		{{Name: mcpVolumeName, VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}}},
		{{Name: "norviq-socket", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
			{Name: mcpVolumeName, VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}}},
		{{Name: mcpVolumeName, VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/x"}}}},
	}
	annos := []map[string]string{nil, {mcpServersAnnotation: "mcp-fw-kb"}, {mcpServersAnnotation: "app"}}

	rng := rand.New(rand.NewSource(7))
	seen := map[string]int{}
	examples := map[string]*corev1.Pod{}
	const iters = 1500000
	for i := 0; i < iters; i++ {
		nApp := 1 + rng.Intn(2)
		nInit := rng.Intn(3)
		pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "p", Annotations: annos[rng.Intn(len(annos))]}}
		pod.Spec.Volumes = vols[rng.Intn(len(vols))]
		used := map[string]bool{}
		add := func(init bool, idx int) {
			s := slots[rng.Intn(len(slots))]
			c := s.container(fmt.Sprintf("-%d", idx))
			if used[c.Name] {
				return
			}
			used[c.Name] = true
			if init {
				pod.Spec.InitContainers = append(pod.Spec.InitContainers, c)
			} else {
				pod.Spec.Containers = append(pod.Spec.Containers, c)
			}
		}
		for j := 0; j < nApp; j++ {
			add(false, j)
		}
		for j := 0; j < nInit; j++ {
			add(true, 100+j)
		}
		if len(pod.Spec.Containers) == 0 {
			continue
		}
		oldV := dpxOldClassify(cfg, pod)
		newV, _ := classifyPod(cfg, pod)
		if oldV == newV {
			continue
		}
		key := dpxVname(oldV) + "->" + dpxVname(newV)
		seen[key]++
		if examples[key] == nil {
			examples[key] = pod.DeepCopy()
		}
		if oldV == verdictDeny && newV == verdictInject {
			if problem := dpxInjectedPodProblem(cfg, pod); problem != "" {
				k2 := "UNSAFE-INJECT: " + problem
				seen[k2]++
				if examples[k2] == nil {
					examples[k2] = pod.DeepCopy()
				}
			}
		}
	}
	keys := make([]string, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		b, _ := json.Marshal(examples[k].Spec)
		t.Logf("%-52s n=%-7d annos=%v spec=%s", k, seen[k], examples[k].Annotations, string(b))
	}
}

func dpxInjectedPodProblem(cfg Config, pod *corev1.Pod) string {
	patchBytes, err := NewInjector(cfg).CreatePatch(pod, "", "default")
	if err != nil {
		return ""
	}
	patch, err := jsonpatch.DecodePatch(patchBytes)
	if err != nil {
		return "patch-invalid"
	}
	orig, _ := json.Marshal(pod)
	mutated, err := patch.Apply(orig)
	if err != nil {
		return "patch-apply-failed"
	}
	var out corev1.Pod
	if err := json.Unmarshal(mutated, &out); err != nil {
		return "unmarshal-failed"
	}
	names := map[string]bool{}
	all := append(append([]corev1.Container{}, out.Spec.InitContainers...), out.Spec.Containers...)
	for _, c := range all {
		if names[c.Name] {
			return "duplicate-container-name:" + c.Name
		}
		names[c.Name] = true
	}
	sidecar := false
	for _, c := range out.Spec.Containers {
		if c.Name == injectedSidecarName && c.Image == cfg.SidecarImage && len(c.Command) == 0 && len(c.Args) == 0 {
			sidecar = true
		}
	}
	if !sidecar {
		return "no-real-sidecar"
	}
	if !hasNorviqSocketVolume(&out) {
		return "no-socket-volume"
	}
	for _, c := range all {
		if !containerWired(c) {
			return "unwired-container:" + c.Name
		}
	}
	if cfg.McpInject {
		for _, n := range mcpAnnotatedNames(&out) {
			_, _, c, found := findPodContainer(&out, n)
			if !found {
				return "mcp-target-vanished:" + n
			}
			if !isMcpProxyCommand(c.Command) {
				return "mcp-target-unwrapped:" + n
			}
			if !mountsMcpProxyVolumeReadOnly(c) {
				return "mcp-target-unmounted:" + n
			}
		}
		if len(mcpAnnotatedNames(&out)) > 0 && !hasInjectorMcpInitContainer(cfg, &out) {
			return "mcp-init-not-injector-owned"
		}
	}
	return ""
}

// ---- PoC: a second enforcement engine in the pod, wired by the injector itself -----------------

func TestZZPoCSecondEngine(t *testing.T) {
	for _, mcpOn := range []bool{false, true} {
		cfg := dpxCfg()
		cfg.McpInject = mcpOn
		always := corev1.ContainerRestartPolicyAlways
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "agent", Labels: map[string]string{cfg.EnableLabel: "enabled"}},
			Spec: corev1.PodSpec{
				InitContainers: []corev1.Container{
					{Name: "warm-cache", Image: cfg.SidecarImage, RestartPolicy: &always,
						Env: []corev1.EnvVar{{Name: "NRVQ_API_URL", Value: "http://127.0.0.1:9999"}}},
				},
				Containers: []corev1.Container{
					{Name: "agent", Image: "tenant/agent:1"},
					{Name: "telemetry-helper", Image: cfg.SidecarImage,
						Command: []string{"sh", "-c", "sleep 25; exec python -m norviq.sidecar"},
						Env: []corev1.EnvVar{
							{Name: "NRVQ_API_URL", Value: "http://127.0.0.1:9999"},
						}},
				},
			},
		}
		oldV := dpxOldClassify(cfg, pod)
		newV, reason := classifyPod(cfg, pod)
		t.Logf("mcpInject=%v  OLD=%s  NEW=%s (%s)", mcpOn, dpxVname(oldV), dpxVname(newV), reason)
		if newV != verdictInject {
			continue
		}
		out := applyPatch(t, cfg, pod, "", "default")
		for _, c := range append(append([]corev1.Container{}, out.Spec.InitContainers...), out.Spec.Containers...) {
			b, _ := json.Marshal(c)
			t.Logf("  post-patch %-18s wired=%v %s", c.Name, containerWired(c), string(b))
		}
	}
}

// ---- exhaustive: can a delta container ever sit inside a fullyInjected pod? --------------------

func TestZZDeltaContainerCanNeverBeWired(t *testing.T) {
	cfg := dpxCfg()
	img := configuredSidecarImage(cfg)
	n, withCmd := 0, 0
	for _, s := range dpxBuildSlots(cfg) {
		c := s.container("")
		if !isSidecarContainer(c, img) || occupiesEnforcementPath(c, img) {
			continue
		}
		n++
		if containerWired(c) {
			t.Fatalf("delta container is WIRED (could live inside a fullyInjected pod): %+v", c)
		}
		if c.Image != img {
			t.Fatalf("delta container is not exact-image: %+v", c)
		}
		if len(c.Command) > 0 || len(c.Args) > 0 {
			withCmd++
		}
	}
	t.Logf("delta container templates: %d (with command/args: %d)", n, withCmd)
}
