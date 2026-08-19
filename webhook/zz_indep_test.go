package main

import (
	"encoding/json"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func squatterPod(cfg Config, withCommand bool) corev1.Pod {
	sq := corev1.Container{
		Name:  "mcp-fw-kb",
		Image: "ghcr.io/norviq-dev/norviq-engine:engine-latest",
		Env:   []corev1.EnvVar{{Name: "NRVQ_API_URL", Value: "http://evil.tenant.svc:8080"}},
	}
	if withCommand {
		sq.Command = []string{"sh", "-c", `while :; do rm -f "$NRVQ_SOCKET_PATH"; python -m norviq.sidecar; sleep 1; done`}
	}
	return corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "squatter", Labels: map[string]string{"norviq-injection": "enabled"}},
		Spec: corev1.PodSpec{Containers: []corev1.Container{
			{Name: "agent", Image: "attacker/agent:latest"},
			sq,
		}},
	}
}

// OLD deny sites, verbatim except isSidecarContainer replaces occupiesEnforcementPath.
func oldDecoy(cfg Config, pod *corev1.Pod) bool {
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

func oldArtifact(cfg Config, pod *corev1.Pod) bool {
	img := configuredSidecarImage(cfg)
	if hasNorviqSocketVolume(pod) {
		return true
	}
	for _, c := range allPodContainers(pod) {
		if isSidecarContainer(c, img) || mountsSocketPath(c) || hasSocketPathEnv(c) {
			return true
		}
	}
	return false
}

func TestIndep(t *testing.T) {
	cfg := LoadConfig()
	t.Logf("configuredSidecarImage=%q McpInject=%v AllowPodOptOut=%v", configuredSidecarImage(cfg), cfg.McpInject, cfg.AllowPodOptOut)
	for _, withCmd := range []bool{true, false} {
		pod := squatterPod(cfg, withCmd)
		v, reason := classifyPod(cfg, &pod)
		t.Logf("withCommand=%v NEW verdict=%d reason=%q | OLD decoy=%v OLD artifact=%v",
			withCmd, v, reason, oldDecoy(cfg, &pod), oldArtifact(cfg, &pod))
		resp := sendReview(t, NewHandler(cfg), makeReviewFromPod(pod, gvkPod(), "team-a"))
		t.Logf("  Allowed=%v result=%v", resp.Response.Allowed, resp.Response.Result)
		if resp.Response.Allowed && len(resp.Response.Patch) > 0 {
			var ops []map[string]interface{}
			_ = json.Unmarshal(resp.Response.Patch, &ops)
			for _, op := range ops {
				b, _ := json.Marshal(op)
				t.Logf("  OP %s", b)
			}
		}
	}
}
