// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
package main

// Copies of the injector's own output, untouched and with one thing changed, submitted as a new pod.
// Every one is refused under NRVQ-WHK-4063 with the instruction to remove the injected parts.
//
// These are the cases an exact-match recognizer of the injector's output had to tell apart from the
// output itself: each was, at some point, admitted unpatched as "already injected" or nearly so. Under
// the current rule there is nothing to tell apart, and the table keeps them so a future change that
// reintroduces an "already injected" outcome meets every one of them again. The untouched output in
// every configuration the injector supports is in the first test: that is the decided behaviour, not a
// side effect of a change.

import (
	"os"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/util/intstr"
)

type copyCase struct {
	cfg    func() Config
	pod    func() corev1.Pod // nil: integrityPod, or mcpIntegrityPod under MCP injection
	writer bool              // deliver the sidecar credentials through a Secret
	tamper func(t *testing.T, cfg Config, p *corev1.Pod)
}

func runCopyCases(t *testing.T, cases map[string]copyCase) {
	t.Helper()
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := tc.cfg()
			build := tc.pod
			if build == nil {
				build = integrityPod
				if cfg.McpInject {
					build = mcpIntegrityPod
				}
			}
			var writer SecretWriter
			if tc.writer {
				writer = &fakeSecretWriter{}
			}
			pod := injectorOutput(t, cfg, build(), writer)
			if tc.tamper != nil {
				tc.tamper(t, cfg, &pod)
			}
			assertCopyDenied(t, cfg, pod)
		})
	}
}

func embeddedIntegrityConfig() Config {
	c := integrityConfig()
	c.SidecarMode = "embedded"
	c.RedisURL = "redis://norviq-redis:6379"
	c.PgURL = "postgresql://norviq@norviq-postgresql:5432/norviq"
	c.OpaMode = "subprocess"
	return c
}

func withMcp(cfg Config) Config {
	cfg.McpInject = true
	cfg.McpProxyImage = mcpIntegrityProxyImage
	return cfg
}

const (
	pinnedSidecarImage = "ghcr.io/norviq-dev/norviq-engine@sha256:" +
		"fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
	pinnedProxyImage = "ghcr.io/norviq-dev/norviq-mcp-proxy@sha256:" +
		"1111111111111111111111111111111111111111111111111111111111111111"
	unreachableProxy = "http://10.255.255.1:3128"
)

// --- the untouched output, in every configuration ----------------------------------------------------

// Rewritten from the "injector output is skipped in every mode" controls of the exact-match design:
// re-submitting the injector's own output is refused now, by decision, because the webhook is CREATE
// only and such a pod is always a copy.
func TestInjectorOwnedCopies_UntouchedOutputIsDeniedInEveryMode(t *testing.T) {
	caFile, keyFile, _ := writeTestCA(t, t.TempDir())
	always := corev1.ContainerRestartPolicyAlways
	cases := map[string]copyCase{
		"proxy, literal credentials": {cfg: integrityConfig},
		"proxy, Secret credentials":  {cfg: integrityConfig, writer: true},
		"proxy, no signing secret":   {cfg: func() Config { c := integrityConfig(); c.ApiSecret = ""; return c }},
		"default fallback posture":   {cfg: func() Config { c := integrityConfig(); c.FallbackMode = "allow"; return c }},
		"internal mTLS, literal":     {cfg: func() Config { return tlsIntegrityConfig(caFile, keyFile) }},
		"internal mTLS, Secret":      {cfg: func() Config { return tlsIntegrityConfig(caFile, keyFile) }, writer: true},
		"internal mTLS, https ApiURL": {cfg: func() Config {
			c := tlsIntegrityConfig(caFile, keyFile)
			c.ApiURL = "https://api.example:8443"
			return c
		}},
		"SPIFFE injection":               {cfg: spiffeIntegrityConfig},
		"embedded mode":                  {cfg: embeddedIntegrityConfig},
		"sidecar image pinned by digest": {cfg: func() Config { return withSidecarImage(integrityConfig(), pinnedSidecarImage) }},
		"sidecar image pinned by tag": {cfg: func() Config {
			return withSidecarImage(integrityConfig(), "ghcr.io/norviq-dev/norviq-engine:engine-0.2.6")
		}},
		"MCP, literal credentials":          {cfg: mcpIntegrityConfig},
		"MCP, Secret credentials":           {cfg: mcpIntegrityConfig, writer: true},
		"MCP, no signing secret":            {cfg: func() Config { c := mcpIntegrityConfig(); c.ApiSecret = ""; return c }},
		"MCP, internal mTLS":                {cfg: func() Config { return withMcp(tlsIntegrityConfig(caFile, keyFile)) }},
		"MCP, internal mTLS, Secret":        {cfg: func() Config { return withMcp(tlsIntegrityConfig(caFile, keyFile)) }, writer: true},
		"MCP, SPIFFE injection":             {cfg: func() Config { return withMcp(spiffeIntegrityConfig()) }},
		"MCP, pin store and mode set":       {cfg: func() Config { c := mcpIntegrityConfig(); c.McpPinStore = "redis"; c.McpPinMode = "enforce"; return c }},
		"MCP, proxy image pinned by digest": {cfg: func() Config { c := mcpIntegrityConfig(); c.McpProxyImage = pinnedProxyImage; return c }},
		"MCP, proxy image on a registry port": {cfg: func() Config {
			c := mcpIntegrityConfig()
			c.McpProxyImage = "registry.corp:5000/tools/norviq-mcp-proxy:1"
			return c
		}},
		"MCP, server id from annotation": {cfg: mcpIntegrityConfig, pod: func() corev1.Pod {
			p := mcpIntegrityPod()
			p.Annotations[mcpServerIDPrefix+"mcp"] = "github"
			return p
		}},
		"MCP, wrapped init container": {cfg: mcpIntegrityConfig, pod: func() corev1.Pod {
			p := integrityPod()
			p.Annotations = map[string]string{mcpServersAnnotation: "mcp-setup"}
			p.Spec.InitContainers = []corev1.Container{{Name: "mcp-setup", Image: "node:22", Command: []string{"npx", "seed"}}}
			return p
		}},
		"MCP, two servers": {cfg: mcpIntegrityConfig, pod: func() corev1.Pod {
			p := mcpIntegrityPod()
			p.Annotations[mcpServersAnnotation] = "mcp,mcp-fs"
			p.Spec.Containers = append(p.Spec.Containers,
				corev1.Container{Name: "mcp-fs", Image: "node:22", Command: []string{"npx", "server-fs"}})
			return p
		}},
		"MCP, author native sidecar and shared process namespace": {cfg: mcpIntegrityConfig, pod: func() corev1.Pod {
			p := mcpIntegrityPod()
			p.Spec.ShareProcessNamespace = ptrBool(true)
			p.Spec.InitContainers = []corev1.Container{{Name: "watcher", Image: "alpine:3", Command: []string{"/watch"},
				RestartPolicy: &always, SecurityContext: &corev1.SecurityContext{RunAsUser: ptrInt64(65534)}}}
			return p
		}},
		"MCP, container with its own env and envFrom before injection": {cfg: mcpIntegrityConfig, pod: func() corev1.Pod {
			p := mcpIntegrityPod()
			c := &p.Spec.Containers[1]
			c.EnvFrom = []corev1.EnvFromSource{{SecretRef: &corev1.SecretEnvSource{
				LocalObjectReference: corev1.LocalObjectReference{Name: "github-token"}}}}
			c.Env = []corev1.EnvVar{{Name: "HTTPS_PROXY", Value: "http://egress.corp:3128"},
				{Name: "NRVQ_SDK_FALLBACK_MODE", Value: "allow"}}
			return p
		}},
	}
	runCopyCases(t, cases)
}

// The annotation is checked first, so the untouched copies above are all refused naming it. The same
// copy with the annotation removed is still refused, naming the next part, so the refusal does not
// hang on the one marker a copy is most likely to lose.
func TestInjectorOwnedCopies_DeniedWithoutTheAnnotationToo(t *testing.T) {
	for name, cfg := range map[string]Config{"sidecar": integrityConfig(), "MCP": mcpIntegrityConfig()} {
		t.Run(name, func(t *testing.T) {
			pod := integrityPod()
			if cfg.McpInject {
				pod = mcpIntegrityPod()
			}
			out := injectorOutput(t, cfg, pod, nil)
			assertDenied(t, cfg, out, codeOwnedPart, "carries the norviq.io/injected annotation")
			delete(out.Annotations, injectedAnnotation)
			assertDenied(t, cfg, out, codeOwnedPart, "the pod declares the injector-owned volume norviq-socket")
		})
	}
}

// --- the sidecar ----------------------------------------------------------------------------------

func TestInjectorOwnedCopies_TamperedSidecarIsDenied(t *testing.T) {
	side := func(change func(s *corev1.Container)) func(t *testing.T, _ Config, p *corev1.Pod) {
		return func(t *testing.T, _ Config, p *corev1.Pod) { change(sidecarIn(t, p)) }
	}
	cases := map[string]copyCase{
		"fallback mode changed to allow": {cfg: integrityConfig, tamper: side(func(s *corev1.Container) {
			setEnv(s, "NRVQ_SDK_FALLBACK_MODE", "allow")
		})},
		"fallback mode appended a second time": {cfg: integrityConfig, tamper: side(func(s *corev1.Container) {
			appendEnv(s, "NRVQ_SDK_FALLBACK_MODE", "allow")
		})},
		"fallback mode removed": {cfg: integrityConfig, tamper: side(func(s *corev1.Container) {
			removeEnv(s, "NRVQ_SDK_FALLBACK_MODE")
		})},
		"fallback mode lowercase duplicate": {cfg: integrityConfig, tamper: side(func(s *corev1.Container) {
			appendEnv(s, "nrvq_sdk_fallback_mode", "allow")
		})},
		"HTTP_PROXY":    {cfg: integrityConfig, tamper: side(func(s *corev1.Container) { setEnv(s, "HTTP_PROXY", unreachableProxy) })},
		"HTTPS_PROXY":   {cfg: integrityConfig, tamper: side(func(s *corev1.Container) { setEnv(s, "HTTPS_PROXY", unreachableProxy) })},
		"ALL_PROXY":     {cfg: integrityConfig, tamper: side(func(s *corev1.Container) { setEnv(s, "ALL_PROXY", unreachableProxy) })},
		"http_proxy":    {cfg: integrityConfig, tamper: side(func(s *corev1.Container) { setEnv(s, "http_proxy", unreachableProxy) })},
		"https_proxy":   {cfg: integrityConfig, tamper: side(func(s *corev1.Container) { setEnv(s, "https_proxy", unreachableProxy) })},
		"all_proxy":     {cfg: integrityConfig, tamper: side(func(s *corev1.Container) { setEnv(s, "all_proxy", unreachableProxy) })},
		"SSL_CERT_FILE": {cfg: integrityConfig, tamper: side(func(s *corev1.Container) { setEnv(s, "SSL_CERT_FILE", "/tmp/other-ca.pem") })},
		"unknown NRVQ_ setting": {cfg: integrityConfig, tamper: side(func(s *corev1.Container) {
			setEnv(s, "NRVQ_SIDECAR_REMOTE_CALLERS", "allow")
		})},
		"NRVQ_NO_POLICY_DECISION": {cfg: integrityConfig, tamper: side(func(s *corev1.Container) {
			setEnv(s, "NRVQ_NO_POLICY_DECISION", "allow")
		})},
		"NRVQ_OPA_URL": {cfg: integrityConfig, tamper: side(func(s *corev1.Container) {
			setEnv(s, "NRVQ_OPA_URL", "http://127.0.0.1:8181")
		})},
		"NRVQ_HTTP_FALLBACK_PORT moved": {cfg: integrityConfig, tamper: side(func(s *corev1.Container) {
			setEnv(s, "NRVQ_HTTP_FALLBACK_PORT", "18282")
		})},
		"NRVQ_SOCKET_PATH changed": {cfg: integrityConfig, tamper: side(func(s *corev1.Container) {
			setEnv(s, "NRVQ_SOCKET_PATH", "/var/run/norviq/other.sock")
		})},
		"API URL changed": {cfg: integrityConfig, tamper: side(func(s *corev1.Container) {
			setEnv(s, "NRVQ_API_URL", "http://127.0.0.1:9999")
		})},
		"API URL duplicated, other value last": {cfg: integrityConfig, tamper: side(func(s *corev1.Container) {
			appendEnv(s, "NRVQ_API_URL", "http://127.0.0.1:9999")
		})},
		"namespace changed": {cfg: integrityConfig, tamper: side(func(s *corev1.Container) {
			setEnv(s, "NRVQ_NAMESPACE", "team-b")
		})},
		"namespace read from a fieldRef": {cfg: integrityConfig, tamper: side(func(s *corev1.Container) {
			for i := range s.Env {
				if s.Env[i].Name == "NRVQ_NAMESPACE" {
					s.Env[i] = corev1.EnvVar{Name: "NRVQ_NAMESPACE", ValueFrom: &corev1.EnvVarSource{
						FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.annotations['ns']"}}}
				}
			}
		})},
		"agent class changed": {cfg: integrityConfig, tamper: side(func(s *corev1.Container) {
			setEnv(s, "NRVQ_AGENT_CLASS", "admin")
		})},
		"token signed with another secret": {cfg: integrityConfig, tamper: func(t *testing.T, cfg Config, p *corev1.Pod) {
			other := cfg
			other.ApiSecret = "not-the-webhook-secret"
			setEnv(sidecarIn(t, p), "NRVQ_API_TOKEN", mintSidecarToken(other, integrityNamespace, "support", "checkout"))
		}},
		"token minted for another agent class": {cfg: integrityConfig, tamper: func(t *testing.T, cfg Config, p *corev1.Pod) {
			setEnv(sidecarIn(t, p), "NRVQ_API_TOKEN", mintSidecarToken(cfg, integrityNamespace, "admin", "checkout"))
		}},
		"token removed": {cfg: integrityConfig, tamper: side(func(s *corev1.Container) { removeEnv(s, "NRVQ_API_TOKEN") })},
		"envFrom added": {cfg: integrityConfig, tamper: side(func(s *corev1.Container) {
			s.EnvFrom = []corev1.EnvFromSource{{ConfigMapRef: &corev1.ConfigMapEnvSource{
				LocalObjectReference: corev1.LocalObjectReference{Name: "sidecar-overrides"}}}}
		})},
		"command overridden": {cfg: integrityConfig, tamper: side(func(s *corev1.Container) {
			s.Command = []string{"python", "-m", "http.server"}
		})},
		"args overridden":       {cfg: integrityConfig, tamper: side(func(s *corev1.Container) { s.Args = []string{"--fallback", "allow"} })},
		"working directory set": {cfg: integrityConfig, tamper: side(func(s *corev1.Container) { s.WorkingDir = "/tmp" })},
		"postStart hook added": {cfg: integrityConfig, tamper: side(func(s *corev1.Container) {
			s.Lifecycle = &corev1.Lifecycle{PostStart: &corev1.LifecycleHandler{
				Exec: &corev1.ExecAction{Command: []string{"sh", "-c", "true"}}}}
		})},
		"readiness probe replaced with exec": {cfg: integrityConfig, tamper: side(func(s *corev1.Container) {
			s.ReadinessProbe = &corev1.Probe{ProbeHandler: corev1.ProbeHandler{
				Exec: &corev1.ExecAction{Command: []string{"sh", "-c", "true"}}}}
		})},
		"liveness probe pointed at a dead port": {cfg: integrityConfig, tamper: side(func(s *corev1.Container) {
			s.LivenessProbe = &corev1.Probe{ProbeHandler: corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{
				Path: "/nope", Port: intstr.FromInt(1)}}}
		})},
		"probe host redirected": {cfg: integrityConfig, tamper: side(func(s *corev1.Container) {
			s.ReadinessProbe.HTTPGet.Host = "10.0.0.99"
			s.LivenessProbe.HTTPGet.Host = "10.0.0.99"
		})},
		"probe host external": {cfg: integrityConfig, tamper: side(func(s *corev1.Container) {
			s.ReadinessProbe.HTTPGet.Host = "example.com"
		})},
		"socket mount swapped to another volume": {cfg: integrityConfig, tamper: func(t *testing.T, _ Config, p *corev1.Pod) {
			addVolume(p, "other-sock")
			s := sidecarIn(t, p)
			for i := range s.VolumeMounts {
				if s.VolumeMounts[i].Name == socketVolumeName {
					s.VolumeMounts[i].Name = "other-sock"
				}
			}
		}},
		"socket mount made read-only": {cfg: integrityConfig, tamper: side(func(s *corev1.Container) {
			for i := range s.VolumeMounts {
				if s.VolumeMounts[i].Name == socketVolumeName {
					s.VolumeMounts[i].ReadOnly = true
				}
			}
		})},
		"app socket mount narrowed with a subPath": {cfg: integrityConfig, tamper: func(t *testing.T, _ Config, p *corev1.Pod) {
			a := containerIn(t, p, "agent")
			for i := range a.VolumeMounts {
				if a.VolumeMounts[i].Name == socketVolumeName {
					a.VolumeMounts[i].SubPath = "decoy"
				}
			}
		}},
		"app mounts the socket volume a second time": {cfg: integrityConfig, tamper: func(t *testing.T, _ Config, p *corev1.Pod) {
			a := containerIn(t, p, "agent")
			a.VolumeMounts = append(a.VolumeMounts, corev1.VolumeMount{Name: socketVolumeName, MountPath: "/other"})
		}},
		"extra sidecar mount of the socket volume": {cfg: integrityConfig, tamper: side(func(s *corev1.Container) {
			s.VolumeMounts = append(s.VolumeMounts, corev1.VolumeMount{Name: socketVolumeName, MountPath: "/x"})
		})},
		"socket volume made a hostPath": {cfg: integrityConfig, tamper: func(_ *testing.T, _ Config, p *corev1.Pod) {
			replaceVolume(p, socketVolumeName, corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/run/shared"}})
		}},
		"socket volume medium and size limit changed": {cfg: integrityConfig, tamper: func(_ *testing.T, _ Config, p *corev1.Pod) {
			for i := range p.Spec.Volumes {
				if p.Spec.Volumes[i].Name == socketVolumeName {
					p.Spec.Volumes[i].EmptyDir.Medium = corev1.StorageMediumMemory
					p.Spec.Volumes[i].EmptyDir.SizeLimit = nil
				}
			}
		}},
		"scratch volume made a configMap": {cfg: integrityConfig, tamper: func(_ *testing.T, _ Config, p *corev1.Pod) {
			replaceVolume(p, tmpVolumeName, corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{
				LocalObjectReference: corev1.LocalObjectReference{Name: "scratch"}}})
		}},
		"scratch volume size limit of one byte": {cfg: integrityConfig, tamper: func(_ *testing.T, _ Config, p *corev1.Pod) {
			q := resource.MustParse("1")
			replaceVolume(p, tmpVolumeName, corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{
				Medium: corev1.StorageMediumMemory, SizeLimit: &q}})
		}},
		"extra mount over the package": {cfg: integrityConfig, tamper: func(t *testing.T, _ Config, p *corev1.Pod) {
			p.Spec.Volumes = append(p.Spec.Volumes, corev1.Volume{Name: "code",
				VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{Name: "patched-norviq"}}}})
			s := sidecarIn(t, p)
			s.VolumeMounts = append(s.VolumeMounts, corev1.VolumeMount{Name: "code", MountPath: "/app/norviq"})
		}},
		"hostPath at the service-account token path": {cfg: integrityConfig, tamper: func(t *testing.T, _ Config, p *corev1.Pod) {
			p.Spec.Volumes = append(p.Spec.Volumes, corev1.Volume{Name: "anything",
				VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/"}}})
			s := sidecarIn(t, p)
			s.VolumeMounts = append(s.VolumeMounts, corev1.VolumeMount{Name: "anything", MountPath: serviceAccountTokenPath, ReadOnly: true})
		}},
		"memory limit 1Mi": {cfg: integrityConfig, tamper: side(func(s *corev1.Container) {
			s.Resources.Limits = corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("1Mi")}
		})},
		"memory limit and request 4Mi": {cfg: integrityConfig, tamper: side(func(s *corev1.Container) {
			q := resource.MustParse("4Mi")
			s.Resources.Limits = corev1.ResourceList{corev1.ResourceMemory: q}
			s.Resources.Requests = corev1.ResourceList{corev1.ResourceMemory: q}
		})},
		"resources removed": {cfg: integrityConfig, tamper: side(func(s *corev1.Container) { s.Resources = corev1.ResourceRequirements{} })},
		"runs as root with a writable root filesystem": {cfg: integrityConfig, tamper: side(func(s *corev1.Container) {
			s.SecurityContext = &corev1.SecurityContext{RunAsUser: ptrInt64(0), ReadOnlyRootFilesystem: ptrBool(false),
				RunAsNonRoot: ptrBool(false)}
		})},
		"privileged": {cfg: integrityConfig, tamper: side(func(s *corev1.Container) {
			s.SecurityContext = &corev1.SecurityContext{Privileged: ptrBool(true)}
		})},
		"privileged as root with escalation": {cfg: integrityConfig, tamper: side(func(s *corev1.Container) {
			s.SecurityContext = &corev1.SecurityContext{RunAsUser: ptrInt64(0), RunAsNonRoot: ptrBool(false),
				ReadOnlyRootFilesystem: ptrBool(false), Privileged: ptrBool(true), AllowPrivilegeEscalation: ptrBool(true)}
		})},
		"securityContext removed": {cfg: integrityConfig, tamper: side(func(s *corev1.Container) { s.SecurityContext = nil })},
		"hostPort on the sidecar port": {cfg: integrityConfig, tamper: side(func(s *corev1.Container) {
			for i := range s.Ports {
				s.Ports[i].HostPort = s.Ports[i].ContainerPort
			}
		})},
		"ports replaced with a hostPort": {cfg: integrityConfig, tamper: side(func(s *corev1.Container) {
			s.Ports = []corev1.ContainerPort{{ContainerPort: 8282, HostPort: 8282}}
		})},
		"stdin and tty":         {cfg: integrityConfig, tamper: side(func(s *corev1.Container) { s.Stdin = true; s.TTY = true })},
		"imagePullPolicy Never": {cfg: integrityConfig, tamper: side(func(s *corev1.Container) { s.ImagePullPolicy = corev1.PullNever })},
		"pod hostAliases for the API": {cfg: integrityConfig, tamper: func(_ *testing.T, _ Config, p *corev1.Pod) {
			p.Spec.HostAliases = []corev1.HostAlias{{IP: "127.0.0.1", Hostnames: []string{"norviq-api", "norviq-api.norviq.svc"}}}
		}},
		"pod dnsPolicy None": {cfg: integrityConfig, tamper: func(_ *testing.T, _ Config, p *corev1.Pod) {
			p.Spec.DNSPolicy = corev1.DNSNone
			p.Spec.DNSConfig = &corev1.PodDNSConfig{Nameservers: []string{"10.9.9.9"}}
		}},
		"pod shareProcessNamespace": {cfg: integrityConfig, tamper: func(_ *testing.T, _ Config, p *corev1.Pod) {
			p.Spec.ShareProcessNamespace = ptrBool(true)
		}},
		"pod-level PVC and supplementalGroups only": {cfg: integrityConfig, tamper: func(_ *testing.T, _ Config, p *corev1.Pod) {
			addPVC(p, "blk")
			p.Spec.SecurityContext = &corev1.PodSecurityContext{SupplementalGroups: []int64{6}}
		}},
		"relabelled to another agent class": {cfg: integrityConfig, tamper: func(_ *testing.T, _ Config, p *corev1.Pod) {
			p.Labels["norviq.io/agent-class"] = "admin"
		}},
		"second sidecar-image container beside the real one": {cfg: integrityConfig, tamper: func(_ *testing.T, cfg Config, p *corev1.Pod) {
			p.Spec.Containers = append(p.Spec.Containers, corev1.Container{
				Name: "norviq-sidecar-2", Image: cfg.SidecarImage,
				VolumeMounts: []corev1.VolumeMount{{Name: socketVolumeName, MountPath: socketMountPath}},
				Env: []corev1.EnvVar{{Name: "NRVQ_SOCKET_PATH", Value: socketFilePath}, {Name: "NRVQ_SIDECAR_MODE", Value: "proxy"},
					{Name: "NRVQ_API_URL", Value: cfg.ApiURL}, {Name: "NRVQ_SDK_FALLBACK_MODE", Value: "allow"},
					{Name: "HTTPS_PROXY", Value: unreachableProxy}},
			})
		}},
		"rogue engine wired in spec.containers": {cfg: integrityConfig, tamper: func(_ *testing.T, cfg Config, p *corev1.Pod) {
			p.Spec.Containers = append([]corev1.Container{rogueEngine(cfg, nil, true)}, p.Spec.Containers...)
		}},
		"app container's own fallback in embedded mode, scratch mounted": {cfg: embeddedIntegrityConfig, tamper: func(t *testing.T, _ Config, p *corev1.Pod) {
			a := containerIn(t, p, "agent")
			a.VolumeMounts = append(a.VolumeMounts, corev1.VolumeMount{Name: tmpVolumeName, MountPath: "/sidecar-tmp"})
		}},
		"SPIFFE: app NRVQ_SPIFFE_MODE appended last": {cfg: spiffeIntegrityConfig, tamper: func(t *testing.T, _ Config, p *corev1.Pod) {
			appendEnv(containerIn(t, p, "agent"), "NRVQ_SPIFFE_MODE", "mock")
		}},
		"SPIFFE: app NRVQ_SPIFFE_SOCKET overridden last": {cfg: spiffeIntegrityConfig, tamper: func(t *testing.T, _ Config, p *corev1.Pod) {
			appendEnv(containerIn(t, p, "agent"), "NRVQ_SPIFFE_SOCKET", "unix:///var/run/norviq/evil.sock")
		}},
		"SPIFFE: app without the SPIFFE env and mount": {cfg: spiffeIntegrityConfig, tamper: func(t *testing.T, _ Config, p *corev1.Pod) {
			a := containerIn(t, p, "agent")
			removeEnv(a, "NRVQ_SPIFFE_MODE")
			removeEnv(a, "NRVQ_SPIFFE_SOCKET")
			var kept []corev1.VolumeMount
			for _, m := range a.VolumeMounts {
				if m.Name != spiffeVolumeName {
					kept = append(kept, m)
				}
			}
			a.VolumeMounts = kept
		}},
	}
	runCopyCases(t, cases)
}

// rogueEngine is a container running the sidecar image's own entrypoint with a pod author's outage
// posture and an unreachable proxy, optionally pre-wired to the enforcement socket.
func rogueEngine(cfg Config, restart *corev1.ContainerRestartPolicy, wired bool) corev1.Container {
	c := corev1.Container{
		Name: "warmup", Image: configuredSidecarImage(cfg), RestartPolicy: restart,
		Env: []corev1.EnvVar{{Name: "NRVQ_SDK_FALLBACK_MODE", Value: "allow"},
			{Name: "HTTPS_PROXY", Value: unreachableProxy}, {Name: "HTTP_PROXY", Value: unreachableProxy},
			{Name: "NRVQ_HTTP_FALLBACK_PORT", Value: "18282"}},
		LivenessProbe: &corev1.Probe{ProbeHandler: corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{
			Path: "/nope", Port: intstr.FromInt(1)}}},
	}
	if wired {
		c.Env = append(c.Env, corev1.EnvVar{Name: "NRVQ_SOCKET_PATH", Value: socketFilePath})
		c.VolumeMounts = []corev1.VolumeMount{{Name: socketVolumeName, MountPath: socketMountPath}}
	}
	return c
}

// The injector never adds an init container running the sidecar image or named as the sidecar.
func TestInjectorOwnedCopies_SidecarClaimInInitContainersIsDenied(t *testing.T) {
	always := corev1.ContainerRestartPolicyAlways
	add := func(c func(cfg Config) corev1.Container) func(*testing.T, Config, *corev1.Pod) {
		return func(_ *testing.T, cfg Config, p *corev1.Pod) {
			p.Spec.InitContainers = append(p.Spec.InitContainers, c(cfg))
		}
	}
	runCopyCases(t, map[string]copyCase{
		"native sidecar running the engine entrypoint, wired": {cfg: integrityConfig,
			tamper: add(func(cfg Config) corev1.Container { return rogueEngine(cfg, &always, true) })},
		"plain init container running the engine, wired": {cfg: integrityConfig,
			tamper: add(func(cfg Config) corev1.Container { return rogueEngine(cfg, nil, true) })},
		"native sidecar running the engine entrypoint, unwired": {cfg: integrityConfig,
			tamper: add(func(cfg Config) corev1.Container { return rogueEngine(cfg, &always, false) })},
		"init container named as the sidecar": {cfg: integrityConfig, tamper: add(func(Config) corev1.Container {
			return corev1.Container{Name: injectedSidecarName, Image: "busybox:1.36",
				Env:          []corev1.EnvVar{{Name: "NRVQ_SOCKET_PATH", Value: socketFilePath}},
				VolumeMounts: []corev1.VolumeMount{{Name: socketVolumeName, MountPath: socketMountPath}}}
		})},
	})
}

// Another image in the sidecar slot: an older or newer engine tag, the project's other components (the
// repository holds every component's image under one name), a digest, a registry the injector would
// refuse, under a tag and under a digest pin.
func TestInjectorOwnedCopies_SidecarImageChangedIsDenied(t *testing.T) {
	images := []string{
		"ghcr.io/norviq-dev/norviq-engine:engine-some-old-sha",
		"ghcr.io/norviq-dev/norviq-engine:engine-0.2.2",
		"ghcr.io/norviq-dev/norviq-engine:engine-0.1.1",
		"ghcr.io/norviq-dev/norviq-engine:engine-0.1.0",
		"ghcr.io/norviq-dev/norviq-engine:engine-latest",
		"ghcr.io/norviq-dev/norviq-engine:0.2.2",
		"ghcr.io/norviq-dev/norviq-engine:ui-0.2.6",
		"ghcr.io/norviq-dev/norviq-engine:api-0.2.6",
		"ghcr.io/norviq-dev/norviq-engine:api-0.2.2",
		"ghcr.io/norviq-dev/norviq-engine:webhook-0.2.6",
		"ghcr.io/norviq-dev/norviq-engine:bootstrap-0.2.6",
		"ghcr.io/norviq-dev/norviq-engine:api-latest",
		"ghcr.io/norviq-dev/norviq-engine:0.2.6",
		"ghcr.io/norviq-dev/norviq-engine@sha256:" + strings.Repeat("0", 64),
		"ghcr.io/norviq-dev/norviq-engine@sha256:" + strings.Repeat("b", 64),
		"docker.io/attacker/norviq-engine:engine-x",
		"norviq/norviq-engine:engine-latest",
	}
	configs := map[string]func() Config{
		"tag configuration": func() Config {
			return withSidecarImage(integrityConfig(), "ghcr.io/norviq-dev/norviq-engine:engine-0.2.6")
		},
		"digest configuration": func() Config { return withSidecarImage(integrityConfig(), pinnedSidecarImage) },
	}
	cases := map[string]copyCase{}
	for cfgName, cfg := range configs {
		for _, img := range images {
			img := img
			cases[cfgName+"/"+img] = copyCase{cfg: cfg, tamper: func(t *testing.T, _ Config, p *corev1.Pod) {
				sidecarIn(t, p).Image = img
			}}
		}
		cases[cfgName+"/older engine tag with fallback changed"] = copyCase{cfg: cfg, tamper: func(t *testing.T, _ Config, p *corev1.Pod) {
			s := sidecarIn(t, p)
			s.Image = "ghcr.io/norviq-dev/norviq-engine:engine-some-old-sha"
			setEnv(s, "NRVQ_SDK_FALLBACK_MODE", "allow")
		}}
	}
	runCopyCases(t, cases)
}

func TestInjectorOwnedCopies_SecretReferenceChangedIsDenied(t *testing.T) {
	ref := func(change func(*corev1.SecretKeySelector)) func(*testing.T, Config, *corev1.Pod) {
		return func(t *testing.T, _ Config, p *corev1.Pod) {
			tok, ok := envOn(sidecarIn(t, p), "NRVQ_API_TOKEN")
			if !ok || tok.ValueFrom == nil || tok.ValueFrom.SecretKeyRef == nil {
				t.Fatalf("fixture: expected a secretKeyRef token, got %+v", tok)
			}
			change(tok.ValueFrom.SecretKeyRef)
		}
	}
	runCopyCases(t, map[string]copyCase{
		"another Secret":     {cfg: integrityConfig, writer: true, tamper: ref(func(r *corev1.SecretKeySelector) { r.Name = "norviq-sidecar-admin-0000beef" })},
		"another key":        {cfg: integrityConfig, writer: true, tamper: ref(func(r *corev1.SecretKeySelector) { r.Key = "NRVQ_OTHER_TOKEN" })},
		"optional reference": {cfg: integrityConfig, writer: true, tamper: ref(func(r *corev1.SecretKeySelector) { r.Optional = ptrBool(true) })},
		"unchanged":          {cfg: integrityConfig, writer: true, tamper: ref(func(*corev1.SecretKeySelector) {})},
	})
}

func TestInjectorOwnedCopies_TLSMaterialChangedIsDenied(t *testing.T) {
	caFile, keyFile, _ := writeTestCA(t, t.TempDir())
	otherCA, otherKey, _ := writeTestCA(t, t.TempDir())
	otherCfg := Config{CACertFile: otherCA, CAKeyFile: otherKey}
	tlsCfg := func() Config { return tlsIntegrityConfig(caFile, keyFile) }
	withMaterial := func(change func(t *testing.T, cfg Config, s *corev1.Container)) func(*testing.T, Config, *corev1.Pod) {
		return func(t *testing.T, cfg Config, p *corev1.Pod) {
			s := sidecarIn(t, p)
			if _, ok := envOn(s, "NRVQ_CLIENT_CERT_PEM"); !ok {
				t.Fatal("fixture: the injector did not deliver mTLS material")
			}
			change(t, cfg, s)
		}
	}
	runCopyCases(t, map[string]copyCase{
		"CA bundle swapped": {cfg: tlsCfg, tamper: withMaterial(func(t *testing.T, _ Config, s *corev1.Container) {
			pemBytes, err := os.ReadFile(otherCA)
			if err != nil {
				t.Fatal(err)
			}
			setEnv(s, "NRVQ_API_CA_PEM", string(pemBytes))
		})},
		"client cert from another CA": {cfg: tlsCfg, tamper: withMaterial(func(t *testing.T, _ Config, s *corev1.Container) {
			cert, key, err := mintClientCert(otherCfg, integrityNamespace)
			if err != nil {
				t.Fatal(err)
			}
			setEnv(s, "NRVQ_CLIENT_CERT_PEM", cert)
			setEnv(s, "NRVQ_CLIENT_KEY_PEM", key)
		})},
		"client cert minted for another namespace": {cfg: tlsCfg, tamper: withMaterial(func(t *testing.T, cfg Config, s *corev1.Container) {
			cert, key, err := mintClientCert(cfg, "team-b")
			if err != nil {
				t.Fatal(err)
			}
			setEnv(s, "NRVQ_CLIENT_CERT_PEM", cert)
			setEnv(s, "NRVQ_CLIENT_KEY_PEM", key)
		})},
		"client key that does not match the cert": {cfg: tlsCfg, tamper: withMaterial(func(t *testing.T, cfg Config, s *corev1.Container) {
			_, key, err := mintClientCert(cfg, integrityNamespace)
			if err != nil {
				t.Fatal(err)
			}
			setEnv(s, "NRVQ_CLIENT_KEY_PEM", key)
		})},
		"downgraded to plaintext": {cfg: tlsCfg, tamper: withMaterial(func(_ *testing.T, cfg Config, s *corev1.Container) {
			for _, n := range []string{"NRVQ_INTERNAL_TLS", "NRVQ_API_CA_PEM", "NRVQ_CLIENT_CERT_PEM", "NRVQ_CLIENT_KEY_PEM"} {
				removeEnv(s, n)
			}
			setEnv(s, "NRVQ_API_URL", cfg.ApiURL)
		})},
		"REQUESTS_CA_BUNDLE added": {cfg: tlsCfg, tamper: withMaterial(func(_ *testing.T, _ Config, s *corev1.Container) {
			setEnv(s, "REQUESTS_CA_BUNDLE", "/tmp/other-ca.pem")
		})},
	})
}

// Volume devices and termination message paths make the kubelet create a file at a path the pod author
// picks inside the sidecar, the way an extra mount does.
func TestInjectorOwnedCopies_KubeletPlacedFilesAreDenied(t *testing.T) {
	const packageFile = "/usr/local/lib/python3.12/site-packages/zz.pth"
	withBlock := func(p *corev1.Pod) {
		addPVC(p, "blk")
		p.Spec.SecurityContext = &corev1.PodSecurityContext{SupplementalGroups: []int64{6}}
	}
	side := func(change func(s *corev1.Container)) func(*testing.T, Config, *corev1.Pod) {
		return func(t *testing.T, _ Config, p *corev1.Pod) { withBlock(p); change(sidecarIn(t, p)) }
	}
	runCopyCases(t, map[string]copyCase{
		"API server default termination message path": {cfg: integrityConfig, tamper: side(func(s *corev1.Container) {
			s.TerminationMessagePath = corev1.TerminationMessagePathDefault
			s.TerminationMessagePolicy = corev1.TerminationMessageReadFile
		})},
		"block volume as an extra sidecar mount": {cfg: integrityConfig, tamper: side(func(s *corev1.Container) {
			s.VolumeMounts = append(s.VolumeMounts, corev1.VolumeMount{Name: "blk", MountPath: "/usr/local/lib/python3.12/site-packages/zz"})
		})},
		"volume device in site-packages": {cfg: integrityConfig, tamper: side(func(s *corev1.Container) {
			s.VolumeDevices = append(s.VolumeDevices, corev1.VolumeDevice{Name: "blk", DevicePath: packageFile})
		})},
		"volume device at an unrelated path": {cfg: integrityConfig, tamper: side(func(s *corev1.Container) {
			s.VolumeDevices = append(s.VolumeDevices, corev1.VolumeDevice{Name: "blk", DevicePath: "/dev/xvdz"})
		})},
		"volume device over the socket file": {cfg: integrityConfig, tamper: side(func(s *corev1.Container) {
			s.VolumeDevices = []corev1.VolumeDevice{{Name: "blk", DevicePath: socketFilePath}}
		})},
		"termination message path over a package file": {cfg: integrityConfig, tamper: side(func(s *corev1.Container) {
			s.TerminationMessagePath = packageFile
		})},
		"termination message path over the sidecar module": {cfg: integrityConfig, tamper: side(func(s *corev1.Container) {
			s.TerminationMessagePath = "/usr/local/lib/python3.12/site-packages/norviq/sidecar/__init__.py"
		})},
		"termination message path over resolv.conf": {cfg: integrityConfig, tamper: side(func(s *corev1.Container) {
			s.TerminationMessagePath = "/etc/resolv.conf"
		})},
		"termination message path in the socket directory": {cfg: integrityConfig, tamper: side(func(s *corev1.Container) {
			s.TerminationMessagePath = socketMountPath + "/log"
		})},
		"termination message path in /tmp": {cfg: integrityConfig, tamper: side(func(s *corev1.Container) {
			s.TerminationMessagePath = "/tmp/x"
		})},
	})
}

// The sidecar's scratch volume holds the mTLS key while the client is built, and in embedded mode the
// policy and input files each evaluation reads. A copy in which another container mounts it, or mounts
// a volume of the pod's own beside it, is refused like any other copy.
func TestInjectorOwnedCopies_ScratchVolumeCopiesAreDenied(t *testing.T) {
	withInit := func() corev1.Pod {
		p := integrityPod()
		p.Spec.InitContainers = []corev1.Container{{Name: "setup", Image: "busybox", Command: []string{"true"}}}
		return p
	}
	targets := map[string]struct {
		cfg       func() Config
		pod       func() corev1.Pod
		container string
	}{
		"app container":           {integrityConfig, integrityPod, "agent"},
		"app container, embedded": {embeddedIntegrityConfig, integrityPod, "agent"},
		"init container":          {integrityConfig, withInit, "setup"},
		"MCP-wrapped container":   {mcpIntegrityConfig, mcpIntegrityPod, "mcp"},
	}
	cases := map[string]copyCase{}
	for name, tc := range targets {
		tc := tc
		cases[name+", untouched"] = copyCase{cfg: tc.cfg, pod: tc.pod}
		cases[name+", mounting a volume of the pod's own"] = copyCase{cfg: tc.cfg, pod: tc.pod,
			tamper: func(t *testing.T, _ Config, p *corev1.Pod) {
				addVolume(p, "scratch")
				c := containerIn(t, p, tc.container)
				c.VolumeMounts = append(c.VolumeMounts, corev1.VolumeMount{Name: "scratch", MountPath: "/scratch"})
			}}
		cases[name+", mounting the scratch volume"] = copyCase{cfg: tc.cfg, pod: tc.pod,
			tamper: func(t *testing.T, _ Config, p *corev1.Pod) {
				c := containerIn(t, p, tc.container)
				c.VolumeMounts = append(c.VolumeMounts, corev1.VolumeMount{Name: tmpVolumeName, MountPath: "/sidecar-tmp"})
			}}
	}
	runCopyCases(t, cases)
}

// --- MCP ----------------------------------------------------------------------------------------------

func TestInjectorOwnedCopies_TamperedWrappedContainerIsDenied(t *testing.T) {
	caFile, keyFile, _ := writeTestCA(t, t.TempDir())
	otherCA, otherKey, _ := writeTestCA(t, t.TempDir())
	tlsMcp := func() Config { return withMcp(tlsIntegrityConfig(caFile, keyFile)) }
	mcp := func(change func(t *testing.T, cfg Config, c *corev1.Container, p *corev1.Pod)) func(*testing.T, Config, *corev1.Pod) {
		return func(t *testing.T, cfg Config, p *corev1.Pod) { change(t, cfg, containerIn(t, p, "mcp"), p) }
	}
	env := func(name, value string) func(*testing.T, Config, *corev1.Pod) {
		return mcp(func(_ *testing.T, _ Config, c *corev1.Container, _ *corev1.Pod) { setEnv(c, name, value) })
	}
	cases := map[string]copyCase{
		"fallback mode changed to allow": {cfg: mcpIntegrityConfig, tamper: env("NRVQ_SDK_FALLBACK_MODE", "allow")},
		"fallback mode appended a second time": {cfg: mcpIntegrityConfig, tamper: mcp(func(_ *testing.T, _ Config, c *corev1.Container, _ *corev1.Pod) {
			appendEnv(c, "NRVQ_SDK_FALLBACK_MODE", "allow")
		})},
		"fallback mode removed": {cfg: mcpIntegrityConfig, tamper: mcp(func(_ *testing.T, _ Config, c *corev1.Container, _ *corev1.Pod) {
			removeEnv(c, "NRVQ_SDK_FALLBACK_MODE")
		})},
		"fallback mode removed and supplied by envFrom": {cfg: mcpIntegrityConfig, tamper: mcp(func(_ *testing.T, _ Config, c *corev1.Container, _ *corev1.Pod) {
			removeEnv(c, "NRVQ_SDK_FALLBACK_MODE")
			c.EnvFrom = append(c.EnvFrom, corev1.EnvFromSource{ConfigMapRef: &corev1.ConfigMapEnvSource{
				LocalObjectReference: corev1.LocalObjectReference{Name: "mcp-overrides"}}})
		})},
		"envFrom added": {cfg: mcpIntegrityConfig, tamper: mcp(func(_ *testing.T, _ Config, c *corev1.Container, _ *corev1.Pod) {
			c.EnvFrom = append(c.EnvFrom, corev1.EnvFromSource{ConfigMapRef: &corev1.ConfigMapEnvSource{
				LocalObjectReference: corev1.LocalObjectReference{Name: "evil"}}})
		})},
		"envFrom Secret added": {cfg: mcpIntegrityConfig, tamper: mcp(func(_ *testing.T, _ Config, c *corev1.Container, _ *corev1.Pod) {
			c.EnvFrom = []corev1.EnvFromSource{{SecretRef: &corev1.SecretEnvSource{
				LocalObjectReference: corev1.LocalObjectReference{Name: "github-token"}}}}
		})},
		"HTTPS_PROXY appended": {cfg: mcpIntegrityConfig, tamper: mcp(func(_ *testing.T, _ Config, c *corev1.Container, _ *corev1.Pod) {
			appendEnv(c, "HTTPS_PROXY", unreachableProxy)
		})},
		"HTTPS_PROXY and HTTP_PROXY with fallback allow": {cfg: mcpIntegrityConfig, tamper: mcp(func(_ *testing.T, _ Config, c *corev1.Container, _ *corev1.Pod) {
			setEnv(c, "NRVQ_SDK_FALLBACK_MODE", "allow")
			setEnv(c, "HTTPS_PROXY", unreachableProxy)
			setEnv(c, "HTTP_PROXY", unreachableProxy)
		})},
		"own HTTPS_PROXY appended after the injector's env": {cfg: mcpIntegrityConfig, tamper: mcp(func(_ *testing.T, _ Config, c *corev1.Container, _ *corev1.Pod) {
			appendEnv(c, "HTTPS_PROXY", "http://egress.corp:3128")
		})},
		"SSL_CERT_FILE appended": {cfg: mcpIntegrityConfig, tamper: mcp(func(_ *testing.T, _ Config, c *corev1.Container, _ *corev1.Pod) {
			appendEnv(c, "SSL_CERT_FILE", "/tmp/other-ca.pem")
		})},
		"unknown NRVQ_ setting appended": {cfg: mcpIntegrityConfig, tamper: mcp(func(_ *testing.T, _ Config, c *corev1.Container, _ *corev1.Pod) {
			appendEnv(c, "NRVQ_NO_POLICY_DECISION", "allow")
		})},
		"API URL changed": {cfg: mcpIntegrityConfig, tamper: env("NRVQ_API_URL", "http://127.0.0.1:9999")},
		"API URL appended": {cfg: mcpIntegrityConfig, tamper: mcp(func(_ *testing.T, _ Config, c *corev1.Container, _ *corev1.Pod) {
			appendEnv(c, "NRVQ_API_URL", "http://attacker.local:8080")
		})},
		"pin mode changed":    {cfg: mcpIntegrityConfig, tamper: env("NRVQ_MCP_PIN_MODE", "off")},
		"pin store changed":   {cfg: mcpIntegrityConfig, tamper: env("NRVQ_MCP_PIN_STORE", "memory")},
		"namespace changed":   {cfg: mcpIntegrityConfig, tamper: env("NRVQ_NAMESPACE", "team-b")},
		"agent class changed": {cfg: mcpIntegrityConfig, tamper: env("NRVQ_AGENT_CLASS", "admin")},
		"token removed": {cfg: mcpIntegrityConfig, tamper: mcp(func(_ *testing.T, _ Config, c *corev1.Container, _ *corev1.Pod) {
			removeEnv(c, "NRVQ_API_TOKEN")
		})},
		"token signed with another secret": {cfg: mcpIntegrityConfig, tamper: mcp(func(_ *testing.T, cfg Config, c *corev1.Container, _ *corev1.Pod) {
			other := cfg
			other.ApiSecret = "not-the-webhook-secret"
			setEnv(c, "NRVQ_API_TOKEN", mintSidecarToken(other, integrityNamespace, "support", "checkout"))
		})},
		"token minted for another agent class": {cfg: mcpIntegrityConfig, tamper: mcp(func(_ *testing.T, cfg Config, c *corev1.Container, _ *corev1.Pod) {
			setEnv(c, "NRVQ_API_TOKEN", mintSidecarToken(cfg, integrityNamespace, "admin", "checkout"))
		})},
		"token read from a Secret": {cfg: mcpIntegrityConfig, tamper: mcp(func(_ *testing.T, _ Config, c *corev1.Container, _ *corev1.Pod) {
			for i := range c.Env {
				if c.Env[i].Name == "NRVQ_API_TOKEN" {
					c.Env[i] = corev1.EnvVar{Name: "NRVQ_API_TOKEN", ValueFrom: &corev1.EnvVarSource{
						SecretKeyRef: &corev1.SecretKeySelector{Key: "token",
							LocalObjectReference: corev1.LocalObjectReference{Name: "my-token"}}}}
				}
			}
		})},
		"socket path set ahead of the wiring": {cfg: mcpIntegrityConfig, tamper: mcp(func(_ *testing.T, _ Config, c *corev1.Container, _ *corev1.Pod) {
			c.Env = append([]corev1.EnvVar{{Name: "NRVQ_SOCKET_PATH", Value: "/tmp/other.sock"}}, c.Env...)
		})},
		"args added after the wrap": {cfg: mcpIntegrityConfig, tamper: mcp(func(_ *testing.T, _ Config, c *corev1.Container, _ *corev1.Pod) {
			c.Args = []string{"--read-only=false"}
		})},
		"server id changed": {cfg: mcpIntegrityConfig, tamper: mcp(func(_ *testing.T, _ Config, c *corev1.Container, _ *corev1.Pod) {
			c.Command[2] = "other"
		})},
		"unwrapped, everything else left": {cfg: mcpIntegrityConfig, tamper: mcp(func(_ *testing.T, _ Config, c *corev1.Container, _ *corev1.Pod) {
			c.Command = []string{"npx", "server-github"}
		})},
		"wrapped twice": {cfg: mcpIntegrityConfig, tamper: mcp(func(_ *testing.T, _ Config, c *corev1.Container, _ *corev1.Pod) {
			c.Command = append([]string{mcpProxyBinary, "--server-id", "mcp", "--"}, c.Command...)
		})},
		"proxy mount made writable": {cfg: mcpIntegrityConfig, tamper: mcp(func(_ *testing.T, _ Config, c *corev1.Container, _ *corev1.Pod) {
			for i := range c.VolumeMounts {
				if c.VolumeMounts[i].Name == mcpVolumeName {
					c.VolumeMounts[i].ReadOnly = false
				}
			}
		})},
		"proxy mount narrowed with a subPath": {cfg: mcpIntegrityConfig, tamper: mcp(func(_ *testing.T, _ Config, c *corev1.Container, _ *corev1.Pod) {
			for i := range c.VolumeMounts {
				if c.VolumeMounts[i].Name == mcpVolumeName {
					c.VolumeMounts[i].SubPath = "bin"
				}
			}
		})},
		"another volume mounted below the proxy mount": {cfg: mcpIntegrityConfig, tamper: mcp(func(_ *testing.T, _ Config, c *corev1.Container, p *corev1.Pod) {
			p.Spec.Volumes = append(p.Spec.Volumes, corev1.Volume{Name: "shim",
				VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{Name: "shim"}, DefaultMode: ptrInt32(0o755)}}})
			c.VolumeMounts = append(c.VolumeMounts, corev1.VolumeMount{Name: "shim", MountPath: mcpMountPath + "/bin"})
		})},
		"own volume mounted at a symlinked alias of the proxy path": {cfg: mcpIntegrityConfig, tamper: mcp(func(_ *testing.T, _ Config, c *corev1.Container, p *corev1.Pod) {
			addVolume(p, "x")
			c.VolumeMounts = append(c.VolumeMounts, corev1.VolumeMount{Name: "x", MountPath: "/alias/mcp/bin"})
		})},
		"block device below the proxy mount": {cfg: mcpIntegrityConfig, tamper: mcp(func(_ *testing.T, _ Config, c *corev1.Container, p *corev1.Pod) {
			addPVC(p, "blk")
			c.VolumeDevices = []corev1.VolumeDevice{{Name: "blk", DevicePath: "/norviq/mcp/bin/_internal/zz"}}
		})},
		"termination message path below the proxy mount": {cfg: mcpIntegrityConfig, tamper: mcp(func(_ *testing.T, _ Config, c *corev1.Container, _ *corev1.Pod) {
			c.TerminationMessagePath = "/norviq/mcp/bin/_internal/libssl.so.3"
		})},
		"termination message path on the proxy binary": {cfg: mcpIntegrityConfig, tamper: mcp(func(_ *testing.T, _ Config, c *corev1.Container, _ *corev1.Pod) {
			c.TerminationMessagePath = mcpProxyBinary
		})},
		"scratch volume mounted": {cfg: mcpIntegrityConfig, tamper: mcp(func(_ *testing.T, _ Config, c *corev1.Container, _ *corev1.Pod) {
			c.VolumeMounts = append(c.VolumeMounts, corev1.VolumeMount{Name: tmpVolumeName, MountPath: "/sidecar-tmp"})
		})},
		"mTLS: CA bundle swapped": {cfg: tlsMcp, tamper: mcp(func(t *testing.T, _ Config, c *corev1.Container, _ *corev1.Pod) {
			pemBytes, err := os.ReadFile(otherCA)
			if err != nil {
				t.Fatal(err)
			}
			setEnv(c, "NRVQ_API_CA_PEM", string(pemBytes))
		})},
		"mTLS: client cert from another CA": {cfg: tlsMcp, tamper: mcp(func(t *testing.T, _ Config, c *corev1.Container, _ *corev1.Pod) {
			cert, key, err := mintClientCert(Config{CACertFile: otherCA, CAKeyFile: otherKey}, integrityNamespace)
			if err != nil {
				t.Fatal(err)
			}
			setEnv(c, "NRVQ_CLIENT_CERT_PEM", cert)
			setEnv(c, "NRVQ_CLIENT_KEY_PEM", key)
		})},
		"mTLS: client cert minted for another namespace": {cfg: tlsMcp, tamper: mcp(func(t *testing.T, cfg Config, c *corev1.Container, _ *corev1.Pod) {
			cert, key, err := mintClientCert(cfg, "team-b")
			if err != nil {
				t.Fatal(err)
			}
			setEnv(c, "NRVQ_CLIENT_CERT_PEM", cert)
			setEnv(c, "NRVQ_CLIENT_KEY_PEM", key)
		})},
		"mTLS: downgraded to plaintext": {cfg: tlsMcp, tamper: mcp(func(_ *testing.T, cfg Config, c *corev1.Container, _ *corev1.Pod) {
			for _, n := range []string{"NRVQ_INTERNAL_TLS", "NRVQ_API_CA_PEM", "NRVQ_CLIENT_CERT_PEM", "NRVQ_CLIENT_KEY_PEM"} {
				removeEnv(c, n)
			}
			setEnv(c, "NRVQ_API_URL", cfg.ApiURL)
		})},
		"sidecar fallback changed beside an untouched wrap": {cfg: mcpIntegrityConfig, tamper: func(t *testing.T, _ Config, p *corev1.Pod) {
			setEnv(sidecarIn(t, p), "NRVQ_SDK_FALLBACK_MODE", "allow")
		}},
		"sidecar termination message path": {cfg: mcpIntegrityConfig, tamper: func(t *testing.T, _ Config, p *corev1.Pod) {
			sidecarIn(t, p).TerminationMessagePath = "/tmp/x"
		}},
		"app socket mount narrowed with a subPath": {cfg: mcpIntegrityConfig, tamper: func(t *testing.T, _ Config, p *corev1.Pod) {
			a := containerIn(t, p, "agent")
			for i := range a.VolumeMounts {
				if a.VolumeMounts[i].Name == socketVolumeName {
					a.VolumeMounts[i].SubPath = "elsewhere"
				}
			}
		}},
	}
	// Each mode's wrapped container with its outage posture changed.
	for name, cfg := range map[string]func() Config{
		"mode literal":         mcpIntegrityConfig,
		"mode no signing":      func() Config { c := mcpIntegrityConfig(); c.ApiSecret = ""; return c },
		"mode internal mTLS":   tlsMcp,
		"mode SPIFFE":          func() Config { return withMcp(spiffeIntegrityConfig()) },
		"mode pin store/mode":  func() Config { c := mcpIntegrityConfig(); c.McpPinStore = "redis"; c.McpPinMode = "enforce"; return c },
		"mode Secret delivery": mcpIntegrityConfig,
	} {
		cases[name+": fallback changed to allow"] = copyCase{cfg: cfg, writer: name == "mode Secret delivery",
			tamper: env("NRVQ_SDK_FALLBACK_MODE", "allow")}
	}
	runCopyCases(t, cases)
}

func TestInjectorOwnedCopies_TamperedDeliveryInitContainerIsDenied(t *testing.T) {
	const digest = "@sha256:abababababababababababababababababababababababababababababababab"
	always := corev1.ContainerRestartPolicyAlways
	writeShim := []string{"sh", "-c", "printf '#!/bin/sh\\nshift 3\\nexec \"$@\"\\n' > " + mcpInitMountPath + "/bin/norviq-mcp"}
	init := func(change func(c *corev1.Container, p *corev1.Pod)) func(*testing.T, Config, *corev1.Pod) {
		return func(t *testing.T, _ Config, p *corev1.Pod) { change(mcpDeliveryIn(t, p), p) }
	}
	image := func(img string) func(*testing.T, Config, *corev1.Pod) {
		return init(func(c *corev1.Container, _ *corev1.Pod) { c.Image = img })
	}
	digestCfg := func() Config { c := mcpIntegrityConfig(); c.McpProxyImage = pinnedProxyImage; return c }
	portCfg := func() Config {
		c := mcpIntegrityConfig()
		c.McpProxyImage = "registry.corp:5000/tools/norviq-mcp-proxy:1"
		return c
	}
	cases := map[string]copyCase{}
	for _, img := range []string{
		"docker.io/someone/norviq-mcp-proxy:shim",
		"docker.io/attacker/norviq-mcp-proxy:shim",
		"docker.io/attacker/other:x",
		"localhost:5000/norviq-mcp-proxy" + digest,
		"norviq-mcp-proxy:0.2.6",
		"ghcr.io/norviq-dev/norviq-mcp-proxy" + digest,
		"ghcr.io/norviq-dev/norviq-mcp-proxy",
		"ghcr.io/norviq-dev/norviq-mcp-proxy-debug:0.2.6",
		"ghcr.io/norviq-dev/other/norviq-mcp-proxy:0.2.6",
		"ghcr.io/norviq-dev/norviq-mcp-proxy:0.2.5",
		"ghcr.io/norviq-dev/norviq-mcp-proxy:0.1.0",
		"ghcr.io/attacker/norviq-mcp-proxy:0.1.0",
	} {
		cases["tag configuration, image "+img] = copyCase{cfg: mcpIntegrityConfig, tamper: image(img)}
	}
	for _, img := range []string{
		"ghcr.io/norviq-dev/norviq-mcp-proxy:0.1.0",
		"ghcr.io/norviq-dev/norviq-mcp-proxy:0.2.6",
		"ghcr.io/norviq-dev/norviq-mcp-proxy:latest",
		"ghcr.io/norviq-dev/norviq-mcp-proxy@sha256:" + strings.Repeat("2", 64),
		"ghcr.io/attacker/norviq-mcp-proxy:0.1.0",
	} {
		cases["digest configuration, image "+img] = copyCase{cfg: digestCfg, tamper: image(img)}
	}
	cases["registry port configuration, another tag"] = copyCase{cfg: portCfg, tamper: image("registry.corp:5000/tools/norviq-mcp-proxy:2")}
	cases["registry port configuration, another port"] = copyCase{cfg: portCfg, tamper: image("registry.corp:5001/tools/norviq-mcp-proxy:2")}
	for name, change := range map[string]func(c *corev1.Container, p *corev1.Pod){
		"PATH set": func(c *corev1.Container, _ *corev1.Pod) {
			appendEnv(c, "PATH", mcpInitMountPath+"/tools:/usr/bin:/bin")
		},
		"LD_PRELOAD set":        func(c *corev1.Container, _ *corev1.Pod) { appendEnv(c, "LD_PRELOAD", "/tmp/x.so") },
		"socket env duplicated": func(c *corev1.Container, _ *corev1.Pod) { appendEnv(c, "NRVQ_SOCKET_PATH", socketFilePath) },
		"envFrom added": func(c *corev1.Container, _ *corev1.Pod) {
			c.EnvFrom = []corev1.EnvFromSource{{ConfigMapRef: &corev1.ConfigMapEnvSource{
				LocalObjectReference: corev1.LocalObjectReference{Name: "path-override"}}}}
		},
		"extra mount": func(c *corev1.Container, p *corev1.Pod) {
			addVolume(p, "tools")
			c.VolumeMounts = append(c.VolumeMounts, corev1.VolumeMount{Name: "tools", MountPath: "/usr/local/bin"})
		},
		"payload source shadowed": func(c *corev1.Container, p *corev1.Pod) {
			addVolume(p, "shadow")
			c.VolumeMounts = append(c.VolumeMounts, corev1.VolumeMount{Name: "shadow", MountPath: "/opt/norviq/mcp-proxy"})
		},
		"staging mount narrowed with a subPath": func(c *corev1.Container, _ *corev1.Pod) {
			for i := range c.VolumeMounts {
				if c.VolumeMounts[i].Name == mcpVolumeName {
					c.VolumeMounts[i].SubPath = "other"
				}
			}
		},
		"restartPolicy Always":   func(c *corev1.Container, _ *corev1.Pod) { c.RestartPolicy = &always },
		"command copies nothing": func(c *corev1.Container, _ *corev1.Pod) { c.Command = []string{"/bin/sh", "-c", "true"} },
		"postStart hook": func(c *corev1.Container, _ *corev1.Pod) {
			c.Lifecycle = &corev1.Lifecycle{PostStart: &corev1.LifecycleHandler{Exec: &corev1.ExecAction{Command: writeShim}}}
		},
		"startup probe": func(c *corev1.Container, _ *corev1.Pod) {
			c.StartupProbe = &corev1.Probe{ProbeHandler: corev1.ProbeHandler{Exec: &corev1.ExecAction{Command: writeShim}}}
		},
		"working directory": func(c *corev1.Container, _ *corev1.Pod) { c.WorkingDir = "/tmp" },
		"args added":        func(c *corev1.Container, _ *corev1.Pod) { c.Args = []string{"extra"} },
		"runAsUser 0": func(c *corev1.Container, _ *corev1.Pod) {
			c.SecurityContext = &corev1.SecurityContext{RunAsUser: ptrInt64(0)}
		},
		"runAsUser 1234": func(c *corev1.Container, _ *corev1.Pod) {
			c.SecurityContext = &corev1.SecurityContext{RunAsUser: ptrInt64(1234)}
		},
		"termination message path on the staged binary": func(c *corev1.Container, _ *corev1.Pod) {
			c.TerminationMessagePath = mcpInitMountPath + "/bin/norviq-mcp"
		},
		"termination message path on a staged data file": func(c *corev1.Container, _ *corev1.Pod) {
			c.TerminationMessagePath = mcpInitMountPath + "/bin/_internal/certifi/cacert.pem"
		},
		"termination message path over a payload source file": func(c *corev1.Container, _ *corev1.Pod) {
			c.TerminationMessagePath = "/opt/norviq/mcp-proxy/_internal/base_library.zip"
		},
		"API server default termination message path": func(c *corev1.Container, _ *corev1.Pod) {
			c.TerminationMessagePath = corev1.TerminationMessagePathDefault
		},
	} {
		cases[name] = copyCase{cfg: mcpIntegrityConfig, tamper: init(change)}
	}
	// Init containers run in order; the payload staged after an author's native sidecar.
	cases["delivery moved after the author's native sidecar"] = copyCase{cfg: mcpIntegrityConfig,
		pod: func() corev1.Pod {
			p := mcpIntegrityPod()
			p.Spec.ShareProcessNamespace = ptrBool(true)
			p.Spec.InitContainers = []corev1.Container{{Name: "watcher", Image: "alpine:3", Command: []string{"/watch"},
				RestartPolicy: &always}}
			return p
		},
		tamper: func(t *testing.T, _ Config, p *corev1.Pod) {
			ic := p.Spec.InitContainers
			if ic[0].Name != mcpInitContainerName {
				t.Fatalf("fixture: unexpected init order %v", ic)
			}
			p.Spec.InitContainers = []corev1.Container{ic[1], ic[0]}
		}}
	runCopyCases(t, cases)
}

func TestInjectorOwnedCopies_TamperedDeliveryVolumeAndPodIsDenied(t *testing.T) {
	small := resource.MustParse("1Ki")
	volume := func(change func(v *corev1.Volume)) func(*testing.T, Config, *corev1.Pod) {
		return func(_ *testing.T, _ Config, p *corev1.Pod) {
			for i := range p.Spec.Volumes {
				if p.Spec.Volumes[i].Name == mcpVolumeName {
					change(&p.Spec.Volumes[i])
				}
			}
		}
	}
	wired := func(c corev1.Container) corev1.Container {
		c.VolumeMounts = append(c.VolumeMounts, corev1.VolumeMount{Name: socketVolumeName, MountPath: socketMountPath})
		c.Env = append(c.Env, corev1.EnvVar{Name: "NRVQ_SOCKET_PATH", Value: socketFilePath})
		return c
	}
	withTokenMount := func(p *corev1.Pod) {
		p.Spec.Volumes = append(p.Spec.Volumes, corev1.Volume{Name: "kube-api-access-x1",
			VolumeSource: corev1.VolumeSource{Projected: &corev1.ProjectedVolumeSource{}}})
		for _, list := range [][]corev1.Container{p.Spec.InitContainers, p.Spec.Containers} {
			for i := range list {
				list[i].VolumeMounts = append(list[i].VolumeMounts, corev1.VolumeMount{
					Name: "kube-api-access-x1", MountPath: serviceAccountTokenPath, ReadOnly: true})
			}
		}
	}
	runCopyCases(t, map[string]copyCase{
		"medium Memory": {cfg: mcpIntegrityConfig, tamper: volume(func(v *corev1.Volume) { v.EmptyDir.Medium = corev1.StorageMediumMemory })},
		"size limit":    {cfg: mcpIntegrityConfig, tamper: volume(func(v *corev1.Volume) { v.EmptyDir.SizeLimit = &small })},
		"no size limit": {cfg: mcpIntegrityConfig, tamper: volume(func(v *corev1.Volume) { v.EmptyDir.SizeLimit = nil })},
		"hostPath": {cfg: mcpIntegrityConfig, tamper: volume(func(v *corev1.Volume) {
			v.VolumeSource = corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/opt/shim"}}
		})},
		"emptyDir and hostPath": {cfg: mcpIntegrityConfig, tamper: volume(func(v *corev1.Volume) { v.HostPath = &corev1.HostPathVolumeSource{Path: "/opt/shim"} })},
		"another container mounts the proxy volume writable": {cfg: mcpIntegrityConfig, tamper: func(_ *testing.T, _ Config, p *corev1.Pod) {
			p.Spec.Containers = append(p.Spec.Containers, wired(corev1.Container{Name: "helper", Image: "busybox:1.36",
				Command:      []string{"sh", "-c", "sleep 5; cp /x/shim /payload/bin/norviq-mcp; sleep infinity"},
				VolumeMounts: []corev1.VolumeMount{{Name: mcpVolumeName, MountPath: "/payload"}}}))
		}},
		"an unnamed container runs a proxy command": {cfg: mcpIntegrityConfig, tamper: func(_ *testing.T, _ Config, p *corev1.Pod) {
			p.Spec.Containers = append(p.Spec.Containers, wired(corev1.Container{Name: "other", Image: "busybox:1.36",
				Command: []string{mcpProxyBinary, "--server-id", "other", "--", "sh"}}))
		}},
		"the init container's name taken in spec.containers": {cfg: mcpIntegrityConfig, tamper: func(_ *testing.T, _ Config, p *corev1.Pod) {
			p.Spec.Containers = append(p.Spec.Containers, wired(corev1.Container{Name: mcpInitContainerName,
				Image: "busybox:1.36", Command: []string{"sleep", "infinity"}}))
		}},
		"the annotation removed": {cfg: mcpIntegrityConfig, tamper: func(_ *testing.T, _ Config, p *corev1.Pod) {
			delete(p.Annotations, mcpServersAnnotation)
		}},
		"service-account token mount on every container": {cfg: mcpIntegrityConfig, tamper: func(_ *testing.T, _ Config, p *corev1.Pod) {
			withTokenMount(p)
		}},
		"service-account token mount writable on the init container": {cfg: mcpIntegrityConfig, tamper: func(t *testing.T, _ Config, p *corev1.Pod) {
			withTokenMount(p)
			c := mcpDeliveryIn(t, p)
			c.VolumeMounts[len(c.VolumeMounts)-1].ReadOnly = false
		}},
	})
}

// A pod built by hand to look injected, with a shell shim of its own in place of the proxy, and no
// minted token or certificate anywhere in it.
func TestInjectorOwnedCopies_HandBuiltLookalikeIsDenied(t *testing.T) {
	cfg := mcpIntegrityConfig()
	pod := mcpIntegrityPod()
	pod.Spec.Containers = []corev1.Container{
		{Name: injectedSidecarName, Image: configuredSidecarImage(cfg),
			Env: []corev1.EnvVar{{Name: "NRVQ_SIDECAR_MODE", Value: "proxy"}, {Name: "NRVQ_API_URL", Value: cfg.ApiURL},
				{Name: "NRVQ_SOCKET_PATH", Value: socketFilePath}},
			VolumeMounts: []corev1.VolumeMount{{Name: socketVolumeName, MountPath: socketMountPath}}},
		{Name: "mcp", Image: "docker.io/attacker/mcp:1",
			Command: []string{mcpProxyBinary, "--server-id", "mcp", "--", "mcp-server"},
			Env: []corev1.EnvVar{{Name: "NRVQ_SOCKET_PATH", Value: socketFilePath}, {Name: "NRVQ_API_URL", Value: cfg.ApiURL},
				{Name: "NRVQ_MCP_PIN_STORE", Value: cfg.McpPinStore}, {Name: "NRVQ_MCP_PIN_MODE", Value: cfg.McpPinMode}},
			VolumeMounts: []corev1.VolumeMount{{Name: mcpVolumeName, MountPath: mcpMountPath, ReadOnly: true},
				{Name: socketVolumeName, MountPath: socketMountPath}}},
	}
	addVolume(&pod, socketVolumeName)
	addVolume(&pod, mcpVolumeName)
	pod.Spec.InitContainers = []corev1.Container{{
		Name: mcpInitContainerName, Image: "docker.io/attacker/payload:1",
		Command: []string{"/bin/sh", "-c",
			`printf '#!/bin/sh\nshift 3\nexec "$@"\n' > /stage/norviq-mcp; chmod 755 /stage/norviq-mcp`},
		Env:          []corev1.EnvVar{{Name: "NRVQ_SOCKET_PATH", Value: socketFilePath}},
		VolumeMounts: []corev1.VolumeMount{{Name: mcpVolumeName, MountPath: "/stage"}, {Name: socketVolumeName, MountPath: socketMountPath}},
	}}
	assertDenied(t, cfg, pod, codeOwnedPart, "the pod declares the injector-owned volume norviq-socket")
}
