// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// injector_owned.go decides whether a pod being created already carries something the injector adds.
//
// Such a pod is refused. There is no "already injected" outcome: the chart registers this webhook for
// pod CREATE only, with reinvocationPolicy Never, so a pod that reaches it carrying the injector's parts
// is a spec someone wrote or copied (`kubectl get pod -o yaml` of a running pod, `kubectl debug
// --copy-to`, a template filled in from a live object), never one the injector just produced.
//
// Admitting such a pod unpatched meant deciding that its sidecar and MCP wrapping were the ones the
// injector would have built, which takes a comparison of every field the injector emits against
// everything a pod author can set. Each field the comparison did not cover was configuration the pod
// author chose (an outage posture, a proxy variable, another image tag, an extra mount) running under
// the injector's name. Refusing every injector-owned part needs no such list: the webhook builds the
// plumbing itself, from its own configuration, on every pod it admits.
package main

import (
	"path"
	"strings"

	corev1 "k8s.io/api/core/v1"
)

const (
	// socketVolumeName is the shared enforcement-socket volume (volumeTemplate).
	socketVolumeName = "norviq-socket"
	// spiffeVolumeName is the SPIFFE Workload API CSI volume (spiffeVolumeTemplate).
	spiffeVolumeName = "spiffe-workload-api"
	// socketMountPathAlias is the same directory as socketMountPath in any image that follows the
	// FHS and makes /var/run a symlink to /run. The runtime resolves a mount destination through
	// symlinks in the image, so a mount at /run/norviq lands where the injected socket mount does.
	socketMountPathAlias = "/run/norviq"
)

// injectorOwnedVolumes is every volume name the injector adds under cfg.
func injectorOwnedVolumes(cfg Config) map[string]bool {
	owned := map[string]bool{socketVolumeName: true, tmpVolumeName: true}
	if cfg.McpInject {
		owned[mcpVolumeName] = true
	}
	if cfg.SpiffeInject {
		owned[spiffeVolumeName] = true
	}
	return owned
}

// injectorOwnedPaths is every directory the injector mounts something at under cfg.
func injectorOwnedPaths(cfg Config) []string {
	paths := []string{socketMountPath, socketMountPathAlias}
	if cfg.McpInject {
		paths = append(paths, mcpMountPath, mcpInitMountPath)
	}
	if cfg.SpiffeInject {
		paths = append(paths, spiffeMountPath)
	}
	return paths
}

// injectorOwnedEnv is every env name the injector appends to the pod's own containers under cfg.
// (The sidecar's and the MCP proxy's other variables are set only on containers the injector builds or
// wraps, which are recognised by their name, image or command instead; a pod's own container may
// legitimately carry NRVQ_API_URL and the like for the SDK.)
func injectorOwnedEnv(cfg Config) []string {
	names := []string{"NRVQ_SOCKET_PATH"}
	if cfg.SpiffeInject {
		names = append(names, "NRVQ_SPIFFE_MODE", "NRVQ_SPIFFE_SOCKET")
	}
	return names
}

// injectorPlumbing reports the first injector-owned part the pod carries, with the code its denial
// is logged and returned under:
//
//   - NRVQ-WHK-4063: a part the injector itself adds — the norviq.io/injected annotation, one of its
//     volumes or a mount of one, its sidecar or MCP init container (by name), a container running the
//     sidecar image (as it ships, or with any command on a pod that opts out of injection),
//     NRVQ_SOCKET_PATH (and the SPIFFE variables when SPIFFE injection is on), and with MCP injection
//     on a container running the MCP proxy image, a command run under the MCP proxy or naming its
//     executable or payload, or a reference to the sidecar's credential Secret.
//   - NRVQ-WHK-4034: something of the pod's own (a volume, a block device, a termination message
//     file) placed at or below a path the injector mounts its plumbing at.
//
// Checked before any opt-out is honoured: a pod that opts out of injection and carries the plumbing
// anyway reads as governed to anyone looking at its spec, while nothing in it was built by the webhook.
func injectorPlumbing(cfg Config, pod *corev1.Pod) (code string, reason string, found bool) {
	if reason, ok := injectorOwnedPart(cfg, pod); ok {
		return "NRVQ-WHK-4063", reason, true
	}
	if reason, ok := injectorPathOccupied(cfg, pod); ok {
		return "NRVQ-WHK-4034", reason, true
	}
	return "", "", false
}

func injectorOwnedPart(cfg Config, pod *corev1.Pod) (string, bool) {
	if _, ok := pod.Annotations[injectedAnnotation]; ok {
		return "the pod carries the " + injectedAnnotation + " annotation the webhook stamps on pods it injects", true
	}
	volumes := injectorOwnedVolumes(cfg)
	for _, v := range pod.Spec.Volumes {
		if volumes[v.Name] {
			return "the pod declares the injector-owned volume " + v.Name, true
		}
		if name, ok := volumeSidecarSecret(v); ok {
			return "volume " + v.Name + " reads the sidecar credential Secret " + name, true
		}
	}
	configuredImage := configuredSidecarImage(cfg)
	ownedEnv := injectorOwnedEnv(cfg)
	// An opted-out pod is admitted as it stands, with no sidecar added beside it, so there the sidecar
	// image counts as the injector's part whatever command it is given (runsAnySidecarImage).
	injected := !(optedOut(cfg, pod) && cfg.AllowPodOptOut)
	for _, c := range allPodContainers(pod) {
		if c.Name == injectedSidecarName {
			return "container " + c.Name + " takes the injected sidecar's name", true
		}
		if cfg.McpInject && c.Name == mcpInitContainerName {
			return "container " + c.Name + " takes the MCP proxy init container's name", true
		}
		if runsSidecarAsShipped(c, configuredImage) {
			return "container " + c.Name + " runs the sidecar image " + c.Image +
				" with the image's own entrypoint, which is the sidecar the webhook injects", true
		}
		if !injected && runsAnySidecarImage(c, configuredImage) {
			return "container " + c.Name + " runs the sidecar image " + c.Image + " in a pod that" +
				" opts out of injection, so nothing the webhook builds would run beside it", true
		}
		if cfg.McpInject {
			if reason, ok := mcpProxyPart(cfg, c); ok {
				return reason, true
			}
		}
		for _, m := range c.VolumeMounts {
			if volumes[m.Name] {
				return "container " + c.Name + " mounts the injector-owned volume " + m.Name, true
			}
		}
		for _, d := range c.VolumeDevices {
			if volumes[d.Name] {
				return "container " + c.Name + " maps the injector-owned volume " + d.Name + " as a device", true
			}
		}
		for _, e := range c.Env {
			for _, owned := range ownedEnv {
				if e.Name == owned {
					return "container " + c.Name + " sets " + e.Name + ", which the webhook sets", true
				}
			}
			if e.ValueFrom != nil && e.ValueFrom.SecretKeyRef != nil && isSidecarSecretName(e.ValueFrom.SecretKeyRef.Name) {
				return "container " + c.Name + " reads " + e.Name + " from the sidecar credential Secret " +
					e.ValueFrom.SecretKeyRef.Name, true
			}
		}
		for _, src := range c.EnvFrom {
			if src.SecretRef != nil && isSidecarSecretName(src.SecretRef.Name) {
				return "container " + c.Name + " imports the sidecar credential Secret " + src.SecretRef.Name, true
			}
		}
	}
	return "", false
}

// mcpProxyPart reports a container that delivers or runs the MCP proxy, which with MCP injection on
// only the injector does: one running the proxy image (any tag or digest of its repository, under any
// container name), or one whose command or args refer to the proxy's mount or staging path, to its
// executable by name (norviq-mcp, wherever it was copied to), or to the payload's path inside the proxy
// image.
func mcpProxyPart(cfg Config, c corev1.Container) (string, bool) {
	if repo := imageRepository(mcpProxyImage(cfg)); repo != "" && imageRepository(c.Image) == repo {
		return "container " + c.Name + " runs the MCP proxy image " + c.Image +
			", which the webhook runs to deliver the proxy", true
	}
	if runsUnderMcpProxy(c) {
		return "container " + c.Name + " runs a command under the MCP proxy at " + mcpMountPath, true
	}
	for _, tok := range containerCommandLine(c) {
		for _, word := range strings.FieldsFunc(tok, isShellSeparator) {
			if path.Base(word) == mcpProxyExecutable {
				return "container " + c.Name + " runs the MCP proxy executable " + word +
					", which the webhook wraps MCP servers in", true
			}
		}
		if src := cfg.McpProxySourcePath; src != "" && referencesPath(tok, path.Clean(src)) {
			return "container " + c.Name + " refers to the MCP proxy payload at " + src +
				", which the webhook copies into the pod", true
		}
	}
	return "", false
}

// runsSidecarAsShipped reports whether c runs the sidecar image (any registry, tag or digest of the
// configured image's repository name) with neither command nor args — which is what the sidecar the
// injector builds is. Refused on every pod.
//
// A command or args is the line drawn on a pod that is injected. The engine image also carries the
// rest of the norviq package, and running another of its modules beside an agent is a shipped pattern:
// examples/chatbot runs three `norviq.mcp` firewalls from it. Such a container is admitted; the
// injector adds the real sidecar beside it and wires it like any other container. The configured
// repository only, for the same reason: the chatbot itself runs from the -dev repository the allowlist
// also accepts, with that image's own entrypoint. This check recognises the injector's own sidecar
// under another name. It is not what keeps other containers off the enforcement socket: every
// container the injector wires shares the socket volume, which is the cooperative boundary
// docs/security-model.md describes.
func runsSidecarAsShipped(c corev1.Container, configuredImage string) bool {
	if configuredImage == "" || len(c.Command) > 0 || len(c.Args) > 0 {
		return false
	}
	name := imageName(c.Image)
	return name != "" && name == imageName(configuredImage)
}

// runsAnySidecarImage is the rule on a pod that opts out of injection, where no sidecar is added beside
// it: any container running the configured image's repository name or any image the injector's own
// allowlist accepts as a sidecar, whatever its command. The image declares no ENTRYPOINT, so a command
// that spells out its CMD (`python -m norviq.sidecar`) is the sidecar process itself, under a name and
// with settings of the pod's choosing.
func runsAnySidecarImage(c corev1.Container, configuredImage string) bool {
	if c.Image == "" {
		return false
	}
	if isAllowedSidecarImage(c.Image) {
		return true
	}
	name := imageName(c.Image)
	return configuredImage != "" && name != "" && name == imageName(configuredImage)
}

// mcpProxyExecutable is the proxy executable's file name in the payload (mcpProxyBinary's base name).
const mcpProxyExecutable = "norviq-mcp"

func containerCommandLine(c corev1.Container) []string {
	return append(append([]string{}, c.Command...), c.Args...)
}

// isShellSeparator splits a command token into the words a shell would run, so a path inside
// `sh -c "set -e; /tools/norviq-mcp --server-id x -- npx srv"` is seen.
func isShellSeparator(r rune) bool {
	switch r {
	case ' ', '\t', '\n', ';', '&', '|', '(', ')', '<', '>', '\'', '"', '`', '=', '$', '{', '}':
		return true
	}
	return false
}

// imageRepository is an image reference without its tag or digest, with Docker Hub's implied registry
// and library namespace removed, so `docker.io/library/x:1` and `x@sha256:...` name the same
// repository.
func imageRepository(img string) string {
	if i := strings.IndexByte(img, '@'); i >= 0 {
		img = img[:i]
	}
	if colon := strings.LastIndexByte(img, ':'); colon > strings.LastIndexByte(img, '/') {
		img = img[:colon]
	}
	for _, prefix := range []string{"docker.io/", "index.docker.io/"} {
		img = strings.TrimPrefix(img, prefix)
	}
	return strings.TrimPrefix(img, "library/")
}

// runsUnderMcpProxy reports whether any command or args token refers to the proxy's mount or staging
// path, which is how a command wrapped by the injector, or written to look wrapped, begins.
func runsUnderMcpProxy(c corev1.Container) bool {
	for _, tok := range containerCommandLine(c) {
		if referencesPath(tok, mcpMountPath) || referencesPath(tok, mcpInitMountPath) {
			return true
		}
	}
	return false
}

// referencesPath reports whether s names root or a path below it, standing alone or inside a shell
// string (`sh -c "exec /norviq/mcp/bin/norviq-mcp ..."`). Repeated slashes are collapsed first, since
// the kernel treats `/norviq//mcp` as `/norviq/mcp`. A longer name that merely starts with root's last
// segment (`/norviq/mcp-tools`) is not a match.
func referencesPath(s, root string) bool {
	for strings.Contains(s, "//") {
		s = strings.ReplaceAll(s, "//", "/")
	}
	for from := 0; ; {
		idx := strings.Index(s[from:], root)
		if idx < 0 {
			return false
		}
		start, end := from+idx, from+idx+len(root)
		before := start == 0 || !isPathByte(s[start-1])
		after := end == len(s) || s[end] == '/' || !isPathByte(s[end])
		if before && after {
			return true
		}
		from = start + 1
	}
}

func isPathByte(b byte) bool {
	return b == '/' || b == '.' || b == '-' || b == '_' ||
		(b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

// injectorPathOccupied reports a mount, block device or termination message file of the pod's own at
// or below a directory the injector mounts its plumbing at. The runtime layers a deeper path on top of
// a shallower one, so anything placed there would sit over the socket or the proxy binary once the
// pod is injected. (A mount of an injector-owned volume is reported by injectorOwnedPart first.)
func injectorPathOccupied(cfg Config, pod *corev1.Pod) (string, bool) {
	roots := injectorOwnedPaths(cfg)
	for _, c := range allPodContainers(pod) {
		for _, m := range c.VolumeMounts {
			if root, ok := atOrBelowAny(m.MountPath, roots); ok {
				return "container " + c.Name + " mounts volume " + m.Name + " at " + m.MountPath +
					", inside the injector-owned path " + root, true
			}
		}
		for _, d := range c.VolumeDevices {
			if root, ok := atOrBelowAny(d.DevicePath, roots); ok {
				return "container " + c.Name + " maps a device at " + d.DevicePath +
					", inside the injector-owned path " + root, true
			}
		}
		if root, ok := atOrBelowAny(c.TerminationMessagePath, roots); ok {
			return "container " + c.Name + " writes its termination message to " + c.TerminationMessagePath +
				", inside the injector-owned path " + root, true
		}
	}
	return "", false
}

// atOrBelowAny reports the first root that p is equal to or below, after cleaning p the way the runtime
// resolves it (`/var/run/norviq/`, `/var/run//norviq/x` and `/var/run/norviq/./x` all count).
func atOrBelowAny(p string, roots []string) (string, bool) {
	if p == "" {
		return "", false
	}
	clean := path.Clean("/" + p)
	for _, root := range roots {
		if clean == root || strings.HasPrefix(clean, root+"/") {
			return root, true
		}
	}
	return "", false
}

func isSidecarSecretName(name string) bool { return strings.HasPrefix(name, sidecarSecretPrefix) }

func volumeSidecarSecret(v corev1.Volume) (string, bool) {
	if v.Secret != nil && isSidecarSecretName(v.Secret.SecretName) {
		return v.Secret.SecretName, true
	}
	if v.Projected != nil {
		for _, src := range v.Projected.Sources {
			if src.Secret != nil && isSidecarSecretName(src.Secret.Name) {
				return src.Secret.Name, true
			}
		}
	}
	return "", false
}
