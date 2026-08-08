// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// mcp_injector.go makes MCP governance zero-code-change, the way sidecar injection already is for
// the SDK. A pod names its MCP server containers in an annotation; the injector rewrites each one's
// command to run UNDER the Norviq MCP proxy, and delivers that proxy through an init container so
// the upstream image needs nothing installed in it.
//
//	// before                                   // after
//	{"command": ["mcp-server"]}                 {"command": ["/norviq/mcp/norviq-mcp",
//	                                                         "--server-id","fs","--","mcp-server"]}
//
// For stdio this wrapping is the ONLY faithful interception point: a stdio MCP server is a child
// process of its client, so there is no socket to put a gateway in front of — becoming the child is
// the whole mechanism (DESIGN-NOTE-MCP-FIREWALL.md §2.2).
package main

import (
	"fmt"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
)

// mcpServersAnnotation lists the containers in this pod whose command IS an MCP server, comma
// separated. Naming them is required rather than inferred: guessing wrong either leaves a server
// ungoverned or wraps a container that is not an MCP server at all, and both fail silently.
const mcpServersAnnotation = "norviq.io/mcp-servers"

// mcpServerIDPrefix overrides the pin id for one container: norviq.io/mcp-server-id.<container>.
// The id keys the Gate-A definition pins, so it must be stable across restarts and rollouts — the
// container name is the default because it is exactly that.
const mcpServerIDPrefix = "norviq.io/mcp-server-id."

const (
	mcpVolumeName = "norviq-mcp-proxy"
	mcpMountPath  = "/norviq/mcp"
	// The payload lands in a SUBDIRECTORY of the mount, not at its root. The init container runs as
	// 65534 and an emptyDir's root is owned by root, so `cp -a` onto the root failed at the last step
	// with `cp: preserving times for '/…/.': Operation not permitted` — writing was allowed, but
	// setting a directory's timestamps requires owning it. Copying into a directory the init
	// container creates itself means it owns the destination and the copy completes.
	mcpPayloadDir        = "bin"
	mcpProxyBinary       = mcpMountPath + "/" + mcpPayloadDir + "/norviq-mcp"
	mcpInitContainerName = "norviq-mcp-init"
	// Staging path the init container writes to. It mounts the SAME volume at a different path so
	// the app-container mount can stay readOnly.
	mcpInitMountPath = "/norviq-mcp-staging"
)

// mcpTarget is one container to be wrapped, resolved against the pod.
type mcpTarget struct {
	Kind      string // "containers" or "initContainers"
	Index     int
	Name      string
	ServerID  string
	Container corev1.Container
}

// mcpProxyImage is the image the proxy payload is copied from.
//
// There is deliberately NO fallback to the sidecar image. That fallback was wrong: the shipped
// engine image carries the norviq *package*, not the frozen relocatable payload, so `cp
// /opt/norviq/mcp-proxy` finds nothing and every governed pod fails its init container. A default
// that cannot work is worse than no default, because it fails at pod start rather than at install.
// Unset is treated as a misconfiguration and refused at admission with an actionable message.
func mcpProxyImage(cfg Config) string { return cfg.McpProxyImage }

// mcpAnnotatedNames parses the annotation into container names, de-duplicated and order-preserving.
func mcpAnnotatedNames(pod *corev1.Pod) []string {
	raw := pod.Annotations[mcpServersAnnotation]
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	seen := make(map[string]bool)
	names := make([]string, 0, 4)
	for _, part := range strings.Split(raw, ",") {
		name := strings.TrimSpace(part)
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		names = append(names, name)
	}
	return names
}

// mcpTargets resolves the annotated names against the pod's containers.
//
// Both error paths are deliberate DENIALS rather than skips, matching the enforcement-integrity
// posture the sidecar path already takes: the operator asked for these containers to be governed, and
// quietly declining would run an MCP server unpoliced while the annotation says otherwise.
//
//   - a name that matches no container is a typo, and a typo that "worked" is the failure mode.
//   - a container with no explicit `command` cannot be wrapped: its real argv is the image's
//     ENTRYPOINT, which an admission webhook cannot see. Prepending the proxy to `args` would
//     silently produce `ENTRYPOINT norviq-mcp -- …` and run neither correctly.
func mcpTargets(cfg Config, pod *corev1.Pod) ([]mcpTarget, error) {
	names := mcpAnnotatedNames(pod)
	if len(names) == 0 {
		return nil, nil
	}
	if mcpProxyImage(cfg) == "" {
		return nil, fmt.Errorf("MCP injection is enabled but no proxy image is configured; set " +
			"NRVQ_MCP_PROXY_IMAGE (helm: webhook.injection.mcp.proxyImage) to an image containing the " +
			"relocatable payload built by scripts/mcp-proxy-payload.Dockerfile")
	}
	targets := make([]mcpTarget, 0, len(names))
	for _, name := range names {
		kind, idx, container, found := findPodContainer(pod, name)
		if !found {
			return nil, fmt.Errorf("annotation %s names container %q, which this pod does not have",
				mcpServersAnnotation, name)
		}
		if len(container.Command) == 0 {
			return nil, fmt.Errorf("container %q is named by %s but sets no explicit command; the MCP "+
				"proxy cannot wrap an image ENTRYPOINT the webhook cannot see — set command (and args) "+
				"explicitly on that container", name, mcpServersAnnotation)
		}
		targets = append(targets, mcpTarget{
			Kind:      kind,
			Index:     idx,
			Name:      name,
			ServerID:  mcpServerID(pod, name),
			Container: container,
		})
	}
	return targets, nil
}

// mcpServerID is the pin key for a container: the explicit per-container annotation when present,
// otherwise the container name.
func mcpServerID(pod *corev1.Pod, name string) string {
	if id := strings.TrimSpace(pod.Annotations[mcpServerIDPrefix+name]); id != "" {
		return id
	}
	return name
}

func findPodContainer(pod *corev1.Pod, name string) (kind string, idx int, c corev1.Container, found bool) {
	for i, container := range pod.Spec.Containers {
		if container.Name == name {
			return "containers", i, container, true
		}
	}
	for i, container := range pod.Spec.InitContainers {
		if container.Name == name {
			return "initContainers", i, container, true
		}
	}
	return "", 0, corev1.Container{}, false
}

// mcpWrappedCommand is the rewritten argv: the proxy, its flags, then `--`, then the container's
// ORIGINAL command followed by its original args.
//
// command+args are folded into a single `command` because Kubernetes ignores the image CMD once
// `command` is set and `args` is empty — so the caller pairs this with an explicit `args: []` and the
// effective argv is exactly what is returned here. Keeping the original args in place instead would
// append them AFTER the upstream server command, which is where they already belong, but only by
// accident of ordering; folding makes the result independent of how the author split the two fields.
func mcpWrappedCommand(target mcpTarget) []string {
	cmd := []string{mcpProxyBinary, "--server-id", target.ServerID, "--"}
	cmd = append(cmd, target.Container.Command...)
	cmd = append(cmd, target.Container.Args...)
	return cmd
}

// mcpPatches rewrites each target container and mounts the proxy volume into it. The pod-level
// additions (the volume and the init container that fills it) are emitted by the caller.
func mcpPatches(cfg Config, targets []mcpTarget, namespace, agentClass, workload string) []patchOp {
	patches := make([]patchOp, 0, len(targets)*4)
	// Computed ONCE. Under auto-mTLS mcpEnv mints an RSA-2048 client certificate, and building it
	// inside the loop meant a pod with N MCP containers minted N certs on the admission hot path —
	// and gave sibling containers different credentials for no reason.
	env := mcpEnv(cfg, namespace, agentClass, workload)
	for _, target := range targets {
		base := fmt.Sprintf("/spec/%s/%d", target.Kind, target.Index)
		// "add" on an existing object member REPLACES it (RFC 6902 §4.1), so this is an upsert and
		// works whether or not the container declared args.
		patches = append(patches, patchOp{Op: "add", Path: base + "/command", Value: mcpWrappedCommand(target)})
		patches = append(patches, patchOp{Op: "add", Path: base + "/args", Value: []string{}})

		// Both lists are APPENDED to, never created. Patch ops apply in order, and CreatePatch emits
		// the sidecar's mount/env ops first: those create /volumeMounts and /env for any container that
		// had none, and a container they skip was skipped precisely because it already had them. So by
		// the time these ops land both lists exist for every container.
		//
		// Deciding create-vs-append from the ORIGINAL container (the way mountPatches does) is wrong
		// here for exactly that reason: it emits a second "add /volumeMounts", which REPLACES the list
		// the socket patch just created and silently unwires the container from enforcement.
		mount := map[string]interface{}{"name": mcpVolumeName, "mountPath": mcpMountPath, "readOnly": true}
		patches = append(patches, patchOp{Op: "add", Path: base + "/volumeMounts/-", Value: mount})
		for _, e := range env {
			patches = append(patches, patchOp{Op: "add", Path: base + "/env/-", Value: e})
		}
	}
	return patches
}

// mcpEnv is the proxy's wiring. It is deliberately the SAME contract the thin-proxy sidecar already
// uses — NRVQ_API_URL plus a namespace-scoped service JWT — because the MCP proxy calls the identical
// /evaluate endpoint through the identical PolicyEngineClient. Nothing here is MCP-specific except
// the pin backend.
func mcpEnv(cfg Config, namespace, agentClass, workload string) []map[string]interface{} {
	apiURL := cfg.ApiURL
	tlsEnv, tlsOn := buildSidecarTLSEnv(cfg, namespace, &apiURL)
	env := []map[string]interface{}{
		{"name": "NRVQ_API_URL", "value": apiURL},
		{"name": "NRVQ_NAMESPACE", "value": namespace},
		{"name": "NRVQ_AGENT_CLASS", "value": agentClass},
		{"name": "NRVQ_MCP_PIN_STORE", "value": cfg.McpPinStore},
		{"name": "NRVQ_MCP_PIN_MODE", "value": cfg.McpPinMode},
	}
	if tok := mintSidecarToken(cfg, namespace, agentClass, workload); tok != "" {
		env = append(env, map[string]interface{}{"name": "NRVQ_API_TOKEN", "value": tok})
	}
	if tlsOn {
		env = append(env, tlsEnv...)
	}
	// NRVQ_SPIFFE_MODE/SOCKET are deliberately NOT set here. envPatches already adds them to every
	// container when SpiffeInject is on, and adding them again appended a duplicate pair to exactly
	// the containers this path touches. Kubernetes takes the last occurrence, so the values were
	// right and the pod spec was merely confusing — but a duplicated env var is the kind of thing an
	// operator reads as a wiring bug, and there is nothing to gain by restating it.
	//
	// Same outage posture as the sidecar and the SDK, so all three paths behave identically when the
	// engine is unreachable.
	env = appendIfSet(env, "NRVQ_SDK_FALLBACK_MODE", cfg.FallbackMode)
	return env
}

// mcpInitContainer copies the proxy into the shared volume before any app container starts.
//
// This is what makes the injection zero-code-change: the upstream MCP server image needs no norviq
// package, no Python, and no cooperation — it just execs a file that is already there. The copy is a
// plain `cp` so the init container inherits the proxy image's own security posture and adds no
// tooling of its own.
func mcpInitContainer(cfg Config) map[string]interface{} {
	src := cfg.McpProxySourcePath
	dstDir := mcpInitMountPath + "/" + mcpPayloadDir
	binary := dstDir + "/norviq-mcp"
	return map[string]interface{}{
		"name":  mcpInitContainerName,
		"image": mcpProxyImage(cfg),
		// mkdir first so the destination is owned by the (non-root) init container — see mcpPayloadDir.
		// `cp -a <src>/.` then copies the payload's CONTENTS, preserving modes and the symlinks a
		// frozen tree contains. The trailing chmod is belt-and-braces: the app container mounts the
		// volume readOnly and so could not fix an unset exec bit itself.
		"command": []string{"/bin/sh", "-c",
			fmt.Sprintf("set -e; mkdir -p %s; cp -a %s/. %s/; chmod 0755 %s", dstDir, src, dstDir, binary)},
		"resources": map[string]interface{}{
			"requests": map[string]string{"cpu": "10m", "memory": "16Mi"},
			"limits":   map[string]string{"cpu": "100m", "memory": "64Mi"},
		},
		"securityContext": sidecarSecurityContext(),
		"volumeMounts": []map[string]interface{}{
			{"name": mcpVolumeName, "mountPath": mcpInitMountPath},
			// Wired to the enforcement socket like every other init container, so a re-admitted pod
			// still satisfies fullyInjected's "every container is wired" rule.
			{"name": "norviq-socket", "mountPath": socketMountPath},
		},
		"env": []map[string]interface{}{
			{"name": "NRVQ_SOCKET_PATH", "value": socketFilePath},
		},
	}
}

// mcpVolumeTemplate is the proxy's delivery volume. Deliberately NOT `medium: Memory`, unlike the
// sidecar's tmpfs: that one exists to keep a private key off disk, whereas this payload is a public
// executable and a frozen interpreter tree runs to tens of MB — charging that against the pod's
// memory limit would silently shrink every governed workload's budget.
func mcpVolumeTemplate() map[string]interface{} {
	return map[string]interface{}{
		"name":     mcpVolumeName,
		"emptyDir": map[string]interface{}{"sizeLimit": "256Mi"},
	}
}

// -- integrity: recognizing the injector's own MCP output ---------------------------------------

// isMcpProxyCommand reports whether an argv has already been wrapped by this injector.
func isMcpProxyCommand(cmd []string) bool {
	return len(cmd) > 0 && cmd[0] == mcpProxyBinary
}

// mcpWrappedCorrectly reports whether a container carries EXACTLY the wrapping the injector would
// produce for it — the right proxy argv for its server id, and the proxy volume mounted readOnly.
//
// The argv is re-derived from what is on the pod rather than pattern-matched, so a pod that presents
// a proxy-shaped command with the flags swung elsewhere (a different --server-id, so it pins against
// a catalogue the operator never approved) does not read as already-governed.
func mcpWrappedCorrectly(cfg Config, pod *corev1.Pod, c corev1.Container) bool {
	if !isMcpProxyCommand(c.Command) {
		return false
	}
	// readOnly is required, not incidental: the injector emits it so a governed workload cannot
	// overwrite the very binary that polices it. A writable mount under the same name is not the
	// injector's output and must not be accepted as such.
	if !mountsMcpProxyVolumeReadOnly(c) {
		return false
	}
	if !mcpRoutingTrusted(cfg, c) {
		return false
	}
	want := []string{mcpProxyBinary, "--server-id", mcpServerID(pod, c.Name), "--"}
	if len(c.Command) < len(want) {
		return false
	}
	for i, w := range want {
		if c.Command[i] != w {
			return false
		}
	}
	// Anything after `--` is the upstream server's own argv, which the injector preserves verbatim
	// and therefore cannot re-derive. `args` must be empty: a non-empty args would append tokens the
	// upstream server never saw before wrapping.
	return len(c.Command) > len(want) && len(c.Args) == 0
}

func mountsMcpProxyVolumeReadOnly(c corev1.Container) bool {
	for _, m := range c.VolumeMounts {
		if m.Name == mcpVolumeName && m.MountPath == mcpMountPath {
			return m.ReadOnly
		}
	}
	return false
}

// mcpFullyInjected reports whether every container the pod ASKS to have governed actually is. It is
// the MCP half of fullyInjected: a pod carrying a correct sidecar but an unwrapped MCP container is
// not "already injected", because that server would run unpoliced.
// It re-derives the injector's output and compares, rather than looking for injector-SHAPED plumbing.
// Recognizing the delivery init container by name alone was a full bypass: a tenant could ship a pod
// carrying a `norviq-mcp-init` container of their own that wrote a three-line shell shim
// (`shift 3; exec "$@"`) into a `norviq-mcp-proxy` volume of their own, wrap their MCP container in a
// command that merely LOOKED proxied, and be admitted UNPATCHED as "already injected" — with the
// firewall replaced by a script that drops the proxy arguments and execs the server directly. The
// pod needed nothing the webhook alone can produce (no minted JWT, no CA material), so name-shaped
// checks are not evidence of injection. Everything below is checked against what the injector would
// actually emit for THIS pod and THIS config.
func mcpFullyInjected(cfg Config, pod *corev1.Pod) bool {
	if !cfg.McpInject {
		return true
	}
	names := mcpAnnotatedNames(pod)
	if len(names) == 0 {
		return true
	}
	if !hasInjectorMcpProxyVolume(pod) || !hasInjectorMcpInitContainer(cfg, pod) {
		return false
	}
	for _, name := range names {
		_, _, container, found := findPodContainer(pod, name)
		if !found || !mcpWrappedCorrectly(cfg, pod, container) {
			return false
		}
	}
	return true
}

// hasInjectorMcpProxyVolume requires the delivery volume to be the emptyDir the injector emits.
// Matching the NAME alone let a pod present a hostPath under that name, so the "payload" the
// governed container execs would be a file the node operator never placed there.
func hasInjectorMcpProxyVolume(pod *corev1.Pod) bool {
	for _, v := range pod.Spec.Volumes {
		if v.Name == mcpVolumeName {
			return v.EmptyDir != nil
		}
	}
	return false
}

func hasInjectorMcpInitContainer(cfg Config, pod *corev1.Pod) bool {
	for _, c := range pod.Spec.InitContainers {
		if c.Name == mcpInitContainerName {
			return isInjectorMcpInitContainer(cfg, c)
		}
	}
	return false
}

// mcpRoutingTrusted is the MCP counterpart of sidecarRoutingTrusted. A wrapped container whose
// NRVQ_API_URL points at a co-located allow-all engine enforces nothing, and one whose pin settings
// were swung locally silently changes the Gate-A posture the operator configured — neither may read
// as already-governed.
func mcpRoutingTrusted(cfg Config, c corev1.Container) bool {
	url, ok := envValue(c, "NRVQ_API_URL")
	if !ok {
		return false
	}
	if url != cfg.ApiURL &&
		!(cfg.InternalTLS && !strings.HasPrefix(cfg.ApiURL, "https://") && url == "https://norviq-api:8443") {
		return false
	}
	if v, _ := envValue(c, "NRVQ_MCP_PIN_STORE"); v != cfg.McpPinStore {
		return false
	}
	if v, _ := envValue(c, "NRVQ_MCP_PIN_MODE"); v != cfg.McpPinMode {
		return false
	}
	return true
}

// mcpArtifact reports injector-owned MCP plumbing on a pod that is NOT fully injected — the proxy
// volume, the proxy mount, a proxy-shaped command, or a container occupying the init container's
// name. Same reasoning as enforcementArtifact: the injector cannot safely wire over plumbing it did
// not place, and a pre-occupied proxy path is a route to running a chosen binary in place of the
// firewall. Tenant workloads never carry these names.
func mcpArtifact(cfg Config, pod *corev1.Pod) (string, bool) {
	if hasMcpProxyVolume(pod) {
		return "pod declares the injector-owned " + mcpVolumeName + " volume but is not fully injected", true
	}
	for _, c := range allPodContainers(pod) {
		// Not `c.Name == mcpInitContainerName` alone: this path is also reached by the injector's own
		// output when something ELSE about the pod is not fully injected, and denying then would make
		// the injector refuse its own work. A container wearing the name without being the real thing
		// is exactly what must be refused.
		if c.Name == mcpInitContainerName && !isInjectorMcpInitContainer(cfg, c) {
			return "container " + c.Name + " occupies the injector-owned MCP init container name", true
		}
		if mountsMcpProxyPath(c) {
			return "container " + c.Name + " pre-occupies the MCP proxy mount at " + mcpMountPath, true
		}
		if isMcpProxyCommand(c.Command) {
			return "container " + c.Name + " pre-sets an MCP proxy command at " + mcpProxyBinary, true
		}
	}
	return "", false
}

func mountsMcpProxyPath(c corev1.Container) bool {
	for _, m := range c.VolumeMounts {
		if m.Name == mcpVolumeName || m.MountPath == mcpMountPath || m.MountPath == mcpInitMountPath {
			return true
		}
	}
	return false
}

func hasMcpProxyVolume(pod *corev1.Pod) bool {
	for _, v := range pod.Spec.Volumes {
		if v.Name == mcpVolumeName {
			return true
		}
	}
	return false
}

func hasMcpInitContainer(pod *corev1.Pod) bool {
	for _, c := range pod.Spec.InitContainers {
		if c.Name == mcpInitContainerName {
			return true
		}
	}
	return false
}

// isInjectorMcpInitContainer reports whether c is the injector's OWN MCP init container, byte for
// byte. The sidecar decoy check refuses any sidecar-identity container that overrides command/args,
// and this init container is exactly that (same image, explicit `cp` command) — so without an exact
// recognizer the injector's own output would be denied on re-admission. Matching on the full
// generated spec rather than the name keeps the exemption useless to an attacker: reproducing it
// means reproducing the real proxy copy.
func isInjectorMcpInitContainer(cfg Config, c corev1.Container) bool {
	if c.Name != mcpInitContainerName {
		return false
	}
	// Image is compared by repository NAME, not by exact ref — the same rule the sidecar path already
	// uses (sameSidecarImageName). Exact-ref equality meant that rolling the proxy image tag turned
	// every already-injected pod's own init container into an unrecognized one, so the injector's own
	// output stopped being recognized as its own the moment the operator upgraded.
	if imageName(c.Image) == "" || imageName(c.Image) != imageName(mcpProxyImage(cfg)) {
		return false
	}
	want, _ := mcpInitContainer(cfg)["command"].([]string)
	if len(c.Command) != len(want) {
		return false
	}
	for i := range want {
		if c.Command[i] != want[i] {
			return false
		}
	}
	if len(c.Args) != 0 {
		return false
	}
	// The command names a SOURCE path inside the container, so an otherwise byte-identical container
	// carrying an extra mount over that path copies something else entirely into the volume. The
	// staging mount must be present and nothing may be layered on the source.
	var staged bool
	for _, m := range c.VolumeMounts {
		if m.Name == mcpVolumeName && m.MountPath == mcpInitMountPath {
			staged = true
			continue
		}
		if strings.HasPrefix(cfg.McpProxySourcePath+"/", m.MountPath+"/") || m.MountPath == cfg.McpProxySourcePath {
			return false
		}
	}
	return staged
}

// mcpAnnotationKeys returns the MCP annotation keys present on the pod, sorted — used only for log
// and error context.
func mcpAnnotationKeys(pod *corev1.Pod) []string {
	keys := make([]string, 0, 2)
	for k := range pod.Annotations {
		if k == mcpServersAnnotation || strings.HasPrefix(k, mcpServerIDPrefix) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return keys
}
