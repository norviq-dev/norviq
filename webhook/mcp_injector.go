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
	"log/slog"
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
		// HTTP-TRANSPORT MCP SERVERS ARE NOT GOVERNED BY THIS ANNOTATION (F-028), and the operator
		// gets no signal today. The wrapping model is stdio: the command is rewritten to run the
		// server as a child of `python -m norviq.mcp`, which is the only faithful interception point
		// for a process speaking MCP over its own stdin/stdout.
		//
		// A FastMCP / streamable-HTTP server speaks over a socket instead. The rewrite still happens
		// and the pod still comes up, but the Service targets the raw server, the firewall is not in
		// the MCP data path, and `/api/v1/mcp/servers` stays empty — while the operator sees an
		// injected pod and reasonably concludes it is governed. Silently-not-governed is the worst of
		// the three possible outcomes; a refusal or a warning are both better.
		//
		// Warned rather than refused: the heuristic is a heuristic. A declared containerPort is strong
		// evidence of a socket-speaking server, but a stdio server can legitimately expose a health or
		// metrics port, and failing admission on that would stop a pod this annotation does govern.
		// So the pod starts and the ambiguity is stated, loudly, with the container named.
		if httpTransportLikely(container) {
			slog.Warn("NRVQ-WHK-4051: MCP container looks like an HTTP-transport server; the "+
				mcpServersAnnotation+" annotation wraps STDIO servers only. The proxy is NOT in the "+
				"MCP data path for this container, so Gate A/B do not see its traffic and it will not "+
				"appear under /api/v1/mcp/servers. Front it with the norviq.mcp HTTP proxy instead, or "+
				"remove the container from the annotation so the pod does not read as governed.",
				"container", name, "namespace", pod.Namespace, "ports", len(container.Ports))
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

// httpTransportLikely reports whether a container looks like it speaks MCP over a socket rather than
// stdio. Best-effort by design — see the call site for why this warns instead of refusing.
//
// Two independent signals, either of which is enough: a declared containerPort (a stdio server has no
// reason to listen), or an argv that names an HTTP transport or an ASGI server.
func httpTransportLikely(c corev1.Container) bool {
	if len(c.Ports) > 0 {
		return true
	}
	argv := strings.ToLower(strings.Join(append(append([]string{}, c.Command...), c.Args...), " "))
	for _, marker := range []string{
		"--http", "--transport http", "--transport=http", "streamable-http", "--sse", "--port",
		"uvicorn", "hypercorn", "gunicorn", "fastapi",
	} {
		if strings.Contains(argv, marker) {
			return true
		}
	}
	return false
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
			// Wired to the enforcement socket like every other init container the injector touches, and
			// readOnly like them: see socketMountForClient.
			socketMountForClient(),
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

// isMcpProxyCommand reports whether an argv begins with the proxy binary the injector wraps commands in.
func isMcpProxyCommand(cmd []string) bool {
	return len(cmd) > 0 && cmd[0] == mcpProxyBinary
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
