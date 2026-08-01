// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// config.go defines the webhook's runtime configuration surface and loads it from
// environment variables (image, ports, TLS/mTLS, sidecar mode, SPIFFE, opt-out policy).
package main

import (
	"log/slog"
	"os"
	"strconv"
	"sync"
)

type Config struct {
	Port         int
	CertFile     string
	KeyFile      string
	SidecarImage string
	SidecarPort  int
	// Resources for the INJECTED sidecar. Supplied by the chart, which picks them per sidecarMode —
	// embedded runs a whole engine (redis client, policy warm, audit emitter, pubsub watcher, plus an
	// OPA subprocess) and cannot live inside the thin proxy's budget. Defaults below are the proxy
	// values that were previously hardcoded here, so an unset env renders exactly as before.
	SidecarCPURequest string
	SidecarMemRequest string
	SidecarCPULimit   string
	SidecarMemLimit   string
	EnableLabel       string
	EnableValue       string
	AgentClassLabel   string
	// When false, the injector IGNORES the per-pod opt-out (norviq-injection=disabled label /
	// norviq.io/skip-injection annotation) so a pod author in an injection-enabled namespace cannot
	// self-exempt their workload from enforcement — the namespace-uniform guarantee holds. Default
	// true (opt-out honored, backward-compatible); govern label/annotation write access with RBAC.
	AllowPodOptOut       bool
	AdminPolicyNamespace string
	LogLevel             slog.Level
	Runtime              *RuntimeConfig
	// SPIFFE workload-identity injection. When SpiffeInject is true, injected pods also get the
	// SPIFFE Workload API socket (csi.spiffe.io) mounted + NRVQ_SPIFFE_MODE/SOCKET env, so the sidecar
	// and app resolve a real attested SVID. Default off so injection is unchanged where SPIRE is absent.
	SpiffeInject bool
	SpiffeMode   string
	SpiffeSocket string
	// Mode injected into sidecars. "proxy" (default) = thin sidecar POSTs to the central
	// norviq-api /evaluate with a namespace-scoped service JWT; "embedded" = full local engine.
	SidecarMode string
	// Data-plane posture when the central engine is UNREACHABLE (5xx/timeout/connect). "block"
	// (default) fails closed; "allow" keeps agents running ungoverned through an outage. A 4xx is
	// never covered by this — the engine answered and refused, so it always blocks.
	FallbackMode string
	// Central API URL + HS256 signing secret. In proxy mode the injector wires ApiURL and mints a
	// per-workload service token from ApiSecret (reused from the controller's env).
	ApiURL    string
	ApiSecret string
	// Lifetime (hours) of the minted sidecar service JWT. The token is baked into the pod env and
	// cannot self-refresh, so it is long-lived by necessity; mTLS + short-lived tokens are the
	// documented fast-follow. NRVQ_SIDECAR_TOKEN_TTL_HOURS.
	SidecarTokenTTLHours int
	// Embedded-mode wiring passed through from the webhook's own env (sourced from
	// norviq-config/norviq-secrets). Only used when SidecarMode=embedded.
	RedisURL  string
	PgURL     string
	DBSSLMode string
	OpaMode   string
	// Auto-mTLS (internal-TLS). When InternalTLS is true, the controller verifies the API's serving
	// cert against the internal CA (CACertFile) and the injector mints a per-namespace client cert
	// (signed by CACertFile/CAKeyFile, mounted from secret norviq-internal-ca) so the sidecar does
	// mTLS to https://norviq-api:8443. Default off -> current plaintext behavior, byte-identical.
	InternalTLS bool
	CACertFile  string
	CAKeyFile   string
	// MCP action-firewall injection. When McpInject is true, every container named by the pod's
	// norviq.io/mcp-servers annotation has its command rewritten to run UNDER the MCP proxy
	// (norviq/mcp/__main__.py), so Model Context Protocol traffic is governed with no change to the
	// agent's code or image. Default OFF: with it off not a single byte of the emitted patch changes,
	// so existing clusters upgrade into identical output.
	McpInject bool
	// Image the proxy payload is copied FROM by the injected init container. Empty -> the sidecar
	// image, which already carries the norviq package. NRVQ_MCP_PROXY_IMAGE.
	McpProxyImage string
	// Directory holding the relocatable proxy payload inside McpProxyImage, with the executable
	// `norviq-mcp` at its root (scripts/mcp-proxy-payload.Dockerfile builds exactly that). The init
	// container copies the whole tree into the shared volume and the rewritten command execs it from
	// there. A directory rather than a single file because the payload is a PyInstaller onedir tree —
	// it carries its own interpreter and stdlib, which is what lets it run in an image that has no
	// Python. NRVQ_MCP_PROXY_SOURCE_PATH.
	McpProxySourcePath string
	// Pin backend + mode handed to injected proxies. "control-plane" is the right posture in a
	// cluster: pins are approvals, approvals belong with policy, and an emptyDir pin file would be
	// lost on every restart (see norviq/mcp/pins.py). NRVQ_MCP_PIN_STORE / NRVQ_MCP_PIN_MODE.
	McpPinStore string
	McpPinMode  string
}

type RuntimeConfig struct {
	mu           sync.RWMutex
	sidecarImage string
}

func LoadConfig() Config {
	runtime := &RuntimeConfig{}
	cfg := Config{
		Port:         envInt("NRVQ_WEBHOOK_PORT", 8443),
		CertFile:     envStr("NRVQ_TLS_CERT", "/etc/webhook/certs/tls.crt"),
		KeyFile:      envStr("NRVQ_TLS_KEY", "/etc/webhook/certs/tls.key"),
		SidecarImage: envStr("NRVQ_SIDECAR_IMAGE", "ghcr.io/norviq-dev/norviq-engine:engine-latest"),
		SidecarPort:  envInt("NRVQ_SIDECAR_PORT", 8282),

		SidecarCPURequest: envStr("NRVQ_SIDECAR_CPU_REQUEST", "50m"),
		SidecarMemRequest: envStr("NRVQ_SIDECAR_MEM_REQUEST", "64Mi"),
		SidecarCPULimit:   envStr("NRVQ_SIDECAR_CPU_LIMIT", "200m"),
		SidecarMemLimit:   envStr("NRVQ_SIDECAR_MEM_LIMIT", "128Mi"),
		// Unify the opt-in/out label key with the MutatingWebhookConfiguration namespaceSelector
		// (norviq-injection). The namespace opts in (MWC selector); a pod opts OUT with
		// norviq-injection=disabled. Default flipped from the legacy "norviq" key.
		EnableLabel:          envStr("NRVQ_ENABLE_LABEL", "norviq-injection"),
		EnableValue:          envStr("NRVQ_ENABLE_VALUE", "enabled"),
		AgentClassLabel:      envStr("NRVQ_AGENT_CLASS_LABEL", "norviq.io/agent-class"),
		AdminPolicyNamespace: envStr("NRVQ_ADMIN_POLICY_NAMESPACE", "norviq"),
		LogLevel:             slog.LevelInfo,
		Runtime:              runtime,
		AllowPodOptOut:       envBool("NRVQ_ALLOW_POD_OPT_OUT", true),
		SpiffeInject:         envBool("NRVQ_SPIFFE_INJECT", false),
		SpiffeMode:           envStr("NRVQ_SPIFFE_MODE", "mock"),
		SpiffeSocket:         envStr("NRVQ_SPIFFE_SOCKET", "/spiffe-workload-api/spire-agent.sock"),
		SidecarMode:          envStr("NRVQ_SIDECAR_MODE", "proxy"),
		FallbackMode:         envStr("NRVQ_SDK_FALLBACK_MODE", "block"),
		ApiURL:               envStr("NRVQ_API_URL", "http://norviq-api:8080"),
		ApiSecret:            envStr("NRVQ_API_SECRET_KEY", envStr("NRVQ_API_TOKEN", "")),
		SidecarTokenTTLHours: envInt("NRVQ_SIDECAR_TOKEN_TTL_HOURS", 720),
		RedisURL:             envStr("NRVQ_REDIS_URL", ""),
		PgURL:                envStr("NRVQ_PG_URL", ""),
		DBSSLMode:            envStr("NRVQ_DB_SSL_MODE", "require"),
		OpaMode:              envStr("NRVQ_SIDECAR_OPA_MODE", "subprocess"),
		InternalTLS:          envBool("NRVQ_INTERNAL_TLS", false),
		CACertFile:           envStr("NRVQ_CA_CERT_FILE", ""),
		CAKeyFile:            envStr("NRVQ_CA_KEY_FILE", ""),
		McpInject:            envBool("NRVQ_MCP_INJECT", false),
		McpProxyImage:        envStr("NRVQ_MCP_PROXY_IMAGE", ""),
		McpProxySourcePath:   envStr("NRVQ_MCP_PROXY_SOURCE_PATH", "/opt/norviq/mcp-proxy"),
		McpPinStore:          envStr("NRVQ_MCP_PIN_STORE", "control-plane"),
		McpPinMode:           envStr("NRVQ_MCP_PIN_MODE", "tofu"),
	}
	runtime.SetSidecarImage(cfg.SidecarImage)
	return cfg
}

func (r *RuntimeConfig) SetSidecarImage(image string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sidecarImage = image
}

func (r *RuntimeConfig) SidecarImage(defaultImage string) string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.sidecarImage == "" {
		return defaultImage
	}
	return r.sidecarImage
}

func envStr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func envInt(key string, fallback int) int {
	if value := os.Getenv(key); value != "" {
		if parsed, err := strconv.Atoi(value); err == nil {
			return parsed
		}
	}
	return fallback
}

func envBool(key string, fallback bool) bool {
	if value := os.Getenv(key); value != "" {
		if parsed, err := strconv.ParseBool(value); err == nil {
			return parsed
		}
	}
	return fallback
}
