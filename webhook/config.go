// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
package main

import (
	"log/slog"
	"os"
	"strconv"
	"sync"
)

type Config struct {
	Port                 int
	CertFile             string
	KeyFile              string
	SidecarImage         string
	SidecarPort          int
	EnableLabel          string
	EnableValue          string
	AgentClassLabel      string
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
