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
	Port            int
	CertFile        string
	KeyFile         string
	SidecarImage    string
	SidecarPort     int
	EnableLabel     string
	EnableValue     string
	AgentClassLabel string
	AdminPolicyNamespace string
	LogLevel        slog.Level
	Runtime         *RuntimeConfig
}

type RuntimeConfig struct {
	mu           sync.RWMutex
	sidecarImage string
}

func LoadConfig() Config {
	runtime := &RuntimeConfig{}
	cfg := Config{
		Port:            envInt("NRVQ_WEBHOOK_PORT", 8443),
		CertFile:        envStr("NRVQ_TLS_CERT", "/etc/webhook/certs/tls.crt"),
		KeyFile:         envStr("NRVQ_TLS_KEY", "/etc/webhook/certs/tls.key"),
		SidecarImage:    envStr("NRVQ_SIDECAR_IMAGE", "sanman97/norviq-engine:engine-latest"),
		SidecarPort:     envInt("NRVQ_SIDECAR_PORT", 8282),
		EnableLabel:     envStr("NRVQ_ENABLE_LABEL", "norviq"),
		EnableValue:     envStr("NRVQ_ENABLE_VALUE", "enabled"),
		AgentClassLabel: envStr("NRVQ_AGENT_CLASS_LABEL", "norviq.io/agent-class"),
		AdminPolicyNamespace: envStr("NRVQ_ADMIN_POLICY_NAMESPACE", "norviq"),
		LogLevel:        slog.LevelInfo,
		Runtime:         runtime,
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
