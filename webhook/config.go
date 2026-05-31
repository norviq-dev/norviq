// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
package main

import (
	"log/slog"
	"os"
	"strconv"
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
	LogLevel        slog.Level
}

func LoadConfig() Config {
	return Config{
		Port:            envInt("NRVQ_WEBHOOK_PORT", 8443),
		CertFile:        envStr("NRVQ_TLS_CERT", "/etc/webhook/certs/tls.crt"),
		KeyFile:         envStr("NRVQ_TLS_KEY", "/etc/webhook/certs/tls.key"),
		SidecarImage:    envStr("NRVQ_SIDECAR_IMAGE", "sanman97/norviq-engine:engine-latest"),
		SidecarPort:     envInt("NRVQ_SIDECAR_PORT", 8282),
		EnableLabel:     envStr("NRVQ_ENABLE_LABEL", "norviq"),
		EnableValue:     envStr("NRVQ_ENABLE_VALUE", "enabled"),
		AgentClassLabel: envStr("NRVQ_AGENT_CLASS_LABEL", "norviq.io/agent-class"),
		LogLevel:        slog.LevelInfo,
	}
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
