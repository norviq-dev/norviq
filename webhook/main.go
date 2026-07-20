// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// main.go is the webhook entrypoint: it starts the mutating admission HTTPS server and,
// when enabled, the CRD controller, and handles graceful shutdown and panic recovery.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"
	"time"
)

type contextKey string

const admissionUIDKey contextKey = "admission_uid"

type admissionUIDEnvelope struct {
	Request *struct {
		UID string `json:"uid"`
	} `json:"request,omitempty"`
}

func main() {
	cfg := LoadConfig()
	setLogger(cfg)
	server, err := newServer(cfg)
	if err != nil {
		slog.Error("NRVQ-WHK-4001: TLS cert load failed", "error", err)
		os.Exit(1)
	}
	stopCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	done := make(chan struct{})
	go func() {
		<-stopCtx.Done()
		shutdownOnSignal(server)
		close(done)
	}()

	if os.Getenv("NRVQ_CONTROLLER_ENABLED") == "true" {
		apiURL := envStr("NRVQ_API_URL", "http://norviq-api:8080")
		// HS256 signing key for the controller's service JWT. Prefer NRVQ_API_SECRET_KEY; fall back to
		// the legacy NRVQ_API_TOKEN env (also the raw secret) for backward compatibility.
		apiSecret := envStr("NRVQ_API_SECRET_KEY", envStr("NRVQ_API_TOKEN", ""))
		ctrl, err := NewController(apiURL, apiSecret)
		if err != nil {
			slog.Error("NRVQ-WHK-4020: controller init failed", "error", err)
		} else {
			ctrl.runtime = cfg.Runtime
			ctrl.defaultSidecarImage = cfg.SidecarImage
			ctrl.adminPolicyNamespace = cfg.AdminPolicyNamespace
			go func() {
				if err := ctrl.Start(stopCtx); err != nil {
					slog.Error("NRVQ-WHK-4021: controller failed", "error", err)
				}
			}()
		}
	}

	slog.Info("NRVQ-WHK-4000: webhook server starting", "port", cfg.Port)
	if err = server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
		slog.Error("NRVQ-WHK-4002: server failed to start", "error", err)
		os.Exit(1)
	}
	<-done
}

func setLogger(cfg Config) {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: cfg.LogLevel})))
}

func newServer(cfg Config) (*http.Server, error) {
	handler := NewHandler(cfg)
	mux := http.NewServeMux()
	mux.HandleFunc("/mutate", handler.Mutate)
	mux.HandleFunc("/validate-policy", handler.ValidatePolicy)
	mux.HandleFunc("/healthz", handler.Healthz)
	mux.HandleFunc("/readyz", handler.Readyz)
	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, err
	}
	return &http.Server{
		Addr:              fmt.Sprintf(":%d", cfg.Port),
		Handler:           recoveryMiddleware(mux),
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		MaxHeaderBytes:    1 << 20,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			},
		},
	}, nil
}

func shutdownOnSignal(server *http.Server) {
	slog.Info("NRVQ-WHK-4011: graceful shutdown")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_ = server.Shutdown(shutdownCtx)
}

func recoveryMiddleware(next http.Handler) http.Handler {
	return withAdmissionUID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if recovered := recover(); recovered != nil {
				slog.Error("NRVQ-WHK-4010: panic recovered", "error", recovered, "stack", string(debug.Stack()))
				uid, _ := r.Context().Value(admissionUIDKey).(string)
				denyResponse(w, uid, "admission webhook internal error")
			}
		}()
		next.ServeHTTP(w, r)
	}))
}

func allowResponse(w http.ResponseWriter, uid string) {
	payload, _ := json.Marshal(map[string]interface{}{
		"apiVersion": "admission.k8s.io/v1",
		"kind":       "AdmissionReview",
		"response": map[string]interface{}{
			"allowed": true,
			"uid":     uid,
		},
	})
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(payload)
}

func denyResponse(w http.ResponseWriter, uid, message string) {
	payload, _ := json.Marshal(map[string]interface{}{
		"apiVersion": "admission.k8s.io/v1",
		"kind":       "AdmissionReview",
		"response": map[string]interface{}{
			"allowed": false,
			"uid":     uid,
			"status": map[string]interface{}{
				"message": message,
			},
		},
	})
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(payload)
}

func withAdmissionUID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/mutate" || r.Body == nil {
			next.ServeHTTP(w, r)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, maxAdmissionBodySize+1))
		_ = r.Body.Close()
		r.Body = io.NopCloser(bytes.NewReader(body))
		if err != nil || len(body) > maxAdmissionBodySize {
			next.ServeHTTP(w, r)
			return
		}
		uid := ""
		var review admissionUIDEnvelope
		if json.Unmarshal(body, &review) == nil && review.Request != nil {
			uid = review.Request.UID
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), admissionUIDKey, uid)))
	})
}
