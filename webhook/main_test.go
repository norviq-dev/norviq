// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRecoveryMiddlewareIncludesUID(t *testing.T) {
	wrapped := recoveryMiddleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("boom")
	}))
	body := []byte(`{"apiVersion":"admission.k8s.io/v1","kind":"AdmissionReview","request":{"uid":"uid-123"}}`)
	req := httptest.NewRequest(http.MethodPost, "/mutate", bytes.NewReader(body))
	w := httptest.NewRecorder()
	wrapped.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var out struct {
		Response struct {
			UID     string `json:"uid"`
			Allowed bool   `json:"allowed"`
		} `json:"response"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if out.Response.UID != "uid-123" || out.Response.Allowed {
		t.Fatalf("expected denied response with uid-123, got uid=%q allowed=%v", out.Response.UID, out.Response.Allowed)
	}
}

func TestMutateDecodeFailClosedPreservesUID(t *testing.T) {
	h := NewHandler(LoadConfig())
	wrapped := recoveryMiddleware(http.HandlerFunc(h.Mutate))
	body := []byte(`{"apiVersion":"admission.k8s.io/v1","kind":"AdmissionReview","request":{"uid":"uid-decode-fail"}}`)
	req := httptest.NewRequest(http.MethodPost, "/mutate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "text/plain")
	w := httptest.NewRecorder()
	wrapped.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var out struct {
		Response struct {
			UID     string `json:"uid"`
			Allowed bool   `json:"allowed"`
		} `json:"response"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if out.Response.UID != "uid-decode-fail" || out.Response.Allowed {
		t.Fatalf("expected denied response with uid-decode-fail, got uid=%q allowed=%v", out.Response.UID, out.Response.Allowed)
	}
}
