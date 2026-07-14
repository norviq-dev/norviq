// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeTestCA generates a self-signed CA and writes ca.crt (CERTIFICATE) + ca.key (PKCS#8) into dir.
// Returns the file paths and the parsed CA cert (for chain verification).
func writeTestCA(t *testing.T, dir string) (certFile, keyFile string, caCert *x509.Certificate) {
	t.Helper()
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen CA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "norviq-internal-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	caCert, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}
	certFile = filepath.Join(dir, "ca.crt")
	keyFile = filepath.Join(dir, "ca.key")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(caKey)
	if err != nil {
		t.Fatalf("marshal CA key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatalf("write ca.crt: %v", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatalf("write ca.key: %v", err)
	}
	return certFile, keyFile, caCert
}

func TestMintClientCert_ParsesChainsAndEKU(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile, caCert := writeTestCA(t, dir)
	cfg := Config{CACertFile: certFile, CAKeyFile: keyFile}

	const ns = "team-alpha"
	certPEM, keyPEM, err := mintClientCert(cfg, ns)
	if err != nil {
		t.Fatalf("mintClientCert: %v", err)
	}

	// Cert PEM parses back.
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatal("cert PEM did not decode to a CERTIFICATE block")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse minted cert: %v", err)
	}

	// Key PEM parses back and is 2048-bit RSA.
	kblock, _ := pem.Decode([]byte(keyPEM))
	if kblock == nil {
		t.Fatal("key PEM did not decode")
	}
	rsaKey, err := x509.ParsePKCS1PrivateKey(kblock.Bytes)
	if err != nil {
		t.Fatalf("parse minted key: %v", err)
	}
	if bits := rsaKey.N.BitLen(); bits != 2048 {
		t.Fatalf("expected 2048-bit key, got %d", bits)
	}

	// Subject: CN=norviq-sidecar, OU=<namespace>.
	if leaf.Subject.CommonName != "norviq-sidecar" {
		t.Fatalf("CN = %q, want norviq-sidecar", leaf.Subject.CommonName)
	}
	if len(leaf.Subject.OrganizationalUnit) != 1 || leaf.Subject.OrganizationalUnit[0] != ns {
		t.Fatalf("OU = %v, want [%s]", leaf.Subject.OrganizationalUnit, ns)
	}

	// ClientAuth EKU present.
	foundClientAuth := false
	for _, eku := range leaf.ExtKeyUsage {
		if eku == x509.ExtKeyUsageClientAuth {
			foundClientAuth = true
		}
	}
	if !foundClientAuth {
		t.Fatalf("ExtKeyUsage %v missing ClientAuth", leaf.ExtKeyUsage)
	}

	// ~30-day validity.
	dur := leaf.NotAfter.Sub(leaf.NotBefore)
	if dur < 29*24*time.Hour || dur > 31*24*time.Hour {
		t.Fatalf("validity %v, want ~30 days", dur)
	}

	// Chains to the CA with clientAuth usage.
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Fatalf("minted cert does not chain to CA: %v", err)
	}
}

func TestMintClientCert_MissingCAFilesErrors(t *testing.T) {
	cfg := Config{CACertFile: "/nonexistent/ca.crt", CAKeyFile: "/nonexistent/ca.key"}
	if _, _, err := mintClientCert(cfg, "ns"); err == nil {
		t.Fatal("expected error when CA files are missing")
	}
}

func TestBuildAPIHTTPClient_PlaintextWhenOff(t *testing.T) {
	client, err := buildAPIHTTPClient(false, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Byte-identical to the historical client: no custom Transport, 5s timeout.
	if client.Transport != nil {
		t.Fatalf("expected nil Transport when internal TLS is off, got %T", client.Transport)
	}
	if client.Timeout != 5*time.Second {
		t.Fatalf("timeout = %v, want 5s", client.Timeout)
	}
}

func TestBuildAPIHTTPClient_TLSWhenOnWithCA(t *testing.T) {
	dir := t.TempDir()
	certFile, _, _ := writeTestCA(t, dir)

	client, err := buildAPIHTTPClient(true, certFile)
	if err != nil {
		t.Fatalf("buildAPIHTTPClient: %v", err)
	}
	tr, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("expected *http.Transport, got %T", client.Transport)
	}
	if tr.TLSClientConfig == nil || tr.TLSClientConfig.RootCAs == nil {
		t.Fatal("expected TLSClientConfig with a RootCAs pool")
	}
}

func TestBuildAPIHTTPClient_TLSOnMissingCAErrors(t *testing.T) {
	if _, err := buildAPIHTTPClient(true, "/nonexistent/ca.crt"); err == nil {
		t.Fatal("expected error when CA file is missing and TLS is on")
	}
}

func TestSidecarEnv_TLSOffByteIdentical(t *testing.T) {
	cfg := LoadConfig() // InternalTLS defaults false
	env := sidecarEnv("sales", "default", cfg)
	for _, e := range env {
		name, _ := e["name"].(string)
		switch name {
		case "NRVQ_INTERNAL_TLS", "NRVQ_API_CA_PEM", "NRVQ_CLIENT_CERT_PEM", "NRVQ_CLIENT_KEY_PEM":
			t.Fatalf("TLS env %q leaked when internal TLS is off", name)
		case "NRVQ_API_URL":
			if v, _ := e["value"].(string); v != cfg.ApiURL {
				t.Fatalf("NRVQ_API_URL = %q, want unchanged %q", v, cfg.ApiURL)
			}
		}
	}
}

func TestSidecarEnv_TLSOnAddsMTLSEnvAndUpgradesURL(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile, caCert := writeTestCA(t, dir)
	cfg := Config{
		InternalTLS: true,
		CACertFile:  certFile,
		CAKeyFile:   keyFile,
		ApiURL:      "http://norviq-api:8080",
		ApiSecret:   "test-secret",
		SidecarMode: "proxy",
	}
	env := sidecarEnv("sales", "team-beta", cfg)

	got := map[string]string{}
	for _, e := range env {
		name, _ := e["name"].(string)
		val, _ := e["value"].(string)
		got[name] = val
	}

	if got["NRVQ_INTERNAL_TLS"] != "true" {
		t.Fatalf("NRVQ_INTERNAL_TLS = %q, want true", got["NRVQ_INTERNAL_TLS"])
	}
	if got["NRVQ_API_URL"] != "https://norviq-api:8443" {
		t.Fatalf("NRVQ_API_URL = %q, want https://norviq-api:8443", got["NRVQ_API_URL"])
	}
	if _, ok := got["NRVQ_API_TOKEN"]; !ok {
		t.Fatal("JWT NRVQ_API_TOKEN must still be present (defense in depth)")
	}
	if got["NRVQ_API_CA_PEM"] == "" || got["NRVQ_CLIENT_CERT_PEM"] == "" || got["NRVQ_CLIENT_KEY_PEM"] == "" {
		t.Fatal("expected CA/cert/key PEM env to be populated")
	}

	// The delivered client cert chains to the CA.
	block, _ := pem.Decode([]byte(got["NRVQ_CLIENT_CERT_PEM"]))
	if block == nil {
		t.Fatal("client cert PEM did not decode")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse client cert: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatalf("delivered client cert does not chain to CA: %v", err)
	}
}

func TestSidecarEnv_TLSOnAlreadyHTTPSPreserved(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile, _ := writeTestCA(t, dir)
	cfg := Config{
		InternalTLS: true,
		CACertFile:  certFile,
		CAKeyFile:   keyFile,
		ApiURL:      "https://custom-api:9443",
		ApiSecret:   "test-secret",
		SidecarMode: "proxy",
	}
	env := sidecarEnv("sales", "ns", cfg)
	for _, e := range env {
		if e["name"] == "NRVQ_API_URL" {
			if v, _ := e["value"].(string); v != "https://custom-api:9443" {
				t.Fatalf("NRVQ_API_URL = %q, want existing https URL preserved", v)
			}
		}
	}
}
