package main

import (
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestAdminRequestPinsOwnCertificateAndRejectsOthers(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer ts.Close()
	cfg := orchConfig{StateDir: t.TempDir(), TLS: true}
	t.Setenv("ORCH_ADMIN_URL", ts.URL)

	if err := adminGet(cfg, "/admin/v1/status", io.Discard); err == nil {
		t.Fatal("an unknown self-signed certificate must be rejected")
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ts.Certificate().Raw})
	if err := os.WriteFile(filepath.Join(cfg.StateDir, "tls.crt"), certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := adminGet(cfg, "/admin/v1/status", io.Discard); err != nil {
		t.Fatalf("pinned orchestrator certificate rejected: %v", err)
	}
}

func TestAdminRequestClassifiesUnreachableAndHTTPErrors(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	cfg := orchConfig{StateDir: t.TempDir()}
	t.Setenv("ORCH_ADMIN_URL", "http://"+addr)
	if err := adminGet(cfg, "/admin/v1/status", io.Discard); !errors.Is(err, errAdminServerUnreachable) {
		t.Fatalf("closed port must be unreachable, got %v", err)
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "admin session required", http.StatusUnauthorized)
	}))
	defer ts.Close()
	t.Setenv("ORCH_ADMIN_URL", ts.URL)
	err = adminGet(cfg, "/admin/v1/status", io.Discard)
	if err == nil || errors.Is(err, errAdminServerUnreachable) {
		t.Fatalf("HTTP error must be reported, not treated as unreachable: %v", err)
	}
}
