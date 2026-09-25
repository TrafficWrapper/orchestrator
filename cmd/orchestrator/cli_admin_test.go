package main

import (
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
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

// ORC-L23: the CLI falls back to the local database only when it targets
// this host, and never creates a database it would then write into.
func TestAdminFallbackOnlyForLocalAdminURL(t *testing.T) {
	cases := []struct {
		env  string
		url  string
		want bool
	}{
		{env: "", url: "http://10.1.2.3:9091", want: true},
		{env: "set", url: "http://127.0.0.1:9091", want: true},
		{env: "set", url: "http://[::1]:9091", want: true},
		{env: "set", url: "https://localhost:9091", want: true},
		{env: "set", url: "https://admin.example.com:9091", want: false},
		{env: "set", url: "http://198.51.100.7:9091", want: false},
	}
	for _, tc := range cases {
		t.Setenv("ORCH_ADMIN_URL", tc.env)
		target, err := url.Parse(tc.url)
		if err != nil {
			t.Fatal(err)
		}
		if got := adminURLAllowsLocalFallback(target); got != tc.want {
			t.Fatalf("env=%q url=%s fallback=%v want %v", tc.env, tc.url, got, tc.want)
		}
	}
}

func TestAdminRequestRemoteUnreachableIsNotFallback(t *testing.T) {
	cfg := orchConfig{StateDir: t.TempDir()}
	t.Setenv("ORCH_ADMIN_URL", "http://orchestrator-admin.invalid:9091")
	err := adminGet(cfg, "/admin/v1/status", io.Discard)
	if err == nil || errors.Is(err, errAdminServerUnreachable) {
		t.Fatalf("remote unreachable admin API must be an error without fallback, got %v", err)
	}
}

func TestCLIFallbackDoesNotCreateLocalDatabase(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	stateDir := filepath.Join(t.TempDir(), "state")
	cfg := orchConfig{StateDir: stateDir}
	t.Setenv("ORCH_ADMIN_URL", "http://"+addr)
	if err := statusCommand(cfg); err == nil {
		t.Fatal("status without a reachable API or a local database succeeded")
	}
	if _, err := os.Stat(filepath.Join(stateDir, "orchestrator.db")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("offline fallback created a local database: %v", err)
	}
	if _, err := os.Stat(filepath.Join(stateDir, "master.key")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("offline fallback created a master key: %v", err)
	}
}

func TestCLIFallbackUsesExistingLocalDatabase(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	cfg := orchConfig{StateDir: t.TempDir()}
	st, err := openOrchStore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	st.close()
	t.Setenv("ORCH_ADMIN_URL", "http://"+addr)
	if err := statusCommand(cfg); err != nil {
		t.Fatalf("local fallback over an existing database failed: %v", err)
	}
}
