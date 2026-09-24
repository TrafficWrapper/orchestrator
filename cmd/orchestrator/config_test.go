package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadConfigDefaults(t *testing.T) {
	t.Setenv("ORCH_STATE_DIR", "/var/lib/tw")
	cfg, err := readConfig()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.TLS || cfg.APKKeepReleases != 5 || cfg.SeedVersionCode != 1 {
		t.Fatalf("defaults: %+v", cfg)
	}
	if cfg.SignerSocket != filepath.Join("/var/lib/tw", "signer.sock") {
		t.Fatalf("signer socket must follow ORCH_STATE_DIR: %s", cfg.SignerSocket)
	}
}

func TestReadConfigParsesBooleans(t *testing.T) {
	for value, want := range map[string]bool{"0": false, "false": false, "OFF": false, "no": false, "1": true, "true": true, "yes": true} {
		t.Setenv("ORCH_TLS", value)
		cfg, err := readConfig()
		if err != nil || cfg.TLS != want {
			t.Fatalf("ORCH_TLS=%q: tls=%t err=%v", value, cfg.TLS, err)
		}
	}
}

func TestReadConfigRejectsMalformedValues(t *testing.T) {
	t.Setenv("ORCH_TLS", "maybe")
	t.Setenv("ORCH_APK_KEEP_RELEASES", "-3")
	t.Setenv("SEED_APK_VERSION_CODE", "abc")
	t.Setenv("ORCH_PUBLIC_URL", "orch.example.com")
	t.Setenv("ORCH_EGRESS_PROBE_URL", "ftp://x")
	_, err := readConfig()
	if err == nil {
		t.Fatal("malformed configuration must fail")
	}
	for _, key := range []string{"ORCH_TLS", "ORCH_APK_KEEP_RELEASES", "SEED_APK_VERSION_CODE", "ORCH_PUBLIC_URL", "ORCH_EGRESS_PROBE_URL"} {
		if !strings.Contains(err.Error(), key) {
			t.Fatalf("error must name %s: %v", key, err)
		}
	}
}

func TestPublicURLIsLoopback(t *testing.T) {
	for raw, want := range map[string]bool{"https://127.0.0.1:9091": true, "https://localhost": true, "https://[::1]:1": true, "https://orch.example.com": false, "https://203.0.113.5": false} {
		if got := publicURLIsLoopback(raw); got != want {
			t.Fatalf("%s: %t", raw, got)
		}
	}
}

type failingSigner struct{ fakeSigner }

func (failingSigner) publicKey() (string, error) { return "", errors.New("signer down") }

func TestReadyzReflectsSigner(t *testing.T) {
	s := newTestServer(t)
	rec := httptest.NewRecorder()
	s.handleReadyz(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("ready status=%d body=%s", rec.Code, rec.Body.String())
	}
	s2 := newTestServer(t)
	s2.signer = failingSigner{}
	rec = httptest.NewRecorder()
	s2.handleReadyz(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), `"signer":"unavailable"`) {
		t.Fatalf("signer outage must fail readiness: %d %s", rec.Code, rec.Body.String())
	}
}
