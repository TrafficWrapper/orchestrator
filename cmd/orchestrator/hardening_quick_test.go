package main

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// ORC-M10: TLS on a proxy in front (ORCH_TLS=0, https public URL) still
// gets a Secure session cookie; direct TLS responses carry HSTS.
func TestSessionCookieSecureBehindTLSProxy(t *testing.T) {
	s := newTestServer(t)
	s.cfg.TLS = false
	s.cfg.PublicURL = "https://orch.example"
	rec := httptest.NewRecorder()
	s.createAdminSession(rec, httptest.NewRequest(http.MethodPost, "/admin/v1/login", nil), false)
	if !strings.Contains(rec.Header().Get("Set-Cookie"), "Secure") {
		t.Fatalf("cookie not Secure behind a TLS proxy: %q", rec.Header().Get("Set-Cookie"))
	}
	h := withSecurityHeaders(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.TLS = &tls.ConnectionState{}
	out := httptest.NewRecorder()
	h.ServeHTTP(out, req)
	if !strings.Contains(out.Header().Get("Strict-Transport-Security"), "max-age=") {
		t.Fatal("HSTS missing on TLS responses")
	}
}

// ORC-M18: live state and keys never enter the image build context.
func TestDockerignoreExcludesStateAndKeys(t *testing.T) {
	raw, err := os.ReadFile("../../.dockerignore")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range []string{"orch-state", "signer-state", "signer-run", "seed", "*.key", ".env", ".git"} {
		if !strings.Contains(string(raw), "\n"+entry+"\n") {
			t.Fatalf(".dockerignore misses %s", entry)
		}
	}
}

// ORC-L6/L26: the entrypoint drops the bounding set and sets no_new_privs;
// compose gives shutdown enough time.
func TestContainerHardening(t *testing.T) {
	entry, _ := os.ReadFile("../../docker-entrypoint.sh")
	for _, want := range []string{"--no-new-privs", "--bounding-set=-all,+net_bind_service"} {
		if !strings.Contains(string(entry), want) {
			t.Fatalf("entrypoint misses %s", want)
		}
	}
	compose, _ := os.ReadFile("../../docker-compose.yml")
	if strings.Count(string(compose), "stop_grace_period: 30s") != 2 || strings.Count(string(compose), "cap_drop: [ALL]") != 2 {
		t.Fatal("compose must set stop_grace_period and cap_drop for both services")
	}
}
