package main

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

func withAuditLogForTest(t *testing.T, s *server, rotation ...auditRotation) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.log")
	audit, err := openAuditLog(path, rotation...)
	if err != nil {
		t.Fatal(err)
	}
	s.audit = audit
	t.Cleanup(func() { _ = audit.Close() })
	return path
}

func captureLogForTest(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })
	return &buf
}

func webGetForTest(s *server, path, token string) *httptest.ResponseRecorder {
	mux := http.NewServeMux()
	s.registerWebRoutes(mux)
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if token != "" {
		req.AddCookie(&http.Cookie{Name: adminSessionCookie, Value: token})
	}
	rec := httptest.NewRecorder()
	withSecurityHeaders(mux).ServeHTTP(rec, req)
	return rec
}

// ORC-L15: every response is no-store; API responses get a deny-all CSP and
// admin pages a nonce-based script policy with no inline handlers.
func TestSecurityHeadersNoStoreAndNonceCSP(t *testing.T) {
	h := withSecurityHeaders(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, map[string]any{"ok": true}) }))
	for _, path := range []string{"/admin/v1/login", "/admin/v1/bootstrap-token/create", "/admin/v1/token/create"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, nil))
		if rec.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("%s: Cache-Control=%q", path, rec.Header().Get("Cache-Control"))
		}
		if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'none'") || !strings.Contains(csp, "frame-ancestors 'none'") {
			t.Fatalf("%s: CSP=%q", path, csp)
		}
	}

	s := newTestServer(t)
	s.adminSessions.Store("tok", adminSession{Token: "tok", CSRFToken: "csrf", ExpiresAt: time.Now().Add(time.Hour)})
	for _, tc := range []struct{ path, token string }{{"/login", ""}, {"/devices", "tok"}, {"/settings", "tok"}, {"/", "tok"}} {
		rec := webGetForTest(s, tc.path, tc.token)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status %d", tc.path, rec.Code)
		}
		if rec.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("%s: Cache-Control=%q", tc.path, rec.Header().Get("Cache-Control"))
		}
		csp := rec.Header().Get("Content-Security-Policy")
		m := regexp.MustCompile(`script-src 'nonce-([0-9a-f]+)'`).FindStringSubmatch(csp)
		if m == nil || strings.Contains(csp, "'unsafe-inline' 'nonce") || strings.Contains(csp, "script-src 'unsafe-inline'") {
			t.Fatalf("%s: CSP without a script nonce: %q", tc.path, csp)
		}
		body := rec.Body.String()
		if !strings.Contains(body, `<script nonce="`+m[1]+`">`) {
			t.Fatalf("%s: page script does not carry the CSP nonce", tc.path)
		}
		if inline := regexp.MustCompile(`\son[a-z]+\s*=`).FindString(body); inline != "" {
			t.Fatalf("%s: inline event handler %q is blocked by the CSP", tc.path, inline)
		}
	}
	a := webGetForTest(s, "/login", "").Header().Get("Content-Security-Policy")
	b := webGetForTest(s, "/login", "").Header().Get("Content-Security-Policy")
	if a == b {
		t.Fatal("CSP nonce must change per response")
	}
}

// ORC-L16 (already fixed with ORC-L4): a login whose approval is denied
// leaves no "ok" entry, only the denial.
func TestLoginAuditOKOnlyAfterApproval(t *testing.T) {
	s := newTestServer(t)
	path := withAuditLogForTest(t, s)
	if err := s.store.setAdminPassword("owner-secret-value"); err != nil {
		t.Fatal(err)
	}
	s.setAuthApproverForTest(denyApprover{})
	if rec := adminCall(t, s.handleAdminLogin, "/admin/v1/login", map[string]string{"secret": "owner-secret-value"}, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("denied login: %d", rec.Code)
	}
	var denied bool
	for _, e := range readAuditEntriesForTest(t, path) {
		if e.Event == "admin_login" && e.Result == "ok" {
			t.Fatalf("ok audited before approval: %+v", e)
		}
		denied = denied || (e.Event == "admin_login_approval" && e.Result == "denied")
	}
	if !denied {
		t.Fatal("denial not audited")
	}
}

// ORC-L16: a discovery seq bump is audited.
func TestDiscoveryBumpIsAudited(t *testing.T) {
	s := newTestServer(t)
	path := withAuditLogForTest(t, s)
	rec := adminCall(t, s.handleAdminDiscoveryBump, "/admin/v1/discovery/bump", map[string]string{}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("bump: %d %s", rec.Code, rec.Body)
	}
	entries := readAuditEntriesForTest(t, path)
	if len(entries) == 0 || entries[len(entries)-1].Event != "discovery_bump" || entries[len(entries)-1].Result != "ok" || entries[len(entries)-1].Fields["seq"] == "" {
		t.Fatalf("discovery bump not audited: %+v", entries)
	}
}

// ORC-L16: verification goes on after the first break and reports each one.
func TestAuditVerifyReportsEveryBreak(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	audit, err := openAuditLog(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, ev := range []string{"a", "b", "c", "d", "e"} {
		audit.Log(auditEntry{Event: ev, Result: "failed"})
	}
	if err := audit.Close(); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	tampered := strings.Replace(string(raw), `"event":"b","result":"failed"`, `"event":"b","result":"ok"`, 1)
	tampered = strings.Replace(tampered, `"event":"d","result":"failed"`, `"event":"d","result":"ok"`, 1)
	if err := os.WriteFile(path, []byte(tampered), 0o600); err != nil {
		t.Fatal(err)
	}
	err = verifyAuditChain(path)
	var chainErr *auditChainError
	if !errors.Is(err, errAuditChainBroken) || !errors.As(err, &chainErr) {
		t.Fatalf("err=%v", err)
	}
	if len(chainErr.Breaks) != 2 || !strings.Contains(err.Error(), "line 2") || !strings.Contains(err.Error(), "line 4") {
		t.Fatalf("want breaks at lines 2 and 4, got %v", chainErr.Breaks)
	}
}

// ORC-M12: requests during a lockout write one entry per window and address
// with a repeat count instead of one fsync'd entry each.
func TestLockedLoginAuditIsAggregated(t *testing.T) {
	s := newTestServer(t)
	path := withAuditLogForTest(t, s)
	now := time.Now()
	s.audit.now = func() time.Time { return now }
	if err := s.store.setAdminPassword("owner-secret-value"); err != nil {
		t.Fatal(err)
	}
	for range adminLoginFailureLimit {
		adminCall(t, s.handleAdminLogin, "/admin/v1/login", map[string]string{"secret": "wrong-secret"}, nil)
	}
	before := len(readAuditEntriesForTest(t, path))
	for range 50 {
		if rec := adminCall(t, s.handleAdminLogin, "/admin/v1/login", map[string]string{"secret": "wrong-secret"}, nil); rec.Code != http.StatusTooManyRequests {
			t.Fatalf("locked login: %d", rec.Code)
		}
	}
	if got := len(readAuditEntriesForTest(t, path)) - before; got != 1 {
		t.Fatalf("50 locked requests wrote %d entries, want 1", got)
	}
	now = now.Add(2 * auditRepeatWindow)
	adminCall(t, s.handleAdminLogin, "/admin/v1/login", map[string]string{"secret": "wrong-secret"}, nil)
	entries := readAuditEntriesForTest(t, path)[before:]
	if len(entries) != 3 || entries[1].Fields["repeats"] != "49" || entries[1].Result != "locked" || entries[2].Fields["repeats"] != "" {
		t.Fatalf("want first, summary(49), new window: %+v", entries)
	}
	if err := s.audit.Close(); err != nil {
		t.Fatal(err)
	}
	if err := verifyAuditChain(path); err != nil {
		t.Fatal(err)
	}
}

// ORC-M12: the audit log rotates by size, keeps Keep old files, and the
// chain stays verifiable across files and reopens.
func TestAuditRotationKeepsChainVerifiable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	rotation := auditRotation{MaxBytes: 4096, Keep: 2}
	audit, err := openAuditLog(path, rotation)
	if err != nil {
		t.Fatal(err)
	}
	for range 200 {
		audit.Log(auditEntry{Event: "admin_login", Result: "failed", IP: "198.51.100.7"})
	}
	if err := audit.Close(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{path, path + ".1", path + ".2"} {
		info, err := os.Stat(name)
		if err != nil || info.Size() > rotation.MaxBytes {
			t.Fatalf("%s: %v size over limit", name, err)
		}
	}
	if _, err := os.Stat(path + ".3"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("more rotated files kept than configured")
	}
	if first := readAuditEntriesForTest(t, path)[0]; first.Event != auditRotatedEvent {
		t.Fatalf("rotated file must start with a marker: %+v", first)
	}
	if err := verifyAuditChain(path); err != nil {
		t.Fatalf("rotated chain: %v", err)
	}
	reopened, err := openAuditLog(path, rotation)
	if err != nil {
		t.Fatal(err)
	}
	reopened.Log(auditEntry{Event: "after_reopen", Result: "ok"})
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
	if err := verifyAuditChain(path); err != nil {
		t.Fatalf("after reopen: %v", err)
	}
	raw, _ := os.ReadFile(path + ".1")
	if err := os.WriteFile(path+".1", []byte(strings.Replace(string(raw), `"result":"failed"`, `"result":"ok"`, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifyAuditChain(path); !errors.Is(err, errAuditChainBroken) || !strings.Contains(err.Error(), "audit.log.1") {
		t.Fatalf("tamper in a rotated file: %v", err)
	}
}

// ORC-L36: the session expiry keeps its monotonic reading, so wall-clock
// steps neither end nor extend sessions.
func TestAdminSessionExpiryIsMonotonic(t *testing.T) {
	s := newTestServer(t)
	rec := httptest.NewRecorder()
	s.createAdminSession(rec, httptest.NewRequest(http.MethodPost, "/admin/v1/login", nil), false)
	var session adminSession
	s.adminSessions.Range(func(_, v any) bool { session = v.(adminSession); return false })
	// time.Time prints its monotonic reading as "m=±..."; UTC() drops it.
	if !strings.Contains(session.ExpiresAt.String(), " m=") {
		t.Fatalf("session expiry has no monotonic reading: %s", session.ExpiresAt)
	}
	if _, ok := s.sessionByToken(session.Token); !ok {
		t.Fatal("fresh session rejected")
	}
}

// ORC-L36: alert cooldowns follow this process's monotonic send time, and a
// persisted stamp from the future (clock stepped back) does not silence
// alerts.
func TestBotProblemCooldownIgnoresWallClockSteps(t *testing.T) {
	key := "worker:w1:worker_down"
	entry := botProblemEntry{Scope: "worker", ID: "w1", Kind: "worker_down", Label: "w1"}
	problems := map[string]botProblemEntry{key: entry}
	sent := time.Now()
	prev := botProblemState{
		Active:       problems,
		PendingPolls: map[string]int{key: botProblemPollsBeforeAlert},
		LastNotified: map[string]time.Time{key: sent.UTC()},
		UpdatedAt:    sent.UTC(),
		sentMono:     map[string]time.Time{key: sent},
	}
	current := buildBotProblemState(prev, problems, sent.Add(time.Minute))
	current.UpdatedAt = sent.UTC().Add(botProblemRepeatCooldown + time.Hour) // wall clock jumped forward
	if notices := botProblemNotices(prev, current, true); len(notices) != 0 {
		t.Fatalf("forward clock step broke the cooldown: %+v", notices)
	}

	prev.sentMono = nil
	prev.LastNotified[key] = sent.UTC().Add(10 * time.Hour) // stamp from before a backward step
	current = buildBotProblemState(prev, problems, sent)
	if notices := botProblemNotices(prev, current, true); len(notices) != 1 {
		t.Fatalf("backward clock step silenced the alert: %+v", notices)
	}
	markBotProblemNoticesSent(&current, botProblemNotices(prev, current, true))
	if current.LastNotified[key].After(sent.Add(time.Minute)) {
		t.Fatal("future stamp not replaced after sending")
	}
}

// ORC-L31: without a session "/" answers like any unknown path and the
// login page does not name the product; with a session "/" is the UI.
func TestUnauthenticatedRootIsNeutral(t *testing.T) {
	s := newTestServer(t)
	root := webGetForTest(s, "/", "")
	unknown := webGetForTest(s, "/no-such-path", "")
	if root.Code != http.StatusNotFound || root.Body.String() != unknown.Body.String() {
		t.Fatalf("GET / without session: %d %q", root.Code, root.Body)
	}
	login := webGetForTest(s, "/login", "")
	if login.Code != http.StatusOK || strings.Contains(strings.ToLower(login.Body.String()), "trafficwrapper") {
		t.Fatalf("login page names the product (%d)", login.Code)
	}
	s.adminSessions.Store("tok", adminSession{Token: "tok", CSRFToken: "csrf", ExpiresAt: time.Now().Add(time.Hour)})
	if rec := webGetForTest(s, "/", "tok"); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "TrafficWrapper ORCH") {
		t.Fatalf("GET / with session: %d", rec.Code)
	}
}

// P5: a new self-signed certificate carries neutral names and is logged; an
// existing one is kept as is.
func TestSelfSignedCertificateIsNeutral(t *testing.T) {
	logs := captureLogForTest(t)
	cfg := orchConfig{StateDir: t.TempDir()}
	certPath, _, err := loadOrCreateTLS(cfg)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(certPath)
	block, _ := pem.Decode(raw)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if certificateNamesProduct(raw) || cert.Subject.CommonName != selfSignedTLSName {
		t.Fatalf("new certificate names: CN=%q SAN=%v", cert.Subject.CommonName, cert.DNSNames)
	}
	if !strings.Contains(logs.String(), "WARNING: generated a self-signed TLS certificate") {
		t.Fatalf("no warning for a new self-signed certificate: %s", logs)
	}

	legacyDir := t.TempDir()
	certPEM, keyPEM, err := legacySelfSignedForTest()
	if err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(legacyDir, "tls.crt"), certPEM, 0o600)
	_ = os.WriteFile(filepath.Join(legacyDir, "tls.key"), keyPEM, 0o600)
	logs.Reset()
	if _, _, err := loadOrCreateTLS(orchConfig{StateDir: legacyDir}); err != nil {
		t.Fatal(err)
	}
	kept, _ := os.ReadFile(filepath.Join(legacyDir, "tls.crt"))
	if !bytes.Equal(kept, certPEM) {
		t.Fatal("existing certificate was reissued")
	}
	if !strings.Contains(logs.String(), "names the product") {
		t.Fatalf("no warning for a product-named certificate: %s", logs)
	}
}

// legacySelfSignedForTest builds a certificate like older releases did.
func legacySelfSignedForTest() ([]byte, []byte, error) {
	return selfSigned("trafficwrapper-orchestrator")
}

// P2: plain HTTP on a non-loopback address is an ERROR at startup, refused
// only with ORCH_TLS_STRICT=1, and flagged in the admin UI and status.
func TestPlaintextPublicListenerIsFlagged(t *testing.T) {
	for addr, want := range map[string]bool{"127.0.0.1:9091": true, "[::1]:9091": true, "localhost:9091": true, ":9091": false, "0.0.0.0:9091": false, "203.0.113.4:9091": false} {
		if got := listenAddrIsLoopback(addr); got != want {
			t.Fatalf("listenAddrIsLoopback(%q)=%v", addr, got)
		}
	}
	logs := captureLogForTest(t)
	if err := checkPlaintextListener(orchConfig{Listen: ":9091"}); err != nil {
		t.Fatalf("non-strict must start: %v", err)
	}
	if !strings.Contains(logs.String(), "ERROR: built-in TLS is disabled") {
		t.Fatalf("no ERROR logged: %s", logs)
	}
	if err := checkPlaintextListener(orchConfig{Listen: ":9091", TLSStrict: true}); err == nil {
		t.Fatal("ORCH_TLS_STRICT=1 must refuse plain HTTP on a public address")
	}
	logs.Reset()
	if err := checkPlaintextListener(orchConfig{Listen: "127.0.0.1:9091", TLSStrict: true}); err != nil || strings.Contains(logs.String(), "ERROR") {
		t.Fatalf("loopback behind a proxy: err=%v log=%s", err, logs)
	}
	if err := checkPlaintextListener(orchConfig{Listen: ":9091", TLS: true, TLSStrict: true}); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ORCH_TLS_STRICT", "1")
	if cfg, err := readConfig(); err != nil || !cfg.TLSStrict {
		t.Fatalf("ORCH_TLS_STRICT not read: %v", err)
	}

	s := newTestServer(t)
	s.cfg.Listen = "0.0.0.0:9091"
	s.adminSessions.Store("tok", adminSession{Token: "tok", CSRFToken: "csrf", ExpiresAt: time.Now().Add(time.Hour)})
	if body := webGetForTest(s, "/workers", "tok").Body.String(); !strings.Contains(body, `class="banner"`) {
		t.Fatal("admin UI shows no plain-HTTP banner")
	}
	status := httptest.NewRecorder()
	s.handleAdminStatus(status, httptest.NewRequest(http.MethodGet, "/admin/v1/status", nil))
	if !strings.HasPrefix(status.Body.String(), "warning=plaintext_public_listener ") {
		t.Fatalf("status: %q", status.Body)
	}
	s.cfg.Listen = "127.0.0.1:9091"
	if body := webGetForTest(s, "/workers", "tok").Body.String(); strings.Contains(body, `class="banner"`) {
		t.Fatal("banner shown for a loopback listener")
	}
}
