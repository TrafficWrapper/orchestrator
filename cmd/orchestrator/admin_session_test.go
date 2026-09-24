package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func enableTestTOTP(t *testing.T, s *server, at time.Time) string {
	t.Helper()
	rec, err := s.store.startAdminTOTPEnrollment()
	if err != nil {
		t.Fatal(err)
	}
	code, err := totpCode(rec.Secret, at.Unix()/totpPeriodSeconds)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.store.enableAdminTOTP(code, at); err != nil {
		t.Fatal(err)
	}
	return rec.Secret
}

func TestTOTPReenrollmentKeepsExistingFactorActive(t *testing.T) {
	s := newTestServer(t)
	now := time.Now().UTC()
	original := enableTestTOTP(t, s, now)
	pending, err := s.store.startAdminTOTPEnrollment()
	if err != nil {
		t.Fatal(err)
	}
	if pending.Secret == original {
		t.Fatal("re-enrollment must issue a new secret")
	}
	rec, enabled, err := s.store.adminTOTP()
	if err != nil || !enabled || rec.Secret != original {
		t.Fatalf("unfinished re-enrollment disabled 2FA: enabled=%t err=%v", enabled, err)
	}
	next := now.Add(time.Duration(totpPeriodSeconds) * time.Second)
	code, _ := totpCode(pending.Secret, next.Unix()/totpPeriodSeconds)
	if err := s.store.enableAdminTOTP(code, next); err != nil {
		t.Fatal(err)
	}
	rec, enabled, _ = s.store.adminTOTP()
	if !enabled || rec.Secret != pending.Secret || rec.PendingSecret != "" {
		t.Fatalf("confirmed re-enrollment not applied: %+v", rec)
	}
}

func TestAdminTOTPDisableRequiresCode(t *testing.T) {
	s := newTestServer(t)
	now := time.Now().UTC()
	secret := enableTestTOTP(t, s, now)
	s.adminSessions.Store("tok", adminSession{Token: "tok", ExpiresAt: time.Now().Add(time.Hour)})
	post := func(body string) int {
		req := httptest.NewRequest(http.MethodPost, "/admin/v1/totp/disable", strings.NewReader(body))
		req.Header.Set("authorization", "Bearer tok")
		rec := httptest.NewRecorder()
		s.handleAdminTOTPDisable(rec, req)
		return rec.Code
	}
	if code := post(`{}`); code != http.StatusForbidden {
		t.Fatalf("disable without code status=%d", code)
	}
	if _, enabled, _ := s.store.adminTOTP(); !enabled {
		t.Fatal("2FA must stay enabled after a rejected disable")
	}
	next := now.Add(time.Duration(totpPeriodSeconds) * time.Second)
	code, _ := totpCode(secret, next.Unix()/totpPeriodSeconds)
	raw, _ := json.Marshal(map[string]string{"code": code})
	if status := post(string(raw)); status != http.StatusOK {
		t.Fatalf("disable with valid code status=%d", status)
	}
	if _, ok := s.adminSessions.Load("tok"); ok {
		t.Fatal("disabling 2FA must end existing sessions")
	}
}

func TestAdminPasswordChangeRevokesAllSessions(t *testing.T) {
	s := newTestServer(t)
	if err := s.store.setAdminPassword("old-secret-value"); err != nil {
		t.Fatal(err)
	}
	expires := time.Now().Add(time.Hour)
	s.adminSessions.Store("current", adminSession{Token: "current", ExpiresAt: expires})
	s.adminSessions.Store("stolen", adminSession{Token: "stolen", ExpiresAt: expires})
	raw, _ := json.Marshal(map[string]string{"current_secret": "old-secret-value", "new_secret": "new-secret-value-123"})
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/password/change", bytes.NewReader(raw))
	req.Header.Set("authorization", "Bearer current")
	rec := httptest.NewRecorder()
	s.handleAdminPasswordChange(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if _, ok := s.adminSessions.Load("stolen"); ok {
		t.Fatal("other sessions must not survive a password change")
	}
	if _, ok := s.adminSessions.Load("current"); ok {
		t.Fatal("the old token must be replaced")
	}
}

func TestAdminLogoutAndExpiredSessionPrune(t *testing.T) {
	s := newTestServer(t)
	s.adminSessions.Store("live", adminSession{Token: "live", ExpiresAt: time.Now().Add(time.Hour)})
	s.adminSessions.Store("old", adminSession{Token: "old", ExpiresAt: time.Now().Add(-time.Minute)})
	s.pruneExpiredAdminSessions(time.Now().UTC())
	if _, ok := s.adminSessions.Load("old"); ok {
		t.Fatal("expired session not pruned")
	}
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/logout", nil)
	req.Header.Set("authorization", "Bearer live")
	rec := httptest.NewRecorder()
	s.handleAdminLogout(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("logout status=%d", rec.Code)
	}
	if _, ok := s.adminSessions.Load("live"); ok {
		t.Fatal("logout must end the session")
	}
}

func TestSessionCookieSecureUnderTLSAndSecurityHeaders(t *testing.T) {
	s := newTestServer(t)
	s.cfg.TLS = true
	rec := httptest.NewRecorder()
	s.createAdminSession(rec, httptest.NewRequest(http.MethodPost, "/admin/v1/login", nil), false)
	if !strings.Contains(rec.Header().Get("Set-Cookie"), "Secure") {
		t.Fatalf("cookie not Secure: %q", rec.Header().Get("Set-Cookie"))
	}
	h := withSecurityHeaders(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	out := httptest.NewRecorder()
	h.ServeHTTP(out, httptest.NewRequest(http.MethodGet, "/", nil))
	if out.Header().Get("X-Frame-Options") != "DENY" || !strings.Contains(out.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'") {
		t.Fatalf("missing anti-framing headers: %v", out.Header())
	}
}
