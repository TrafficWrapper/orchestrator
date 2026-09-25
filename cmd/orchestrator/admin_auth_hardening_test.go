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

func adminCall(t *testing.T, h http.HandlerFunc, path string, body any, mutate func(*http.Request)) *httptest.ResponseRecorder {
	t.Helper()
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	if mutate != nil {
		mutate(req)
	}
	rec := httptest.NewRecorder()
	h(rec, req)
	return rec
}

// ORC-M3/ORC-L13: force-set needs the same proof as a change and a strong
// password.
func TestPasswordForceSetNeedsStepUp(t *testing.T) {
	s := newTestServer(t)
	if err := s.store.setAdminPassword("owner-secret-value"); err != nil {
		t.Fatal(err)
	}
	if rec := adminCall(t, s.handleAdminPasswordForceSet, "/admin/v1/password/force-set", map[string]string{"new_secret": "attacker-password-1"}, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("force-set without proof: %d", rec.Code)
	}
	if ok, _, _ := s.store.verifyAdminPassword("owner-secret-value"); !ok {
		t.Fatal("password changed without proof")
	}
	if rec := adminCall(t, s.handleAdminPasswordForceSet, "/admin/v1/password/force-set", map[string]string{"new_secret": "short", "current_secret": "owner-secret-value"}, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("short password accepted: %d", rec.Code)
	}
	if rec := adminCall(t, s.handleAdminPasswordForceSet, "/admin/v1/password/force-set", map[string]string{"new_secret": "a-much-better-secret", "current_secret": "owner-secret-value"}, nil); rec.Code != http.StatusOK {
		t.Fatalf("force-set with proof: %d %s", rec.Code, rec.Body)
	}
}

// ORC-M4: replacing an enabled TOTP needs a code of the current secret.
func TestTOTPReplacementNeedsCurrentFactor(t *testing.T) {
	s := newTestServer(t)
	now := time.Now().UTC()
	oldSecret := enableTestTOTP(t, s, now)
	pending, err := s.store.startAdminTOTPEnrollment()
	if err != nil {
		t.Fatal(err)
	}
	newCode, _ := totpCode(pending.Secret, now.Unix()/totpPeriodSeconds)
	if rec := adminCall(t, s.handleAdminTOTPEnable, "/admin/v1/totp/enable", map[string]string{"code": newCode}, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("replacement without current code: %d", rec.Code)
	}
	next := now.Add(time.Duration(totpPeriodSeconds) * time.Second)
	currentCode, _ := totpCode(oldSecret, next.Unix()/totpPeriodSeconds)
	s.adminSessions.Store("other", adminSession{Token: "other", ExpiresAt: time.Now().Add(time.Hour)})
	if rec := adminCall(t, s.handleAdminTOTPEnable, "/admin/v1/totp/enable", map[string]string{"code": newCode, "current_code": currentCode}, nil); rec.Code != http.StatusOK {
		t.Fatalf("replacement with current code: %d %s", rec.Code, rec.Body)
	}
	if _, ok := s.adminSessions.Load("other"); ok {
		t.Fatal("replacing the second factor must end other sessions")
	}
}

// ORC-L3: changing the approval bot needs step-up.
func TestBotSettingsNeedStepUp(t *testing.T) {
	s := newTestServer(t)
	if err := s.store.setAdminPassword("owner-secret-value"); err != nil {
		t.Fatal(err)
	}
	if rec := adminCall(t, s.handleAdminBotSetToken, "/admin/v1/bot/set-token", map[string]any{"token": "1:x", "owner_id": 7}, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("bot change without step-up: %d", rec.Code)
	}
	if _, ok, _ := s.store.botSettings(); ok {
		t.Fatal("bot settings changed without step-up")
	}
}

// ORC-L18/ORC-L17: login only as a same-site JSON request, one error text.
func TestLoginRejectsCrossSiteAndUnifiesErrors(t *testing.T) {
	s := newTestServer(t)
	if err := s.store.setAdminPassword("owner-secret-value"); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*http.Request){
		"text/plain":  func(r *http.Request) { r.Header.Set("Content-Type", "text/plain") },
		"cross-site":  func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") },
		"origin":      func(r *http.Request) { r.Header.Set("Origin", "https://evil.example") },
		"form-urlenc": func(r *http.Request) { r.Header.Set("Content-Type", "application/x-www-form-urlencoded") },
	} {
		if rec := adminCall(t, s.handleAdminLogin, "/admin/v1/login", map[string]string{"secret": "owner-secret-value"}, mutate); rec.Code != http.StatusForbidden {
			t.Fatalf("%s login accepted: %d", name, rec.Code)
		}
	}
	rec := adminCall(t, s.handleAdminLogin, "/admin/v1/login", map[string]string{"secret": "wrong"}, nil)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "invalid credentials") {
		t.Fatalf("bad password: %d %s", rec.Code, rec.Body)
	}
	if rec := adminCall(t, s.handleAdminLogin, "/admin/v1/login", map[string]string{"secret": "owner-secret-value"}, func(r *http.Request) { r.Header.Set("Origin", "http://example.com") }); rec.Code != http.StatusOK {
		t.Fatalf("same-host login refused: %d %s", rec.Code, rec.Body)
	}
}

// ORC-I3: with bot settings stored but no approver running, logins fail
// closed instead of skipping approval.
func TestApprovalFailsClosedWhileBotIsDown(t *testing.T) {
	s := newTestServer(t)
	if err := s.store.setAdminPassword("owner-secret-value"); err != nil {
		t.Fatal(err)
	}
	if err := s.store.setBotSettings("1:x", 42); err != nil {
		t.Fatal(err)
	}
	s.botFactory = func(string) telegramAPI { return &mockTelegramAPI{} }
	if rec := adminCall(t, s.handleAdminLogin, "/admin/v1/login", map[string]string{"secret": "owner-secret-value"}, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("login without a running approver: %d", rec.Code)
	}
}

// ORC-L4: denied approvals count against the login budget.
func TestDeniedApprovalsCountAsFailures(t *testing.T) {
	s := newTestServer(t)
	if err := s.store.setAdminPassword("owner-secret-value"); err != nil {
		t.Fatal(err)
	}
	s.setAuthApproverForTest(denyApprover{})
	var last int
	for range adminLoginFailureLimit + 1 {
		last = adminCall(t, s.handleAdminLogin, "/admin/v1/login", map[string]string{"secret": "owner-secret-value"}, nil).Code
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("repeated denied approvals must lock the address: %d", last)
	}
}

// ORC-L29: one noisy address does not lock its whole network.
func TestLoginNetworkLockNeedsDistinctSources(t *testing.T) {
	l := newLoginLimiter()
	for range adminLoginPrefixFailureLimit + 5 {
		l.reserveAttempt("198.51.100.7")
	}
	if got := l.reserveAttempt("198.51.100.9"); !got.Allowed || got.Locked {
		t.Fatalf("neighbour locked out by one address: %+v", got)
	}
}
