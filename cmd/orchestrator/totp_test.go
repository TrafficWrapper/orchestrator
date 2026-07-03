package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestAdminTOTPStoreVerifyAndReplay(t *testing.T) {
	s := newTestServer(t)
	rec, err := s.store.startAdminTOTPEnrollment()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0).UTC()
	code, err := totpCode(rec.Secret, now.Unix()/totpPeriodSeconds)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.store.enableAdminTOTP(code, now); err != nil {
		t.Fatalf("enable totp: %v", err)
	}
	enabled, ok, err := s.store.verifyAdminTOTP(code, now)
	if err != nil {
		t.Fatal(err)
	}
	if !enabled || ok {
		t.Fatalf("replayed code accepted: enabled=%t ok=%t", enabled, ok)
	}
	nextCode, err := totpCode(rec.Secret, now.Add(time.Duration(totpPeriodSeconds)*time.Second).Unix()/totpPeriodSeconds)
	if err != nil {
		t.Fatal(err)
	}
	enabled, ok, err = s.store.verifyAdminTOTP(nextCode, now.Add(time.Duration(totpPeriodSeconds)*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if !enabled || !ok {
		t.Fatalf("next code rejected: enabled=%t ok=%t", enabled, ok)
	}
}

func TestAdminLoginTOTPDefaultOffAndEnabled(t *testing.T) {
	s := newTestServer(t)
	if err := s.store.setAdminPassword("secret"); err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(http.HandlerFunc(s.handleAdminLogin))
	defer ts.Close()

	if code := postAdminLogin(t, ts.URL, "secret", ""); code != http.StatusOK {
		t.Fatalf("default-off login status=%d", code)
	}

	rec, err := s.store.startAdminTOTPEnrollment()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	enableCode, err := totpCode(rec.Secret, now.Unix()/totpPeriodSeconds)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.store.enableAdminTOTP(enableCode, now); err != nil {
		t.Fatal(err)
	}
	if code := postAdminLogin(t, ts.URL, "secret", "000000"); code != http.StatusForbidden {
		t.Fatalf("bad totp login status=%d", code)
	}
	loginCode, err := totpCode(rec.Secret, time.Now().UTC().Add(time.Duration(totpPeriodSeconds)*time.Second).Unix()/totpPeriodSeconds)
	if err != nil {
		t.Fatal(err)
	}
	if code := postAdminLogin(t, ts.URL, "secret", loginCode); code != http.StatusOK {
		t.Fatalf("good totp login status=%d", code)
	}
	if code := postAdminLogin(t, ts.URL, "secret", loginCode); code != http.StatusForbidden {
		t.Fatalf("replayed totp login status=%d", code)
	}
}

func postAdminLogin(t *testing.T, baseURL, secret, code string) int {
	t.Helper()
	body := map[string]string{"secret": secret}
	if code != "" {
		body["totp_code"] = code
	}
	raw, _ := json.Marshal(body)
	resp, err := http.Post(baseURL, "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}
