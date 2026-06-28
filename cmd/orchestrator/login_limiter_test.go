package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestAdminLoginLimiterLocksOutAndResets(t *testing.T) {
	s := newTestServer(t)
	if err := s.store.setAdminPassword("owner-secret"); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 6, 28, 10, 0, 0, 0, time.UTC)
	limiter := newLoginLimiter()
	limiter.now = func() time.Time { return now }
	s.loginLimiter = limiter

	ts := httptest.NewServer(http.HandlerFunc(s.handleAdminLogin))
	defer ts.Close()

	for i := 0; i < adminLoginFailureLimit-1; i++ {
		if status, retry := postAdminLoginForTest(t, ts.URL, "bad-secret", "198.51.100.10"); status != http.StatusForbidden || retry != "" {
			t.Fatalf("failure %d status=%d retry=%q", i+1, status, retry)
		}
	}
	now = now.Add(adminLoginWindow + time.Second)
	if status, retry := postAdminLoginForTest(t, ts.URL, "bad-secret", "198.51.100.10"); status != http.StatusForbidden || retry != "" {
		t.Fatalf("window reset failure status=%d retry=%q", status, retry)
	}
	for i := 1; i < adminLoginFailureLimit; i++ {
		status, retry := postAdminLoginForTest(t, ts.URL, "bad-secret", "198.51.100.10")
		if i == adminLoginFailureLimit-1 {
			if status != http.StatusTooManyRequests || retry == "" {
				t.Fatalf("lockout status=%d retry=%q", status, retry)
			}
			continue
		}
		if status != http.StatusForbidden || retry != "" {
			t.Fatalf("post-reset failure %d status=%d retry=%q", i, status, retry)
		}
	}
	if status, retry := postAdminLoginForTest(t, ts.URL, "owner-secret", "198.51.100.10"); status != http.StatusTooManyRequests || retry == "" {
		t.Fatalf("locked success attempt status=%d retry=%q", status, retry)
	}
	now = now.Add(adminLoginLockoutTTL + time.Second)
	if status, retry := postAdminLoginForTest(t, ts.URL, "owner-secret", "198.51.100.10"); status != http.StatusOK || retry != "" {
		t.Fatalf("success after lockout status=%d retry=%q", status, retry)
	}
	if _, locked := limiter.isLocked("198.51.100.10"); locked {
		t.Fatal("successful login did not clear limiter state")
	}
}

func postAdminLoginForTest(t *testing.T, baseURL, secret, forwardedFor string) (int, string) {
	t.Helper()
	raw, _ := json.Marshal(map[string]string{"secret": secret})
	req, err := http.NewRequest(http.MethodPost, baseURL, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("content-type", "application/json")
	if forwardedFor != "" {
		req.Header.Set("X-Forwarded-For", forwardedFor)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode, resp.Header.Get("Retry-After")
}
