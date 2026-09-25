package main

import (
	"net/http/httptest"
	"testing"
)

// ORC-L12: auto mode trusts no proxy header; only an explicitly named one.
func TestClientIPTrustsForwardedOnlyFromLoopbackProxy(t *testing.T) {
	t.Cleanup(func() { _ = setClientIPHeaderMode("") })
	req := httptest.NewRequest("POST", "https://orch.example/admin/v1/login", nil)
	req.RemoteAddr = "127.0.0.1:54432"
	req.Header.Set("X-Forwarded-For", "garbage, 198.51.100.10, 198.51.100.11")
	if got := clientIP(req); got != "127.0.0.1" {
		t.Fatalf("auto mode trusted XFF: %q", got)
	}
	_ = setClientIPHeaderMode("x-forwarded-for")
	if got := clientIP(req); got != "198.51.100.11" {
		t.Fatalf("clientIP loopback XFF = %q", got)
	}

	req = httptest.NewRequest("POST", "https://orch.example/admin/v1/login", nil)
	req.RemoteAddr = "[::1]:54432"
	req.Header.Set("X-Forwarded-For", "198.51.100.10, 198.51.100.11")
	req.Header.Set("X-Real-IP", "1.2.3.4")
	_ = setClientIPHeaderMode("x-real-ip")
	if got := clientIP(req); got != "1.2.3.4" {
		t.Fatalf("clientIP loopback X-Real-IP = %q", got)
	}
	_ = setClientIPHeaderMode("x-forwarded-for")

	req = httptest.NewRequest("POST", "https://orch.example/admin/v1/login", nil)
	req.RemoteAddr = "203.0.113.20:54432"
	req.Header.Set("X-Forwarded-For", "198.51.100.99")
	if got := clientIP(req); got != "203.0.113.20" {
		t.Fatalf("clientIP trusted non-loopback XFF = %q", got)
	}

	req = httptest.NewRequest("POST", "https://orch.example/admin/v1/login", nil)
	req.RemoteAddr = "127.0.0.1:54432"
	req.Header.Set("X-Forwarded-For", "bad, also-bad")
	if got := clientIP(req); got != "127.0.0.1" {
		t.Fatalf("clientIP invalid XFF fallback = %q", got)
	}
}

func TestClientIPHeaderModesIgnoreUntrustedHeader(t *testing.T) {
	t.Cleanup(func() { _ = setClientIPHeaderMode("") })
	req := httptest.NewRequest("POST", "https://orch.example/admin/v1/login", nil)
	req.RemoteAddr = "127.0.0.1:54432"
	req.Header.Set("X-Forwarded-For", "198.51.100.10")
	req.Header.Set("X-Real-IP", "6.6.6.6")

	if err := setClientIPHeaderMode("x-forwarded-for"); err != nil {
		t.Fatal(err)
	}
	if got := clientIP(req); got != "198.51.100.10" {
		t.Fatalf("x-forwarded-for mode trusted forged X-Real-IP: %q", got)
	}
	if err := setClientIPHeaderMode("x-real-ip"); err != nil {
		t.Fatal(err)
	}
	req.Header.Del("X-Real-IP")
	if got := clientIP(req); got != "127.0.0.1" {
		t.Fatalf("x-real-ip mode trusted X-Forwarded-For: %q", got)
	}
	if err := setClientIPHeaderMode("none"); err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Real-IP", "6.6.6.6")
	if got := clientIP(req); got != "127.0.0.1" {
		t.Fatalf("none mode trusted a header: %q", got)
	}
	if err := setClientIPHeaderMode("bogus"); err == nil {
		t.Fatal("unknown mode must be rejected")
	}
}
