package main

import (
	"net/http/httptest"
	"testing"
)

func TestClientIPTrustsForwardedOnlyFromLoopbackProxy(t *testing.T) {
	req := httptest.NewRequest("POST", "https://orch.example/admin/v1/login", nil)
	req.RemoteAddr = "127.0.0.1:54432"
	req.Header.Set("X-Forwarded-For", "garbage, 198.51.100.10, 198.51.100.11")
	if got := clientIP(req); got != "198.51.100.11" {
		t.Fatalf("clientIP loopback XFF = %q", got)
	}

	req = httptest.NewRequest("POST", "https://orch.example/admin/v1/login", nil)
	req.RemoteAddr = "[::1]:54432"
	req.Header.Set("X-Forwarded-For", "198.51.100.10, 198.51.100.11")
	req.Header.Set("X-Real-IP", "1.2.3.4")
	if got := clientIP(req); got != "1.2.3.4" {
		t.Fatalf("clientIP loopback X-Real-IP = %q", got)
	}

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
