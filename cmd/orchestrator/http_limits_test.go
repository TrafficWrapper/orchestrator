package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRequestBodyLimitsRejectOversizedLogin(t *testing.T) {
	called := false
	h := withRequestBodyLimits(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	body := `{"secret":"` + strings.Repeat("A", loginRequestBodyMaxBytes) + `"}`
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/login", strings.NewReader(body))
	req.ContentLength = -1
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status=%d want 413", rec.Code)
	}
	if called {
		t.Fatal("handler must not run for oversized body")
	}
}

func TestRequestBodyLimitsRejectDeclaredOversizedNoiseBody(t *testing.T) {
	h := withRequestBodyLimits(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("handler called") }))
	// Ack has its own larger limit (ORC-L27); every other Noise path keeps
	// the default one.
	for path, limit := range map[string]int64{"/w/v1/config/pull": noiseRequestBodyMaxBytes, "/w/v1/ack": ackRequestBodyMaxBytes} {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader("{}"))
		req.ContentLength = limit + 1
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("%s: status=%d want 413", path, rec.Code)
		}
	}
}

// ORC-L27: an ack with a full usage report fits.
func TestRequestBodyLimitsAckFitsLargeUsage(t *testing.T) {
	called := false
	h := withRequestBodyLimits(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		called = true
		_, _ = io.Copy(io.Discard, r.Body)
	}))
	body := strings.Repeat("A", noiseRequestBodyMaxBytes*3)
	req := httptest.NewRequest(http.MethodPost, "/w/v1/ack", strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if !called || rec.Code == http.StatusRequestEntityTooLarge {
		t.Fatalf("large ack refused: %d", rec.Code)
	}
}

func TestRequestBodyLimitsPassSmallBody(t *testing.T) {
	var got string
	h := withRequestBodyLimits(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		got = string(raw)
	}))
	req := httptest.NewRequest(http.MethodPost, "/w/v1/ack", strings.NewReader(`{"sid":"x"}`))
	h.ServeHTTP(httptest.NewRecorder(), req)
	if got != `{"sid":"x"}` {
		t.Fatalf("body=%q", got)
	}
}

func TestRequestBodyLimitsStreamUploads(t *testing.T) {
	var read int
	h := withRequestBodyLimits(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		read = len(raw)
	}))
	payload := strings.Repeat("x", 3<<20)
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/apk/publish", strings.NewReader(payload))
	h.ServeHTTP(httptest.NewRecorder(), req)
	if read != len(payload) {
		t.Fatalf("read=%d want %d", read, len(payload))
	}
}
