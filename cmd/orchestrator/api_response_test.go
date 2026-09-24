package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestAdminWrapperOrderAndJSONErrors(t *testing.T) {
	s := newTestServer(t)
	h := s.route("/admin/v1/revoke-device")

	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodGet, "/admin/v1/revoke-device", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("wrong method must be 405 before auth, got %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodPost, "/admin/v1/revoke-device", strings.NewReader(`{"id":"x"}`)))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("missing session status=%d", rec.Code)
	}

	s.adminSessions.Store("tok", adminSession{Token: "tok", ExpiresAt: time.Now().Add(time.Hour)})
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/revoke-device", strings.NewReader(`{"id":"missing-device"}`))
	req.Header.Set("authorization", "Bearer tok")
	rec = httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown device status=%d body=%s", rec.Code, rec.Body.String())
	}
	var body apiError
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body.OK || body.Error != "device not found" {
		t.Fatalf("error body=%q err=%v", rec.Body.String(), err)
	}

	req = httptest.NewRequest(http.MethodPost, "/admin/v1/revoke-device", strings.NewReader(`{not json`))
	req.Header.Set("authorization", "Bearer tok")
	rec = httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "invalid JSON body") {
		t.Fatalf("malformed body status=%d body=%s", rec.Code, rec.Body.String())
	}
}
