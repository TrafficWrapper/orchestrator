package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type denyApprover struct{}

func (denyApprover) enabled() bool { return true }
func (denyApprover) requestLoginApproval(context.Context, loginApprovalRequest) (bool, error) {
	return false, nil
}

func TestDeniedApprovalKeepsOldPasswordAndSessions(t *testing.T) {
	s := newTestServer(t)
	if err := s.store.setAdminPassword("old-secret-value"); err != nil {
		t.Fatal(err)
	}
	s.adminSessions.Store("tok", adminSession{Token: "tok", ExpiresAt: time.Now().Add(time.Hour)})
	s.setAuthApproverForTest(denyApprover{})
	raw, _ := json.Marshal(map[string]string{"current_secret": "old-secret-value", "new_secret": "new-secret-value-123"})
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/password/change", bytes.NewReader(raw))
	req.Header.Set("authorization", "Bearer tok")
	rec := httptest.NewRecorder()
	s.handleAdminPasswordChange(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status=%d", rec.Code)
	}
	if ok, _, _ := s.store.verifyAdminPassword("old-secret-value"); !ok {
		t.Fatal("denied approval must keep the old password")
	}
	if _, ok := s.adminSessions.Load("tok"); !ok {
		t.Fatal("denied approval must not end existing sessions")
	}
}
