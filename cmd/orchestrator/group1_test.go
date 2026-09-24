package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
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

type blockingTelegramAPI struct {
	mockTelegramAPI
	active *atomic.Int32
}

func (b *blockingTelegramAPI) getUpdates(ctx context.Context, _ int64, _ int) ([]telegramUpdate, error) {
	b.active.Add(1)
	defer b.active.Add(-1)
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestConcurrentBotRestartsLeaveOnePoller(t *testing.T) {
	s := newTestServer(t)
	if err := s.store.setBotSettings("123:token", 42); err != nil {
		t.Fatal(err)
	}
	var active atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.rootCtx = ctx
	if err := s.startOptionalBot(ctx, func(string) telegramAPI { return &blockingTelegramAPI{active: &active} }); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _ = s.restartOptionalBot(s.baseContext()) }()
	}
	wg.Wait()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && active.Load() != 1 {
		time.Sleep(10 * time.Millisecond)
	}
	if got := active.Load(); got != 1 {
		t.Fatalf("pollers=%d after concurrent restarts, want 1", got)
	}
}

func TestBotActionsAreAudited(t *testing.T) {
	s := newTestServer(t)
	logPath := filepath.Join(t.TempDir(), "audit.log")
	audit, err := openAuditLog(logPath)
	if err != nil {
		t.Fatal(err)
	}
	s.audit = audit
	defer audit.Close()
	worker := addApprovedWorkerWithStatic(t, s, "bot-audit-worker")
	bot := newTelegramBot(s, botSettingsRecord{Token: "t", OwnerID: 77}, &mockTelegramAPI{})
	bot.handleWorkerCallback(context.Background(), telegramCallbackQuery{ID: "cb", Data: "worker:disable:" + worker.ID})
	raw, _ := os.ReadFile(logPath)
	if !strings.Contains(string(raw), `"event":"worker_set_enabled"`) || !strings.Contains(string(raw), `"actor":"bot:77"`) {
		t.Fatalf("bot action not audited: %s", raw)
	}
}
