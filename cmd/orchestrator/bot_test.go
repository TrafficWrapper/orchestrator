package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

type mockTelegramAPI struct {
	mu      sync.Mutex
	sent    []mockTelegramMessage
	answers []string
	updates []telegramUpdate
}

type mockTelegramMessage struct {
	ChatID   int64
	Text     string
	Keyboard *telegramInlineKeyboard
}

func (m *mockTelegramAPI) getUpdates(context.Context, int64, int) ([]telegramUpdate, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := append([]telegramUpdate(nil), m.updates...)
	m.updates = nil
	return out, nil
}

func (m *mockTelegramAPI) sendMessage(_ context.Context, chatID int64, text string, keyboard *telegramInlineKeyboard) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sent = append(m.sent, mockTelegramMessage{ChatID: chatID, Text: text, Keyboard: keyboard})
	return nil
}

func (m *mockTelegramAPI) answerCallback(_ context.Context, callbackID, text string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.answers = append(m.answers, callbackID+":"+text)
	return nil
}

func (m *mockTelegramAPI) sentCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.sent)
}

func (m *mockTelegramAPI) lastSent() mockTelegramMessage {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.sent) == 0 {
		return mockTelegramMessage{}
	}
	return m.sent[len(m.sent)-1]
}

func (m *mockTelegramAPI) waitSent(t *testing.T, want int) mockTelegramMessage {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if m.sentCount() >= want {
			return m.lastSent()
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %d telegram messages, got %d", want, m.sentCount())
	return mockTelegramMessage{}
}

func TestTelegramBotOwnerGateAndStatus(t *testing.T) {
	s := newTestServer(t)
	addApprovedWorker(t, s)
	mock := &mockTelegramAPI{}
	bot := newTelegramBot(s, botSettingsRecord{Token: "test-token", OwnerID: 1001}, mock)

	bot.handleUpdate(context.Background(), telegramUpdate{Message: &telegramMessage{
		From: telegramUser{ID: 1001},
		Chat: telegramChat{ID: 1001},
		Text: "/status",
	}})
	if got := mock.lastSent(); got.ChatID != 1001 || !strings.Contains(got.Text, "Статус платформы") || !strings.Contains(got.Text, "Workers:") {
		t.Fatalf("bad status response: %+v", got)
	}
	before := mock.sentCount()
	bot.handleUpdate(context.Background(), telegramUpdate{Message: &telegramMessage{
		From: telegramUser{ID: 2002},
		Chat: telegramChat{ID: 2002},
		Text: "/status",
	}})
	if got := mock.sentCount(); got != before {
		t.Fatalf("non-owner message was answered: before=%d after=%d", before, got)
	}
}

func TestTelegramBotTokenEncryptedInStore(t *testing.T) {
	s := newTestServer(t)
	token := "123456:secret-token-value"
	if err := s.store.setBotSettings(token, 1001); err != nil {
		t.Fatal(err)
	}
	rec, ok, err := s.store.botSettings()
	if err != nil || !ok {
		t.Fatalf("settings not readable ok=%t err=%v", ok, err)
	}
	if rec.Token != token || rec.OwnerID != 1001 {
		t.Fatalf("bad settings roundtrip: %+v", rec)
	}
	if err := s.store.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket(bucketMeta).Get(metaBotSettings)
		if raw == nil {
			t.Fatal("bot settings missing")
		}
		if bytes.Contains(raw, []byte(token)) || bytes.Contains(raw, []byte("secret-token-value")) {
			t.Fatalf("bot token leaked in sealed record: %q", string(raw))
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestTelegramBotLoginApprovalAndDeny(t *testing.T) {
	s := newTestServer(t)
	if err := s.store.setAdminPassword("owner-secret"); err != nil {
		t.Fatal(err)
	}
	mock := &mockTelegramAPI{}
	bot := newTelegramBot(s, botSettingsRecord{Token: "test-token", OwnerID: 1001}, mock)
	bot.approver.ttl = 2 * time.Second
	s.setAuthApproverForTest(bot.approver)

	ts := httptest.NewServer(http.HandlerFunc(s.handleAdminLogin))
	defer ts.Close()

	approveCh := postLoginAsync(t, ts.URL, "owner-secret")
	approveMsg := mock.waitSent(t, 1)
	approveData := approveMsg.Keyboard.InlineKeyboard[0][0].CallbackData
	bot.handleUpdate(context.Background(), telegramUpdate{CallbackQuery: &telegramCallbackQuery{
		ID:   "cb-approve",
		From: telegramUser{ID: 1001},
		Data: approveData,
	}})
	approved := <-approveCh
	if approved.StatusCode != http.StatusOK || !strings.Contains(approved.Body, "session_token") {
		t.Fatalf("approved login failed: %+v", approved)
	}

	denyCh := postLoginAsync(t, ts.URL, "owner-secret")
	denyMsg := mock.waitSent(t, 2)
	denyData := denyMsg.Keyboard.InlineKeyboard[0][1].CallbackData
	bot.handleUpdate(context.Background(), telegramUpdate{CallbackQuery: &telegramCallbackQuery{
		ID:   "cb-deny",
		From: telegramUser{ID: 1001},
		Data: denyData,
	}})
	denied := <-denyCh
	if denied.StatusCode != http.StatusForbidden || !strings.Contains(denied.Body, "denied") {
		t.Fatalf("denied login was not rejected: %+v", denied)
	}
}

func TestAdminLoginFallbackWithoutBot(t *testing.T) {
	s := newTestServer(t)
	if err := s.store.setAdminPassword("owner-secret"); err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(http.HandlerFunc(s.handleAdminLogin))
	defer ts.Close()
	result := postLogin(t, ts.URL, "owner-secret")
	if result.StatusCode != http.StatusOK || !strings.Contains(result.Body, "session_token") {
		t.Fatalf("fallback login failed: %+v", result)
	}
}

func TestTelegramBotInlineDisableWorkerBumpsSeq(t *testing.T) {
	s := newTestServer(t)
	addApprovedWorker(t, s)
	workers, err := s.store.workers()
	if err != nil {
		t.Fatal(err)
	}
	worker := workers[0]
	mock := &mockTelegramAPI{}
	bot := newTelegramBot(s, botSettingsRecord{Token: "test-token", OwnerID: 1001}, mock)
	bot.handleUpdate(context.Background(), telegramUpdate{CallbackQuery: &telegramCallbackQuery{
		ID:   "cb-disable",
		From: telegramUser{ID: 1001},
		Data: "worker:disable:" + worker.ID,
	}})
	updated, err := s.store.worker(worker.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !updated.Disabled || updated.DesiredSeq <= worker.DesiredSeq {
		t.Fatalf("worker was not disabled or seq not bumped: before=%+v after=%+v", worker, updated)
	}
}

type loginTestResult struct {
	StatusCode int
	Body       string
}

func postLoginAsync(t *testing.T, url, secret string) <-chan loginTestResult {
	t.Helper()
	ch := make(chan loginTestResult, 1)
	go func() {
		ch <- postLogin(t, url, secret)
	}()
	return ch
}

func postLogin(t *testing.T, url, secret string) loginTestResult {
	t.Helper()
	raw, _ := json.Marshal(map[string]string{"secret": secret})
	resp, err := http.Post(url, "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("login request failed: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return loginTestResult{StatusCode: resp.StatusCode, Body: string(body)}
}
