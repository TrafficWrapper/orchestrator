package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

type mockTelegramAPI struct {
	mu      sync.Mutex
	sent    []mockTelegramMessage
	docs    []mockTelegramDocument
	answers []string
	updates []telegramUpdate
}

type mockTelegramMessage struct {
	ChatID   int64
	Text     string
	Keyboard *telegramInlineKeyboard
}

type mockTelegramDocument struct {
	ChatID   int64
	Path     string
	Filename string
	Caption  string
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

func (m *mockTelegramAPI) sendDocument(_ context.Context, chatID int64, path, filename, caption string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.docs = append(m.docs, mockTelegramDocument{ChatID: chatID, Path: path, Filename: filename, Caption: caption})
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

func TestTelegramBotNotifiesPendingWorkersOnce(t *testing.T) {
	s := newTestServer(t)
	worker := addPendingWorker(t, s)
	mock := &mockTelegramAPI{}
	bot := newTelegramBot(s, botSettingsRecord{Token: "test-token", OwnerID: 1001}, mock)

	bot.notifyPendingWorkers(context.Background())
	msg := mock.lastSent()
	if msg.ChatID != 1001 || !strings.Contains(msg.Text, "pending worker") {
		t.Fatalf("bad pending worker notice: %+v", msg)
	}
	if msg.Keyboard == nil || msg.Keyboard.InlineKeyboard[0][0].CallbackData != "worker:approve:"+worker.ID {
		t.Fatalf("bad pending worker keyboard: %+v", msg.Keyboard)
	}
	notified, err := s.store.botPendingWorkerNotified(worker.ID)
	if err != nil || !notified {
		t.Fatalf("pending worker notice not persisted: notified=%t err=%v", notified, err)
	}
	bot.notifyPendingWorkers(context.Background())
	if got := mock.sentCount(); got != 1 {
		t.Fatalf("pending worker notice was not deduplicated, got %d", got)
	}
}

func TestParseTelegramDeviceLimitsAndApply(t *testing.T) {
	now := time.Date(2026, 6, 19, 12, 0, 0, 0, time.UTC)
	limits, err := parseTelegramDeviceLimits("10GB 20mbit 30d", now)
	if err != nil {
		t.Fatalf("parse limits: %v", err)
	}
	if limits.TrafficQuotaBytes != 10*1024*1024*1024 || limits.RateLimit != "20mbit" {
		t.Fatalf("bad limits: %+v", limits)
	}
	if limits.ExpiresAt == nil || *limits.ExpiresAt != now.Add(30*24*time.Hour).Format(time.RFC3339) {
		t.Fatalf("bad expiry: %+v", limits.ExpiresAt)
	}
	reset, err := parseTelegramDeviceLimits("сброс", now)
	if err != nil || !deviceLimitsEmpty(reset) {
		t.Fatalf("bad reset limits: %+v err=%v", reset, err)
	}
	if _, err := parseTelegramDeviceLimits("мусор 20mbit 30d", now); err == nil {
		t.Fatalf("garbage quota accepted")
	}

	s := newTestServer(t)
	addApprovedWorker(t, s)
	secret := "limit-bootstrap-secret"
	if _, err := s.store.createBootstrapToken(secret, time.Now().Add(time.Hour), nil, nil); err != nil {
		t.Fatal(err)
	}
	resp := enrollDeviceForTest(t, s, secret)
	if !resp.OK {
		t.Fatalf("enroll failed: %s", resp.Error)
	}
	beforeWorkers, err := s.store.workers()
	if err != nil {
		t.Fatal(err)
	}
	mock := &mockTelegramAPI{}
	bot := newTelegramBot(s, botSettingsRecord{Token: "test-token", OwnerID: 1001}, mock)
	bot.handleUpdate(context.Background(), telegramUpdate{Message: &telegramMessage{
		From: telegramUser{ID: 1001},
		Chat: telegramChat{ID: 1001},
		Text: "/limit " + resp.DeviceID + " 1GB 5mbit 7d",
	}})
	device, err := s.store.device(resp.DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	if device.Limits.TrafficQuotaBytes != 1024*1024*1024 || device.Limits.RateLimit != "5mbit" || device.Limits.ExpiresAt == nil {
		t.Fatalf("limits not stored: %+v", device.Limits)
	}
	afterWorkers, err := s.store.workers()
	if err != nil {
		t.Fatal(err)
	}
	if afterWorkers[0].DesiredSeq <= beforeWorkers[0].DesiredSeq {
		t.Fatalf("worker seq not bumped: before=%d after=%d", beforeWorkers[0].DesiredSeq, afterWorkers[0].DesiredSeq)
	}
}

func TestTelegramBotSendCurrentAPK(t *testing.T) {
	s := newTestServer(t)
	apkPath := filepath.Join(t.TempDir(), "app.apk")
	if err := os.WriteFile(apkPath, []byte("apk"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.store.setAPKRelease(apkReleaseRecord{
		Seq:         1,
		VersionCode: 11,
		VersionName: "0.1.10",
		APKName:     "TrafficWrapper-app-v0.1.10.apk",
		APKSHA256:   "abc123",
		APKSize:     3,
		APKPath:     apkPath,
		CreatedAt:   time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	mock := &mockTelegramAPI{}
	bot := newTelegramBot(s, botSettingsRecord{Token: "test-token", OwnerID: 1001}, mock)
	if err := bot.sendCurrentAPK(context.Background()); err != nil {
		t.Fatal(err)
	}
	mock.mu.Lock()
	defer mock.mu.Unlock()
	if len(mock.docs) != 1 || mock.docs[0].Filename != "TrafficWrapper-app-v0.1.10-code11.apk" || mock.docs[0].Path != apkPath {
		t.Fatalf("bad document send: %+v", mock.docs)
	}
}

func TestTelegramBotProblemNotifyDebounceCooldownRecovery(t *testing.T) {
	s := newTestServer(t)
	deviceID := "twpk_offline"
	putQuotaDevice(t, s, deviceRecord{
		ID:           deviceID,
		Status:       "approved",
		CreatedAt:    time.Now().UTC().Add(-botProblemDeviceOfflineAfter - time.Minute),
		AWGPublicKey: "awg",
		InternalIP:   "10.13.13.9/32",
		RealityUUID:  "uuid",
	})
	mock := &mockTelegramAPI{}
	bot := newTelegramBot(s, botSettingsRecord{Token: "test-token", OwnerID: 1001}, mock)

	bot.notifyProblemTransitions(context.Background())
	if got := mock.sentCount(); got != 0 {
		t.Fatalf("problem notice sent before debounce: %d", got)
	}
	bot.notifyProblemTransitions(context.Background())
	if got := mock.lastSent(); !strings.Contains(got.Text, "offline") || !strings.Contains(got.Text, shortString(deviceID, 12)) {
		t.Fatalf("bad problem notice: %+v", got)
	}
	bot.notifyProblemTransitions(context.Background())
	if got := mock.sentCount(); got != 1 {
		t.Fatalf("cooldown did not suppress repeat notice: %d", got)
	}

	if err := s.store.setTelemetrySnapshot(telemetrySnapshotRecord{
		DeviceID:   deviceID,
		WorkerID:   "worker-a",
		ReceivedAt: time.Now().UTC(),
		Health:     "ok",
		Carry:      true,
	}); err != nil {
		t.Fatal(err)
	}
	bot.notifyProblemTransitions(context.Background())
	if got := mock.sentCount(); got != 1 {
		t.Fatalf("recovery notice sent before debounce: %d", got)
	}
	bot.notifyProblemTransitions(context.Background())
	if got := mock.lastSent(); !strings.Contains(got.Text, "recovered") {
		t.Fatalf("bad recovery notice: %+v", got)
	}
}

func TestBotProblemSnapshotIncludesQuotaAndWorkerDown(t *testing.T) {
	s := newTestServer(t)
	putQuotaDevice(t, s, deviceRecord{
		ID:             "twpk_quota",
		Status:         "revoked",
		CreatedAt:      time.Now().UTC(),
		Limits:         deviceLimits{TrafficQuotaBytes: 100},
		UsageRxBytes:   100,
		BlockedReason:  "traffic_quota_bytes",
		AWGPublicKey:   "awg-quota",
		InternalIP:     "10.13.13.10/32",
		RealityUUID:    "uuid-quota",
		BootstrapToken: "bootstrap",
	})
	addApprovedWorker(t, s)
	workers, err := s.store.workers()
	if err != nil {
		t.Fatal(err)
	}
	worker := workers[0]
	if _, err := s.store.markStaleWorkersInactive(time.Now().UTC().Add(time.Second)); err != nil {
		t.Fatal(err)
	}

	problems, err := s.botProblemSnapshot(time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := problems["device:twpk_quota:quota100"]; !ok {
		t.Fatalf("quota problem missing: %+v", problems)
	}
	if _, ok := problems["worker:"+worker.ID+":worker_down"]; !ok {
		t.Fatalf("worker down problem missing: %+v", problems)
	}
}

func TestBotProblemCooldownAllowsRepeatAfterWindow(t *testing.T) {
	now := time.Date(2026, 7, 8, 12, 0, 0, 0, time.UTC)
	entry := botProblemEntry{Scope: "device", ID: "twpk_a", Kind: "device_offline", Label: "twpk_a"}
	key := botProblemKey(entry)
	prev := botProblemState{
		Active:        map[string]botProblemEntry{key: entry},
		PendingPolls:  map[string]int{key: botProblemPollsBeforeAlert},
		LastNotified:  map[string]time.Time{key: now.Add(-botProblemRepeatCooldown - time.Minute)},
		UpdatedAt:     now.Add(-botProblemRepeatCooldown - time.Minute),
		RecoveryPolls: map[string]int{},
	}
	current := buildBotProblemState(prev, map[string]botProblemEntry{key: entry}, now)
	notices := botProblemNotices(prev, current, true)
	if len(notices) != 1 || notices[0].Key != key {
		t.Fatalf("repeat after cooldown not emitted: %+v", notices)
	}
}

func TestTelegramBotProblemNotifyNoopWhenBotOff(t *testing.T) {
	var bot *telegramBot
	bot.notifyProblemTransitions(context.Background())
}

func addPendingWorker(t *testing.T, s *server) workerRecord {
	t.Helper()
	rec, err := s.store.upsertPendingWorker("pending-static", map[string]any{
		"public_address": "worker.example",
		"awg": map[string]any{
			"endpoint":   "worker.example:51888",
			"port":       51888,
			"public_key": "awgpub",
			"subnet":     "10.13.13.0/24",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return rec
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
