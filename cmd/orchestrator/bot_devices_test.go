package main

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

func putDeviceRecordsForTest(t *testing.T, s *server, records ...deviceRecord) {
	t.Helper()
	if err := s.store.db.Update(func(tx *bolt.Tx) error {
		for _, rec := range records {
			if err := putSealedTx(s.store, tx, bucketDevices, rec.ID, rec); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func sendBotCommandForTest(s *server, text string) *mockTelegramAPI {
	mock := &mockTelegramAPI{}
	bot := newTelegramBot(s, botSettingsRecord{Token: "test-token", OwnerID: 1001}, mock)
	bot.handleUpdate(context.Background(), telegramUpdate{Message: &telegramMessage{
		From: telegramUser{ID: 1001},
		Chat: telegramChat{ID: 1001},
		Text: text,
	}})
	return mock
}

// ORC-L25: /limit accepts the ID form that /devices prints.
func TestTelegramLimitAcceptsListedDevicePrefix(t *testing.T) {
	s := newTestServer(t)
	addApprovedWorker(t, s)
	secret := "limit-prefix-secret"
	if _, err := s.store.createBootstrapToken(secret, time.Now().Add(time.Hour), nil, nil); err != nil {
		t.Fatal(err)
	}
	resp := enrollDeviceForTest(t, s, secret)
	if !resp.OK {
		t.Fatalf("enroll failed: %s", resp.Error)
	}
	listing := sendBotCommandForTest(s, "/devices").lastSent().Text
	shown := botShortDeviceID(resp.DeviceID)
	if !strings.Contains(listing, shown) {
		t.Fatalf("/devices does not show %q:\n%s", shown, listing)
	}
	sendBotCommandForTest(s, "/limit "+shown+" 1GB 5mbit 7d")
	device, err := s.store.device(resp.DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	if device.Limits.TrafficQuotaBytes != 1024*1024*1024 || device.Limits.RateLimit != "5mbit" {
		t.Fatalf("limits not stored through a listed prefix: %+v", device.Limits)
	}
}

func TestTelegramLimitRejectsAmbiguousDevicePrefix(t *testing.T) {
	s := newTestServer(t)
	putDeviceRecordsForTest(t, s,
		deviceRecord{ID: "twpk_abcdef0011111111111111111111111", Status: "approved"},
		deviceRecord{ID: "twpk_abcdef0022222222222222222222222", Status: "approved"},
	)
	reply := sendBotCommandForTest(s, "/limit twpk_abcdef00 1GB 5mbit 7d").lastSent().Text
	if !strings.Contains(reply, "неоднозначен") {
		t.Fatalf("ambiguous prefix reply=%q", reply)
	}
	for _, id := range []string{"twpk_abcdef0011111111111111111111111", "twpk_abcdef0022222222222222222222222"} {
		device, err := s.store.device(id)
		if err != nil {
			t.Fatal(err)
		}
		if !deviceLimitsEmpty(device.Limits) {
			t.Fatalf("ambiguous prefix changed limits of %s: %+v", id, device.Limits)
		}
	}
	if _, err := resolveBotDeviceID([]deviceRecord{{ID: "twpk_abcdef0011111111111111111111111"}}, "twpk_"); err == nil {
		t.Fatal("a prefix shorter than the minimum was accepted")
	}
	got, err := resolveBotDeviceID([]deviceRecord{{ID: "twpk_ab"}, {ID: "twpk_abc"}}, "twpk_ab")
	if err != nil || got != "twpk_ab" {
		t.Fatalf("exact ID must win over prefix matches: got=%q err=%v", got, err)
	}
}

func TestTelegramDevicesPaginates(t *testing.T) {
	s := newTestServer(t)
	total := 2*botMessageMaxDevices + 3
	records := make([]deviceRecord, 0, total)
	for i := 0; i < total; i++ {
		records = append(records, deviceRecord{ID: fmt.Sprintf("twpk_%08x%024d", i, 0), Status: "approved"})
	}
	putDeviceRecordsForTest(t, s, records...)

	first := sendBotCommandForTest(s, "/devices").lastSent()
	if !strings.Contains(first.Text, "page 1/3") || !strings.Contains(first.Text, "/devices 2") {
		t.Fatalf("first page lacks pagination:\n%s", first.Text)
	}
	if got := len(first.Keyboard.InlineKeyboard); got != botMessageMaxDevices {
		t.Fatalf("first page has %d device buttons want %d", got, botMessageMaxDevices)
	}
	last := sendBotCommandForTest(s, "/devices 3").lastSent()
	if !strings.Contains(last.Text, "page 3/3") || strings.Contains(last.Text, "Next:") {
		t.Fatalf("last page:\n%s", last.Text)
	}
	if !strings.Contains(last.Text, botShortDeviceID(records[total-1].ID)) {
		t.Fatalf("last page misses the last device:\n%s", last.Text)
	}
	if got := len(last.Keyboard.InlineKeyboard); got != 3 {
		t.Fatalf("last page has %d device buttons want 3", got)
	}
}
