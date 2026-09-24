package main

import (
	"context"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestSplitTelegramTextRespectsLimitAndLines(t *testing.T) {
	short := "hello\nworld"
	if got := splitTelegramText(short, 100); len(got) != 1 || got[0] != short {
		t.Fatalf("short text split: %q", got)
	}
	var lines []string
	for i := 0; i < 50; i++ {
		lines = append(lines, strings.Repeat("я", 90))
	}
	lines = append(lines, strings.Repeat("x", 250))
	chunks := splitTelegramText(strings.Join(lines, "\n"), 200)
	total := 0
	for _, c := range chunks {
		n := utf8.RuneCountInString(c)
		if n > 200 {
			t.Fatalf("chunk has %d runes", n)
		}
		total += n
	}
	if total < 50*90+250 {
		t.Fatalf("content lost: total=%d", total)
	}
}

func TestSendOwnerMessageSplitsAndKeepsKeyboardLast(t *testing.T) {
	s := newTestServer(t)
	mock := &mockTelegramAPI{}
	bot := newTelegramBot(s, botSettingsRecord{Token: "t", OwnerID: 7}, mock)
	kb := &telegramInlineKeyboard{}
	long := strings.Repeat(strings.Repeat("a", 100)+"\n", 90)
	if err := bot.sendOwnerMessage(context.Background(), long, kb); err != nil {
		t.Fatal(err)
	}
	mock.mu.Lock()
	defer mock.mu.Unlock()
	if len(mock.sent) < 2 {
		t.Fatalf("expected split, got %d messages", len(mock.sent))
	}
	for i, m := range mock.sent {
		if utf8.RuneCountInString(m.Text) > telegramMessageMaxRunes {
			t.Fatalf("message %d too long", i)
		}
		if (m.Keyboard != nil) != (i == len(mock.sent)-1) {
			t.Fatalf("keyboard must be attached only to the last chunk (i=%d)", i)
		}
	}
}

func TestTruncateRunes(t *testing.T) {
	if got := truncateRunes("абвгд", 3); got != "аб…" {
		t.Fatalf("got %q", got)
	}
	if got := truncateRunes("ok", 3); got != "ok" {
		t.Fatalf("got %q", got)
	}
}
