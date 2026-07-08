package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestRateLimitKeyAggregatesIPv6By64(t *testing.T) {
	if got, want := rateLimitKey("198.51.100.10"), "198.51.100.10"; got != want {
		t.Fatalf("IPv4 key=%q want %q", got, want)
	}
	a := rateLimitKey("2001:db8:1:2::1")
	b := rateLimitKey("2001:db8:1:2:ffff::abcd")
	c := rateLimitKey("2001:db8:1:3::1")
	if a == "" || a != b {
		t.Fatalf("same IPv6 /64 keys differ: %q vs %q", a, b)
	}
	if a == c {
		t.Fatalf("different IPv6 /64 keys collapsed: %q", a)
	}
}

func TestHandshakeRateMapCapsDistinctIPs(t *testing.T) {
	s := &server{}
	for i := 0; i < maxHandshakeRateKeys+128; i++ {
		req := &http.Request{RemoteAddr: fmt.Sprintf("[2001:db8:%x:%x::1]:443", i/0x10000, i%0x10000)}
		reserved, _ := s.reserveHandshakeStart(req)
		if reserved {
			s.sessionCount.Add(-1)
		}
	}
	s.handshakeMu.Lock()
	got := len(s.handshakeRates)
	s.handshakeMu.Unlock()
	if got != maxHandshakeRateKeys {
		t.Fatalf("handshake rate keys=%d want hard cap %d", got, maxHandshakeRateKeys)
	}
}

func TestHandshakeRateMapEvictsWhenFullForNewKey(t *testing.T) {
	s := &server{handshakeRates: make(map[string]handshakeRate, maxHandshakeRateKeys)}
	now := time.Now()
	for i := 0; i < maxHandshakeRateKeys; i++ {
		s.handshakeRates[rateLimitKey(fmt.Sprintf("2001:db8:%x:%x::1", i/0x10000, i%0x10000))] = handshakeRate{
			WindowStart: now,
			Count:       1,
		}
	}
	s.handshakePrune = now
	req := &http.Request{RemoteAddr: "[2001:db8:ffff:ffff::1]:443"}
	reserved, reason := s.reserveHandshakeStart(req)
	if !reserved {
		t.Fatalf("new handshake key rejected at cap: %s", reason)
	}
	s.sessionCount.Add(-1)
	s.handshakeMu.Lock()
	defer s.handshakeMu.Unlock()
	if got := len(s.handshakeRates); got != maxHandshakeRateKeys {
		t.Fatalf("handshake rate keys=%d want cap %d", got, maxHandshakeRateKeys)
	}
	if _, ok := s.handshakeRates[rateLimitKey("2001:db8:ffff:ffff::1")]; !ok {
		t.Fatal("new handshake key was not admitted after eviction")
	}
}

func TestLoginLimiterStateMapCapsDistinctIPs(t *testing.T) {
	now := time.Date(2026, 7, 8, 10, 0, 0, 0, time.UTC)
	limiter := newLoginLimiter()
	limiter.now = func() time.Time { return now }
	for i := 0; i < maxLoginLimiterStates+128; i++ {
		limiter.recordFailure(fmt.Sprintf("2001:db8:%x:%x::1", i/0x10000, i%0x10000))
	}
	limiter.mu.Lock()
	got := len(limiter.states)
	limiter.mu.Unlock()
	if got != maxLoginLimiterStates {
		t.Fatalf("login limiter states=%d want hard cap %d", got, maxLoginLimiterStates)
	}
}

func TestLoginLimiterEvictsWhenFullForNewKey(t *testing.T) {
	now := time.Date(2026, 7, 8, 10, 0, 0, 0, time.UTC)
	limiter := fullLoginLimiterForTest(now)
	reservation := limiter.reserveAttempt("2001:db8:ffff:ffff::1")
	if !reservation.Allowed || reservation.Locked {
		t.Fatalf("new login key rejected at cap: %+v", reservation)
	}
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	if got := len(limiter.states); got != maxLoginLimiterStates {
		t.Fatalf("login limiter states=%d want cap %d", got, maxLoginLimiterStates)
	}
	if _, ok := limiter.states[rateLimitKey("2001:db8:ffff:ffff::1")]; !ok {
		t.Fatal("new login key was not admitted after eviction")
	}
}

func TestAdminLoginSucceedsWhenLimiterMapIsFull(t *testing.T) {
	s := newTestServer(t)
	if err := s.store.setAdminPassword("owner-secret"); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 8, 10, 0, 0, 0, time.UTC)
	s.loginLimiter = fullLoginLimiterForTest(now)
	ts := httptest.NewServer(http.HandlerFunc(s.handleAdminLogin))
	defer ts.Close()

	raw, _ := json.Marshal(map[string]string{"secret": "owner-secret"})
	req, err := http.NewRequest(http.MethodPost, ts.URL, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("content-type", "application/json")
	req.Header.Set("X-Forwarded-For", "2001:db8:ffff:ffff::2")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("admin login status=%d want 200", resp.StatusCode)
	}
}

func TestLoginLimiterReserveAttemptIsAtomicUnderConcurrency(t *testing.T) {
	now := time.Date(2026, 7, 8, 10, 0, 0, 0, time.UTC)
	limiter := newLoginLimiter()
	limiter.now = func() time.Time { return now }
	const workers = 64
	var ready sync.WaitGroup
	var done sync.WaitGroup
	start := make(chan struct{})
	var allowed atomic.Int64
	var lockedAfter atomic.Int64
	var lockedBefore atomic.Int64
	for i := 0; i < workers; i++ {
		ready.Add(1)
		done.Add(1)
		go func() {
			defer done.Done()
			ready.Done()
			<-start
			reservation := limiter.reserveAttempt("2001:db8:9:9::1234")
			if reservation.Allowed {
				allowed.Add(1)
			}
			if reservation.LockedAfterAttempt {
				lockedAfter.Add(1)
			}
			if reservation.Locked && !reservation.Allowed {
				lockedBefore.Add(1)
			}
		}()
	}
	ready.Wait()
	close(start)
	done.Wait()
	if got := allowed.Load(); got != adminLoginFailureLimit {
		t.Fatalf("allowed attempts=%d want %d", got, adminLoginFailureLimit)
	}
	if got := lockedAfter.Load(); got != 1 {
		t.Fatalf("attempts that triggered lockout=%d want 1", got)
	}
	if got, want := lockedBefore.Load(), int64(workers-adminLoginFailureLimit); got != want {
		t.Fatalf("pre-locked attempts=%d want %d", got, want)
	}
}

func fullLoginLimiterForTest(now time.Time) *loginLimiter {
	limiter := newLoginLimiter()
	limiter.now = func() time.Time { return now }
	limiter.states = make(map[string]*loginLimitState, maxLoginLimiterStates)
	for i := 0; i < maxLoginLimiterStates; i++ {
		limiter.states[rateLimitKey(fmt.Sprintf("2001:db8:%x:%x::1", i/0x10000, i%0x10000))] = &loginLimitState{
			Failures:    1,
			WindowStart: now,
		}
	}
	limiter.lastPrune = now
	return limiter
}
