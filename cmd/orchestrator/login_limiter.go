package main

import (
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	adminLoginFailureLimit = 5
	adminLoginLockoutTTL   = 15 * time.Minute
	adminLoginWindow       = 15 * time.Minute
	adminLoginPruneEvery   = time.Second
	maxLoginLimiterStates  = 64 * 1024
	// adminLoginPrefixFailureLimit caps failures across a whole IPv4 /24 or
	// IPv6 /48, so rotating addresses inside one network does not multiply
	// the per-address budget.
	adminLoginPrefixFailureLimit = 25
)

type loginLimiter struct {
	mu        sync.Mutex
	states    map[string]*loginLimitState
	lastPrune time.Time
	now       func() time.Time
}

type loginLimitState struct {
	Failures    int
	WindowStart time.Time
	LockedUntil time.Time
}

type loginAttemptReservation struct {
	Allowed            bool
	Locked             bool
	LockedUntil        time.Time
	LockedAfterAttempt bool
}

func newLoginLimiter() *loginLimiter {
	return &loginLimiter{states: map[string]*loginLimitState{}, now: time.Now}
}

func (s *server) adminLoginLimiter() *loginLimiter {
	s.loginLimiterMu.Lock()
	defer s.loginLimiterMu.Unlock()
	if s.loginLimiter == nil {
		s.loginLimiter = newLoginLimiter()
	}
	return s.loginLimiter
}

type loginLimiterKey struct {
	key   string
	limit int
}

// loginLimiterKeys charges an attempt to the address (IPv4 or IPv6 /64) and
// to its wider network (IPv4 /24, IPv6 /48).
func loginLimiterKeys(ip string) []loginLimiterKey {
	return []loginLimiterKey{
		{key: rateLimitKey(ip), limit: adminLoginFailureLimit},
		{key: pendingPrefixKey(ip), limit: adminLoginPrefixFailureLimit},
	}
}

func (l *loginLimiter) reserveAttempt(key string) loginAttemptReservation {
	if l == nil || strings.TrimSpace(key) == "" {
		return loginAttemptReservation{Allowed: true}
	}
	keys := loginLimiterKeys(key)
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.clock()
	l.pruneLocked(now)
	var lockedUntil time.Time
	for _, k := range keys {
		if state := l.states[k.key]; state.isLocked(now) && state.LockedUntil.After(lockedUntil) {
			lockedUntil = state.LockedUntil
		}
	}
	if !lockedUntil.IsZero() {
		return loginAttemptReservation{Locked: true, LockedUntil: lockedUntil}
	}
	for _, k := range keys {
		state := l.states[k.key]
		if state == nil || state.WindowStart.IsZero() || now.Sub(state.WindowStart) > adminLoginWindow {
			if state == nil && len(l.states) >= maxLoginLimiterStates {
				evictOneLoginLimitStateLocked(l.states, now)
			}
			state = &loginLimitState{WindowStart: now}
			l.states[k.key] = state
		}
		state.Failures++
		if state.Failures >= k.limit {
			state.LockedUntil = now.Add(adminLoginLockoutTTL)
			if state.LockedUntil.After(lockedUntil) {
				lockedUntil = state.LockedUntil
			}
		}
	}
	if !lockedUntil.IsZero() {
		return loginAttemptReservation{
			Allowed:            true,
			LockedUntil:        lockedUntil,
			LockedAfterAttempt: true,
		}
	}
	return loginAttemptReservation{Allowed: true}
}

func (l *loginLimiter) recordSuccess(key string) {
	if l == nil || strings.TrimSpace(key) == "" {
		return
	}
	prefix := pendingPrefixKey(key)
	key = rateLimitKey(key)
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.states, key)
	// reserveAttempt charges the network before the outcome is known; refund
	// it so successful logins never count toward the network lockout.
	if state := l.states[prefix]; state != nil && state.Failures > 0 && !state.isLocked(l.clock()) {
		state.Failures--
	}
}

func (l *loginLimiter) clock() time.Time {
	if l.now != nil {
		return l.now()
	}
	return time.Now()
}

func (l *loginLimiter) pruneLocked(now time.Time) {
	if !l.lastPrune.IsZero() && now.Before(l.lastPrune.Add(adminLoginPruneEvery)) {
		if now.Before(l.lastPrune) {
			// Clock stepped backwards: rebase instead of pruning on every call.
			l.lastPrune = now
		}
		return
	}
	l.lastPrune = now
	for key, state := range l.states {
		if state == nil || state.expired(now) {
			delete(l.states, key)
		}
	}
}

func (s *loginLimitState) isLocked(now time.Time) bool {
	return s != nil && !s.LockedUntil.IsZero() && now.Before(s.LockedUntil)
}

func (s *loginLimitState) expired(now time.Time) bool {
	if s == nil {
		return true
	}
	if !s.LockedUntil.IsZero() {
		return !now.Before(s.LockedUntil)
	}
	return !s.WindowStart.IsZero() && now.Sub(s.WindowStart) > 2*adminLoginWindow
}

// evictOneLoginLimitStateLocked frees a slot, preferring an entry that is
// not currently locked so a flood of new addresses cannot erase lockouts.
func evictOneLoginLimitStateLocked(states map[string]*loginLimitState, now time.Time) {
	fallback := ""
	checked := 0
	for key, state := range states {
		if !state.isLocked(now) {
			delete(states, key)
			return
		}
		if fallback == "" {
			fallback = key
		}
		if checked++; checked >= 64 {
			break
		}
	}
	if fallback != "" {
		delete(states, fallback)
	}
}

func retryAfterSeconds(until time.Time, now time.Time) string {
	if until.IsZero() || !until.After(now) {
		return "0"
	}
	remaining := until.Sub(now)
	seconds := int64((remaining + time.Second - 1) / time.Second)
	return strconv.FormatInt(seconds, 10)
}
