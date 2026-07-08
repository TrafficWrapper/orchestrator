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

func (l *loginLimiter) isLocked(key string) (time.Time, bool) {
	if l == nil || strings.TrimSpace(key) == "" {
		return time.Time{}, false
	}
	key = rateLimitKey(key)
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.clock()
	l.pruneLocked(now)
	state := l.states[key]
	if state == nil || state.LockedUntil.IsZero() || !now.Before(state.LockedUntil) {
		return time.Time{}, false
	}
	return state.LockedUntil, true
}

func (l *loginLimiter) reserveAttempt(key string) loginAttemptReservation {
	if l == nil || strings.TrimSpace(key) == "" {
		return loginAttemptReservation{Allowed: true}
	}
	key = rateLimitKey(key)
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.clock()
	l.pruneLocked(now)
	state := l.states[key]
	if state != nil && state.isLocked(now) {
		return loginAttemptReservation{Locked: true, LockedUntil: state.LockedUntil}
	}
	if state == nil || state.WindowStart.IsZero() || now.Sub(state.WindowStart) > adminLoginWindow {
		if state == nil && len(l.states) >= maxLoginLimiterStates {
			evictOneLoginLimitStateLocked(l.states)
		}
		state = &loginLimitState{WindowStart: now}
		l.states[key] = state
	}
	state.Failures++
	if state.Failures >= adminLoginFailureLimit {
		state.LockedUntil = now.Add(adminLoginLockoutTTL)
		return loginAttemptReservation{
			Allowed:            true,
			LockedUntil:        state.LockedUntil,
			LockedAfterAttempt: true,
		}
	}
	return loginAttemptReservation{Allowed: true}
}

func (l *loginLimiter) recordFailure(key string) (time.Time, bool) {
	reservation := l.reserveAttempt(key)
	return reservation.LockedUntil, reservation.Locked || reservation.LockedAfterAttempt
}

func (l *loginLimiter) recordSuccess(key string) {
	if l == nil || strings.TrimSpace(key) == "" {
		return
	}
	key = rateLimitKey(key)
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.states, key)
}

func (l *loginLimiter) clock() time.Time {
	if l.now != nil {
		return l.now()
	}
	return time.Now()
}

func (l *loginLimiter) pruneLocked(now time.Time) {
	if !l.lastPrune.IsZero() && now.After(l.lastPrune) && now.Sub(l.lastPrune) < adminLoginPruneEvery {
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

func evictOneLoginLimitStateLocked(states map[string]*loginLimitState) {
	for key := range states {
		delete(states, key)
		return
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
