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
)

type loginLimiter struct {
	mu     sync.Mutex
	states map[string]*loginLimitState
	now    func() time.Time
}

type loginLimitState struct {
	Failures    int
	WindowStart time.Time
	LockedUntil time.Time
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

func (l *loginLimiter) recordFailure(key string) (time.Time, bool) {
	if l == nil || strings.TrimSpace(key) == "" {
		return time.Time{}, false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.clock()
	l.pruneLocked(now)
	state := l.states[key]
	if state == nil || state.WindowStart.IsZero() || now.Sub(state.WindowStart) > adminLoginWindow {
		state = &loginLimitState{WindowStart: now}
		l.states[key] = state
	}
	state.Failures++
	if state.Failures >= adminLoginFailureLimit {
		state.LockedUntil = now.Add(adminLoginLockoutTTL)
		return state.LockedUntil, true
	}
	return time.Time{}, false
}

func (l *loginLimiter) recordSuccess(key string) {
	if l == nil || strings.TrimSpace(key) == "" {
		return
	}
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
	for key, state := range l.states {
		if state == nil {
			delete(l.states, key)
			continue
		}
		if !state.LockedUntil.IsZero() {
			if now.After(state.LockedUntil) {
				delete(l.states, key)
			}
			continue
		}
		if !state.WindowStart.IsZero() && now.Sub(state.WindowStart) > 2*adminLoginWindow {
			delete(l.states, key)
		}
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
