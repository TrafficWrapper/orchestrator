package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"strconv"
	"strings"
	"time"
)

// Worker handshake cookies (ORC-M14): after an authenticated call an approved
// worker gets a short-lived MAC over its ID. Presenting it on the next
// handshake start puts the worker in a reserved pool, so floods of anonymous
// handshakes (which only ever compete in the shared per-IP/per-prefix pool)
// cannot starve the fleet. The cookie proves nothing else: the Noise
// handshake still authenticates the worker. Keys live in memory, so a
// restart just sends workers through the shared pool once.
const (
	workerCookieTTL             = time.Hour
	maxWorkerNoiseSessions      = 1024
	maxPendingHandshakesPerWork = 8
	workerCookiePrefix          = "v1"
)

func (s *server) workerCookieKey() []byte {
	s.cookieKeyOnce.Do(func() {
		s.cookieKey = make([]byte, 32)
		if _, err := rand.Read(s.cookieKey); err != nil {
			panic(err)
		}
	})
	return s.cookieKey
}

func (s *server) workerCookieMAC(workerID string, expires int64) string {
	mac := hmac.New(sha256.New, s.workerCookieKey())
	mac.Write([]byte("tw-worker-handshake-cookie\x00" + workerID + "\x00" + strconv.FormatInt(expires, 10)))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil)[:16])
}

func (s *server) issueWorkerCookie(workerID string, now time.Time) string {
	expires := now.Add(workerCookieTTL).Unix()
	return strings.Join([]string{workerCookiePrefix, workerID, strconv.FormatInt(expires, 10), s.workerCookieMAC(workerID, expires)}, ".")
}

// verifyWorkerCookie returns the worker ID a valid, unexpired cookie names.
func (s *server) verifyWorkerCookie(cookie string, now time.Time) (string, bool) {
	parts := strings.Split(strings.TrimSpace(cookie), ".")
	if len(parts) != 4 || parts[0] != workerCookiePrefix || parts[1] == "" || len(parts[1]) > 64 {
		return "", false
	}
	expires, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil || now.Unix() > expires || expires > now.Add(2*workerCookieTTL).Unix() {
		return "", false
	}
	want := s.workerCookieMAC(parts[1], expires)
	if subtle.ConstantTimeCompare([]byte(want), []byte(parts[3])) != 1 {
		return "", false
	}
	return parts[1], true
}

// cookieForPeer issues a cookie when the authenticated peer is a worker that
// may serve clients or is being wound down.
func (s *server) cookieForPeer(peerStatic string, now time.Time) string {
	rec, err := s.store.worker(workerID(peerStatic))
	if err != nil || rec.StaticPublicKey != peerStatic {
		return ""
	}
	if rec.Status != "approved" && rec.Status != "active" && rec.Status != "inactive" {
		return ""
	}
	return s.issueWorkerCookie(rec.ID, now)
}

// reserveWorkerHandshake takes a slot in the worker pool, rate limited per
// worker instead of per source address.
func (s *server) reserveWorkerHandshake(workerID string, now time.Time) bool {
	key := "worker:" + workerID
	s.handshakeMu.Lock()
	if s.handshakeRates == nil {
		s.handshakeRates = map[string]handshakeRate{}
	}
	if s.handshakePending == nil {
		s.handshakePending = map[string]int{}
	}
	s.pruneHandshakeRatesLocked(now)
	rate := s.handshakeRates[key]
	if rate.WindowStart.IsZero() || now.Sub(rate.WindowStart) > handshakeRateWindow {
		rate = handshakeRate{WindowStart: now}
	}
	if rate.Count >= handshakeRateLimit || s.handshakePending[key] >= maxPendingHandshakesPerWork {
		s.handshakeMu.Unlock()
		return false
	}
	rate.Count++
	s.handshakeRates[key] = rate
	s.handshakePending[key]++
	s.handshakeMu.Unlock()
	if s.workerSessionCount.Add(1) > maxWorkerNoiseSessions {
		s.releaseWorkerHandshake(workerID)
		return false
	}
	return true
}

func (s *server) releaseWorkerHandshake(workerID string) {
	s.workerSessionCount.Add(-1)
	key := "worker:" + workerID
	s.handshakeMu.Lock()
	defer s.handshakeMu.Unlock()
	if s.handshakePending[key] <= 1 {
		delete(s.handshakePending, key)
	} else {
		s.handshakePending[key]--
	}
}

// releaseSession returns whichever pool slot a pending handshake held.
func (s *server) releaseSession(sess noiseSession) {
	if sess.workerPool != "" {
		s.releaseWorkerHandshake(sess.workerPool)
		return
	}
	s.releasePendingHandshake(sess.pendingKey)
}
