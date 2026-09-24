package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/flynn/noise"

	"github.com/TrafficWrapper/orchestrator/internal/protocol"
)

type noiseSession struct {
	hs        *noise.HandshakeState
	createdAt time.Time
	// pendingKey identifies the source bucket charged for this pending
	// handshake (see reserveHandshakeStart).
	pendingKey string
}

type handshakeRate struct {
	WindowStart time.Time
	Count       int
}

type startRequest struct {
	Message string `json:"message"`
}

type startResponse struct {
	OK      bool   `json:"ok"`
	Error   string `json:"error,omitempty"`
	SID     string `json:"sid,omitempty"`
	Message string `json:"message,omitempty"`
}

type noiseEnvelope struct {
	SID     string `json:"sid"`
	Message string `json:"message"`
	Payload string `json:"payload"`
}

type noiseEnvelopeResponse struct {
	OK      bool   `json:"ok"`
	Error   string `json:"error,omitempty"`
	Payload string `json:"payload,omitempty"`
}

func (s *server) handleHandshakeStart(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	reserved, reason := s.reserveHandshakeStart(r)
	if !reserved {
		w.WriteHeader(http.StatusTooManyRequests)
		writeJSON(w, startResponse{OK: false, Error: reason})
		return
	}
	stored := false
	ip := clientIP(r)
	defer func() {
		if !stored {
			s.releasePendingHandshake(ip)
		}
	}()
	var req startRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, startResponse{OK: false, Error: err.Error()})
		return
	}
	msg1, err := base64.StdEncoding.DecodeString(req.Message)
	if err != nil {
		writeJSON(w, startResponse{OK: false, Error: "bad message"})
		return
	}
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   protocol.CipherSuite(),
		Pattern:       noise.HandshakeXK,
		Initiator:     false,
		Prologue:      []byte(protocol.Prologue),
		StaticKeypair: s.static,
	})
	if err != nil {
		writeJSON(w, startResponse{OK: false, Error: err.Error()})
		return
	}
	if _, _, _, err := hs.ReadMessage(nil, msg1); err != nil {
		writeJSON(w, startResponse{OK: false, Error: err.Error()})
		return
	}
	msg2, _, _, err := hs.WriteMessage(nil, nil)
	if err != nil {
		writeJSON(w, startResponse{OK: false, Error: err.Error()})
		return
	}
	sid := randID()
	s.sessions.Store(sid, noiseSession{hs: hs, createdAt: time.Now(), pendingKey: ip})
	stored = true
	writeJSON(w, startResponse{OK: true, SID: sid, Message: base64.StdEncoding.EncodeToString(msg2)})
}

func (s *server) reserveHandshakeStart(r *http.Request) (bool, string) {
	now := time.Now()
	key := rateLimitKey(clientIP(r))
	s.handshakeMu.Lock()
	if s.handshakeRates == nil {
		s.handshakeRates = map[string]handshakeRate{}
	}
	s.pruneHandshakeRatesLocked(now)
	rate, exists := s.handshakeRates[key]
	if !exists && len(s.handshakeRates) >= maxHandshakeRateKeys {
		evictOneHandshakeRateLocked(s.handshakeRates)
	}
	if rate.WindowStart.IsZero() || now.Sub(rate.WindowStart) > handshakeRateWindow {
		rate = handshakeRate{WindowStart: now}
	}
	if rate.Count >= handshakeRateLimit {
		s.handshakeMu.Unlock()
		return false, "handshake rate limit exceeded"
	}
	rate.Count++
	s.handshakeRates[key] = rate
	if s.handshakePending == nil {
		s.handshakePending = map[string]int{}
	}
	prefix := pendingPrefixKey(clientIP(r))
	if s.handshakePending[key] >= maxPendingHandshakesPerKey || s.handshakePending[prefix] >= maxPendingHandshakesPerPrefix {
		s.handshakeMu.Unlock()
		return false, "too many pending handshakes from this network"
	}
	s.handshakePending[key]++
	s.handshakePending[prefix]++
	s.handshakeMu.Unlock()
	if s.sessionCount.Add(1) > maxNoiseSessions {
		s.releasePendingHandshake(clientIP(r))
		return false, "too many pending handshakes"
	}
	return true, ""
}

// releasePendingHandshake returns the global and per-source slots taken by
// reserveHandshakeStart for a handshake from ip.
func (s *server) releasePendingHandshake(ip string) {
	s.sessionCount.Add(-1)
	key := rateLimitKey(ip)
	prefix := pendingPrefixKey(ip)
	s.handshakeMu.Lock()
	defer s.handshakeMu.Unlock()
	for _, k := range []string{key, prefix} {
		if s.handshakePending[k] <= 1 {
			delete(s.handshakePending, k)
		} else {
			s.handshakePending[k]--
		}
	}
}

// pendingPrefixKey aggregates addresses one level wider than rateLimitKey:
// IPv4 /24 and IPv6 /48.
func pendingPrefixKey(ip string) string {
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return "prefix:" + strings.TrimSpace(ip)
	}
	addr = addr.Unmap()
	bits := 48
	if addr.Is4() {
		bits = 24
	}
	prefix, err := addr.Prefix(bits)
	if err != nil {
		return "prefix:" + addr.String()
	}
	return "prefix:" + prefix.String()
}

func (s *server) pruneHandshakeRatesLocked(now time.Time) {
	if !s.handshakePrune.IsZero() && now.Before(s.handshakePrune.Add(handshakeRatePruneEvery)) {
		if now.Before(s.handshakePrune) {
			s.handshakePrune = now
		}
		return
	}
	s.handshakePrune = now
	for key, rate := range s.handshakeRates {
		if rate.WindowStart.IsZero() || now.Sub(rate.WindowStart) > 2*handshakeRateWindow {
			delete(s.handshakeRates, key)
		}
	}
}

func evictOneHandshakeRateLocked(rates map[string]handshakeRate) {
	for key := range rates {
		delete(rates, key)
		return
	}
}

func remoteIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err == nil && host != "" {
		return host
	}
	return remoteAddr
}

func (s *server) runNoiseSessionJanitor(ctx context.Context) {
	ticker := time.NewTicker(noiseSessionJanitorEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cutoff := time.Now().Add(-noiseSessionTTL)
			s.sessions.Range(func(key, value any) bool {
				sess, ok := value.(noiseSession)
				if !ok || sess.createdAt.Before(cutoff) {
					if _, loaded := s.sessions.LoadAndDelete(key); loaded {
						s.releasePendingHandshake(sess.pendingKey)
					}
				}
				return true
			})
			s.pruneExpiredAdminSessions(time.Now().UTC())
		}
	}
}

func (s *server) handleNoise(fn func([]byte, []byte) (any, error)) http.HandlerFunc {
	return s.handleNoiseContext(func(_ context.Context, peer []byte, raw []byte) (any, error) {
		return fn(peer, raw)
	})
}

func (s *server) handleNoiseContext(fn func(context.Context, []byte, []byte) (any, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		var env noiseEnvelope
		if err := json.NewDecoder(r.Body).Decode(&env); err != nil {
			writeJSON(w, noiseEnvelopeResponse{OK: false, Error: err.Error()})
			return
		}
		v, ok := s.sessions.LoadAndDelete(env.SID)
		if !ok {
			writeJSON(w, noiseEnvelopeResponse{OK: false, Error: "noise session expired"})
			return
		}
		sess := v.(noiseSession)
		s.releasePendingHandshake(sess.pendingKey)
		if time.Since(sess.createdAt) > noiseSessionTTL {
			writeJSON(w, noiseEnvelopeResponse{OK: false, Error: "noise session expired"})
			return
		}
		msg3, err := base64.StdEncoding.DecodeString(env.Message)
		if err != nil {
			writeJSON(w, noiseEnvelopeResponse{OK: false, Error: "bad message"})
			return
		}
		payload, err := base64.StdEncoding.DecodeString(env.Payload)
		if err != nil {
			writeJSON(w, noiseEnvelopeResponse{OK: false, Error: "bad payload"})
			return
		}
		_, recvCipher, sendCipher, err := sess.hs.ReadMessage(nil, msg3)
		if err != nil {
			writeJSON(w, noiseEnvelopeResponse{OK: false, Error: err.Error()})
			return
		}
		plain, err := decryptBytes(recvCipher, payload)
		if err != nil {
			writeJSON(w, noiseEnvelopeResponse{OK: false, Error: "noise decrypt failed"})
			return
		}
		peer := append([]byte(nil), sess.hs.PeerStatic()...)
		resp, err := fn(r.Context(), peer, plain)
		if err != nil {
			resp = map[string]any{"ok": false, "error": err.Error()}
		}
		encrypted, err := protocol.EncryptJSON(sendCipher, resp)
		if err != nil {
			writeJSON(w, noiseEnvelopeResponse{OK: false, Error: err.Error()})
			return
		}
		writeJSON(w, noiseEnvelopeResponse{OK: true, Payload: base64.StdEncoding.EncodeToString(encrypted)})
	}
}

func decryptBytes(cipher *noise.CipherState, payload []byte) ([]byte, error) {
	plain, err := cipher.Decrypt(nil, nil, payload)
	if err != nil {
		return nil, errors.New("noise decrypt failed")
	}
	return plain, nil
}
