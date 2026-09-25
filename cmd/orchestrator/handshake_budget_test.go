package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/flynn/noise"

	"github.com/TrafficWrapper/orchestrator/internal/protocol"
)

// workerNoiseCall runs one Noise call on /w/ and returns the start status and
// the handshake cookie from the envelope.
func workerNoiseCall(t *testing.T, baseURL string, serverPub []byte, static noise.DHKey, path, cookie string, req, resp any) (int, string) {
	t.Helper()
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite: protocol.CipherSuite(), Pattern: noise.HandshakeXK, Initiator: true,
		Prologue: []byte(protocol.Prologue), StaticKeypair: static, PeerStatic: serverPub,
	})
	if err != nil {
		t.Fatal(err)
	}
	msg1, _, _, _ := hs.WriteMessage(nil, nil)
	raw, _ := json.Marshal(startRequest{Message: base64.StdEncoding.EncodeToString(msg1), Cookie: cookie})
	httpResp, err := http.Post(baseURL+"/w/v1/handshake/start", "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	var start startResponse
	_ = json.NewDecoder(httpResp.Body).Decode(&start)
	httpResp.Body.Close()
	if !start.OK {
		return httpResp.StatusCode, ""
	}
	msg2, _ := base64.StdEncoding.DecodeString(start.Message)
	if _, _, _, err := hs.ReadMessage(nil, msg2); err != nil {
		t.Fatal(err)
	}
	msg3, send, recv, _ := hs.WriteMessage(nil, nil)
	payload, _ := protocol.EncryptJSON(send, req)
	var env noiseEnvelopeResponse
	postJSONForTest(t, baseURL+path, noiseEnvelope{SID: start.SID, Message: base64.StdEncoding.EncodeToString(msg3), Payload: base64.StdEncoding.EncodeToString(payload)}, &env)
	encrypted, _ := base64.StdEncoding.DecodeString(env.Payload)
	if err := protocol.DecryptJSON(recv, encrypted, resp); err != nil {
		t.Fatal(err)
	}
	return http.StatusOK, env.Cookie
}

// ORC-M14: an approved worker gets a cookie that lets it handshake even when
// its source network's shared pool is exhausted.
func TestWorkerCookieReservesHandshakePool(t *testing.T) {
	s := newTestServer(t)
	static, _ := protocol.GenerateKeypair()
	s.static = static
	workerKey, _ := protocol.GenerateKeypair()
	w := addApprovedWorkerWithStatic(t, s, protocol.KeyToBase64(workerKey.Public))
	mux := http.NewServeMux()
	mux.HandleFunc("/w/v1/handshake/start", s.handleHandshakeStart)
	mux.HandleFunc("/w/v1/config/pull", s.handleNoise(s.handlePull))
	ts := httptest.NewServer(mux)
	defer ts.Close()

	var pull pullResponse
	status, cookie := workerNoiseCall(t, ts.URL, static.Public, workerKey, "/w/v1/config/pull", "", pullRequest{WorkerID: w.ID}, &pull)
	if status != http.StatusOK || cookie == "" {
		t.Fatalf("approved worker must get a cookie: status=%d cookie=%q", status, cookie)
	}
	if id, ok := s.verifyWorkerCookie(cookie, time.Now()); !ok || id != w.ID {
		t.Fatalf("cookie does not verify: id=%q ok=%t", id, ok)
	}
	// Exhaust the shared pool for 127.0.0.1.
	for range maxPendingHandshakesPerKey {
		req := httptest.NewRequest(http.MethodPost, "/w/v1/handshake/start", nil)
		req.RemoteAddr = "127.0.0.1:1"
		s.reserveHandshakeStart(req)
	}
	if status, _ := workerNoiseCall(t, ts.URL, static.Public, workerKey, "/w/v1/config/pull", "", pullRequest{WorkerID: w.ID}, &pull); status != http.StatusTooManyRequests {
		t.Fatalf("without cookie the shared pool must be full: status=%d", status)
	}
	if status, _ := workerNoiseCall(t, ts.URL, static.Public, workerKey, "/w/v1/config/pull", cookie, pullRequest{WorkerID: w.ID}, &pull); status != http.StatusOK {
		t.Fatalf("cookie must use the reserved pool: status=%d", status)
	}
	if s.workerSessionCount.Load() != 0 {
		t.Fatalf("reserved slot not released: %d", s.workerSessionCount.Load())
	}
}

func TestWorkerCookieRejectsTamperingAndExpiry(t *testing.T) {
	s := newTestServer(t)
	now := time.Now()
	cookie := s.issueWorkerCookie("abc", now)
	if _, ok := s.verifyWorkerCookie(cookie, now); !ok {
		t.Fatal("fresh cookie rejected")
	}
	if _, ok := s.verifyWorkerCookie(strings.Replace(cookie, "abc", "abd", 1), now); ok {
		t.Fatal("cookie for another worker accepted")
	}
	if _, ok := s.verifyWorkerCookie(cookie, now.Add(workerCookieTTL+time.Minute)); ok {
		t.Fatal("expired cookie accepted")
	}
	if s.cookieForPeer("unknown-key", now) != "" {
		t.Fatal("unknown peer must not get a cookie")
	}
}

func TestPendingPrefixAggregatesIPv6By56(t *testing.T) {
	if pendingPrefixKey("2001:db8:1:ff::1") != pendingPrefixKey("2001:db8:1:1::1") {
		t.Fatal("same /56 must share a bucket")
	}
	if pendingPrefixKey("2001:db8:1:100::1") == pendingPrefixKey("2001:db8:1:1::1") {
		t.Fatal("different /56 must not share a bucket")
	}
}

// ORC-L37: the listener caps concurrent connections.
func TestLimitListenerCapsConnections(t *testing.T) {
	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l := newLimitListener(base, 1)
	defer l.Close()
	accepted := make(chan net.Conn, 2)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			accepted <- c
		}
	}()
	c1, _ := net.Dial("tcp", base.Addr().String())
	defer c1.Close()
	first := <-accepted
	c2, _ := net.Dial("tcp", base.Addr().String())
	defer c2.Close()
	select {
	case <-accepted:
		t.Fatal("second connection accepted over the cap")
	case <-time.After(200 * time.Millisecond):
	}
	first.Close()
	select {
	case c := <-accepted:
		c.Close()
	case <-time.After(2 * time.Second):
		t.Fatal("slot not released on close")
	}
}

func TestBufferedBodiesAreBounded(t *testing.T) {
	for range cap(bufferedBodySlots) {
		bufferedBodySlots <- struct{}{}
	}
	defer func() {
		for range cap(bufferedBodySlots) {
			<-bufferedBodySlots
		}
	}()
	h := withRequestBodyLimits(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("handler ran without a slot") }))
	req := httptest.NewRequest(http.MethodPost, "/w/v1/ack", strings.NewReader("{}"))
	ctx, cancel := contextWithTimeout(50 * time.Millisecond)
	defer cancel()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req.WithContext(ctx))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d want 503", rec.Code)
	}
}

func TestServerCapsHeaderBytes(t *testing.T) {
	if srv := newOrchestratorHTTPServer("127.0.0.1:0", http.NotFoundHandler()); srv.MaxHeaderBytes != maxRequestHeaderBytes {
		t.Fatalf("MaxHeaderBytes=%d", srv.MaxHeaderBytes)
	}
}

func contextWithTimeout(d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), d)
}
