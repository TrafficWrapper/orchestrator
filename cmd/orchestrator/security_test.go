package main

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/flynn/noise"

	"github.com/TrafficWrapper/orchestrator/internal/protocol"
)

func TestOrchestratorHTTPServerTimeoutsPreserveLongPoll(t *testing.T) {
	srv := newOrchestratorHTTPServer("127.0.0.1:0", http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	if srv.ReadHeaderTimeout != 15*time.Second {
		t.Fatalf("read header timeout=%s want 15s", srv.ReadHeaderTimeout)
	}
	if srv.IdleTimeout != 120*time.Second {
		t.Fatalf("idle timeout=%s want 120s", srv.IdleTimeout)
	}
	if srv.ReadTimeout != 0 || srv.WriteTimeout != 0 {
		t.Fatalf("global read/write timeouts must stay disabled for long-poll: read=%s write=%s", srv.ReadTimeout, srv.WriteTimeout)
	}
}

func TestNoiseDecryptFailureDoesNotCallHandler(t *testing.T) {
	s := newTestServer(t)
	serverStatic, err := protocol.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	s.static = serverStatic
	calls := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/d/v1/handshake/start", s.handleHandshakeStart)
	mux.HandleFunc("/d/v1/test", s.handleNoise(func(_ []byte, _ []byte) (any, error) {
		calls++
		return map[string]any{"ok": true}, nil
	}))
	ts := httptest.NewServer(mux)
	defer ts.Close()

	clientStatic, err := protocol.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	env := noiseEnvelopeForTest(t, ts.URL, serverStatic.Public, clientStatic, map[string]any{"test": true})
	ciphertext, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext[len(ciphertext)-1] ^= 0xff
	env.Payload = base64.StdEncoding.EncodeToString(ciphertext)
	var rejected noiseEnvelopeResponse
	postJSONForTest(t, ts.URL+"/d/v1/test", env, &rejected)
	if rejected.OK || rejected.Error != "noise decrypt failed" {
		t.Fatalf("tampered ciphertext response=%+v", rejected)
	}
	if calls != 0 {
		t.Fatalf("handler called %d times for tampered ciphertext", calls)
	}

	var accepted map[string]any
	noiseCallForTest(t, ts.URL, serverStatic.Public, clientStatic, "/d/v1/test", map[string]any{"test": true}, &accepted)
	if accepted["ok"] != true || calls != 1 {
		t.Fatalf("valid ciphertext response=%v calls=%d", accepted, calls)
	}
}

func TestRequireAdminCSRFUsesConstantTimeMatcher(t *testing.T) {
	s := newTestServer(t)
	const sessionToken = "session-token"
	const csrfToken = "0123456789abcdef0123456789abcdef"
	s.adminSessions.Store(sessionToken, adminSession{
		Token:      sessionToken,
		CSRFToken:  csrfToken,
		ExpiresAt:  time.Now().UTC().Add(time.Hour),
		MustChange: false,
	})

	wrong := httptest.NewRequest(http.MethodPost, "/admin/v1/test", nil)
	wrong.AddCookie(&http.Cookie{Name: "tw_admin_session", Value: sessionToken})
	wrong.Header.Set("x-csrf-token", "fedcba9876543210fedcba9876543210")
	wrongResponse := httptest.NewRecorder()
	if s.requireAdmin(wrongResponse, wrong) || wrongResponse.Code != http.StatusForbidden {
		t.Fatalf("wrong csrf accepted or wrong status=%d", wrongResponse.Code)
	}

	valid := httptest.NewRequest(http.MethodPost, "/admin/v1/test", nil)
	valid.AddCookie(&http.Cookie{Name: "tw_admin_session", Value: sessionToken})
	valid.Header.Set("x-csrf-token", csrfToken)
	validResponse := httptest.NewRecorder()
	if !s.requireAdmin(validResponse, valid) {
		t.Fatalf("valid csrf rejected status=%d", validResponse.Code)
	}
	if !csrfTokenMatches(csrfToken, csrfToken) || csrfTokenMatches(csrfToken, "wrong") || csrfTokenMatches("", "") {
		t.Fatal("csrf constant-time matcher semantics are incorrect")
	}
}

func noiseEnvelopeForTest(t *testing.T, baseURL string, serverPub []byte, static noise.DHKey, req any) noiseEnvelope {
	t.Helper()
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   protocol.CipherSuite(),
		Pattern:       noise.HandshakeXK,
		Initiator:     true,
		Prologue:      []byte(protocol.Prologue),
		StaticKeypair: static,
		PeerStatic:    serverPub,
	})
	if err != nil {
		t.Fatal(err)
	}
	msg1, _, _, err := hs.WriteMessage(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	var start startResponse
	postJSONForTest(t, baseURL+"/d/v1/handshake/start", startRequest{Message: base64.StdEncoding.EncodeToString(msg1)}, &start)
	if !start.OK {
		t.Fatalf("handshake start failed: %+v", start)
	}
	msg2, err := base64.StdEncoding.DecodeString(start.Message)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := hs.ReadMessage(nil, msg2); err != nil {
		t.Fatal(err)
	}
	msg3, sendCipher, _, err := hs.WriteMessage(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := protocol.EncryptJSON(sendCipher, req)
	if err != nil {
		t.Fatal(err)
	}
	return noiseEnvelope{
		SID:     start.SID,
		Message: base64.StdEncoding.EncodeToString(msg3),
		Payload: base64.StdEncoding.EncodeToString(payload),
	}
}
